package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// RegisterAgent is tested end to end against two fakes wired together:
//
//   - a fake qurl-service (httptest) answering GET /v1/agent/registration-info
//     and POST /v1/agent/registration/complete; and
//   - a fake relay+NHP server (httptest) that opens the posted NHP OTP/REG
//     packets with relayknocktest's responder-role primitives
//     (OpenInitiatorMessage) and answers a REG with a scripted NHP_RAK built via
//     relayknocktest.BuildReply.
//
// The relay fake uses the SAME relayknock crypto the SDK uses on the other end;
// the wire bytes themselves are fenced by relayknock's golden vectors, so this
// exercises the qurl orchestration (paths, state machine, error mapping,
// persistence) rather than re-testing the handshake.

// --- fake NHP relay + server ---

// fakeNHPServer is a scripted relay+NHP responder. It holds a server static
// keypair, decodes the agent's posted OTP/REG bodies, and answers REG with an
// NHP_RAK whose errCode the test scripts.
type fakeNHPServer struct {
	t          *testing.T
	serverPriv []byte
	serverPub  []byte

	mu       sync.Mutex
	otpSends int
	regs     []registerRequestBody
	lastOTP  otpRequestBody
	// enrolled is set true once a REG succeeds (RAK errCode "0"), modeling the
	// server having a registered device. The fake service gates completion on it
	// so completion only succeeds after a successful REG (or when a test pre-sets
	// it to model a crash-recovery probe).
	enrolled bool

	// expectDevicePub is the agent device public key the fake expects to knock,
	// synced from the AgentState the SDK persists before its first network call.
	// The responder-role open needs it to verify the header digest.
	expectDevicePub []byte

	// rakErrCode is the errCode the next REG is answered with ("0"/"" = success).
	rakErrCode string
	rakErrMsg  string
	// replyREGWithCOK, when true, answers a REG with an overload cookie-challenge
	// (NHP_COK) instead of an NHP_RAK, modeling a relay under load.
	replyREGWithCOK bool
	// regReplyCounterOffset, when non-zero, stamps the RAK header counter with
	// req.Counter+offset instead of echoing it, modeling a byzantine relay that
	// swaps in a mis-correlated reply. relayknock.Exchange must refuse it.
	regReplyCounterOffset uint64
	// expectCredential, when non-empty, asserts the REG body carried it.
	expectCredential string
}

// isEnrolled reports whether a successful REG has been recorded (or a test
// pre-set the flag to model an already-enrolled device).
func (s *fakeNHPServer) isEnrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrolled
}

// regCount returns the number of REG packets received, read under the lock so
// assertions are race-free against the handler goroutine.
func (s *fakeNHPServer) regCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.regs)
}

// otpCount returns the number of OTP dispatches received, read under the lock.
func (s *fakeNHPServer) otpCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.otpSends
}

// setEnrolled pre-marks the device as enrolled, so a completion probe succeeds
// without a REG in the current run (crash-recovery modeling).
func (s *fakeNHPServer) setEnrolled(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrolled = v
}

func newFakeNHPServer(t *testing.T) *fakeNHPServer {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("server key: %v", err)
	}
	pub, err := relayknockPublic(priv)
	if err != nil {
		t.Fatalf("derive server pub: %v", err)
	}
	return &fakeNHPServer{t: t, serverPriv: priv, serverPub: pub, rakErrCode: rakSuccess}
}

// relayknockPublic derives the X25519 public key for a raw private scalar via
// crypto/ecdh (matching the bytes relayknock derives internally).
func relayknockPublic(priv []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func (s *fakeNHPServer) serverPubB64() string {
	return base64.StdEncoding.EncodeToString(s.serverPub)
}

func (s *fakeNHPServer) serverID() string {
	return relayknock.PubKeyFingerprint(s.serverPub)
}

// handler is the relay HTTP handler: POST /relay/{serverID} with a raw NHP
// packet. It opens the packet in the responder role, and for a REG answers with
// a scripted RAK; for an OTP acknowledges dispatch with 202.
func (s *fakeNHPServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/relay/" + s.serverID()
		if r.URL.Path != wantPath {
			s.t.Errorf("relay path = %q, want %q", r.URL.Path, wantPath)
			http.Error(w, "bad relay path", http.StatusNotFound)
			return
		}
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			s.t.Errorf("read posted packet: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		// The responder-role open needs the expected agent device public key to
		// verify the header digest. The harness syncs it from the AgentState the
		// SDK persists before its first network call (see armDevicePubOnInfo).
		reply, devicePub, err := s.openAny(packet)
		if err != nil {
			s.t.Errorf("server-side open: %v", err)
			http.Error(w, "open error", http.StatusInternalServerError)
			return
		}

		switch reply.Type {
		case relayknock.TypeOTP:
			var body otpRequestBody
			if err := json.Unmarshal(reply.Body, &body); err != nil {
				s.t.Errorf("decode OTP body: %v", err)
			}
			s.mu.Lock()
			s.otpSends++
			s.lastOTP = body
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		case relayknock.TypeRegister:
			var body registerRequestBody
			if err := json.Unmarshal(reply.Body, &body); err != nil {
				s.t.Errorf("decode REG body: %v", err)
			}
			s.mu.Lock()
			s.regs = append(s.regs, body)
			errCode, errMsg := s.rakErrCode, s.rakErrMsg
			expect := s.expectCredential
			cok := s.replyREGWithCOK
			counterOffset := s.regReplyCounterOffset
			if !cok && (errCode == "" || errCode == rakSuccess) {
				// A successful REG enrolls the device server-side, so a later
				// completion (or probe) succeeds.
				s.enrolled = true
			}
			s.mu.Unlock()
			if expect != "" && body.OTP != expect {
				s.t.Errorf("REG credential = %q, want %q", body.OTP, expect)
			}
			if cok {
				// Overload cookie-challenge instead of a registration reply.
				cokPkt, err := relayknocktest.BuildReply(relayknock.TypeCookieChallenge, &relayknock.KnockInputs{
					DeviceStaticPriv: s.serverPriv,
					ServerStaticPub:  devicePub,
					EphemeralPriv:    scriptedEphemeral(0x6b),
					TimestampNanos:   uint64(time.Now().UnixNano()),
					Counter:          reply.Counter,
					Preamble:         0x2b3c4d5e,
					Body:             nil,
				})
				if err != nil {
					s.t.Errorf("build COK: %v", err)
					http.Error(w, "cok error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(cokPkt)
				return
			}
			ackBody, err := json.Marshal(registerAckBody{ErrCode: errCode, ErrMsg: errMsg, AspID: agentAspID})
			if err != nil {
				s.t.Errorf("marshal RAK body: %v", err)
			}
			rak, err := relayknocktest.BuildReply(relayknock.TypeRegisterAck, &relayknock.KnockInputs{
				DeviceStaticPriv: s.serverPriv,
				ServerStaticPub:  devicePub,
				EphemeralPriv:    scriptedEphemeral(0x5a),
				TimestampNanos:   uint64(time.Now().UnixNano()),
				Counter:          reply.Counter + counterOffset,
				Preamble:         0x1a2b3c4d,
				Body:             ackBody,
			})
			if err != nil {
				s.t.Errorf("build RAK: %v", err)
				http.Error(w, "rak error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(rak)
		default:
			s.t.Errorf("unexpected posted packet type %d", reply.Type)
			http.Error(w, "bad type", http.StatusBadRequest)
		}
	}
}

// openAny opens a posted initiator packet in the responder role using the agent
// device public key synced from the persisted AgentState (see expectDevicePub).
func (s *fakeNHPServer) openAny(packet []byte) (*relayknock.Reply, []byte, error) {
	s.mu.Lock()
	devicePub := s.expectDevicePub
	s.mu.Unlock()
	if devicePub == nil {
		return nil, nil, errors.New("fake server: expectDevicePub not set")
	}
	reply, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, devicePub, packet)
	if err != nil {
		return nil, nil, err
	}
	return reply, devicePub, nil
}

// expectDevicePub is the agent device public key the fake expects to knock. The
// test sets it from the AgentState the SDK persists before any network call.
// Guarded by mu.
func (s *fakeNHPServer) setExpectDevicePub(pub []byte) {
	s.mu.Lock()
	s.expectDevicePub = pub
	s.mu.Unlock()
}

// scriptedEphemeral returns a deterministic 32-byte ephemeral private key for a
// fabricated reply, so a fake server reply is reproducible.
func scriptedEphemeral(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed
	}
	return b
}

// --- fake qurl-service (registration-info + completion) ---

// fakeService is the httptest qurl-service backing the two registration HTTPS
// endpoints. Its behavior is scripted per test.
type fakeService struct {
	t   *testing.T
	nhp *fakeNHPServer

	mu sync.Mutex

	keyKind     string
	keyID       string
	maskedEmail string

	// completion scripting
	completionStatus int    // 0 => 200 success
	completionCode   string // error code for a non-200
	deviceAPIKey     string
	agentID          string // agent id echoed by completion; "" => echo the request device_id
	registeredAt     *time.Time

	// counters
	infoCalls       atomic.Int32
	completionCalls atomic.Int32

	// expectedBearer asserts the Authorization header on both endpoints.
	expectedBearer string
}

func newFakeService(t *testing.T, nhp *fakeNHPServer) *fakeService {
	t.Helper()
	now := time.Now().UTC()
	return &fakeService{
		t:            t,
		nhp:          nhp,
		keyKind:      keyKindBootstrap,
		keyID:        "key_test123",
		deviceAPIKey: "lv_device_secret",
		registeredAt: &now,
	}
}

func (f *fakeService) handler(relayBaseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if f.expectedBearer != "" {
			if got := r.Header.Get("Authorization"); got != "Bearer "+f.expectedBearer {
				f.t.Errorf("Authorization = %q, want Bearer %q", got, f.expectedBearer)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info":
			f.infoCalls.Add(1)
			f.serveInfo(w, relayBaseURL)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete":
			f.completionCalls.Add(1)
			f.serveCompletion(w, r)
		default:
			f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

func (f *fakeService) serveInfo(w http.ResponseWriter, relayBaseURL string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := registrationInfoResponse{
		KeyKind: f.keyKind,
		KeyID:   f.keyID,
		NHPServerPeer: NHPServerPeerInfo{
			PublicKeyB64: f.nhp.serverPubB64(),
			Host:         "nhp.example.test",
			Port:         62206,
			ExpireTime:   0,
		},
		Relay: registrationRelay{
			BaseURL:  relayBaseURL,
			ServerID: f.nhp.serverID(),
		},
		MaskedEmail: f.maskedEmail,
	}
	writeEnvelope(f.t, w, resp)
}

func (f *fakeService) serveCompletion(w http.ResponseWriter, r *http.Request) {
	var req completeRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("decode completion body: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completionStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.completionStatus)
		_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"detail":"scripted completion error"}}`, f.completionCode)
		return
	}
	// Model server state: completion only succeeds once the device is enrolled
	// (a REG has succeeded), or a test pre-marked it enrolled to exercise the
	// crash-recovery probe. Otherwise the device is not yet registered.
	if !f.nhp.isEnrolled() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":{"code":"device_not_registered","detail":"device is not yet registered"}}`)
		return
	}
	agentID := f.agentID
	if agentID == "" {
		agentID = req.DeviceID
	}
	resp := completionResponse{
		AgentID:      agentID,
		RegisteredAt: f.registeredAt,
		NHPServerPeer: NHPServerPeerInfo{
			PublicKeyB64: f.nhp.serverPubB64(),
			Host:         "nhp.example.test",
			Port:         62206,
			ExpireTime:   0,
		},
		DeviceAPIKey: f.deviceAPIKey,
	}
	writeEnvelope(f.t, w, resp)
}

func writeEnvelope[T any](t *testing.T, w http.ResponseWriter, data T) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(apiEnvelope[T]{Data: data}); err != nil {
		t.Errorf("encode envelope: %v", err)
	}
}

// registerHarness wires a fakeService + fakeNHPServer to two httptest servers
// and returns everything a test needs to drive RegisterAgent.
//
// The API server is created with ONE stable dispatcher handler that loads the
// current handler from a mutex-guarded field on every request. Tests swap the
// active handler with setHandler (never by reassigning apiSrv.Config.Handler on
// a live server, which net/http reads unsynchronized from each connection
// goroutine — a write-after-serve race).
type registerHarness struct {
	svc       *fakeService
	nhp       *fakeNHPServer
	apiSrv    *httptest.Server
	relaySrv  *httptest.Server
	statePath string
	store     AgentStateStore

	handlerMu sync.Mutex
	handler   http.Handler
}

func newRegisterHarness(t *testing.T) *registerHarness {
	t.Helper()
	nhp := newFakeNHPServer(t)
	relaySrv := httptest.NewServer(nhp.handler())
	t.Cleanup(relaySrv.Close)

	svc := newFakeService(t, nhp)
	statePath := filepath.Join(t.TempDir(), "agent-state.json")
	h := &registerHarness{
		svc:       svc,
		nhp:       nhp,
		relaySrv:  relaySrv,
		statePath: statePath,
		store:     FileAgentState(statePath),
	}
	h.handler = svc.handler(relaySrv.URL)
	// One stable dispatcher installed at NewServer time; the swappable handler
	// lives behind handlerMu, so a per-test override is race-free under -race.
	h.apiSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.handlerMu.Lock()
		handler := h.handler
		h.handlerMu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.apiSrv.Close)
	return h
}

// setHandler swaps the active API handler race-free (the dispatcher installed at
// NewServer time reads it under handlerMu on each request).
func (h *registerHarness) setHandler(handler http.Handler) {
	h.handlerMu.Lock()
	h.handler = handler
	h.handlerMu.Unlock()
}

// registerOpts returns the options that point RegisterAgent at the harness's
// fake API and relay (loopback http is permitted by validateHTTPSOrLoopbackURL).
func (h *registerHarness) registerOpts(extra ...RegisterOption) []RegisterOption {
	base := []RegisterOption{
		WithRegisterBaseURL(h.apiSrv.URL),
	}
	return append(base, extra...)
}

// withClock is a test-only RegisterOption that injects the engine clock, so a
// test can advance time deterministically (e.g. across the OTP resend cooldown)
// without sleeping. The engine reads cfg.clock everywhere it needs "now".
func withClock(clk func() time.Time) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		o.clock = clk
		return nil
	})
}

// primeDeviceKey pre-seeds the fake NHP server with the agent device public key
// the SDK will knock with. RegisterAgent persists the keypair before the first
// network call, so the test reads it from the state file after a first attempt,
// or the harness sets it eagerly by generating the state.
func (h *registerHarness) loadState(t *testing.T) *AgentState {
	t.Helper()
	state, err := h.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	return state
}

// syncDevicePub reads the persisted device public key and hands it to the fake
// NHP server so its responder-role open can verify the header digest. It must be
// called after the keypair is persisted (after the first registration-info
// round trip) and before any REG/OTP is opened. Because the SDK persists the
// keypair before the first HTTP call, the fake service triggers this on the
// registration-info request.
func (h *registerHarness) armDevicePubOnInfo() {
	// Wrap the API handler so the first registration-info call syncs the device
	// pub from the persisted state before the relay ever sees a packet.
	inner := h.svc.handler(h.relaySrv.URL)
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info" {
			if state, err := h.store.LoadAgentState(r.Context()); err == nil {
				if pub, decErr := base64.StdEncoding.DecodeString(state.PublicKeyB64); decErr == nil {
					h.nhp.setExpectDevicePub(pub)
				}
			}
		}
		inner(w, r)
	}))
}

// failingSaveStore wraps an AgentStateStore and fails SaveAgentState the first
// time the predicate matches the state being saved, then delegates normally. It
// is used to inject a persist failure at a specific state transition (the OTP
// request save) without failing the other saves in the flow.
type failingSaveStore struct {
	inner     AgentStateStore
	failWhen  func(*AgentState) bool
	failErr   error
	failsLeft int
	saveCalls atomic.Int32
}

func (s *failingSaveStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *failingSaveStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	s.saveCalls.Add(1)
	if s.failsLeft > 0 && s.failWhen(state) {
		s.failsLeft--
		return s.failErr
	}
	return s.inner.SaveAgentState(ctx, state)
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64 %q: %v", s, err)
	}
	return b
}

// --- tests: bootstrap path (PATH A) ---

func TestRegisterAgent_BootstrapPath_EnrollsAndReturnsClient(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.svc.expectedBearer = "lv_bootstrap_key"
	h.nhp.expectCredential = "lv_bootstrap_key"
	h.armDevicePubOnInfo()

	client, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if client == nil {
		t.Fatal("RegisterAgent returned a nil client")
	}

	state := h.loadState(t)
	if state.RegisteredAt == nil {
		t.Fatal("state not marked registered")
	}
	if state.DeviceAPIKey != "lv_device_secret" {
		t.Fatalf("DeviceAPIKey = %q, want lv_device_secret", state.DeviceAPIKey)
	}
	if state.SchemaVersion != agentStateSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", state.SchemaVersion, agentStateSchemaVersion)
	}
	if !strings.HasPrefix(state.AgentID, "agent-") {
		t.Fatalf("AgentID = %q, want generated agent- prefix", state.AgentID)
	}
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completion calls = %d, want 1", h.svc.completionCalls.Load())
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count = %d, want 1", h.nhp.regCount())
	}
	if h.nhp.otpCount() != 0 {
		t.Fatalf("OTP sends = %d, want 0 on bootstrap path", h.nhp.otpCount())
	}
}

// TestRegisterAgent_MalformedRegisterReplyMapsToTaxonomy is the enrollment-side
// half of the #54 coverage: a byzantine relay answers the NHP_REG with a RAK
// whose header counter does not echo the request. relayknock.Exchange refuses it
// with relayknock.ErrMalformedReply, and RegisterAgent must surface that as the
// ErrRegisterReplyMalformed taxonomy sentinel — not a raw string — while keeping
// the underlying relayknock sentinel matchable. The portal-side half is
// TestNormalizeRelayError_MalformedReplyMapsToClass (unit) in portal_test.go.
func TestRegisterAgent_MalformedRegisterReplyMapsToTaxonomy(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.regReplyCounterOffset = 1 // RAK counter won't echo the REG → mis-correlated
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...)
	if err == nil {
		t.Fatal("RegisterAgent accepted a mis-correlated registration reply, want rejection")
	}
	if !errors.Is(err, ErrRegisterReplyMalformed) {
		t.Errorf("error %v does not match ErrRegisterReplyMalformed; the byzantine-relay reply bypassed the enrollment taxonomy", err)
	}
	if !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Errorf("error %v lost the underlying relayknock.ErrMalformedReply cause", err)
	}
	// The device must not be recorded as registered off a reply Exchange refused.
	if state := h.loadState(t); state.RegisteredAt != nil {
		t.Error("state marked registered despite a refused registration reply")
	}
}

func TestRegisterAgent_FastPath_NoNetworkOnceRegistered(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.expectedBearer = "lv_bootstrap_key"
	h.armDevicePubOnInfo()

	if _, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...); err != nil {
		t.Fatalf("first RegisterAgent: %v", err)
	}
	infoAfterFirst := h.svc.infoCalls.Load()

	client, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("second RegisterAgent: %v", err)
	}
	if got := h.svc.infoCalls.Load(); got != infoAfterFirst {
		t.Fatalf("fast path made %d extra registration-info calls, want 0", got-infoAfterFirst)
	}

	// The fast-path client authorizes from the store: prove Authorize reads the
	// persisted device key without any network.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.test/", http.NoBody)
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("store-backed Authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer lv_device_secret" {
		t.Fatalf("Authorization = %q, want Bearer lv_device_secret", got)
	}
}

// TestRegisterAgent_ConcurrentFreshStoreSetupSerializes exercises the #48
// advisory flock end to end: two RegisterAgent calls race a FRESH shared
// FileAgentState. Without the lock each would generate its own device identity
// and race the atomic save, ending with two enrolled identities where one
// silently wins. With the advisory lock the two setups serialize — the second
// blocks until the first enrolls, then loads the registered state via the fast
// path — so both callers converge on ONE identity. Run under -race, the two
// goroutines share the store, the file, and the fake servers.
func TestRegisterAgent_ConcurrentFreshStoreSetupSerializes(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skipf("advisory flock is a no-op on %s; concurrent fresh-store setup is not serialized there", runtime.GOOS)
	}
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	const goroutines = 2
	var wg sync.WaitGroup
	clients := make([]*Client, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // release together so both hit the fresh store at once
			c, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...)
			clients[idx] = c
			errs[idx] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d RegisterAgent: %v", i, errs[i])
		}
		if clients[i] == nil {
			t.Fatalf("goroutine %d returned a nil client", i)
		}
	}

	// One identity, not two: the persisted state is registered and both callers
	// agree on the same agent id. The serialized second run short-circuits on the
	// fast path, so the server sees exactly one REG.
	state := h.loadState(t)
	if state.RegisteredAt == nil {
		t.Fatal("state not marked registered after concurrent setup")
	}
	if got := h.nhp.regCount(); got != 1 {
		t.Fatalf("REG count = %d, want 1 (the advisory lock should serialize the two setups to a single enrollment)", got)
	}
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completion calls = %d, want 1", h.svc.completionCalls.Load())
	}
}

func TestRegisterAgent_StoreBackedCredentialConcurrentAuthorize(t *testing.T) {
	// The store-backed Client authorizes through CachedCredentials, whose
	// Authorize has a real singleflight (refreshDone channel + mutex). Exercise it
	// concurrently so -race has something meaningful to inspect on the one
	// production path that has cross-goroutine coordination: N goroutines each
	// authorize a fresh request through the SAME provider, and all must succeed
	// with the bearer set.
	h := newRegisterHarness(t)
	h.svc.expectedBearer = "lv_bootstrap_key"
	h.armDevicePubOnInfo()

	client, err := RegisterAgent(context.Background(), "lv_bootstrap_key", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	auths := make([]string, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.test/", http.NoBody)
			if reqErr != nil {
				errs[idx] = reqErr
				return
			}
			<-start // release all goroutines together to maximize contention
			if authErr := client.credentials.Authorize(context.Background(), req); authErr != nil {
				errs[idx] = authErr
				return
			}
			auths[idx] = req.Header.Get("Authorization")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d Authorize: %v", i, errs[i])
		}
		if auths[i] != "Bearer lv_device_secret" {
			t.Fatalf("goroutine %d Authorization = %q, want Bearer lv_device_secret", i, auths[i])
		}
	}
}

func TestRegisterAgent_FastPath_MissingDeviceKeyFailsClosed(t *testing.T) {
	registeredAt := time.Now().UTC()
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-x"
	state.RegisteredAt = &registeredAt
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Host:         "nhp.example.test",
		Port:         62206,
	}
	// No DeviceAPIKey: a registered-but-credential-less state.

	store := memoryAgentStateStore{state: state}
	_, err = RegisterAgent(context.Background(), "lv_key", store)
	if !errors.Is(err, ErrDeviceCredentialMissing) {
		t.Fatalf("RegisterAgent: want ErrDeviceCredentialMissing, got %v", err)
	}
}

// --- tests: account path (PATH B) two-phase OTP ---

func TestRegisterAgent_AccountPath_TwoPhaseOTP(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.svc.expectedBearer = "lv_account_key"
	h.nhp.expectCredential = "123456"
	h.armDevicePubOnInfo()

	// Phase 1: no code -> OTP is sent, state goes otp_pending, *OTPPendingError.
	_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...)
	var pending *OTPPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("phase 1: want *OTPPendingError, got %v", err)
	}
	if !errors.Is(err, ErrOTPPending) {
		t.Fatalf("phase 1: error does not match ErrOTPPending: %v", err)
	}
	if pending.MaskedEmail != "j***@x.com" {
		t.Fatalf("pending MaskedEmail = %q, want j***@x.com", pending.MaskedEmail)
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("OTP sends after phase 1 = %d, want 1", h.nhp.otpCount())
	}
	state := h.loadState(t)
	if state.OTPRequestedAt == nil {
		t.Fatal("phase 1 did not persist OTPRequestedAt (otp_pending)")
	}
	if state.RegisteredAt != nil {
		t.Fatal("phase 1 marked registered too early")
	}

	// Phase 2: supply the code -> REG -> completion -> *Client.
	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("123456"))...)
	if err != nil {
		t.Fatalf("phase 2 RegisterAgent: %v", err)
	}
	if client == nil {
		t.Fatal("phase 2 returned nil client")
	}
	state = h.loadState(t)
	if state.RegisteredAt == nil || state.DeviceAPIKey == "" {
		t.Fatalf("phase 2 state not fully registered: %#v", state)
	}
	if state.OTPRequestedAt != nil {
		t.Fatal("phase 2 did not clear OTPRequestedAt")
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count = %d, want 1", h.nhp.regCount())
	}
}

func TestRegisterAgent_AccountPath_OTPResendCooldown(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	// First pending call sends one OTP.
	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("first call: want ErrOTPPending, got %v", err)
	}
	// Immediate re-run (within cooldown) must NOT re-send.
	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("second call: want ErrOTPPending, got %v", err)
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("OTP sends within cooldown = %d, want 1 (no resend)", h.nhp.otpCount())
	}
}

func TestRegisterAgent_AccountPath_OTPResendAfterCooldown(t *testing.T) {
	// Positive resend case: a long-idle no-code re-run (past the cooldown)
	// dispatches a SECOND code. Uses an injected clock advanced by
	// otpResendCooldown+1s rather than sleeping.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	base := time.Now()
	var mu sync.Mutex
	nowVal := base
	clk := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return nowVal
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		nowVal = nowVal.Add(d)
	}

	// First no-code call: fresh request skips the probe and emits exactly one code.
	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(withClock(clk))...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("first call: want ErrOTPPending, got %v", err)
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("first call OTP sends = %d, want 1", h.nhp.otpCount())
	}

	// Past the cooldown, the resume's crash-recovery probe runs BEFORE the resend,
	// so report the device not-yet-registered (else the fake self-heals to
	// registered and no resend happens). Then the no-code branch re-sends.
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":{"code":"device_not_registered","detail":"not yet"}}`)
			return
		}
		h.svc.handler(h.relaySrv.URL)(w, r)
	}))

	advance(otpResendCooldown + time.Second)

	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(withClock(clk))...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("post-cooldown call: want ErrOTPPending, got %v", err)
	}
	if h.nhp.otpCount() != 2 {
		t.Fatalf("OTP sends after cooldown elapsed = %d, want 2 (a second code was dispatched)", h.nhp.otpCount())
	}
}

func TestRegisterAgent_AccountPath_OTPSavePersistsBeforeSend(t *testing.T) {
	// Anti-spam fence: requestOTP persists OTPRequestedAt BEFORE sending the code.
	// If the persist fails, NO email is dispatched (the caller retries as a
	// still-fresh request), and across the failed attempt + retry exactly ONE code
	// is ultimately sent — no duplicate from a persist that lost the otp_pending
	// marker.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	// Fail the save that records otp_pending (the first save whose state carries
	// OTPRequestedAt) exactly once, then behave normally.
	saveErr := errors.New("injected transient store write failure")
	failing := &failingSaveStore{
		inner:     h.store,
		failWhen:  func(st *AgentState) bool { return st.OTPRequestedAt != nil },
		failErr:   saveErr,
		failsLeft: 1,
	}
	h.store = failing

	// First attempt: the otp_pending persist fails, so no email is sent and the
	// store error surfaces (not *OTPPendingError).
	_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...)
	if !errors.Is(err, saveErr) {
		t.Fatalf("first attempt: want the injected store error, got %v", err)
	}
	if h.nhp.otpCount() != 0 {
		t.Fatalf("first attempt sent %d codes despite the persist failing, want 0", h.nhp.otpCount())
	}
	// The failed persist must not have left otp_pending on disk.
	state := h.loadState(t)
	if state.OTPRequestedAt != nil {
		t.Fatalf("failed OTP persist leaked otp_pending: %#v", state.OTPRequestedAt)
	}

	// Retry: the save now succeeds, exactly one code is dispatched, and it pauses.
	_, err = RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrOTPPending) {
		t.Fatalf("retry: want ErrOTPPending, got %v", err)
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("total codes dispatched across failure+retry = %d, want exactly 1 (no duplicate)", h.nhp.otpCount())
	}
}

func TestRegisterAgent_AccountPath_FreshStoreWithOTPPausesInsteadOfDoomedREG(t *testing.T) {
	// A static WithOTP literal supplied on a FRESH store cannot match the code the
	// same call is about to email, so RegisterAgent must email the code and pause
	// (*OTPPendingError) rather than burn a doomed REG that would fail 52100.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("staleCode"))...)
	if !errors.Is(err, ErrOTPPending) {
		t.Fatalf("fresh-store WithOTP: want ErrOTPPending, got %v", err)
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("OTP sends = %d, want 1 (code emailed for the next run)", h.nhp.otpCount())
	}
	if h.nhp.regCount() != 0 {
		t.Fatalf("REG count = %d, want 0 (no doomed REG on a fresh-store WithOTP)", h.nhp.regCount())
	}
	// The resume with the (now-valid) code proceeds to REG and completes.
	h.nhp.expectCredential = "realCode"
	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("realCode"))...)
	if err != nil {
		t.Fatalf("resume with real code: %v", err)
	}
	if client == nil {
		t.Fatal("nil client on resume")
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count after resume = %d, want 1", h.nhp.regCount())
	}
}

func TestRegisterAgent_CookieChallengeMapsToRetryLater(t *testing.T) {
	// A REG answered with an overload cookie-challenge (NHP_COK) must surface as
	// ErrRegistrationRetryLater, not a generic config error.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.replyREGWithCOK = true
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrRegistrationRetryLater) {
		t.Fatalf("want ErrRegistrationRetryLater on a COK reply, got %v", err)
	}
	if errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("COK must not map to ErrInvalidRegisterConfig: %v", err)
	}
}

func TestRegisterAgent_AccountPath_OTPProvider(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.nhp.expectCredential = "778899"
	h.armDevicePubOnInfo()

	called := false
	provider := func(context.Context) (string, error) {
		called = true
		return "778899", nil
	}
	// A single call with a provider completes on a FRESH store: the SDK requests
	// the code (emails it) first — a code can only be valid after that send — then
	// calls the provider to fetch it, then REG + complete. So exactly one OTP send
	// happens, unlike WithOTP-resume which relies on a prior phase-1 send.
	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTPProvider(provider))...)
	if err != nil {
		t.Fatalf("RegisterAgent with provider: %v", err)
	}
	if !called {
		t.Fatal("OTP provider was not called")
	}
	if client == nil {
		t.Fatal("nil client")
	}
	if h.nhp.otpCount() != 1 {
		t.Fatalf("OTP sends with provider = %d, want 1 (email requested before the provider fetches the code)", h.nhp.otpCount())
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count = %d, want 1", h.nhp.regCount())
	}
	state := h.loadState(t)
	if state.RegisteredAt == nil || state.DeviceAPIKey == "" {
		t.Fatalf("provider flow did not fully register: %#v", state)
	}
}

func TestRegisterAgent_AccountPath_EmptyMaskedEmailFailsFast(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "" // no email on file
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrNoAccountEmail) {
		t.Fatalf("want ErrNoAccountEmail, got %v", err)
	}
	if h.nhp.otpCount() != 0 {
		t.Fatalf("OTP sends = %d, want 0 (fail before any OTP)", h.nhp.otpCount())
	}
}

// --- tests: RAK error mapping over the wire ---

func TestRegisterAgent_AccountPath_RAKErrorsMapToSentinels(t *testing.T) {
	tests := []struct {
		name    string
		errCode string
		want    error
	}{
		{name: "wrong otp", errCode: rakCredentialInvalid, want: ErrOTPIncorrect},
		{name: "expired otp", errCode: rakCredentialExpired, want: ErrOTPExpired},
		{name: "identity conflict", errCode: rakIdentityConflict, want: ErrAgentIdentityConflict},
		{name: "rate limited", errCode: rakRateLimited, want: ErrRegistrationRateLimited},
		{name: "invalid input", errCode: rakInvalidInput, want: ErrRegistrationInvalidInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@x.com"
			h.nhp.rakErrCode = tt.errCode
			h.nhp.rakErrMsg = "scripted denial"
			h.armDevicePubOnInfo()

			// Phase 1: reach otp_pending so the WithOTP resume actually sends REG
			// (a fresh-store WithOTP would pause rather than REG — see the
			// fresh-store guard test).
			if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
				t.Fatalf("prime otp_pending: want ErrOTPPending, got %v", err)
			}

			_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("000000"))...)
			if !errors.Is(err, tt.want) {
				t.Fatalf("errCode %s: want %v, got %v", tt.errCode, tt.want, err)
			}
			// A denied REG must not persist a registered state. (A completion
			// PROBE does run first on the account resume and returns not-registered;
			// what matters is that no device credential was persisted.)
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("REG denial persisted a registered state: %#v", state)
			}
		})
	}
}

func TestRegisterAgent_BootstrapPath_CredentialInvalidMapsToKeyRejected(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.rakErrCode = rakCredentialInvalid // 52100 on bootstrap path => key rejected
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_bad_bootstrap", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("want ErrKeyRejected on bootstrap 52100, got %v", err)
	}
	if errors.Is(err, ErrOTPIncorrect) {
		t.Fatalf("bootstrap 52100 must not map to ErrOTPIncorrect: %v", err)
	}
}

func TestRegisterAgent_BootstrapPath_ConsumedSetupKey(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.rakErrCode = rakBootstrapConsumed // 52108
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_used_setup", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrBootstrapSetupKeyConsumed) {
		t.Fatalf("want ErrBootstrapSetupKeyConsumed on 52108, got %v", err)
	}
}

// TestRegisterAgent_CompletionConsumedSetupKeyIsPathGated fences the path-gated
// completion class: a completion 409 carrying setup_key_consumed maps to
// ErrBootstrapSetupKeyConsumed ONLY on the bootstrap path. The account path
// cannot legitimately consume a one-shot setup key, so the same completion error
// must fall through to the raw wrapped *APIError, never the bootstrap sentinel
// (mirrors how mapRAKError keeps 52100 path-dependent).
func TestRegisterAgent_CompletionConsumedSetupKeyIsPathGated(t *testing.T) {
	t.Run("bootstrap path surfaces the sentinel", func(t *testing.T) {
		h := newRegisterHarness(t)
		h.svc.keyKind = keyKindBootstrap
		h.svc.completionStatus = http.StatusConflict
		h.svc.completionCode = "setup_key_consumed"
		h.armDevicePubOnInfo()

		_, err := RegisterAgent(context.Background(), "lv_setup_once", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrBootstrapSetupKeyConsumed) {
			t.Fatalf("bootstrap completion setup_key_consumed: want ErrBootstrapSetupKeyConsumed, got %v", err)
		}
	})

	t.Run("account path does not surface the sentinel", func(t *testing.T) {
		h := newRegisterHarness(t)
		h.svc.keyKind = keyKindAccount
		h.svc.maskedEmail = "j***@x.com"
		h.armDevicePubOnInfo()

		// Prime otp_pending (this also arms the device pub for the responder open).
		if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
			t.Fatalf("prime otp_pending: want ErrOTPPending, got %v", err)
		}

		// On resume, the crash-recovery PROBE (completion #1) reports the device
		// not-yet-registered so the flow falls through to REG; the REAL completion
		// (#2, post-REG) then returns 409 setup_key_consumed with pathAccount.
		var completionHits atomic.Int32
		h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
				switch completionHits.Add(1) {
				case 1: // probe: not yet registered → fall through to REG
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{"error":{"code":"device_not_registered","detail":"not yet"}}`)
					return
				default: // real completion: consumed-setup-key on the account path
					w.WriteHeader(http.StatusConflict)
					_, _ = fmt.Fprint(w, `{"error":{"code":"setup_key_consumed","detail":"already consumed"}}`)
					return
				}
			}
			h.svc.handler(h.relaySrv.URL)(w, r)
		}))

		_, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("123456"))...)
		if errors.Is(err, ErrBootstrapSetupKeyConsumed) {
			t.Fatalf("account completion setup_key_consumed must NOT map to ErrBootstrapSetupKeyConsumed, got %v", err)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
			t.Fatalf("account path: want the raw wrapped *APIError (409), got %v", err)
		}
		if apiErr.Code != "setup_key_consumed" {
			t.Fatalf("account path APIError code = %q, want setup_key_consumed", apiErr.Code)
		}
		if completionHits.Load() < 2 {
			t.Fatalf("completion hits = %d, want >=2 (probe not-registered, then real completion)", completionHits.Load())
		}
	})
}

func TestRegisterAgent_UnknownRAKCodeIsRegistrationDeny(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.rakErrCode = "59999" // unknown code
	h.nhp.rakErrMsg = "brand new failure"
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_key", h.store, h.registerOpts()...)
	var deny *RegistrationDenyError
	if !errors.As(err, &deny) {
		t.Fatalf("want *RegistrationDenyError for unknown code, got %v", err)
	}
	if deny.ErrCode != "59999" || deny.ErrMsg != "brand new failure" {
		t.Fatalf("deny = %#v", deny)
	}
}

// --- tests: completion 409 already-issued + crash-recovery probe ---

func TestRegisterAgent_Completion409MapsToDeviceCredentialMissing(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.svc.completionStatus = http.StatusConflict
	h.svc.completionCode = "device_key_already_issued"
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrDeviceCredentialMissing) {
		t.Fatalf("want ErrDeviceCredentialMissing on completion 409, got %v", err)
	}
}

func TestRegisterAgent_BareCompletion409IsNotDeviceCredentialMissing(t *testing.T) {
	// A 409 that arrives WITHOUT the structured device_key_already_issued code
	// (e.g. an infra/proxy conflict) must NOT be mapped to the destructive
	// ErrDeviceCredentialMissing ("re-register / takeover") guidance; it surfaces
	// as the raw *APIError instead.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.svc.completionStatus = http.StatusConflict
	h.svc.completionCode = "" // no structured code
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_key", h.store, h.registerOpts()...)
	if errors.Is(err, ErrDeviceCredentialMissing) {
		t.Fatalf("bare 409 must not map to ErrDeviceCredentialMissing, got %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("want raw *APIError 409, got %v", err)
	}
}

func TestRegisterAgent_AccountPath_CrashRecoveryProbeSelfHeals(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	// Simulate a prior run that reached otp_pending: persist that state directly
	// so the resume call has OTPRequestedAt set and the device keypair present.
	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("prime otp_pending: want ErrOTPPending, got %v", err)
	}

	// Model the crash: a prior run's REG succeeded server-side (device enrolled)
	// but the process died before completion. On resume the completion PROBE runs
	// before any code is resolved, so a resume with NO code in hand still
	// self-heals to a registered Client (previously this returned OTPPendingError).
	h.nhp.setEnrolled(true)

	regsBefore := h.nhp.regCount()
	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("no-code resume against an enrolled device should self-heal, got %v", err)
	}
	if client == nil {
		t.Fatal("nil client")
	}
	if h.nhp.regCount() != regsBefore {
		t.Fatalf("resume sent a REG despite a successful completion probe (regs %d -> %d)", regsBefore, h.nhp.regCount())
	}
	if h.svc.completionCalls.Load() < 1 {
		t.Fatalf("completion probe did not run")
	}
	state := h.loadState(t)
	if state.RegisteredAt == nil || state.DeviceAPIKey == "" {
		t.Fatalf("self-heal did not persist a registered state: %#v", state)
	}
}

func TestRegisterAgent_AccountPath_ResumeProbeSkipsProvider(t *testing.T) {
	// Regression fence: on a resume against an already-enrolled device, the
	// completion probe runs BEFORE resolveOTP, so a WithOTPProvider (which may do
	// real work — a mailbox poll) is NOT invoked when the probe can finish.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("prime otp_pending: want ErrOTPPending, got %v", err)
	}
	h.nhp.setEnrolled(true)

	var providerCalls atomic.Int32
	provider := func(context.Context) (string, error) {
		providerCalls.Add(1)
		return "999000", nil
	}
	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTPProvider(provider))...)
	if err != nil {
		t.Fatalf("resume with provider against an enrolled device: %v", err)
	}
	if client == nil {
		t.Fatal("nil client")
	}
	if providerCalls.Load() != 0 {
		t.Fatalf("provider was called %d times on a self-healing resume, want 0", providerCalls.Load())
	}
	if h.nhp.regCount() != 0 {
		t.Fatalf("resume sent a REG despite the probe self-healing (regs=%d)", h.nhp.regCount())
	}
}

// --- tests: server_id agreement ---

func TestRegisterAgent_RejectsServerIDPeerMismatch(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	// Override the handler so registration-info returns a server_id that does NOT
	// match the peer key fingerprint.
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info" {
			resp := registrationInfoResponse{
				KeyKind: keyKindBootstrap,
				KeyID:   "key_test123",
				NHPServerPeer: NHPServerPeerInfo{
					PublicKeyB64: h.nhp.serverPubB64(),
					Host:         "nhp.example.test",
					Port:         62206,
				},
				Relay: registrationRelay{
					BaseURL:  h.relaySrv.URL,
					ServerID: "AAAAAAAAAAA", // wrong (11-char) fingerprint
				},
			}
			writeEnvelope(t, w, resp)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))

	_, err := RegisterAgent(context.Background(), "lv_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("want ErrInvalidRegisterConfig on server_id mismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "server_id") {
		t.Fatalf("error should name server_id: %v", err)
	}
}

func TestRegisterAgent_WithNHPPeerAndRelayURLOverrideWorks(t *testing.T) {
	// The server_id integrity check validates the registration-info RESPONSE's
	// own (server_id, peer) pair, independent of the WithNHPPeer override. With
	// the override pointing at the same fake NHP server, registration completes —
	// proving the override path is not tripped by the integrity assertion.
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	overridePeer := NHPServerPeerInfo{
		PublicKeyB64: h.nhp.serverPubB64(),
		Host:         "nhp.override.test",
		Port:         7777,
	}
	client, err := RegisterAgent(context.Background(), "lv_key", h.store,
		h.registerOpts(WithNHPPeer(overridePeer), WithRelayURL(h.relaySrv.URL))...)
	if err != nil {
		t.Fatalf("RegisterAgent with peer/relay override: %v", err)
	}
	if client == nil {
		t.Fatal("nil client")
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count = %d, want 1 (override relay was used)", h.nhp.regCount())
	}
}

func TestRegisterAgent_AccountPath_ProbeToleratesTransientCompletionFault(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@x.com"
	h.armDevicePubOnInfo()

	// Prime otp_pending.
	if _, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("prime otp_pending: want ErrOTPPending, got %v", err)
	}

	// On resume, make the completion PROBE fault transiently (503) on its first
	// call, then succeed once the device is enrolled by REG. A transient probe
	// fault must NOT abort registration — the flow proceeds to REG.
	var completionHits atomic.Int32
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			if completionHits.Add(1) == 1 {
				// The probe call: transient fault.
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprint(w, `{"error":{"code":"upstream_unavailable","detail":"try again"}}`)
				return
			}
		}
		// registration-info and the real (post-REG) completion go to the fake.
		h.svc.handler(h.relaySrv.URL)(w, r)
	}))

	client, err := RegisterAgent(context.Background(), "lv_account_key", h.store, h.registerOpts(WithOTP("424242"))...)
	if err != nil {
		t.Fatalf("resume despite transient probe fault: %v", err)
	}
	if client == nil {
		t.Fatal("nil client")
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("REG count = %d, want 1 (flow proceeded to REG after transient probe fault)", h.nhp.regCount())
	}
	if completionHits.Load() < 2 {
		t.Fatalf("completion hits = %d, want >=2 (probe faulted, then real completion)", completionHits.Load())
	}
}

func TestRegistrationInfoServerIDMatchesComputedFingerprint(t *testing.T) {
	// The harness's fake service always returns server_id == fingerprint(peer);
	// assert the two are byte-equal so the SDK's assertServerIDMatches is exercised
	// against a real agreement (not just a rejection).
	nhp := newFakeNHPServer(t)
	peerKey := decodeB64(t, nhp.serverPubB64())
	if got, want := nhp.serverID(), relayknock.PubKeyFingerprint(peerKey); got != want {
		t.Fatalf("fake server_id %q != computed fingerprint %q", got, want)
	}
	if len(nhp.serverID()) != relayknock.PubKeyFingerprintLen {
		t.Fatalf("server_id length = %d, want %d", len(nhp.serverID()), relayknock.PubKeyFingerprintLen)
	}
}

// --- tests: option/config validation ---

func TestRegisterAgent_Validation(t *testing.T) {
	store := memoryAgentStateStore{}
	if _, err := RegisterAgent(context.Background(), "", store); !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("empty key: want ErrInvalidRegisterConfig, got %v", err)
	}
	if _, err := RegisterAgent(context.Background(), "lv_key", nil); !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("nil store: want ErrInvalidRegisterConfig, got %v", err)
	}
	if _, err := RegisterAgent(context.Background(), "lv_key", store, WithOTP("123"), WithOTPProvider(func(context.Context) (string, error) { return "x", nil })); !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("both OTP options: want ErrInvalidRegisterConfig, got %v", err)
	}
	if _, err := RegisterAgent(context.Background(), "lv_key", store, WithRegisterBaseURL("ftp://x")); !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("bad base URL: want ErrInvalidRegisterConfig, got %v", err)
	}
	if _, err := RegisterAgent(context.Background(), "lv_key", store, WithDeviceID("")); !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("empty device id: want ErrInvalidRegisterConfig, got %v", err)
	}
}

func TestRegisterAgent_RegistrationInfoUnauthorizedMapsToKeyRejected(t *testing.T) {
	h := newRegisterHarness(t)
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":{"code":"invalid_api_key","detail":"bad key"}}`)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))

	_, err := RegisterAgent(context.Background(), "lv_bad_key", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("want ErrKeyRejected on 401 registration-info, got %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want wrapped *APIError, got %v", err)
	}
}

func TestRegisterAgent_WithTakeoverSetsFlagInREG(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	if _, err := RegisterAgent(context.Background(), "lv_key", h.store,
		h.registerOpts(WithTakeover(), WithRegisterHostname("host-9"), WithRegisterVersion("2.0.1"))...); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	h.nhp.mu.Lock()
	defer h.nhp.mu.Unlock()
	if len(h.nhp.regs) != 1 {
		t.Fatalf("REG count = %d, want 1", len(h.nhp.regs))
	}
	reg := h.nhp.regs[0]
	if !reg.UsrData.Takeover {
		t.Error("REG usrData.takeover = false, want true (WithTakeover)")
	}
	if reg.UsrData.Hostname != "host-9" || reg.UsrData.Version != "2.0.1" {
		t.Errorf("REG usrData = %#v, want hostname/version set", reg.UsrData)
	}
}

func TestOTPPendingError_MessageIsActionable(t *testing.T) {
	e := &OTPPendingError{RequestedAt: time.Now(), MaskedEmail: "j***@x.com"}
	msg := e.Error()
	for _, want := range []string{"j***@x.com", "qurl.WithOTP", "qurl.RegisterAgent", "expire"} {
		if !strings.Contains(msg, want) {
			t.Errorf("OTPPendingError message %q missing %q", msg, want)
		}
	}
	if !errors.Is(e, ErrOTPPending) {
		t.Error("OTPPendingError should match ErrOTPPending")
	}
	// Empty masked email falls back to a generic destination phrase.
	generic := (&OTPPendingError{}).Error()
	if !strings.Contains(generic, "your account email") {
		t.Errorf("empty masked email message %q missing generic fallback", generic)
	}
}

func TestRegisterAgent_DeviceIDMismatchOnFastPath(t *testing.T) {
	registeredAt := time.Now().UTC()
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-original"
	state.RegisteredAt = &registeredAt
	state.DeviceAPIKey = "lv_device_secret"
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Host:         "nhp.example.test",
		Port:         62206,
	}
	store := memoryAgentStateStore{state: state}

	_, err = RegisterAgent(context.Background(), "lv_key", store, WithDeviceID("agent-different"))
	if !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("want ErrInvalidRegisterConfig on device id mismatch, got %v", err)
	}
}

// --- load-path front-door error-class split ---

// TestLoadPath_CorruptKeypairMatchesFrontDoorClass fences the load-path class
// split: a persisted state with a corrupt private key surfaces as the front
// door's own config class — ErrInvalidRegisterConfig for RegisterAgent,
// ErrInvalidBootstrapConfig for BootstrapAgent — not the other verb's class.
func TestLoadPath_CorruptKeypairMatchesFrontDoorClass(t *testing.T) {
	badStates := []struct {
		name string
		priv string
		pub  string
	}{
		{name: "bad base64 priv", priv: "not-base64", pub: "also-bad"},
		{name: "non-x25519 priv", priv: base64.StdEncoding.EncodeToString([]byte("too short")), pub: ""},
		{name: "pub does not match priv", priv: base64.StdEncoding.EncodeToString(make([]byte, 32)), pub: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))},
	}
	for _, bs := range badStates {
		t.Run(bs.name, func(t *testing.T) {
			mkStore := func() memoryAgentStateStore {
				return memoryAgentStateStore{state: &AgentState{PrivateKeyB64: bs.priv, PublicKeyB64: bs.pub}}
			}

			_, rerr := RegisterAgent(context.Background(), "lv_key", mkStore())
			if !errors.Is(rerr, ErrInvalidRegisterConfig) {
				t.Fatalf("RegisterAgent: want ErrInvalidRegisterConfig, got %v", rerr)
			}
			if errors.Is(rerr, ErrInvalidBootstrapConfig) {
				t.Fatalf("RegisterAgent leaked ErrInvalidBootstrapConfig: %v", rerr)
			}

			_, berr := BootstrapAgent(context.Background(), "lv_key", mkStore())
			if !errors.Is(berr, ErrInvalidBootstrapConfig) {
				t.Fatalf("BootstrapAgent: want ErrInvalidBootstrapConfig, got %v", berr)
			}
			if errors.Is(berr, ErrInvalidRegisterConfig) {
				t.Fatalf("BootstrapAgent leaked ErrInvalidRegisterConfig: %v", berr)
			}
		})
	}
}

// TestLoadPath_CorruptStateFileMatchesBothClasses fences the corrupt-file path:
// the store returns the neutral ErrInvalidAgentState, and each front door
// re-wraps it in its own class — so a corrupt file matches BOTH the front-door
// class AND the neutral store sentinel through the wrapped chain.
func TestLoadPath_CorruptStateFileMatchesBothClasses(t *testing.T) {
	newCorruptFileStore := func(t *testing.T) AgentStateStore {
		t.Helper()
		path := filepath.Join(t.TempDir(), "agent-state.json")
		if err := os.WriteFile(path, []byte("{ this is not valid json"), 0o600); err != nil {
			t.Fatalf("write corrupt state: %v", err)
		}
		return FileAgentState(path)
	}

	_, rerr := RegisterAgent(context.Background(), "lv_key", newCorruptFileStore(t))
	if !errors.Is(rerr, ErrInvalidRegisterConfig) {
		t.Fatalf("RegisterAgent corrupt file: want ErrInvalidRegisterConfig, got %v", rerr)
	}
	if !errors.Is(rerr, ErrInvalidAgentState) {
		t.Fatalf("RegisterAgent corrupt file: should still match ErrInvalidAgentState, got %v", rerr)
	}

	_, berr := BootstrapAgent(context.Background(), "lv_key", newCorruptFileStore(t))
	if !errors.Is(berr, ErrInvalidBootstrapConfig) {
		t.Fatalf("BootstrapAgent corrupt file: want ErrInvalidBootstrapConfig, got %v", berr)
	}
	if !errors.Is(berr, ErrInvalidAgentState) {
		t.Fatalf("BootstrapAgent corrupt file: should still match ErrInvalidAgentState, got %v", berr)
	}
}

// TestLoadPath_BadPermsFileMatchesFrontDoorAndPermSentinel fences the insecure
// permissions path: a group-readable state file surfaces the front-door class
// AND still matches ErrInsecureAgentStatePermissions through the wrapped chain.
func TestLoadPath_BadPermsFileMatchesFrontDoorAndPermSentinel(t *testing.T) {
	newBadPermsStore := func(t *testing.T) AgentStateStore {
		t.Helper()
		path := filepath.Join(t.TempDir(), "agent-state.json")
		raw := []byte(`{"private_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatalf("write state: %v", err)
		}
		return FileAgentState(path)
	}

	_, rerr := RegisterAgent(context.Background(), "lv_key", newBadPermsStore(t))
	if !errors.Is(rerr, ErrInvalidRegisterConfig) {
		t.Fatalf("RegisterAgent bad perms: want ErrInvalidRegisterConfig, got %v", rerr)
	}
	if !errors.Is(rerr, ErrInsecureAgentStatePermissions) {
		t.Fatalf("RegisterAgent bad perms: should still match ErrInsecureAgentStatePermissions, got %v", rerr)
	}

	_, berr := BootstrapAgent(context.Background(), "lv_key", newBadPermsStore(t))
	if !errors.Is(berr, ErrInvalidBootstrapConfig) {
		t.Fatalf("BootstrapAgent bad perms: want ErrInvalidBootstrapConfig, got %v", berr)
	}
	if !errors.Is(berr, ErrInsecureAgentStatePermissions) {
		t.Fatalf("BootstrapAgent bad perms: should still match ErrInsecureAgentStatePermissions, got %v", berr)
	}
}

// TestResponseValidators_UseFrontDoorErrorClass fences the wire-validator class
// split: registrationInfoResponse.validate and completionResponse.validate wrap a
// malformed response in the front-door class they are handed (fetchRegistrationInfo
// and postCompletion pass cfg.invalidConfigErr), so a BootstrapAgent call against a
// malformed registration-info/completion response surfaces ErrInvalidBootstrapConfig
// rather than leaking the register class — and vice versa.
func TestResponseValidators_UseFrontDoorErrorClass(t *testing.T) {
	now := time.Now()
	classes := []struct {
		name  string
		kind  error
		other error
	}{
		{name: "register", kind: ErrInvalidRegisterConfig, other: ErrInvalidBootstrapConfig},
		{name: "bootstrap", kind: ErrInvalidBootstrapConfig, other: ErrInvalidRegisterConfig},
	}
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			// Malformed registration-info (unknown key_kind).
			infoErr := registrationInfoResponse{KeyKind: "bogus"}.validate(now, c.kind)
			if !errors.Is(infoErr, c.kind) {
				t.Fatalf("registration-info validate: want %v, got %v", c.kind, infoErr)
			}
			if errors.Is(infoErr, c.other) {
				t.Fatalf("registration-info validate leaked %v: %v", c.other, infoErr)
			}
			// Malformed completion (missing agent_id).
			compErr := completionResponse{}.validate(now, c.kind)
			if !errors.Is(compErr, c.kind) {
				t.Fatalf("completion validate: want %v, got %v", c.kind, compErr)
			}
			if errors.Is(compErr, c.other) {
				t.Fatalf("completion validate leaked %v: %v", c.other, compErr)
			}
		})
	}
}
