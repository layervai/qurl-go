package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// runtimePublicResolver preserves the production transport's public-address
// check. runtimeLoopbackDialer maps the synthetic public answer to the local UDP
// responder, so tests exercise the full resolver and transport path without
// weakening the SSRF boundary.
type runtimePublicResolver struct{}

func (runtimePublicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type countingRuntimeResolver struct{ calls atomic.Int32 }

func (r *countingRuntimeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type runtimeLoopbackDialer struct{}

func (runtimeLoopbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}

func runtimeUDPOptions() []RegisterOption {
	return []RegisterOption{
		WithAgentRuntimeUDPResolver(runtimePublicResolver{}),
		WithAgentRuntimeUDPDialer(runtimeLoopbackDialer{}),
		WithAgentRuntimeUDPBounds(2*time.Second, 1),
	}
}

func runtimeRefreshOptions(h *registerHarness) []AgentRuntimeOption {
	return []AgentRuntimeOption{
		WithAgentClientBaseURL(h.apiSrv.URL),
		WithAgentClientHTTPClient(h.apiSrv.Client()),
		WithAgentRuntimeUDPResolver(runtimePublicResolver{}),
		WithAgentRuntimeUDPDialer(runtimeLoopbackDialer{}),
		WithAgentRuntimeUDPBounds(2*time.Second, 1),
	}
}

type nativeRegistrationUDPServer struct {
	t    *testing.T
	nhp  *fakeNHPServer
	conn *net.UDPConn
	done chan struct{}
}

func startNativeRegistrationUDPServer(t *testing.T, nhp *fakeNHPServer) *nativeRegistrationUDPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen native registration UDP: %v", err)
	}
	server := &nativeRegistrationUDPServer{t: t, nhp: nhp, conn: conn, done: make(chan struct{})}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("native registration UDP server did not stop")
		}
	})
	return server
}

func (s *nativeRegistrationUDPServer) port() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}

func (s *nativeRegistrationUDPServer) serve() {
	defer close(s.done)
	packet := make([]byte, 1<<16)
	for {
		n, remote, err := s.conn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		reply, devicePub, err := s.nhp.openAny(packet[:n])
		if err != nil {
			s.t.Errorf("open native registration packet: %v", err)
			continue
		}
		if reply.Type != relayknock.TypeRegister {
			s.t.Errorf("native registration packet type = %d, want REG", reply.Type)
			continue
		}
		var body registerRequestBody
		if err := json.Unmarshal(reply.Body, &body); err != nil {
			s.t.Errorf("decode native registration body: %v", err)
			continue
		}
		s.nhp.mu.Lock()
		s.nhp.regs = append(s.nhp.regs, body)
		errCode, errMsg := s.nhp.rakErrCode, s.nhp.rakErrMsg
		if errCode == "" || errCode == rakSuccess {
			s.nhp.enrolled = true
		}
		s.nhp.mu.Unlock()
		ackBody, err := json.Marshal(registerAckBody{ErrCode: errCode, ErrMsg: errMsg, AspID: agentAspID})
		if err != nil {
			s.t.Errorf("marshal native RAK: %v", err)
			continue
		}
		rak, err := relayknocktest.BuildReply(relayknock.TypeRegisterAck, &relayknock.KnockInputs{
			DeviceStaticPriv: s.nhp.serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    scriptedEphemeral(0x7a),
			TimestampNanos:   uint64(time.Now().UnixNano()),
			Counter:          reply.Counter,
			Preamble:         0x3c4d5e6f,
			Body:             ackBody,
		})
		if err != nil {
			s.t.Errorf("build native RAK: %v", err)
			continue
		}
		if _, err := s.conn.WriteToUDP(rak, remote); err != nil {
			s.t.Errorf("write native RAK: %v", err)
		}
	}
}

type assignmentRequestRecord struct {
	Authorization  string
	AgentID        string
	IdempotencyKey string
}

type assignmentRecorder struct {
	mu      sync.Mutex
	records []assignmentRequestRecord
}

func (r *assignmentRecorder) append(record assignmentRequestRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record)
}

func (r *assignmentRecorder) snapshot() []assignmentRequestRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]assignmentRequestRecord(nil), r.records...)
}

func installRuntimeAssignmentHandler(t *testing.T, h *registerHarness, port int) *assignmentRecorder {
	t.Helper()
	return installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		writeEnvelope(t, w, runtimeAssignment(h, body.AgentID, port))
	})
}

func runtimeAssignment(h *registerHarness, agentID string, port int) AgentAssignment {
	return AgentAssignment{
		AgentID:              agentID,
		CellID:               "cell0",
		AssignmentGeneration: 1,
		EndpointRevision:     1,
		LeaseExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		Endpoint: NHPUDPEndpoint{
			Host:               "cell0.nhp.layerv.ai",
			Port:               port,
			ServerPublicKeyB64: h.nhp.serverPubB64(),
		},
	}
}

func installRuntimeAssignmentHandlerWith(t *testing.T, h *registerHarness, respond func(int, http.ResponseWriter, *http.Request, assignmentRequestBody)) *assignmentRecorder {
	t.Helper()
	recorder := &assignmentRecorder{}
	enrollmentHandler := h.svc.handler(h.relaySrv.URL)
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != assignmentEndpointPath {
			enrollmentHandler.ServeHTTP(w, req)
			return
		}
		var body assignmentRequestBody
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, fmt.Sprintf("decode assignment: %v", err), http.StatusBadRequest)
			return
		}
		record := assignmentRequestRecord{Authorization: req.Header.Get("Authorization"), AgentID: body.AgentID, IdempotencyKey: req.Header.Get("Idempotency-Key")}
		recorder.append(record)
		respond(len(recorder.snapshot()), w, req, body)
	}))
	return recorder
}

type runtimeCountingStore struct {
	inner AgentStateStore
	loads atomic.Int32
	saves atomic.Int32
}

func (s *runtimeCountingStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	s.loads.Add(1)
	return s.inner.LoadAgentState(ctx)
}

func (s *runtimeCountingStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	s.saves.Add(1)
	return s.inner.SaveAgentState(ctx, state)
}

func bindPersistedNativeAssignment(t *testing.T, h *registerHarness, port int, lease time.Time) *AgentState {
	t.Helper()
	state := h.loadState(t)
	state.Assignment = &AgentAssignment{
		AgentID:              state.AgentID,
		CellID:               "cell0",
		AssignmentGeneration: 1,
		EndpointRevision:     1,
		LeaseExpiresAt:       lease.UTC(),
		Endpoint: NHPUDPEndpoint{
			Host:               "cell0.nhp.layerv.ai",
			Port:               port,
			ServerPublicKeyB64: h.nhp.serverPubB64(),
		},
	}
	state.NHPPeer = assignmentPeer(state.Assignment)
	if err := h.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save persisted native assignment: %v", err)
	}
	return state
}

func TestRefreshAgentRegistration_UsesOnlyStoredDeviceCredentialAndOneLoad(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	wantState := bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	assignmentRequests := installRuntimeAssignmentHandler(t, h, udpServer.port())
	infoCalls := h.svc.infoCalls.Load()
	completionCalls := h.svc.completionCalls.Load()
	regCount := h.nhp.regCount()
	store := &runtimeCountingStore{inner: h.store}

	client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	defer binding.Destroy()
	if store.loads.Load() != 1 || store.saves.Load() != 1 {
		t.Fatalf("refresh store loads/saves = %d/%d, want 1/1", store.loads.Load(), store.saves.Load())
	}
	requests := assignmentRequests.snapshot()
	if len(requests) != 1 {
		t.Fatalf("assignment requests = %#v, want exactly one", requests)
	}
	if requests[0].Authorization != "Bearer "+wantState.DeviceAPIKey || requests[0].AgentID != wantState.AgentID {
		t.Fatalf("assignment request = %#v, want stored agent id + device credential", requests[0])
	}
	if requests[0].IdempotencyKey != "" {
		t.Fatalf("ordinary assignment refresh emitted Idempotency-Key %q", requests[0].IdempotencyKey)
	}
	if h.svc.infoCalls.Load() != infoCalls || h.svc.completionCalls.Load() != completionCalls {
		t.Fatalf("ordinary refresh called registration-info/completion: info %d->%d completion %d->%d", infoCalls, h.svc.infoCalls.Load(), completionCalls, h.svc.completionCalls.Load())
	}
	if h.nhp.regCount() != regCount+1 {
		t.Fatalf("native REG count = %d, want %d", h.nhp.regCount(), regCount+1)
	}
	h.nhp.mu.Lock()
	lastREG := h.nhp.regs[len(h.nhp.regs)-1]
	h.nhp.mu.Unlock()
	if lastREG.UsrID != wantState.DeviceAPIKeyID || lastREG.OTP != wantState.DeviceAPIKey {
		t.Fatalf("native durable REG credential pair = usrId %q / otp %q", lastREG.UsrID, lastREG.OTP)
	}
	if lastREG.UsrID == wantState.KeyID {
		t.Fatalf("native durable REG reused enrollment key id %q", wantState.KeyID)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.apiSrv.URL+"/v1/resources", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.credentials.Authorize(context.Background(), request); err != nil {
		t.Fatalf("authorize primed runtime client: %v", err)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+wantState.DeviceAPIKey {
		t.Fatalf("primed runtime Authorization = %q", got)
	}
	if store.loads.Load() != 1 {
		t.Fatalf("first resource authorization reloaded store: loads = %d", store.loads.Load())
	}
	if binding.DeviceAPIKeyID != wantState.DeviceAPIKeyID || binding.CellID != "cell0" || binding.AssignmentGeneration != 1 {
		t.Fatalf("refreshed binding = %s", binding)
	}
}

func TestRefreshAgentRegistration_ValidatesPersistedAssignmentBeforeHTTP(t *testing.T) {
	tests := []struct {
		name string
		edit func(*AgentState)
		want error
	}{
		{name: "missing assignment", edit: func(s *AgentState) { s.Assignment = nil }, want: ErrAssignmentInvalidResponse},
		{name: "missing device key id", edit: func(s *AgentState) { s.DeviceAPIKeyID = "" }, want: ErrCredentialRecoveryRequired},
		{name: "non LayerV host", edit: func(s *AgentState) { s.Assignment.Endpoint.Host = "cell0.example.com" }, want: ErrAssignmentInvalidResponse},
		{name: "zero lease", edit: func(s *AgentState) { s.Assignment.LeaseExpiresAt = time.Time{} }, want: ErrAssignmentInvalidResponse},
		{name: "invalid server key", edit: func(s *AgentState) { s.Assignment.Endpoint.ServerPublicKeyB64 = "not-base64" }, want: ErrAssignmentInvalidResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := registeredHarness(t)
			state := h.loadState(t)
			tt.edit(state)
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			var httpCalls atomic.Int32
			refusing := doerFunc(func(*http.Request) (*http.Response, error) {
				httpCalls.Add(1)
				return nil, errors.New("unexpected assignment HTTP")
			})
			store := &runtimeCountingStore{inner: h.store}
			client, binding, err := RefreshAgentRegistration(context.Background(), store,
				WithAgentClientBaseURL("https://api.layerv.test"),
				WithAgentClientHTTPClient(refusing),
			)
			if client != nil || binding != nil || !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, tt.want) {
				t.Fatalf("malformed persisted assignment result = client %v binding %v err %v", client, binding, err)
			}
			if store.loads.Load() != 1 || store.saves.Load() != 0 || httpCalls.Load() != 0 {
				t.Fatalf("loads/saves/http = %d/%d/%d, want 1/0/0", store.loads.Load(), store.saves.Load(), httpCalls.Load())
			}
		})
	}
}

func TestRefreshAgentRegistration_RejectsAssignmentDiscontinuityBeforeUDPOrSave(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AgentAssignment)
		wantErr error
	}{
		{name: "cell changed", mutate: func(a *AgentAssignment) { a.CellID = "cell1" }, wantErr: ErrAssignmentReassignmentRequired},
		{name: "generation changed", mutate: func(a *AgentAssignment) { a.AssignmentGeneration = 2 }, wantErr: ErrAssignmentReassignmentRequired},
		{name: "endpoint revision regressed", mutate: func(a *AgentAssignment) { a.EndpointRevision = 0 }, wantErr: ErrAssignmentInvalidResponse},
		{name: "endpoint changed without revision", mutate: func(a *AgentAssignment) { a.Endpoint.Host = "cell0-rotated.nhp.layerv.ai" }, wantErr: ErrAssignmentInvalidResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := registeredHarness(t)
			udpServer := startNativeRegistrationUDPServer(t, h.nhp)
			bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
			regCount := h.nhp.regCount()
			installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
				assignment := runtimeAssignment(h, body.AgentID, udpServer.port())
				tt.mutate(&assignment)
				writeEnvelope(t, w, assignment)
			})
			store := &runtimeCountingStore{inner: h.store}
			client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
			if client != nil || binding != nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("discontinuity result = client %v binding %v err %v, want %v", client, binding, err, tt.wantErr)
			}
			if store.loads.Load() != 1 || store.saves.Load() != 0 || h.nhp.regCount() != regCount {
				t.Fatalf("loads/saves/REG = %d/%d/%d, want 1/0/%d", store.loads.Load(), store.saves.Load(), h.nhp.regCount(), regCount)
			}
			if errors.Is(tt.wantErr, ErrAssignmentReassignmentRequired) {
				var changed *AgentAssignmentChangedError
				if !errors.As(err, &changed) || changed.PersistedCellID != "cell0" || changed.PersistedGeneration != 1 {
					t.Fatalf("typed reassignment error = %#v", changed)
				}
			}
		})
	}
}

func TestRefreshAgentRegistration_AdoptsEndpointRevisionAndRefreshesExpiredLease(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(-time.Hour))
	installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		assignment := runtimeAssignment(h, body.AgentID, udpServer.port())
		assignment.EndpointRevision = 2
		assignment.Endpoint.Host = "cell0-rotated.nhp.layerv.ai"
		writeEnvelope(t, w, assignment)
	})

	client, binding, err := RefreshAgentRegistration(context.Background(), h.store, runtimeRefreshOptions(h)...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	defer binding.Destroy()
	if client == nil || binding.EndpointRevision != 2 || binding.NHPUDPEndpoint.Host != "cell0-rotated.nhp.layerv.ai" {
		t.Fatalf("rotated runtime result = client %v binding %s", client, binding)
	}
	persisted := h.loadState(t)
	if persisted.Assignment.EndpointRevision != 2 || persisted.Assignment.Endpoint.Host != binding.NHPUDPEndpoint.Host || persisted.Assignment.LeaseExpired(time.Now()) {
		t.Fatalf("persisted rotated assignment = %#v", persisted.Assignment)
	}
}

func TestRefreshAgentRegistration_SaveFailureIsRetryableBindingPersistenceFailure(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	original := bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	installRuntimeAssignmentHandler(t, h, udpServer.port())
	regCount := h.nhp.regCount()
	saveErr := errors.New("state volume unavailable")
	store := &failingSaveStore{
		inner:     h.store,
		failWhen:  func(*AgentState) bool { return true },
		failErr:   saveErr,
		failsLeft: 1,
	}

	client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
	if client != nil || binding != nil || !errors.Is(err, ErrAgentBindingPersistence) || !errors.Is(err, saveErr) {
		t.Fatalf("save failure result = client %v binding %v err %v", client, binding, err)
	}
	if h.nhp.regCount() != regCount+1 || h.svc.completionCalls.Load() != 1 {
		t.Fatalf("save failure REG/completion counts = %d/%d, want %d/1", h.nhp.regCount(), h.svc.completionCalls.Load(), regCount+1)
	}
	persisted := h.loadState(t)
	if !persisted.Assignment.LeaseExpiresAt.Equal(original.Assignment.LeaseExpiresAt) || persisted.DeviceAPIKey != original.DeviceAPIKey || persisted.DeviceAPIKeyID != original.DeviceAPIKeyID {
		t.Fatal("failed binding save mutated the durable assignment or device credential pair")
	}
}

func TestRefreshAgentRegistration_Ordinary401IsTerminalWithoutRetryOrUDP(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	requests := installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, _ assignmentRequestBody) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"code":"api_key_invalid","detail":"device key not visible"}}`)
	})
	var sleeps atomic.Int32
	regCount := h.nhp.regCount()
	store := &runtimeCountingStore{inner: h.store}
	opts := runtimeRefreshOptions(h)
	opts = append(opts, withAgentRuntimeSleep(func(context.Context, time.Duration) error {
		sleeps.Add(1)
		return nil
	}))

	client, binding, err := RefreshAgentRegistration(context.Background(), store, opts...)
	if client != nil || binding != nil || !errors.Is(err, ErrAssignmentForbidden) {
		t.Fatalf("ordinary 401 result = client %v binding %v err %v", client, binding, err)
	}
	if len(requests.snapshot()) != 1 || sleeps.Load() != 0 || h.nhp.regCount() != regCount || store.saves.Load() != 0 {
		t.Fatalf("ordinary 401 requests/sleeps/REG/saves = %d/%d/%d/%d", len(requests.snapshot()), sleeps.Load(), h.nhp.regCount(), store.saves.Load())
	}
}

func TestRefreshAgentRegistration_503UsesBoundedDeviceKeyBudgetThenRequiresRecovery(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	state := bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	requests := installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, _ assignmentRequestBody) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":{"code":"cell_assignment_unavailable","detail":"authority unavailable"}}`)
	})
	now := time.Now().UTC()
	var slept []time.Duration
	regCount := h.nhp.regCount()
	store := &runtimeCountingStore{inner: h.store}
	opts := runtimeRefreshOptions(h)
	opts = append(opts,
		WithAgentRuntimeAssignmentRetryBudget(3, 10*time.Second),
		withAgentRuntimeClock(func() time.Time { return now }),
		withAgentRuntimeJitter(func() float64 { return 0 }),
		withAgentRuntimeSleep(func(_ context.Context, delay time.Duration) error {
			slept = append(slept, delay)
			now = now.Add(delay)
			return nil
		}),
	)

	client, binding, err := RefreshAgentRegistration(context.Background(), store, opts...)
	if client != nil || binding != nil || !errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("503 exhaustion result = client %v binding %v err %v", client, binding, err)
	}
	gotRequests := requests.snapshot()
	if len(gotRequests) != 3 || fmt.Sprint(slept) != fmt.Sprint([]time.Duration{time.Second, time.Second}) {
		t.Fatalf("503 requests/sleeps = %d/%v, want 3/[1s 1s]", len(gotRequests), slept)
	}
	for _, request := range gotRequests {
		if request.Authorization != "Bearer "+state.DeviceAPIKey || request.IdempotencyKey != "" {
			t.Fatalf("503 retry request used wrong credential or idempotency header: %#v", request)
		}
	}
	if store.loads.Load() != 1 || store.saves.Load() != 0 || h.nhp.regCount() != regCount {
		t.Fatalf("503 loads/saves/REG = %d/%d/%d, want 1/0/%d", store.loads.Load(), store.saves.Load(), h.nhp.regCount(), regCount)
	}
}

func TestRegisterAgentRuntime_PostMint401RetryIsExactFiniteAndNeverRepeatsCompletion(t *testing.T) {
	tests := []struct {
		name          string
		misses        int
		code          string
		wantSuccess   bool
		wantRequests  int
		wantSleeps    []time.Duration
		advanceOnMiss time.Duration
	}{
		{name: "eventual visibility", misses: 2, code: assignmentCodeAPIKeyInvalid, wantSuccess: true, wantRequests: 4, wantSleeps: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}},
		{name: "different 401 code is terminal", misses: 1, code: "device_key_revoked", wantRequests: 2},
		{name: "attempt budget exhausted", misses: postMintVisibilityMaxAttempts, code: assignmentCodeAPIKeyInvalid, wantRequests: 5, wantSleeps: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}},
		{name: "elapsed budget exhausted", misses: 1, code: assignmentCodeAPIKeyInvalid, wantRequests: 2, advanceOnMiss: postMintVisibilityBudget + time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newFreshCountingRegisterHarness(t)
			h.svc.keyID = "key_enrollment01"
			udpServer := startNativeRegistrationUDPServer(t, h.nhp)
			baseNow := time.Now().UTC()
			var clockOffset atomic.Int64
			assignmentRequests := installRuntimeAssignmentHandlerWith(t, h, func(call int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
				// The first assignment uses the enrollment credential and must
				// succeed before native REG. Only post-completion device-key calls
				// model the eventually-consistent visibility edge.
				if call > 1 && call <= tt.misses+1 {
					clockOffset.Store(tt.advanceOnMiss.Nanoseconds())
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"detail":"scripted post-mint lookup"}}`, tt.code)
					return
				}
				writeEnvelope(t, w, runtimeAssignment(h, body.AgentID, udpServer.port()))
			})
			var slept []time.Duration
			runtimeOpts := runtimeUDPOptions()
			runtimeOpts = append(runtimeOpts,
				WithAgentClientBaseURL(h.apiSrv.URL),
				WithAgentClientHTTPClient(h.apiSrv.Client()),
				withAgentRuntimeClock(func() time.Time { return baseNow.Add(time.Duration(clockOffset.Load())) }),
				withAgentRuntimeSleep(func(_ context.Context, delay time.Duration) error {
					slept = append(slept, delay)
					clockOffset.Add(delay.Nanoseconds())
					return nil
				}),
			)

			client, binding, err := RegisterAgentRuntime(context.Background(), "lv_enroll", h.store, h.registerOpts(runtimeOpts...)...)
			if tt.wantSuccess {
				if err != nil || client == nil || binding == nil {
					t.Fatalf("post-mint visibility result = client %v binding %v err %v", client, binding, err)
				}
				binding.Destroy()
			} else {
				if client != nil || binding != nil || !errors.Is(err, ErrAssignmentForbidden) {
					t.Fatalf("post-mint terminal result = client %v binding %v err %v", client, binding, err)
				}
			}
			if got := len(assignmentRequests.snapshot()); got != tt.wantRequests {
				t.Fatalf("assignment requests = %d, want %d", got, tt.wantRequests)
			}
			if fmt.Sprint(slept) != fmt.Sprint(tt.wantSleeps) {
				t.Fatalf("post-mint sleeps = %v, want %v", slept, tt.wantSleeps)
			}
			requests := assignmentRequests.snapshot()
			if requests[0].Authorization != "Bearer lv_enroll" {
				t.Fatalf("initial assignment authorization = %q", requests[0].Authorization)
			}
			for _, request := range requests[1:] {
				if request.Authorization != "Bearer lv_device_secret" {
					t.Fatalf("post-mint assignment authorization = %q", request.Authorization)
				}
			}
			if h.svc.completionCalls.Load() != 1 || h.nhp.regCount() != 1 {
				t.Fatalf("completion/native REG counts = %d/%d, want 1/1", h.svc.completionCalls.Load(), h.nhp.regCount())
			}
			state := h.loadState(t)
			if state.RegisteredAt == nil || state.DeviceAPIKeyID != "key_device000001" || state.DeviceAPIKey != "lv_device_secret" {
				t.Fatal("completion credential pair was not durably saved before post-mint confirmation")
			}
			if !tt.wantSuccess {
				// A retry reopens the already-completed local state. It must never
				// dispatch completion again after the first call's terminal/ambiguous
				// post-mint result.
				reopened, reopenedBinding, reopenErr := RegisterAgentRuntime(context.Background(), "ignored", h.store, h.registerOpts(runtimeOpts...)...)
				if reopenErr != nil || reopened == nil || reopenedBinding == nil {
					t.Fatalf("reopen completed state: client %v binding %v err %v", reopened, reopenedBinding, reopenErr)
				}
				reopenedBinding.Destroy()
				if h.svc.completionCalls.Load() != 1 {
					t.Fatalf("completed-state reopen repeated completion: calls = %d", h.svc.completionCalls.Load())
				}
			}
		})
	}
}

type nativeKnockVectorServer struct {
	t      *testing.T
	nhp    *fakeNHPServer
	vector conformance.AgentKnockReplyCase
	conn   *net.UDPConn
	done   chan struct{}

	mu          sync.Mutex
	requestBody []byte
}

func startNativeKnockVectorServer(t *testing.T, nhp *fakeNHPServer, vector conformance.AgentKnockReplyCase) *nativeKnockVectorServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen native knock UDP: %v", err)
	}
	server := &nativeKnockVectorServer{t: t, nhp: nhp, vector: vector, conn: conn, done: make(chan struct{})}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("native knock vector server did not stop")
		}
	})
	return server
}

func (s *nativeKnockVectorServer) port() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}

func (s *nativeKnockVectorServer) recordedBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.requestBody...)
}

func (s *nativeKnockVectorServer) serve() {
	defer close(s.done)
	packet := make([]byte, 1<<16)
	for {
		n, remote, err := s.conn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		request, devicePub, err := s.nhp.openAny(packet[:n])
		if err != nil {
			s.t.Errorf("open native knock packet: %v", err)
			continue
		}
		if request.Type != relayknock.TypeKnock {
			s.t.Errorf("native knock packet type = %d, want KNK", request.Type)
			continue
		}
		s.mu.Lock()
		s.requestBody = append(s.requestBody[:0], request.Body...)
		s.mu.Unlock()

		requestVectorCounter, err := strconv.ParseUint(s.vector.RequestCounter, 10, 64)
		if err != nil {
			s.t.Errorf("parse conformance request counter: %v", err)
			continue
		}
		replyVectorCounter, err := strconv.ParseUint(s.vector.ReplyCounter, 10, 64)
		if err != nil {
			s.t.Errorf("parse conformance reply counter: %v", err)
			continue
		}
		counter := request.Counter
		switch {
		case replyVectorCounter > requestVectorCounter:
			counter += replyVectorCounter - requestVectorCounter
		case replyVectorCounter < requestVectorCounter:
			counter -= requestVectorCounter - replyVectorCounter
		}
		replyPacket, err := relayknocktest.BuildReply(s.vector.ReplyType, &relayknock.KnockInputs{
			DeviceStaticPriv: s.nhp.serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    scriptedEphemeral(0x6c),
			TimestampNanos:   uint64(time.Now().UnixNano()),
			Counter:          counter,
			Preamble:         0x4d5e6f70,
			Body:             []byte(s.vector.BodyJSON),
		})
		if err != nil {
			s.t.Errorf("build conformance native knock reply: %v", err)
			continue
		}
		if _, err := s.conn.WriteToUDP(replyPacket, remote); err != nil {
			s.t.Errorf("write conformance native knock reply: %v", err)
		}
	}
}

func TestKnockRegisteredAgent_ConsumesQURLConformanceReplyVectorsThroughNativeUDP(t *testing.T) {
	vectors, err := conformance.AgentKnockApplication()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-knock application vectors: %v", err)
	}
	fields := vectors.Request.Fields
	for _, vector := range vectors.ReplyCases {
		t.Run(vector.Name, func(t *testing.T) {
			h := registeredHarness(t)
			server := startNativeKnockVectorServer(t, h.nhp, vector)
			state := bindPersistedNativeAssignment(t, h, server.port(), time.Now().Add(time.Hour))
			state.AgentID = fields.DeviceID
			state.Assignment.AgentID = fields.DeviceID
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			_, binding, err := OpenRegisteredAgentRuntime(context.Background(), h.store)
			if err != nil {
				t.Fatalf("OpenRegisteredAgentRuntime: %v", err)
			}
			defer binding.Destroy()
			privateKey := binding.TakeDeviceStaticPrivateKey()
			defer wipeBytes(privateKey)
			result, err := KnockRegisteredAgent(context.Background(), binding, privateKey, fields.KnockResourceID, NativeKnockOptions{RunID: fields.RunID},
				WithAgentRuntimeUDPResolver(runtimePublicResolver{}),
				WithAgentRuntimeUDPDialer(runtimeLoopbackDialer{}),
				WithAgentRuntimeUDPBounds(2*time.Second, 1),
			)
			if got := string(server.recordedBody()); got != vectors.Request.BodyJSON {
				t.Fatalf("native knock request body mismatch:\n got=%s\nwant=%s", got, vectors.Request.BodyJSON)
			}
			switch vector.Outcome {
			case conformance.AgentKnockOutcomeSuccess:
				if err != nil || result == nil {
					t.Fatalf("success vector result = %#v err %v", result, err)
				}
				if result.ACToken != "ac-token-conformance-01" || result.ResourceHost != "frps.sandbox.example:7000" || result.OpenTime != 900 || result.AgentAddr != "203.0.113.9:49152" {
					t.Fatalf("success vector result = %#v", result)
				}
			case conformance.AgentKnockOutcomeDeny:
				var deny *ServerDenyError
				if result != nil || !errors.As(err, &deny) || deny.ErrCode != "52004" {
					t.Fatalf("deny vector result = %#v err %v", result, err)
				}
			case conformance.AgentKnockOutcomeRetry:
				if result != nil || !errors.Is(err, ErrServerOverloaded) {
					t.Fatalf("retry vector result = %#v err %v", result, err)
				}
			case conformance.AgentKnockOutcomeReject:
				if result != nil || !errors.Is(err, ErrMalformedReply) {
					t.Fatalf("reject class %q result = %#v err %v", vector.RejectClass, result, err)
				}
			default:
				t.Fatalf("unknown conformance outcome %q", vector.Outcome)
			}
		})
	}
}

func TestKnockRegisteredAgent_InvalidRunIDOrExpiredLeaseFailsBeforeDNS(t *testing.T) {
	h := registeredHarness(t)
	state := h.loadState(t)
	_, binding, err := OpenRegisteredAgentRuntime(context.Background(), h.store)
	if err != nil {
		t.Fatalf("OpenRegisteredAgentRuntime: %v", err)
	}
	defer binding.Destroy()
	privateKey := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(privateKey)

	t.Run("invalid RunID", func(t *testing.T) {
		resolver := &countingRuntimeResolver{}
		result, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "connector-01", NativeKnockOptions{RunID: "NOT-CANONICAL"},
			WithAgentRuntimeUDPResolver(resolver),
		)
		if result != nil || !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrInvalidCycleRunID) {
			t.Fatalf("invalid RunID result = %#v err %v", result, err)
		}
		if resolver.calls.Load() != 0 {
			t.Fatalf("invalid RunID performed %d DNS lookups", resolver.calls.Load())
		}
	})

	t.Run("expired lease", func(t *testing.T) {
		resolver := &countingRuntimeResolver{}
		result, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "connector-01", NativeKnockOptions{RunID: "0123456789abcdef"},
			WithAgentRuntimeUDPResolver(resolver),
			withAgentRuntimeClock(func() time.Time { return state.Assignment.LeaseExpiresAt.Add(time.Nanosecond) }),
		)
		if result != nil || !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrAssignmentInvalidResponse) {
			t.Fatalf("expired lease result = %#v err %v", result, err)
		}
		if resolver.calls.Load() != 0 {
			t.Fatalf("expired lease performed %d DNS lookups", resolver.calls.Load())
		}
	})
}
