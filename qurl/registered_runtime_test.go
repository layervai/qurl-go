package qurl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
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
	t         *testing.T
	nhp       *fakeNHPServer
	conn      *net.UDPConn
	done      chan struct{}
	useRawRAK bool
	rawRAK    []byte
}

func startNativeRegistrationUDPServer(t *testing.T, nhp *fakeNHPServer) *nativeRegistrationUDPServer {
	return startNativeRegistrationUDPServerWithRAK(t, nhp, false, nil)
}

func startNativeRegistrationUDPServerWithRAK(t *testing.T, nhp *fakeNHPServer, useRawRAK bool, rawRAK []byte) *nativeRegistrationUDPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen native registration UDP: %v", err)
	}
	server := &nativeRegistrationUDPServer{t: t, nhp: nhp, conn: conn, done: make(chan struct{}), useRawRAK: useRawRAK, rawRAK: append([]byte(nil), rawRAK...)}
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
		counterOffset := s.nhp.regReplyCounterOffset
		if errCode == "" || errCode == rakSuccess {
			s.nhp.enrolled = true
		}
		s.nhp.mu.Unlock()
		var ackBody []byte
		if s.useRawRAK {
			ackBody = append([]byte(nil), s.rawRAK...)
		} else {
			if errCode == "" {
				errCode = rakSuccess
			}
			ackBody, err = json.Marshal(registerAckBody{ErrCode: errCode, ErrMsg: errMsg, AspID: agentAspID})
			if err != nil {
				s.t.Errorf("marshal native RAK: %v", err)
				continue
			}
		}
		rak, err := relayknocktest.BuildReply(relayknock.TypeRegisterAck, &relayknock.KnockInputs{
			DeviceStaticPriv: s.nhp.serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    scriptedEphemeral(0x7a),
			TimestampNanos:   uint64(time.Now().UnixNano()),
			Counter:          reply.Counter + counterOffset,
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

func TestAgentRuntimeClockOptionIsRegistrationClock(t *testing.T) {
	want := time.Date(2035, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := func() time.Time { return want }
	cfg, err := newRegisterConfig([]RegisterOption{withAgentRuntimeClock(clock)})
	if err != nil {
		t.Fatalf("newRegisterConfig: %v", err)
	}
	if !cfg.runtime.clock().Equal(want) {
		t.Fatalf("registration/runtime clock = %s, want %s", cfg.runtime.clock(), want)
	}
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

func TestRefreshAgentRegistration_HoldsSetupLockAcrossNetworkTransition(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))

	requestStarted := make(chan struct{})
	allowResponse := make(chan struct{})
	installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		close(requestStarted)
		<-allowResponse
		writeEnvelope(t, w, runtimeAssignment(h, body.AgentID, udpServer.port()))
	})

	var acquired, released atomic.Int32
	h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
	type result struct {
		binding *AgentRuntimeBinding
		err     error
	}
	done := make(chan result, 1)
	go func() {
		_, binding, err := RefreshAgentRegistration(context.Background(), h.store, runtimeRefreshOptions(h)...)
		done <- result{binding: binding, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("assignment request did not start")
	}
	if acquired.Load() != 1 || released.Load() != 0 {
		t.Fatalf("setup lock acquire/release during assignment = %d/%d, want 1/0", acquired.Load(), released.Load())
	}
	close(allowResponse)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("RefreshAgentRegistration: %v", got.err)
		}
		got.binding.Destroy()
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not complete")
	}
	if acquired.Load() != 1 || released.Load() != 1 {
		t.Fatalf("setup lock acquire/release after native REG = %d/%d, want 1/1", acquired.Load(), released.Load())
	}
}

func TestRefreshAgentRegistration_ContextCancellationReleasesSetupLock(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))

	requestStarted := make(chan struct{})
	refusing := doerFunc(func(req *http.Request) (*http.Response, error) {
		close(requestStarted)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	var acquired, released atomic.Int32
	h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type result struct {
		binding *AgentRuntimeBinding
		err     error
	}
	done := make(chan result, 1)
	go func() {
		opts := append(runtimeRefreshOptions(h), WithAgentClientHTTPClient(refusing))
		_, binding, err := RefreshAgentRegistration(ctx, h.store, opts...)
		done <- result{binding: binding, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("assignment request did not start")
	}
	if acquired.Load() != 1 || released.Load() != 0 {
		t.Fatalf("setup lock acquire/release before cancellation = %d/%d, want 1/0", acquired.Load(), released.Load())
	}
	cancel()
	select {
	case got := <-done:
		if got.binding != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("canceled refresh = binding %v err %v, want nil/context.Canceled", got.binding, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled refresh did not return promptly")
	}
	if acquired.Load() != 1 || released.Load() != 1 {
		t.Fatalf("setup lock acquire/release after cancellation = %d/%d, want 1/1", acquired.Load(), released.Load())
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

func TestRefreshAgentRegistration_RejectsUnstructuredNativeRAKWithoutSaving(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "empty object", body: `{}`},
		{name: "whitespace success code", body: `{"errCode":" 0 ","aspId":"agent"}`},
		{name: "missing asp id", body: `{"errCode":"0"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := registeredHarness(t)
			udpServer := startNativeRegistrationUDPServerWithRAK(t, h.nhp, true, []byte(tt.body))
			bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
			before := h.loadState(t)
			installRuntimeAssignmentHandler(t, h, udpServer.port())
			store := &runtimeCountingStore{inner: h.store}

			client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
			if client != nil || binding != nil || !errors.Is(err, ErrRegisterReplyMalformed) {
				t.Fatalf("unstructured native RAK result = client %v binding %v err %v", client, binding, err)
			}
			if store.loads.Load() != 1 || store.saves.Load() != 0 {
				t.Fatalf("unstructured native RAK loads/saves = %d/%d, want 1/0", store.loads.Load(), store.saves.Load())
			}
			after := h.loadState(t)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("unstructured native RAK mutated durable state: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestRefreshAgentRegistration_DeviceRAKDenialsRequireCredentialRecovery(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{name: "expired credential", code: rakCredentialExpired},
		{name: "identity conflict", code: rakIdentityConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := registeredHarness(t)
			body := fmt.Sprintf(`{"errCode":%q,"errMsg":"scripted device denial","aspId":"agent"}`, tt.code)
			udpServer := startNativeRegistrationUDPServerWithRAK(t, h.nhp, true, []byte(body))
			bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
			before := h.loadState(t)
			installRuntimeAssignmentHandler(t, h, udpServer.port())
			store := &runtimeCountingStore{inner: h.store}

			client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
			if client != nil || binding != nil || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("device RAK denial result = client %v binding %v err %v", client, binding, err)
			}
			if errors.Is(err, ErrOTPExpired) || errors.Is(err, ErrAgentIdentityConflict) || errors.Is(err, ErrKeyRejected) {
				t.Fatalf("device RAK denial exposed enrollment-only sentinel: %v", err)
			}
			var recovery *CredentialRecoveryRequiredError
			if !errors.As(err, &recovery) || recovery.DeviceID != before.AgentID {
				t.Fatalf("device RAK recovery error = %#v, want device id %q", recovery, before.AgentID)
			}
			if !strings.Contains(err.Error(), tt.code) || !strings.Contains(err.Error(), "scripted device denial") {
				t.Fatalf("device RAK recovery error lost authenticated detail: %v", err)
			}
			if store.loads.Load() != 1 || store.saves.Load() != 0 {
				t.Fatalf("device RAK denial loads/saves = %d/%d, want 1/0", store.loads.Load(), store.saves.Load())
			}
			after := h.loadState(t)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("device RAK denial mutated durable state: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestRefreshAgentRegistration_MalformedNativeTransportReplyMapsToTaxonomy(t *testing.T) {
	h := registeredHarness(t)
	h.nhp.regReplyCounterOffset = 1 // RAK counter won't echo REG -> mis-correlated.
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	before := h.loadState(t)
	installRuntimeAssignmentHandler(t, h, udpServer.port())
	store := &runtimeCountingStore{inner: h.store}

	client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
	if client != nil || binding != nil || !errors.Is(err, ErrRegisterReplyMalformed) {
		t.Fatalf("mis-correlated native RAK result = client %v binding %v err %v", client, binding, err)
	}
	if !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("mis-correlated native RAK lost underlying malformed-reply cause: %v", err)
	}
	if store.loads.Load() != 1 || store.saves.Load() != 0 {
		t.Fatalf("mis-correlated native RAK loads/saves = %d/%d, want 1/0", store.loads.Load(), store.saves.Load())
	}
	after := h.loadState(t)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("mis-correlated native RAK mutated durable state: before=%#v after=%#v", before, after)
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

func TestEqualAgentAssignment_UsesLeaseInstantNotTimeRepresentation(t *testing.T) {
	h := registeredHarness(t)
	a := validAssignment(t, h.loadState(t).AgentID)
	b := a
	b.LeaseExpiresAt = a.LeaseExpiresAt.In(time.FixedZone("equivalent-offset", 0))
	if reflect.DeepEqual(a.LeaseExpiresAt, b.LeaseExpiresAt) {
		t.Fatal("test setup produced identical time.Time representation")
	}
	if !a.equal(&b) {
		t.Fatal("equivalent lease instants should not force a redundant state save")
	}
	b.EndpointRevision++
	if a.equal(&b) {
		t.Fatal("different endpoint revisions must not compare equal")
	}
}

func TestRefreshAgentRegistration_UnchangedBindingSkipsRedundantSave(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	persisted := bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, _ assignmentRequestBody) {
		writeEnvelope(t, w, persisted.Assignment)
	})
	store := &runtimeCountingStore{inner: h.store}
	regCount := h.nhp.regCount()

	client, binding, err := RefreshAgentRegistration(context.Background(), store, runtimeRefreshOptions(h)...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	defer binding.Destroy()
	if client == nil || !binding.LeaseExpiresAt.Equal(persisted.Assignment.LeaseExpiresAt) {
		t.Fatalf("unchanged runtime result = client %v binding %s", client, binding)
	}
	if store.loads.Load() != 1 || store.saves.Load() != 0 || h.nhp.regCount() != regCount+1 {
		t.Fatalf("unchanged binding loads/saves/REG = %d/%d/%d, want 1/0/%d", store.loads.Load(), store.saves.Load(), h.nhp.regCount(), regCount+1)
	}
}

func TestRefreshAgentRegistration_AdoptsAuthoritativeShorterLeaseAtSameRevision(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	originalLease := time.Now().Add(2 * time.Hour).UTC()
	shorterLease := originalLease.Add(-time.Hour)
	bindPersistedNativeAssignment(t, h, udpServer.port(), originalLease)
	installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		assignment := runtimeAssignment(h, body.AgentID, udpServer.port())
		assignment.LeaseExpiresAt = shorterLease
		writeEnvelope(t, w, assignment)
	})

	client, binding, err := RefreshAgentRegistration(context.Background(), h.store, runtimeRefreshOptions(h)...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	defer binding.Destroy()
	if client == nil || !binding.LeaseExpiresAt.Equal(shorterLease) {
		t.Fatalf("shortened-lease runtime result = client %v binding %s", client, binding)
	}
	persisted := h.loadState(t)
	if !persisted.Assignment.LeaseExpiresAt.Equal(shorterLease) {
		t.Fatalf("persisted lease = %s, want authoritative shortened lease %s", persisted.Assignment.LeaseExpiresAt, shorterLease)
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

func TestConfirmFreshDeviceAssignment_RequiresPersistedAssignmentBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	cfg := defaultAgentRuntimeConfig()
	cfg.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected HTTP request")
	})
	for _, tc := range []struct {
		name  string
		state *AgentState
	}{
		{name: "nil state"},
		{name: "missing assignment", state: &AgentState{AgentID: "agent-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := cfg.confirmFreshDeviceAssignment(context.Background(), nil, tc.state)
			if state != nil || !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("confirmation result = state %#v err %v, want invalid assignment", state, err)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid confirmation state performed %d HTTP requests, want 0", requests.Load())
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

func TestRefreshAgentRegistration_503JitterEntropyFailureRequiresRecovery(t *testing.T) {
	h := registeredHarness(t)
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	bindPersistedNativeAssignment(t, h, udpServer.port(), time.Now().Add(time.Hour))
	requests := installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, _ assignmentRequestBody) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":{"code":"cell_assignment_unavailable","detail":"authority unavailable"}}`)
	})
	entropyErr := errors.New("entropy unavailable")
	var sleeps atomic.Int32
	regCount := h.nhp.regCount()
	store := &runtimeCountingStore{inner: h.store}
	opts := runtimeRefreshOptions(h)
	opts = append(opts,
		WithAgentRuntimeAssignmentRetryBudget(3, 10*time.Second),
		withAgentRuntimeJitterSource(func() (float64, error) { return 0, entropyErr }),
		withAgentRuntimeSleep(func(context.Context, time.Duration) error {
			sleeps.Add(1)
			return nil
		}),
	)

	client, binding, err := RefreshAgentRegistration(context.Background(), store, opts...)
	if client != nil || binding != nil || !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, entropyErr) {
		t.Fatalf("jitter failure result = client %v binding %v err %v", client, binding, err)
	}
	if len(requests.snapshot()) != 1 || sleeps.Load() != 0 || store.saves.Load() != 0 || h.nhp.regCount() != regCount {
		t.Fatalf("jitter failure requests/sleeps/saves/REG = %d/%d/%d/%d", len(requests.snapshot()), sleeps.Load(), store.saves.Load(), h.nhp.regCount())
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
				if client != nil || binding != nil || !errors.Is(err, ErrAgentRuntimeReopenRequired) || !errors.Is(err, ErrAssignmentForbidden) {
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

func TestRegisterAgentRuntime_AccountCrashResumeConfirmsPostMintDeviceVisibility(t *testing.T) {
	h, _ := newFreshCountingRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.keyID = "key_enrollment01"
	h.svc.maskedEmail = "j***@example.test"
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	var deviceVisibilityCalls atomic.Int32
	assignmentRequests := installRuntimeAssignmentHandlerWith(t, h, func(call int, w http.ResponseWriter, req *http.Request, body assignmentRequestBody) {
		if call == 1 {
			if got := h.nhp.otpCount(); got != 0 {
				t.Errorf("first account assignment ran after %d OTP dispatches, want placement before OTP", got)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer lv_account" {
				t.Errorf("pre-OTP assignment Authorization = %q, want account key", got)
			}
		}
		if req.Header.Get("Authorization") == "Bearer lv_device_secret" && deviceVisibilityCalls.Add(1) <= 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":{"code":"api_key_invalid","detail":"device key is not visible yet"}}`)
			return
		}
		writeEnvelope(t, w, runtimeAssignment(h, body.AgentID, udpServer.port()))
	})
	baseNow := time.Now().UTC()
	var clockOffset atomic.Int64
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

	// The first account call persists the identity and assignment, dispatches the
	// OTP, and pauses. Model another process then completing native REG/RAK but
	// dying before it can call completion.
	client, binding, err := RegisterAgentRuntime(context.Background(), "lv_account", h.store, h.registerOpts(runtimeOpts...)...)
	if client != nil || binding != nil || !errors.Is(err, ErrOTPPending) {
		t.Fatalf("prime account runtime = client %v binding %v err %v", client, binding, err)
	}
	h.nhp.setEnrolled(true)
	regsBefore := h.nhp.regCount()

	client, binding, err = RegisterAgentRuntime(context.Background(), "lv_account", h.store, h.registerOpts(runtimeOpts...)...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("account crash resume = client %v binding %v err %v", client, binding, err)
	}
	binding.Destroy()
	if h.nhp.regCount() != regsBefore {
		t.Fatalf("successful completion probe repeated native REG: %d -> %d", regsBefore, h.nhp.regCount())
	}
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completion probe calls = %d, want exactly 1", h.svc.completionCalls.Load())
	}
	if got := fmt.Sprint(slept); got != fmt.Sprint([]time.Duration{100 * time.Millisecond, 200 * time.Millisecond}) {
		t.Fatalf("post-probe visibility sleeps = %s, want [100ms 200ms]", got)
	}
	requests := assignmentRequests.snapshot()
	if len(requests) != 5 {
		t.Fatalf("assignment requests = %#v, want two enrollment + three post-mint device requests", requests)
	}
	for i, request := range requests {
		wantAuthorization := "Bearer lv_account"
		if i >= 2 {
			wantAuthorization = "Bearer lv_device_secret"
		}
		if request.Authorization != wantAuthorization || request.IdempotencyKey != "" {
			t.Fatalf("assignment request %d = %#v, want Authorization %q and no idempotency key", i, request, wantAuthorization)
		}
	}
	state := h.loadState(t)
	if state.RegisteredAt == nil || state.DeviceAPIKeyID != "key_device000001" || state.DeviceAPIKey != "lv_device_secret" {
		t.Fatalf("completion probe did not durably persist credential pair: %#v", state)
	}

	// A normal reopen consumes the completed durable state and cannot repeat the
	// first-issue completion after this crash-recovery path.
	reopened, reopenedBinding, reopenErr := RegisterAgentRuntime(context.Background(), "ignored", h.store, h.registerOpts(runtimeOpts...)...)
	if reopenErr != nil || reopened == nil || reopenedBinding == nil {
		t.Fatalf("reopen completed crash-resume state = client %v binding %v err %v", reopened, reopenedBinding, reopenErr)
	}
	reopenedBinding.Destroy()
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completed-state reopen repeated completion: calls = %d", h.svc.completionCalls.Load())
	}
}

func TestRegisterAgentRuntime_AccountOTPUsesRegistrationRelayBeforeNativeCell(t *testing.T) {
	h, counting := newFreshCountingRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.keyID = "key_enrollment01"
	h.svc.maskedEmail = "j***@example.test"

	cellNHP := newFakeNHPServer(t)
	cellNHP.expectCredential = "424242"
	cellUDP := startNativeRegistrationUDPServer(t, cellNHP)
	h.svc.completionNHP = cellNHP
	h.svc.completionPeer = &NHPServerPeerInfo{
		PublicKeyB64: cellNHP.serverPubB64(),
		Host:         "cell0.nhp.layerv.ai",
		Port:         cellUDP.port(),
	}
	counting.onSave = func(state *AgentState) {
		publicKey, err := base64.StdEncoding.Strict().DecodeString(state.PublicKeyB64)
		if err == nil {
			h.nhp.setExpectDevicePub(publicKey)
			cellNHP.setExpectDevicePub(publicKey)
		}
	}
	requests := installRuntimeAssignmentHandlerWith(t, h, func(_ int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		assignment := runtimeAssignment(h, body.AgentID, cellUDP.port())
		assignment.Endpoint.ServerPublicKeyB64 = cellNHP.serverPubB64()
		writeEnvelope(t, w, assignment)
	})
	runtimeOpts := append(runtimeUDPOptions(),
		WithAgentClientBaseURL(h.apiSrv.URL),
		WithAgentClientHTTPClient(h.apiSrv.Client()),
	)

	client, binding, err := RegisterAgentRuntime(context.Background(), "lv_account", h.store, h.registerOpts(runtimeOpts...)...)
	if client != nil || binding != nil || !errors.Is(err, ErrOTPPending) {
		t.Fatalf("fresh account runtime = client %v binding %v err %v, want OTP pending", client, binding, err)
	}
	if h.nhp.otpCount() != 1 || cellNHP.otpCount() != 0 {
		t.Fatalf("OTP relay/cell sends = %d/%d, want 1/0", h.nhp.otpCount(), cellNHP.otpCount())
	}
	if h.nhp.regCount() != 0 || cellNHP.regCount() != 0 {
		t.Fatalf("pre-code relay/cell REGs = %d/%d, want 0/0", h.nhp.regCount(), cellNHP.regCount())
	}

	client, binding, err = RegisterAgentRuntime(context.Background(), "lv_account", h.store, h.registerOpts(append(runtimeOpts, WithOTP("424242"))...)...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("account runtime resume = client %v binding %v err %v", client, binding, err)
	}
	binding.Destroy()
	if h.nhp.regCount() != 0 || cellNHP.regCount() != 1 {
		t.Fatalf("relay/cell REGs = %d/%d, want 0/1", h.nhp.regCount(), cellNHP.regCount())
	}
	if binding.NHPUDPEndpoint.ServerPublicKeyB64 != cellNHP.serverPubB64() {
		t.Fatalf("runtime binding server key = %q, want assigned-cell key", binding.NHPUDPEndpoint.ServerPublicKeyB64)
	}
	gotRequests := requests.snapshot()
	if len(gotRequests) != 3 {
		t.Fatalf("assignment requests = %#v, want initial, resume, and post-mint confirmation", gotRequests)
	}
	if gotRequests[0].Authorization != "Bearer lv_account" || gotRequests[1].Authorization != "Bearer lv_account" || gotRequests[2].Authorization != "Bearer lv_device_secret" {
		t.Fatalf("assignment authorization sequence = %#v", gotRequests)
	}
}

func TestRegisterAgentRuntime_PostMintEndpointAdvanceReopensAndRefreshesWithoutRepeatingCompletion(t *testing.T) {
	h, _ := newFreshCountingRegisterHarness(t)
	h.svc.keyID = "key_enrollment01"
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	requests := installRuntimeAssignmentHandlerWith(t, h, func(call int, w http.ResponseWriter, _ *http.Request, body assignmentRequestBody) {
		assignment := runtimeAssignment(h, body.AgentID, udpServer.port())
		if call > 1 {
			assignment.EndpointRevision = 2
			assignment.Endpoint.Host = "cell0-rotated.nhp.layerv.ai"
		}
		writeEnvelope(t, w, assignment)
	})
	runtimeOpts := runtimeUDPOptions()
	runtimeOpts = append(runtimeOpts,
		WithAgentClientBaseURL(h.apiSrv.URL),
		WithAgentClientHTTPClient(h.apiSrv.Client()),
	)

	client, binding, err := RegisterAgentRuntime(context.Background(), "lv_enroll", h.store, h.registerOpts(runtimeOpts...)...)
	if client != nil || binding != nil || !errors.Is(err, ErrAgentRuntimeReopenRequired) || !errors.Is(err, ErrAssignmentEndpointRefreshRequired) {
		t.Fatalf("post-mint endpoint advance = client %v binding %v err %v", client, binding, err)
	}
	state := h.loadState(t)
	if state.DeviceAPIKeyID != "key_device000001" || state.DeviceAPIKey != "lv_device_secret" || state.RegisteredAt == nil {
		t.Fatalf("post-mint endpoint advance lost durable device credential: %#v", state)
	}
	if state.Assignment.EndpointRevision != 1 {
		t.Fatalf("post-mint endpoint advance mutated durable revision = %d, want authenticated revision 1", state.Assignment.EndpointRevision)
	}
	if h.svc.completionCalls.Load() != 1 || h.nhp.regCount() != 1 {
		t.Fatalf("initial completion/native REG counts = %d/%d, want 1/1", h.svc.completionCalls.Load(), h.nhp.regCount())
	}

	refreshedClient, refreshedBinding, err := RefreshAgentRegistration(context.Background(), h.store, runtimeRefreshOptions(h)...)
	if err != nil || refreshedClient == nil || refreshedBinding == nil {
		t.Fatalf("ordinary refresh after endpoint advance = client %v binding %v err %v", refreshedClient, refreshedBinding, err)
	}
	defer refreshedBinding.Destroy()
	if refreshedBinding.EndpointRevision != 2 || refreshedBinding.NHPUDPEndpoint.Host != "cell0-rotated.nhp.layerv.ai" {
		t.Fatalf("refreshed endpoint binding = %s", refreshedBinding)
	}
	if h.svc.completionCalls.Load() != 1 || h.nhp.regCount() != 2 {
		t.Fatalf("post-refresh completion/native REG counts = %d/%d, want 1/2", h.svc.completionCalls.Load(), h.nhp.regCount())
	}
	if got := requests.snapshot(); len(got) != 3 || got[0].Authorization != "Bearer lv_enroll" || got[1].Authorization != "Bearer lv_device_secret" || got[2].Authorization != "Bearer lv_device_secret" {
		t.Fatalf("assignment request sequence = %#v, want enrollment then two device-key calls", got)
	}
}

func TestNativeKnockResult_FormattingRedactsACToken(t *testing.T) {
	result := &NativeKnockResult{
		ACToken:      "ac-sensitive-bearer-token",
		ResourceHost: "connector.example.test:7000",
		OpenTime:     900,
		AgentAddr:    "203.0.113.9:49152",
	}
	formatted := map[string]string{
		"pointer %v":  fmt.Sprintf("%v", result),
		"pointer %+v": fmt.Sprintf("%+v", result),
		"pointer %#v": fmt.Sprintf("%#v", result),
		"value %v":    fmt.Sprintf("%v", *result),
		"value %+v":   fmt.Sprintf("%+v", *result),
		"value %#v":   fmt.Sprintf("%#v", *result),
	}
	for label, value := range formatted {
		if !strings.Contains(value, "[REDACTED]") || strings.Contains(value, result.ACToken) {
			t.Fatalf("%s leaked ACToken: %s", label, value)
		}
	}
	var nilResult *NativeKnockResult
	for _, value := range []string{fmt.Sprintf("%v", nilResult), fmt.Sprintf("%+v", nilResult), fmt.Sprintf("%#v", nilResult)} {
		if value != "<nil>" {
			t.Fatalf("nil NativeKnockResult formatting = %q, want <nil>", value)
		}
	}
	_, err := interpretNativeAgentKnockReply(&relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`{"errCode":"0","acTokens":{"other":"ac-sensitive-bearer-token"},"resHost":{"other":"connector.example.test:7000"}}`),
	}, "requested")
	if !errors.Is(err, ErrMalformedReply) || strings.Contains(err.Error(), result.ACToken) {
		t.Fatalf("wrong-resource ACK error leaked ACToken: %v", err)
	}
}

func TestInterpretNativeAgentKnockReply_RejectsNullACKAsNonObject(t *testing.T) {
	result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`null`),
	}, "requested")
	if result != nil || !errors.Is(err, ErrMalformedReply) || !strings.Contains(err.Error(), "must be an object") {
		t.Fatalf("null ACK result = %#v err %v, want non-object malformed reply", result, err)
	}
}

func TestInterpretNativeAgentKnockReply_AcceptsCurrentOpenNHPProducerEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "pre-access actions absent",
			body: `{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		},
		{
			name: "pre-access actions empty",
			body: `{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":{}}`,
		},
		{
			name: "nil pre-access action emitted for successful AC result",
			body: `{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":{"requested":null}}`,
		},
		{
			name: "all-null actions and optional current producer metadata",
			body: `{"errCode":"","errMsg":"","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"aspToken":"asp-opaque-token","agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":{"other":null,"requested":null},"redirectUrl":"https://qurl.link/next"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
				Type: relayknock.TypeACK,
				Body: []byte(tc.body),
			}, "requested")
			if err != nil || result == nil {
				t.Fatalf("current producer ACK result = %#v err %v", result, err)
			}
			if result.ACToken != "ac-live-token" || result.ResourceHost != "frps.example.test:7000" || result.OpenTime != 900 || result.AgentAddr != "203.0.113.9:49152" {
				t.Fatalf("current producer ACK result = %#v", result)
			}
		})
	}
}

func TestInterpretNativeAgentKnockReply_RejectsEveryNonNullPreAccessAction(t *testing.T) {
	for _, action := range []string{
		`{"acIp":"198.51.100.7","acPort":"443","acPubKey":"synthetic-public-key","acToken":"synthetic-pre-access-token","acCipherScheme":1}`,
		`{"future":true}`,
		`{}`,
		`"opaque-future-action"`,
		`7`,
		`[]`,
	} {
		t.Run(action, func(t *testing.T) {
			body := `{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":{"other":` + action + `,"requested":null}}`
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
				Type: relayknock.TypeACK,
				Body: []byte(body),
			}, "requested")
			if result != nil || !errors.Is(err, ErrMalformedReply) || !strings.Contains(err.Error(), "unsupported pre-access action") {
				t.Fatalf("pre-access ACK result = %#v err %v, want explicit fail-closed rejection", result, err)
			}
		})
	}
}

func TestInterpretNativeAgentKnockReply_PreservesTypedDenyWithPreAccessMetadata(t *testing.T) {
	body := `{"errCode":"52004","errMsg":"failed to find resource","resHost":{},"opnTime":0,"agentAddr":"203.0.113.9:49152","acTokens":{},"preActions":{"other":{"acIp":"198.51.100.7","acPort":"443","acPubKey":"synthetic-public-key","acToken":"synthetic-pre-access-token","acCipherScheme":1}}}`
	result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(body),
	}, "requested")
	var deny *ServerDenyError
	if result != nil || !errors.As(err, &deny) {
		t.Fatalf("denied pre-access ACK result = %#v err %v, want typed server denial", result, err)
	}
	if deny.ErrCode != "52004" || deny.ErrMsg != "failed to find resource" {
		t.Fatalf("denied pre-access detail = %#v", deny)
	}
}

func TestInterpretNativeAgentKnockReply_RejectsProducerEnvelopeDrift(t *testing.T) {
	for _, body := range []string{
		`{"resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":null,"resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","errMsg":null,"resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":null,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":null,"acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"aspToken":null,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"redirectUrl":null}`,
		`{"errCode":"0","resHost":{"requested":null},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":null}}`,
		`{"errCode":"0","resHost":{"requested":" frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token "}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":null}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"aspToken":{},"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":[]}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"preActions":{"requested":{"future":true}}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"redirectUrl":7}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"},"future":true}`,
		`{"errCode":"0","errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}`,
		`{"errCode":"0","resHost":{"requested":"frps.example.test:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"requested":"ac-live-token"}}{}`,
	} {
		result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
			Type: relayknock.TypeACK,
			Body: []byte(body),
		}, "requested")
		if result != nil || !errors.Is(err, ErrMalformedReply) {
			t.Errorf("drifted producer ACK %q result = %#v err %v, want malformed", body, result, err)
		}
	}
}

func TestInterpretNativeAgentKnockReply_DuplicateFieldNamesTheOffendingKey(t *testing.T) {
	result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`{"errCode":"0","errCode":"0"}`),
	}, "requested")
	if result != nil || !errors.Is(err, ErrMalformedReply) || !strings.Contains(err.Error(), `"errCode"`) {
		t.Fatalf("duplicate-field ACK result = %#v err %v, want malformed reply naming errCode", result, err)
	}
}

func TestInterpretNativeAgentKnockReply_RequiresCurrentProducerKeys(t *testing.T) {
	base := map[string]any{
		"errCode":   "0",
		"resHost":   map[string]string{"requested": "frps.example.test:7000"},
		"opnTime":   900,
		"agentAddr": "203.0.113.9:49152",
		"acTokens":  map[string]string{"requested": "ac-live-token"},
	}
	for _, missing := range []string{"errCode", "resHost", "opnTime", "agentAddr", "acTokens"} {
		t.Run(missing, func(t *testing.T) {
			body := make(map[string]any, len(base)-1)
			for key, value := range base {
				if key != missing {
					body[key] = value
				}
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{
				Type: relayknock.TypeACK,
				Body: encoded,
			}, "requested")
			if result != nil || !errors.Is(err, ErrMalformedReply) || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing %s result = %#v err %v, want required-field failure", missing, result, err)
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
				if result != nil || !errors.As(err, &deny) {
					t.Fatalf("deny vector result = %#v err %v", result, err)
				}
				if deny.ErrCode != "52004" || deny.ErrMsg != "failed to find resource" {
					t.Fatalf("deny vector detail = %#v", deny)
				}
				if !strings.Contains(err.Error(), deny.ErrMsg) {
					t.Fatalf("deny error omitted authenticated detail: %v", err)
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

	t.Run("wrong-length device private key", func(t *testing.T) {
		resolver := &countingRuntimeResolver{}
		result, err := KnockRegisteredAgent(context.Background(), binding, make([]byte, 31), "connector-01", NativeKnockOptions{RunID: "0123456789abcdef"},
			WithAgentRuntimeUDPResolver(resolver),
		)
		if result != nil || !errors.Is(err, ErrInvalidNativeKnockInput) {
			t.Fatalf("wrong-length private key result = %#v err %v", result, err)
		}
		if resolver.calls.Load() != 0 {
			t.Fatalf("wrong-length private key performed %d DNS lookups", resolver.calls.Load())
		}
	})

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

	t.Run("tampered non-LayerV host", func(t *testing.T) {
		tampered := *binding
		tampered.authoritativeAssignment = binding.authoritativeAssignment.clone()
		tampered.authoritativeAssignment.Endpoint.Host = "cell0.attacker.example"
		resolver := &countingRuntimeResolver{}
		result, err := KnockRegisteredAgent(context.Background(), &tampered, privateKey, "connector-01", NativeKnockOptions{RunID: "0123456789abcdef"},
			WithAgentRuntimeUDPResolver(resolver),
		)
		if result != nil || !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrAssignmentInvalidResponse) {
			t.Fatalf("tampered host result = %#v err %v", result, err)
		}
		if resolver.calls.Load() != 0 {
			t.Fatalf("tampered host performed %d DNS lookups", resolver.calls.Load())
		}
	})
}
