package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

const canonicalNativeDeviceCredential = "lv_live_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

var reassignmentFixtureLeaseExpiresAt = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

type runtimeUDPStep struct {
	requestType       int
	replyType         int
	replyBody         string
	reknockCookie     []byte
	replyCounterDelta uint64
	noReply           bool
}

type runtimeUDPRequest struct {
	typeID int
	body   []byte
}

type runtimeAssignmentProof struct {
	stepIndex int
	body      []byte
	cookie    []byte
}

type runtimeUDPServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	agentPub   []byte
	steps      []runtimeUDPStep
	done       chan struct{}

	mu       sync.Mutex
	requests []runtimeUDPRequest
}

func newRuntimeUDPServer(t *testing.T, serverPriv, agentPub []byte, steps ...runtimeUDPStep) *runtimeUDPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen runtime UDP: %v", err)
	}
	server := &runtimeUDPServer{
		t: t, conn: conn, serverPriv: bytes.Clone(serverPriv), agentPub: bytes.Clone(agentPub),
		steps: append([]runtimeUDPStep(nil), steps...), done: make(chan struct{}),
	}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(runtimeReplyTimeout):
			t.Error("runtime UDP server did not stop")
		}
	})
	return server
}

func (s *runtimeUDPServer) serve() {
	defer close(s.done)
	buffer := make([]byte, 4096)
	var assignmentProof *runtimeAssignmentProof
	for {
		n, remote, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := bytes.Clone(buffer[:n])
		if assignmentProof != nil {
			opened, openErr := relayknocktest.OpenHubLSTCookieProofMessage(s.serverPriv, s.agentPub, assignmentProof.cookie, packet)
			if openErr != nil {
				s.t.Errorf("open runtime assignment proof: %v", openErr)
				continue
			}
			if !bytes.Equal(opened.Body, assignmentProof.body) {
				s.t.Errorf("runtime assignment proof body changed: got %q want %q", opened.Body, assignmentProof.body)
				continue
			}
			stepIndex := assignmentProof.stepIndex
			step := s.steps[stepIndex]
			assignmentProof = nil
			if step.noReply {
				continue
			}
			if err := s.writeReply(remote, step.replyType, opened.Counter+step.replyCounterDelta, []byte(step.replyBody), stepIndex*2+1); err != nil {
				s.t.Logf("write runtime assignment result: %v", err)
			}
			continue
		}
		s.mu.Lock()
		index := len(s.requests)
		s.mu.Unlock()
		var opened *relayknock.Reply
		if index < len(s.steps) && s.steps[index].requestType == relayknock.TypeReknock {
			opened, err = relayknocktest.OpenReknockMessage(s.serverPriv, s.agentPub, s.steps[index].reknockCookie, packet)
		} else {
			opened, err = relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, packet)
		}
		if err != nil {
			s.t.Errorf("open runtime request: %v", err)
			continue
		}
		s.mu.Lock()
		s.requests = append(s.requests, runtimeUDPRequest{typeID: opened.Type, body: bytes.Clone(opened.Body)})
		s.mu.Unlock()
		if index >= len(s.steps) {
			continue
		}
		step := s.steps[index]
		if opened.Type != step.requestType {
			s.t.Errorf("runtime request %d type = %d, want %d", index, opened.Type, step.requestType)
			continue
		}
		if opened.Type == relayknock.TypeListRequest && isHubAssignmentRequest(opened.Body) {
			cookie := bytes.Repeat([]byte{0x5a}, 32)
			challengeBody := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, opened.Counter, base64.StdEncoding.EncodeToString(cookie)))
			if err := s.writeReply(remote, relayknock.TypeCookieChallenge, opened.Counter+99, challengeBody, index*2); err != nil {
				s.t.Logf("write runtime assignment challenge: %v", err)
				continue
			}
			assignmentProof = &runtimeAssignmentProof{stepIndex: index, body: bytes.Clone(opened.Body), cookie: cookie}
			continue
		}
		if step.noReply {
			continue
		}
		replyBody := step.replyBody
		if step.replyType == relayknock.TypeCookieChallenge && len(step.reknockCookie) != 0 {
			replyBody = fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, opened.Counter, base64.StdEncoding.EncodeToString(step.reknockCookie))
		}
		if err := s.writeReply(remote, step.replyType, opened.Counter+step.replyCounterDelta, []byte(replyBody), index); err != nil {
			s.t.Logf("write runtime reply: %v", err)
		}
	}
}

func isHubAssignmentRequest(body []byte) bool {
	var request struct {
		UsrData struct {
			Query string `json:"query"`
		} `json:"usrData"`
	}
	return json.Unmarshal(body, &request) == nil && request.UsrData.Query == assignmentQuery
}

func (s *runtimeUDPServer) writeReply(remote *net.UDPAddr, replyType int, counter uint64, body []byte, sequence int) error {
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: s.serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    bytes.Repeat([]byte{byte(0x40 + sequence)}, 32),
		TimestampNanos:   uint64(assignmentFixtureNow.UnixNano()) + uint64(sequence),
		Counter:          counter,
		Preamble:         uint32(0x50607080 + sequence),
		Body:             body,
	})
	if err != nil {
		return fmt.Errorf("build runtime reply: %w", err)
	}
	_, err = s.conn.WriteToUDP(packet, remote)
	return err
}

func (s *runtimeUDPServer) snapshot() []runtimeUDPRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]runtimeUDPRequest, len(s.requests))
	for i := range s.requests {
		result[i] = runtimeUDPRequest{typeID: s.requests[i].typeID, body: bytes.Clone(s.requests[i].body)}
	}
	return result
}

// waitRuntimeUDPRequests waits for requests the caller expects to arrive, so its
// deadline is patience rather than an assertion: it only has to outlast a
// scheduler stall.
func waitRuntimeUDPRequests(t *testing.T, server *runtimeUDPServer, count int) []runtimeUDPRequest {
	t.Helper()
	deadline := time.Now().Add(runtimeReplyTimeout)
	for {
		requests := server.snapshot()
		if len(requests) >= count {
			return requests
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d UDP requests; got %d", count, len(requests))
		}
		time.Sleep(time.Millisecond)
	}
}

type runtimeRouteResolver struct {
	hosts map[string]netip.Addr
}

type runtimeResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f runtimeResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func (r runtimeRouteResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}
	address, ok := r.hosts[host]
	if !ok {
		return nil, fmt.Errorf("unexpected host %q", host)
	}
	return []netip.Addr{address}, nil
}

type runtimeRouteDialer struct {
	targets map[string]string
}

func (d runtimeRouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	target, ok := d.targets[host]
	if !ok {
		return nil, fmt.Errorf("unexpected resolved address %q", host)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

type countingNativeDialer struct {
	inner nativeudp.Dialer
	calls atomic.Int32
}

func (d *countingNativeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	return d.inner.DialContext(ctx, network, address)
}

type noIONativeResolver struct{ calls atomic.Int32 }

func (r *noIONativeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type noIONativeDialer struct{ calls atomic.Int32 }

func (d *noIONativeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("dial must not be reached")
}

type runtimeRecordingStore struct {
	inner                     AgentStateStore
	mu                        sync.Mutex
	saves                     []*AgentState
	calls                     int
	fail                      int
	failAfterCommit           int
	waitForContextAfterCommit int
	cancelBeforeSave          int
	cancelOnSave              int
	cancel                    context.CancelFunc
}

type runtimeRecordingStoreView struct {
	recorder *runtimeRecordingStore
	inner    AgentStateStore
}

func (s *runtimeRecordingStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *runtimeRecordingStore) decoratedAgentStateStore() AgentStateStore {
	return s.inner
}

func (s *runtimeRecordingStore) withDecoratedAgentStateStore(inner AgentStateStore) AgentStateStore {
	return &runtimeRecordingStoreView{recorder: s, inner: inner}
}

func (s *runtimeRecordingStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	locker, ok := s.inner.(setupLockingAgentStateStore)
	if !ok {
		return nil, errors.New("runtime test store lost its setup-lock capability")
	}
	return locker.acquireSetupLock(ctx)
}

func (s *runtimeRecordingStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	return s.saveAgentState(ctx, s.inner, state)
}

func (s *runtimeRecordingStore) saveAgentState(ctx context.Context, inner AgentStateStore, state *AgentState) error {
	s.mu.Lock()
	s.calls++
	call := s.calls
	fail := s.fail
	failAfterCommit := s.failAfterCommit
	waitForContextAfterCommit := s.waitForContextAfterCommit
	cancelBeforeSave := s.cancelBeforeSave
	cancelOnSave := s.cancelOnSave
	cancel := s.cancel
	s.mu.Unlock()
	if call == cancelBeforeSave && cancel != nil {
		cancel()
	}
	if call == fail {
		return errors.New("injected runtime state save failure")
	}
	if err := inner.SaveAgentState(ctx, state); err != nil {
		return err
	}
	s.mu.Lock()
	s.saves = append(s.saves, state.clone())
	s.mu.Unlock()
	if call == cancelOnSave && cancel != nil {
		cancel()
	}
	if call == waitForContextAfterCommit {
		<-ctx.Done()
	}
	if call == failAfterCommit {
		return errors.New("injected runtime state post-commit acknowledgement failure")
	}
	return nil
}

func (s *runtimeRecordingStoreView) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *runtimeRecordingStoreView) SaveAgentState(ctx context.Context, state *AgentState) error {
	return s.recorder.saveAgentState(ctx, s.inner, state)
}

func (s *runtimeRecordingStoreView) decoratedAgentStateStore() AgentStateStore {
	return s.inner
}

func (s *runtimeRecordingStoreView) withDecoratedAgentStateStore(inner AgentStateStore) AgentStateStore {
	return &runtimeRecordingStoreView{recorder: s.recorder, inner: inner}
}

func (s *runtimeRecordingStoreView) acquireSetupLock(ctx context.Context) (setupLock, error) {
	locker, ok := s.inner.(setupLockingAgentStateStore)
	if !ok {
		return nil, errors.New("runtime test store view lost its setup-lock capability")
	}
	return locker.acquireSetupLock(ctx)
}

func (s *runtimeRecordingStore) snapshots() []*AgentState {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*AgentState, len(s.saves))
	for i := range s.saves {
		result[i] = s.saves[i].clone()
	}
	return result
}

func TestRuntimeRecordingStorePreservesPinnedSetupCapability(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inner, err := OpenFileAgentState(filepath.Join(stateDir, "agent-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := inner.Close(); err != nil {
			t.Errorf("close state store: %v", err)
		}
	})
	store := &runtimeRecordingStore{inner: inner}
	state := &AgentState{AgentID: "agent-decorator", SchemaVersion: agentStateSchemaVersion}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = withAgentSetupLock(ctx, store, func(struct{}) {}, func(lockedCtx context.Context, locked AgentStateStore) (struct{}, error) {
		if err := store.SaveAgentState(lockedCtx, state); !errors.Is(err, ErrAgentSetupLock) {
			return struct{}{}, fmt.Errorf("reentrant public save error = %w, want ErrAgentSetupLock", err)
		}
		return struct{}{}, locked.SaveAgentState(lockedCtx, state)
	})
	if err != nil {
		t.Fatalf("save through lock-bound decorator: %v", err)
	}
	if got := len(store.snapshots()); got != 1 {
		t.Fatalf("successful recorded saves = %d, want 1", got)
	}
}

// Transport patience for the fixtures. A scripted exchange against the
// in-process fake hub answers in microseconds, so for a script whose steps all
// reply these bounds are never actually waited on: their only job is to outlast
// a scheduler stall on a loaded CI runner. They are therefore generous, and
// track the production nativeudp default rather than racing it.
//
// Raising the attempt count is deliberately not the lever here. runtimeUDPServer
// selects its step by the count of datagrams it has received, so a retry
// consumes the *next* scripted step and shows up in snapshot(); patience has to
// come from the bounds instead.
const (
	runtimeReplyTimeout = 5 * time.Second
	runtimeReplyBudget  = 30 * time.Second
)

// Transport patience for a script that deliberately leaves a request
// unanswered. Such a test spends real time waiting out these bounds and asserts
// on the exhaustion that follows, so they stay tight.
//
// Both must tighten together. The socket deadline is min(timeout, transaction
// deadline), so a generous timeout under a tight budget would let the whole
// transaction expire inside the first attempt, and a multi-attempt test would
// never reach its second attempt.
const (
	runtimeSilenceTimeout = 100 * time.Millisecond
	runtimeSilenceBudget  = time.Second
)

type runtimeFixture struct {
	contract *conformance.AgentAssignmentFile
	store    *runtimeRecordingStore
	hub      HubBootstrap
	resolver runtimeRouteResolver
	dialer   runtimeRouteDialer
	hubUDP   *runtimeUDPServer
	cellUDP  *runtimeUDPServer
	// silent records that the script withholds a reply, so the fixture keeps the
	// tight bounds a silence assertion depends on.
	silent bool
}

// scriptsSilence reports whether any scripted step withholds its reply.
func scriptsSilence(scripts ...[]runtimeUDPStep) bool {
	for _, script := range scripts {
		for _, step := range script {
			if step.noReply {
				return true
			}
		}
	}
	return false
}

func newRuntimeFixture(t *testing.T, hubSteps, cellSteps []runtimeUDPStep) *runtimeFixture {
	t.Helper()
	contract := loadAssignmentFixture(t)
	agentPriv := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	agentPub := assignmentHex(t, contract.Keys.Agent.StaticPubHex)
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := FileAgentState(filepath.Join(stateDir, "agent-state.json"))
	if err := inner.SaveAgentState(context.Background(), &AgentState{
		AgentID: "agent-conform", PrivateKeyB64: base64.StdEncoding.EncodeToString(agentPriv),
		PublicKeyB64: base64.StdEncoding.EncodeToString(agentPub), SchemaVersion: agentStateSchemaVersion,
	}); err != nil {
		t.Fatalf("seed runtime state: %v", err)
	}
	store := &runtimeRecordingStore{inner: inner}
	hubUDP := newRuntimeUDPServer(t, assignmentHex(t, contract.Keys.Hub.StaticPrivHex), agentPub, hubSteps...)
	cellUDP := newRuntimeUDPServer(t, assignmentHex(t, contract.Keys.AssignedCell.StaticPrivHex), agentPub, cellSteps...)
	hubAddress := netip.MustParseAddr("8.8.8.8")
	cellAddress := netip.MustParseAddr("9.9.9.9")
	return &runtimeFixture{
		contract: contract, store: store,
		hub:      HubBootstrap{Host: "hub.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Hub.StaticPubHex))},
		resolver: runtimeRouteResolver{hosts: map[string]netip.Addr{"hub.nhp.layerv.ai": hubAddress, "cell0.nhp.layerv.ai": cellAddress}},
		dialer:   runtimeRouteDialer{targets: map[string]string{hubAddress.String(): hubUDP.conn.LocalAddr().String(), cellAddress.String(): cellUDP.conn.LocalAddr().String()}},
		hubUDP:   hubUDP, cellUDP: cellUDP,
		silent: scriptsSilence(hubSteps, cellSteps),
	}
}

// expectSilence keeps the tight bounds for a fixture whose silence comes from a
// script that runs out of steps rather than from an explicit noReply step. The
// server answers only while its step list lasts, so an unscripted or short
// script is a silent endpoint too, and scriptsSilence cannot see that coming.
func (f *runtimeFixture) expectSilence() *runtimeFixture {
	f.silent = true
	return f
}

// transportBounds returns the per-datagram timeout and whole-transaction budget
// this fixture's script calls for.
func (f *runtimeFixture) transportBounds() (timeout, budget time.Duration) {
	if f.silent {
		return runtimeSilenceTimeout, runtimeSilenceBudget
	}
	return runtimeReplyTimeout, runtimeReplyBudget
}

func (f *runtimeFixture) options(extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	return f.optionsWithMetadata(true, extra...)
}

func (f *runtimeFixture) optionsWithoutMetadata(extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	return f.optionsWithMetadata(false, extra...)
}

// defaultPolicyOptions builds the same fixture wiring but leaves the SDK's
// enrollment policy at its default, so a test can prove what a plain
// RegisterAgentRuntime call accepts.
func (f *runtimeFixture) defaultPolicyOptions(extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	return append(f.baseOptions(true), extra...)
}

func (f *runtimeFixture) optionsWithMetadata(include bool, extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	// These fixtures enroll with the pre-issued bootstrap credential, so they opt
	// out of the default OTP policy. Cases that exercise OTP enrollment append
	// their own key-kind and provider options, which overwrite this one.
	opts := f.baseOptions(include, WithAgentRuntimeHeadlessEnrollment())
	return append(opts, extra...)
}

func (f *runtimeFixture) baseOptions(includeMetadata bool, policy ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	timeout, budget := f.transportBounds()
	opts := append([]AgentRuntimeRegistrationOption{}, policy...)
	opts = append(opts,
		WithAgentRuntimeHub(f.hub),
		WithAgentRuntimeIdentity("agent-conform"),
		WithAgentRuntimeUDPResolver(f.resolver),
		WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(timeout, 1),
		WithAgentRuntimeAssignmentRetryBudget(1, budget),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }),
		withTestAgentRuntimeAssignmentNonce(conformance.AgentAssignmentInitialRequestNonceFixture),
		withAgentRuntimeDeviceCredential(canonicalNativeDeviceCredential),
	)
	if includeMetadata {
		opts = append(opts, WithAgentRuntimeMetadata("conformance-host", "0.0.0-conformance"))
	}
	return opts
}

func (f *runtimeFixture) refreshOptions(extra ...AgentRuntimeRefreshOption) []AgentRuntimeRefreshOption {
	timeout, budget := f.transportBounds()
	opts := []AgentRuntimeRefreshOption{
		WithAgentRuntimeUDPResolver(f.resolver),
		WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(timeout, 1),
		WithAgentRuntimeAssignmentRetryBudget(1, budget),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }),
		withTestAgentRuntimeAssignmentNonce(conformance.AgentAssignmentRefreshRequestNonceFixture),
	}
	return append(opts, extra...)
}

func seedCompletedRuntimeAssignment(t *testing.T, f *runtimeFixture, assignment *AgentAssignment) {
	t.Helper()
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := assignmentFixtureNow.Add(-time.Hour)
	state.RegisteredAt = &registeredAt
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_DvK9mN2pQr7S"
	state.Assignment = assignment.clone()
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func rewriteRefreshAssignment(t *testing.T, contract *conformance.AgentAssignmentFile, assignment *AgentAssignment) string {
	t.Helper()
	return strings.NewReplacer(
		`"cell_id":"cell0"`, fmt.Sprintf(`"cell_id":%q`, assignment.CellID),
		`"assignment_generation":1`, fmt.Sprintf(`"assignment_generation":%d`, assignment.AssignmentGeneration),
		`"endpoint_revision":1`, fmt.Sprintf(`"endpoint_revision":%d`, assignment.EndpointRevision),
		`"lease_expires_at":"2026-07-16T12:00:00Z"`, fmt.Sprintf(`"lease_expires_at":%q`, assignment.LeaseExpiresAt.Format(time.RFC3339)),
		`"host":"cell0.nhp.layerv.ai"`, fmt.Sprintf(`"host":%q`, assignment.Endpoint.Host),
		base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)), assignment.Endpoint.ServerPublicKeyB64,
	).Replace(contract.RefreshAssignment.Result.BodyJSON)
}

// refusingReassignmentHTTP returns an HTTP doer that refuses every request and a
// counter of attempts, proving reassignment adoption performs no HTTP.
func refusingReassignmentHTTP() (*atomic.Int32, HTTPDoer) {
	httpCalls := new(atomic.Int32)
	return httpCalls, doerFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, errors.New("HTTP is forbidden during native reassignment adoption")
	})
}

func newReassignmentTarget(t *testing.T, contract *conformance.AgentAssignmentFile, cellID string, generation int64, serverPublicKeyB64 string, leaseExpiresAt time.Time) *AgentAssignment {
	t.Helper()
	if serverPublicKeyB64 == "" {
		serverPublicKeyB64 = base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))
	}
	if leaseExpiresAt.IsZero() {
		leaseExpiresAt = reassignmentFixtureLeaseExpiresAt
	}
	return &AgentAssignment{
		CellID: cellID, AssignmentGeneration: generation, EndpointRevision: 1,
		LeaseExpiresAt: leaseExpiresAt,
		Endpoint: NHPUDPEndpoint{
			Host: cellID + ".nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: serverPublicKeyB64,
		},
	}
}

func seedPendingActivation(t *testing.T, contract *conformance.AgentAssignmentFile, optionSet func(*runtimeFixture) []AgentRuntimeRegistrationOption) *runtimeFixture {
	t.Helper()
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
	)
	opts := f.options()
	if optionSet != nil {
		opts = optionSet(f)
	}
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, opts...)
	if !errors.Is(err, ErrRegistrationRecoveryRequired) {
		t.Fatalf("seed pending activation: %v", err)
	}
	return f
}

func withTestAgentRuntimeAssignmentSleep(sleep func(context.Context, time.Duration) error) AgentRuntimeLifecycleOption {
	return nativeRuntimeLifecycleOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.assignmentOptions = append(c.assignmentOptions, withAssignmentSleep(sleep))
		return nil
	})
}

func withTestAgentRuntimeAssignmentNonce(encoded string) AgentRuntimeLifecycleOption {
	return nativeRuntimeLifecycleOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		nonce, err := conformance.DecodeConnectorHubRequestNonce(encoded)
		if err != nil {
			return err
		}
		c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
			return bytes.Clone(nonce), nil
		}))
		return nil
	})
}

func testOTPProvider(context.Context, AgentOTPChallenge) (string, error) { return "12345678", nil }

func TestAgentRuntimeRegistrationKeyKindPolicy_AllNativeKinds(t *testing.T) {
	// The default policy is OTP alone: exactly the account kind. Every other
	// kind is rejected until the caller opts into another path.
	cfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeOTPProvider(testOTPProvider),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.requireAllowedRegistrationKeyKind(string(RegistrationKeyKindAccount)); err != nil {
		t.Fatalf("default policy rejected account enrollment: %v", err)
	}
	wantAllowed := []RegistrationKeyKind{RegistrationKeyKindAccount}
	// The one-shot kinds stay out because minting them is itself the
	// authorization; the durable agent kind stays out because it is retired
	// and the platform no longer mints keys that classify as it.
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindAgent,
	} {
		refusal := cfg.requireAllowedRegistrationKeyKind(string(kind))
		var disallowed *RegistrationKeyKindDisallowedError
		if !errors.As(refusal, &disallowed) || !errors.Is(refusal, ErrRegistrationKeyKindDisallowed) {
			t.Fatalf("default policy error for %q = %v, want typed disallowed error", kind, refusal)
		}
		if !slices.Equal(disallowed.Allowed, wantAllowed) {
			t.Fatalf("default allowed kinds = %v, want %v", disallowed.Allowed, wantAllowed)
		}
	}

	// The escape hatch admits exactly the one-shot enrollment token kinds. The
	// account kind is out because this runtime just said it cannot answer a
	// code, and the retired agent kind is admitted by no path at all without
	// the explicit option.
	headlessCfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeHeadlessEnrollment(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindBootstrap,
	} {
		if err := headlessCfg.requireAllowedRegistrationKeyKind(string(kind)); err != nil {
			t.Errorf("headless policy rejected %q: %v", kind, err)
		}
	}
	wantHeadless := []RegistrationKeyKind{
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindConnectorBootstrap,
	}
	for _, kind := range []RegistrationKeyKind{RegistrationKeyKindAccount, RegistrationKeyKindAgent} {
		refusal := headlessCfg.requireAllowedRegistrationKeyKind(string(kind))
		var disallowed *RegistrationKeyKindDisallowedError
		if !errors.As(refusal, &disallowed) || !errors.Is(refusal, ErrRegistrationKeyKindDisallowed) {
			t.Fatalf("headless policy error for %q = %v, want typed disallowed error", kind, refusal)
		}
		if !slices.Equal(disallowed.Allowed, wantHeadless) {
			t.Fatalf("headless allowed kinds = %v, want %v", disallowed.Allowed, wantHeadless)
		}
	}

	// The explicit option remains the one path that can admit the retired
	// agent kind, for a caller holding a legacy durable key.
	legacyCfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAgent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyCfg.requireAllowedRegistrationKeyKind(string(RegistrationKeyKindAgent)); err != nil {
		t.Errorf("explicit legacy policy rejected the agent kind: %v", err)
	}

	// The last policy option wins, so one binary can still widen to both.
	bothCfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeHeadlessEnrollment(),
		WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount, RegistrationKeyKindBootstrap),
		WithAgentRuntimeOTPProvider(testOTPProvider),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []RegistrationKeyKind{RegistrationKeyKindAccount, RegistrationKeyKindBootstrap} {
		if err := bothCfg.requireAllowedRegistrationKeyKind(string(kind)); err != nil {
			t.Errorf("mixed policy rejected %q: %v", kind, err)
		}
	}
	if err := bothCfg.requireAllowedRegistrationKeyKind(string(RegistrationKeyKindAgent)); !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
		t.Fatalf("mixed policy for agent kind = %v, want disallowed", err)
	}

	for _, kinds := range [][]RegistrationKeyKind{nil, {"future-kind"}} {
		_, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
			WithAgentRuntimeHub(runtimeTestHub()),
			WithAgentRuntimeAllowedRegistrationKeyKinds(kinds...),
		})
		if !errors.Is(err, ErrInvalidRegisterConfig) {
			t.Errorf("invalid native key-kind option %v = %v, want ErrInvalidRegisterConfig", kinds, err)
		}
	}
	if err := cfg.requireAllowedRegistrationKeyKind("future-kind"); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("unsupported authenticated key kind = %v, want ErrAssignmentInvalidResponse", err)
	}
}

// TestAgentRuntimeEnrollmentPolicyContradictions pins the other direction of
// the invariant: a provider under a policy that rejects OTP is a contradiction,
// not a harmless dead option, and is refused when the config is built.
func TestAgentRuntimeEnrollmentPolicyContradictions(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []AgentRuntimeRegistrationOption
		wantErr bool
	}{
		{
			name: "headless with provider",
			options: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeHeadlessEnrollment(),
				WithAgentRuntimeOTPProvider(testOTPProvider),
			},
			wantErr: true,
		},
		{
			name: "provider then headless",
			options: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeOTPProvider(testOTPProvider),
				WithAgentRuntimeHeadlessEnrollment(),
			},
			wantErr: true,
		},
		{
			name: "explicit pre-issued kinds with provider",
			options: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindBootstrap),
				WithAgentRuntimeOTPProvider(testOTPProvider),
			},
			wantErr: true,
		},
		{
			name: "headless widened back to account keeps the provider",
			options: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeHeadlessEnrollment(),
				WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount, RegistrationKeyKindBootstrap),
				WithAgentRuntimeOTPProvider(testOTPProvider),
			},
		},
		{
			name:    "headless alone",
			options: []AgentRuntimeRegistrationOption{WithAgentRuntimeHeadlessEnrollment()},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := append([]AgentRuntimeRegistrationOption{WithAgentRuntimeHub(runtimeTestHub())}, test.options...)
			_, err := newNativeAgentRuntimeConfig(opts)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidRegisterConfig) {
					t.Fatalf("config = %v, want ErrInvalidRegisterConfig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("config = %v, want nil", err)
			}
		})
	}
}

// TestRegisterAgentRuntime_ContradictoryPolicyFailsBeforeAnyIO proves the
// contradiction is caught while the config is built: no packet is sent and
// nothing on disk moves.
func TestRegisterAgentRuntime_ContradictoryPolicyFailsBeforeAnyIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		nil,
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(WithAgentRuntimeOTPProvider(testOTPProvider))...)
	if !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("headless plus provider = %v, want ErrInvalidRegisterConfig", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("contradictory policy Hub/cell counts = %d/%d, want 0/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Assignment != nil || state.PendingActivation != nil {
		t.Fatalf("contradictory policy mutated persisted state: %#v", state)
	}
}

// TestAgentRuntimeOTPProviderRequiredBeforeNetworkIO pins the fail-fast half of
// the default: whenever the account kind is accepted, a missing provider is a
// config error, not something discovered after a Hub round trip.
func TestAgentRuntimeOTPProviderRequiredBeforeNetworkIO(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []AgentRuntimeRegistrationOption
		wantErr error
	}{
		{
			name:    "default policy without provider",
			options: nil,
			wantErr: ErrAgentOTPRequired,
		},
		{
			name:    "explicit account opt-in without provider",
			options: []AgentRuntimeRegistrationOption{WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount)},
			wantErr: ErrAgentOTPRequired,
		},
		{
			name:    "default policy with provider",
			options: []AgentRuntimeRegistrationOption{WithAgentRuntimeOTPProvider(testOTPProvider)},
		},
		{
			name:    "headless escape hatch needs no provider",
			options: []AgentRuntimeRegistrationOption{WithAgentRuntimeHeadlessEnrollment()},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := append([]AgentRuntimeRegistrationOption{WithAgentRuntimeHub(runtimeTestHub())}, test.options...)
			cfg, err := newNativeAgentRuntimeConfig(opts)
			if err != nil {
				t.Fatalf("config = %v, want nil", err)
			}
			err = cfg.requireOTPProviderForPolicy()
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("policy = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("policy = %v, want %v", err, test.wantErr)
			}
		})
	}
}

// TestRegisterAgentRuntime_HeadlessKeyPolicy_AllFourKinds covers the escape
// hatch end to end: the two one-shot enrollment token kinds reach REG, while
// the account kind and the retired agent kind are refused before any cell I/O
// or OTP callback.
func TestRegisterAgentRuntime_HeadlessKeyPolicy_AllFourKinds(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindAgent,
		RegistrationKeyKindAccount,
	} {
		refused := kind == RegistrationKeyKindAccount || kind == RegistrationKeyKindAgent
		t.Run(string(kind), func(t *testing.T) {
			assignmentResult := strings.Replace(
				contract.InitialAssignment.Result.BodyJSON,
				`"key_kind":"bootstrap"`,
				fmt.Sprintf(`"key_kind":%q`, kind),
				1,
			)
			cellSteps := []runtimeUDPStep(nil)
			if !refused {
				cellSteps = []runtimeUDPStep{{
					requestType: relayknock.TypeRegister,
					replyType:   relayknock.TypeRegisterAck,
					replyBody:   `{"errCode":"52103","errMsg":"identity conflict","aspId":"agent"}`,
				}}
			}
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: assignmentResult}},
				cellSteps,
			)
			// No OTP provider is installed, and under this policy none can be: the
			// contradictory pair is rejected at config time, which is a stronger
			// guarantee than watching a callback that never fires.
			_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
				f.options()...)
			if refused {
				var disallowed *RegistrationKeyKindDisallowedError
				if !errors.As(err, &disallowed) || disallowed.Kind != kind {
					t.Fatalf("headless policy error for %q = %v, want typed %q rejection", kind, err, kind)
				}
				if len(f.cellUDP.snapshot()) != 0 {
					t.Fatalf("policy rejection for %q cell requests = %d, want 0", kind, len(f.cellUDP.snapshot()))
				}
				state, loadErr := f.store.LoadAgentState(context.Background())
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if state.Assignment != nil {
					t.Fatalf("disallowed assignment was persisted: %#v", state.Assignment)
				}
			} else {
				if !errors.Is(err, ErrAgentIdentityConflict) {
					t.Fatalf("headless native policy for %q = %v, want assigned-cell REG", kind, err)
				}
				requests := f.cellUDP.snapshot()
				if len(requests) != 1 || requests[0].typeID != relayknock.TypeRegister {
					t.Fatalf("headless native policy for %q made cell requests %v, want one REG", kind, requests)
				}
			}
			if len(f.hubUDP.snapshot()) != 1 {
				t.Fatalf("headless native policy for %q made %d Hub requests, want 1", kind, len(f.hubUDP.snapshot()))
			}
		})
	}
}

// TestRegisterAgentRuntime_OTPIsTheDefaultPolicy proves the shipped default:
// with no policy option at all, an account credential enrolls and the OTP
// callback fires.
func TestRegisterAgentRuntime_OTPIsTheDefaultPolicy(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{
				requestType: relayknock.TypeRegister,
				replyType:   relayknock.TypeRegisterAck,
				replyBody:   `{"errCode":"52103","errMsg":"identity conflict","aspId":"agent"}`,
			},
		},
	)
	var otpCallbacks atomic.Int32
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.defaultPolicyOptions(
			WithAgentRuntimeOTPProvider(func(context.Context, AgentOTPChallenge) (string, error) {
				otpCallbacks.Add(1)
				return "12345678", nil
			}),
		)...)
	if !errors.Is(err, ErrAgentIdentityConflict) {
		t.Fatalf("default OTP enrollment = %v, want assigned-cell REG", err)
	}
	if otpCallbacks.Load() != 1 {
		t.Fatalf("default OTP callbacks = %d, want 1", otpCallbacks.Load())
	}
}

// TestRegisterAgentRuntime_PreIssuedCredentialNeedsHeadlessOptIn pins the other
// half of the flip: a pre-issued credential under the default policy is refused
// with the typed error that names the escape hatch, after the Hub round trip
// that reported the kind and before any cell I/O.
func TestRegisterAgentRuntime_PreIssuedCredentialNeedsHeadlessOptIn(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		nil,
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.defaultPolicyOptions(WithAgentRuntimeOTPProvider(testOTPProvider))...)
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindBootstrap {
		t.Fatalf("bootstrap credential under default policy = %v, want typed bootstrap rejection", err)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("rejection Hub/cell counts = %d/%d, want 1/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	// The guide tells readers a wrong first guess is free, so pin exactly what a
	// rejected attempt leaves behind: the agent identity persists (the retry
	// reuses it rather than enrolling a second one), but no assignment or
	// pending activation does.
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.AgentID == "" || state.PublicKeyB64 == "" {
		t.Fatalf("rejected attempt did not retain a reusable identity: %#v", state)
	}
	if state.Assignment != nil || state.PendingActivation != nil || state.RegisteredAt != nil {
		t.Fatalf("rejected attempt persisted registration progress: %#v", state)
	}
}

// TestRegisterAgentRuntime_AccountOptInStillRequiresOTPProviderBeforeAnyIO
// keeps the explicit opt-in honest: naming the account kind without a provider
// is now caught at config time, so no Hub request is made at all.
func TestRegisterAgentRuntime_AccountOptInStillRequiresOTPProviderBeforeAnyIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")}},
		nil,
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
		)...)
	if !errors.Is(err, ErrAgentOTPRequired) {
		t.Fatalf("account opt-in without provider = %v, want ErrAgentOTPRequired", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("missing-provider Hub/cell counts = %d/%d, want 0/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestValidateNativeDeviceCredential_ExactShape(t *testing.T) {
	valid := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	if err := validateNativeDeviceCredential(valid, "test credential", ErrInvalidRegisterConfig); err != nil {
		t.Fatalf("valid native device credential: %v", err)
	}
	if valid != canonicalNativeDeviceCredential {
		t.Fatalf("canonical fixture = %q, want %q", valid, canonicalNativeDeviceCredential)
	}
	allOnesBody := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, deviceKeyRandomLength))
	noncanonical := valid[:len(valid)-1] + "9"
	canonicalBytes, err := base64.RawURLEncoding.DecodeString(valid[len(deviceKeyPrefix):])
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalBytes, err := base64.RawURLEncoding.DecodeString(noncanonical[len(deviceKeyPrefix):])
	if err != nil || !bytes.Equal(noncanonicalBytes, canonicalBytes) {
		t.Fatalf("test setup: noncanonical spelling must decode to the canonical bytes: %x / %x, %v", noncanonicalBytes, canonicalBytes, err)
	}
	tests := map[string]string{
		"wrong prefix":               "lv_test_" + valid[len(deviceKeyPrefix):],
		"wrong decoded length":       deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, deviceKeyRandomLength-1)),
		"padding":                    valid + "=",
		"standard alphabet":          deviceKeyPrefix + strings.Replace(allOnesBody, "_", "/", 1),
		"invalid body":               deviceKeyPrefix + "!" + valid[len(deviceKeyPrefix)+1:],
		"noncanonical trailing bits": noncanonical,
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateNativeDeviceCredential(candidate, "test credential", ErrInvalidRegisterConfig)
			if !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("validateNativeDeviceCredential(%q) = %v, want ErrInvalidRegisterConfig", candidate, err)
			}
		})
	}
}

func TestNativeDeviceCredentialValidation_FailsClosedForPersistedState(t *testing.T) {
	invalid := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, deviceKeyRandomLength-1))
	completed := &AgentState{AgentID: "agent-conform", DeviceAPIKey: invalid, DeviceAPIKeyID: "key_AbCdEf123456"}
	err := validatePersistedNativeDeviceCredential(completed, ErrInvalidRegisterConfig)
	if !errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("completed malformed native credential error = %v", err)
	}
	var nativeRecovery *NativeCredentialRecoveryRequiredError
	if !errors.As(err, &nativeRecovery) || strings.Contains(err.Error(), "HTTP recovery") {
		t.Fatalf("native malformed credential guidance = %T: %v", err, err)
	}

	pending := &AgentState{
		Assignment: &AgentAssignment{CellID: "cell0", AssignmentGeneration: 1},
		PendingCompletion: &PendingAgentCompletion{
			DeviceAPIKey: invalid, CellID: "cell0", AssignmentGeneration: 1,
		},
	}
	if err := validateLoadedAgentAssignment(pending); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("pending malformed native credential error = %v, want ErrInvalidAgentState", err)
	}
}

func TestRegisterAgentRuntime_RejectsMutuallyExclusiveRecoveryMarkersBeforeIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply(
		[]byte(contract.InitialAssignment.Result.BodyJSON),
		"agent-conform",
		assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	activation.AgentID = "agent-conform"
	activation.Assignment = initial.Assignment.clone()
	activation.SchemaVersion = agentStateSchemaVersion
	activation.PendingActivation, err = newPendingAgentActivation(
		initial,
		activation,
		"conformance-host",
		"0.0.0-conformance",
		conformance.AgentAssignmentBootstrapCredentialFixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLoadedAgentAssignment(activation); err != nil {
		t.Fatalf("valid activation fixture: %v", err)
	}

	completion := activation.clone()
	completion.PendingActivation = nil
	completion.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey:                  canonicalNativeDeviceCredential,
		CellID:                        completion.Assignment.CellID,
		AssignmentGeneration:          completion.Assignment.AssignmentGeneration,
		RecoveryAnchorTicketExpiresAt: activation.PendingActivation.RecoveryAnchorTicketExpiresAt,
		RecoveryExpiresAt:             activation.PendingActivation.RecoveryExpiresAt,
	}
	if err := validateLoadedAgentAssignment(completion); err != nil {
		t.Fatalf("valid completion fixture: %v", err)
	}

	pendingCompletion := func(state *AgentState) *PendingAgentCompletion {
		return &PendingAgentCompletion{
			DeviceAPIKey:                  canonicalNativeDeviceCredential,
			CellID:                        state.Assignment.CellID,
			AssignmentGeneration:          state.Assignment.AssignmentGeneration,
			RecoveryAnchorTicketExpiresAt: activation.PendingActivation.RecoveryAnchorTicketExpiresAt,
			RecoveryExpiresAt:             activation.PendingActivation.RecoveryExpiresAt,
		}
	}
	tests := []struct {
		name       string
		base       *AgentState
		credential string
		mutate     func(*AgentState)
	}{
		{
			name: "activation with pending completion", base: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate:     func(state *AgentState) { state.PendingCompletion = pendingCompletion(state) },
		},
		{
			name: "activation with registered at", base: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate: func(state *AgentState) {
				registeredAt := assignmentFixtureNow
				state.RegisteredAt = &registeredAt
			},
		},
		{
			name: "activation with device API key", base: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate:     func(state *AgentState) { state.DeviceAPIKey = canonicalNativeDeviceCredential },
		},
		{
			name: "activation with device API key id", base: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate:     func(state *AgentState) { state.DeviceAPIKeyID = "key_AbCdEf123456" },
		},
		{
			name: "completion with pending activation", base: completion,
			mutate: func(state *AgentState) {
				state.PendingActivation = activation.clone().PendingActivation
			},
		},
		{
			name: "completion with registered at", base: completion,
			mutate: func(state *AgentState) {
				registeredAt := assignmentFixtureNow
				state.RegisteredAt = &registeredAt
			},
		},
		{
			name: "completion with device API key", base: completion,
			mutate: func(state *AgentState) {
				state.DeviceAPIKey = canonicalNativeDeviceCredential
			},
		},
		{
			name: "completion with device API key id", base: completion,
			mutate: func(state *AgentState) {
				state.DeviceAPIKeyID = "key_AbCdEf123456"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := test.base.clone()
			test.mutate(state)
			fixture := newRuntimeFixture(t, nil, nil)
			if err := fixture.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, _, err := RegisterAgentRuntime(
				context.Background(),
				test.credential,
				fixture.store,
				fixture.options(
					WithAgentRuntimeUDPResolver(resolver),
					WithAgentRuntimeUDPDialer(dialer),
				)...,
			)
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("mutually exclusive state error = %v, want invalid persisted state", err)
			}
			if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 ||
				len(fixture.hubUDP.snapshot()) != 0 || len(fixture.cellUDP.snapshot()) != 0 {
				t.Fatalf(
					"mutually exclusive state performed I/O: resolver=%d dialer=%d Hub=%d cell=%d",
					resolver.calls.Load(), dialer.calls.Load(),
					len(fixture.hubUDP.snapshot()), len(fixture.cellUDP.snapshot()),
				)
			}
		})
	}
}

func TestNewPendingAgentActivation_RequiresInitialAssignmentMatch(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply(
		[]byte(contract.InitialAssignment.Result.BodyJSON),
		"agent-conform",
		assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	state.AgentID = "agent-conform"
	state.Assignment = initial.Assignment.clone()
	state.Assignment.EndpointRevision++
	_, err = newPendingAgentActivation(initial, state, "host", "version", conformance.AgentAssignmentBootstrapCredentialFixture)
	if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), "does not match initial assignment") {
		t.Fatalf("assignment mismatch = %v, want invalid config", err)
	}
}

func TestRegisterAgentRuntime_UDPOnlyGoldenLifecycle(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	var httpCalls atomic.Int32
	refusingHTTP := doerFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, errors.New("HTTP is forbidden during native enrollment")
	})

	client, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(WithAgentClientHTTPClient(refusingHTTP))...)
	if err != nil {
		t.Fatalf("RegisterAgentRuntime: %v", err)
	}
	if client == nil || binding == nil {
		t.Fatalf("runtime result = client %v, binding %v", client, binding)
	}
	defer binding.Destroy()
	if httpCalls.Load() != 0 {
		t.Fatalf("native enrollment made %d HTTP calls", httpCalls.Load())
	}
	if binding.CellID != "cell0" || binding.AssignmentGeneration != 1 || binding.EndpointRevision != 1 || binding.NHPUDPEndpoint.Host != "cell0.nhp.layerv.ai" || binding.DeviceAPIKeyID != "key_DvK9mN2pQr7S" {
		t.Fatalf("native binding = %s", binding)
	}
	if rendered := fmt.Sprintf("%#v", binding); strings.Contains(rendered, conformance.AgentAssignmentDeviceAPIKeyFixture) || strings.Contains(rendered, binding.NHPUDPEndpoint.ServerPublicKeyB64) {
		t.Fatalf("binding formatting leaked a secret or server key: %s", rendered)
	}
	hubRequests := f.hubUDP.snapshot()
	cellRequests := f.cellUDP.snapshot()
	if len(hubRequests) != 1 || string(hubRequests[0].body) != contract.InitialAssignment.Request.BodyJSON {
		t.Fatalf("initial Hub request = %v, want golden %q", hubRequests, contract.InitialAssignment.Request.BodyJSON)
	}
	if len(cellRequests) != 2 || string(cellRequests[0].body) != contract.AssignedCellRegistration.Request.BodyJSON || string(cellRequests[1].body) != contract.RegistrationCompletion.Request.BodyJSON {
		t.Fatalf("assigned-cell registration/completion bodies = %v", cellRequests)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.DeviceAPIKey != conformance.AgentAssignmentDeviceAPIKeyFixture || state.DeviceAPIKeyID != "key_DvK9mN2pQr7S" || state.PendingActivation != nil || state.PendingCompletion != nil || state.RegisteredAt == nil {
		t.Fatalf("completed native state = %#v", state)
	}
	for i, snapshot := range f.store.snapshots() {
		persisted, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(persisted, []byte(conformance.AgentAssignmentInitialRequestNonceFixture)) {
			t.Fatalf("assignment request nonce persisted in state snapshot %d: %s", i, persisted)
		}
	}
	activationWasDurable := false
	pendingWasDurable := false
	for _, snapshot := range f.store.snapshots() {
		if snapshot.PendingActivation != nil && snapshot.PendingActivation.AssignmentTicket == "conformance-assignment-ticket-0001" && snapshot.PendingCompletion == nil {
			activationWasDurable = true
		}
		if snapshot.PendingCompletion != nil && snapshot.PendingCompletion.DeviceAPIKey == conformance.AgentAssignmentDeviceAPIKeyFixture && snapshot.RegisteredAt == nil {
			pendingWasDurable = true
		}
	}
	if !activationWasDurable {
		t.Fatal("assignment ticket and binding were not durably saved before REG")
	}
	if !pendingWasDurable {
		t.Fatal("device credential candidate was not durably saved before completion")
	}
	hubCalls, cellCalls := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
	_, reopened, err := RegisterAgentRuntime(context.Background(), "", f.store, f.options()...)
	if err != nil || reopened == nil {
		t.Fatalf("completed fast path with no enrollment credential = %v, %v", reopened, err)
	}
	reopened.Destroy()
	if len(f.hubUDP.snapshot()) != hubCalls || len(f.cellUDP.snapshot()) != cellCalls {
		t.Fatal("completed fast path with no enrollment credential performed UDP I/O")
	}
}

func TestRegisterAgentRuntime_ReturnedPrivateKeyKnocksImmediately(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initialResult := strings.Replace(
		contract.InitialAssignment.Result.BodyJSON,
		`"lease_expires_at":"2026-07-16T12:00:00Z"`,
		`"lease_expires_at":"`+time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)+`"`,
		1,
	)
	knockBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-fresh"},"preActions":{"resource-public-key":null}}`
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: initialResult}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
			{requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK, replyBody: knockBody},
		},
	)
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || binding == nil {
		t.Fatalf("fresh runtime = %v, %v", binding, err)
	}
	defer binding.Destroy()
	privateKey := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(privateKey)
	if len(privateKey) != x25519key.Size {
		t.Fatalf("fresh runtime returned private key length = %d, want %d", len(privateKey), x25519key.Size)
	}
	knock, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil || knock == nil || knock.ACToken != "ac-fresh" {
		t.Fatalf("fresh returned-key knock = %#v, %v", knock, err)
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || requests[2].typeID != relayknock.TypeKnock {
		t.Fatalf("fresh lifecycle/knock requests = %v, want REG, completion, knock", requests)
	}
}

func TestKnockRegisteredAgent_UsesAuthoritativeAssignedCell(t *testing.T) {
	contract := loadAssignmentFixture(t)
	knockBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"},"preActions":{"resource-public-key":null}}`
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK, replyBody: knockBody}})
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))},
	}
	binding := &AgentRuntimeBinding{
		AgentID: "agent-conform", PublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)), CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: assignment.Endpoint,
		authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)),
		authoritativeAssignment: assignment.clone(),
	}
	privateKey := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(privateKey)
	result, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil {
		t.Fatalf("KnockRegisteredAgent: %v", err)
	}
	if result.ACToken != "ac-secret" || result.ResourceHost != "frps.cell0.example:7000" {
		t.Fatalf("native knock result = %s", result)
	}
	if rendered := fmt.Sprintf("%#v", result); strings.Contains(rendered, result.ACToken) {
		t.Fatalf("native knock result leaked bearer token: %s", rendered)
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeKnock {
		t.Fatalf("native knock requests = %v", requests)
	}
}

func TestKnockRegisteredAgent_CookieChallengeReResolvesForOneBoundReknock(t *testing.T) {
	contract := loadAssignmentFixture(t)
	cookie := bytes.Repeat([]byte{0x7a}, 32)
	knockBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"},"preActions":{"resource-public-key":null}}`
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeKnock, replyType: relayknock.TypeCookieChallenge, reknockCookie: cookie, replyCounterDelta: 1,
	}})
	// Model DNS/NLB routing the second exchange to another cell replica. Both
	// replicas share the assignment's server identity and the stateless cookie
	// material, so the RKN remains authenticated and bound to the first KNK.
	reknockServer := newRuntimeUDPServer(
		t,
		assignmentHex(t, contract.Keys.AssignedCell.StaticPrivHex),
		assignmentHex(t, contract.Keys.Agent.StaticPubHex),
		runtimeUDPStep{requestType: relayknock.TypeReknock, replyType: relayknock.TypeACK, replyBody: knockBody, reknockCookie: cookie},
	)
	knockAddress := netip.MustParseAddr("9.9.9.9")
	reknockAddress := netip.MustParseAddr("149.112.112.112")
	var resolveCalls atomic.Int32
	resolver := assignmentTestResolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "cell0.nhp.layerv.ai" {
			return nil, fmt.Errorf("unexpected resolution %q %q", network, host)
		}
		switch resolveCalls.Add(1) {
		case 1:
			return []netip.Addr{knockAddress}, nil
		case 2:
			return []netip.Addr{reknockAddress}, nil
		default:
			return nil, errors.New("unexpected third resolution")
		}
	})
	dialer := runtimeRouteDialer{targets: map[string]string{
		knockAddress.String():   f.cellUDP.conn.LocalAddr().String(),
		reknockAddress.String(): reknockServer.conn.LocalAddr().String(),
	}}
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))},
	}
	binding := &AgentRuntimeBinding{
		AgentID: "agent-conform", PublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)), CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: assignment.Endpoint,
		authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)),
		authoritativeAssignment: assignment.clone(),
	}
	privateKey := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(privateKey)
	if _, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1)); err != nil {
		t.Fatalf("KnockRegisteredAgent COK→RKN: %v", err)
	}
	if resolveCalls.Load() != 2 {
		t.Fatalf("assignment-host resolution count = %d, want KNK and RKN resolved separately", resolveCalls.Load())
	}
	knockRequests := f.cellUDP.snapshot()
	reknockRequests := reknockServer.snapshot()
	if len(knockRequests) != 1 || knockRequests[0].typeID != relayknock.TypeKnock || len(reknockRequests) != 1 || reknockRequests[0].typeID != relayknock.TypeReknock {
		t.Fatalf("cross-replica session packets = KNK %#v, RKN %#v; want exactly one of each", knockRequests, reknockRequests)
	}
	var knk, rkn nativeAgentKnockBody
	if err := json.Unmarshal(knockRequests[0].body, &knk); err != nil {
		t.Fatalf("decode KNK body: %v", err)
	}
	if err := json.Unmarshal(reknockRequests[0].body, &rkn); err != nil {
		t.Fatalf("decode RKN body: %v", err)
	}
	if knk.HeaderType != nhpKNKHeaderType || rkn.HeaderType != nhpRKNHeaderType || knk.UserID != rkn.UserID || knk.DeviceID != rkn.DeviceID || knk.AuthServiceID != rkn.AuthServiceID || knk.KnockResourceID != rkn.KnockResourceID || knk.RunID != rkn.RunID {
		t.Fatalf("KNK/RKN session bodies drifted: knk=%#v rkn=%#v", knk, rkn)
	}
}

func TestKnockRegisteredAgent_MalformedCookieChallengeFailsWithoutReknock(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeKnock,
		replyType:   relayknock.TypeCookieChallenge,
		replyBody:   `{"trxId":0,"cookie":"***"}`,
	}})
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))},
	}
	binding := &AgentRuntimeBinding{
		AgentID: "agent-conform", PublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)), CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: assignment.Endpoint,
		authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)),
		authoritativeAssignment: assignment.clone(),
	}
	privateKey := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(privateKey)
	_, err := KnockRegisteredAgent(context.Background(), binding, privateKey, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if !errors.Is(err, ErrMalformedReply) {
		t.Fatalf("malformed COK error = %v, want ErrMalformedReply", err)
	}
	requests := waitRuntimeUDPRequests(t, f.cellUDP, 1)
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeKnock {
		t.Fatalf("malformed COK session packets = %#v, want exactly one KNK", requests)
	}
}

func TestExitRegisteredAgentSession_UsesEXTAndDoesNotChangeBinding(t *testing.T) {
	contract := loadAssignmentFixture(t)
	ackBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":1,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"},"preActions":{"resource-public-key":null}}`
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{requestType: relayknock.TypeExit, replyType: relayknock.TypeACK, replyBody: ackBody}})
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))},
	}
	binding := &AgentRuntimeBinding{
		AgentID: "agent-conform", PublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)), CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: assignment.Endpoint,
		authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex)),
		authoritativeAssignment: assignment.clone(),
	}
	privateKey := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(privateKey)
	if err := ExitRegisteredAgentSession(context.Background(), binding, privateKey, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1)); err != nil {
		t.Fatalf("ExitRegisteredAgentSession: %v", err)
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeExit {
		t.Fatalf("exit packet types = %#v, want one EXT", requests)
	}
	var ext nativeAgentKnockBody
	if err := json.Unmarshal(requests[0].body, &ext); err != nil {
		t.Fatalf("decode EXT body: %v", err)
	}
	if ext.HeaderType != nhpEXTHeaderType || ext.RunID != "0123456789abcdef" {
		t.Fatalf("EXT body = %#v, want header type %d and caller RunID", ext, nhpEXTHeaderType)
	}
	if binding.assignment() == nil || binding.CellID != "cell0" || binding.AssignmentGeneration != 1 || binding.EndpointRevision != 1 {
		t.Fatalf("clean exit mutated durable binding: %#v", binding)
	}
}

func TestKnockRegisteredAgent_RejectsIdentityDriftBeforeIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	agentPublic := base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.Agent.StaticPubHex))
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1,
		LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)),
		},
	}
	validPrivate := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(validPrivate)
	wrongPrivate := bytes.Repeat([]byte{0x42}, x25519key.Size)
	defer wipeBytes(wrongPrivate)
	wrongKey, err := ecdh.X25519().NewPrivateKey(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic := base64.StdEncoding.EncodeToString(wrongKey.PublicKey().Bytes())

	tests := map[string]func(*AgentRuntimeBinding) []byte{
		"wrong private key": func(*AgentRuntimeBinding) []byte { return wrongPrivate },
		"mutated public key": func(binding *AgentRuntimeBinding) []byte {
			binding.PublicKeyB64 = wrongPublic
			return validPrivate
		},
		"mutated agent id": func(binding *AgentRuntimeBinding) []byte {
			binding.AgentID = "agent-mutated"
			return validPrivate
		},
		"mutated identity and matching wrong key": func(binding *AgentRuntimeBinding) []byte {
			binding.AgentID = "agent-mutated"
			binding.PublicKeyB64 = wrongPublic
			return wrongPrivate
		},
		"malformed authoritative public key": func(binding *AgentRuntimeBinding) []byte {
			binding.PublicKeyB64 = "not-base64"
			binding.authoritativePublicKeyB64 = "not-base64"
			return validPrivate
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			binding := &AgentRuntimeBinding{
				AgentID: "agent-conform", PublicKeyB64: agentPublic,
				CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
				EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: assignment.Endpoint,
				authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: agentPublic,
				authoritativeAssignment: assignment.clone(),
			}
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, err := KnockRegisteredAgent(context.Background(), binding, mutate(binding), "resource-public-key",
				NativeKnockOptions{RunID: "0123456789abcdef"},
				WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
			if !errors.Is(err, ErrInvalidNativeKnockInput) {
				t.Fatalf("identity drift error = %v, want ErrInvalidNativeKnockInput", err)
			}
			if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 {
				t.Fatalf("identity drift resolver/dial calls = %d/%d, want 0/0", resolver.calls.Load(), dialer.calls.Load())
			}
		})
	}
}

func TestConsumeNativeAgentKnockReply_WipesBearerBody(t *testing.T) {
	assertWiped := func(t *testing.T, body []byte) {
		t.Helper()
		for i, value := range body {
			if value != 0 {
				t.Fatalf("reply body byte %d = 0x%02x after consume, want zero", i, value)
			}
		}
	}
	successBody := []byte(`{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"}}`)
	result, err := consumeNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: successBody}, "resource-public-key")
	if err != nil || result == nil || result.ACToken != "ac-secret" {
		t.Fatalf("consume success = %#v, %v", result, err)
	}
	assertWiped(t, successBody)
	if result.ACToken != "ac-secret" {
		t.Fatal("wiping the raw ACK body corrupted the returned token copy")
	}

	malformedBody := []byte(`{"errCode":`)
	if _, err := consumeNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: malformedBody}, "resource-public-key"); err == nil {
		t.Fatal("malformed ACK was accepted")
	}
	assertWiped(t, malformedBody)

	denyBody := []byte(`{"errCode":"52004","errMsg":"denied"}`)
	_, err = consumeNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: denyBody}, "resource-public-key")
	var deny *ServerDenyError
	if !errors.As(err, &deny) || deny.ErrCode != "52004" || errors.Is(err, ErrMalformedReply) {
		t.Fatalf("authenticated native deny = %T: %v, want ServerDenyError(52004)", err, err)
	}
	assertWiped(t, denyBody)
}

func TestInterpretNativeAgentKnockReply_ErrCodePresenceAndDenyPrecedence(t *testing.T) {
	// A non-empty wantDenyCode expects *ServerDenyError carrying exactly that
	// code; an empty one expects ErrMalformedReply. Every canonical non-success
	// errCode is an authenticated deny — the vocabulary is the producer's, so no
	// digit code is "unknown enough" to become malformed. Malformed stays
	// reserved for genuinely malformed replies: a missing/null errCode or a
	// value outside the producer's decimal-digit code grammar (surrounding
	// whitespace, free-form text), which also keeps producer-controlled text out
	// of ServerDenyError's public rendering.
	tests := map[string]struct {
		body         string
		wantDenyCode string
	}{
		"deny needs no success fields":     {body: `{"errCode":"52004"}`, wantDenyCode: "52004"},
		"deny resource not found":          {body: `{"errCode":"52004","errMsg":"failed to find resource"}`, wantDenyCode: "52004"},
		"deny knock server not found":      {body: `{"errCode":"51002","errMsg":"failed to find knock server"}`, wantDenyCode: "51002"},
		"deny ac operation failed":         {body: `{"errCode":"52005","errMsg":"server ac operation failed"}`, wantDenyCode: "52005"},
		"deny asp not found":               {body: `{"errCode":"52002","errMsg":"failed to find auth service provider"}`, wantDenyCode: "52002"},
		"deny code outside pinned vectors": {body: `{"errCode":"59999"}`, wantDenyCode: "59999"},
		"missing errCode":                  {body: `{"errMsg":"denied"}`},
		"null errCode":                     {body: `{"errCode":null}`},
		"noncanonical errCode":             {body: `{"errCode":" 52101"}`},
		"noncanonical success errCode":     {body: `{"errCode":"  0  "}`},
		"free-form errCode":                {body: `{"errCode":"lv_live_not_a_code"}`},
		"success needs success fields":     {body: `{"errCode":"0"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(test.body)}, "resource-public-key")
			var deny *ServerDenyError
			if test.wantDenyCode != "" {
				if !errors.As(err, &deny) || deny.ErrCode != test.wantDenyCode || errors.Is(err, ErrMalformedReply) {
					t.Fatalf("deny classification error = %T: %v, want ServerDenyError(%s)", err, err, test.wantDenyCode)
				}
				return
			}
			if !errors.Is(err, ErrMalformedReply) || errors.As(err, &deny) {
				t.Fatalf("presence error = %T: %v, want ErrMalformedReply", err, err)
			}
		})
	}
}

func TestInterpretNativeAgentKnockReply_SuccessErrCodeVocabulary(t *testing.T) {
	// The knock ACK success vocabulary is {"", "0"}, matching the portal path's
	// isSuccess predicate and the conformance ack_success_empty_err_code vector.
	for name, errCode := range map[string]string{"zero": "0", "empty string": ""} {
		t.Run(name, func(t *testing.T) {
			body := []byte(`{"errCode":"` + errCode + `","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"}}`)
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: body}, "resource-public-key")
			if err != nil || result == nil || result.ACToken != "ac-secret" || result.ResourceHost != "frps.cell0.example:7000" {
				t.Fatalf("success reply = %#v, %v", result, err)
			}
		})
	}
}

func TestRegisterAgentRuntime_RejectsIncompleteCredentialStateBeforeIO(t *testing.T) {
	tests := map[string]func(*AgentState){
		"device credential":    func(state *AgentState) { state.DeviceAPIKey = canonicalNativeDeviceCredential },
		"device credential id": func(state *AgentState) { state.DeviceAPIKeyID = "key_AbCdEf123456" },
		"both": func(state *AgentState) {
			state.DeviceAPIKey = canonicalNativeDeviceCredential
			state.DeviceAPIKeyID = "key_AbCdEf123456"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil)
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			mutate(state)
			if err := f.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, _, err = RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
				WithAgentRuntimeHeadlessEnrollment(), WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
			if !errors.Is(err, ErrInvalidAgentState) {
				t.Fatalf("incomplete credential state error = %v, want ErrInvalidAgentState", err)
			}
			if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("incomplete credential state resolver/dial/Hub/cell calls = %d/%d/%d/%d, want zero",
					resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRegisterAgentRuntime_InitialIdentitySaveUsesBindingPersistenceTaxonomy(t *testing.T) {
	f := newRuntimeFixture(t, nil, nil)
	inner, ok := f.store.inner.(*FileAgentStateStore)
	if !ok {
		t.Fatalf("fixture store = %T, want *FileAgentStateStore", f.store.inner)
	}
	if err := os.Remove(inner.path); err != nil {
		t.Fatal(err)
	}
	f.store.fail = 1

	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("initial identity save error = %v, want ErrAgentBindingPersistence", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("initial identity save failure contacted Hub/cell: %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_RejectsNonCanonicalPersistedNativeAgentIDBeforeMutationOrIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for name, agentID := range map[string]string{
		"missing":    "",
		"whitespace": " agent-conform ",
		"uppercase":  "Agent-conform",
		"malformed":  "agent_conform",
	} {
		t.Run(name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil)
			initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			state.AgentID = agentID
			state.Assignment = initial.Assignment.clone()
			if err := f.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			beforeSaves := len(f.store.snapshots())
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, _, err = RegisterAgentRuntime(context.Background(), "", f.store,
				WithAgentRuntimeHeadlessEnrollment(), WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("persisted native agent id %q error = %v, want invalid state/config", agentID, err)
			}
			if len(f.store.snapshots()) != beforeSaves || resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("invalid native id mutated/performed I/O: saves=%d/%d resolver=%d dialer=%d Hub=%d cell=%d",
					len(f.store.snapshots()), beforeSaves, resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRegisterAgentRuntime_CompletedIdentityMismatchFailsBeforeIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := assignmentFixtureNow
	state.RegisteredAt = &registeredAt
	state.Assignment = initial.Assignment.clone()
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_DvK9mN2pQr7S"
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	resolver := &noIONativeResolver{}
	dialer := &noIONativeDialer{}
	_, _, err = RegisterAgentRuntime(context.Background(), "unused-on-completed-fast-path", f.store,
		WithAgentRuntimeHeadlessEnrollment(), WithAgentRuntimeHub(f.hub), WithAgentRuntimeIdentity("agent-different"),
		WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
	if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("completed identity mismatch error = %v, want ErrInvalidRegisterConfig mismatch", err)
	}
	if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("completed mismatch resolver/dial/Hub/cell calls = %d/%d/%d/%d, want zero",
			resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_FreshEnrollmentRequiresCredentialBeforeMutationOrIO(t *testing.T) {
	for name, credential := range map[string]string{
		"empty":             "",
		"low entropy shape": "user-chosen-password",
	} {
		t.Run(name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil)
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, _, err := RegisterAgentRuntime(context.Background(), credential, f.store,
				WithAgentRuntimeHeadlessEnrollment(), WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
			if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), "enrollment credential") {
				t.Fatalf("fresh invalid credential error = %v", err)
			}
			if len(f.store.snapshots()) != 0 || resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("fresh invalid credential mutated/performed I/O: saves=%d resolver=%d dialer=%d Hub=%d cell=%d",
					len(f.store.snapshots()), resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRunCompletionExchange_DeadlineDuringBackoffRequiresRecovery(t *testing.T) {
	contract := loadAssignmentFixture(t)
	agentPrivate := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	defer wipeBytes(agentPrivate)
	resolver := &noIONativeResolver{}
	dialer := &noIONativeDialer{}
	fixed := assignmentFixtureNow
	const budget = 20 * time.Millisecond
	cfg := &nativeAgentRuntimeConfig{
		resolver: resolver, dialer: dialer, timeout: time.Millisecond, maxAddresses: 1,
		clock: func() time.Time { return fixed },
		assignmentOptions: []AssignmentOption{
			WithAssignmentRetryBudget(2, budget),
			withAssignmentClock(func() time.Time { return fixed }),
			withAssignmentJitter(func(time.Duration) (time.Duration, error) { return time.Millisecond, nil }),
			withAssignmentSleep(func(ctx context.Context, _ time.Duration) error {
				<-ctx.Done()
				return ctx.Err()
			}),
		},
	}
	endpoint := nativeudp.Endpoint{
		Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
		ServerStaticPub: assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex),
	}
	_, err := cfg.runCompletionExchange(context.Background(), endpoint, []byte(`{"query":"register_agent"}`), cfg.udpOptions(agentPrivate))
	var recovery *CompletionRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrCompletionRecoveryRequired) ||
		!errors.Is(err, nativeudp.ErrTransport) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("completion deadline error = %v, want typed recovery preserving transport and deadline causes", err)
	}
	if recovery.Attempts != 1 || recovery.Elapsed != budget {
		t.Fatalf("completion recovery attempts/elapsed = %d/%s, want 1/%s", recovery.Attempts, recovery.Elapsed, budget)
	}
	if resolver.calls.Load() != 1 || dialer.calls.Load() != 1 {
		t.Fatalf("completion resolver/dial calls = %d/%d, want 1/1", resolver.calls.Load(), dialer.calls.Load())
	}
}

func TestRegisterAgentRuntime_RateLimitRetriesSameHubOperationWithinBudget(t *testing.T) {
	contract := loadAssignmentFixture(t)
	const reflectedSecret = "lv_live_rate_limit_reflection"
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52204","errMsg":"` + reflectedSecret + `","retryAfterSeconds":1}`},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	now := assignmentFixtureNow
	var slept []time.Duration
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAssignmentRetryBudget(2, 5*time.Second),
			withAgentRuntimeClock(func() time.Time { return now }),
			withTestAgentRuntimeAssignmentSleep(func(_ context.Context, delay time.Duration) error {
				slept = append(slept, delay)
				now = now.Add(delay)
				return nil
			}),
		)...)
	if err != nil || binding == nil {
		t.Fatalf("rate-limited lifecycle = %v, %v", binding, err)
	}
	binding.Destroy()
	if !slices.Equal(slept, []time.Duration{time.Second}) || len(f.hubUDP.snapshot()) != 2 {
		t.Fatalf("rate-limit sleeps/Hub calls = %v/%d, want [1s]/2", slept, len(f.hubUDP.snapshot()))
	}
	hubRequests := f.hubUDP.snapshot()
	if !bytes.Equal(hubRequests[0].body, hubRequests[1].body) {
		t.Fatalf("rate-limit retry changed the logical Hub request body: %v", hubRequests)
	}
	if strings.Contains(fmt.Sprint(err), reflectedSecret) {
		t.Fatalf("rate-limit lifecycle leaked Hub diagnostic: %v", err)
	}
}

func TestRegisterAgentRuntime_RateLimitExceedingBudgetRequiresRecovery(t *testing.T) {
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52204","errMsg":"ignored","retryAfterSeconds":1}`}},
		nil,
	)
	var sleepCalls atomic.Int32
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAssignmentRetryBudget(2, 500*time.Millisecond),
			withTestAgentRuntimeAssignmentSleep(func(context.Context, time.Duration) error { sleepCalls.Add(1); return nil }),
		)...)
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, ErrAssignmentRateLimited) {
		t.Fatalf("over-budget rate limit = %T: %v, want typed recovery preserving rate limit", err, err)
	}
	if recovery.Attempts != 1 || sleepCalls.Load() != 0 || len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("over-budget attempts/sleeps/Hub = %d/%d/%d, want 1/0/1", recovery.Attempts, sleepCalls.Load(), len(f.hubUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_RateLimitParentCancellationWins(t *testing.T) {
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52204","errMsg":"ignored","retryAfterSeconds":1}`}},
		nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	_, _, err := RegisterAgentRuntime(ctx, conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAssignmentRetryBudget(2, 5*time.Second),
			withTestAgentRuntimeAssignmentSleep(func(context.Context, time.Duration) error {
				cancel()
				return context.Canceled
			}),
		)...)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("parent cancellation = %v, want context.Canceled only", err)
	}
}

func TestRegisterAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, noReply: true},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrCompletionRecoveryRequired) {
		t.Fatalf("lost completion reply error = %v, want ErrCompletionRecoveryRequired", err)
	}
	pending, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending.PendingCompletion == nil || pending.PendingCompletion.DeviceAPIKey != conformance.AgentAssignmentDeviceAPIKeyFixture || pending.RegisteredAt != nil {
		t.Fatalf("persisted recovery state = %#v", pending)
	}
	client, binding, err := RegisterAgentRuntime(context.Background(), "", f.store,
		f.options(withAgentRuntimeDeviceCredential(deviceKeyPrefix+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, deviceKeyRandomLength))))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("resume completion = client %v, binding %v, error %v", client, binding, err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || !bytes.Equal(requests[1].body, requests[2].body) || string(requests[2].body) != contract.RegistrationCompletion.Request.BodyJSON {
		t.Fatalf("completion retry did not reuse exact persisted candidate: %v", requests)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatal("live pending assignment unexpectedly refreshed through Hub")
	}
	completed, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if completed.PendingCompletion != nil ||
		completed.DeviceAPIKey != conformance.AgentAssignmentDeviceAPIKeyFixture ||
		completed.DeviceAPIKeyID != "key_DvK9mN2pQr7S" ||
		completed.RegisteredAt == nil {
		t.Fatalf("completion recovery did not promote the exact candidate/key id: %#v", completed)
	}
}

func TestRegisterAgentRuntime_PreREGCancellationLeavesExactPendingActivation(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	f.store.cancelOnSave = 2 // initial identity, then pending activation
	f.store.cancel = cancel
	_, _, err := RegisterAgentRuntime(ctx, conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-REG cancellation = %v, want context.Canceled", err)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("pre-REG cancellation Hub/cell requests = %d/%d, want 1/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0001" || pending.PendingCompletion != nil {
		t.Fatalf("pre-REG cancellation lost exact pending activation: %#v", pending)
	}
	raw, marshalErr := json.Marshal(pending)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	fileStore, ok := f.store.inner.(*FileAgentStateStore)
	if !ok {
		t.Fatal("runtime fixture is not backed by FileAgentState")
	}
	fileRaw, readErr := os.ReadFile(fileStore.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, secret := range []string{conformance.AgentAssignmentBootstrapCredentialFixture, canonicalNativeDeviceCredential, "12345678"} {
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(fileRaw, []byte(secret)) {
			t.Fatalf("pending activation persisted forbidden plaintext secret %q: decoded=%s file=%s", secret, raw, fileRaw)
		}
	}
}

func TestRegisterAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	var recovery *RegistrationRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrRegistrationRecoveryRequired) || !errors.Is(err, nativeudp.ErrTransport) || recovery.Attempts != 1 {
		t.Fatalf("lost RAK = %T: %v, want one-attempt registration recovery", err, err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || pending.PendingActivation == nil {
		t.Fatalf("lost RAK pending state = %#v, %v", pending, loadErr)
	}
	afterTicketExpiry := assignmentFixtureNow.Add(30 * time.Minute)
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return afterTicketExpiry }))...)
	if err != nil {
		t.Fatalf("expired exact activation replay: %v", err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || requests[0].typeID != relayknock.TypeRegister || requests[1].typeID != relayknock.TypeRegister ||
		!bytes.Equal(requests[0].body, requests[1].body) || string(requests[1].body) != contract.AssignedCellRegistration.Request.BodyJSON {
		t.Fatalf("lost RAK restart did not re-drive exact REG: %v", requests)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("lost RAK replay contacted Hub %d times, want only original assignment", len(f.hubUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_AccountLostRAKReusesOriginalCodeWithoutSecondOTP(t *testing.T) {
	contract := loadAssignmentFixture(t)
	ticket := "conformance-account-assignment-ticket-0001"
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, ticket)}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	var challenges []AgentOTPChallenge
	provider := func(_ context.Context, challenge AgentOTPChallenge) (string, error) {
		challenges = append(challenges, challenge)
		return "12345678", nil
	}
	opts := f.options(
		WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
		WithAgentRuntimeOTPProvider(provider),
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store, opts...)
	if !errors.Is(err, ErrRegistrationRecoveryRequired) {
		t.Fatalf("account lost RAK = %v, want ErrRegistrationRecoveryRequired", err)
	}
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store, opts...)
	if err != nil {
		t.Fatalf("account lost RAK replay: %v", err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if len(requests) != 4 || requests[0].typeID != relayknock.TypeOTP || requests[1].typeID != relayknock.TypeRegister || requests[2].typeID != relayknock.TypeRegister ||
		!bytes.Equal(requests[1].body, requests[2].body) {
		t.Fatalf("account recovery sent another OTP or changed exact REG: %v", requests)
	}
	if len(challenges) != 2 || challenges[0].PendingActivationRecovery || !challenges[1].PendingActivationRecovery {
		t.Fatalf("account OTP challenge recovery markers = %#v, want false then true", challenges)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatal("account ambiguous replay consulted Hub")
	}
}

func TestRegisterAgentRuntime_ConsumedCredentialCannotReplaceExpiredUncommittedTicket(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52108","errMsg":"consumed"}`},
		},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`}},
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAssignmentBootstrapConsumed) {
		t.Fatalf("consumed credential replacement = %v, want ErrAssignmentBootstrapConsumed", err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0001" {
		t.Fatalf("consumed replacement erased old pending proof: %#v, %v", pending, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("consumed replacement Hub/cell counts = %d/%d, want 2/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_PendingActivationCorruptionAndChangedCredentialFailBeforeIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	tests := map[string]func(*AgentState){
		"missing assignment": func(state *AgentState) { state.Assignment = nil },
		"peer": func(state *AgentState) {
			state.PendingActivation.AgentPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, x25519key.Size))
		},
		"cell":       func(state *AgentState) { state.PendingActivation.Assignment.CellID = "cell1" },
		"generation": func(state *AgentState) { state.PendingActivation.Assignment.AssignmentGeneration++ },
		"ticket expiry equals lease": func(state *AgentState) {
			state.PendingActivation.AssignmentTicketExpiresAt = state.PendingActivation.Assignment.LeaseExpiresAt
		},
		"hostname without version": func(state *AgentState) { state.PendingActivation.AgentVersion = "" },
		"version without hostname": func(state *AgentState) { state.PendingActivation.Hostname = "" },
		"server identity": func(state *AgentState) {
			state.PendingActivation.Assignment.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, x25519key.Size))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := seedPendingActivation(t, contract, nil)
			state, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			mutate(state)
			if saveErr := f.store.SaveAgentState(context.Background(), state); saveErr != nil {
				t.Fatal(saveErr)
			}
			hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}
			_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
				f.options(WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))...)
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("changed %s pending state = %v, want invalid durable state", name, err)
			}
			if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 ||
				len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
				t.Fatalf("changed %s pending state performed I/O", name)
			}
		})
	}

	t.Run("changed opaque ticket is denied only by pinned cell", func(t *testing.T) {
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
			[]runtimeUDPStep{
				{requestType: relayknock.TypeRegister, noReply: true},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52110","errMsg":"invalid ticket","aspId":"agent"}`},
			},
		)
		_, _, firstErr := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
		if !errors.Is(firstErr, ErrRegistrationRecoveryRequired) {
			t.Fatalf("seed pending activation: %v", firstErr)
		}
		state, loadErr := f.store.LoadAgentState(context.Background())
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		state.PendingActivation.AssignmentTicket += "-changed"
		if saveErr := f.store.SaveAgentState(context.Background(), state); saveErr != nil {
			t.Fatal(saveErr)
		}
		hubBefore := len(f.hubUDP.snapshot())
		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
		if !errors.Is(err, ErrAssignmentTicketInvalid) {
			t.Fatalf("changed ticket = %v, want authenticated ErrAssignmentTicketInvalid", err)
		}
		requests := f.cellUDP.snapshot()
		if len(requests) != 2 || !bytes.Contains(requests[1].body, []byte("conformance-assignment-ticket-0001-changed")) {
			t.Fatalf("changed ticket did not go only to the pinned cell: %v", requests)
		}
		if len(f.hubUDP.snapshot()) != hubBefore {
			t.Fatal("changed ticket denial fell back to Hub")
		}
	})

	f := seedPendingActivation(t, contract, nil)
	hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
	wrongCredential := "different-high-entropy-enrollment-credential"
	_, _, err := RegisterAgentRuntime(context.Background(), wrongCredential, f.store, f.options()...)
	if !errors.Is(err, ErrInvalidRegisterConfig) || strings.Contains(err.Error(), wrongCredential) || strings.Contains(err.Error(), conformance.AgentAssignmentBootstrapCredentialFixture) {
		t.Fatalf("changed pending credential classification/redaction = %v", err)
	}
	if len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
		t.Fatal("changed pending credential performed I/O")
	}
	_, _, err = RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(WithAgentRuntimeMetadata("changed-host", "changed-version"))...)
	if !errors.Is(err, ErrInvalidRegisterConfig) ||
		!strings.Contains(err.Error(), "original hostname and version") ||
		!strings.Contains(err.Error(), "no replacement or fallback") {
		t.Fatalf("changed pending metadata remedy = %v", err)
	}
	if len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
		t.Fatal("changed pending metadata performed I/O")
	}

	for _, test := range []struct {
		name       string
		seedOpts   func(*runtimeFixture) []AgentRuntimeRegistrationOption
		resumeOpts func(*runtimeFixture) []AgentRuntimeRegistrationOption
	}{
		{
			name:       "persisted empty caller present",
			seedOpts:   func(f *runtimeFixture) []AgentRuntimeRegistrationOption { return f.optionsWithoutMetadata() },
			resumeOpts: func(f *runtimeFixture) []AgentRuntimeRegistrationOption { return f.options() },
		},
		{
			name:       "persisted present caller empty",
			seedOpts:   func(f *runtimeFixture) []AgentRuntimeRegistrationOption { return f.options() },
			resumeOpts: func(f *runtimeFixture) []AgentRuntimeRegistrationOption { return f.optionsWithoutMetadata() },
		},
	} {
		t.Run("metadata "+test.name, func(t *testing.T) {
			f := seedPendingActivation(t, contract, test.seedOpts)
			hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
			_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, test.resumeOpts(f)...)
			if !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("metadata mismatch = %v, want ErrInvalidRegisterConfig", err)
			}
			if len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
				t.Fatal("metadata mismatch performed I/O")
			}
		})
	}
}

func TestRegisterAgentRuntime_PendingActivationSaveFailureSendsNoREG(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		nil,
	)
	f.store.fail = 2 // initial identity save succeeds; pending activation save fails
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("pending activation save = %v, want ErrAgentBindingPersistence", err)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("pending save failure Hub/cell requests = %d/%d, want 1/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	state, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || state.PendingActivation != nil || state.Assignment != nil {
		t.Fatalf("failed pending save changed durable state: %#v, %v", state, loadErr)
	}
}

func TestRegisterAgentRuntime_AmbiguousREGUsesBoundedExactRetries(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}, {requestType: relayknock.TypeRegister, noReply: true}},
	)
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAssignmentRetryBudget(2, time.Second),
			withTestAgentRuntimeAssignmentSleep(func(context.Context, time.Duration) error { return nil }),
		)...)
	var recovery *RegistrationRecoveryRequiredError
	if !errors.As(err, &recovery) || recovery.Attempts != 2 || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("bounded REG recovery = %T: %v", err, err)
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 2 || !bytes.Equal(requests[0].body, requests[1].body) {
		t.Fatalf("bounded REG retries changed body or count: %v", requests)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatal("ambiguous REG retry fell back to Hub")
	}
}

func TestRegisterAgentRuntime_AmbiguousREGCancellationDuringBackoffPreservesPending(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, err := RegisterAgentRuntime(ctx, conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAssignmentRetryBudget(3, time.Second),
			withTestAgentRuntimeAssignmentSleep(func(ctx context.Context, _ time.Duration) error {
				cancel()
				<-ctx.Done()
				return ctx.Err()
			}),
		)...)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("REG backoff cancellation = %v, want context.Canceled", err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0001" {
		t.Fatalf("REG cancellation lost exact pending activation: %#v, %v", pending, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("REG cancellation Hub/cell requests = %d/%d, want 1/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_ReenrollsOnceOnExpiredAssignmentTicket(t *testing.T) {
	contract := loadAssignmentFixture(t)
	secondAssignment := bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002")
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: secondAssignment},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil {
		t.Fatalf("bounded ticket reenrollment: %v", err)
	}
	binding.Destroy()
	if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 3 {
		t.Fatalf("Hub/cell request counts = %d/%d, want 2/3", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	requests := f.cellUDP.snapshot()
	if !bytes.Contains(requests[0].body, []byte("conformance-assignment-ticket-0001")) ||
		!bytes.Contains(requests[1].body, []byte("conformance-assignment-ticket-0002")) ||
		bytes.Contains(requests[1].body, []byte("conformance-assignment-ticket-0001")) {
		t.Fatalf("expired first use did not replace the exact pending ticket: %v", requests)
	}
}

func TestRegisterAgentRuntime_StopsAfterOneReplacementOnConsecutiveNonCommitVerdicts(t *testing.T) {
	contract := loadAssignmentFixture(t)
	t.Run("unattended 52111", func(t *testing.T) {
		secondAssignment := bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002")
		thirdAssignment := bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0003")
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: secondAssignment},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: thirdAssignment},
			},
			[]runtimeUDPStep{
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
			},
		)
		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
		if !errors.Is(err, ErrAssignmentTicketExpired) {
			t.Fatalf("second authenticated 52111 = %v, want terminal ErrAssignmentTicketExpired", err)
		}
		if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 2 {
			t.Fatalf("double 52111 Hub/cell requests = %d/%d, want exactly 2/2", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
		}
		pending, loadErr := f.store.LoadAgentState(context.Background())
		if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0002" {
			t.Fatalf("double 52111 pending ticket = %#v, %v", pending, loadErr)
		}
	})

	t.Run("account 52101", func(t *testing.T) {
		firstAssignment := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")
		secondAssignment := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0002")
		thirdAssignment := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0003")
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: firstAssignment},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: secondAssignment},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: thirdAssignment},
			},
			[]runtimeUDPStep{
				{requestType: relayknock.TypeOTP, noReply: true},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52101","errMsg":"OTP expired","aspId":"agent"}`},
				{requestType: relayknock.TypeOTP, noReply: true},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52101","errMsg":"OTP expired","aspId":"agent"}`},
				{requestType: relayknock.TypeOTP, noReply: true},
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
			},
		)
		codes := []string{"12345678", "87654321", "11223344"}
		var callbacks atomic.Int32
		provider := func(context.Context, AgentOTPChallenge) (string, error) {
			index := int(callbacks.Add(1)) - 1
			if index >= len(codes) {
				return "", errors.New("unexpected OTP callback")
			}
			return codes[index], nil
		}
		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
			f.options(
				WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
				WithAgentRuntimeOTPProvider(provider),
			)...)
		if !errors.Is(err, ErrOTPExpired) {
			t.Fatalf("second authenticated account 52101 = %v, want terminal ErrOTPExpired", err)
		}
		if callbacks.Load() != 2 || len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 4 {
			t.Fatalf("double 52101 callbacks/Hub/cell = %d/%d/%d, want exactly 2/2/4",
				callbacks.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
		}
		pending, loadErr := f.store.LoadAgentState(context.Background())
		if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-account-assignment-ticket-0002" {
			t.Fatalf("double 52101 pending ticket = %#v, %v", pending, loadErr)
		}
	})
}

func TestRegisterAgentRuntime_ReplacementPendingSaveFailurePreservesOldTicket(t *testing.T) {
	contract := loadAssignmentFixture(t)
	secondAssignment := bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002")
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: secondAssignment},
		},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`}},
	)
	f.store.fail = 3 // identity, first pending, then replacement pending
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("replacement pending save = %v, want ErrAgentBindingPersistence", err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0001" {
		t.Fatalf("replacement save failure erased old pending record: %#v, %v", pending, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("replacement save failure Hub/cell counts = %d/%d, want 2/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_ReplacementPendingPostCommitErrorReplaysNewTicket(t *testing.T) {
	contract := loadAssignmentFixture(t)
	secondAssignment := bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002")
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: secondAssignment},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	f.store.failAfterCommit = 3 // initial identity, first pending, replacement pending
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("replacement post-commit save = %v, want ErrAgentBindingPersistence", err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || pending.PendingActivation == nil || pending.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0002" {
		t.Fatalf("replacement post-commit reload lost new ticket: %#v, %v", pending, loadErr)
	}
	if len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("replacement post-commit error sent REG before reload: %v", f.cellUDP.snapshot())
	}

	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || binding == nil {
		t.Fatalf("resume committed replacement pending activation = %v, %v", binding, err)
	}
	binding.Destroy()
	if len(f.hubUDP.snapshot()) != 2 {
		t.Fatalf("replacement resume fetched a third Hub ticket: %v", f.hubUDP.snapshot())
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || !bytes.Contains(requests[1].body, []byte("conformance-assignment-ticket-0002")) || bytes.Contains(requests[1].body, []byte("conformance-assignment-ticket-0001")) {
		t.Fatalf("replacement resume did not exact-replay new ticket: %v", requests)
	}
}

func TestRegisterAgentRuntime_AccountOTPIsOneWayAndTargetsAssignedCell(t *testing.T) {
	contract := loadAssignmentFixture(t)
	accountResult := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountResult}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	var callbacks atomic.Int32
	provider := func(ctx context.Context, challenge AgentOTPChallenge) (string, error) {
		callbacks.Add(1)
		if challenge.AgentID != "agent-conform" || challenge.CredentialKeyID != "key_A1b2C3d4E5f6" || challenge.CellID != "cell0" {
			t.Fatalf("OTP challenge = %#v", challenge)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("OTP callback context has no ticket-bounded deadline")
		}
		return "12345678", nil
	}
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(provider),
		)...)
	if err != nil {
		t.Fatalf("account native enrollment: %v", err)
	}
	binding.Destroy()
	if callbacks.Load() != 1 {
		t.Fatalf("OTP callbacks = %d, want 1", callbacks.Load())
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || requests[0].typeID != relayknock.TypeOTP || string(requests[0].body) != contract.AccountCredentialOTP.Request.BodyJSON {
		t.Fatalf("assigned-cell OTP request = %v, want one exact golden OTP", requests)
	}
	wantREG, err := marshalRegisterRequestBody("key_A1b2C3d4E5f6", "agent-conform", "12345678", registerUserData{
		Hostname: "conformance-host", Version: "0.0.0-conformance", AssignmentTicket: "conformance-account-assignment-ticket-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requests[1].body, wantREG) {
		t.Fatalf("account REG = %s, want %s", requests[1].body, wantREG)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatal("OTP was sent to Hub instead of assigned cell")
	}
	persisted, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	rawState, marshalErr := json.Marshal(persisted)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(rawState, []byte("12345678")) {
		t.Fatalf("successful native account state persisted OTP code: %s", rawState)
	}
}

func TestRegisterAgentRuntime_AccountOTPProviderFailuresSendOneOTPNoREGAndPersistNoCode(t *testing.T) {
	contract := loadAssignmentFixture(t)
	type testCase struct {
		code        string
		providerErr error
		cancel      bool
		want        error
	}
	tests := map[string]testCase{
		"seven digits":          {code: "1234567", want: ErrInvalidRegisterConfig},
		"nine digits":           {code: "123456789", want: ErrInvalidRegisterConfig},
		"non-digit":             {code: "1234567x", want: ErrInvalidRegisterConfig},
		"surrounding space":     {code: " 1234567", want: ErrInvalidRegisterConfig},
		"provider error":        {providerErr: errors.New("mailbox unavailable")},
		"provider cancellation": {cancel: true, want: context.Canceled},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")}},
				[]runtimeUDPStep{{requestType: relayknock.TypeOTP, noReply: true}},
			)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dialer := &countingNativeDialer{inner: f.dialer}
			var httpCalls atomic.Int32
			refusingHTTP := doerFunc(func(*http.Request) (*http.Response, error) {
				httpCalls.Add(1)
				return nil, errors.New("HTTP is forbidden during native OTP failure handling")
			})
			provider := func(context.Context, AgentOTPChallenge) (string, error) {
				if test.cancel {
					cancel()
					return "", context.Canceled
				}
				return test.code, test.providerErr
			}
			_, _, err := RegisterAgentRuntime(ctx, conformance.AgentAssignmentAccountCredentialFixture, f.store,
				f.options(
					WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
					WithAgentRuntimeOTPProvider(provider),
					WithAgentRuntimeUDPDialer(dialer),
					WithAgentClientHTTPClient(refusingHTTP),
				)...)
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("provider failure = %v, want %v", err, test.want)
			}
			if test.providerErr != nil && !errors.Is(err, test.providerErr) {
				t.Fatalf("provider error = %v, want injected cause", err)
			}
			if test.code != "" && strings.Contains(err.Error(), test.code) {
				t.Fatalf("invalid OTP code leaked through error: %v", err)
			}
			requests := waitRuntimeUDPRequests(t, f.cellUDP, 1)
			if len(requests) != 1 || requests[0].typeID != relayknock.TypeOTP {
				t.Fatalf("provider failure cell requests = %v, want exactly one OTP and zero REG", requests)
			}
			// Mandatory Hub challenge/proof uses two synchronous dials and OTP uses
			// one. A REG-after-OTP regression would increment this before the
			// lifecycle returns, even if the server has not recorded that datagram.
			if dialer.calls.Load() != 3 {
				t.Fatalf("provider failure UDP dials = %d, want Hub challenge/proof + OTP only", dialer.calls.Load())
			}
			if httpCalls.Load() != 0 {
				t.Fatalf("provider failure attempted %d HTTP fallback calls", httpCalls.Load())
			}
			persisted, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			rawState, marshalErr := json.Marshal(persisted)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if persisted.PendingCompletion != nil || persisted.DeviceAPIKey != "" || (test.code != "" && bytes.Contains(rawState, []byte(test.code))) {
				t.Fatalf("provider failure persisted OTP/candidate state: %s", rawState)
			}
		})
	}
}

func TestRegisterAgentRuntime_AccountRegistrationRateLimitIsTerminalForCall(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, code := range []string{rakAttemptsExceeded, rakRateLimited} {
		t.Run(code, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{
					requestType: relayknock.TypeListRequest,
					replyType:   relayknock.TypeListResult,
					replyBody:   accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001"),
				}},
				[]runtimeUDPStep{
					{requestType: relayknock.TypeOTP, noReply: true},
					{
						requestType: relayknock.TypeRegister,
						replyType:   relayknock.TypeRegisterAck,
						replyBody:   fmt.Sprintf(`{"errCode":%q,"errMsg":"untrusted detail","aspId":"agent"}`, code),
					},
				},
			)
			callbacks := 0
			_, _, err := RegisterAgentRuntime(
				context.Background(),
				conformance.AgentAssignmentAccountCredentialFixture,
				f.store,
				f.options(
					WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
					WithAgentRuntimeOTPProvider(func(context.Context, AgentOTPChallenge) (string, error) {
						callbacks++
						return "12345678", nil
					}),
				)...,
			)
			if !errors.Is(err, ErrRegistrationRateLimited) {
				t.Fatalf("authenticated account REG %s = %v, want ErrRegistrationRateLimited", code, err)
			}
			if strings.Contains(err.Error(), "untrusted detail") {
				t.Fatalf("authenticated account REG %s reflected producer detail: %v", code, err)
			}
			if callbacks != 1 || len(f.hubUDP.snapshot()) != 1 {
				t.Fatalf("authenticated account REG %s callbacks/Hub requests = %d/%d, want 1/1", code, callbacks, len(f.hubUDP.snapshot()))
			}
			requests := f.cellUDP.snapshot()
			if len(requests) != 2 ||
				requests[0].typeID != relayknock.TypeOTP ||
				requests[1].typeID != relayknock.TypeRegister {
				t.Fatalf("authenticated account REG %s cell requests = %v, want one OTP then one REG", code, requests)
			}
			pending, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if pending.PendingActivation == nil || pending.PendingCompletion != nil || pending.RegisteredAt != nil {
				t.Fatalf("authenticated account REG %s lost exact pending activation: %#v", code, pending)
			}
		})
	}
}

func TestRegisterAgentRuntime_AccountPendingSaveFailureSendsOneOTPNoREG(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")}},
		[]runtimeUDPStep{{requestType: relayknock.TypeOTP, noReply: true}},
	)
	f.store.fail = 2 // initial identity save succeeds; pending activation save fails after OTP dispatch
	dialer := &countingNativeDialer{inner: f.dialer}
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(func(context.Context, AgentOTPChallenge) (string, error) { return "12345678", nil }),
			WithAgentRuntimeUDPDialer(dialer),
		)...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("account pending save failure = %v, want ErrAgentBindingPersistence", err)
	}
	requests := waitRuntimeUDPRequests(t, f.cellUDP, 1)
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeOTP {
		t.Fatalf("account pending save failure cell requests = %v, want one OTP and zero REG", requests)
	}
	if dialer.calls.Load() != 3 {
		t.Fatalf("account pending save failure UDP dials = %d, want Hub challenge/proof + OTP only", dialer.calls.Load())
	}
	persisted, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	raw, marshalErr := json.Marshal(persisted)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if persisted.Assignment != nil || persisted.PendingActivation != nil || bytes.Contains(raw, []byte("12345678")) {
		t.Fatalf("account pending save failure persisted attempted ticket or OTP: %s", raw)
	}
}

func TestNativeAccountOTPMinimumTicketLifetimeBeforeDispatch(t *testing.T) {
	contract := loadAssignmentFixture(t)
	minimum := time.Duration(contract.AccountCredentialOTP.EnrollmentBinding.MinimumTicketRemainingSeconds) * time.Second
	if minimum != nativeAccountOTPMinimumTicketRemaining {
		t.Fatalf("SDK account OTP minimum = %s, conformance metadata = %s", nativeAccountOTPMinimumTicketRemaining, minimum)
	}
	providerErr := errors.New("stop after OTP provider")
	for _, test := range []struct {
		name              string
		remaining         time.Duration
		wantDispatch      bool
		wantProviderCalls int32
	}{
		{name: "inclusive 630 second boundary", remaining: minimum, wantDispatch: true, wantProviderCalls: 1},
		{name: "629 seconds rejected", remaining: minimum - time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			cellSteps := []runtimeUDPStep(nil)
			if test.wantDispatch {
				cellSteps = []runtimeUDPStep{{requestType: relayknock.TypeOTP, noReply: true}}
			}
			f := newRuntimeFixture(t, nil, cellSteps)
			initial, err := parseInitialAssignmentReply(
				[]byte(accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")),
				"agent-conform", assignmentFixtureNow,
			)
			if err != nil {
				t.Fatal(err)
			}
			initial.AssignmentTicketExpiresAt = assignmentFixtureNow.Add(test.remaining)
			state := &AgentState{AgentID: "agent-conform", Assignment: initial.Assignment.clone()}
			var clockCalls atomic.Int32
			var providerCalls atomic.Int32
			cfg := &nativeAgentRuntimeConfig{
				resolver: f.resolver, dialer: f.dialer, timeout: 100 * time.Millisecond, maxAddresses: 1,
				clock: func() time.Time {
					clockCalls.Add(1)
					return assignmentFixtureNow
				},
				otpProvider: func(context.Context, AgentOTPChallenge) (string, error) {
					providerCalls.Add(1)
					return "", providerErr
				},
			}
			privateKey := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
			defer wipeBytes(privateKey)
			_, err = cfg.registrationCredential(context.Background(), state, initial, conformance.AgentAssignmentAccountCredentialFixture, privateKey)
			if test.wantDispatch {
				if !errors.Is(err, providerErr) {
					t.Fatalf("inclusive boundary error = %v, want provider cause", err)
				}
				requests := waitRuntimeUDPRequests(t, f.cellUDP, 1)
				if len(requests) != 1 || requests[0].typeID != relayknock.TypeOTP {
					t.Fatalf("inclusive boundary requests = %v, want one OTP and no REG", requests)
				}
			} else {
				if !errors.Is(err, ErrAssignmentTicketExpired) {
					t.Fatalf("below-minimum error = %v, want ErrAssignmentTicketExpired", err)
				}
				if len(f.cellUDP.snapshot()) != 0 {
					t.Fatalf("below-minimum ticket dispatched cell traffic: %v", f.cellUDP.snapshot())
				}
			}
			if got := clockCalls.Load(); got != 1 {
				t.Fatalf("ticket boundary clock samples = %d, want exactly 1", got)
			}
			if got := providerCalls.Load(); got != test.wantProviderCalls {
				t.Fatalf("OTP provider calls = %d, want %d", got, test.wantProviderCalls)
			}
			if len(f.hubUDP.snapshot()) != 0 {
				t.Fatal("account OTP boundary contacted Hub")
			}
		})
	}
}

func TestRegisterAgentRuntime_AccountOTPExpiryPermitsOneFreshTicketAndOTP(t *testing.T) {
	contract := loadAssignmentFixture(t)
	firstTicket := "conformance-account-assignment-ticket-0001"
	secondTicket := "conformance-account-assignment-ticket-0002"
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, firstTicket)},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: accountAssignmentResult(contract, secondTicket)},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52101","errMsg":"expired","aspId":"agent"}`},
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	var callbacks atomic.Int32
	provider := func(context.Context, AgentOTPChallenge) (string, error) {
		if callbacks.Add(1) == 1 {
			return "12345678", nil
		}
		return "87654321", nil
	}
	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(provider),
		)...)
	if err != nil {
		t.Fatalf("fresh account attempt after authenticated OTP expiry: %v", err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if callbacks.Load() != 2 || len(f.hubUDP.snapshot()) != 2 || len(requests) != 5 {
		t.Fatalf("callback/Hub/cell counts = %d/%d/%d, want 2/2/5", callbacks.Load(), len(f.hubUDP.snapshot()), len(requests))
	}
	if requests[0].typeID != relayknock.TypeOTP || requests[2].typeID != relayknock.TypeOTP ||
		!bytes.Contains(requests[0].body, []byte(firstTicket)) || !bytes.Contains(requests[2].body, []byte(secondTicket)) ||
		bytes.Contains(requests[2].body, []byte(firstTicket)) || !bytes.Contains(requests[1].body, []byte("12345678")) ||
		!bytes.Contains(requests[3].body, []byte("87654321")) || bytes.Equal(requests[1].body, requests[3].body) {
		t.Fatalf("authenticated OTP expiry did not replace the pending ticket before one fresh OTP/REG: %v", requests)
	}
}

func accountAssignmentResult(contract *conformance.AgentAssignmentFile, ticket string) string {
	return strings.NewReplacer(
		`"key_id":"key_BsT4rP8wXn6Q"`, `"key_id":"key_A1b2C3d4E5f6"`,
		`"key_kind":"bootstrap"`, `"key_kind":"account"`,
		"conformance-assignment-ticket-0001", ticket,
	).Replace(contract.InitialAssignment.Result.BodyJSON)
}

func bootstrapAssignmentResult(contract *conformance.AgentAssignmentFile, ticket string) string {
	return strings.Replace(contract.InitialAssignment.Result.BodyJSON,
		"conformance-assignment-ticket-0001", ticket, 1)
}

func TestRegisterAgentRuntime_FinalSaveFailureKeepsCandidateRecoverable(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	// Identity, assignment, and pending-candidate saves succeed. Fail the atomic
	// promotion after the first authenticated completion result.
	f.store.fail = 4
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("final save failure = %v, want ErrAgentBindingPersistence", err)
	}
	pending, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending.PendingCompletion == nil || pending.PendingCompletion.DeviceAPIKey != conformance.AgentAssignmentDeviceAPIKeyFixture || pending.RegisteredAt != nil {
		t.Fatalf("post-save-failure durable state = %#v", pending)
	}
	_, binding, err := RegisterAgentRuntime(context.Background(), "", f.store, f.options()...)
	if err != nil {
		t.Fatalf("resume after final save failure: %v", err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || !bytes.Equal(requests[1].body, requests[2].body) {
		t.Fatalf("final-save recovery changed completion candidate: %v", requests)
	}
	completed, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if completed.PendingCompletion != nil ||
		completed.DeviceAPIKey != conformance.AgentAssignmentDeviceAPIKeyFixture ||
		completed.DeviceAPIKeyID != "key_DvK9mN2pQr7S" ||
		completed.RegisteredAt == nil {
		t.Fatalf("final-save recovery did not promote the exact candidate/key id: %#v", completed)
	}
}

func TestRegisterAgentRuntime_AuthenticatedCompletionIgnoresCallerCancellationForFinalSave(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest,
			replyType:   relayknock.TypeListResult,
			replyBody:   contract.InitialAssignment.Result.BodyJSON,
		}},
		[]runtimeUDPStep{
			{
				requestType: relayknock.TypeRegister,
				replyType:   relayknock.TypeRegisterAck,
				replyBody:   contract.AssignedCellRegistration.Result.BodyJSON,
			},
			{
				requestType: relayknock.TypeListRequest,
				replyType:   relayknock.TypeListResult,
				replyBody:   contract.RegistrationCompletion.Result.BodyJSON,
			},
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.store.cancelBeforeSave = 4 // identity, pending activation, pending completion, final promotion
	f.store.cancel = cancel

	client, binding, err := RegisterAgentRuntime(
		ctx, conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...,
	)
	if err != nil || client == nil || binding == nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("canceled post-auth promotion = %v/%v/%v; context=%v", client, binding, err, ctx.Err())
	}
	defer binding.Destroy()
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion != nil ||
		loaded.DeviceAPIKey != canonicalNativeDeviceCredential ||
		loaded.DeviceAPIKeyID != "key_DvK9mN2pQr7S" ||
		loaded.RegisteredAt == nil {
		t.Fatalf("canceled post-auth result was not durable: state=%#v load=%v", loaded, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 2 {
		t.Fatalf("canceled post-auth result network = Hub %d cell %d, want 1/2",
			len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_PostRAKPreCommitSaveFailureRequiresReloadBeforeRecovery(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	// The initial native-identity and pending-activation saves succeed; the first
	// save after authenticated RAK is the candidate durability boundary.
	f.store.fail = 3
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	var persistence *AgentCompletionCandidatePersistenceError
	if !errors.As(err, &persistence) || !errors.Is(err, ErrAgentCompletionCandidatePersistence) || !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("candidate save failure = %T: %v, want typed post-RAK persistence outcome", err, err)
	}
	if persistence.AgentID != "agent-conform" || strings.Contains(err.Error(), conformance.AgentAssignmentBootstrapCredentialFixture) || strings.Contains(err.Error(), canonicalNativeDeviceCredential) {
		t.Fatalf("candidate persistence error identity/redaction = %#v / %v", persistence, err)
	}
	if !strings.Contains(err.Error(), "reload state first") || !strings.Contains(err.Error(), "same enrollment credential") ||
		!strings.Contains(err.Error(), "save ambiguity alone never authorizes a replacement ticket") ||
		!strings.Contains(err.Error(), "authenticated as 52111 or account 52101") || strings.Contains(err.Error(), "not persisted") {
		t.Fatalf("candidate persistence recovery guidance is categorical or incomplete: %v", err)
	}
	persisted, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if persisted.PendingActivation == nil || persisted.PendingCompletion != nil || persisted.RegisteredAt != nil || persisted.Assignment == nil {
		t.Fatalf("post-RAK candidate save failure persisted unexpected resumable state: %#v", persisted)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("post-RAK failure Hub/cell calls = %d/%d, want 1/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}

	_, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || binding == nil {
		t.Fatalf("resume post-RAK pre-commit state = %v, %v", binding, err)
	}
	binding.Destroy()
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("post-RAK pending activation replay contacted Hub: %v", f.hubUDP.snapshot())
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 3 || requests[0].typeID != relayknock.TypeRegister || requests[1].typeID != relayknock.TypeRegister ||
		requests[2].typeID != relayknock.TypeListRequest || !bytes.Equal(requests[0].body, requests[1].body) ||
		string(requests[1].body) != contract.AssignedCellRegistration.Request.BodyJSON {
		t.Fatalf("post-RAK recovery did not replay exact REG before completion: %v", requests)
	}
	if !slices.ContainsFunc(f.store.snapshots(), func(state *AgentState) bool {
		return state.PendingActivation == nil && state.PendingCompletion != nil
	}) {
		t.Fatal("post-RAK recovery never durably transitioned to pending completion")
	}
	completed, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if completed.PendingActivation != nil || completed.PendingCompletion != nil || completed.RegisteredAt == nil ||
		completed.DeviceAPIKey != canonicalNativeDeviceCredential {
		t.Fatalf("post-RAK recovery did not complete atomically: %#v", completed)
	}
}

func TestRegisterAgentRuntime_PostRAKCommitThenErrorReloadsAndResumesExactCandidate(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	// The initial native-identity and pending-activation saves succeed. The
	// candidate save commits to the real file store, then the wrapper reports an
	// acknowledgement failure.
	f.store.failAfterCommit = 3
	_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	var persistence *AgentCompletionCandidatePersistenceError
	if !errors.As(err, &persistence) || !errors.Is(err, ErrAgentCompletionCandidatePersistence) || !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("post-commit candidate save = %T: %v, want typed durability-unknown outcome", err, err)
	}
	pending, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if pending.PendingCompletion == nil || pending.PendingCompletion.DeviceAPIKey != canonicalNativeDeviceCredential || pending.RegisteredAt != nil {
		t.Fatalf("post-commit reload lost exact pending candidate: %#v", pending)
	}

	_, binding, err := RegisterAgentRuntime(context.Background(), "", f.store, f.options()...)
	if err != nil || binding == nil {
		t.Fatalf("empty-credential resume after post-commit error = %v, %v", binding, err)
	}
	binding.Destroy()
	requests := f.cellUDP.snapshot()
	if len(requests) != 2 || requests[0].typeID != relayknock.TypeRegister || requests[1].typeID != relayknock.TypeListRequest {
		t.Fatalf("post-commit resume cell requests = %v, want one REG then one completion", requests)
	}
	if !bytes.Contains(requests[1].body, []byte(canonicalNativeDeviceCredential)) || bytes.Contains(requests[1].body, []byte(conformance.AgentAssignmentBootstrapCredentialFixture)) {
		t.Fatalf("post-commit resume did not reuse only the exact candidate: %s", requests[1].body)
	}
	completed, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if completed.PendingCompletion != nil || completed.DeviceAPIKey != canonicalNativeDeviceCredential || completed.RegisteredAt == nil {
		t.Fatalf("post-commit resume did not promote exact candidate: %#v", completed)
	}
}

func TestRefreshAgentRuntime_UsesCredentialFreeHubRefreshOnly(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RefreshAssignment.Result.BodyJSON},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	_, first, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()
	client, refreshed, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentClientBaseURL("https://resources.example.test"))...)
	if err != nil {
		t.Fatalf("RefreshAgentRuntime: %v", err)
	}
	refreshed.Destroy()
	if client == nil || client.baseURL != "https://resources.example.test" {
		t.Fatalf("refresh resource client = %#v", client)
	}
	hubRequests := f.hubUDP.snapshot()
	if len(hubRequests) != 2 || string(hubRequests[1].body) != contract.RefreshAssignment.Request.BodyJSON {
		t.Fatalf("Hub refresh request = %v, want exact credential-free golden", hubRequests)
	}
	if bytes.Contains(hubRequests[1].body, []byte(conformance.AgentAssignmentBootstrapCredentialFixture)) || bytes.Contains(hubRequests[1].body, []byte(conformance.AgentAssignmentDeviceAPIKeyFixture)) {
		t.Fatalf("Hub refresh leaked a credential: %s", hubRequests[1].body)
	}
	if len(f.cellUDP.snapshot()) != 2 {
		t.Fatal("assignment refresh contacted assigned cell")
	}
}

func TestRefreshAgentRuntime_PersistsRevisionedEndpointAndKeyRotationForNextKnock(t *testing.T) {
	contract := loadAssignmentFixture(t)
	rotatedPrivateBytes := bytes.Repeat([]byte{0x22}, x25519key.Size)
	rotatedPrivate, err := ecdh.X25519().NewPrivateKey(rotatedPrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	rotatedPublicB64 := base64.StdEncoding.EncodeToString(rotatedPrivate.PublicKey().Bytes())
	refreshResult := strings.NewReplacer(
		`"endpoint_revision":1`, `"endpoint_revision":2`,
		`"host":"cell0.nhp.layerv.ai"`, `"host":"cell0-r2.nhp.layerv.ai"`,
		`"lease_expires_at":"2026-07-16T12:00:00Z"`, `"lease_expires_at":"`+time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)+`"`,
		base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)), rotatedPublicB64,
	).Replace(contract.RefreshAssignment.Result.BodyJSON)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: refreshResult}},
		nil,
	)
	knockBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0-r2.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-rotated"},"preActions":{"resource-public-key":null}}`
	rotatedCell := newRuntimeUDPServer(t, rotatedPrivateBytes, assignmentHex(t, contract.Keys.Agent.StaticPubHex),
		runtimeUDPStep{requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK, replyBody: knockBody})
	rotatedAddress := netip.MustParseAddr("11.11.11.11")
	f.resolver.hosts["cell0-r2.nhp.layerv.ai"] = rotatedAddress
	f.dialer.targets[rotatedAddress.String()] = rotatedCell.conn.LocalAddr().String()

	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)

	_, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }))
	if err != nil || binding == nil {
		t.Fatalf("rotated assignment refresh = %v, %v", binding, err)
	}
	defer binding.Destroy()
	if binding.EndpointRevision != 2 || binding.NHPUDPEndpoint.Host != "cell0-r2.nhp.layerv.ai" || binding.NHPUDPEndpoint.ServerPublicKeyB64 != rotatedPublicB64 {
		t.Fatalf("rotated runtime binding = %#v", binding)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Assignment.Endpoint != binding.NHPUDPEndpoint || persisted.Assignment.EndpointRevision != 2 {
		t.Fatalf("rotated assignment was not persisted: %#v", persisted.Assignment)
	}
	agentPrivate := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(agentPrivate)
	if len(agentPrivate) != x25519key.Size {
		t.Fatalf("refreshed runtime returned private key length = %d, want %d", len(agentPrivate), x25519key.Size)
	}
	result, err := KnockRegisteredAgent(context.Background(), binding, agentPrivate, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil || result == nil || result.ACToken != "ac-rotated" || result.ResourceHost != "frps.cell0-r2.example:7000" {
		t.Fatalf("knock after endpoint/key rotation = %#v, %v", result, err)
	}
	if len(f.cellUDP.snapshot()) != 0 || len(rotatedCell.snapshot()) != 1 {
		t.Fatalf("old/new cell calls = %d/%d, want 0/1", len(f.cellUDP.snapshot()), len(rotatedCell.snapshot()))
	}
}

// A relocation must cost the caller nothing. An ordinary refresh — no options,
// no advance notice, no second call — follows the authority-directed move and
// persists it, so customers never write reassignment handling.
func TestRefreshAgentRuntime_AdoptsAuthorityMoveByDefault(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	httpCalls, refusingHTTP := refusingReassignmentHTTP()

	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentClientHTTPClient(refusingHTTP))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("default refresh across a move = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != target.CellID || binding.AssignmentGeneration != target.AssignmentGeneration {
		t.Fatalf("adopted binding = %#v, want cell %q generation %d", binding, target.CellID, target.AssignmentGeneration)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The move is followed using only the authenticated Hub result: no HTTP, one
	// Hub exchange, and no contact with either the old or the new cell.
	if !sameAgentAssignment(persisted.Assignment, target) || httpCalls.Load() != 0 ||
		len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("default adoption changed transport or persisted the wrong assignment: state=%#v HTTP=%d Hub/cell=%d/%d",
			persisted.Assignment, httpCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

// The opt-out still exists for callers whose placement feeds something outside
// the SDK, and it must leave durable state exactly as it found it.
func TestRefreshAgentRuntime_PinnedAssignmentFailsClosedAndPersistsNothing(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)

	_, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentRuntimePinnedAssignment())...)
	if binding != nil {
		binding.Destroy()
		t.Fatal("pinned refresh unexpectedly returned an adopted binding")
	}
	var changed *AgentAssignmentChangedError
	if !errors.As(err, &changed) || !errors.Is(err, ErrAssignmentReassignmentRequired) {
		t.Fatalf("pinned refresh error = %v, want AgentAssignmentChangedError", err)
	}
	if changed.Previous.CellID != "cell0" || changed.Current.CellID != "cell1" || changed.Current.AssignmentGeneration != 2 {
		t.Fatalf("reassignment snapshots = %#v -> %#v", changed.Previous, changed.Current)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Assignment.CellID != "cell0" || len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("pinned refresh was adopted or contacted a cell: state=%#v Hub/cell=%d/%d", persisted.Assignment, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRefreshAgentRuntime_AdoptsAuthenticatedReassignmentForNextKnock(t *testing.T) {
	contract := loadAssignmentFixture(t)
	cell1PrivateBytes := bytes.Repeat([]byte{0x22}, x25519key.Size)
	cell1Private, err := ecdh.X25519().NewPrivateKey(cell1PrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	cell1PublicB64 := base64.StdEncoding.EncodeToString(cell1Private.PublicKey().Bytes())
	target := newReassignmentTarget(t, contract, "cell1", 2, cell1PublicB64, time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	knockBody := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell1.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-cell1"},"preActions":{"resource-public-key":null}}`
	cell1 := newRuntimeUDPServer(t, cell1PrivateBytes, assignmentHex(t, contract.Keys.Agent.StaticPubHex),
		runtimeUDPStep{requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK, replyBody: knockBody})
	cell1Address := netip.MustParseAddr("11.11.11.11")
	f.resolver.hosts[target.Endpoint.Host] = cell1Address
	f.dialer.targets[cell1Address.String()] = cell1.conn.LocalAddr().String()

	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	httpCalls, refusingHTTP := refusingReassignmentHTTP()

	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentClientHTTPClient(refusingHTTP))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("adopt reassignment = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != target.CellID || binding.AssignmentGeneration != target.AssignmentGeneration ||
		binding.EndpointRevision != target.EndpointRevision || binding.NHPUDPEndpoint != target.Endpoint ||
		!binding.LeaseExpiresAt.Equal(target.LeaseExpiresAt) {
		t.Fatalf("adopted binding = %#v, want %#v", binding, target)
	}
	hubRequests := f.hubUDP.snapshot()
	if httpCalls.Load() != 0 || len(hubRequests) != 1 || string(hubRequests[0].body) != contract.RefreshAssignment.Request.BodyJSON ||
		len(f.cellUDP.snapshot()) != 0 || len(cell1.snapshot()) != 0 {
		t.Fatalf("adoption used an unexpected transport or request: HTTP=%d Hub=%v old/new cell=%d/%d", httpCalls.Load(), hubRequests, len(f.cellUDP.snapshot()), len(cell1.snapshot()))
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, target) {
		t.Fatalf("persisted assignment = %#v, want %#v", persisted.Assignment, target)
	}

	agentPrivate := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(agentPrivate)
	result, err := KnockRegisteredAgent(context.Background(), binding, agentPrivate, "resource-public-key", NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil || result == nil || result.ACToken != "ac-cell1" || result.ResourceHost != "frps.cell1.example:7000" {
		t.Fatalf("knock after reassignment = %#v, %v", result, err)
	}
	if len(f.cellUDP.snapshot()) != 0 || len(cell1.snapshot()) != 1 {
		t.Fatalf("old/new cell calls = %d/%d, want 0/1", len(f.cellUDP.snapshot()), len(cell1.snapshot()))
	}
}

// This case also pins the compatibility contract for the deprecated adoption
// option: code written against the old fail-closed default still compiles and
// still adopts, so upgrading requires no edit.
func TestRefreshAgentRuntime_AdoptsSameCellGenerationAdvance(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell0", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	httpCalls, refusingHTTP := refusingReassignmentHTTP()

	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentRuntimeReassignmentAdoption(), WithAgentClientHTTPClient(refusingHTTP))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("adopt same-cell generation advance = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != target.CellID || binding.AssignmentGeneration != target.AssignmentGeneration {
		t.Fatalf("adopted binding = %#v, want cell %q generation %d", binding, target.CellID, target.AssignmentGeneration)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, target) || httpCalls.Load() != 0 ||
		len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("same-cell adoption changed transport or persisted the wrong assignment: state=%#v HTTP=%d Hub/cell=%d/%d",
			persisted.Assignment, httpCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRefreshAgentRuntime_ReassignmentAdoptionRejectsStaleOrExpiredTarget(t *testing.T) {
	contract := loadAssignmentFixture(t)
	serverPublicKeyB64 := base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex))
	tests := []struct {
		name               string
		previousGeneration int64
		targetGeneration   int64
		leaseExpiresAt     time.Time
		agentID            string
		want               []error
		wantDetail         string
	}{
		{
			name: "same-generation cell move is stale", previousGeneration: 1, targetGeneration: 1,
			leaseExpiresAt: reassignmentFixtureLeaseExpiresAt, want: []error{ErrAssignmentInvalidResponse},
			wantDetail: "assignment generation must advance",
		},
		{
			name: "generation regression", previousGeneration: 2, targetGeneration: 1,
			leaseExpiresAt: reassignmentFixtureLeaseExpiresAt, want: []error{ErrAssignmentInvalidResponse},
			wantDetail: "assignment generation must advance",
		},
		{
			name: "expired target", previousGeneration: 1, targetGeneration: 2,
			leaseExpiresAt: assignmentFixtureNow, want: []error{ErrAssignmentInvalidResponse, ErrAssignmentLeaseExpired},
		},
		{
			name: "mismatched agent identity", previousGeneration: 1, targetGeneration: 2,
			leaseExpiresAt: reassignmentFixtureLeaseExpiresAt, agentID: "agent-other", want: []error{ErrAssignmentInvalidResponse},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			target := newReassignmentTarget(t, contract, "cell1", testCase.targetGeneration, serverPublicKeyB64, testCase.leaseExpiresAt)
			replyBody := rewriteRefreshAssignment(t, contract, target)
			if testCase.agentID != "" {
				replyBody = strings.Replace(replyBody, `"agent_id":"agent-conform"`, fmt.Sprintf(`"agent_id":%q`, testCase.agentID), 1)
			}
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: replyBody}},
				nil,
			)
			initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			previous := initial.Assignment.clone()
			previous.AssignmentGeneration = testCase.previousGeneration
			seedCompletedRuntimeAssignment(t, f, previous)

			client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store, f.refreshOptions()...)
			if client != nil || binding != nil {
				if binding != nil {
					binding.Destroy()
				}
				t.Fatalf("stale reassignment returned client/binding: %v/%v", client, binding)
			}
			for _, want := range testCase.want {
				if !errors.Is(err, want) {
					t.Fatalf("stale reassignment error = %v, want %v", err, want)
				}
			}
			if testCase.wantDetail != "" && !strings.Contains(err.Error(), testCase.wantDetail) {
				t.Fatalf("stale reassignment error = %v, want safe detail %q", err, testCase.wantDetail)
			}
			persisted, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if !sameAgentAssignment(persisted.Assignment, previous) || len(f.store.snapshots()) != 1 ||
				len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("rejected target changed state or contacted a cell: state=%#v saves=%d Hub/cell=%d/%d", persisted.Assignment, len(f.store.snapshots()), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRefreshAgentRuntime_ReassignmentAdoptionPersistenceIsAtomic(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	tests := []struct {
		name             string
		failBeforeCommit bool
		wantCommitted    bool
	}{
		{name: "save fails before commit", failBeforeCommit: true},
		{name: "save acknowledgement fails after atomic commit", wantCommitted: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
				nil,
			)
			initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			previous := initial.Assignment.clone()
			seedCompletedRuntimeAssignment(t, f, previous)
			if testCase.failBeforeCommit {
				f.store.fail = 2
			} else {
				f.store.failAfterCommit = 2
			}

			client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store, f.refreshOptions()...)
			if client != nil || binding != nil {
				if binding != nil {
					binding.Destroy()
				}
				t.Fatalf("failed save returned client/binding: %v/%v", client, binding)
			}
			if !errors.Is(err, ErrAgentBindingPersistence) {
				t.Fatalf("failed reassignment save = %v, want ErrAgentBindingPersistence", err)
			}
			persisted, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			want := previous
			if testCase.wantCommitted {
				want = target
			}
			if !sameAgentAssignment(persisted.Assignment, want) ||
				persisted.DeviceAPIKey != canonicalNativeDeviceCredential || persisted.DeviceAPIKeyID != "key_DvK9mN2pQr7S" ||
				len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("persistence failure left a partial state: state=%#v cell=%d", persisted, len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestNativeRuntimeConformanceRejectCases(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	executed := map[string]int{}
	for _, testCase := range fixture.SuccessResultCases {
		var parse func([]byte) error
		switch testCase.Phase {
		case "assigned_cell_registration":
			parse = func(body []byte) error {
				_, err := parseNativeRegisterAck(body)
				return err
			}
		case "registration_completion":
			parse = func(body []byte) error {
				_, err := parseCompletionReply(body)
				return err
			}
		default:
			continue
		}
		executed[testCase.Phase]++
		t.Run(testCase.Name, func(t *testing.T) {
			if err := parse([]byte(testCase.BodyJSON)); err == nil {
				t.Fatal("authenticated malformed runtime result was accepted")
			}
		})
	}
	if executed["assigned_cell_registration"] == 0 || executed["registration_completion"] == 0 {
		t.Fatalf("executed conformance phases = %v", executed)
	}
}

func TestNativeRuntimeConformanceErrorTaxonomy(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	registrationKinds := map[string]error{
		"52103": ErrAgentIdentityConflict,
		"52110": ErrAssignmentTicketInvalid,
		"52111": ErrAssignmentTicketExpired,
		"52112": ErrAssignmentQuotaExceeded,
	}
	for _, testCase := range fixture.ErrorContract.RegistrationCases {
		t.Run(testCase.Name, func(t *testing.T) {
			ack, err := parseNativeRegisterAck([]byte(testCase.BodyJSON))
			if err != nil {
				t.Fatalf("parse RAK: %v", err)
			}
			err = classifyNativeRegisterError(ack, keyKindBootstrap)
			if !errors.Is(err, registrationKinds[testCase.ErrCode]) {
				t.Fatalf("RAK %s error = %v, want %v", testCase.ErrCode, err, registrationKinds[testCase.ErrCode])
			}
		})
	}
	completionKinds := map[string]error{
		"52300": ErrCompletionUnavailable,
		"52301": ErrCompletionIdentityRejected,
		"52302": ErrDeviceKeyQuotaExceeded,
		"52303": ErrCompletionCredentialConflict,
		"52304": ErrCompletionRequestRejected,
	}
	for _, testCase := range fixture.ErrorContract.CompletionCases {
		t.Run(testCase.Name, func(t *testing.T) {
			_, err := parseCompletionReply([]byte(testCase.BodyJSON))
			if !errors.Is(err, completionKinds[testCase.ErrCode]) {
				t.Fatalf("completion %s error = %v, want %v", testCase.ErrCode, err, completionKinds[testCase.ErrCode])
			}
		})
	}
	for _, testCase := range fixture.ErrorContract.MalformedCases {
		if testCase.Phase != "assigned_cell_registration" && testCase.Phase != "registration_completion" {
			continue
		}
		t.Run(testCase.Name, func(t *testing.T) {
			var err error
			if testCase.Phase == "assigned_cell_registration" {
				var ack *registerAckBody
				ack, err = parseNativeRegisterAck([]byte(testCase.BodyJSON))
				if err == nil {
					err = classifyNativeRegisterError(ack, keyKindBootstrap)
				}
			} else {
				_, err = parseCompletionReply([]byte(testCase.BodyJSON))
			}
			if err == nil {
				t.Fatal("malformed authenticated runtime error was accepted")
			}
		})
	}
}

func TestNativeRuntimeErrorsDoNotEchoServerControlledSecrets(t *testing.T) {
	const secret = "lv_live_attacker_echoed_candidate_secret"
	ack, err := parseNativeRegisterAck([]byte(`{"errCode":"52110","errMsg":"` + secret + `","aspId":"agent"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := classifyNativeRegisterError(ack, keyKindBootstrap); strings.Contains(err.Error(), secret) {
		t.Fatalf("native RAK error echoed server-controlled secret: %v", err)
	}
	_, err = parseCompletionReply([]byte(`{"errCode":"52301","errMsg":"` + secret + `"}`))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("completion error leaked server-controlled secret: %v", err)
	}
	ack, parseErr := parseNativeRegisterAck([]byte(`{"errCode":"` + secret + `","errMsg":"ignored","aspId":"agent"}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := classifyNativeRegisterError(ack, keyKindBootstrap); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unknown RAK code leaked producer-controlled value: %v", err)
	}
	_, err = parseCompletionReply([]byte(`{"errCode":"` + secret + `","errMsg":"ignored"}`))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unknown completion code leaked producer-controlled value: %v", err)
	}
}

func TestNativeRuntimeContractViolationErrorsRedactAllProducerTextChannels(t *testing.T) {
	contract := loadAssignmentFixture(t)
	enrollmentSecret := conformance.AgentAssignmentBootstrapCredentialFixture
	deviceSecret := canonicalNativeDeviceCredential
	ticketSecret := contract.AccountCredentialOTP.EnrollmentBinding.VerifiedAssignmentTicket
	secrets := []string{enrollmentSecret, deviceSecret, ticketSecret}
	assertRedacted := func(name string, err, want error) {
		t.Helper()
		if err == nil || !errors.Is(err, want) {
			t.Fatalf("%s error = %v, want %v", name, err, want)
		}
		rendered := fmt.Sprintf("%v | %+v | %#v", err, err, err)
		for _, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Fatalf("%s error reflected producer-controlled secret: %s", name, rendered)
			}
		}
	}

	for name, body := range map[string]string{
		"RAK aspId value":          fmt.Sprintf(`{"errCode":"0","aspId":%q}`, enrollmentSecret),
		"RAK unknown field name":   fmt.Sprintf(`{"errCode":"0","aspId":"agent",%q:true}`, deviceSecret),
		"RAK duplicate field name": fmt.Sprintf(`{%q:1,%q:2,"errCode":"0","aspId":"agent"}`, ticketSecret, ticketSecret),
	} {
		_, err := parseNativeRegisterAck([]byte(body))
		assertRedacted(name, err, ErrRegisterReplyMalformed)
	}

	initialBody := contract.InitialAssignment.Result.BodyJSON
	hubCases := map[string]string{
		"Hub returned agent_id":    strings.Replace(initialBody, `"agent_id":"agent-conform"`, fmt.Sprintf(`"agent_id":%q`, enrollmentSecret), 1),
		"Hub returned key_kind":    strings.Replace(initialBody, `"key_kind":"bootstrap"`, fmt.Sprintf(`"key_kind":%q`, deviceSecret), 1),
		"Hub returned timestamp":   strings.Replace(initialBody, `"assignment_ticket_expires_at":"2026-07-15T23:15:00Z"`, fmt.Sprintf(`"assignment_ticket_expires_at":%q`, ticketSecret), 1),
		"Hub unknown field name":   fmt.Sprintf(`{%q:true,%s`, enrollmentSecret, initialBody[1:]),
		"Hub duplicate field name": fmt.Sprintf(`{%q:1,%q:2,%s`, deviceSecret, deviceSecret, initialBody[1:]),
	}
	for name, body := range hubCases {
		_, err := parseInitialAssignmentReply([]byte(body), "agent-conform", assignmentFixtureNow)
		assertRedacted(name, err, ErrAssignmentInvalidResponse)
	}

	completionBody := contract.RegistrationCompletion.Result.BodyJSON
	for name, body := range map[string]string{
		"completion unknown field name":   fmt.Sprintf(`{%q:true,%s`, deviceSecret, completionBody[1:]),
		"completion duplicate field name": fmt.Sprintf(`{%q:1,%q:2,%s`, ticketSecret, ticketSecret, completionBody[1:]),
	} {
		_, err := parseCompletionReply([]byte(body))
		assertRedacted(name, err, ErrRegisterReplyMalformed)
	}

	knockSuccess := `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-secret"},"preActions":{"resource-public-key":null}}`
	for name, body := range map[string]string{
		"knock arbitrary errCode":    fmt.Sprintf(`{"errCode":%q}`, enrollmentSecret),
		"knock unknown field name":   fmt.Sprintf(`{%q:true,%s`, deviceSecret, knockSuccess[1:]),
		"knock duplicate field name": fmt.Sprintf(`{%q:1,%q:2,%s`, ticketSecret, ticketSecret, knockSuccess[1:]),
		"knock map entry key":        fmt.Sprintf(`{"errCode":"0","resHost":{},"opnTime":1,"agentAddr":"203.0.113.9:49152","acTokens":{%q:{}},"preActions":{}}`, enrollmentSecret),
	} {
		_, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)}, "resource-public-key")
		assertRedacted(name, err, ErrMalformedReply)
	}
}

func TestClassifyNativeRegisterError_RetainsEstablished521xxTaxonomy(t *testing.T) {
	tests := []struct {
		code    string
		keyKind string
		want    error
	}{
		{rakCredentialInvalid, keyKindAccount, ErrOTPIncorrect},
		{rakCredentialInvalid, keyKindBootstrap, ErrKeyRejected},
		{rakCredentialExpired, keyKindAccount, ErrOTPExpired},
		{rakCredentialExpired, keyKindBootstrap, ErrKeyRejected},
		{rakAttemptsExceeded, keyKindAccount, ErrRegistrationRateLimited},
		{rakRateLimited, keyKindBootstrap, ErrRegistrationRateLimited},
		{rakEmailUnavailable, keyKindAccount, ErrNoAccountEmail},
		{rakInvalidAPIKey, keyKindBootstrap, ErrKeyRejected},
		{rakRegistrationOff, keyKindBootstrap, ErrRegistrationDisabled},
		{rakBootstrapConsumed, keyKindBootstrap, ErrBootstrapSetupKeyConsumed},
		{rakInvalidInput, keyKindBootstrap, ErrRegistrationInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.code+"/"+test.keyKind, func(t *testing.T) {
			err := classifyNativeRegisterError(&registerAckBody{ErrCode: test.code, ErrMsg: "untrusted detail"}, test.keyKind)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "untrusted detail") {
				t.Fatalf("native RAK %s/%s = %v, want %v without errMsg echo", test.code, test.keyKind, err, test.want)
			}
			if test.code == rakCredentialExpired && test.keyKind != keyKindAccount && (errors.Is(err, ErrOTPExpired) || registrationVerdictPermitsReplacement(err)) {
				t.Fatalf("out-of-contract %s/%s gained account replacement authority: %v", test.code, test.keyKind, err)
			}
		})
	}
}

func TestNative521xxGuidanceNamesNativeRecoveryActions(t *testing.T) {
	for _, test := range []struct {
		code string
		want string
	}{
		{rakCredentialExpired, "RegisterAgentRuntime"},
		{rakIdentityConflict, "NHP-native reprovisioning"},
		{rakInvalidInput, "WithAgentRuntimeIdentity"},
	} {
		err := classifyNativeRegisterError(&registerAckBody{ErrCode: test.code}, keyKindAccount)
		if !strings.Contains(err.Error(), test.want) {
			t.Fatalf("native %s guidance = %v, want %q", test.code, err, test.want)
		}
	}
	assignmentErr := (&AssignmentError{Code: "52109", kind: ErrAssignmentRequestRejected}).Error()
	if !strings.Contains(assignmentErr, "WithAgentRuntimeIdentity") {
		t.Fatalf("native Hub 52109 guidance = %q", assignmentErr)
	}
	consumed := &AssignmentError{Code: "52108", kind: ErrAssignmentBootstrapConsumed}
	if !errors.Is(consumed, ErrAssignmentBootstrapConsumed) {
		t.Fatalf("52108 assignment error does not unwrap to ErrAssignmentBootstrapConsumed: %v", consumed)
	}
	if consumedErr := consumed.Error(); !strings.Contains(consumedErr, "mint a new enrollment token") ||
		!strings.Contains(consumedErr, "single-use") {
		t.Fatalf("native Hub 52108 guidance = %q, want the typed remedy naming a new enrollment token and single-use, not a bare code", consumedErr)
	}
	completionErr := (&CompletionError{Code: "52303", kind: ErrCompletionCredentialConflict}).Error()
	if !strings.Contains(completionErr, "NHP-native credential recovery or reprovisioning") ||
		!strings.Contains(completionErr, "do not delete the persisted candidate") {
		t.Fatalf("native 52303 guidance = %q", completionErr)
	}
}

func TestEnsureAssignmentContinuity(t *testing.T) {
	base := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 4, EndpointRevision: 7,
		LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint:       NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: validTestNHPServerPublicKeyB64},
	}
	tests := []struct {
		name string
		edit func(*AgentAssignment)
		want error
	}{
		{name: "sticky lease refresh", edit: func(a *AgentAssignment) { a.LeaseExpiresAt = a.LeaseExpiresAt.Add(time.Hour) }},
		{name: "revision advance permits endpoint rotation", edit: func(a *AgentAssignment) { a.EndpointRevision++; a.Endpoint.Host = "cell0-new.nhp.layerv.ai" }},
		{name: "cell move requires explicit reassignment", edit: func(a *AgentAssignment) { a.CellID = "cell1" }, want: ErrAssignmentReassignmentRequired},
		{name: "generation move requires explicit reassignment", edit: func(a *AgentAssignment) { a.AssignmentGeneration++ }, want: ErrAssignmentReassignmentRequired},
		{name: "revision regression", edit: func(a *AgentAssignment) { a.EndpointRevision-- }, want: ErrAssignmentEndpointContinuity},
		{name: "unrevisioned endpoint change", edit: func(a *AgentAssignment) { a.Endpoint.Host = "cell0-new.nhp.layerv.ai" }, want: ErrAssignmentEndpointContinuity},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			current := base.clone()
			testCase.edit(current)
			err := ensureAssignmentContinuity(base, current)
			if testCase.want == nil && err != nil || testCase.want != nil && !errors.Is(err, testCase.want) {
				t.Fatalf("continuity error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestCompletionRetryClasses(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{name: "transport", err: nativeudp.ErrTransport, retryable: true},
		{name: "resolve", err: nativeudp.ErrResolve, retryable: true},
		{name: "authenticated unavailable", err: &CompletionError{Code: "52300", RetryAfter: time.Second, kind: ErrCompletionUnavailable}, retryable: true},
		{name: "authenticated identity rejection", err: &CompletionError{Code: "52301", kind: ErrCompletionIdentityRejected}},
		{name: "unauthenticated server", err: nativeudp.ErrServerUnauthenticated},
		{name: "authenticated malformed", err: ErrRegisterReplyMalformed},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, retryable := completionRetryInfo(testCase.err)
			if retryable != testCase.retryable {
				t.Fatalf("retryable = %t, want %t", retryable, testCase.retryable)
			}
		})
	}
}

// openFixtureClock pins warm open to the same instant the Hub fixtures assume.
func openFixtureClock() func() time.Time {
	return func() time.Time { return assignmentFixtureNow }
}

// The common warm start must stay exactly as cheap as it was: one store load,
// no lock, no packet. Auto-renewal is a repair for an expired lease, not a new
// cost on every process start.
func TestOpenRegisteredAgentRuntime_LiveLeaseStaysOffline(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	savesAfterSeed := len(f.store.snapshots())

	client, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil || client == nil || binding == nil {
		t.Fatalf("warm open with a live lease = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if !sameAgentAssignment(&AgentAssignment{
		CellID: binding.CellID, AssignmentGeneration: binding.AssignmentGeneration,
		EndpointRevision: binding.EndpointRevision, LeaseExpiresAt: binding.LeaseExpiresAt,
		Endpoint: binding.NHPUDPEndpoint,
	}, &initial.Assignment) {
		t.Fatalf("warm open changed the live assignment: %#v", binding)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != savesAfterSeed {
		t.Fatalf("warm open with a live lease was not offline: Hub/cell=%d/%d saves=%d want=%d",
			len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), len(f.store.snapshots()), savesAfterSeed)
	}
}

// An expired lease is repaired in place. A restart after any outage longer than
// the lease produces a knockable binding with no special-case caller code.
func TestOpenRegisteredAgentRuntime_RenewsExpiredLeaseThroughHub(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	renewed.EndpointRevision = 1
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	expired := initial.Assignment.clone()
	expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, expired)
	httpCalls, refusingHTTP := refusingReassignmentHTTP()

	client, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions(),
		WithAgentClientHTTPClient(refusingHTTP))
	if err != nil || client == nil || binding == nil {
		t.Fatalf("warm open with an expired lease = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if !binding.LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) || binding.CellID != "cell0" {
		t.Fatalf("warm open did not renew the lease: %#v", binding)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Renewal goes through the Hub over UDP only, and the repaired lease is
	// durable so the next start is offline again.
	if !sameAgentAssignment(persisted.Assignment, renewed) || httpCalls.Load() != 0 ||
		len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("expired-lease renewal used an unexpected transport or did not persist: state=%#v HTTP=%d Hub/cell=%d/%d",
			persisted.Assignment, httpCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

// The payoff of both changes together: a process restarting after LayerV moved
// it lands on the new cell with no error and no reassignment handling.
func TestOpenRegisteredAgentRuntime_FollowsRelocationOnExpiredLease(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	expired := initial.Assignment.clone()
	expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, expired)
	httpCalls, refusingHTTP := refusingReassignmentHTTP()

	client, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions(),
		WithAgentClientHTTPClient(refusingHTTP))
	if err != nil || client == nil || binding == nil {
		t.Fatalf("warm open across a relocation = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != "cell1" || binding.AssignmentGeneration != 2 {
		t.Fatalf("warm open did not follow the move: %#v", binding)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, target) || httpCalls.Load() != 0 ||
		len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("relocation on warm open used an unexpected transport or did not persist: state=%#v HTTP=%d Hub/cell=%d/%d",
			persisted.Assignment, httpCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestOpenRegisteredAgentRuntime_OfflineOpenKeepsExpiredLeaseError(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	expired := initial.Assignment.clone()
	expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, expired)
	savesAfterSeed := len(f.store.snapshots())

	client, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions(),
		WithAgentRuntimeOfflineOpen())
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || binding != nil || !errors.Is(err, ErrAssignmentLeaseExpired) {
		t.Fatalf("offline open = client %v, binding %v, err %v; want ErrAssignmentLeaseExpired", client, binding, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.store.snapshots()) != savesAfterSeed {
		t.Fatalf("offline open performed I/O: Hub=%d saves=%d want=%d", len(f.hubUDP.snapshot()), len(f.store.snapshots()), savesAfterSeed)
	}
}

// Only an expired lease is repairable by renewal. A structurally invalid
// assignment must still fail closed without reaching for the network.
func TestOpenRegisteredAgentRuntime_InvalidAssignmentFailsClosedWithoutRenewal(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewable := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	// A Hub that would happily renew: if the renewal guard ever widened past an
	// expired lease, this open would succeed instead of failing closed.
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewable)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := initial.Assignment.clone()
	corrupt.Endpoint.Host = "cell0.attacker.example"
	seedCompletedRuntimeAssignment(t, f, corrupt)

	client, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || binding != nil || err == nil || errors.Is(err, ErrAssignmentLeaseExpired) {
		t.Fatalf("corrupt assignment open = client %v, binding %v, err %v; want a non-lease failure", client, binding, err)
	}
	if len(f.hubUDP.snapshot()) != 0 {
		t.Fatalf("corrupt assignment triggered a renewal: Hub=%d", len(f.hubUDP.snapshot()))
	}
}

// Production code that restarts constantly cannot know whether this is the
// first enrollment, so re-running RegisterAgentRuntime must be safe. With a live
// lease it stays exactly as cheap as a warm open: no setup lock, no packet.
func TestRegisterAgentRuntime_LiveLeaseRestartStaysOffline(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	savesAfterSeed := len(f.store.snapshots())

	client, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("re-register with a live lease = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != "cell0" || !binding.LeaseExpiresAt.Equal(initial.Assignment.LeaseExpiresAt) {
		t.Fatalf("re-register changed the live assignment: %#v", binding)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != savesAfterSeed {
		t.Fatalf("re-register with a live lease was not offline: Hub/cell=%d/%d saves=%d want=%d",
			len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), len(f.store.snapshots()), savesAfterSeed)
	}
}

// The latent production failure this guards: an unconditional re-register used
// to work for the life of the lease and then hard-fail on the first restart
// after it expired. It must renew instead, without re-enrolling.
func TestRegisterAgentRuntime_RenewsExpiredLeaseOnRestart(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	expired := initial.Assignment.clone()
	expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, expired)

	client, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("re-register with an expired lease = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if !binding.LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) {
		t.Fatalf("re-register did not renew the lease: %#v", binding)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one credential-free Hub refresh, no assigned-cell REG, and the
	// original device credential untouched: this renewed, it did not re-enroll.
	hubRequests := f.hubUDP.snapshot()
	if !sameAgentAssignment(persisted.Assignment, renewed) || len(hubRequests) != 1 || len(f.cellUDP.snapshot()) != 0 ||
		persisted.DeviceAPIKey != canonicalNativeDeviceCredential || persisted.DeviceAPIKeyID != "key_DvK9mN2pQr7S" {
		t.Fatalf("expired-lease re-register did not renew in place: state=%#v Hub/cell=%d/%d",
			persisted.Assignment, len(hubRequests), len(f.cellUDP.snapshot()))
	}
	if bytes.Contains(hubRequests[0].body, []byte(conformance.AgentAssignmentBootstrapCredentialFixture)) {
		t.Fatalf("expired-lease re-register replayed the enrollment credential: %s", hubRequests[0].body)
	}
}

func TestRegisterAgentRuntime_FollowsRelocationOnRestart(t *testing.T) {
	contract := loadAssignmentFixture(t)
	target := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	expired := initial.Assignment.clone()
	expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, expired)

	client, binding, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("re-register across a relocation = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != "cell1" || binding.AssignmentGeneration != 2 {
		t.Fatalf("re-register did not follow the move: %#v", binding)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, target) || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("relocation on re-register did not persist cleanly: state=%#v cell=%d", persisted.Assignment, len(f.cellUDP.snapshot()))
	}
}

// Session-renewal fixtures use wall-clock leases because KnockRegisteredAgent's
// option set deliberately excludes a clock: the renewal decision is made against
// the same real clock the knock validates with.
func seedSessionLease(t *testing.T, f *runtimeFixture, contract *conformance.AgentAssignmentFile, leaseExpiresAt time.Time) *AgentAssignment {
	t.Helper()
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seeded := initial.Assignment.clone()
	seeded.LeaseExpiresAt = leaseExpiresAt
	seedCompletedRuntimeAssignment(t, f, seeded)
	return seeded
}

func sessionKnockStep() runtimeUDPStep {
	return runtimeUDPStep{
		requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK,
		replyBody: `{"errCode":"0","resHost":{"resource-public-key":"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-session"},"preActions":{"resource-public-key":null}}`,
	}
}

func (f *runtimeFixture) knock(t *testing.T, binding *AgentRuntimeBinding, key []byte) (*NativeKnockResult, error) {
	t.Helper()
	return KnockRegisteredAgent(context.Background(), binding, key, "resource-public-key",
		NativeKnockOptions{RunID: "0123456789abcdef"},
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
}

// The steady state an enterprise lives in: register once, hold one binding, keep
// knocking. Crossing into the renewal window must renew in place, not fail.
func TestKnockRegisteredAgent_RenewsLeaseWithoutCallerInvolvement(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	seeded := seedSessionLease(t, f, contract, time.Now().Add(time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	if !binding.LeaseExpiresAt.Equal(seeded.LeaseExpiresAt) {
		t.Fatalf("warm open renewed a still-live lease: %v", binding.LeaseExpiresAt)
	}
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	result, err := f.knock(t, binding, key)
	if err != nil || result == nil || result.ACToken != "ac-session" {
		t.Fatalf("knock inside the renewal window = %#v, %v", result, err)
	}
	if !binding.Assignment().LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) {
		t.Fatalf("Assignment did not report the renewed lease: got %v want %v",
			binding.Assignment().LeaseExpiresAt, renewed.LeaseExpiresAt)
	}
	// The exported fields are a construction-time record and must not move, so a
	// caller may read them from any goroutine without racing a renewal.
	if !binding.LeaseExpiresAt.Equal(seeded.LeaseExpiresAt) || binding.CellID != seeded.CellID {
		t.Fatalf("renewal mutated the exported snapshot: lease=%v cell=%q", binding.LeaseExpiresAt, binding.CellID)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, renewed) {
		t.Fatalf("session renewal was not durable: %#v", persisted.Assignment)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("session renewal Hub/cell exchanges = %d/%d, want 1/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

// An already-expired lease is the case that used to fail every later knock.
func TestKnockRegisteredAgent_RenewsExpiredLease(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	seedSessionLease(t, f, contract, time.Now().Add(-time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	result, err := f.knock(t, binding, key)
	if err != nil || result == nil || result.ACToken != "ac-session" {
		t.Fatalf("knock with an expired lease = %#v, %v; want an in-place renewal", result, err)
	}
}

// A relocation that lands while a process is running is followed too.
func TestKnockRegisteredAgent_FollowsRelocationMidSession(t *testing.T) {
	contract := loadAssignmentFixture(t)
	cell1PrivateBytes := bytes.Repeat([]byte{0x22}, x25519key.Size)
	cell1Private, err := ecdh.X25519().NewPrivateKey(cell1PrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	cell1PublicB64 := base64.StdEncoding.EncodeToString(cell1Private.PublicKey().Bytes())
	target := newReassignmentTarget(t, contract, "cell1", 2, cell1PublicB64, time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, target)}},
		nil,
	)
	cell1 := newRuntimeUDPServer(t, cell1PrivateBytes, assignmentHex(t, contract.Keys.Agent.StaticPubHex),
		runtimeUDPStep{
			requestType: relayknock.TypeKnock, replyType: relayknock.TypeACK,
			replyBody: `{"errCode":"0","resHost":{"resource-public-key":"frps.cell1.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"resource-public-key":"ac-cell1"},"preActions":{"resource-public-key":null}}`,
		})
	cell1Address := netip.MustParseAddr("11.11.11.11")
	f.resolver.hosts[target.Endpoint.Host] = cell1Address
	f.dialer.targets[cell1Address.String()] = cell1.conn.LocalAddr().String()
	seedSessionLease(t, f, contract, time.Now().Add(-time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	result, err := f.knock(t, binding, key)
	if err != nil || result == nil || result.ACToken != "ac-cell1" {
		t.Fatalf("knock across a mid-session relocation = %#v, %v", result, err)
	}
	live := binding.Assignment()
	if live.CellID != "cell1" || live.AssignmentGeneration != 2 || len(f.cellUDP.snapshot()) != 0 || len(cell1.snapshot()) != 1 {
		t.Fatalf("mid-session move went to the wrong cell: live=%#v old/new=%d/%d", live, len(f.cellUDP.snapshot()), len(cell1.snapshot()))
	}
}

// Renewal is once per lease, not once per knock.
func TestKnockRegisteredAgent_LiveLeaseDoesNotRenew(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{sessionKnockStep()})
	seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	if _, err := f.knock(t, binding, key); err != nil {
		t.Fatalf("knock with a live lease: %v", err)
	}
	if len(f.hubUDP.snapshot()) != 0 {
		t.Fatalf("live-lease knock contacted the Hub %d times, want 0", len(f.hubUDP.snapshot()))
	}
}

// Renewal ahead of expiry is best effort: a Hub outage while the lease is still
// valid must not take down an agent that is working perfectly well.
func TestKnockRegisteredAgent_HubOutageInRenewalWindowKeepsWorking(t *testing.T) {
	contract := loadAssignmentFixture(t)
	// The outage is the Hub having no steps, so the renewal waits out its bounds.
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{sessionKnockStep()}).expectSilence()
	seeded := seedSessionLease(t, f, contract, time.Now().Add(time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	result, err := f.knock(t, binding, key)
	if err != nil || result == nil || result.ACToken != "ac-session" {
		t.Fatalf("knock during a Hub outage with a live lease = %#v, %v; want the knock to succeed", result, err)
	}
	if !binding.LeaseExpiresAt.Equal(seeded.LeaseExpiresAt) {
		t.Fatalf("failed best-effort renewal changed the lease: %v", binding.LeaseExpiresAt)
	}
}

// Editing exported assignment fields must still be unable to retarget a knock.
func TestKnockRegisteredAgent_TamperedExportedFieldsStillRejected(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{sessionKnockStep()})
	seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)
	binding.NHPUDPEndpoint.Host = "attacker.nhp.layerv.ai"

	if _, err := f.knock(t, binding, key); !errors.Is(err, ErrInvalidNativeKnockInput) {
		t.Fatalf("tampered endpoint knock = %v, want ErrInvalidNativeKnockInput", err)
	}
	if len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("tampered knock reached a cell %d times", len(f.cellUDP.snapshot()))
	}
}

// A shared binding renews exactly once under concurrent knocks, and every
// goroutine observes the same placement. Run with -race.
func TestKnockRegisteredAgent_ConcurrentRenewalHappensOnce(t *testing.T) {
	const knockers = 8
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	cellSteps := make([]runtimeUDPStep, knockers)
	for i := range cellSteps {
		cellSteps[i] = sessionKnockStep()
	}
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		cellSteps,
	)
	seedSessionLease(t, f, contract, time.Now().Add(time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	var wg sync.WaitGroup
	errs := make([]error, knockers)
	leases := make([]time.Time, knockers)
	start := make(chan struct{})
	for i := range knockers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = f.knock(t, binding, key)
			leases[i] = binding.Assignment().LeaseExpiresAt
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent knock %d: %v", i, err)
		}
		if !leases[i].Equal(renewed.LeaseExpiresAt) {
			t.Fatalf("concurrent knock %d saw lease %v, want the renewed %v", i, leases[i], renewed.LeaseExpiresAt)
		}
	}
	// One Hub exchange total: the renewal lock collapses the stampede.
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("concurrent renewal made %d Hub exchanges, want 1", len(f.hubUDP.snapshot()))
	}
	if len(f.cellUDP.snapshot()) != knockers {
		t.Fatalf("cell exchanges = %d, want %d", len(f.cellUDP.snapshot()), knockers)
	}
}

// The exported assignment fields are written once and never again, so a caller
// may read them from any goroutine while another knocks and renews. Run with
// -race: this is the guarantee that replaced the old "read them from the same
// goroutine that knocks" caveat.
func TestKnockRegisteredAgent_ExportedFieldsAreImmutableUnderConcurrentRenewal(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	seeded := seedSessionLease(t, f, contract, time.Now().Add(time.Minute))

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Concurrent reads of the exported snapshot must never race a renewal.
			if binding.CellID != seeded.CellID || !binding.LeaseExpiresAt.Equal(seeded.LeaseExpiresAt) {
				t.Errorf("exported snapshot changed under a renewal: cell=%q lease=%v", binding.CellID, binding.LeaseExpiresAt)
				return
			}
		}
	}()

	if _, err := f.knock(t, binding, key); err != nil {
		t.Fatalf("knock during concurrent snapshot reads: %v", err)
	}
	close(stop)
	wg.Wait()

	if live := binding.Assignment(); !live.LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) {
		t.Fatalf("Assignment did not report the renewed lease: %v want %v", live.LeaseExpiresAt, renewed.LeaseExpiresAt)
	}
}

// ConnectAgentRuntime is the one call a service makes on every start. Prove the
// three states it has to absorb without the caller knowing which one it is in.
func TestConnectAgentRuntime_OneCallCoversEveryStart(t *testing.T) {
	contract := loadAssignmentFixture(t)

	t.Run("first start enrolls with a credential", func(t *testing.T) {
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
			[]runtimeUDPStep{
				{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
				{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
			},
		)
		client, binding, err := ConnectAgentRuntime(context.Background(), f.store,
			f.options(WithAgentRuntimeEnrollmentCredential(conformance.AgentAssignmentBootstrapCredentialFixture))...)
		if err != nil || client == nil || binding == nil {
			t.Fatalf("first start = client %v, binding %v, err %v", client, binding, err)
		}
		binding.Destroy()
	})

	t.Run("later start needs no credential and no network", func(t *testing.T) {
		f := newRuntimeFixture(t, nil, nil)
		initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
		if err != nil {
			t.Fatal(err)
		}
		seedCompletedRuntimeAssignment(t, f, &initial.Assignment)

		client, binding, err := ConnectAgentRuntime(context.Background(), f.store, f.options()...)
		if err != nil || client == nil || binding == nil {
			t.Fatalf("later start = client %v, binding %v, err %v", client, binding, err)
		}
		defer binding.Destroy()
		if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
			t.Fatalf("later start was not offline: Hub/cell=%d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
		}
	})

	t.Run("expired lease renews without a credential", func(t *testing.T) {
		renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, renewed)}},
			nil,
		)
		initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
		if err != nil {
			t.Fatal(err)
		}
		expired := initial.Assignment.clone()
		expired.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Minute)
		seedCompletedRuntimeAssignment(t, f, expired)

		client, binding, err := ConnectAgentRuntime(context.Background(), f.store, f.options()...)
		if err != nil || client == nil || binding == nil {
			t.Fatalf("expired-lease start = client %v, binding %v, err %v", client, binding, err)
		}
		defer binding.Destroy()
		if !binding.Assignment().LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) {
			t.Fatalf("expired-lease start did not renew: %v", binding.Assignment().LeaseExpiresAt)
		}
	})

	t.Run("first start without a credential cannot enroll", func(t *testing.T) {
		f := newRuntimeFixture(t, nil, nil)
		client, binding, err := ConnectAgentRuntime(context.Background(), f.store, f.options()...)
		if binding != nil {
			binding.Destroy()
		}
		if client != nil || binding != nil || !errors.Is(err, ErrInvalidRegisterConfig) {
			t.Fatalf("credential-free first start = client %v, binding %v, err %v; want ErrInvalidRegisterConfig", client, binding, err)
		}
		if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
			t.Fatalf("credential-free first start reached the network: Hub/cell=%d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
		}
	})
}

// The deprecated entry points must keep behaving exactly as before, so code
// written against them upgrades without an edit.
func TestDeprecatedEntryPointsStillDelegate(t *testing.T) {
	contract := loadAssignmentFixture(t)
	// A wall-clock-live lease: these wrappers take no clock, so the seeded lease
	// has to be live against time.Now for the offline path to be exercised.
	seed := func(t *testing.T) *runtimeFixture {
		t.Helper()
		f := newRuntimeFixture(t, nil, nil)
		seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
		return f
	}

	t.Run("RegisterAgentRuntime with a positional credential", func(t *testing.T) {
		f := seed(t)
		client, binding, err := RegisterAgentRuntime(context.Background(), //nolint:staticcheck // asserts the compatibility wrapper
			conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
		if err != nil || client == nil || binding == nil {
			t.Fatalf("deprecated register = client %v, binding %v, err %v", client, binding, err)
		}
		binding.Destroy()
	})

	t.Run("OpenRegisteredAgentRuntime", func(t *testing.T) {
		f := seed(t)
		client, binding, err := OpenRegisteredAgentRuntime(context.Background(), f.store) //nolint:staticcheck // asserts the compatibility wrapper
		if err != nil || client == nil || binding == nil {
			t.Fatalf("deprecated open = client %v, binding %v, err %v", client, binding, err)
		}
		binding.Destroy()
		if len(f.hubUDP.snapshot()) != 0 {
			t.Fatalf("deprecated open contacted the Hub %d times", len(f.hubUDP.snapshot()))
		}
	})
}

// A service that calls ConnectAgentRuntime on every start keeps passing whatever
// credential it was configured with. Once registered, that credential is never
// used, so it must not matter if it has since rotated, expired, or become
// malformed — the positional argument it replaces was ignored the same way.
func TestConnectAgentRuntime_StaleCredentialIgnoredOnceRegistered(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)

	client, binding, err := ConnectAgentRuntime(context.Background(), f.store,
		f.options(WithAgentRuntimeEnrollmentCredential("not-a-valid-credential"))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("registered start with a stale credential = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("stale-credential start reached the network: Hub/cell=%d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

// A binding outlives the call that produced it, so it must not carry that call's
// secrets for the life of the process. Renewal sends no credential at all.
func TestBinding_RenewalStateHoldsNoCredential(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	_, binding, err := ConnectAgentRuntime(context.Background(), f.store,
		f.options(WithAgentRuntimeEnrollmentCredential(conformance.AgentAssignmentBootstrapCredentialFixture))...)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Destroy()
	if binding.renewal == nil {
		t.Fatal("expected a renewal-capable binding")
	}
	if got := binding.renewal.cfg.enrollCredential; got != "" {
		t.Errorf("binding retained the enrollment credential: %q", got)
	}
	if got := binding.renewal.cfg.deviceCredential; got != "" {
		t.Errorf("binding retained the device credential: %q", got)
	}
	if binding.renewal.cfg.otpProvider != nil {
		t.Error("binding retained the OTP provider")
	}
}

// seedExpiredSessionLease seeds a placement that is live against the fixture
// clock a warm open uses and expired against the wall clock a knock judges the
// lease with, so the binding opens offline and the renewal decision lands on the
// knock. It returns the seeded placement.
func seedExpiredSessionLease(t *testing.T, f *runtimeFixture, assignment *AgentAssignment) *AgentAssignment {
	t.Helper()
	seeded := assignment.clone()
	seeded.LeaseExpiresAt = time.Now().Add(-time.Minute)
	seedCompletedRuntimeAssignment(t, f, seeded)
	return seeded
}

func openSessionBinding(t *testing.T, f *runtimeFixture, refreshOpts ...AgentRuntimeRefreshOption) (*AgentRuntimeBinding, []byte) {
	t.Helper()
	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions(refreshOpts...))
	if err != nil {
		t.Fatalf("open session binding: %v", err)
	}
	t.Cleanup(binding.Destroy)
	key := binding.TakeDeviceStaticPrivateKey()
	t.Cleanup(func() { wipeBytes(key) })
	return binding, key
}

// assertSessionPlacementUnchanged proves a failed renewal changed nothing a
// later call could act on: not the live placement and not the durable record.
func assertSessionPlacementUnchanged(t *testing.T, f *runtimeFixture, binding *AgentRuntimeBinding, want *AgentAssignment) {
	t.Helper()
	if live := binding.Assignment(); !sameAgentAssignment(&live, want) {
		t.Fatalf("failed renewal moved the live placement: %#v, want %#v", live, want)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameAgentAssignment(persisted.Assignment, want) {
		t.Fatalf("failed renewal persisted a placement: %#v, want %#v", persisted.Assignment, want)
	}
}

// The single failure mode PR #126 kept: best effort stops at the expiry
// boundary, so a lease that has actually run out and a Hub that cannot renew it
// must fail the exchange carrying the renewal's own error class. Knocking the
// stale placement anyway would send an admission request to a cell that no
// longer holds this agent's lease.
func TestKnockRegisteredAgent_ExpiredLeaseFailsWhenRenewalFails(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, test := range []struct {
		name      string
		hubSteps  []runtimeUDPStep
		wantClass error
	}{
		{name: "Hub outage", wantClass: ErrAssignmentRecoveryRequired},
		{
			name: "authenticated Hub denial",
			hubSteps: []runtimeUDPStep{{
				requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
				replyBody: `{"errCode":"52201","errMsg":"identity rejected"}`,
			}},
			wantClass: ErrAssignmentIdentityRejected,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t, test.hubSteps, []runtimeUDPStep{sessionKnockStep()})
			if len(test.hubSteps) == 0 {
				// The outage case has nothing to answer it and waits out its bounds.
				f.expectSilence()
			}
			initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			seeded := seedExpiredSessionLease(t, f, &initial.Assignment)
			binding, key := openSessionBinding(t, f)

			result, err := f.knock(t, binding, key)
			if result != nil || !errors.Is(err, test.wantClass) {
				t.Fatalf("knock on an unrenewable expired lease = %#v, %v; want %v", result, err, test.wantClass)
			}
			if len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("failed renewal still knocked the stale cell %d times", len(f.cellUDP.snapshot()))
			}
			assertSessionPlacementUnchanged(t, f, binding, seeded)
		})
	}
}

// Anti-rollback is the property that makes automatic adoption safe, and PR #126
// made renewal automatic on the knock path. A replayed or stale Hub LRT must be
// rejected here exactly as it is for an explicit RefreshAgentRuntime.
func TestKnockRegisteredAgent_RenewalRejectsRolledBackAssignment(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, test := range []struct {
		name      string
		seeded    func(*testing.T) *AgentAssignment
		hubReply  func(*testing.T) *AgentAssignment
		wantClass error
	}{
		{
			// A same-or-lower generation cannot carry the agent into another cell.
			name: "generation rollback into another cell",
			seeded: func(t *testing.T) *AgentAssignment {
				return newReassignmentTarget(t, contract, "cell1", 3, "", time.Time{})
			},
			hubReply: func(t *testing.T) *AgentAssignment {
				return newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
			},
			wantClass: ErrAssignmentInvalidResponse,
		},
		{
			// Within one generation the endpoint revision is the ordering, so a
			// regression is a replayed reply rather than a move.
			name: "endpoint revision regression inside one generation",
			seeded: func(t *testing.T) *AgentAssignment {
				seeded := newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
				seeded.EndpointRevision = 3
				return seeded
			},
			hubReply: func(t *testing.T) *AgentAssignment {
				return newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})
			},
			wantClass: ErrAssignmentEndpointContinuity,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{
					requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
					replyBody: rewriteRefreshAssignment(t, contract, test.hubReply(t)),
				}},
				[]runtimeUDPStep{sessionKnockStep()},
			)
			seeded := seedExpiredSessionLease(t, f, test.seeded(t))
			binding, key := openSessionBinding(t, f)

			result, err := f.knock(t, binding, key)
			if result != nil || !errors.Is(err, test.wantClass) {
				t.Fatalf("knock adopting a rolled-back placement = %#v, %v; want %v", result, err, test.wantClass)
			}
			if len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("rejected rollback still reached a cell %d times", len(f.cellUDP.snapshot()))
			}
			assertSessionPlacementUnchanged(t, f, binding, seeded)
		})
	}
}

// WithAgentRuntimePinnedAssignment travels into the binding through attachRenewal,
// so a relocation LayerV makes mid-session must be refused on the knock path too.
// Placement that feeds an egress allowlist cannot move because a knock happened.
func TestKnockRegisteredAgent_PinnedAssignmentRefusesMidSessionRelocation(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initialOf := func(t *testing.T) *AgentAssignment {
		t.Helper()
		initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
		if err != nil {
			t.Fatal(err)
		}
		return &initial.Assignment
	}

	t.Run("expired lease fails closed", func(t *testing.T) {
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{{
				requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
				replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})),
			}},
			[]runtimeUDPStep{sessionKnockStep()},
		)
		seeded := seedExpiredSessionLease(t, f, initialOf(t))
		binding, key := openSessionBinding(t, f, WithAgentRuntimePinnedAssignment())

		result, err := f.knock(t, binding, key)
		var changed *AgentAssignmentChangedError
		if result != nil || !errors.As(err, &changed) || !errors.Is(err, ErrAssignmentReassignmentRequired) {
			t.Fatalf("pinned knock across a relocation = %#v, %v; want *AgentAssignmentChangedError", result, err)
		}
		if len(f.cellUDP.snapshot()) != 0 {
			t.Fatalf("pinned knock reached a cell %d times", len(f.cellUDP.snapshot()))
		}
		assertSessionPlacementUnchanged(t, f, binding, seeded)
	})

	t.Run("live lease keeps knocking the pinned cell", func(t *testing.T) {
		f := newRuntimeFixture(t,
			[]runtimeUDPStep{{
				requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
				replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})),
			}},
			[]runtimeUDPStep{sessionKnockStep()},
		)
		// Inside the renewal lead but not expired, so the refused move is
		// best effort and must not take down a working agent.
		seeded := initialOf(t).clone()
		seeded.LeaseExpiresAt = time.Now().Add(time.Minute)
		seedCompletedRuntimeAssignment(t, f, seeded)
		binding, key := openSessionBinding(t, f, WithAgentRuntimePinnedAssignment())

		result, err := f.knock(t, binding, key)
		if err != nil || result == nil || result.ACToken != "ac-session" {
			t.Fatalf("pinned knock inside the renewal window = %#v, %v; want the pinned cell to answer", result, err)
		}
		if len(f.cellUDP.snapshot()) != 1 {
			t.Fatalf("pinned knock reached the original cell %d times, want 1", len(f.cellUDP.snapshot()))
		}
		assertSessionPlacementUnchanged(t, f, binding, seeded)
	})
}

// The renewal runs under the setup lock against freshly loaded state, so every
// guard between taking that lock and trusting the loaded placement has to fail
// closed rather than renew against state the binding was not built from.
func TestKnockRegisteredAgent_RenewalGuardsFailClosed(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, test := range []struct {
		name        string
		corrupt     func(*AgentState)
		wantClass   error
		wantMessage string
	}{
		{
			name:        "state stopped loading as a completed registration",
			corrupt:     func(s *AgentState) { s.RegisteredAt = nil },
			wantClass:   ErrInvalidRegisterConfig,
			wantMessage: "missing registration time",
		},
		{
			name:        "persisted agent id changed under the held binding",
			corrupt:     func(s *AgentState) { s.AgentID = "agent-replaced" },
			wantClass:   ErrInvalidRegisterConfig,
			wantMessage: "persisted agent id changed under a held binding",
		},
		{
			name:        "completed state lost its assignment",
			corrupt:     func(s *AgentState) { s.Assignment = nil },
			wantClass:   ErrInvalidRegisterConfig,
			wantMessage: "completed state has no assignment",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{
					requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
					replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})),
				}},
				[]runtimeUDPStep{sessionKnockStep()},
			)
			initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			seedExpiredSessionLease(t, f, &initial.Assignment)
			binding, key := openSessionBinding(t, f)

			// The binding is already built; only what the renewal reloads changes.
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			test.corrupt(state)
			if err := f.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("persist the diverged state: %v", err)
			}

			result, err := f.knock(t, binding, key)
			if result != nil || !errors.Is(err, test.wantClass) || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("knock renewing against diverged state = %#v, %v; want %v containing %q", result, err, test.wantClass, test.wantMessage)
			}
			if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("a guard that must fail before I/O sent Hub/cell packets: %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

// The documented shared-state-file pattern: a sibling process holding the same
// store already renewed. Adopting that result is what keeps N processes from
// spending N Hub exchanges for one lease.
func TestKnockRegisteredAgent_AdoptsRenewalAnotherProcessAlreadyPersisted(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})),
		}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedExpiredSessionLease(t, f, &initial.Assignment)
	binding, key := openSessionBinding(t, f)

	sibling := initial.Assignment.clone()
	sibling.LeaseExpiresAt = reassignmentFixtureLeaseExpiresAt
	sibling.EndpointRevision = 2
	seedCompletedRuntimeAssignment(t, f, sibling)
	savesBeforeKnock := len(f.store.snapshots())

	result, err := f.knock(t, binding, key)
	if err != nil || result == nil || result.ACToken != "ac-session" {
		t.Fatalf("knock after a sibling renewal = %#v, %v", result, err)
	}
	// The Hub reply this fixture holds would also renew successfully, so a Hub
	// exchange here means the fast path was skipped rather than unavailable.
	if len(f.hubUDP.snapshot()) != 0 {
		t.Fatalf("adopted renewal still spent %d Hub exchanges", len(f.hubUDP.snapshot()))
	}
	if live := binding.Assignment(); !sameAgentAssignment(&live, sibling) {
		t.Fatalf("binding did not adopt the sibling renewal: %#v, want %#v", live, sibling)
	}
	if got := len(f.store.snapshots()); got != savesBeforeKnock {
		t.Fatalf("adopted renewal rewrote the shared state file: saves %d, want %d", got, savesBeforeKnock)
	}
}

// unpersistableAgentStateStore refuses saves once armed. It deliberately does
// not implement agentStateStoreDecorator: attachRenewal keeps only
// baseAgentStateStore(store), so a decorator's fault injection is invisible to a
// session renewal and the failure has to live in the base store instead.
type unpersistableAgentStateStore struct {
	inner AgentStateStore
	armed atomic.Bool
}

func (s *unpersistableAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *unpersistableAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	if s.armed.Load() {
		return errors.New("injected renewed-assignment save failure")
	}
	return s.inner.SaveAgentState(ctx, state)
}

func (s *unpersistableAgentStateStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	locker, ok := s.inner.(setupLockingAgentStateStore)
	if !ok {
		return nil, errors.New("unpersistable test store lost its setup-lock capability")
	}
	return locker.acquireSetupLock(ctx)
}

// A renewed placement that cannot be proven durable must not be knocked with.
// The next process to load this file would otherwise disagree with the binding
// about where this agent lives.
func TestKnockRegisteredAgent_UnpersistableRenewalFailsTheKnock(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})),
		}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	unpersistable := &unpersistableAgentStateStore{inner: f.store.inner}
	f.store.inner = unpersistable
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seeded := seedExpiredSessionLease(t, f, &initial.Assignment)
	binding, key := openSessionBinding(t, f)
	unpersistable.armed.Store(true)

	result, err := f.knock(t, binding, key)
	if result != nil || !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("knock whose renewal could not be saved = %#v, %v; want ErrAgentBindingPersistence", result, err)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("renewal Hub exchanges = %d, want 1", len(f.hubUDP.snapshot()))
	}
	if len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("unpersisted renewal still knocked a cell %d times", len(f.cellUDP.snapshot()))
	}
	assertSessionPlacementUnchanged(t, f, binding, seeded)
}

// WithAgentRuntimeOfflineOpen promises the binding does not renew itself. The
// open-time half of that is already tested; this is the half a caller meets
// later, when the lease it chose to manage itself has run out.
func TestKnockRegisteredAgent_OfflineOpenBindingNeverRenews(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: rewriteRefreshAssignment(t, contract, newReassignmentTarget(t, contract, "cell0", 1, "", time.Time{})),
		}},
		[]runtimeUDPStep{sessionKnockStep()},
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seeded := seedExpiredSessionLease(t, f, &initial.Assignment)

	_, binding, err := openRegisteredAgentRuntime(context.Background(), f.store, openFixtureClock(), f.hub, f.refreshOptions(),
		WithAgentRuntimeOfflineOpen())
	if err != nil {
		t.Fatalf("offline open with a fixture-live lease: %v", err)
	}
	defer binding.Destroy()
	if binding.renewal != nil {
		t.Fatal("offline open returned a self-renewing binding")
	}
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)

	result, err := f.knock(t, binding, key)
	if result != nil || !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrAssignmentLeaseExpired) {
		t.Fatalf("offline-open knock past the lease = %#v, %v; want ErrInvalidNativeKnockInput and ErrAssignmentLeaseExpired", result, err)
	}
	// A Hub that would happily renew stayed untouched, which is the whole point
	// of the option.
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("offline-open knock performed I/O: Hub/cell=%d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	assertSessionPlacementUnchanged(t, f, binding, seeded)
}

// Renewal is once per lease, and the lead is what decides "once". Existing
// coverage brackets this boundary from a minute away on each side; an off-by-one
// in the comparison would silently move renewal by a whole lead.
func TestLiveSessionAssignment_RenewalLeadBoundary(t *testing.T) {
	contract := loadAssignmentFixture(t)
	lease := time.Now().Add(24 * time.Hour)
	for _, test := range []struct {
		name        string
		now         time.Time
		wantRenewal bool
	}{
		{name: "one nanosecond before the lead", now: lease.Add(-sessionLeaseRenewalLead - time.Nanosecond)},
		{name: "exactly at the lead", now: lease.Add(-sessionLeaseRenewalLead), wantRenewal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A Hub with no steps: the renewal attempt is observable as a recorded
			// request, and its failure is best effort while the lease is still live.
			f := newRuntimeFixture(t, nil, nil).expectSilence()
			seedSessionLease(t, f, contract, lease)
			binding, key := openSessionBinding(t, f)

			if _, err := binding.liveSessionAssignment(context.Background(), key, test.now); err != nil {
				t.Fatalf("liveSessionAssignment at the lead boundary: %v", err)
			}
			attempts := len(f.hubUDP.snapshot())
			if test.wantRenewal != (attempts > 0) {
				t.Fatalf("Hub renewal attempts = %d, want renewal=%t", attempts, test.wantRenewal)
			}
		})
	}
}

// KnockRegisteredAgent and ExitRegisteredAgentSession share one no-I/O admission
// gate, so every rejection below has to hold for both. A short or mistyped key
// must be refused on length before any curve operation.
func TestRegisteredAgentSessionControl_RejectsInvalidArgumentsBeforeIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	// The existing identity-drift tests all use correct-length wrong keys, so
	// only a length check reaches this branch before the curve rejects anything.
	sameKey := func(valid []byte) []byte { return valid }
	// Each case names the message of the branch it must land on. The key-length
	// cases in particular would otherwise be indistinguishable from the curve
	// rejecting the same bytes a few lines later.
	for _, test := range []struct {
		name          string
		nilBinding    bool
		key           func([]byte) []byte
		transportOpts []AgentRuntimeUDPOption
		wantMessage   string
	}{
		{name: "nil binding", nilBinding: true, key: sameKey, wantMessage: "runtime binding must not be nil"},
		{name: "short key", key: func([]byte) []byte { return make([]byte, x25519key.Size-1) }, wantMessage: "device static private key must be 32 bytes"},
		{name: "long key", key: func([]byte) []byte { return make([]byte, x25519key.Size+1) }, wantMessage: "device static private key must be 32 bytes"},
		{name: "empty key", key: func([]byte) []byte { return nil }, wantMessage: "device static private key must be 32 bytes"},
		{name: "nil transport option", key: sameKey, transportOpts: []AgentRuntimeUDPOption{nil}, wantMessage: "nil native UDP transport option"},
		{
			name: "rejected transport option", key: sameKey,
			transportOpts: []AgentRuntimeUDPOption{WithAgentRuntimeUDPBounds(0, 0)},
			wantMessage:   "native UDP transport option",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, []runtimeUDPStep{sessionKnockStep()})
			seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
			binding, key := openSessionBinding(t, f)
			key = test.key(key)
			if test.nilBinding {
				binding = nil
			}
			opts := append([]AgentRuntimeUDPOption{
				WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer),
			}, test.transportOpts...)

			_, knockErr := KnockRegisteredAgent(context.Background(), binding, key, "resource-public-key",
				NativeKnockOptions{RunID: "0123456789abcdef"}, opts...)
			exitErr := ExitRegisteredAgentSession(context.Background(), binding, key, "resource-public-key",
				NativeKnockOptions{RunID: "0123456789abcdef"}, opts...)
			for entryPoint, err := range map[string]error{"knock": knockErr, "exit": exitErr} {
				if !errors.Is(err, ErrInvalidNativeKnockInput) || !strings.Contains(err.Error(), test.wantMessage) {
					t.Fatalf("%s = %v, want ErrInvalidNativeKnockInput containing %q", entryPoint, err, test.wantMessage)
				}
			}
			if len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("rejected session control reached a cell %d times", len(f.cellUDP.snapshot()))
			}
		})
	}
}

// A clean exit is the documented end of every cycle, so its own failures have to
// stay classified: a rejected body must not look like a transport fault, and a
// transport fault must arrive in the same normalized class a knock would report.
func TestExitRegisteredAgentSession_ClassifiesBodyAndTransportFailures(t *testing.T) {
	contract := loadAssignmentFixture(t)

	t.Run("rejected session body sends nothing", func(t *testing.T) {
		f := newRuntimeFixture(t, nil, []runtimeUDPStep{sessionKnockStep()})
		seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
		binding, key := openSessionBinding(t, f)

		for name, opts := range map[string]NativeKnockOptions{
			"missing run id":   {},
			"malformed run id": {RunID: "not-a-run-id"},
		} {
			t.Run(name, func(t *testing.T) {
				err := ExitRegisteredAgentSession(context.Background(), binding, key, "resource-public-key", opts,
					WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer))
				if !errors.Is(err, ErrInvalidNativeKnockInput) {
					t.Fatalf("exit with a rejected body = %v, want ErrInvalidNativeKnockInput", err)
				}
			})
		}
		if len(f.cellUDP.snapshot()) != 0 {
			t.Fatalf("rejected exit body reached a cell %d times", len(f.cellUDP.snapshot()))
		}
	})

	t.Run("silent cell normalizes the transport failure", func(t *testing.T) {
		f := newRuntimeFixture(t, nil, []runtimeUDPStep{{requestType: relayknock.TypeExit, noReply: true}})
		seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
		binding, key := openSessionBinding(t, f)

		err := ExitRegisteredAgentSession(context.Background(), binding, key, "resource-public-key",
			NativeKnockOptions{RunID: "0123456789abcdef"},
			WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer),
			WithAgentRuntimeUDPBounds(200*time.Millisecond, 1))
		if err == nil || errors.Is(err, ErrInvalidNativeKnockInput) {
			t.Fatalf("exit against a silent cell = %v, want a transport failure", err)
		}
		if !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("exit transport failure = %v, want nativeudp.ErrTransport", err)
		}
		if got := len(f.cellUDP.snapshot()); got != 1 {
			t.Fatalf("exit reached the cell %d times, want 1", got)
		}
	})
}

// The SDK-generated agent id is what a caller who never passes
// WithAgentRuntimeIdentity depends on, and its documented promise is that the id
// exists and is durable before anything is sent.
func TestRegisterAgentRuntime_GeneratesAndPersistsAgentIdentityBeforeIO(t *testing.T) {
	// newRuntimeFixture seeds a persisted agent id, which is exactly the branch
	// this test must avoid; an unidentified state is the fresh-install shape.
	newUnidentifiedFixture := func(t *testing.T, hubSteps []runtimeUDPStep) *runtimeFixture {
		t.Helper()
		f := newRuntimeFixture(t, hubSteps, nil)
		state, err := f.store.LoadAgentState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		state.AgentID = ""
		if err := f.store.SaveAgentState(context.Background(), state); err != nil {
			t.Fatal(err)
		}
		return f
	}
	// The same wiring the other fixtures use, minus WithAgentRuntimeIdentity:
	// every existing fixture pins the id, which is why this branch has no cover.
	registerOptions := func(f *runtimeFixture) []AgentRuntimeRegistrationOption {
		timeout, budget := f.transportBounds()
		return []AgentRuntimeRegistrationOption{
			WithAgentRuntimeHeadlessEnrollment(),
			WithAgentRuntimeHub(f.hub),
			WithAgentRuntimeUDPResolver(f.resolver),
			WithAgentRuntimeUDPDialer(f.dialer),
			WithAgentRuntimeUDPBounds(timeout, 1),
			WithAgentRuntimeAssignmentRetryBudget(1, budget),
			withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }),
			withTestAgentRuntimeAssignmentNonce(conformance.AgentAssignmentInitialRequestNonceFixture),
			withAgentRuntimeDeviceCredential(canonicalNativeDeviceCredential),
			WithAgentRuntimeMetadata("conformance-host", "0.0.0-conformance"),
		}
	}

	t.Run("identity is generated, canonical, and durable before any packet", func(t *testing.T) {
		// A Hub with no steps: enrollment cannot get past the first exchange, so
		// anything durable at that point was written before the SDK sent anything.
		f := newUnidentifiedFixture(t, nil).expectSilence()
		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, registerOptions(f)...)
		if err == nil {
			t.Fatal("enrollment against a silent Hub succeeded")
		}
		persisted, err := f.store.LoadAgentState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if persisted.AgentID == "" {
			t.Fatal("no agent id was persisted before the Hub exchange")
		}
		if validateErr := validateAssignmentAgentID(persisted.AgentID); validateErr != nil {
			t.Fatalf("generated agent id %q is not a valid assignment identity: %v", persisted.AgentID, validateErr)
		}
		if !strings.HasPrefix(persisted.AgentID, "agent-") || len(persisted.AgentID) != len("agent-")+32 {
			t.Fatalf("generated agent id %q is not the documented agent-<128 bits hex> shape", persisted.AgentID)
		}

		// Restart: the saved id is reused rather than a second one minted, which
		// is what keeps one install from enrolling twice.
		before := persisted.AgentID
		_, _, err = RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, registerOptions(f)...)
		if err == nil {
			t.Fatal("second enrollment against a silent Hub succeeded")
		}
		restarted, err := f.store.LoadAgentState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if restarted.AgentID != before {
			t.Fatalf("restart changed the generated agent id: %q, want %q", restarted.AgentID, before)
		}
	})

	t.Run("an unsavable identity stops before the Hub is contacted", func(t *testing.T) {
		f := newUnidentifiedFixture(t, []runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: loadAssignmentFixture(t).InitialAssignment.Result.BodyJSON,
		}})
		f.store.fail = len(f.store.snapshots()) + 1

		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, registerOptions(f)...)
		if !errors.Is(err, ErrAgentBindingPersistence) {
			t.Fatalf("unsavable generated identity = %v, want ErrAgentBindingPersistence", err)
		}
		if len(f.hubUDP.snapshot()) != 0 {
			t.Fatalf("identity save failure still contacted the Hub %d times", len(f.hubUDP.snapshot()))
		}
	})
}

// Two distinct generated ids must not collide, or one install could adopt
// another's identity on a shared authority.
func TestGenerateDeviceID_IsCanonicalAndUnique(t *testing.T) {
	seen := make(map[string]bool, 64)
	for range 64 {
		id, err := generateDeviceID()
		if err != nil {
			t.Fatalf("generateDeviceID: %v", err)
		}
		if err := validateAssignmentAgentID(id); err != nil {
			t.Fatalf("generated id %q is not a valid assignment identity: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("generated id %q repeated", id)
		}
		seen[id] = true
	}
}
