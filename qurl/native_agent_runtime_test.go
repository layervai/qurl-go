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

type runtimeUDPStep struct {
	requestType int
	replyType   int
	replyBody   string
	noReply     bool
}

type runtimeUDPRequest struct {
	typeID int
	body   []byte
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
		case <-time.After(2 * time.Second):
			t.Error("runtime UDP server did not stop")
		}
	})
	return server
}

func (s *runtimeUDPServer) serve() {
	defer close(s.done)
	buffer := make([]byte, 4096)
	for {
		n, remote, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		opened, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, bytes.Clone(buffer[:n]))
		if err != nil {
			s.t.Errorf("open runtime request: %v", err)
			continue
		}
		s.mu.Lock()
		index := len(s.requests)
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
		if step.noReply {
			continue
		}
		packet, err := relayknocktest.BuildReply(step.replyType, &relayknock.KnockInputs{
			DeviceStaticPriv: s.serverPriv,
			ServerStaticPub:  s.agentPub,
			EphemeralPriv:    bytes.Repeat([]byte{byte(0x40 + index)}, 32),
			TimestampNanos:   uint64(assignmentFixtureNow.UnixNano()) + uint64(index),
			Counter:          opened.Counter,
			Preamble:         uint32(0x50607080 + index),
			Body:             []byte(step.replyBody),
		})
		if err != nil {
			s.t.Errorf("build runtime reply: %v", err)
			continue
		}
		if _, err := s.conn.WriteToUDP(packet, remote); err != nil {
			s.t.Logf("write runtime reply: %v", err)
		}
	}
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

func waitRuntimeUDPRequests(t *testing.T, server *runtimeUDPServer, count int) []runtimeUDPRequest {
	t.Helper()
	deadline := time.Now().Add(time.Second)
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
	inner           AgentStateStore
	mu              sync.Mutex
	saves           []*AgentState
	calls           int
	fail            int
	failAfterCommit int
	cancelOnSave    int
	cancel          context.CancelFunc
}

func (s *runtimeRecordingStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *runtimeRecordingStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	locker, ok := s.inner.(setupLockingAgentStateStore)
	if !ok {
		return nil, errors.New("runtime test store lost its setup-lock capability")
	}
	return locker.acquireSetupLock(ctx)
}

func (s *runtimeRecordingStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	s.mu.Lock()
	s.calls++
	call := s.calls
	fail := s.fail
	failAfterCommit := s.failAfterCommit
	cancelOnSave := s.cancelOnSave
	cancel := s.cancel
	s.mu.Unlock()
	if call == fail {
		return errors.New("injected runtime state save failure")
	}
	if err := s.inner.SaveAgentState(ctx, state); err != nil {
		return err
	}
	s.mu.Lock()
	s.saves = append(s.saves, state.clone())
	s.mu.Unlock()
	if call == cancelOnSave && cancel != nil {
		cancel()
	}
	if call == failAfterCommit {
		return errors.New("injected runtime state post-commit acknowledgement failure")
	}
	return nil
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

type runtimeFixture struct {
	contract *conformance.AgentAssignmentFile
	store    *runtimeRecordingStore
	hub      HubBootstrap
	resolver runtimeRouteResolver
	dialer   runtimeRouteDialer
	hubUDP   *runtimeUDPServer
	cellUDP  *runtimeUDPServer
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
	}
}

func (f *runtimeFixture) options(extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	return f.optionsWithMetadata(true, extra...)
}

func (f *runtimeFixture) optionsWithoutMetadata(extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	return f.optionsWithMetadata(false, extra...)
}

func (f *runtimeFixture) optionsWithMetadata(include bool, extra ...AgentRuntimeRegistrationOption) []AgentRuntimeRegistrationOption {
	opts := []AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(f.hub),
		WithAgentRuntimeIdentity("agent-conform"),
		WithAgentRuntimeUDPResolver(f.resolver),
		WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(100*time.Millisecond, 1),
		WithAgentRuntimeAssignmentRetryBudget(1, time.Second),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }),
		withAgentRuntimeDeviceCredential(canonicalNativeDeviceCredential),
	}
	if include {
		opts = append(opts, WithAgentRuntimeMetadata("conformance-host", "0.0.0-conformance"))
	}
	return append(opts, extra...)
}

func withTestAgentRuntimeAssignmentSleep(sleep func(context.Context, time.Duration) error) AgentRuntimeLifecycleOption {
	return nativeRuntimeLifecycleOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.assignmentOptions = append(c.assignmentOptions, withAssignmentSleep(sleep))
		return nil
	})
}

func TestAgentRuntimeRegistrationKeyKindPolicy_AllNativeKinds(t *testing.T) {
	cfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{WithAgentRuntimeHub(runtimeTestHub())})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindAgent,
	} {
		if err := cfg.requireAllowedRegistrationKeyKind(string(kind)); err != nil {
			t.Errorf("default native policy rejected %q: %v", kind, err)
		}
	}
	accountErr := cfg.requireAllowedRegistrationKeyKind(string(RegistrationKeyKindAccount))
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(accountErr, &disallowed) || !errors.Is(accountErr, ErrRegistrationKeyKindDisallowed) {
		t.Fatalf("default account policy error = %v, want typed disallowed error", accountErr)
	}
	wantAllowed := []RegistrationKeyKind{
		RegistrationKeyKindAgent,
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindConnectorBootstrap,
	}
	if !slices.Equal(disallowed.Allowed, wantAllowed) {
		t.Fatalf("default native allowed kinds = %v, want %v", disallowed.Allowed, wantAllowed)
	}

	accountCfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := accountCfg.requireAllowedRegistrationKeyKind(string(RegistrationKeyKindAccount)); err != nil {
		t.Fatalf("explicit account opt-in rejected: %v", err)
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

func TestRegisterAgentRuntime_DefaultKeyPolicy_AllFourKinds(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindAgent,
		RegistrationKeyKindAccount,
	} {
		t.Run(string(kind), func(t *testing.T) {
			assignmentResult := strings.Replace(
				contract.InitialAssignment.Result.BodyJSON,
				`"key_kind":"bootstrap"`,
				fmt.Sprintf(`"key_kind":%q`, kind),
				1,
			)
			cellSteps := []runtimeUDPStep(nil)
			if kind != RegistrationKeyKindAccount {
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
			var otpCallbacks atomic.Int32
			_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
				f.options(WithAgentRuntimeOTPProvider(func(context.Context, AgentOTPChallenge) (string, error) {
					otpCallbacks.Add(1)
					return "12345678", nil
				}))...)
			if kind == RegistrationKeyKindAccount {
				var disallowed *RegistrationKeyKindDisallowedError
				if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
					t.Fatalf("default account policy error = %v, want typed account rejection", err)
				}
				if len(f.cellUDP.snapshot()) != 0 || otpCallbacks.Load() != 0 {
					t.Fatalf("account policy rejection cell/callback counts = %d/%d, want 0/0", len(f.cellUDP.snapshot()), otpCallbacks.Load())
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
					t.Fatalf("default native policy for %q = %v, want assigned-cell REG", kind, err)
				}
				requests := f.cellUDP.snapshot()
				if len(requests) != 1 || requests[0].typeID != relayknock.TypeRegister {
					t.Fatalf("default native policy for %q made cell requests %v, want one REG", kind, requests)
				}
			}
			if len(f.hubUDP.snapshot()) != 1 {
				t.Fatalf("default native policy for %q made %d Hub requests, want 1", kind, len(f.hubUDP.snapshot()))
			}
		})
	}
}

func TestRegisterAgentRuntime_AccountOptInStillRequiresOTPProviderBeforeCellIO(t *testing.T) {
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
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("missing-provider Hub/cell counts = %d/%d, want 1/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
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
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(time.Second, 1))
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
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(time.Second, 1))
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
	tests := map[string]struct {
		body     string
		wantDeny bool
	}{
		"deny needs no success fields": {body: `{"errCode":"52004"}`, wantDeny: true},
		"missing errCode":              {body: `{"errMsg":"denied"}`},
		"null errCode":                 {body: `{"errCode":null}`},
		"noncanonical errCode":         {body: `{"errCode":" 52101"}`},
		"success needs success fields": {body: `{"errCode":"0"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(test.body)}, "resource-public-key")
			var deny *ServerDenyError
			if test.wantDeny {
				if !errors.As(err, &deny) || errors.Is(err, ErrMalformedReply) {
					t.Fatalf("deny precedence error = %T: %v", err, err)
				}
				return
			}
			if !errors.Is(err, ErrMalformedReply) || errors.As(err, &deny) {
				t.Fatalf("presence error = %T: %v, want ErrMalformedReply", err, err)
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
				WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
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
	inner, ok := f.store.inner.(fileAgentStateStore)
	if !ok {
		t.Fatalf("fixture store = %T, want fileAgentStateStore", f.store.inner)
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
				WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
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
		WithAgentRuntimeHub(f.hub), WithAgentRuntimeIdentity("agent-different"),
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
				WithAgentRuntimeHub(f.hub), WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
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

func TestRegisterAgentRuntime_RateLimitRetriesWholeHubTransactionWithinBudget(t *testing.T) {
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

func TestRunAssignmentLifecycle_DeadlineDuringRateLimitWaitRequiresRecovery(t *testing.T) {
	fixed := assignmentFixtureNow
	_, err := runAssignmentLifecycle(context.Background(), []AssignmentOption{
		WithAssignmentRetryBudget(2, 20*time.Millisecond),
		withAssignmentClock(func() time.Time { return fixed }),
		withAssignmentSleep(func(ctx context.Context, _ time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		}),
	}, func(context.Context) (*AgentAssignment, error) {
		return nil, &AssignmentError{Code: "52204", RetryAfter: time.Millisecond, kind: ErrAssignmentRateLimited}
	})
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, ErrAssignmentRateLimited) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rate-limit deadline = %T: %v, want recovery preserving rate limit/deadline", err, err)
	}
	if recovery.Attempts != 1 || recovery.Elapsed != 20*time.Millisecond {
		t.Fatalf("rate-limit deadline attempts/elapsed = %d/%s", recovery.Attempts, recovery.Elapsed)
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
	fileStore, ok := f.store.inner.(fileAgentStateStore)
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
		"peer": func(state *AgentState) {
			state.PendingActivation.AgentPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, x25519key.Size))
		},
		"cell":       func(state *AgentState) { state.PendingActivation.Assignment.CellID = "cell1" },
		"generation": func(state *AgentState) { state.PendingActivation.Assignment.AssignmentGeneration++ },
		"server identity": func(state *AgentState) {
			state.PendingActivation.Assignment.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, x25519key.Size))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
				[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
			)
			_, _, firstErr := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
			if !errors.Is(firstErr, ErrRegistrationRecoveryRequired) {
				t.Fatalf("seed pending activation: %v", firstErr)
			}
			state, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			mutate(state)
			if saveErr := f.store.SaveAgentState(context.Background(), state); saveErr != nil {
				t.Fatal(saveErr)
			}
			hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
			_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("changed %s pending state = %v, want invalid durable state", name, err)
			}
			if len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
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

	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
	)
	_, _, firstErr := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(firstErr, ErrRegistrationRecoveryRequired) {
		t.Fatal(firstErr)
	}
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
	if !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("changed pending metadata = %v, want ErrInvalidRegisterConfig", err)
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
			f := newRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
				[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
			)
			_, _, firstErr := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, test.seedOpts(f)...)
			if !errors.Is(firstErr, ErrRegistrationRecoveryRequired) {
				t.Fatalf("seed pending activation: %v", firstErr)
			}
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
	secondAssignment := strings.Replace(contract.InitialAssignment.Result.BodyJSON,
		"conformance-assignment-ticket-0001", "conformance-assignment-ticket-0002", 1)
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

func TestRegisterAgentRuntime_ReplacementPendingSaveFailurePreservesOldTicket(t *testing.T) {
	contract := loadAssignmentFixture(t)
	secondAssignment := strings.Replace(contract.InitialAssignment.Result.BodyJSON,
		"conformance-assignment-ticket-0001", "conformance-assignment-ticket-0002", 1)
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
	secondAssignment := strings.Replace(contract.InitialAssignment.Result.BodyJSON,
		"conformance-assignment-ticket-0001", "conformance-assignment-ticket-0002", 1)
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
}

func TestRegisterAgentRuntime_PostRAKPreCommitSaveFailureRequiresReloadBeforeRecovery(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON}},
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
	if !strings.Contains(err.Error(), "reload state first") || !strings.Contains(err.Error(), "same enrollment credential") || !strings.Contains(err.Error(), "never request a replacement ticket") || strings.Contains(err.Error(), "not persisted") {
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
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(time.Second, 1),
		WithAgentClientBaseURL("https://resources.example.test"),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }))
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
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := assignmentFixtureNow.Add(-time.Hour)
	state.RegisteredAt = &registeredAt
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_DvK9mN2pQr7S"
	state.Assignment = initial.Assignment.clone()
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(time.Second, 1),
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
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer), WithAgentRuntimeUDPBounds(time.Second, 1))
	if err != nil || result == nil || result.ACToken != "ac-rotated" || result.ResourceHost != "frps.cell0-r2.example:7000" {
		t.Fatalf("knock after endpoint/key rotation = %#v, %v", result, err)
	}
	if len(f.cellUDP.snapshot()) != 0 || len(rotatedCell.snapshot()) != 1 {
		t.Fatalf("old/new cell calls = %d/%d, want 0/1", len(f.cellUDP.snapshot()), len(rotatedCell.snapshot()))
	}
}

func TestRefreshAgentRuntime_ReassignmentIsExplicitAndNotPersisted(t *testing.T) {
	contract := loadAssignmentFixture(t)
	reassignedResult := strings.Replace(
		contract.RefreshAssignment.Result.BodyJSON,
		`"cell_id":"cell0"`,
		`"cell_id":"cell1"`,
		1,
	)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: reassignedResult}},
		nil,
	)
	initial, err := parseInitialAssignmentReply(
		[]byte(contract.InitialAssignment.Result.BodyJSON),
		"agent-conform",
		assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := assignmentFixtureNow.Add(-time.Hour)
	state.RegisteredAt = &registeredAt
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_DvK9mN2pQr7S"
	state.Assignment = initial.Assignment.clone()
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		WithAgentRuntimeUDPResolver(f.resolver),
		WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(time.Second, 1),
		withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }),
	)
	if binding != nil {
		binding.Destroy()
		t.Fatal("reassignment unexpectedly returned an adopted binding")
	}
	var changed *AgentAssignmentChangedError
	if !errors.As(err, &changed) || !errors.Is(err, ErrAssignmentReassignmentRequired) {
		t.Fatalf("reassignment refresh error = %v, want AgentAssignmentChangedError", err)
	}
	if changed.Previous.CellID != "cell0" || changed.Current.CellID != "cell1" {
		t.Fatalf("reassignment snapshots = %#v -> %#v", changed.Previous, changed.Current)
	}
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Assignment.CellID != "cell0" || len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("reassignment was adopted or contacted a cell: state=%#v Hub/cell=%d/%d", persisted.Assignment, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
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
