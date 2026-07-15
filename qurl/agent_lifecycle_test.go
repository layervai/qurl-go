package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func allowAccountLifecycle() RegisterOption {
	return WithAllowedRegistrationKeyKinds(RegistrationKeyKindAccount)
}

// legacyEnrollmentRefreshForTest keeps coverage of forceRegistration, the
// enrollment-key recovery engine that RecoverAgentCredential still uses. It is
// intentionally test-only: the public ordinary refresh API must never accept or
// read an enrollment key.
func legacyEnrollmentRefreshForTest(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*AgentRuntimeBinding, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	cfg.applyLifecycleDefaultKeyPolicy()
	var privateKey []byte
	defer func() { wipeBytes(privateKey) }()
	state, err := withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadCompletedRegisteredState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		privateKey, err = decodeRuntimePrivateKey(state, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, false)
	})
	if err != nil {
		return nil, err
	}
	if state.Assignment == nil {
		state.Assignment = &AgentAssignment{
			AgentID:              state.AgentID,
			CellID:               "legacy-test",
			AssignmentGeneration: 1,
			EndpointRevision:     1,
			LeaseExpiresAt:       time.Now().Add(time.Hour),
			Endpoint: NHPUDPEndpoint{
				Host:               state.NHPPeer.Host,
				Port:               state.NHPPeer.Port,
				ServerPublicKeyB64: state.NHPPeer.PublicKeyB64,
			},
		}
	}
	binding := newAgentRuntimeBinding(state, privateKey)
	privateKey = nil
	return binding, nil
}

func TestAgentStateClone_IsolatesEveryMutableField(t *testing.T) {
	// Keep this list explicit: adding any non-scalar field to AgentState must fail
	// here until clone and this mutation test are extended together. The
	// mutations below prove the currently known fields do not alias the source.
	stateType := reflect.TypeOf(AgentState{})
	handledNames := []string{"RegisteredAt", "NHPPeer", "OTPRequestedAt", "Assignment"}
	handled := make(map[string]bool, len(handledNames))
	for _, name := range handledNames {
		handled[name] = false
	}
	for i := 0; i < stateType.NumField(); i++ {
		field := stateType.Field(i)
		switch field.Type.Kind() {
		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
			reflect.String:
			continue
		default:
			if _, ok := handled[field.Name]; !ok {
				t.Fatalf("AgentState field %s has non-scalar kind %s; update clone and its isolation test", field.Name, field.Type.Kind())
			}
			handled[field.Name] = true
		}
	}
	for _, name := range handledNames {
		if !handled[name] {
			t.Fatalf("AgentState clone guard names missing field %s; update the handled set", name)
		}
	}

	registeredAt := time.Unix(1_700_000_000, 0).UTC()
	requestedAt := registeredAt.Add(time.Minute)
	original := &AgentState{
		AgentID:        "agent-original",
		RegisteredAt:   &registeredAt,
		NHPPeer:        &NHPServerPeerInfo{Host: "peer-original.example.test"},
		OTPRequestedAt: &requestedAt,
		Assignment: &AgentAssignment{
			CellID:   "cell0",
			Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai"},
		},
	}
	cloned := original.clone()
	cloned.AgentID = "agent-cloned"
	*cloned.RegisteredAt = cloned.RegisteredAt.Add(time.Hour)
	cloned.NHPPeer.Host = "peer-cloned.example.test"
	*cloned.OTPRequestedAt = cloned.OTPRequestedAt.Add(time.Hour)
	cloned.Assignment.CellID = "cell9"
	cloned.Assignment.Endpoint.Host = "cell9.nhp.layerv.ai"

	if original.AgentID != "agent-original" ||
		!original.RegisteredAt.Equal(registeredAt) ||
		original.NHPPeer.Host != "peer-original.example.test" ||
		!original.OTPRequestedAt.Equal(requestedAt) ||
		original.Assignment.CellID != "cell0" ||
		original.Assignment.Endpoint.Host != "cell0.nhp.layerv.ai" {
		t.Fatalf("AgentState clone mutated source: %#v", original)
	}
}

func TestForcedRegistrationCredential_ErrorPathsReturnUnknownPath(t *testing.T) {
	cfg := &registerConfig{invalidConfigErr: ErrInvalidRegisterConfig, clock: time.Now}
	tests := []struct {
		name string
		info *registrationInfoResponse
		want error
	}{
		{
			name: "account key without email",
			info: &registrationInfoResponse{KeyKind: keyKindAccount},
			want: ErrNoAccountEmail,
		},
		{
			name: "unknown key kind",
			info: &registrationInfoResponse{KeyKind: "future-kind"},
			want: ErrInvalidRegisterConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, path, err := cfg.forcedRegistrationCredential(context.Background(), "unused", nil, nil, nil, tt.info)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if credential != "" || path != pathUnknown {
				t.Fatalf("credential/path = %q/%v, want empty/pathUnknown", credential, path)
			}
		})
	}

	t.Run("OTP provider error", func(t *testing.T) {
		providerErr := errors.New("provider unavailable")
		requestedAt := time.Now()
		cfg.otpProvider = func(context.Context) (string, error) { return "", providerErr }
		credential, path, err := cfg.forcedRegistrationCredential(
			context.Background(),
			"unused",
			nil,
			&AgentState{OTPRequestedAt: &requestedAt},
			&AgentState{},
			&registrationInfoResponse{KeyKind: keyKindAccount, MaskedEmail: "j***@example.test"},
		)
		if !errors.Is(err, providerErr) {
			t.Fatalf("error = %v, want provider error", err)
		}
		if credential != "" || path != pathUnknown {
			t.Fatalf("credential/path = %q/%v, want empty/pathUnknown", credential, path)
		}
	})
}

type countingAgentStateStore struct {
	inner  AgentStateStore
	loads  atomic.Int32
	onSave func(*AgentState)
}

type pointerTrackingAgentStateStore struct {
	inner          AgentStateStore
	lastLoaded     *AgentState
	savedCandidate *AgentState
}

func (s *pointerTrackingAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	state, err := s.inner.LoadAgentState(ctx)
	if err == nil {
		s.lastLoaded = state
	}
	return state, err
}

func (s *pointerTrackingAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	s.savedCandidate = state
	return s.inner.SaveAgentState(ctx, state)
}

func (s *countingAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	s.loads.Add(1)
	return s.inner.LoadAgentState(ctx)
}

func (s *countingAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	if err := s.inner.SaveAgentState(ctx, state); err != nil {
		return err
	}
	if s.onSave != nil {
		s.onSave(state)
	}
	return nil
}

func newFreshCountingRegisterHarness(t *testing.T) (*registerHarness, *countingAgentStateStore) {
	t.Helper()
	h := newRegisterHarness(t)
	counting := &countingAgentStateStore{
		inner: h.store,
		onSave: func(state *AgentState) {
			publicKey, err := base64.StdEncoding.Strict().DecodeString(state.PublicKeyB64)
			if err == nil {
				h.nhp.setExpectDevicePub(publicKey)
			}
		},
	}
	h.store = counting
	return h, counting
}

func TestOpenRegisteredAgent_ZeroNetworkIgnoresKnockPeer(t *testing.T) {
	cases := []struct {
		name string
		edit func(*AgentState)
	}{
		{name: "missing", edit: func(state *AgentState) { state.NHPPeer = nil }},
		{name: "malformed", edit: func(state *AgentState) {
			state.NHPPeer = &NHPServerPeerInfo{PublicKeyB64: "not-base64", Host: "", Port: -1}
		}},
		{name: "expired", edit: func(state *AgentState) {
			state.NHPPeer.ExpireTime = time.Now().Add(-time.Hour).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			state := h.loadState(t)
			tc.edit(state)
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save peer variant: %v", err)
			}

			var networkCalls atomic.Int32
			refusing := doerFunc(func(*http.Request) (*http.Response, error) {
				networkCalls.Add(1)
				return nil, errors.New("unexpected network call")
			})
			client, err := OpenRegisteredAgent(context.Background(), h.store,
				WithBaseURL("https://resources.example.test"),
				WithHTTPClient(refusing),
			)
			if err != nil {
				t.Fatalf("OpenRegisteredAgent: %v", err)
			}
			if client == nil {
				t.Fatal("OpenRegisteredAgent returned nil Client")
			}
			if networkCalls.Load() != 0 {
				t.Fatalf("OpenRegisteredAgent network calls = %d, want 0", networkCalls.Load())
			}
		})
	}
}

func TestOpenRegisteredAgentRuntime_OneLoadThroughFirstAuthorization(t *testing.T) {
	h := registeredHarness(t)
	counting := &countingAgentStateStore{inner: h.store}
	client, binding, err := OpenRegisteredAgentRuntime(context.Background(), counting,
		WithAgentClientBaseURL("https://resources.example.test"),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgentRuntime: %v", err)
	}
	defer binding.Destroy()
	if counting.loads.Load() != 1 {
		t.Fatalf("warm runtime store loads = %d, want 1", counting.loads.Load())
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
	if err != nil {
		t.Fatalf("new resource request: %v", err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize from primed runtime client: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer lv_device_secret" {
		t.Fatalf("primed Authorization = %q", got)
	}
	if counting.loads.Load() != 1 {
		t.Fatalf("first authorization reloaded store: loads = %d, want 1", counting.loads.Load())
	}
	privateKey := binding.TakeDeviceStaticPrivateKey()
	if len(privateKey) != 32 {
		t.Fatalf("warm runtime private key length = %d, want 32", len(privateKey))
	}
	wipeBytes(privateKey)
}

func TestAgentRuntimeBinding_NilPointerFormattingDoesNotPanic(t *testing.T) {
	var binding *AgentRuntimeBinding
	formatted := map[string]string{
		"%v":  fmt.Sprintf("%v", binding),
		"%+v": fmt.Sprintf("%+v", binding),
		"%#v": fmt.Sprintf("%#v", binding),
	}
	for format, got := range formatted {
		if strings.Contains(got, "%!") || strings.Contains(got, "deviceStaticPrivateKey") {
			t.Fatalf("nil runtime binding %s formatting failed closed: %s", format, got)
		}
	}
}

func TestAgentRuntimeBinding_AccidentalCopySharesSynchronizedOneShotKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x5a}, 32)
	binding := &AgentRuntimeBinding{
		deviceStaticPrivateKey: newAgentRuntimePrivateKey(bytes.Clone(want)),
	}
	copied := *binding
	start := make(chan struct{})
	results := make(chan []byte, 2)
	for _, candidate := range []*AgentRuntimeBinding{binding, &copied} {
		go func(candidate *AgentRuntimeBinding) {
			<-start
			results <- candidate.TakeDeviceStaticPrivateKey()
		}(candidate)
	}
	close(start)
	first, second := <-results, <-results
	if first == nil {
		first, second = second, first
	}
	if !bytes.Equal(first, want) || second != nil {
		t.Fatalf("copy one-shot results = %x / %x, want key / nil", first, second)
	}
	if binding.deviceStaticPrivateKey.cleanup != nil {
		t.Fatal("one-shot transfer left the best-effort runtime cleanup armed")
	}
	wipeBytes(first)
	binding.Destroy()
	copied.Destroy()
}

func TestEnrollmentRefreshLegacy_CustomStoreReceivesClonedCandidate(t *testing.T) {
	h := registeredHarness(t)
	tracking := &pointerTrackingAgentStateStore{inner: h.store}
	binding, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", tracking, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	binding.Destroy()
	if tracking.lastLoaded == nil || tracking.savedCandidate == nil {
		t.Fatalf("custom store pointers = loaded %p, saved %p", tracking.lastLoaded, tracking.savedCandidate)
	}
	if tracking.lastLoaded == tracking.savedCandidate {
		t.Fatal("lifecycle save reused the custom store's loaded pointer; want an isolated candidate snapshot")
	}
}

func TestRegisterAgentRuntime_FreshRegistrationAddsNoStoreReload(t *testing.T) {
	h, counting := newFreshCountingRegisterHarness(t)
	h.svc.keyID = "key_enrollment01"
	udpServer := startNativeRegistrationUDPServer(t, h.nhp)
	assignmentRequests := installRuntimeAssignmentHandler(t, h, udpServer.port())
	runtimeOpts := runtimeUDPOptions()
	runtimeOpts = append(runtimeOpts,
		WithAgentClientBaseURL(h.apiSrv.URL),
		WithAgentClientHTTPClient(h.apiSrv.Client()),
		WithRegisterHostname("connector-host"),
		WithRegisterVersion("v0.1.0"),
		WithTakeover(),
	)

	client, binding, err := RegisterAgentRuntime(context.Background(), "lv_enroll", h.store, h.registerOpts(runtimeOpts...)...)
	if err != nil {
		t.Fatalf("RegisterAgentRuntime: %v", err)
	}
	defer binding.Destroy()
	if counting.loads.Load() != 2 {
		t.Fatalf("fresh runtime state-machine loads = %d, want 2", counting.loads.Load())
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
	if err != nil {
		t.Fatalf("new resource request: %v", err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize from fresh primed client: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer lv_device_secret" {
		t.Fatalf("fresh primed Authorization = %q", got)
	}
	if counting.loads.Load() != 2 {
		t.Fatalf("fresh first authorization added store load: loads = %d, want 2", counting.loads.Load())
	}
	requests := assignmentRequests.snapshot()
	if len(requests) != 2 {
		t.Fatalf("assignment requests = %#v, want initial + post-mint confirmation", requests)
	}
	if requests[0].Authorization != "Bearer lv_enroll" || requests[1].Authorization != "Bearer lv_device_secret" {
		t.Fatalf("assignment credentials = %q / %q, want enrollment then newly minted device key", requests[0].Authorization, requests[1].Authorization)
	}
	if h.nhp.regCount() != 1 {
		t.Fatalf("native REG count = %d, want 1", h.nhp.regCount())
	}
	h.nhp.mu.Lock()
	registration := h.nhp.regs[0]
	h.nhp.mu.Unlock()
	if registration.UsrData.Hostname != "connector-host" || registration.UsrData.Version != "v0.1.0" || !registration.UsrData.Takeover {
		t.Fatalf("native enrollment REG user data = %#v", registration.UsrData)
	}
	privateKey := binding.TakeDeviceStaticPrivateKey()
	if len(privateKey) != 32 {
		t.Fatalf("fresh runtime private key length = %d, want 32", len(privateKey))
	}
	wipeBytes(privateKey)
}

func TestAgentRuntime_PrimedCredentialExpiresOnInjectedClock(t *testing.T) {
	tests := []struct {
		name string
		open func(context.Context, AgentStateStore, func() time.Time) (*Client, *AgentRuntimeBinding, error)
	}{
		{name: "register runtime", open: func(ctx context.Context, store AgentStateStore, now func() time.Time) (*Client, *AgentRuntimeBinding, error) {
			return RegisterAgentRuntime(ctx, "unused-on-fast-path", store, withClock(now))
		}},
		{name: "open runtime", open: func(ctx context.Context, store AgentStateStore, now func() time.Time) (*Client, *AgentRuntimeBinding, error) {
			return openRegisteredAgentRuntime(ctx, store, now)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			counting := &countingAgentStateStore{inner: h.store}
			now := time.Unix(1_700_000_000, 0).UTC()
			client, binding, err := tc.open(context.Background(), counting, func() time.Time { return now })
			if err != nil {
				t.Fatalf("open runtime: %v", err)
			}
			binding.Destroy()
			if counting.loads.Load() != 1 {
				t.Fatalf("runtime fast-path loads = %d, want 1", counting.loads.Load())
			}

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
			if err != nil {
				t.Fatalf("new first resource request: %v", err)
			}
			if err := client.credentials.Authorize(context.Background(), req); err != nil {
				t.Fatalf("authorize primed credential: %v", err)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer lv_device_secret" {
				t.Fatalf("initial primed Authorization = %q", got)
			}
			if counting.loads.Load() != 1 {
				t.Fatalf("first authorization reloaded store: loads = %d, want 1", counting.loads.Load())
			}

			state := h.loadState(t)
			state.DeviceAPIKey = "lv_device_rotated_after_prime"
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save subsequent credential rotation: %v", err)
			}
			now = now.Add(storeCredentialCacheTTL + time.Second)
			req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
			if err != nil {
				t.Fatalf("new post-TTL resource request: %v", err)
			}
			if err := client.credentials.Authorize(context.Background(), req); err != nil {
				t.Fatalf("authorize after primed TTL: %v", err)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer lv_device_rotated_after_prime" {
				t.Fatalf("post-TTL Authorization = %q", got)
			}
			if counting.loads.Load() != 2 {
				t.Fatalf("post-TTL store loads = %d, want 2", counting.loads.Load())
			}
		})
	}
}

func TestRegisterAgent_LegacyClientRemainsLazyStoreBacked(t *testing.T) {
	h, counting := newFreshCountingRegisterHarness(t)
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if counting.loads.Load() != 2 {
		t.Fatalf("legacy registration state-machine loads = %d, want 2", counting.loads.Load())
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
	if err != nil {
		t.Fatalf("new resource request: %v", err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize from legacy client: %v", err)
	}
	if counting.loads.Load() != 3 {
		t.Fatalf("legacy first authorization loads = %d, want 3", counting.loads.Load())
	}
}

func TestRecoverAgentCredential_PrimesClientFromCommittedState(t *testing.T) {
	h := registeredHarness(t)
	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	counting := &countingAgentStateStore{inner: h.store}

	client, err := RecoverAgentCredential(context.Background(), "lv_enroll", counting, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	if counting.loads.Load() != 1 {
		t.Fatalf("recovery state-machine loads = %d, want 1", counting.loads.Load())
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
	if err != nil {
		t.Fatalf("new resource request: %v", err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize from recovered primed client: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer lv_device_recovered" {
		t.Fatalf("recovered primed Authorization = %q", got)
	}
	if counting.loads.Load() != 1 {
		t.Fatalf("recovery first authorization added store load: loads = %d, want 1", counting.loads.Load())
	}
}

func TestOpenRegisteredAgentRuntime_InvalidKnockStateFailsInOneLoadWithoutNetwork(t *testing.T) {
	tests := []struct {
		name string
		edit func(*AgentState)
	}{
		{name: "missing assignment", edit: func(state *AgentState) { state.Assignment = nil }},
		{name: "malformed assignment server key", edit: func(state *AgentState) { state.Assignment.Endpoint.ServerPublicKeyB64 = "not-base64" }},
		{name: "expired assignment", edit: func(state *AgentState) { state.Assignment.LeaseExpiresAt = time.Now().Add(-time.Hour) }},
		{name: "missing device key id", edit: func(state *AgentState) { state.DeviceAPIKeyID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			state := h.loadState(t)
			tc.edit(state)
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save malformed runtime state: %v", err)
			}
			counting := &countingAgentStateStore{inner: h.store}
			var networkCalls atomic.Int32
			refusing := doerFunc(func(*http.Request) (*http.Response, error) {
				networkCalls.Add(1)
				return nil, errors.New("unexpected network call")
			})

			client, binding, err := OpenRegisteredAgentRuntime(context.Background(), counting, WithAgentClientHTTPClient(refusing))
			if client != nil || binding != nil || !errors.Is(err, ErrInvalidClientConfig) {
				t.Fatalf("invalid runtime open = client %v, binding %v, error %v", client, binding, err)
			}
			if counting.loads.Load() != 1 || networkCalls.Load() != 0 {
				t.Fatalf("invalid runtime loads/network = %d/%d, want 1/0", counting.loads.Load(), networkCalls.Load())
			}
		})
	}
}

func TestAgentLifecycle_MissingCredentialRequiresExplicitRecoveryWithoutNetwork(t *testing.T) {
	h := registeredHarness(t)
	state := h.loadState(t)
	state.DeviceAPIKey = ""
	if err := h.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save state without credential: %v", err)
	}

	var networkCalls atomic.Int32
	refusing := doerFunc(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, errors.New("unexpected network call")
	})
	assertRecoveryRequired := func(t *testing.T, err error) {
		t.Helper()
		var recoveryErr *CredentialRecoveryRequiredError
		if !errors.As(err, &recoveryErr) || !errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, ErrDeviceCredentialMissing) {
			t.Fatalf("want typed credential recovery error, got %v", err)
		}
		if recoveryErr.DeviceID != state.AgentID {
			t.Fatalf("recovery device id = %q, want %q", recoveryErr.DeviceID, state.AgentID)
		}
	}

	client, err := OpenRegisteredAgent(context.Background(), h.store,
		WithBaseURL("https://resources.example.test"),
		WithHTTPClient(refusing),
	)
	if client != nil {
		t.Fatal("OpenRegisteredAgent returned a Client without a credential")
	}
	assertRecoveryRequired(t, err)

	refreshed, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store,
		WithRegisterBaseURL(h.apiSrv.URL),
		WithRegisterHTTPClient(refusing),
	)
	if refreshed != nil {
		t.Fatal("RefreshAgentRegistration returned state without a credential")
	}
	assertRecoveryRequired(t, err)
	if networkCalls.Load() != 0 {
		t.Fatalf("missing-credential lifecycle network calls = %d, want 0", networkCalls.Load())
	}
}

func TestAgentLifecycle_MalformedPersistedCredentialFailsClosedWithoutNetwork(t *testing.T) {
	for _, credential := range []string{" lv_device_secret", "lv_device_secret ", "lv_device\nsecret"} {
		t.Run(fmt.Sprintf("%q", credential), func(t *testing.T) {
			h := registeredHarness(t)
			state := h.loadState(t)
			state.DeviceAPIKey = credential
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save malformed credential: %v", err)
			}

			var networkCalls atomic.Int32
			refusing := doerFunc(func(*http.Request) (*http.Response, error) {
				networkCalls.Add(1)
				return nil, errors.New("unexpected network call")
			})
			if client, err := OpenRegisteredAgent(context.Background(), h.store,
				WithBaseURL("https://resources.example.test"),
				WithHTTPClient(refusing),
			); client != nil || !errors.Is(err, ErrInvalidClientConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("OpenRegisteredAgent malformed credential = client %v, error %v", client, err)
			}
			if client, err := RegisterAgent(context.Background(), "lv_enroll", h.store,
				WithRegisterBaseURL(h.apiSrv.URL),
				WithRegisterHTTPClient(refusing),
			); client != nil || !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("RegisterAgent malformed credential = client %v, error %v", client, err)
			}
			if client, binding, err := OpenRegisteredAgentRuntime(context.Background(), h.store,
				WithAgentClientBaseURL("https://resources.example.test"),
				WithAgentClientHTTPClient(refusing),
			); client != nil || binding != nil || !errors.Is(err, ErrInvalidClientConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("OpenRegisteredAgentRuntime malformed credential = client %v, binding %v, error %v", client, binding, err)
			}
			if client, binding, err := RegisterAgentRuntime(context.Background(), "lv_enroll", h.store,
				WithRegisterBaseURL(h.apiSrv.URL),
				WithRegisterHTTPClient(refusing),
			); client != nil || binding != nil || !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("RegisterAgentRuntime malformed credential = client %v, binding %v, error %v", client, binding, err)
			}
			if refreshed, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store,
				WithRegisterBaseURL(h.apiSrv.URL),
				WithRegisterHTTPClient(refusing),
			); refreshed != nil || !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("RefreshAgentRegistration malformed credential = state %v, error %v", refreshed, err)
			}

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			provider := &storeCredentialProvider{store: h.store}
			if err := provider.Authorize(context.Background(), req); !errors.Is(err, ErrInvalidClientConfig) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("store credential provider error = %v, want invalid-config recovery-required", err)
			}
			if got := req.Header.Get("Authorization"); got != "" {
				t.Fatalf("malformed persisted credential set Authorization = %q", got)
			}
			if networkCalls.Load() != 0 {
				t.Fatalf("malformed-credential network calls = %d, want 0", networkCalls.Load())
			}
		})
	}
}

func TestEnrollmentRefreshLegacy_InvalidPrivateKeyFailsBeforeNetworkOrMutation(t *testing.T) {
	h := registeredHarness(t)
	state := h.loadState(t)
	state.PrivateKeyB64 = "AAAA!partial-secret"
	if err := h.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save invalid private key: %v", err)
	}
	before := h.loadState(t)
	var networkCalls atomic.Int32
	refusing := doerFunc(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, errors.New("unexpected network call")
	})

	binding, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store,
		WithRegisterHTTPClient(refusing),
	)
	if binding != nil || !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("invalid private key refresh = binding %v, error %v; want invalid config", binding, err)
	}
	if networkCalls.Load() != 0 {
		t.Fatalf("invalid private key refresh network calls = %d, want 0", networkCalls.Load())
	}
	after := h.loadState(t)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("invalid private key refresh mutated state: before=%#v after=%#v", before, after)
	}
}

func TestAgentLifecycle_RejectsNonExactEnrollmentKeysAndAppendBreakingOrigins(t *testing.T) {
	h := registeredHarness(t)
	var networkCalls atomic.Int32
	refusing := doerFunc(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, errors.New("unexpected network call")
	})
	for _, key := range []string{" lv_enroll", "lv_enroll ", "lv_enroll\n"} {
		if state, err := legacyEnrollmentRefreshForTest(context.Background(), key, h.store, WithRegisterHTTPClient(refusing)); state != nil || !errors.Is(err, ErrInvalidRegisterConfig) {
			t.Fatalf("RefreshAgentRegistration key %q = state %v, error %v", key, state, err)
		}
		if client, err := RecoverAgentCredential(context.Background(), key, h.store, WithRegisterHTTPClient(refusing)); client != nil || !errors.Is(err, ErrInvalidRegisterConfig) {
			t.Fatalf("RecoverAgentCredential key %q = client %v, error %v", key, client, err)
		}
	}
	for _, rawURL := range []string{"https://resources.example.test/prefix?wrong=1", "https://resources.example.test/prefix#wrong"} {
		if client, err := OpenRegisteredAgent(context.Background(), h.store, WithBaseURL(rawURL), WithHTTPClient(refusing)); client != nil || !errors.Is(err, ErrInvalidClientConfig) {
			t.Fatalf("OpenRegisteredAgent URL %q = client %v, error %v", rawURL, client, err)
		}
	}
	opened, err := OpenRegisteredAgent(context.Background(), h.store,
		WithBaseURL("https://resources.example.test/custom/prefix/"),
		WithHTTPClient(refusing),
	)
	if err != nil || opened == nil {
		t.Fatalf("OpenRegisteredAgent path prefix = client %v, error %v", opened, err)
	}
	if opened.baseURL != "https://resources.example.test/custom/prefix" {
		t.Fatalf("OpenRegisteredAgent path prefix = %q", opened.baseURL)
	}
	if networkCalls.Load() != 0 {
		t.Fatalf("invalid lifecycle input network calls = %d, want 0", networkCalls.Load())
	}
}

func TestOpenRegisteredAgent_RejectsMixedResourceOptionFamilies(t *testing.T) {
	h := registeredHarness(t)
	transport := doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network call")
	})
	tests := []struct {
		name string
		opts []ClientOption
		want string
	}{
		{
			name: "generic URL then agent URL",
			opts: []ClientOption{WithBaseURL("https://resources.example.test"), WithAgentClientBaseURL("https://resources.example.test")},
			want: "WithBaseURL or WithAgentClientBaseURL",
		},
		{
			name: "agent URL then generic URL",
			opts: []ClientOption{WithAgentClientBaseURL("https://resources.example.test"), WithBaseURL("https://resources.example.test")},
			want: "WithBaseURL or WithAgentClientBaseURL",
		},
		{
			name: "generic transport then agent transport",
			opts: []ClientOption{WithHTTPClient(transport), WithAgentClientHTTPClient(transport)},
			want: "WithHTTPClient or WithAgentClientHTTPClient",
		},
		{
			name: "agent transport then generic transport",
			opts: []ClientOption{WithAgentClientHTTPClient(transport), WithHTTPClient(transport)},
			want: "WithHTTPClient or WithAgentClientHTTPClient",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := OpenRegisteredAgent(context.Background(), h.store, tc.opts...)
			if client != nil || !errors.Is(err, ErrInvalidClientConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("mixed resource options = client %v, error %v; want invalid config naming %q", client, err, tc.want)
			}
		})
	}
}

func TestEnrollmentRefreshLegacy_RotatesBindingPreservesCredentialAndSkipsCompletion(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	if _, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	before := h.loadState(t)
	before.NHPPeer = nil
	before.RelayURL = ""
	if err := h.store.SaveAgentState(context.Background(), before); err != nil {
		t.Fatalf("save lost binding: %v", err)
	}

	rotated := newFakeNHPServer(t)
	rotatedRelay := httptest.NewServer(rotated.handler())
	t.Cleanup(rotatedRelay.Close)
	h.svc.mu.Lock()
	h.svc.nhp = rotated
	h.svc.keyID = "key_rotated"
	h.svc.mu.Unlock()
	inner := h.svc.handler(rotatedRelay.URL)
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info" {
			state, err := h.store.LoadAgentState(r.Context())
			if err != nil {
				t.Errorf("load state for rotated peer: %v", err)
			} else {
				pub, decErr := base64.StdEncoding.DecodeString(state.PublicKeyB64)
				if decErr != nil {
					t.Errorf("decode device pub: %v", decErr)
				} else {
					rotated.setExpectDevicePub(pub)
				}
			}
		}
		inner.ServeHTTP(w, r)
	}))

	completeBefore := h.svc.completionCalls.Load()
	refreshed, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	if _, exposed := reflect.TypeOf(*refreshed).FieldByName("DeviceAPIKey"); exposed {
		t.Fatal("AgentRuntimeBinding exposes DeviceAPIKey")
	}
	encodedBinding, err := json.Marshal(refreshed)
	if err != nil {
		t.Fatalf("marshal runtime binding: %v", err)
	}
	if bytes.Contains(encodedBinding, []byte(before.DeviceAPIKey)) || bytes.Contains(encodedBinding, []byte(before.PrivateKeyB64)) {
		t.Fatalf("serialized runtime binding contains persisted secret: %s", encodedBinding)
	}
	wantPrivateKey, err := base64.StdEncoding.Strict().DecodeString(before.PrivateKeyB64)
	if err != nil {
		t.Fatalf("decode prior private key: %v", err)
	}
	formattedBindings := map[string]string{
		"pointer %v":  fmt.Sprintf("%v", refreshed),
		"pointer %+v": fmt.Sprintf("%+v", refreshed),
		"pointer %#v": fmt.Sprintf("%#v", refreshed),
		"value %v":    fmt.Sprintf("%v", *refreshed),
		"value %+v":   fmt.Sprintf("%+v", *refreshed),
		"value %#v":   fmt.Sprintf("%#v", *refreshed),
	}
	privateKeyDecimal := fmt.Sprintf("%v", wantPrivateKey)
	privateKeyHex := fmt.Sprintf("%x", wantPrivateKey)
	for label, formattedBinding := range formattedBindings {
		if !strings.Contains(formattedBinding, "[REDACTED]") ||
			strings.Contains(formattedBinding, "deviceStaticPrivateKey") ||
			strings.Contains(formattedBinding, before.PrivateKeyB64) ||
			strings.Contains(formattedBinding, privateKeyDecimal) ||
			strings.Contains(formattedBinding, privateKeyHex) {
			t.Fatalf("%s runtime binding is not redacted: %s", label, formattedBinding)
		}
	}
	privateKey := refreshed.TakeDeviceStaticPrivateKey()
	if !reflect.DeepEqual(privateKey, wantPrivateKey) {
		t.Fatal("runtime binding private key differs from persisted identity")
	}
	if second := refreshed.TakeDeviceStaticPrivateKey(); second != nil {
		t.Fatalf("second private-key transfer = %x, want nil", second)
	}
	wipeBytes(privateKey)
	wipeBytes(wantPrivateKey)
	refreshed.Destroy()
	if got := refreshed.TakeDeviceStaticPrivateKey(); got != nil {
		t.Fatalf("private key after Destroy = %x, want nil", got)
	}
	persisted := h.loadState(t)
	if persisted.DeviceAPIKey != before.DeviceAPIKey {
		t.Fatalf("DeviceAPIKey changed during refresh")
	}
	if !refreshed.RegisteredAt.Equal(*before.RegisteredAt) {
		t.Fatalf("RegisteredAt changed during refresh: before=%v after=%v", before.RegisteredAt, refreshed.RegisteredAt)
	}
	if persisted.NHPPeer == nil ||
		persisted.NHPPeer.PublicKeyB64 != rotated.serverPubB64() ||
		persisted.RelayURL != rotatedRelay.URL ||
		persisted.KeyID != "key_rotated" {
		t.Fatalf("rotated enrollment binding = peer %#v, relay %q, key id %q", persisted.NHPPeer, persisted.RelayURL, persisted.KeyID)
	}
	if h.svc.completionCalls.Load() != completeBefore {
		t.Fatal("binding refresh called registration completion")
	}
	if rotated.regCount() != 1 {
		t.Fatalf("rotated REG count = %d, want 1", rotated.regCount())
	}
}

func TestEnrollmentRefreshLegacy_SaveFailureDoesNotCommitNewBinding(t *testing.T) {
	h := registeredHarness(t)
	before := h.loadState(t)
	h.svc.mu.Lock()
	h.svc.keyID = "key_new_binding"
	h.svc.mu.Unlock()
	saveFailure := errors.New("injected refresh save failure")
	failing := &failingSaveStore{
		inner: h.store,
		failWhen: func(state *AgentState) bool {
			return state.KeyID == "key_new_binding"
		},
		failErr:   saveFailure,
		failsLeft: 1,
	}
	h.store = failing

	_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrAgentBindingPersistence) || !errors.Is(err, saveFailure) || !strings.Contains(err.Error(), "persist refreshed binding") {
		t.Fatalf("refresh save failure lost context/cause: %v", err)
	}
	if errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("pre-completion refresh save failure misclassified as mint ambiguity: %v", err)
	}
	after, err := failing.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load state after failed refresh: %v", err)
	}
	if after.KeyID != before.KeyID || after.RelayURL != before.RelayURL || after.DeviceAPIKey != before.DeviceAPIKey {
		t.Fatalf("failed refresh committed partial metadata: before=%#v after=%#v", before, after)
	}
}

func TestRegisterAgent_RegisterOriginDoesNotRetargetReturnedClient(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if client.baseURL != defaultAPIBaseURL {
		t.Fatalf("returned Client baseURL = %q, want independent default %q", client.baseURL, defaultAPIBaseURL)
	}
}

func TestEnrollmentRefreshLegacy_TakeoverCookieAndRateLimit(t *testing.T) {
	t.Run("takeover", func(t *testing.T) {
		h := registeredHarness(t)
		if _, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts(WithTakeover())...); err != nil {
			t.Fatalf("RefreshAgentRegistration: %v", err)
		}
		h.nhp.mu.Lock()
		last := h.nhp.regs[len(h.nhp.regs)-1]
		h.nhp.mu.Unlock()
		if !last.UsrData.Takeover {
			t.Fatal("forced REG did not carry takeover=true")
		}
	})

	t.Run("cookie challenge", func(t *testing.T) {
		h := registeredHarness(t)
		h.nhp.mu.Lock()
		h.nhp.replyREGWithCOK = true
		h.nhp.mu.Unlock()
		_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRetryLater) {
			t.Fatalf("want ErrRegistrationRetryLater, got %v", err)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		h := registeredHarness(t)
		h.nhp.mu.Lock()
		h.nhp.rakErrCode = rakRateLimited
		h.nhp.mu.Unlock()
		_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRateLimited) {
			t.Fatalf("want ErrRegistrationRateLimited, got %v", err)
		}
	})

	t.Run("registration HTTP rate limited", func(t *testing.T) {
		h := registeredHarness(t)
		regsBefore := h.nhp.regCount()
		h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":{"code":"rate_limited","detail":"slow down"}}`)
		}))
		_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRateLimited) {
			t.Fatalf("want ErrRegistrationRateLimited, got %v", err)
		}
		if h.nhp.regCount() != regsBefore {
			t.Fatal("HTTP preflight rate limit still sent REG")
		}
	})
}

func TestRegisterAgent_KeyKindPolicyRejectsBeforeOTPOrREG(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_account", h.store, h.registerOpts(
		WithAllowedRegistrationKeyKinds(RegistrationKeyKindBootstrap),
	)...)
	if !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
		t.Fatalf("want ErrRegistrationKeyKindDisallowed, got %v", err)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("typed disallowed error = %#v", disallowed)
	}
	if h.nhp.otpCount() != 0 || h.nhp.regCount() != 0 {
		t.Fatalf("policy rejection made NHP side effects: otp=%d reg=%d", h.nhp.otpCount(), h.nhp.regCount())
	}
	state := h.loadState(t)
	if state.OTPRequestedAt != nil {
		t.Fatalf("policy rejection mutated OTP-pending state: %#v", state.OTPRequestedAt)
	}
}

func TestAgentLifecycle_DefaultKeyPolicyRejectsAccountBeforeOTPOrREG(t *testing.T) {
	tests := []struct {
		name string
		run  func(*registerHarness) error
	}{
		{name: "refresh", run: func(h *registerHarness) error {
			_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts()...)
			return err
		}},
		{name: "recovery", run: func(h *registerHarness) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts()...)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			h.svc.mu.Lock()
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@example.test"
			h.svc.mu.Unlock()
			otpBefore := h.nhp.otpCount()
			regsBefore := h.nhp.regCount()

			err := tc.run(h)
			var disallowed *RegistrationKeyKindDisallowedError
			if !errors.As(err, &disallowed) || !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
				t.Fatalf("default account lifecycle error = %v, want typed disallowed kind", err)
			}
			if disallowed.Kind != RegistrationKeyKindAccount || !reflect.DeepEqual(disallowed.Allowed, []RegistrationKeyKind{RegistrationKeyKindBootstrap}) {
				t.Fatalf("default account lifecycle policy = %#v", disallowed)
			}
			if h.nhp.otpCount() != otpBefore || h.nhp.regCount() != regsBefore {
				t.Fatalf("default policy rejection side effects: OTP %d->%d, REG %d->%d", otpBefore, h.nhp.otpCount(), regsBefore, h.nhp.regCount())
			}
		})
	}
}

func TestEnrollmentRefreshLegacy_AccountOTPResumeDoesNotComplete(t *testing.T) {
	h := registeredHarness(t)
	h.svc.mu.Lock()
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.svc.mu.Unlock()
	completeBefore := h.svc.completionCalls.Load()

	_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle())...)
	var pending *OTPPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("first account refresh: want OTPPendingError, got %v", err)
	}
	if h.nhp.otpCount() != 1 || h.nhp.regCount() != 1 { // initial bootstrap REG only
		t.Fatalf("first account refresh side effects: otp=%d regs=%d", h.nhp.otpCount(), h.nhp.regCount())
	}

	h.nhp.mu.Lock()
	h.nhp.expectCredential = "424242"
	h.nhp.mu.Unlock()
	binding, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("424242"))...)
	if err != nil {
		t.Fatalf("account refresh resume: %v", err)
	}
	binding.Destroy()
	if key := binding.TakeDeviceStaticPrivateKey(); key != nil {
		t.Fatalf("destroyed binding retained private key: %x", key)
	}
	if state := h.loadState(t); state.DeviceAPIKey != "lv_device_secret" {
		t.Fatal("account binding refresh replaced device credential")
	}
	if h.svc.completionCalls.Load() != completeBefore {
		t.Fatal("account binding refresh called completion")
	}
}

func TestAgentLifecycle_FreshAccountLiteralOTPDispatchesThenPauses(t *testing.T) {
	tests := []struct {
		name string
		run  func(*registerHarness) error
	}{
		{name: "refresh", run: func(h *registerHarness) error {
			_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("stale-literal"))...)
			return err
		}},
		{name: "recovery", run: func(h *registerHarness) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("stale-literal"))...)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			h.svc.mu.Lock()
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@example.test"
			h.svc.mu.Unlock()
			regsBefore := h.nhp.regCount()
			completionBefore := h.svc.completionCalls.Load()

			err := tc.run(h)
			var pending *OTPPendingError
			if !errors.As(err, &pending) || !errors.Is(err, ErrOTPPending) {
				t.Fatalf("fresh account literal = %v, want OTP pending", err)
			}
			if !strings.Contains(err.Error(), "same qurl operation") || strings.Contains(err.Error(), "qurl.RegisterAgent") {
				t.Fatalf("pending guidance is not lifecycle-safe: %v", err)
			}
			if h.nhp.otpCount() != 1 || h.nhp.regCount() != regsBefore {
				t.Fatalf("fresh literal side effects: otp=%d regs=%d, want 1/%d", h.nhp.otpCount(), h.nhp.regCount(), regsBefore)
			}
			if h.svc.completionCalls.Load() != completionBefore {
				t.Fatal("fresh literal called completion before OTP resume")
			}
			state := h.loadState(t)
			if state.OTPRequestedAt == nil || state.RegisteredAt == nil || state.DeviceAPIKey != "lv_device_secret" {
				t.Fatalf("fresh literal persisted more than the OTP marker: %#v", state)
			}
		})
	}
}

func TestRecoverAgentCredential_AccountLiteralResumesAfterPending(t *testing.T) {
	h := registeredHarness(t)
	h.svc.mu.Lock()
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	if _, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("stale-literal"))...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("fresh recovery literal = %v, want OTP pending", err)
	}
	h.nhp.mu.Lock()
	h.nhp.expectCredential = "424242"
	h.nhp.mu.Unlock()
	regsBefore := h.nhp.regCount()
	completionBefore := h.svc.completionCalls.Load()

	client, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("424242"))...)
	if err != nil || client == nil {
		t.Fatalf("account recovery resume = client %v, error %v", client, err)
	}
	if h.nhp.regCount() != regsBefore+1 || h.svc.completionCalls.Load() != completionBefore+1 {
		t.Fatalf("recovery resume REG/completion = %d/%d, want %d/%d", h.nhp.regCount(), h.svc.completionCalls.Load(), regsBefore+1, completionBefore+1)
	}
	state := h.loadState(t)
	if state.OTPRequestedAt != nil || state.DeviceAPIKey != "lv_device_recovered" {
		t.Fatalf("recovery resume did not commit replacement: %#v", state)
	}
}

func TestRecoverAgentCredential_AccountReREGAfterAbandonedRAK(t *testing.T) {
	ctx := context.Background()
	h := registeredHarness(t)
	h.svc.mu.Lock()
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	if _, err := RecoverAgentCredential(ctx, "lv_account", h.store, h.registerOpts(allowAccountLifecycle())...); !errors.Is(err, ErrOTPPending) {
		t.Fatalf("account recovery phase 1 = %v, want OTP pending", err)
	}
	h.nhp.mu.Lock()
	h.nhp.expectCredential = "424242"
	h.nhp.mu.Unlock()

	opts := h.registerOpts(allowAccountLifecycle(), WithOTP("424242"))
	cfg, err := validateRegisterInputs(ctx, "lv_account", h.store, opts)
	if err != nil {
		t.Fatalf("validate recovery inputs: %v", err)
	}
	cfg.applyLifecycleDefaultKeyPolicy()
	state := h.loadState(t)
	info, peer, relayURL, err := cfg.preflight(ctx, "lv_account")
	if err != nil {
		t.Fatalf("preflight abandoned recovery: %v", err)
	}
	state.NHPPeer = peer
	state.RelayURL = relayURL
	state.KeyID = info.KeyID
	if err := cfg.registerExchangeChecked(ctx, state, peer, relayURL, "424242", pathAccount); err != nil {
		t.Fatalf("simulate successful RAK before abandoned completion: %v", err)
	}
	regsAfterAbandonedRAK := h.nhp.regCount()
	completionsBeforeRetry := h.svc.completionCalls.Load()

	client, err := RecoverAgentCredential(ctx, "lv_account", h.store, opts...)
	if err != nil || client == nil {
		t.Fatalf("recovery after abandoned RAK = client %v, error %v", client, err)
	}
	if h.nhp.regCount() != regsAfterAbandonedRAK+1 {
		t.Fatalf("recovery did not re-REG after abandoned RAK: regs = %d, want %d", h.nhp.regCount(), regsAfterAbandonedRAK+1)
	}
	if h.svc.completionCalls.Load() != completionsBeforeRetry+1 {
		t.Fatalf("recovery completion calls = %d, want %d", h.svc.completionCalls.Load(), completionsBeforeRetry+1)
	}
	if state := h.loadState(t); state.DeviceAPIKey != "lv_device_recovered" || state.OTPRequestedAt != nil {
		t.Fatalf("re-REG recovery did not commit replacement: %#v", state)
	}
}

func TestAgentLifecycle_FreshAccountOTPProviderCompletesInOneCall(t *testing.T) {
	tests := []struct {
		name                string
		wantCompletionDelta int32
		run                 func(*registerHarness, RegisterOption) error
	}{
		{name: "refresh", run: func(h *registerHarness, provider RegisterOption) error {
			_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), provider)...)
			return err
		}},
		{name: "recovery", wantCompletionDelta: 1, run: func(h *registerHarness, provider RegisterOption) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), provider)...)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			h.svc.mu.Lock()
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@example.test"
			h.svc.deviceAPIKey = "lv_device_provider"
			h.svc.mu.Unlock()
			h.nhp.mu.Lock()
			h.nhp.expectCredential = "provider-code"
			h.nhp.mu.Unlock()
			regsBefore := h.nhp.regCount()
			completionBefore := h.svc.completionCalls.Load()
			var providerCalls atomic.Int32
			provider := WithOTPProvider(func(context.Context) (string, error) {
				providerCalls.Add(1)
				return "provider-code", nil
			})

			if err := tc.run(h, provider); err != nil {
				t.Fatalf("fresh provider lifecycle: %v", err)
			}
			if providerCalls.Load() != 1 || h.nhp.otpCount() != 1 || h.nhp.regCount() != regsBefore+1 {
				t.Fatalf("provider/OTP/REG = %d/%d/%d, want 1/1/%d", providerCalls.Load(), h.nhp.otpCount(), h.nhp.regCount(), regsBefore+1)
			}
			if h.svc.completionCalls.Load() != completionBefore+tc.wantCompletionDelta {
				t.Fatalf("completion calls = %d, want %d", h.svc.completionCalls.Load(), completionBefore+tc.wantCompletionDelta)
			}
			if state := h.loadState(t); state.OTPRequestedAt != nil {
				t.Fatalf("provider flow left OTP marker: %#v", state)
			}
		})
	}
}

func TestAgentLifecycle_AccountOTPProviderResumeAfterCooldownDoesNotRedispatch(t *testing.T) {
	now := time.Date(2026, time.July, 11, 20, 0, 0, 0, time.UTC)
	tests := []struct {
		name                string
		wantCompletionDelta int32
		run                 func(*registerHarness, ...RegisterOption) error
	}{
		{name: "refresh", run: func(h *registerHarness, opts ...RegisterOption) error {
			binding, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(opts...)...)
			if binding != nil {
				binding.Destroy()
			}
			return err
		}},
		{name: "recovery", wantCompletionDelta: 1, run: func(h *registerHarness, opts ...RegisterOption) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_account", h.store, h.registerOpts(opts...)...)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			h.svc.mu.Lock()
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@example.test"
			h.svc.deviceAPIKey = "lv_device_provider_resume"
			h.svc.mu.Unlock()
			h.nhp.mu.Lock()
			h.nhp.expectCredential = "provider-code"
			h.nhp.mu.Unlock()

			state := h.loadState(t)
			requestedAt := now.Add(-otpResendCooldown)
			state.OTPRequestedAt = &requestedAt
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save elapsed OTP marker: %v", err)
			}
			regsBefore := h.nhp.regCount()
			completionBefore := h.svc.completionCalls.Load()
			var providerCalls atomic.Int32
			provider := WithOTPProvider(func(context.Context) (string, error) {
				providerCalls.Add(1)
				return "provider-code", nil
			})

			if err := tc.run(h, allowAccountLifecycle(), withClock(func() time.Time { return now }), provider); err != nil {
				t.Fatalf("provider resume after cooldown: %v", err)
			}
			if providerCalls.Load() != 1 || h.nhp.otpCount() != 0 || h.nhp.regCount() != regsBefore+1 {
				t.Fatalf("provider/OTP/REG = %d/%d/%d, want 1/0/%d", providerCalls.Load(), h.nhp.otpCount(), h.nhp.regCount(), regsBefore+1)
			}
			if h.svc.completionCalls.Load() != completionBefore+tc.wantCompletionDelta {
				t.Fatalf("completion calls = %d, want %d", h.svc.completionCalls.Load(), completionBefore+tc.wantCompletionDelta)
			}
			if state := h.loadState(t); state.OTPRequestedAt != nil {
				t.Fatalf("provider resume left OTP marker: %#v", state)
			}
		})
	}
}

func TestEnrollmentRefreshLegacy_OTPErrorsUseLifecycleSafeGuidance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rakCode string
		want    error
	}{
		{name: "incorrect", rakCode: rakCredentialInvalid, want: ErrOTPIncorrect},
		{name: "expired", rakCode: rakCredentialExpired, want: ErrOTPExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			h.svc.mu.Lock()
			h.svc.keyKind = keyKindAccount
			h.svc.maskedEmail = "j***@example.test"
			h.svc.mu.Unlock()
			if _, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle())...); !errors.Is(err, ErrOTPPending) {
				t.Fatalf("prime OTP marker: %v", err)
			}
			h.nhp.mu.Lock()
			h.nhp.rakErrCode = tc.rakCode
			h.nhp.rakErrMsg = "scripted OTP denial"
			h.nhp.mu.Unlock()

			_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_account", h.store, h.registerOpts(allowAccountLifecycle(), WithOTP("bad-code"))...)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "same operation") || strings.Contains(err.Error(), "qurl.RegisterAgent") {
				t.Fatalf("lifecycle OTP guidance = %v, want %v and same-operation guidance", err, tc.want)
			}
		})
	}
}

func TestCredentialPersistenceFailureAndExplicitSameIDRecovery(t *testing.T) {
	h := newRegisterHarness(t)
	persistFailure := errors.New("injected final save failure")
	failing := &failingSaveStore{
		inner: h.store,
		failWhen: func(state *AgentState) bool {
			return state.RegisteredAt != nil && state.DeviceAPIKey != ""
		},
		failErr:   persistFailure,
		failsLeft: 1,
	}
	h.store = failing
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistErr *CredentialPersistenceError
	if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, persistFailure) {
		t.Fatalf("want typed credential persistence error, got %v", err)
	}
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completion calls after failed final save = %d, want 1", h.svc.completionCalls.Load())
	}
	preRecovery := h.loadState(t)
	if preRecovery.AgentID != persistErr.DeviceID || preRecovery.DeviceAPIKey != "" {
		t.Fatalf("pre-recovery state/device mismatch: state=%#v err=%#v", preRecovery, persistErr)
	}

	// A normal restart gets the server's first-issue-only denial and maps it to
	// the same recovery class; it does not overwrite local state or mint again.
	h.svc.mu.Lock()
	h.svc.completionStatus = http.StatusConflict
	h.svc.completionCode = "device_key_already_issued"
	h.svc.mu.Unlock()
	_, err = RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var recoveryErr *CredentialRecoveryRequiredError
	if !errors.As(err, &recoveryErr) || recoveryErr.DeviceID != preRecovery.AgentID || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("restart recovery error = %v", err)
	}
	unchanged := h.loadState(t)
	if unchanged.DeviceAPIKey != "" || unchanged.AgentID != preRecovery.AgentID {
		t.Fatalf("ordinary restart mutated recovery state: %#v", unchanged)
	}
	completeBeforeRevoke := h.svc.completionCalls.Load()
	_, err = RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.As(err, &recoveryErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("explicit recovery before owner revoke = %v", err)
	}
	if h.svc.completionCalls.Load() != completeBeforeRevoke+1 {
		t.Fatalf("pre-revoke recovery completion calls = %d, want exactly one", h.svc.completionCalls.Load()-completeBeforeRevoke)
	}

	// Model owner revoke clearing the issued sentinel, then recover the exact
	// same id/keypair. Recovery makes one completion request and durably reopens.
	h.svc.mu.Lock()
	h.svc.completionStatus = 0
	h.svc.completionCode = ""
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	completeBefore := h.svc.completionCalls.Load()
	client, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts(
		WithDeviceID(preRecovery.AgentID),
	)...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	if client == nil {
		t.Fatal("RecoverAgentCredential returned nil Client")
	}
	if h.svc.completionCalls.Load() != completeBefore+1 {
		t.Fatalf("recovery completion calls = %d, want exactly one", h.svc.completionCalls.Load()-completeBefore)
	}
	recovered := h.loadState(t)
	if recovered.AgentID != preRecovery.AgentID || recovered.PrivateKeyB64 != preRecovery.PrivateKeyB64 || recovered.DeviceAPIKey != "lv_device_recovered" {
		t.Fatalf("same-id recovery did not preserve identity/replace credential: %#v", recovered)
	}
	if _, err := OpenRegisteredAgent(context.Background(), h.store); err != nil {
		t.Fatalf("durable reopen after recovery: %v", err)
	}
}

func TestRecoverAgentCredential_NoProbeAfterAmbiguousReplacementMint(t *testing.T) {
	h := registeredHarness(t)
	before := h.loadState(t)
	regsBefore := h.nhp.regCount()
	h.handlerMu.Lock()
	inner := h.handler
	h.handlerMu.Unlock()
	var completionAttempts atomic.Int32
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			switch completionAttempts.Add(1) {
			case 1:
				w.WriteHeader(http.StatusInternalServerError)
			case 2:
				w.WriteHeader(http.StatusConflict)
				_, _ = fmt.Fprint(w, `{"error":{"code":"device_key_already_issued","detail":"device key already issued"}}`)
			default:
				t.Fatalf("unexpected completion retry")
			}
			return
		}
		inner.ServeHTTP(w, r)
	}))

	_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistenceErr *CredentialPersistenceError
	if !errors.As(err, &persistenceErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("ambiguous replacement mint = %v, want persistence recovery", err)
	}
	_, err = RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var recoveryErr *CredentialRecoveryRequiredError
	if !errors.As(err, &recoveryErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("retry after ambiguous replacement mint = %v, want already-issued recovery", err)
	}
	if !strings.Contains(err.Error(), "revoke the active") ||
		!strings.Contains(err.Error(), "WithTakeover alone does not clear") ||
		!strings.Contains(err.Error(), "only no-revoke alternative") {
		t.Fatalf("already-issued guidance is incomplete: %v", err)
	}
	if completionAttempts.Load() != 2 || h.nhp.regCount() != regsBefore+2 {
		t.Fatalf("recovery completion/REG attempts = %d/%d, want 2/%d (one REG+completion per call, no probe)", completionAttempts.Load(), h.nhp.regCount(), regsBefore+2)
	}
	if after := h.loadState(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("ambiguous replacement/retry changed prior state: before=%#v after=%#v", before, after)
	}
}

func TestRegisterAgent_PostCompletionContractFailuresRequireRecoveryWithoutRetry(t *testing.T) {
	rotated := newFakeNHPServer(t)
	cases := []struct {
		name string
		edit func(*fakeService)
	}{
		{name: "rotated peer", edit: func(service *fakeService) {
			service.completionPeer = &NHPServerPeerInfo{
				PublicKeyB64: rotated.serverPubB64(),
				Host:         "rotated.example.test",
				Port:         62206,
			}
		}},
		{name: "agent id mismatch", edit: func(service *fakeService) {
			service.agentID = "agent-different"
		}},
		{name: "device key surrounding whitespace", edit: func(service *fakeService) {
			service.deviceAPIKey = " lv_device_secret "
		}},
		{name: "device key control character", edit: func(service *fakeService) {
			service.deviceAPIKey = "lv_device\nsecret"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			tc.edit(h.svc)
			h.armDevicePubOnInfo()

			_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			var persistErr *CredentialPersistenceError
			if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("want post-completion CredentialPersistenceError, got %v", err)
			}
			if strings.Contains(err.Error(), "lv_device_secret") {
				t.Fatalf("error exposed completion credential: %v", err)
			}
			if h.svc.completionCalls.Load() != 1 {
				t.Fatalf("completion calls = %d, want exactly 1", h.svc.completionCalls.Load())
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("invalid completion response was persisted: %#v", state)
			}
			if state.NHPPeer == nil || state.NHPPeer.PublicKeyB64 != h.nhp.serverPubB64() {
				t.Fatalf("authenticated RAK peer was not preserved: %#v", state.NHPPeer)
			}
		})
	}
}

func TestRegisterAgent_CompletionCoordinatesDoNotReplaceRAKPeer(t *testing.T) {
	tests := []struct {
		name string
		peer func(string) *NHPServerPeerInfo
	}{
		{name: "empty coordinates", peer: func(key string) *NHPServerPeerInfo {
			return &NHPServerPeerInfo{PublicKeyB64: key}
		}},
		{name: "malformed coordinates", peer: func(key string) *NHPServerPeerInfo {
			return &NHPServerPeerInfo{PublicKeyB64: key, Host: "stale.example.test", Port: 65536, ExpireTime: time.Now().Add(-time.Hour).Unix()}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			h.svc.completionPeer = tc.peer(h.nhp.serverPubB64())
			h.armDevicePubOnInfo()

			if _, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
				t.Fatalf("RegisterAgent with irrelevant completion coordinates: %v", err)
			}
			state := h.loadState(t)
			if state.NHPPeer == nil || state.NHPPeer.Host != "nhp.example.test" || state.NHPPeer.Port != 62206 || state.NHPPeer.ExpireTime != 0 {
				t.Fatalf("completion coordinates or lease replaced RAK peer: %#v", state.NHPPeer)
			}
		})
	}
}

func TestRecoverAgentCredential_CompletionPeerRotationFailsClosed(t *testing.T) {
	h := registeredHarness(t)
	before := h.loadState(t)
	rotated := newFakeNHPServer(t)
	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_rotated"
	h.svc.completionPeer = &NHPServerPeerInfo{
		PublicKeyB64: rotated.serverPubB64(),
		Host:         "rotated.example.test",
		Port:         62206,
	}
	h.svc.mu.Unlock()

	completeBefore := h.svc.completionCalls.Load()
	_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistErr *CredentialPersistenceError
	if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("want recovery-required peer mismatch, got %v", err)
	}
	if h.svc.completionCalls.Load() != completeBefore+1 {
		t.Fatalf("recovery completion calls = %d, want exactly 1", h.svc.completionCalls.Load()-completeBefore)
	}
	after := h.loadState(t)
	if after.DeviceAPIKey != before.DeviceAPIKey || after.NHPPeer.PublicKeyB64 != before.NHPPeer.PublicKeyB64 {
		t.Fatalf("failed recovery replaced durable credential/peer: before=%#v after=%#v", before, after)
	}
}

func TestPersistCompletion_PeerMismatchDropsPlaintextReference(t *testing.T) {
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-original"
	peerA := newFakeNHPServer(t)
	peerB := newFakeNHPServer(t)
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: peerA.serverPubB64(),
		Host:         "peer-a.example.test",
		Port:         62206,
	}
	now := time.Now().UTC()
	comp := &completionResponse{
		AgentID:      state.AgentID,
		RegisteredAt: &now,
		NHPServerPeer: NHPServerPeerInfo{
			PublicKeyB64: peerB.serverPubB64(),
			Host:         "peer-b.example.test",
			Port:         62206,
		},
		DeviceAPIKey:   "lv_plaintext_must_drop",
		DeviceAPIKeyID: "key_device000001",
	}
	cfg, err := newRegisterConfig(nil)
	if err != nil {
		t.Fatalf("newRegisterConfig: %v", err)
	}
	_, err = cfg.persistCompletion(context.Background(), memoryAgentStateStore{}, state, comp)
	if !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("persistCompletion: want recovery-required, got %v", err)
	}
	if comp.DeviceAPIKey != "" {
		t.Fatal("completion response retained plaintext credential after rejection")
	}
	if state.DeviceAPIKey != "" || state.NHPPeer.PublicKeyB64 != peerA.serverPubB64() {
		t.Fatalf("rejected completion mutated state: %#v", state)
	}
}

func TestPersistCompletion_SameKeyDifferentCoordinatesPreservesRAKBinding(t *testing.T) {
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-original"
	peer := newFakeNHPServer(t)
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: peer.serverPubB64(),
		Host:         "rak-authoritative.example.test",
		Port:         62206,
	}
	now := time.Now().UTC()
	comp := &completionResponse{
		AgentID:      state.AgentID,
		RegisteredAt: &now,
		NHPServerPeer: NHPServerPeerInfo{
			PublicKeyB64: strings.TrimRight(peer.serverPubB64(), "="),
			Host:         "completion-corroboration-only.example.test",
			Port:         443,
		},
		DeviceAPIKey:   "lv_device_secret",
		DeviceAPIKeyID: "key_device000001",
	}
	cfg, err := newRegisterConfig(nil)
	if err != nil {
		t.Fatalf("newRegisterConfig: %v", err)
	}
	persisted, err := cfg.persistCompletion(context.Background(), memoryAgentStateStore{}, state, comp)
	if err != nil {
		t.Fatalf("persistCompletion: %v", err)
	}
	if persisted.NHPPeer.Host != "rak-authoritative.example.test" || persisted.NHPPeer.Port != 62206 {
		t.Fatalf("completion replaced RAK-authoritative coordinates: %#v", persisted.NHPPeer)
	}
	if persisted.DeviceAPIKey != "lv_device_secret" {
		t.Fatal("completion credential was not committed")
	}
	if comp.DeviceAPIKey != "" {
		t.Fatal("completion response retained plaintext credential reference")
	}
}

func TestCompletionPeerComparisonUsesDecodedKeyBytes(t *testing.T) {
	peer := newFakeNHPServer(t)
	otherPeer := newFakeNHPServer(t)
	padded := peer.serverPubB64()
	raw := strings.TrimRight(padded, "=")
	cfg, err := newRegisterConfig(nil)
	if err != nil {
		t.Fatalf("newRegisterConfig: %v", err)
	}
	cases := []struct {
		name       string
		registered string
		completed  string
		wantErr    bool
	}{
		{name: "padded equality", registered: padded, completed: padded},
		{name: "padded to raw equality", registered: padded, completed: raw},
		{name: "raw to padded equality", registered: raw, completed: padded},
		{name: "different decoded key", registered: padded, completed: otherPeer.serverPubB64(), wantErr: true},
		{name: "invalid registered encoding", registered: "not-base64", completed: padded, wantErr: true},
		{name: "invalid completion encoding", registered: padded, completed: "not-base64", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &AgentState{NHPPeer: &NHPServerPeerInfo{PublicKeyB64: tc.registered}}
			comp := &completionResponse{NHPServerPeer: NHPServerPeerInfo{PublicKeyB64: tc.completed}}
			err := cfg.assertCompletionPeerMatchesRegistration(state, comp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("peer comparison error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("peer comparison error = %v, want ErrInvalidRegisterConfig", err)
			}
		})
	}

	rawPeer := NHPServerPeerInfo{PublicKeyB64: raw, Host: "nhp.example.test", Port: 62206}
	if err := validateNHPServerPeerInfo(rawPeer, time.Now(), true, "test peer", ErrInvalidRegisterConfig); err != nil {
		t.Fatalf("raw standard-base64 peer validation: %v", err)
	}
}

func TestRegisterAgent_CompletionOutcomeUnknownRequiresRecoveryWithoutRetry(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*registerHarness, *atomic.Int32) RegisterOption
		wantCause error
	}{
		{name: "malformed successful response", configure: func(h *registerHarness, attempts *atomic.Int32) RegisterOption {
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, `{"data":`)
					return
				}
				inner.ServeHTTP(w, r)
			}))
			return nil
		}},
		{name: "server error", configure: func(h *registerHarness, attempts *atomic.Int32) RegisterOption {
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = fmt.Fprint(w, `{"error":{"code":"upstream_unavailable","detail":"unknown outcome"}}`)
					return
				}
				inner.ServeHTTP(w, r)
			}))
			return nil
		}},
		{name: "transport failure", configure: func(_ *registerHarness, attempts *atomic.Int32) RegisterOption {
			client := doerFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost && req.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					return nil, errors.New("injected completion transport loss")
				}
				return http.DefaultClient.Do(req)
			})
			return WithRegisterHTTPClient(client)
		}},
		{name: "context cancellation after completion dispatch", wantCause: context.Canceled, configure: func(_ *registerHarness, attempts *atomic.Int32) RegisterOption {
			client := doerFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost && req.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					return nil, context.Canceled
				}
				return http.DefaultClient.Do(req)
			})
			return WithRegisterHTTPClient(client)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			h.armDevicePubOnInfo()
			var attempts atomic.Int32
			opt := tc.configure(h, &attempts)
			opts := h.registerOpts()
			if opt != nil {
				opts = append(opts, opt)
			}

			_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, opts...)
			var persistErr *CredentialPersistenceError
			if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("want ambiguous completion persistence error, got %v", err)
			}
			if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
				t.Fatalf("ambiguous completion error = %v, want cause %v", err, tc.wantCause)
			}
			if attempts.Load() != 1 {
				t.Fatalf("completion attempts = %d, want exactly 1", attempts.Load())
			}
			if h.nhp.regCount() != 1 {
				t.Fatalf("REG count = %d, want 1", h.nhp.regCount())
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("ambiguous completion persisted credential: %#v", state)
			}
		})
	}
}

func TestRegisterAgent_BareCompletion500RequiresRecoveryWithoutRetry(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	h.handlerMu.Lock()
	inner := h.handler
	h.handlerMu.Unlock()
	var attempts atomic.Int32
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			attempts.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		inner.ServeHTTP(w, r)
	}))

	_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistErr *CredentialPersistenceError
	var apiErr *APIError
	if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) ||
		!errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("bare completion 500 = %v, want persistence ambiguity preserving API 500", err)
	}
	if attempts.Load() != 1 || h.nhp.regCount() != 1 {
		t.Fatalf("bare 500 completion/REG attempts = %d/%d, want 1/1", attempts.Load(), h.nhp.regCount())
	}
	state := h.loadState(t)
	if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
		t.Fatalf("bare completion 500 persisted credential: %#v", state)
	}
}

func TestRegisterAgent_CompletionNoWriteUnavailableRemainsRetryable(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	h.handlerMu.Lock()
	inner := h.handler
	h.handlerMu.Unlock()
	var attempts atomic.Int32
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":{"code":"service_unavailable","detail":"no-write admission unavailable"}}`)
			return
		}
		inner.ServeHTTP(w, r)
	}))

	_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrRegistrationRetryLater) {
		t.Fatalf("want retry-later no-write failure, got %v", err)
	}
	if errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("no-write service_unavailable must not be ambiguous mint: %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("completion attempts = %d, want 1", attempts.Load())
	}
}

func TestRegisterAgent_Completion4xxRequiresExplicitNoWriteClassification(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		code          string
		wantMapped    error
		wantAmbiguous bool
	}{
		{name: "unclassified invalid input", status: http.StatusBadRequest, code: "invalid_input", wantAmbiguous: true},
		{name: "unauthorized", status: http.StatusUnauthorized, code: "unauthorized", wantMapped: ErrKeyRejected},
		{name: "forbidden", status: http.StatusForbidden, code: "forbidden", wantMapped: ErrKeyRejected},
		{name: "not enrolled", status: http.StatusNotFound, code: "agent_not_enrolled"},
		{name: "payload admission", status: http.StatusRequestEntityTooLarge, code: "request_too_large", wantMapped: ErrRegistrationRequestTooLarge},
		{name: "bare not found after REG", status: http.StatusNotFound, code: "", wantAmbiguous: true},
		{name: "unclassified conflict", status: http.StatusConflict, code: "conflict", wantAmbiguous: true},
		{name: "device key quota", status: http.StatusConflict, code: "device_key_quota_exceeded", wantMapped: ErrDeviceKeyQuotaExceeded},
		{name: "quota code wrong status", status: http.StatusBadRequest, code: "device_key_quota_exceeded", wantAmbiguous: true},
		{name: "already-issued code wrong status", status: http.StatusBadRequest, code: "device_key_already_issued", wantAmbiguous: true},
		{name: "unclassified newer status", status: http.StatusUnprocessableEntity, code: "new_completion_error", wantAmbiguous: true},
		{name: "unclassified gateway timeout", status: http.StatusGatewayTimeout, code: "gateway_timeout", wantAmbiguous: true},
		{name: "no-write rate limit", status: http.StatusTooManyRequests, code: "rate_limited", wantMapped: ErrRegistrationRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			h.armDevicePubOnInfo()
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			var attempts atomic.Int32
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"detail":"rejected before mint"}}`, tc.code)
					return
				}
				inner.ServeHTTP(w, r)
			}))

			_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			if err == nil {
				t.Fatal("completion 4xx unexpectedly succeeded")
			}
			var persistenceErr *CredentialPersistenceError
			if tc.wantAmbiguous {
				if !errors.As(err, &persistenceErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
					t.Fatalf("unclassified completion 4xx = %v, want persistence ambiguity", err)
				}
			} else if errors.As(err, &persistenceErr) || errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("authoritative no-write 4xx misclassified as mint ambiguity: %v", err)
			}
			if tc.wantMapped != nil && !errors.Is(err, tc.wantMapped) {
				t.Fatalf("completion error = %v, want %v", err, tc.wantMapped)
			}
			if errors.Is(err, ErrRegistrationRequestTooLarge) {
				var tooLarge *RegistrationRequestTooLargeError
				var apiErr *APIError
				if !errors.As(err, &tooLarge) || !errors.As(err, &apiErr) || tooLarge.DeviceID == "" || apiErr.StatusCode != http.StatusRequestEntityTooLarge {
					t.Fatalf("request-too-large error lost typed/API detail: %v", err)
				}
			}
			if attempts.Load() != 1 || h.nhp.regCount() != 1 {
				t.Fatalf("completion/REG attempts = %d/%d, want 1/1", attempts.Load(), h.nhp.regCount())
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("completion 4xx persisted a credential: %#v", state)
			}
		})
	}
}

func TestRegisterAgent_DeviceKeyQuotaExceededIsAuthoritativeNoWriteForBothPaths(t *testing.T) {
	tests := []struct {
		name    string
		account bool
		key     string
	}{
		{name: "bootstrap", key: "lv_enroll"},
		{name: "account", key: "lv_account", account: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			var opts []RegisterOption
			if tc.account {
				h.svc.keyKind = keyKindAccount
				h.svc.maskedEmail = "j***@x.com"
				h.nhp.expectCredential = "424242"
			}
			h.armDevicePubOnInfo()
			if tc.account {
				if _, err := RegisterAgent(context.Background(), tc.key, h.store, h.registerOpts()...); !errors.Is(err, ErrOTPPending) {
					t.Fatalf("account phase 1 = %v, want OTP pending", err)
				}
				opts = []RegisterOption{WithOTP("424242")}
			}

			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			var completionAttempts atomic.Int32
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempt := completionAttempts.Add(1)
					if tc.account && attempt == 1 {
						w.WriteHeader(http.StatusNotFound)
						_, _ = fmt.Fprint(w, `{"error":{"code":"device_not_registered","detail":"device is not yet registered"}}`)
						return
					}
					w.WriteHeader(http.StatusConflict)
					_, _ = fmt.Fprint(w, `{"error":{"code":"device_key_quota_exceeded","title":"Device Key Quota Exceeded","detail":"the account has reached its active device key limit. Revoke an existing device key to free a slot, then retry completion. If replacing an existing device, revoke that device key and use takeover re-enrollment."}}`)
					return
				}
				inner.ServeHTTP(w, r)
			}))

			_, err := RegisterAgent(context.Background(), tc.key, h.store, h.registerOpts(opts...)...)
			var quotaErr *DeviceKeyQuotaExceededError
			if !errors.Is(err, ErrDeviceKeyQuotaExceeded) || !errors.As(err, &quotaErr) {
				t.Fatalf("quota completion error = %v, want typed quota error", err)
			}
			if quotaErr.DeviceID == "" || !strings.Contains(err.Error(), "revoke an existing unused device key") {
				t.Fatalf("quota error lacks device id/guidance: %#v / %v", quotaErr, err)
			}
			operatorMessage := (&DeviceKeyQuotaExceededError{DeviceID: quotaErr.DeviceID}).Error()
			if strings.Contains(operatorMessage, "retry completion") ||
				!strings.Contains(operatorMessage, "qurl.RegisterAgent") ||
				!strings.Contains(operatorMessage, "qurl.RecoverAgentCredential") ||
				!strings.Contains(operatorMessage, "different key") {
				t.Fatalf("quota typed guidance is not public-operation-safe: %q", operatorMessage)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "device_key_quota_exceeded" || apiErr.Title != "Device Key Quota Exceeded" {
				t.Fatalf("quota error lost API cause: %v", err)
			}
			if errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("authoritative no-write quota rejection was classified as recovery-required: %v", err)
			}
			wantCompletionAttempts := int32(1)
			if tc.account {
				wantCompletionAttempts = 2 // pre-REG not-enrolled probe, then quota rejection
			}
			if completionAttempts.Load() != wantCompletionAttempts || h.nhp.regCount() != 1 {
				t.Fatalf("completion/REG attempts = %d/%d, want %d/1", completionAttempts.Load(), h.nhp.regCount(), wantCompletionAttempts)
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("quota response persisted a credential: %#v", state)
			}
		})
	}
}

func TestRecoverAgentCredential_AuthoritativeNoWritePreservesPriorState(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{name: "device key quota", status: http.StatusConflict, code: "device_key_quota_exceeded", want: ErrDeviceKeyQuotaExceeded},
		{name: "request too large", status: http.StatusRequestEntityTooLarge, code: "request_too_large", want: ErrRegistrationRequestTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			before := h.loadState(t)
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			var completionAttempts atomic.Int32
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					completionAttempts.Add(1)
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"detail":"authoritative rejection before mint"}}`, tc.code)
					return
				}
				inner.ServeHTTP(w, r)
			}))

			_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			var apiErr *APIError
			if !errors.Is(err, tc.want) || !errors.As(err, &apiErr) {
				t.Fatalf("authoritative recovery rejection = %v, want %v + API error", err, tc.want)
			}
			if apiErr.StatusCode != tc.status || apiErr.Code != tc.code || errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("authoritative recovery classification = %v", err)
			}
			if errors.Is(err, ErrDeviceKeyQuotaExceeded) {
				var typed *DeviceKeyQuotaExceededError
				if !errors.As(err, &typed) || typed.DeviceID == "" {
					t.Fatalf("quota recovery lost typed detail: %v", err)
				}
			} else if errors.Is(err, ErrRegistrationRequestTooLarge) {
				var typed *RegistrationRequestTooLargeError
				if !errors.As(err, &typed) || typed.DeviceID == "" {
					t.Fatalf("request-too-large recovery lost typed detail: %v", err)
				}
			}
			if completionAttempts.Load() != 1 {
				t.Fatalf("recovery completion attempts = %d, want 1", completionAttempts.Load())
			}
			after := h.loadState(t)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("authoritative rejection changed prior state: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestAgentLifecycle_RegistrationAndResourceOriginsRemainIndependent(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.expectedBearer = "lv_enroll"
	h.armDevicePubOnInfo()

	var resourceCalls atomic.Int32
	var credentialMu sync.Mutex
	wantCredential := "lv_device_secret"
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources" {
			t.Errorf("resource origin got unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		credentialMu.Lock()
		want := wantCredential
		credentialMu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+want {
			t.Errorf("resource Authorization = %q, want Bearer %q", got, want)
		}
		resourceCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"resource_id":"r_lifecycle123","target_url":"https://internal.example.test","status":"active"}}`)
	}))
	t.Cleanup(resourceServer.Close)

	registerOpts := h.registerOpts(WithAgentClientBaseURL(resourceServer.URL))
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, registerOpts...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	protectOnce(t, client)

	reopened, err := OpenRegisteredAgent(context.Background(), h.store, WithAgentClientBaseURL(resourceServer.URL))
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	protectOnce(t, reopened)

	completeBeforeRefresh := h.svc.completionCalls.Load()
	if _, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, registerOpts...); err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	if h.svc.completionCalls.Load() != completeBeforeRefresh {
		t.Fatal("refresh crossed into completion")
	}

	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	credentialMu.Lock()
	wantCredential = "lv_device_recovered"
	credentialMu.Unlock()
	recoveredClient, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, registerOpts...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	protectOnce(t, recoveredClient)

	if resourceCalls.Load() != 3 {
		t.Fatalf("resource calls = %d, want 3", resourceCalls.Load())
	}
	if h.svc.infoCalls.Load() != 3 {
		t.Fatalf("registration-info calls = %d, want 3 (initial, refresh, recovery)", h.svc.infoCalls.Load())
	}
}

func TestAgentLifecycle_RegistrationAndResourceTransportsRemainIndependent(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()

	var resourceCredentialMu sync.Mutex
	resourceCredential := "lv_device_secret"
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceCredentialMu.Lock()
		want := resourceCredential
		resourceCredentialMu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+want {
			t.Errorf("resource Authorization = %q, want Bearer %q", got, want)
		}
		_, _ = fmt.Fprint(w, `{"data":{"resource_id":"r_transport123","target_url":"https://internal.example.test","status":"active"}}`)
	}))
	t.Cleanup(resourceServer.Close)

	apiHost := strings.TrimPrefix(h.apiSrv.URL, "http://")
	relayHost := strings.TrimPrefix(h.relaySrv.URL, "http://")
	resourceHost := strings.TrimPrefix(resourceServer.URL, "http://")
	var registrationCalls, registrationRefusals atomic.Int32
	registrationTransport := doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != apiHost && req.URL.Host != relayHost {
			registrationRefusals.Add(1)
			return nil, fmt.Errorf("registration transport refused host %q", req.URL.Host)
		}
		registrationCalls.Add(1)
		return http.DefaultClient.Do(req)
	})
	var resourceCalls, resourceRefusals atomic.Int32
	resourceTransport := doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != resourceHost {
			resourceRefusals.Add(1)
			return nil, fmt.Errorf("resource transport refused host %q", req.URL.Host)
		}
		resourceCalls.Add(1)
		return http.DefaultClient.Do(req)
	})

	opts := h.registerOpts(
		WithRegisterHTTPClient(registrationTransport),
		WithAgentClientBaseURL(resourceServer.URL),
		WithAgentClientHTTPClient(resourceTransport),
	)
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, opts...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	protectOnce(t, client)

	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	resourceCredentialMu.Lock()
	resourceCredential = "lv_device_recovered"
	resourceCredentialMu.Unlock()
	recovered, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, opts...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	protectOnce(t, recovered)

	opened, err := OpenRegisteredAgent(context.Background(), h.store,
		WithAgentClientBaseURL(resourceServer.URL),
		WithAgentClientHTTPClient(resourceTransport),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	protectOnce(t, opened)

	if registrationCalls.Load() < 6 { // two each: info, relay REG, completion
		t.Fatalf("registration transport calls = %d, want at least 6", registrationCalls.Load())
	}
	if resourceCalls.Load() != 3 {
		t.Fatalf("resource transport calls = %d, want 3", resourceCalls.Load())
	}
	if registrationRefusals.Load() != 0 || resourceRefusals.Load() != 0 {
		t.Fatalf("transport crossed origins: registration refusals=%d resource refusals=%d", registrationRefusals.Load(), resourceRefusals.Load())
	}
}

func TestAgentLifecycleMutationsParticipateInSharedSetupLock(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		h := registeredHarness(t)
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
		if _, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
			t.Fatalf("RefreshAgentRegistration: %v", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("refresh setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
	})

	t.Run("recover", func(t *testing.T) {
		h := registeredHarness(t)
		h.svc.mu.Lock()
		h.svc.deviceAPIKey = "lv_device_recovered"
		h.svc.mu.Unlock()
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
		if _, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
			t.Fatalf("RecoverAgentCredential: %v", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("recovery setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
	})

	t.Run("refresh release failure preserves binding", func(t *testing.T) {
		h := registeredHarness(t)
		h.svc.mu.Lock()
		h.svc.keyID = "key_after_release_failure"
		h.svc.mu.Unlock()
		completeBefore := h.svc.completionCalls.Load()
		releaseFailure := errors.New("injected refresh lock release failure")
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLockError(t, h.store, &acquired, &released, releaseFailure)

		state, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if state != nil {
			t.Fatal("refresh returned state after ambiguous setup-lock release")
		}
		if !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseFailure) {
			t.Fatalf("refresh release failure = %v, want ErrAgentSetupLock and injected cause", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("refresh setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
		persisted := h.loadState(t)
		if persisted.KeyID != "key_after_release_failure" {
			t.Fatalf("binding after release failure = %q, want committed replacement", persisted.KeyID)
		}
		if h.svc.completionCalls.Load() != completeBefore {
			t.Fatal("refresh release-failure path called completion")
		}
	})

	t.Run("recovery release failure reopens durable replacement without second mint", func(t *testing.T) {
		h := registeredHarness(t)
		h.svc.mu.Lock()
		h.svc.deviceAPIKey = "lv_device_recovered_after_release_failure"
		h.svc.mu.Unlock()
		completeBefore := h.svc.completionCalls.Load()
		releaseFailure := errors.New("injected recovery lock release failure")
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLockError(t, h.store, &acquired, &released, releaseFailure)

		client, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if client != nil {
			t.Fatal("recovery returned client after ambiguous setup-lock release")
		}
		if !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseFailure) {
			t.Fatalf("recovery release failure = %v, want ErrAgentSetupLock and injected cause", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("recovery setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
		persisted := h.loadState(t)
		if persisted.DeviceAPIKey != "lv_device_recovered_after_release_failure" {
			t.Fatal("replacement credential was not durable after setup-lock release failure")
		}
		if h.svc.completionCalls.Load() != completeBefore+1 {
			t.Fatalf("recovery completion calls = %d, want exactly one", h.svc.completionCalls.Load()-completeBefore)
		}

		var qurlCalls atomic.Int32
		opened, openErr := OpenRegisteredAgent(context.Background(), h.store,
			WithBaseURL("https://resources.example.test"),
			WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
				qurlCalls.Add(1)
				return nil, errors.New("unexpected qURL API call")
			})),
		)
		if openErr != nil || opened == nil {
			t.Fatalf("OpenRegisteredAgent after release failure = client %v, error %v", opened, openErr)
		}
		if qurlCalls.Load() != 0 {
			t.Fatalf("OpenRegisteredAgent qURL calls = %d, want 0", qurlCalls.Load())
		}
		if h.svc.completionCalls.Load() != completeBefore+1 {
			t.Fatal("load-first recovery attempted a second credential mint")
		}
	})

	for _, tc := range []struct {
		name string
		run  func(*registerHarness) error
	}{
		{name: "refresh acquisition failure", run: func(h *registerHarness) error {
			_, err := legacyEnrollmentRefreshForTest(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			return err
		}},
		{name: "recovery acquisition failure", run: func(h *registerHarness) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			fileStore, ok := h.store.(fileAgentStateStore)
			if !ok {
				t.Fatalf("store type = %T, want fileAgentStateStore", h.store)
			}
			lockFailure := errors.New("injected lifecycle lock failure")
			fileStore.lockFile = func(context.Context, string) (setupLock, error) {
				return nil, lockFailure
			}
			h.store = fileStore
			infoBefore := h.svc.infoCalls.Load()
			err := tc.run(h)
			if !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, lockFailure) {
				t.Fatalf("lock failure = %v, want ErrAgentSetupLock and injected cause", err)
			}
			if h.svc.infoCalls.Load() != infoBefore {
				t.Fatal("lifecycle mutation performed network I/O after setup-lock failure")
			}
		})
	}
}

type trackingSetupLock struct {
	released *atomic.Int32
	err      error
}

func (l *trackingSetupLock) Close() error {
	l.released.Add(1)
	return l.err
}

func instrumentFileStoreLock(t *testing.T, store AgentStateStore, acquired, released *atomic.Int32) AgentStateStore {
	return instrumentFileStoreLockError(t, store, acquired, released, nil)
}

func instrumentFileStoreLockError(t *testing.T, store AgentStateStore, acquired, released *atomic.Int32, releaseErr error) AgentStateStore {
	t.Helper()
	fileStore, ok := store.(fileAgentStateStore)
	if !ok {
		t.Fatalf("store type = %T, want fileAgentStateStore", store)
	}
	wantPath := fileStore.setupLockPath()
	fileStore.lockFile = func(_ context.Context, path string) (setupLock, error) {
		if path != wantPath {
			t.Errorf("setup lock path = %q, want %q", path, wantPath)
		}
		acquired.Add(1)
		return &trackingSetupLock{released: released, err: releaseErr}, nil
	}
	return fileStore
}

func registeredHarness(t *testing.T) *registerHarness {
	t.Helper()
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	if _, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	state := h.loadState(t)
	state.DeviceAPIKeyID = "key_device000001"
	assignment := validAssignment(t, state.AgentID)
	state.Assignment = &assignment
	if err := h.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save native runtime state: %v", err)
	}
	return h
}

func protectOnce(t *testing.T, client *Client) {
	t.Helper()
	resource, err := client.ProtectURL(context.Background(), "https://internal.example.test")
	if err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
	if !strings.HasPrefix(resource.ID, "r_") {
		t.Fatalf("resource ID = %q", resource.ID)
	}
}
