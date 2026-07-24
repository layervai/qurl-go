package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingAgentStateStore struct {
	inner AgentStateStore
	loads atomic.Int32
}

type memoryAgentStateStore struct {
	state *AgentState
}

type sequenceAgentStateStore struct {
	states   []*AgentState
	returned []*AgentState
	loads    atomic.Int32
}

type releaseErrorAgentStateStore struct {
	*memoryAgentStateStore
	closeErr error
}

type testSetupLock struct{ closeErr error }

func (l testSetupLock) Close() error { return l.closeErr }

func (s *releaseErrorAgentStateStore) acquireSetupLock(context.Context) (setupLock, error) {
	return testSetupLock{closeErr: s.closeErr}, nil
}

func (s *memoryAgentStateStore) LoadAgentState(context.Context) (*AgentState, error) {
	if s.state == nil {
		return nil, ErrAgentStateNotFound
	}
	return s.state.clone(), nil
}

func (s *memoryAgentStateStore) SaveAgentState(_ context.Context, state *AgentState) error {
	s.state = state.clone()
	return nil
}

func (s *countingAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	s.loads.Add(1)
	return s.inner.LoadAgentState(ctx)
}

func (s *countingAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	return s.inner.SaveAgentState(ctx, state)
}

func (s *sequenceAgentStateStore) LoadAgentState(context.Context) (*AgentState, error) {
	index := int(s.loads.Add(1)) - 1
	if index >= len(s.states) {
		return nil, fmt.Errorf("unexpected load %d", index+1)
	}
	state := s.states[index].clone()
	s.returned = append(s.returned, state)
	return state, nil
}

func (s *sequenceAgentStateStore) SaveAgentState(context.Context, *AgentState) error {
	return errors.New("unexpected save")
}

func runtimeTestHub() HubBootstrap {
	return HubBootstrap{Host: "hub.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: validTestNHPServerPublicKeyB64}
}

func TestWithAgentSetupLock_CleansResultBeforeZeroingOnReleaseFailure(t *testing.T) {
	releaseErr := errors.New("release failed")
	transitionErr := errors.New("transition failed")
	for _, test := range []struct {
		name          string
		transitionErr error
	}{
		{name: "successful transition"},
		{name: "failed transition", transitionErr: transitionErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &releaseErrorAgentStateStore{
				memoryAgentStateStore: &memoryAgentStateStore{},
				closeErr:              releaseErr,
			}
			want := new(int)
			cleanupSawResult := false

			got, err := withAgentSetupLock(context.Background(), store, func(result *int) {
				cleanupSawResult = result == want
			}, func(context.Context, AgentStateStore) (*int, error) {
				return want, test.transitionErr
			})

			if got != nil || !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseErr) ||
				(test.transitionErr != nil && !errors.Is(err, test.transitionErr)) {
				t.Fatalf("release failure = result %v, error %v; want nil and all transition/lock/release errors", got, err)
			}
			if !cleanupSawResult {
				t.Fatal("cleanup did not receive the result before it was zeroed")
			}
		})
	}
}

func TestWithAgentSetupLock_ReleaseFailureDestroysNativeRuntimePrivateKey(t *testing.T) {
	releaseErr := errors.New("release failed")
	store := &releaseErrorAgentStateStore{
		memoryAgentStateStore: &memoryAgentStateStore{},
		closeErr:              releaseErr,
	}
	privateKey := bytes.Repeat([]byte{0x5a}, 32)
	result := &nativeRuntimeResult{
		binding: &AgentRuntimeBinding{deviceStaticPrivateKey: newAgentRuntimePrivateKey(privateKey)},
	}

	got, err := withAgentSetupLock(context.Background(), store, destroyNativeRuntimeResult, func(context.Context, AgentStateStore) (*nativeRuntimeResult, error) {
		return result, nil
	})

	if got != nil || !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseErr) {
		t.Fatalf("release failure = result %v, error %v; want nil and joined lock/release errors", got, err)
	}
	if key := result.binding.TakeDeviceStaticPrivateKey(); key != nil {
		t.Fatalf("destroyed binding retained private key %x", key)
	}
	if !bytes.Equal(privateKey, make([]byte, len(privateKey))) {
		t.Fatalf("private key backing bytes = %x, want zeroed", privateKey)
	}
}

func completedNativeTestState(t *testing.T) *AgentState {
	t.Helper()
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := time.Now().UTC()
	state.AgentID = "agent-native"
	state.SchemaVersion = agentStateSchemaVersion
	state.RegisteredAt = &registeredAt
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_AbCdEf123456"
	state.Assignment = &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1,
		LeaseExpiresAt: registeredAt.Add(time.Hour),
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
			ServerPublicKeyB64: validTestNHPServerPublicKeyB64,
		},
	}
	return state
}

func TestAgentStateClone_IsolatesEveryMutableField(t *testing.T) {
	stateType := reflect.TypeOf(AgentState{})
	handledNames := []string{"RegisteredAt", "Assignment", "PendingActivation", "PendingCompletion", "PendingCredentialRecovery", "PendingCredentialRecoveryIssue"}
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

	original := completedNativeTestState(t)
	original.PendingCompletion = &PendingAgentCompletion{DeviceAPIKey: "candidate", CellID: "cell0", AssignmentGeneration: 1}
	original.PendingActivation = &PendingAgentActivation{AssignmentTicket: "ticket-original", Assignment: AgentAssignment{CellID: "cell0"}}
	original.PendingCredentialRecovery = &PendingAgentCredentialRecovery{RecoveryGrant: "qrg1.original", Assignment: AgentAssignment{CellID: "cell0"}}
	original.PendingCredentialRecoveryIssue = &PendingAgentCredentialRecoveryIssue{RequestNonce: "original-nonce", HubHost: "hub.nhp.layerv.ai"}
	cloned := original.clone()
	*cloned.RegisteredAt = cloned.RegisteredAt.Add(time.Hour)
	cloned.Assignment.Endpoint.Host = "changed.nhp.layerv.ai"
	cloned.PendingCompletion.DeviceAPIKey = "changed"
	cloned.PendingActivation.AssignmentTicket = "ticket-changed"
	cloned.PendingActivation.Assignment.CellID = "cell1"
	cloned.PendingCredentialRecovery.RecoveryGrant = "qrg1.changed"
	cloned.PendingCredentialRecovery.Assignment.CellID = "cell2"
	cloned.PendingCredentialRecoveryIssue.RequestNonce = "changed-nonce"

	if original.Assignment.Endpoint.Host != "cell0.nhp.layerv.ai" ||
		original.PendingActivation.AssignmentTicket != "ticket-original" || original.PendingActivation.Assignment.CellID != "cell0" ||
		original.PendingCompletion.DeviceAPIKey != "candidate" ||
		original.PendingCredentialRecovery.RecoveryGrant != "qrg1.original" || original.PendingCredentialRecovery.Assignment.CellID != "cell0" ||
		original.PendingCredentialRecoveryIssue.RequestNonce != "original-nonce" ||
		original.RegisteredAt.Equal(*cloned.RegisteredAt) {
		t.Fatalf("AgentState clone mutated source: %#v", original)
	}
}

func TestOpenRegisteredAgentRuntime_OneLoadThroughFirstAuthorization(t *testing.T) {
	store := &memoryAgentStateStore{state: completedNativeTestState(t)}
	counting := &countingAgentStateStore{inner: store}
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
		t.Fatal(err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize from primed runtime client: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+canonicalNativeDeviceCredential {
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

func TestOpenRegisteredAgentWithIdentity_OneSnapshotPinsClientIdentity(t *testing.T) {
	now := time.Now().UTC()
	clock := now
	stateA := completedNativeTestState(t)
	stateA.AgentID = "agent-a"
	stateA.DeviceAPIKey = canonicalNativeDeviceCredential
	stateB := completedNativeTestState(t)
	stateB.AgentID = "agent-b"
	stateB.DeviceAPIKey = canonicalNativeDeviceCredential
	stateC := completedNativeTestState(t)
	stateC.AgentID = "agent-c"
	stateC.DeviceAPIKey = canonicalNativeDeviceCredential
	store := &sequenceAgentStateStore{states: []*AgentState{stateA, stateB, stateC}}

	client, agentID, err := openRegisteredAgentWithIdentity(context.Background(), store, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("OpenRegisteredAgentWithIdentity: %v", err)
	}
	if agentID != stateA.AgentID || store.loads.Load() != 1 {
		t.Fatalf("open = agent %q, loads %d; want %q and 1", agentID, store.loads.Load(), stateA.AgentID)
	}
	if got := *store.returned[0]; !reflect.DeepEqual(got, AgentState{}) {
		t.Fatalf("open retained full owned AgentState snapshot: %#v", got)
	}

	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.credentials.Authorize(context.Background(), first); err != nil {
		t.Fatalf("authorize from exact open snapshot: %v", err)
	}
	if got := first.Header.Get("Authorization"); got != "Bearer "+stateA.DeviceAPIKey || store.loads.Load() != 1 {
		t.Fatalf("primed authorization = %q, loads %d; want agent A credential and one load", got, store.loads.Load())
	}

	clock = clock.Add(storeCredentialCacheTTL)
	second, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = client.credentials.Authorize(context.Background(), second)
	if !errors.Is(err, ErrInvalidClientConfig) || second.Header.Get("Authorization") != "" {
		t.Fatalf("post-TTL identity change = authorization %q, error %v; want fail closed before header", second.Header.Get("Authorization"), err)
	}
	if store.loads.Load() != 2 {
		t.Fatalf("identity mismatch loads = %d, want A then B only; C must remain unread", store.loads.Load())
	}
	if got := *store.returned[1]; !reflect.DeepEqual(got, AgentState{}) {
		t.Fatalf("post-TTL authorization retained full owned AgentState snapshot: %#v", got)
	}
}

func TestOpenRegisteredAgentWithIdentity_RejectsIncompleteStateAfterOneLoad(t *testing.T) {
	state := completedNativeTestState(t)
	state.RegisteredAt = nil
	store := &sequenceAgentStateStore{states: []*AgentState{state, completedNativeTestState(t)}}

	client, agentID, err := OpenRegisteredAgentWithIdentity(context.Background(), store)
	if client != nil || agentID != "" || !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("incomplete open = client %v, agent %q, error %v; want nil, empty, invalid config", client, agentID, err)
	}
	if store.loads.Load() != 1 {
		t.Fatalf("incomplete open loads = %d, want exactly 1", store.loads.Load())
	}
	if got := *store.returned[0]; !reflect.DeepEqual(got, AgentState{}) {
		t.Fatalf("rejected open retained full owned AgentState snapshot: %#v", got)
	}
}

func TestOpenRegisteredAgentWithIdentity_AllowsPostTTLCredentialRotationForSameIdentity(t *testing.T) {
	clock := time.Now().UTC()
	stateA := completedNativeTestState(t)
	stateA.AgentID = "agent-a"
	stateB := completedNativeTestState(t)
	stateB.AgentID = stateA.AgentID
	stateB.DeviceAPIKey = deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, deviceKeyRandomLength))
	store := &sequenceAgentStateStore{states: []*AgentState{stateA, stateB}}

	client, agentID, err := openRegisteredAgentWithIdentity(context.Background(), store, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("OpenRegisteredAgentWithIdentity: %v", err)
	}
	if agentID != stateA.AgentID {
		t.Fatalf("opened agent id = %q, want %q", agentID, stateA.AgentID)
	}

	clock = clock.Add(storeCredentialCacheTTL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.credentials.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize after same-agent credential rotation: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+stateB.DeviceAPIKey {
		t.Fatalf("rotated Authorization = %q, want rotated credential", got)
	}
	if store.loads.Load() != 2 {
		t.Fatalf("same-agent rotation loads = %d, want initial and post-TTL loads", store.loads.Load())
	}
	for i, returned := range store.returned {
		if got := *returned; !reflect.DeepEqual(got, AgentState{}) {
			t.Fatalf("load %d retained full owned AgentState snapshot: %#v", i+1, got)
		}
	}
}

func TestNativeRuntimeClients_RejectPostTTLIdentityChange(t *testing.T) {
	for _, test := range []struct {
		name string
		open func(*sequenceAgentStateStore, func() time.Time) (*Client, func(), error)
	}{
		{
			name: "warm runtime open",
			open: func(store *sequenceAgentStateStore, now func() time.Time) (*Client, func(), error) {
				client, binding, err := openRegisteredAgentRuntime(context.Background(), store, now)
				if err != nil {
					return nil, func() {}, err
				}
				if len(store.returned) != 1 || !reflect.DeepEqual(*store.returned[0], AgentState{}) {
					binding.Destroy()
					return nil, func() {}, fmt.Errorf("runtime open retained full owned AgentState snapshot: %#v", store.returned)
				}
				return client, binding.Destroy, nil
			},
		},
		{
			name: "registration finish",
			open: func(store *sequenceAgentStateStore, now func() time.Time) (*Client, func(), error) {
				state := store.states[0].clone()
				// Registration already owns the exact committed state snapshot;
				// the store's first load is therefore the later credential refresh.
				store.states = store.states[1:]
				cfg := defaultNativeAgentRuntimeConfig()
				cfg.clock = now
				client, binding, err := finishNativeRuntime(store, state, cfg)
				if err != nil {
					return nil, func() {}, err
				}
				if !reflect.DeepEqual(*state, AgentState{}) {
					binding.Destroy()
					return nil, func() {}, fmt.Errorf("registration finish retained full owned AgentState snapshot: %#v", state)
				}
				return client, binding.Destroy, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := time.Now().UTC()
			stateA := completedNativeTestState(t)
			stateA.AgentID = "agent-a"
			stateB := completedNativeTestState(t)
			stateB.AgentID = "agent-b"
			store := &sequenceAgentStateStore{states: []*AgentState{stateA, stateB}}
			client, cleanup, err := test.open(store, func() time.Time { return clock })
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			clock = clock.Add(storeCredentialCacheTTL)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resources.example.test/v1/resources", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.credentials.Authorize(context.Background(), req); !errors.Is(err, ErrInvalidClientConfig) {
				t.Fatalf("post-TTL identity change = %v, want invalid client config", err)
			}
			if req.Header.Get("Authorization") != "" {
				t.Fatalf("identity-changed client set Authorization %q", req.Header.Get("Authorization"))
			}
		})
	}
}

func TestOpenRegisteredAgent_NativeCredentialFaultFailsClosed(t *testing.T) {
	state := completedNativeTestState(t)
	state.DeviceAPIKey = ""
	store := &memoryAgentStateStore{state: state}
	client, err := OpenRegisteredAgent(context.Background(), store)
	var recovery *NativeCredentialRecoveryRequiredError
	if client != nil || !errors.As(err, &recovery) ||
		!errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, ErrDeviceCredentialMissing) ||
		strings.Contains(err.Error(), "HTTP recovery") {
		t.Fatalf("native resource-open credential error = client %v, %T: %v", client, err, err)
	}
}

func TestNativeCredentialRecoveryRequiredError_PendingEpisodeDoesNotClaimMissingCredential(t *testing.T) {
	state := completedNativeTestState(t)
	state.PendingCredentialRecoveryIssue = &PendingAgentCredentialRecoveryIssue{}
	err := validatePersistedNativeDeviceCredential(state, ErrInvalidAgentState)
	if !errors.Is(err, ErrCredentialRecoveryRequired) || errors.Is(err, ErrDeviceCredentialMissing) {
		t.Fatalf("pending recovery classification = %v; want recovery-required without device-missing", err)
	}

	state.PendingCredentialRecoveryIssue = nil
	state.DeviceAPIKey = ""
	err = validatePersistedNativeDeviceCredential(state, ErrInvalidAgentState)
	if !errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, ErrDeviceCredentialMissing) {
		t.Fatalf("missing credential classification = %v; want recovery-required plus device-missing", err)
	}
}

func TestOpenRegisteredAgent_RejectsRetiredLifecycleState(t *testing.T) {
	state := completedNativeTestState(t)
	state.Assignment = nil
	state.DeviceAPIKeyID = ""
	store := &memoryAgentStateStore{state: state}
	client, err := OpenRegisteredAgent(context.Background(), store)
	if client != nil || !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("retired state open = client %v, error %v", client, err)
	}
}

func TestOpenRegisteredAgent_RevalidatesCustomStoreAssignment(t *testing.T) {
	state := completedNativeTestState(t)
	state.Assignment.Endpoint.Host = ""
	store := &memoryAgentStateStore{state: state}

	client, err := OpenRegisteredAgent(context.Background(), store)
	if client != nil || !errors.Is(err, ErrInvalidClientConfig) || !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("custom-store assignment error = client %v, error %v; want ErrInvalidClientConfig and ErrInvalidAgentState", client, err)
	}
}

func TestAgentRuntimeBinding_AccidentalCopySharesOneShotKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x5a}, 32)
	binding := &AgentRuntimeBinding{deviceStaticPrivateKey: newAgentRuntimePrivateKey(bytes.Clone(want))}
	copied := *binding
	first := binding.TakeDeviceStaticPrivateKey()
	second := copied.TakeDeviceStaticPrivateKey()
	if !bytes.Equal(first, want) || second != nil {
		t.Fatalf("copy one-shot results = %x / %x, want key / nil", first, second)
	}
	wipeBytes(first)
	binding.Destroy()
	copied.Destroy()
}

func TestAgentRuntimeBinding_ConcurrentCopiesSynchronizeKeyOwnership(t *testing.T) {
	const workers = 32
	for _, test := range []struct {
		name         string
		destroyEvery int
		wantExact    int
	}{
		{name: "concurrent takes", wantExact: 1},
		{name: "take races destroy", destroyEvery: 2, wantExact: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := bytes.Repeat([]byte{0x5a}, 32)
			binding := &AgentRuntimeBinding{deviceStaticPrivateKey: newAgentRuntimePrivateKey(bytes.Clone(want))}
			start := make(chan struct{})
			results := make(chan []byte, workers)
			var group sync.WaitGroup
			for i := 0; i < workers; i++ {
				copied := *binding
				group.Add(1)
				go func(index int) {
					defer group.Done()
					<-start
					if test.destroyEvery > 0 && index%test.destroyEvery == 0 {
						copied.Destroy()
						return
					}
					results <- copied.TakeDeviceStaticPrivateKey()
				}(i)
			}
			close(start)
			group.Wait()
			close(results)

			owned := 0
			for key := range results {
				if key == nil {
					continue
				}
				if !bytes.Equal(key, want) {
					t.Errorf("transferred key = %x, want %x", key, want)
				}
				owned++
				wipeBytes(key)
			}
			binding.Destroy()
			if test.wantExact >= 0 && owned != test.wantExact {
				t.Fatalf("successful key transfers = %d, want %d", owned, test.wantExact)
			}
			if owned > 1 {
				t.Fatalf("successful key transfers = %d, want at most 1", owned)
			}
		})
	}
}

func TestAgentRuntimeBindingFormattingRedactsPrivateKey(t *testing.T) {
	state := completedNativeTestState(t)
	privateKey, err := base64.StdEncoding.Strict().DecodeString(state.PrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	binding := newAgentRuntimeBinding(state, privateKey)
	defer binding.Destroy()
	for _, rendered := range []string{fmt.Sprintf("%v", binding), fmt.Sprintf("%+v", binding), fmt.Sprintf("%#v", binding), fmt.Sprintf("%#v", *binding)} {
		if strings.Contains(rendered, state.PrivateKeyB64) || strings.Contains(rendered, "deviceStaticPrivateKey") || !strings.Contains(rendered, "[REDACTED]") {
			t.Fatalf("runtime binding formatting was not redacted: %s", rendered)
		}
	}
}

func TestAgentRuntimeOptionSetsCompileForIntendedSurfaces(_ *testing.T) {
	// Preserve the original public function signature; recovery has its own Hub
	// option instead of widening this return type and breaking function values.
	acceptRegistrationHubFactory := func(func(HubBootstrap) AgentRuntimeRegistrationOption) {}
	acceptRegistrationHubFactory(WithAgentRuntimeHub)
	acceptClient := func(ClientOption) {}
	acceptRegistration := func(AgentRuntimeRegistrationOption) {}
	acceptRefresh := func(AgentRuntimeRefreshOption) {}
	acceptRecovery := func(AgentRuntimeRecoveryOption) {}
	acceptLifecycle := func(AgentRuntimeLifecycleOption) {}
	acceptUDP := func(AgentRuntimeUDPOption) {}
	acceptRegistration(WithAgentRuntimeHub(runtimeTestHub()))
	acceptRecovery(WithAgentRuntimeRecoveryHub(runtimeTestHub()))
	acceptRegistration(WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAgent))
	acceptRegistration(WithAgentRuntimeUDPBounds(time.Second, 1))
	acceptRefresh(WithAgentRuntimeUDPBounds(time.Second, 1))
	baseURL := WithAgentClientBaseURL("https://api.layerv.ai")
	acceptClient(baseURL)
	acceptRegistration(baseURL)
	acceptRefresh(baseURL)
	acceptRecovery(baseURL)
	acceptLifecycle(baseURL)
	httpClient := WithAgentClientHTTPClient(defaultAPIHTTPClient)
	acceptClient(httpClient)
	acceptRegistration(httpClient)
	acceptRefresh(httpClient)
	acceptRecovery(httpClient)
	acceptLifecycle(httpClient)
	acceptUDP(WithAgentRuntimeUDPBounds(time.Second, 1))
}
