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

type releaseErrorAgentStateStore struct {
	*memoryAgentStateStore
	closeErr error
}

type setupLockFunc func() error

func (f setupLockFunc) Close() error { return f() }

func (s *releaseErrorAgentStateStore) acquireSetupLock(context.Context) (setupLock, error) {
	return setupLockFunc(func() error { return s.closeErr }), nil
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

func runtimeTestHub() HubBootstrap {
	return HubBootstrap{Host: "hub.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: validTestNHPServerPublicKeyB64}
}

func TestWithAgentSetupLock_CleansSuccessfulResultBeforeZeroingOnReleaseFailure(t *testing.T) {
	releaseErr := errors.New("release failed")
	store := &releaseErrorAgentStateStore{
		memoryAgentStateStore: &memoryAgentStateStore{},
		closeErr:              releaseErr,
	}
	want := new(int)
	cleanupSawResult := false

	got, err := withAgentSetupLock(context.Background(), store, func(result *int) {
		cleanupSawResult = result == want
	}, func() (*int, error) {
		return want, nil
	})

	if got != nil || !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseErr) {
		t.Fatalf("release failure = result %v, error %v; want nil and joined lock/release errors", got, err)
	}
	if !cleanupSawResult {
		t.Fatal("cleanup did not receive the successful result before it was zeroed")
	}
}

func TestWithAgentSetupLock_CleansErrorResultBeforeJoiningReleaseFailure(t *testing.T) {
	releaseErr := errors.New("release failed")
	transitionErr := errors.New("transition failed")
	store := &releaseErrorAgentStateStore{
		memoryAgentStateStore: &memoryAgentStateStore{},
		closeErr:              releaseErr,
	}
	want := new(int)
	cleanupSawResult := false

	got, err := withAgentSetupLock(context.Background(), store, func(result *int) {
		cleanupSawResult = result == want
	}, func() (*int, error) {
		return want, transitionErr
	})

	if got != nil || !errors.Is(err, transitionErr) || !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, releaseErr) {
		t.Fatalf("combined failure = result %v, error %v; want nil and joined transition/lock/release errors", got, err)
	}
	if !cleanupSawResult {
		t.Fatal("cleanup did not receive the error result before it was zeroed")
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

	got, err := withAgentSetupLock(context.Background(), store, destroyNativeRuntimeResult, func() (*nativeRuntimeResult, error) {
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
	handledNames := []string{"RegisteredAt", "Assignment", "PendingActivation", "PendingCompletion"}
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
	cloned := original.clone()
	*cloned.RegisteredAt = cloned.RegisteredAt.Add(time.Hour)
	cloned.Assignment.Endpoint.Host = "changed.nhp.layerv.ai"
	cloned.PendingCompletion.DeviceAPIKey = "changed"
	cloned.PendingActivation.AssignmentTicket = "ticket-changed"
	cloned.PendingActivation.Assignment.CellID = "cell1"

	if original.Assignment.Endpoint.Host != "cell0.nhp.layerv.ai" ||
		original.PendingActivation.AssignmentTicket != "ticket-original" || original.PendingActivation.Assignment.CellID != "cell0" ||
		original.PendingCompletion.DeviceAPIKey != "candidate" ||
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
	acceptClient := func(ClientOption) {}
	acceptRegistration := func(AgentRuntimeRegistrationOption) {}
	acceptRefresh := func(AgentRuntimeRefreshOption) {}
	acceptLifecycle := func(AgentRuntimeLifecycleOption) {}
	acceptUDP := func(AgentRuntimeUDPOption) {}
	acceptRegistration(WithAgentRuntimeHub(runtimeTestHub()))
	acceptRegistration(WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAgent))
	acceptRegistration(WithAgentRuntimeUDPBounds(time.Second, 1))
	acceptRefresh(WithAgentRuntimeUDPBounds(time.Second, 1))
	baseURL := WithAgentClientBaseURL("https://api.layerv.ai")
	acceptClient(baseURL)
	acceptRegistration(baseURL)
	acceptRefresh(baseURL)
	acceptLifecycle(baseURL)
	httpClient := WithAgentClientHTTPClient(defaultAPIHTTPClient)
	acceptClient(httpClient)
	acceptRegistration(httpClient)
	acceptRefresh(httpClient)
	acceptLifecycle(httpClient)
	acceptUDP(WithAgentRuntimeUDPBounds(time.Second, 1))
}
