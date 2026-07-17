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
	handledNames := []string{"RegisteredAt", "Assignment", "PendingCompletion"}
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
	cloned := original.clone()
	*cloned.RegisteredAt = cloned.RegisteredAt.Add(time.Hour)
	cloned.Assignment.Endpoint.Host = "changed.nhp.layerv.ai"
	cloned.PendingCompletion.DeviceAPIKey = "changed"

	if original.Assignment.Endpoint.Host != "cell0.nhp.layerv.ai" ||
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
