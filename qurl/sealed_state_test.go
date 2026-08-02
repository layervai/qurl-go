package qurl

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func secureAgentStateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

type localAgentStateStoreFactory struct {
	name string
	new  func(*testing.T) (AgentStateStore, string)
}

func localAgentStateStoreFactories() []localAgentStateStoreFactory {
	return []localAgentStateStoreFactory{
		{name: "plaintext", new: func(t *testing.T) (AgentStateStore, string) {
			path := filepath.Join(secureAgentStateTestDir(t), "agent_state.json")
			return FileAgentState(path), path
		}},
		{name: "sealed", new: func(t *testing.T) (AgentStateStore, string) {
			store := testSealedStore(t, &testAgentStateKeyWrapper{})
			return store, store.path
		}},
	}
}

type testAgentStateKeyWrapper struct {
	mu sync.Mutex

	wrapErr             error
	unwrapErr           error
	unwrapOverride      []byte
	corruptMetadata     bool
	ignoreMetadata      bool
	wrapInputs          [][]byte
	unwrapOutputs       [][]byte
	wrapBindings        []AgentStateKeyBinding
	unwrapBindings      []AgentStateKeyBinding
	unwrapRecords       []WrappedAgentStateKey
	wrappedVersion      int
	wrappedMetadata     json.RawMessage
	wrappedMetadataSize int
}

type blockingAgentStateKeyWrapper struct {
	delegate AgentStateKeyWrapper

	wrapStarted   chan struct{}
	wrapRelease   <-chan struct{}
	wrapStartOnce sync.Once

	unwrapStarted   chan struct{}
	unwrapRelease   <-chan struct{}
	unwrapStartOnce sync.Once
}

type reentrantAgentStateKeyWrapper struct {
	delegate AgentStateKeyWrapper
	store    *SealedFileAgentStateStore
	state    *AgentState
	once     sync.Once
	err      error
}

type serialAgentStateKeyWrapper struct {
	delegate AgentStateKeyWrapper
	mu       sync.Mutex
	calls    int

	firstStarted  chan struct{}
	firstRelease  <-chan struct{}
	secondStarted chan struct{}
}

func (w *serialAgentStateKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, binding AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	w.mu.Lock()
	w.calls++
	call := w.calls
	w.mu.Unlock()
	switch call {
	case 1:
		close(w.firstStarted)
		select {
		case <-w.firstRelease:
		case <-ctx.Done():
			return WrappedAgentStateKey{}, ctx.Err()
		}
	case 2:
		close(w.secondStarted)
	}
	return w.delegate.WrapKey(ctx, plaintextKey, binding)
}

func (w *serialAgentStateKeyWrapper) UnwrapKey(ctx context.Context, record WrappedAgentStateKey, binding AgentStateKeyBinding) ([]byte, error) {
	return w.delegate.UnwrapKey(ctx, record, binding)
}

func (w *reentrantAgentStateKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, binding AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	w.once.Do(func() {
		w.err = w.store.SaveAgentState(ctx, w.state)
	})
	return w.delegate.WrapKey(ctx, plaintextKey, binding)
}

func (w *reentrantAgentStateKeyWrapper) UnwrapKey(ctx context.Context, record WrappedAgentStateKey, binding AgentStateKeyBinding) ([]byte, error) {
	return w.delegate.UnwrapKey(ctx, record, binding)
}

func (w *blockingAgentStateKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, binding AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	if err := waitForBlockingWrapper(ctx, w.wrapStarted, w.wrapRelease, &w.wrapStartOnce); err != nil {
		return WrappedAgentStateKey{}, err
	}
	return w.delegate.WrapKey(ctx, plaintextKey, binding)
}

func (w *blockingAgentStateKeyWrapper) UnwrapKey(ctx context.Context, record WrappedAgentStateKey, binding AgentStateKeyBinding) ([]byte, error) {
	if err := waitForBlockingWrapper(ctx, w.unwrapStarted, w.unwrapRelease, &w.unwrapStartOnce); err != nil {
		return nil, err
	}
	return w.delegate.UnwrapKey(ctx, record, binding)
}

func waitForBlockingWrapper(ctx context.Context, started chan struct{}, release <-chan struct{}, once *sync.Once) error {
	if started == nil {
		return nil
	}
	once.Do(func() { close(started) })
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForTestSignal(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func (w *testAgentStateKeyWrapper) WrapKey(_ context.Context, plaintextKey []byte, binding AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wrapInputs = append(w.wrapInputs, plaintextKey) // retained deliberately: SDK must wipe its isolated input
	w.wrapBindings = append(w.wrapBindings, binding)
	if w.wrapErr != nil {
		return WrappedAgentStateKey{}, w.wrapErr
	}
	key := make([]byte, len(plaintextKey))
	for i := range plaintextKey {
		key[i] = plaintextKey[i] ^ 0xa5
	}
	version := w.wrappedVersion
	if version == 0 {
		version = 7
	}
	metadata := testWrapperMetadata(binding)
	if w.wrappedMetadata != nil {
		metadata = bytes.Clone(w.wrappedMetadata)
	}
	if w.wrappedMetadataSize > 0 {
		metadata = json.RawMessage(`"` + strings.Repeat("m", w.wrappedMetadataSize) + `"`)
	}
	return WrappedAgentStateKey{Version: version, Ciphertext: key, Metadata: metadata}, nil
}

func (w *testAgentStateKeyWrapper) UnwrapKey(_ context.Context, record WrappedAgentStateKey, binding AgentStateKeyBinding) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unwrapBindings = append(w.unwrapBindings, binding)
	w.unwrapRecords = append(w.unwrapRecords, cloneWrappedAgentStateKey(record))
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}
	if record.Version != 7 || w.corruptMetadata || (!w.ignoreMetadata && !sameJSON(record.Metadata, testWrapperMetadata(binding))) {
		return nil, ErrInvalidWrappedAgentStateKey
	}
	if w.unwrapOverride != nil {
		out := bytes.Clone(w.unwrapOverride)
		w.unwrapOutputs = append(w.unwrapOutputs, out)
		return out, nil
	}
	out := make([]byte, len(record.Ciphertext))
	for i := range record.Ciphertext {
		out[i] = record.Ciphertext[i] ^ 0xa5
	}
	w.unwrapOutputs = append(w.unwrapOutputs, out) // retained deliberately: SDK must wipe it
	return out, nil
}

func sameJSON(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}

func testWrapperMetadata(binding AgentStateKeyBinding) json.RawMessage {
	raw, _ := json.Marshal(binding)
	sum := sha256.Sum256(raw)
	metadata, _ := json.Marshal(map[string]string{"binding_sha256": base64.StdEncoding.EncodeToString(sum[:]), "key_id": "test-key"})
	return metadata
}

func testSealedStore(t *testing.T, wrapper *testAgentStateKeyWrapper) *SealedFileAgentStateStore {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSealedFileAgentState(filepath.Join(root, "agent_state.sealed.json"), "test-wrapper", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testAgentState(t *testing.T) *AgentState {
	t.Helper()
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Round(time.Second)
	state.AgentID = "agent-sealed-test"
	state.RegisteredAt = &now
	state.SchemaVersion = agentStateSchemaVersion
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.DeviceAPIKeyID = "key_AbCdEf123456"
	state.Assignment = &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1,
		LeaseExpiresAt: now.Add(time.Hour),
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
			ServerPublicKeyB64: validTestNHPServerPublicKeyB64,
		},
	}
	return state
}

func TestSealedFileAgentState_RoundTripFreshEnvelopeAndZeroization(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	state := testAgentState(t)

	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("first save: %v", err)
	}
	raw1, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw1, []byte(state.DeviceAPIKey)) || bytes.Contains(raw1, []byte(state.PrivateKeyB64)) {
		t.Fatal("sealed file contains plaintext credential material")
	}
	var envelope1 sealedAgentStateEnvelope
	if err := decodeSealedAgentStateEnvelope(raw1, &envelope1); err != nil {
		t.Fatal(err)
	}
	if envelope1.AgentID != state.AgentID || envelope1.ProviderID != "test-wrapper" || envelope1.Purpose != sealedAgentStatePurpose {
		t.Fatalf("unexpected envelope identity: %#v", envelope1)
	}

	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", loaded, state)
	}

	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("second save: %v", err)
	}
	raw2, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope2 sealedAgentStateEnvelope
	if err := decodeSealedAgentStateEnvelope(raw2, &envelope2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(envelope1.Nonce, envelope2.Nonce) || bytes.Equal(envelope1.WrappedKey.Ciphertext, envelope2.WrappedKey.Ciphertext) || bytes.Equal(envelope1.Ciphertext, envelope2.Ciphertext) {
		t.Fatal("successive saves reused nonce, DEK, or ciphertext")
	}

	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}

	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if len(wrapper.wrapInputs) != 2 {
		t.Fatalf("WrapKey calls = %d, want 2", len(wrapper.wrapInputs))
	}
	for i, input := range wrapper.wrapInputs {
		if len(input) != sealedAgentStateDEKBytes || !allZero(input) {
			t.Fatalf("WrapKey input %d was not an isolated, wiped 32-byte buffer: %x", i, input)
		}
	}
	for i, output := range wrapper.unwrapOutputs {
		if len(output) != sealedAgentStateDEKBytes || !allZero(output) {
			t.Fatalf("UnwrapKey output %d was not wiped: %x", i, output)
		}
	}
	wantBinding := AgentStateKeyBinding{Purpose: sealedAgentStatePurpose, EnvelopeVersion: 1, ProviderID: "test-wrapper", AgentID: state.AgentID}
	for _, binding := range append(wrapper.wrapBindings, wrapper.unwrapBindings...) {
		if binding != wantBinding {
			t.Fatalf("binding = %#v, want %#v", binding, wantBinding)
		}
	}
	if len(wrapper.unwrapRecords) == 0 || wrapper.unwrapRecords[len(wrapper.unwrapRecords)-1].Version != 7 || len(wrapper.unwrapRecords[len(wrapper.unwrapRecords)-1].Ciphertext) == 0 || len(wrapper.unwrapRecords[len(wrapper.unwrapRecords)-1].Metadata) == 0 {
		t.Fatal("LoadAgentState did not pass the complete wrapped-key record")
	}
}

func allZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestSealedAgentStateAAD_V1Golden(t *testing.T) {
	envelope := sealedAgentStateEnvelope{
		Version:    1,
		Purpose:    sealedAgentStatePurpose,
		ProviderID: "aws-kms",
		AgentID:    "agent-123",
		WrappedKey: WrappedAgentStateKey{Version: 7, Ciphertext: []byte{1, 2}, Metadata: json.RawMessage(`{"key_id":"k"}`)},
	}
	want := `{"purpose":"qurl-go/agent-state","envelope_version":1,"provider_id":"aws-kms","agent_id":"agent-123","wrapped_key":{"version":7,"ciphertext":"AQI=","metadata":{"key_id":"k"}}}`
	aad, err := envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(aad); got != want {
		t.Fatalf("v1 AAD = %s, want %s", got, want)
	}
}

func TestSealedFileAgentState_MetadataHTMLEscapingRoundTrips(t *testing.T) {
	metadata := json.RawMessage("{\"characters\":\"<>&\u2028\u2029\"}")
	canonical, err := canonicalizeRawJSON(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"characters":"\u003c\u003e\u0026\u2028\u2029"}`; string(canonical) != want {
		t.Fatalf("canonical metadata = %s, want %s", canonical, want)
	}
	envelope := sealedAgentStateEnvelope{
		Version:    sealedAgentStateVersion,
		Purpose:    sealedAgentStatePurpose,
		ProviderID: "test-wrapper",
		AgentID:    "agent-html-test",
		WrappedKey: WrappedAgentStateKey{Version: 7, Ciphertext: []byte{1, 2}, Metadata: metadata},
	}
	beforePersistence, err := envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var reopened sealedAgentStateEnvelope
	if err := json.Unmarshal(persisted, &reopened); err != nil {
		t.Fatal(err)
	}
	afterPersistence, err := reopened.aad()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforePersistence, afterPersistence) {
		t.Fatalf("AAD changed across persistence:\nbefore: %s\nafter:  %s", beforePersistence, afterPersistence)
	}

	wrapper := &testAgentStateKeyWrapper{wrappedMetadata: metadata, ignoreMetadata: true}
	store := testSealedStore(t, wrapper)
	state := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState with HTML-sensitive metadata: %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("round trip = %#v, want %#v", loaded, state)
	}
	assertInvalidSealedMutation(t, store, func(raw []byte) []byte {
		return mutateEnvelopeJSON(t, raw, func(value map[string]any) {
			value["wrapped_key"].(map[string]any)["metadata"] = map[string]any{"characters": "changed<&"}
		})
	})
}

func nestedMetadata(t *testing.T, layers int) json.RawMessage {
	t.Helper()
	var value any = "leaf"
	for range layers {
		value = []any{value}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSealedFileAgentState_RejectsUnreopenableWrapperMetadataBeforeCommit(t *testing.T) {
	tests := []struct {
		name     string
		metadata json.RawMessage
	}{
		{"duplicate keys", json.RawMessage(`{"key_id":"do-not-leak-a","key_id":"do-not-leak-b"}`)},
		{"envelope-relative depth overflow", nestedMetadata(t, maxSealedEnvelopeJSONDepth-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := &testAgentStateKeyWrapper{wrappedMetadata: tt.metadata, ignoreMetadata: true}
			store := testSealedStore(t, wrapper)
			err := store.SaveAgentState(context.Background(), testAgentState(t))
			if !errors.Is(err, ErrAgentStateKeyWrapper) {
				t.Fatalf("SaveAgentState = %v, want ErrAgentStateKeyWrapper", err)
			}
			if errors.Is(err, ErrInvalidAgentState) {
				t.Fatalf("SaveAgentState = %v, must not classify uncommitted wrapper output as corrupt durable state", err)
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("SaveAgentState leaked wrapper metadata: %v", err)
			}
			if _, statErr := os.Stat(store.path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unreopenable metadata committed state: %v", statErr)
			}
		})
	}
}

func TestValidateSealedAgentStateForCommit_ReopensExactPersistedEnvelope(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, sealedAgentStateDEKBytes)
	gcm, err := newSealedAgentStateGCM(dek)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"agent_id":"agent-precommit-test"}`)
	envelope := sealedAgentStateEnvelope{
		Version:    sealedAgentStateVersion,
		Purpose:    sealedAgentStatePurpose,
		ProviderID: "test-wrapper",
		AgentID:    "agent-precommit-test",
		WrappedKey: WrappedAgentStateKey{
			Version:    7,
			Ciphertext: bytes.Repeat([]byte{0x24}, sealedAgentStateDEKBytes),
			Metadata:   json.RawMessage(`{"key_id":"test-key"}`),
		},
		Nonce: bytes.Repeat([]byte{0x11}, gcm.NonceSize()),
	}
	aad, err := envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext = gcm.Seal(nil, envelope.Nonce, plaintext, aad)
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSealedAgentStateForCommit(raw, aad, gcm, plaintext); err != nil {
		t.Fatalf("valid persisted envelope: %v", err)
	}

	envelope.Ciphertext[0] ^= 0x80
	tampered, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSealedAgentStateForCommit(tampered, aad, gcm, plaintext); err == nil {
		t.Fatal("tampered persisted ciphertext: want reopen failure")
	}
}

func TestSealedFileAgentState_MaximumValidMetadataDepthRoundTrips(t *testing.T) {
	// Metadata begins two levels below the envelope root (wrapped_key.metadata),
	// so this many array layers leaves the scalar leaf exactly at the limit.
	metadata := nestedMetadata(t, maxSealedEnvelopeJSONDepth-2)
	wrapper := &testAgentStateKeyWrapper{wrappedMetadata: metadata, ignoreMetadata: true}
	store := testSealedStore(t, wrapper)
	state := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState at depth boundary: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState at depth boundary: %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("round trip = %#v, want %#v", loaded, state)
	}
}

func TestCanonicalizeRawJSON_RejectsInvalidInput(t *testing.T) {
	if _, err := canonicalizeRawJSON(json.RawMessage(`{"key_id":`)); err == nil {
		t.Fatal("canonicalizeRawJSON invalid metadata: want error")
	}
}

func TestNewSealedFileAgentState_ValidatesConfiguration(t *testing.T) {
	var nilWrapper *testAgentStateKeyWrapper
	tests := []struct {
		name       string
		path       string
		providerID string
		wrapper    AgentStateKeyWrapper
	}{
		{"empty path", " ", "test", &testAgentStateKeyWrapper{}},
		{"empty provider", "state", "", &testAgentStateKeyWrapper{}},
		{"noncanonical provider", "state", "AWS-KMS", &testAgentStateKeyWrapper{}},
		{"invalid provider", "state", "aws_kms", &testAgentStateKeyWrapper{}},
		{"trailing provider separator", "state", "aws-kms-", &testAgentStateKeyWrapper{}},
		{"consecutive provider separators", "state", "aws..kms", &testAgentStateKeyWrapper{}},
		{"nil wrapper", "state", "test", nil},
		{"typed nil wrapper", "state", "test", nilWrapper},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSealedFileAgentState(tt.path, tt.providerID, tt.wrapper); !errors.Is(err, ErrInvalidBootstrapConfig) {
				t.Fatalf("got %v, want ErrInvalidBootstrapConfig", err)
			}
		})
	}
}

func TestNewSealedFileAgentState_AcceptsCanonicalProviderID(t *testing.T) {
	store, err := NewSealedFileAgentState(filepath.Join(secureAgentStateTestDir(t), "state"), "aws.kms-v2", &testAgentStateKeyWrapper{})
	if err != nil {
		t.Fatalf("NewSealedFileAgentState: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
}

func TestValidateWrappedAgentStateKey_RejectsZeroVersion(t *testing.T) {
	err := validateWrappedAgentStateKey(WrappedAgentStateKey{Version: 0, Ciphertext: []byte{1}})
	if err == nil || !strings.Contains(err.Error(), "version must be positive") {
		t.Fatalf("zero wrapper version = %v, want positive-version error", err)
	}
}

func TestSealedFileAgentState_ExpectedAgentID(t *testing.T) {
	const (
		expectedID = "agent-expected"
		otherID    = "agent-other"
	)
	if _, err := NewSealedFileAgentState("state", "test", &testAgentStateKeyWrapper{}, nil); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("nil option = %v, want ErrInvalidBootstrapConfig", err)
	}
	if _, err := NewSealedFileAgentState("state", "test", &testAgentStateKeyWrapper{}, WithExpectedSealedAgentID(" ")); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("invalid expected id = %v, want ErrInvalidBootstrapConfig", err)
	}
	if _, err := NewSealedFileAgentState("state", "test", &testAgentStateKeyWrapper{}, WithExpectedSealedAgentID("agent\nexpected")); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("control-character expected id = %v, want ErrInvalidBootstrapConfig", err)
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent_state.sealed.json")
	wrapper := &testAgentStateKeyWrapper{}
	pinned, err := NewSealedFileAgentState(path, "test", wrapper, WithExpectedSealedAgentID(expectedID))
	if err != nil {
		t.Fatal(err)
	}
	state := testAgentState(t)
	state.AgentID = expectedID
	if err := pinned.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save expected agent: %v", err)
	}
	if _, err := pinned.LoadAgentState(context.Background()); err != nil {
		t.Fatalf("load expected agent: %v", err)
	}

	state.AgentID = otherID
	if err := pinned.SaveAgentState(context.Background(), state); !errors.Is(err, ErrInvalidBootstrapConfig) || strings.Contains(err.Error(), otherID) {
		t.Fatalf("save mismatched agent = %v, want non-leaking ErrInvalidBootstrapConfig", err)
	}

	// Persist a valid envelope for another agent through an unpinned store, then
	// prove the pin rejects it before invoking the wrapper at all.
	unpinned, err := NewSealedFileAgentState(path, "test", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := unpinned.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("save other agent through unpinned store: %v", err)
	}
	wrapper.mu.Lock()
	unwrapCalls := len(wrapper.unwrapBindings)
	wrapper.mu.Unlock()
	_, err = pinned.LoadAgentState(context.Background())
	if !errors.Is(err, ErrInvalidAgentState) || strings.Contains(err.Error(), expectedID) || strings.Contains(err.Error(), otherID) {
		t.Fatalf("load mismatched envelope = %v, want non-leaking ErrInvalidAgentState", err)
	}
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if got := len(wrapper.unwrapBindings); got != unwrapCalls {
		t.Fatalf("mismatched pinned load called UnwrapKey %d additional times", got-unwrapCalls)
	}
}

func TestSealedFileAgentState_ControlCharacterAgentIDNeverReachesWrapper(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	state := testAgentState(t)
	state.AgentID = "agent\ncontrol"
	if err := store.SaveAgentState(context.Background(), state); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("save control-character id = %v, want ErrInvalidBootstrapConfig", err)
	}
	wrapper.mu.Lock()
	if got := len(wrapper.wrapBindings); got != 0 {
		wrapper.mu.Unlock()
		t.Fatalf("control-character save reached WrapKey %d times", got)
	}
	wrapper.mu.Unlock()

	state.AgentID = "agent-valid"
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	raw = mutateEnvelopeJSON(t, raw, func(value map[string]any) {
		value["agent_id"] = "agent\u0000control"
	})
	if err := os.WriteFile(store.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper.mu.Lock()
	unwrapCalls := len(wrapper.unwrapBindings)
	wrapper.mu.Unlock()
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("load control-character id = %v, want ErrInvalidAgentState", err)
	}
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if got := len(wrapper.unwrapBindings); got != unwrapCalls {
		t.Fatalf("control-character load reached UnwrapKey %d additional times", got-unwrapCalls)
	}
}

func TestSealedFileAgentState_ReportsNestingLimitAccurately(t *testing.T) {
	store := testSealedStore(t, &testAgentStateKeyWrapper{})
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	raw = mutateEnvelopeJSON(t, raw, func(value map[string]any) {
		var nested any = "leaf"
		for range maxSealedEnvelopeJSONDepth + 1 {
			nested = []any{nested}
		}
		value["wrapped_key"].(map[string]any)["metadata"] = nested
	})
	if err := os.WriteFile(store.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = store.LoadAgentState(context.Background())
	if !errors.Is(err, ErrInvalidAgentState) || !strings.Contains(err.Error(), "JSON nesting exceeds limit") || strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("deeply nested envelope = %v, want accurate ErrInvalidAgentState nesting error", err)
	}
}

func TestSealedFileAgentState_StoreSentinelsAndContext(t *testing.T) {
	store := testSealedStore(t, &testAgentStateKeyWrapper{})
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateNotFound) {
		t.Fatalf("missing load = %v, want ErrAgentStateNotFound", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load = %v", err)
	}
	if err := store.SaveAgentState(ctx, testAgentState(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save = %v", err)
	}
	if err := store.SaveAgentState(context.Background(), nil); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("nil save = %v", err)
	}
	state := testAgentState(t)
	state.AgentID = " noncanonical "
	if err := store.SaveAgentState(context.Background(), state); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("noncanonical id save = %v", err)
	}
}

func TestLocalAgentStateStoreContract(t *testing.T) {
	for _, tt := range localAgentStateStoreFactories() {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := tt.new(t)
			if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateNotFound) {
				t.Fatalf("empty load = %v, want ErrAgentStateNotFound", err)
			}
			state := testAgentState(t)
			if err := store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			state.DeviceAPIKey = "mutated-after-save"
			loaded, err := store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if loaded.DeviceAPIKey != canonicalNativeDeviceCredential {
				t.Fatal("store retained caller state pointer instead of snapshotting on save")
			}
			loaded.DeviceAPIKey = "mutated-after-load"
			reloaded, err := store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.DeviceAPIKey != canonicalNativeDeviceCredential {
				t.Fatal("store shared loaded state pointer across calls")
			}
		})
	}
}

func TestLocalAgentStateStores_PendingActivationRoundTripWithoutPlainCredential(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range localAgentStateStoreFactories() {
		t.Run(tt.name, func(t *testing.T) {
			state, err := newAgentState()
			if err != nil {
				t.Fatal(err)
			}
			state.AgentID = "agent-conform"
			state.Assignment = initial.Assignment.clone()
			state.SchemaVersion = agentStateSchemaVersion
			state.PendingActivation, err = newPendingAgentActivation(
				initial, state, "connector-host", "qurl-go/test",
				conformance.AgentAssignmentBootstrapCredentialFixture,
			)
			if err != nil {
				t.Fatal(err)
			}
			store, path := tt.new(t)
			if err := store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			atRest, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if loaded.PendingActivation == nil || loaded.PendingActivation.AssignmentTicket != initial.AssignmentTicket ||
				!sameAgentAssignment(&loaded.PendingActivation.Assignment, loaded.Assignment) ||
				!loaded.PendingActivation.RecoveryAnchorTicketExpiresAt.Equal(initial.AssignmentTicketExpiresAt) ||
				!loaded.PendingActivation.RecoveryExpiresAt.Equal(initial.AssignmentTicketExpiresAt.Add(AgentRegistrationRecoveryHorizon)) {
				t.Fatalf("pending activation did not round trip: %#v", loaded.PendingActivation)
			}
			raw, err := json.Marshal(loaded)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{
				conformance.AgentAssignmentBootstrapCredentialFixture,
				"12345678",
				canonicalNativeDeviceCredential,
			} {
				if bytes.Contains(raw, []byte(secret)) || bytes.Contains(atRest, []byte(secret)) {
					t.Fatalf("pending activation exposed a plaintext secret in decoded or at-rest state: decoded=%s at-rest=%s", raw, atRest)
				}
			}
		})
	}
}

func TestAgentStateFileStores_LargeStateParityAndOverCapNoCommit(t *testing.T) {
	for _, tt := range localAgentStateStoreFactories() {
		t.Run(tt.name, func(t *testing.T) {
			store, path := tt.new(t)
			state := testAgentState(t)
			state.DeviceAPIKey = strings.Repeat("k", 512<<10)
			if err := store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if loaded.DeviceAPIKey != state.DeviceAPIKey {
				t.Fatal("large AgentState credential did not round trip")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			state.DeviceAPIKey = strings.Repeat("k", maxAgentStateBytes)
			if err := store.SaveAgentState(context.Background(), state); !errors.Is(err, ErrInvalidBootstrapConfig) {
				t.Fatalf("oversized save = %v, want ErrInvalidBootstrapConfig", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("oversized save replaced previously committed state")
			}
			reloaded, err := store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.DeviceAPIKey != loaded.DeviceAPIKey {
				t.Fatal("oversized save changed the loadable committed state")
			}
		})
	}
}

func TestSealedFileAgentState_KeyWrapperFailures(t *testing.T) {
	sentinel := errors.New("provider unavailable")
	tests := []struct {
		name    string
		wrapper *testAgentStateKeyWrapper
	}{
		{"wrap error", &testAgentStateKeyWrapper{wrapErr: sentinel}},
		{"verification unwrap error", &testAgentStateKeyWrapper{unwrapErr: sentinel}},
		{"short verification DEK", &testAgentStateKeyWrapper{unwrapOverride: make([]byte, 31)}},
		{"wrong verification DEK", &testAgentStateKeyWrapper{unwrapOverride: bytes.Repeat([]byte{9}, 32)}},
		{"invalid record version", &testAgentStateKeyWrapper{wrappedVersion: -1}},
		{"oversized metadata", &testAgentStateKeyWrapper{wrappedMetadataSize: maxWrappedAgentStateMetadata + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := testSealedStore(t, tt.wrapper)
			if err := store.SaveAgentState(context.Background(), testAgentState(t)); !errors.Is(err, ErrAgentStateKeyWrapper) {
				t.Fatalf("save = %v, want ErrAgentStateKeyWrapper", err)
			}
			if _, err := os.Stat(store.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed save committed state: %v", err)
			}
		})
	}
}

type terminalErrorReader struct{ err error }

func (r terminalErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestSealedFileAgentState_RandomnessFailuresDoNotCommit(t *testing.T) {
	sentinel := errors.New("random source failed")
	tests := []struct {
		name   string
		reader io.Reader
	}{
		{"DEK", terminalErrorReader{sentinel}},
		{"nonce", io.MultiReader(bytes.NewReader(make([]byte, 32)), terminalErrorReader{sentinel})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := testSealedStore(t, &testAgentStateKeyWrapper{})
			store.random = tt.reader
			if err := store.SaveAgentState(context.Background(), testAgentState(t)); !errors.Is(err, sentinel) {
				t.Fatalf("save = %v, want random error", err)
			}
			if _, err := os.Stat(store.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed save committed state: %v", err)
			}
		})
	}
}

func TestSealedFileAgentState_PostRenameDirectorySyncFailureIsRecoverable(t *testing.T) {
	sentinel := errors.New("injected file failure")
	store := testSealedStore(t, &testAgentStateKeyWrapper{})
	original := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	updated := *original
	updated.DeviceAPIKey = "lv_device_updated"
	originalSync := store.dir.impl.hooks.syncFD
	syncCalls := 0
	store.dir.impl.hooks.syncFD = func(fd int) error {
		syncCalls++
		if syncCalls == 2 {
			return sentinel
		}
		return originalSync(fd)
	}
	err := store.SaveAgentState(context.Background(), &updated)
	if !errors.Is(err, sentinel) {
		t.Fatalf("save = %v, want injected error", err)
	}
	store.dir.impl.hooks.syncFD = originalSync
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".qurl-sealed-agent-state-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("failed save left temporary files: %v", temps)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceAPIKey != updated.DeviceAPIKey {
		t.Fatalf("post-rename sync failure visible state = %q, want committed %q", loaded.DeviceAPIKey, updated.DeviceAPIKey)
	}
}

func TestSealedFileAgentState_CloseWaitsForWholeUnwrapOperation(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, AgentStateStore) error
	}{
		{"load", func(ctx context.Context, store AgentStateStore) error {
			_, err := store.LoadAgentState(ctx)
			return err
		}},
		{"open registered agent", func(ctx context.Context, store AgentStateStore) error {
			_, err := OpenRegisteredAgent(ctx, store)
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			delegate := &testAgentStateKeyWrapper{}
			store := testSealedStore(t, delegate)
			if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			release := make(chan struct{})
			store.wrapper = &blockingAgentStateKeyWrapper{
				delegate:      delegate,
				unwrapStarted: started,
				unwrapRelease: release,
			}
			operationDone := make(chan error, 1)
			go func() { operationDone <- operation.run(context.Background(), store) }()
			waitForTestSignal(t, started, "blocked UnwrapKey")
			closeDone := make(chan error, 1)
			go func() { closeDone <- store.Close() }()
			select {
			case err := <-closeDone:
				t.Fatalf("Close returned while UnwrapKey was in flight: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if err := <-operationDone; err != nil {
				t.Fatalf("operation after unblocking wrapper: %v", err)
			}
			if err := <-closeDone; err != nil {
				t.Fatalf("Close after whole operation completed: %v", err)
			}
		})
	}
}

func TestSealedFileAgentState_CloseWaitsForWholeWrapAndCommitOperation(t *testing.T) {
	delegate := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, delegate)
	original := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	updated := original.clone()
	updated.DeviceAPIKey = "lv_device_close_serialized"
	started := make(chan struct{})
	release := make(chan struct{})
	store.wrapper = &blockingAgentStateKeyWrapper{
		delegate:    delegate,
		wrapStarted: started,
		wrapRelease: release,
	}
	saveDone := make(chan error, 1)
	go func() { saveDone <- store.SaveAgentState(context.Background(), updated) }()
	waitForTestSignal(t, started, "blocked WrapKey")
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while WrapKey was in flight: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-saveDone; err != nil {
		t.Fatalf("SaveAgentState after unblocking wrapper: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close after whole save completed: %v", err)
	}
}

func TestSealedFileAgentState_SaveCannotBypassHeldLifecycleLock(t *testing.T) {
	delegate := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, delegate)
	defer func() { _ = store.Close() }()
	original := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	updated := original.clone()
	updated.DeviceAPIKey = "lv_device_serialized_update"
	wrapStarted := make(chan struct{})
	wrapRelease := make(chan struct{})
	store.wrapper = &blockingAgentStateKeyWrapper{
		delegate:    delegate,
		wrapStarted: wrapStarted,
		wrapRelease: wrapRelease,
	}
	lockedLoaded := make(chan struct{})
	releaseLifecycle := make(chan struct{})
	lifecycleDone := make(chan error, 1)
	go func() {
		_, err := withAgentSetupLock(context.Background(), store, func(struct{}) {}, func(lockedCtx context.Context, locked AgentStateStore) (struct{}, error) {
			loaded, err := locked.LoadAgentState(lockedCtx)
			if err != nil {
				return struct{}{}, err
			}
			if loaded.DeviceAPIKey != original.DeviceAPIKey {
				return struct{}{}, fmt.Errorf("locked load observed %q, want original %q", loaded.DeviceAPIKey, original.DeviceAPIKey)
			}
			close(lockedLoaded)
			<-releaseLifecycle
			return struct{}{}, nil
		})
		lifecycleDone <- err
	}()
	waitForTestSignal(t, lockedLoaded, "lifecycle lock and load")
	saveDone := make(chan error, 1)
	go func() { saveDone <- store.SaveAgentState(context.Background(), updated) }()
	select {
	case <-wrapStarted:
		t.Fatal("concurrent SaveAgentState entered WrapKey before acquiring the held lifecycle lock")
	case <-time.After(75 * time.Millisecond):
	}
	close(releaseLifecycle)
	if err := <-lifecycleDone; err != nil {
		t.Fatalf("locked lifecycle: %v", err)
	}
	waitForTestSignal(t, wrapStarted, "serialized SaveAgentState wrapper")
	close(wrapRelease)
	if err := <-saveDone; err != nil {
		t.Fatalf("serialized SaveAgentState: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceAPIKey != updated.DeviceAPIKey {
		t.Fatalf("final serialized state = %q, want %q", loaded.DeviceAPIKey, updated.DeviceAPIKey)
	}
}

func TestSealedFileAgentState_WrapperReentrantSaveFailsPromptly(t *testing.T) {
	delegate := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, delegate)
	defer func() { _ = store.Close() }()
	state := testAgentState(t)
	reentrant := &reentrantAgentStateKeyWrapper{
		delegate: delegate,
		store:    store,
		state:    state.clone(),
	}
	store.wrapper = reentrant

	start := time.Now()
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("outer SaveAgentState: %v", err)
	}
	if !errors.Is(reentrant.err, ErrAgentSetupLock) {
		t.Fatalf("reentrant SaveAgentState = %v, want ErrAgentSetupLock", reentrant.err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("reentrant SaveAgentState took %v; want prompt failure", elapsed)
	}
}

func TestSealedFileAgentState_ConcurrentSavesSerializeBeforeWrapKey(t *testing.T) {
	delegate := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, delegate)
	defer func() { _ = store.Close() }()
	firstRelease := make(chan struct{})
	wrapper := &serialAgentStateKeyWrapper{
		delegate:      delegate,
		firstStarted:  make(chan struct{}),
		firstRelease:  firstRelease,
		secondStarted: make(chan struct{}),
	}
	store.wrapper = wrapper
	first := testAgentState(t)
	second := first.clone()
	second.DeviceAPIKey = "lv_device_second_serial_save"

	firstDone := make(chan error, 1)
	go func() { firstDone <- store.SaveAgentState(context.Background(), first) }()
	waitForTestSignal(t, wrapper.firstStarted, "first SaveAgentState WrapKey")
	secondDone := make(chan error, 1)
	go func() { secondDone <- store.SaveAgentState(context.Background(), second) }()
	select {
	case <-wrapper.secondStarted:
		t.Fatal("second SaveAgentState entered WrapKey while the first save held the setup lock")
	case <-time.After(75 * time.Millisecond):
	}
	close(firstRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("first SaveAgentState: %v", err)
	}
	waitForTestSignal(t, wrapper.secondStarted, "second SaveAgentState WrapKey")
	if err := <-secondDone; err != nil {
		t.Fatalf("second SaveAgentState: %v", err)
	}
}

func TestSealedFileAgentState_LoadWrapperOperationalVsInvalid(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	wrapper.unwrapErr = errors.New("KMS timeout")
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateKeyWrapper) || errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("operational unwrap = %v, want wrapper failure only", err)
	}
	wrapper.unwrapErr = ErrInvalidWrappedAgentStateKey
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("invalid wrapped key = %v, want ErrInvalidAgentState", err)
	}
	wrapper.unwrapErr = nil
	wrapper.unwrapOverride = make([]byte, 31)
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateKeyWrapper) || errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("wrong-length unwrap = %v, want ErrAgentStateKeyWrapper only", err)
	}
}

func TestSealedFileAgentState_RejectsInsecureDirectoryAndOversizeFile(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewSealedFileAgentState(filepath.Join(dir, "state.json"), "test", wrapper); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("open in 0750 dir = %v", err)
	}

	dir2 := t.TempDir()
	if err := os.Chmod(dir2, 0o700); err != nil {
		t.Fatal(err)
	}
	store2, err := NewSealedFileAgentState(filepath.Join(dir2, "state.json"), "test", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store2.path, bytes.Repeat([]byte{'x'}, maxSealedAgentStateEnvelope+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("oversized load = %v, want ErrInvalidAgentState", err)
	}
}

func assertInvalidSealedMutation(t *testing.T, store *SealedFileAgentStateStore, mutate func([]byte) []byte) {
	t.Helper()
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	raw = mutate(raw)
	if err := os.WriteFile(store.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("tampered load = %v, want ErrInvalidAgentState", err)
	}
}

func mutateEnvelopeJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSealedFileAgentState_TamperAndStrictDecode(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, []byte) []byte
	}{
		{"version", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["version"] = float64(2) })
		}},
		{"purpose", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["purpose"] = "other" })
		}},
		{"outer agent", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["agent_id"] = "agent-other" })
		}},
		{"provider", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["provider_id"] = "other" })
		}},
		{"wrapped key", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["wrapped_key"].(map[string]any)["ciphertext"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
			})
		}},
		{"oversized wrapped key", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["wrapped_key"].(map[string]any)["ciphertext"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, maxWrappedAgentStateKeyBytes+1))
			})
		}},
		{"wrapped metadata", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["wrapped_key"].(map[string]any)["metadata"] = map[string]any{"key_id": "other"}
			})
		}},
		{"oversized wrapped metadata", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["wrapped_key"].(map[string]any)["metadata"] = strings.Repeat("m", maxWrappedAgentStateMetadata+1)
			})
		}},
		{"nonce", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["nonce"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 12)) })
		}},
		{"ciphertext", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["ciphertext"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			})
		}},
		{"oversized ciphertext", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) {
				v["ciphertext"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, maxAgentStateBytes+17))
			})
		}},
		{"unknown field", func(t *testing.T, raw []byte) []byte {
			return mutateEnvelopeJSON(t, raw, func(v map[string]any) { v["unexpected"] = true })
		}},
		{"trailing data", func(_ *testing.T, raw []byte) []byte { return append(raw, []byte(` {}`)...) }},
		{"duplicate top-level field", func(_ *testing.T, raw []byte) []byte { return append([]byte(`{"version":1,`), raw[1:]...) }},
		{"duplicate nested metadata field", func(_ *testing.T, raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"key_id": "test-key"`), []byte(`"key_id":"test-key","key_id":"duplicate"`), 1)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := testSealedStore(t, &testAgentStateKeyWrapper{})
			if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
				t.Fatal(err)
			}
			assertInvalidSealedMutation(t, store, func(raw []byte) []byte { return tt.mutate(t, raw) })
		})
	}
}

func TestSealedFileAgentState_MetadataIsEnvelopeAuthenticated(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	// Simulate a wrapper that does not consume metadata at all. The SDK's own
	// AES-GCM AAD must still reject a metadata-only edit.
	wrapper.ignoreMetadata = true
	assertInvalidSealedMutation(t, store, func(raw []byte) []byte {
		return mutateEnvelopeJSON(t, raw, func(value map[string]any) {
			value["wrapped_key"].(map[string]any)["metadata"] = map[string]any{"key_id": "tampered"}
		})
	})
}

func TestSealedFileAgentState_SetupLockFailuresFailClosed(t *testing.T) {
	store := testSealedStore(t, &testAgentStateKeyWrapper{})
	state := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	originalSync := store.dir.impl.hooks.syncFD
	lockSyncCalls := 0
	lockFailure := errors.New("lock directory sync unavailable")
	store.dir.impl.hooks.syncFD = func(int) error {
		lockSyncCalls++
		return lockFailure
	}

	networkCalls := 0
	refusing := doerFunc(func(*http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("network must not be used on completed runtime fast path")
	})
	client, binding, err := RegisterAgentRuntime(context.Background(), "unused-on-runtime-fast-path", store,
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentClientHTTPClient(refusing),
	)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("completed runtime fast path must not acquire setup lock: client %v, binding %v, error %v", client, binding, err)
	}
	binding.Destroy()
	if lockSyncCalls != 0 {
		t.Fatalf("completed runtime fast path setup-lock sync calls = %d, want 0", lockSyncCalls)
	}
	if networkCalls != 0 {
		t.Fatalf("completed runtime fast path network calls = %d, want 0", networkCalls)
	}
	store.dir.impl.hooks.syncFD = originalSync

	incomplete, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	incomplete.AgentID = "agent-sealed-test"
	incomplete.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(context.Background(), incomplete); err != nil {
		t.Fatal(err)
	}
	store.dir.impl.hooks.syncFD = func(int) error { return lockFailure }
	if _, _, err := RegisterAgentRuntime(context.Background(), "enrollment-key", store, WithAgentRuntimeHub(runtimeTestHub())); !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, lockFailure) {
		t.Fatalf("acquire failure = %v, want ErrAgentSetupLock", err)
	}
	store.dir.impl.hooks.syncFD = originalSync
}

func TestSealedFileAgentState_RejectsInnerOuterAgentMismatch(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope sealedAgentStateEnvelope
	if err := decodeSealedAgentStateEnvelope(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	dek, err := wrapper.UnwrapKey(context.Background(), cloneWrappedAgentStateKey(envelope.WrappedKey), envelope.binding())
	if err != nil {
		t.Fatal(err)
	}
	aad, err := envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := openSealedAgentState(dek, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	var state AgentState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		t.Fatal(err)
	}
	state.AgentID = "agent-inner-other"
	plaintext, _ = json.Marshal(state)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	aad, err = envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext = gcm.Seal(nil, envelope.Nonce, plaintext, aad)
	tampered, _ := json.Marshal(envelope)
	if err := os.WriteFile(store.path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("inner mismatch = %v, want ErrInvalidAgentState", err)
	}
}

func TestSealedFileAgentState_RejectsUnknownNativeStateField(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{}
	store := testSealedStore(t, wrapper)
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope sealedAgentStateEnvelope
	if err := decodeSealedAgentStateEnvelope(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	dek, err := wrapper.UnwrapKey(context.Background(), cloneWrappedAgentStateKey(envelope.WrappedKey), envelope.binding())
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(dek)
	aad, err := envelope.aad()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := openSealedAgentState(dek, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(plaintext)
	mutated := append(bytes.Clone(bytes.TrimSuffix(plaintext, []byte("}"))), []byte(`,"retired_http_field":true}`)...)
	defer wipeBytes(mutated)
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext = gcm.Seal(nil, envelope.Nonce, mutated, aad)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("unknown inner field error = %v, want ErrInvalidAgentState", err)
	}
}

func TestSealedFileAgentState_ErrorMessagesDoNotLeakSecrets(t *testing.T) {
	wrapper := &testAgentStateKeyWrapper{wrapErr: errors.New("provider refused")}
	store := testSealedStore(t, wrapper)
	state := testAgentState(t)
	err := store.SaveAgentState(context.Background(), state)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, secret := range []string{state.DeviceAPIKey, state.PrivateKeyB64} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked secret %q: %v", secret, err)
		}
	}
}

func TestSealedFileAgentState_RejectsSymlink(t *testing.T) {
	dir := secureAgentStateTestDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	store, err := NewSealedFileAgentState(link, "test", &testAgentStateKeyWrapper{})
	if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("symlink open = %v, want invalid-state continuity error", err)
	}
	if store != nil {
		t.Fatal("symlink open returned a store")
	}
}

func TestSealedFileAgentState_EnvelopeDoesNotFormatSecretOnDecodeError(t *testing.T) {
	store := testSealedStore(t, &testAgentStateKeyWrapper{})
	secret := "lv_device_should_not_appear"
	if err := os.WriteFile(store.path, []byte(fmt.Sprintf(`{"ciphertext":%q}`, secret)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.LoadAgentState(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("decode error leaked input: %v", err)
	}
}
