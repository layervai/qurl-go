package qurl

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	sealedAgentStatePurpose       = "qurl-go/agent-state"
	sealedAgentStateVersion       = 1
	sealedAgentStateDEKBytes      = 32
	maxSealedAgentStateBytes      = 1 << 20
	maxSealedAgentStateEnvelope   = 2 << 20
	maxWrappedAgentStateKeyBytes  = 64 << 10
	maxWrappedAgentStateMetadata  = 16 << 10
	maxSealedAgentStateAgentID    = 256
	maxSealedAgentStateProviderID = 64
	maxSealedEnvelopeJSONDepth    = 32
)

var providerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)

// ErrAgentStateKeyWrapper reports an operational failure from an
// AgentStateKeyWrapper. It is distinct from ErrInvalidAgentState: an unavailable
// KMS must not be misdiagnosed as corrupt durable state.
var ErrAgentStateKeyWrapper = errors.New("qurl: agent state key wrapper failed")

// ErrInvalidWrappedAgentStateKey is returned by AgentStateKeyWrapper
// implementations when a persisted wrapped-key record is malformed, has been
// tampered with, or cannot authenticate under its binding. SealedFileAgentState
// maps this implementor-facing sentinel to ErrInvalidAgentState.
var ErrInvalidWrappedAgentStateKey = errors.New("qurl: invalid wrapped agent state key")

// AgentStateKeyBinding is the authenticated domain passed to every key-wrapper
// operation. A KMS adapter must bind all four fields in its encryption context
// (or equivalent authenticated data); omitting a field permits a wrapped DEK to
// be replayed across state files or identities.
type AgentStateKeyBinding struct {
	Purpose         string
	EnvelopeVersion int
	ProviderID      string
	AgentID         string
}

// WrappedAgentStateKey is the opaque wrapped DEK record persisted in a sealed
// AgentState envelope. Version is owned by the wrapper implementation.
// Ciphertext is the provider-wrapped DEK. Metadata is optional provider-owned
// JSON; the SDK validates, bounds, and authenticates it as envelope AAD but does
// not interpret it. A wrapper that uses metadata before AES-GCM verification
// must also authenticate it as part of its own wrapped-key record.
type WrappedAgentStateKey struct {
	Version    int             `json:"version"`
	Ciphertext []byte          `json:"ciphertext"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// AgentStateKeyWrapper wraps and unwraps exactly one 32-byte AES-256 data key.
// Implementations must authenticate every field in binding and return
// ErrInvalidWrappedAgentStateKey for a record that fails provider
// authentication. Other provider/network failures should be returned normally
// so callers can distinguish an outage from corrupt state. If a provider cannot
// distinguish authentication failure from other decrypt failures, it must fail
// closed by returning ErrInvalidWrappedAgentStateKey rather than classifying
// possible tampering as a retryable outage.
//
// Implementations must not retain, log, or otherwise expose plaintextKey or a
// key returned by UnwrapKey. The SDK wipes the byte slices it owns after use.
type AgentStateKeyWrapper interface {
	WrapKey(ctx context.Context, plaintextKey []byte, binding AgentStateKeyBinding) (WrappedAgentStateKey, error)
	UnwrapKey(ctx context.Context, wrapped WrappedAgentStateKey, binding AgentStateKeyBinding) ([]byte, error)
}

// SealedFileAgentStateStore atomically stores a complete AgentState in an
// SDK-owned AES-256-GCM envelope. Only a freshly generated 32-byte DEK crosses
// the AgentStateKeyWrapper boundary; AgentState JSON never does.
type SealedFileAgentStateStore struct {
	fileSetupLock
	providerID string
	wrapper    AgentStateKeyWrapper
	random     io.Reader
	fileOps    privateStateFileOps
}

// NewSealedFileAgentState constructs a sealed local AgentStateStore. providerID
// is a stable, lowercase identifier for the selected wrapper (for example
// "aws-kms" or "gcp-confidential-space") and is authenticated by both AES-GCM
// and the wrapper's own binding.
//
// A successful SaveAgentState performs both WrapKey and UnwrapKey before the
// atomic commit: two provider operations per save. Consequently every identity
// that can mutate AgentState needs both wrap/encrypt and unwrap/decrypt
// permission.
func NewSealedFileAgentState(path, providerID string, wrapper AgentStateKeyWrapper) (*SealedFileAgentStateStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: sealed agent state path must not be empty", ErrInvalidBootstrapConfig)
	}
	if err := validateProviderID(providerID); err != nil {
		return nil, err
	}
	if isNilAgentStateKeyWrapper(wrapper) {
		return nil, fmt.Errorf("%w: agent state key wrapper must not be nil", ErrInvalidBootstrapConfig)
	}
	return &SealedFileAgentStateStore{
		fileSetupLock: fileSetupLock{path: path, lockFile: lockFileExclusive},
		providerID:    providerID,
		wrapper:       wrapper,
		random:        rand.Reader,
		fileOps:       defaultPrivateStateFileOps,
	}, nil
}

func isNilAgentStateKeyWrapper(wrapper AgentStateKeyWrapper) bool {
	if wrapper == nil {
		return true
	}
	v := reflect.ValueOf(wrapper)
	kind := v.Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func validateProviderID(providerID string) error {
	if providerID == "" || providerID != strings.TrimSpace(providerID) || providerID != strings.ToLower(providerID) ||
		len(providerID) > maxSealedAgentStateProviderID || !providerIDPattern.MatchString(providerID) {
		return fmt.Errorf("%w: provider id must be 1-%d lowercase characters matching %s", ErrInvalidBootstrapConfig, maxSealedAgentStateProviderID, providerIDPattern.String())
	}
	return nil
}

func normalizeSealedAgentID(agentID string) (string, error) {
	normalized := strings.TrimSpace(agentID)
	if normalized == "" || normalized != agentID || !utf8.ValidString(normalized) || len(normalized) > maxSealedAgentStateAgentID {
		return "", fmt.Errorf("agent id must be non-empty, canonical (no surrounding whitespace), and at most %d bytes", maxSealedAgentStateAgentID)
	}
	return normalized, nil
}

// LoadAgentState authenticates, unwraps, and decrypts the sealed envelope.
func (s *SealedFileAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	raw, err := readPrivateStateFileBounded(s.path, "sealed agent state", maxSealedAgentStateEnvelope, true, ErrAgentStateNotFound, ErrInvalidAgentState, ErrInsecureAgentStatePermissions)
	if err != nil {
		var tooLarge *inputExceedsCapError
		if errors.As(err, &tooLarge) {
			return nil, invalidSealedState("envelope exceeds size limit")
		}
		return nil, err
	}
	var envelope sealedAgentStateEnvelope
	if err := decodeSealedAgentStateEnvelope(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.ProviderID != s.providerID {
		return nil, invalidSealedState("provider id does not match configured wrapper")
	}
	binding := envelope.binding()
	dek, err := s.wrapper.UnwrapKey(ctx, cloneWrappedAgentStateKey(envelope.WrappedKey), binding)
	if err != nil {
		if errors.Is(err, ErrInvalidWrappedAgentStateKey) {
			return nil, invalidSealedState("wrapped key authentication failed")
		}
		return nil, fmt.Errorf("%w: unwrap sealed agent state DEK: %w", ErrAgentStateKeyWrapper, err)
	}
	defer wipeBytes(dek)
	if len(dek) != sealedAgentStateDEKBytes {
		return nil, fmt.Errorf("%w: unwrap returned a DEK with invalid length", ErrAgentStateKeyWrapper)
	}
	aad, err := envelope.aad()
	if err != nil {
		return nil, fmt.Errorf("qurl: encode sealed agent state AAD: %w", err)
	}
	plaintext, err := openSealedAgentState(dek, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, invalidSealedState("envelope authentication failed")
	}
	defer wipeBytes(plaintext)
	var state AgentState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, invalidSealedState("decrypted agent state is not valid JSON")
	}
	innerID, err := normalizeSealedAgentID(state.AgentID)
	if err != nil || innerID != envelope.AgentID {
		return nil, invalidSealedState("authenticated outer agent id does not match decrypted state")
	}
	return &state, nil
}

// SaveAgentState encrypts the complete state with a fresh DEK and nonce, verifies
// the new wrapped key by unwrapping it, then atomically commits the envelope.
func (s *SealedFileAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("%w: state must not be nil", ErrInvalidBootstrapConfig)
	}
	agentID, err := normalizeSealedAgentID(state.AgentID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBootstrapConfig, err)
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("qurl: encode agent state: %w", err)
	}
	defer wipeBytes(plaintext)
	if len(plaintext) > maxSealedAgentStateBytes {
		return fmt.Errorf("%w: encoded agent state exceeds %d bytes", ErrInvalidBootstrapConfig, maxSealedAgentStateBytes)
	}

	dek := make([]byte, sealedAgentStateDEKBytes)
	defer wipeBytes(dek)
	if _, err := io.ReadFull(s.random, dek); err != nil {
		return fmt.Errorf("qurl: generate agent state DEK: %w", err)
	}
	binding := AgentStateKeyBinding{
		Purpose:         sealedAgentStatePurpose,
		EnvelopeVersion: sealedAgentStateVersion,
		ProviderID:      s.providerID,
		AgentID:         agentID,
	}
	wrapInput := bytes.Clone(dek)
	wrapped, err := s.wrapper.WrapKey(ctx, wrapInput, binding)
	wipeBytes(wrapInput)
	if err != nil {
		return fmt.Errorf("%w: wrap sealed agent state DEK: %w", ErrAgentStateKeyWrapper, err)
	}
	if err := validateWrappedAgentStateKey(wrapped); err != nil {
		return fmt.Errorf("%w: wrapper returned invalid wrapped key: %w", ErrAgentStateKeyWrapper, err)
	}
	wrapped = cloneWrappedAgentStateKey(wrapped)
	verificationRecord := cloneWrappedAgentStateKey(wrapped)
	verifiedDEK, err := s.wrapper.UnwrapKey(ctx, verificationRecord, binding)
	if err != nil {
		return fmt.Errorf("%w: verify wrapped agent state DEK: %w", ErrAgentStateKeyWrapper, err)
	}
	defer wipeBytes(verifiedDEK)
	if len(verifiedDEK) != sealedAgentStateDEKBytes || subtle.ConstantTimeCompare(dek, verifiedDEK) != 1 {
		return fmt.Errorf("%w: wrapped-key verification did not reproduce the 32-byte DEK", ErrAgentStateKeyWrapper)
	}

	gcm, err := newSealedAgentStateGCM(dek)
	if err != nil {
		return fmt.Errorf("qurl: initialize agent state AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return fmt.Errorf("qurl: generate agent state nonce: %w", err)
	}
	envelope := sealedAgentStateEnvelope{
		Version:    sealedAgentStateVersion,
		Purpose:    sealedAgentStatePurpose,
		AgentID:    agentID,
		ProviderID: s.providerID,
		WrappedKey: wrapped,
		Nonce:      nonce,
	}
	aad, err := envelope.aad()
	if err != nil {
		return fmt.Errorf("qurl: encode sealed agent state AAD: %w", err)
	}
	envelope.Ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("qurl: encode sealed agent state envelope: %w", err)
	}
	defer wipeBytes(raw)
	if len(raw) > maxSealedAgentStateEnvelope {
		return fmt.Errorf("%w: sealed agent state envelope exceeds %d bytes", ErrInvalidBootstrapConfig, maxSealedAgentStateEnvelope)
	}
	return writePrivateStateFileAtomic(ctx, s.path, "sealed agent state", ".qurl-sealed-agent-state-*", raw, s.fileOps)
}

type sealedAgentStateEnvelope struct {
	Version    int                  `json:"version"`
	Purpose    string               `json:"purpose"`
	AgentID    string               `json:"agent_id"`
	ProviderID string               `json:"provider_id"`
	WrappedKey WrappedAgentStateKey `json:"wrapped_key"`
	Nonce      []byte               `json:"nonce"`
	Ciphertext []byte               `json:"ciphertext"`
}

func (e sealedAgentStateEnvelope) binding() AgentStateKeyBinding {
	return AgentStateKeyBinding{Purpose: e.Purpose, EnvelopeVersion: e.Version, ProviderID: e.ProviderID, AgentID: e.AgentID}
}

func (e sealedAgentStateEnvelope) aad() ([]byte, error) {
	// Keep the persisted v1 AAD independent of future additions to the public
	// AgentStateKeyBinding type. JSON encoding of this fixed-field internal struct
	// is deterministic and unambiguous.
	wrapped := cloneWrappedAgentStateKey(e.WrappedKey)
	wrapped.Metadata = compactJSON(wrapped.Metadata)
	raw, err := json.Marshal(sealedAgentStateAAD{
		Purpose:         e.Purpose,
		EnvelopeVersion: e.Version,
		ProviderID:      e.ProviderID,
		AgentID:         e.AgentID,
		WrappedKey:      wrapped,
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

type sealedAgentStateAAD struct {
	Purpose         string               `json:"purpose"`
	EnvelopeVersion int                  `json:"envelope_version"`
	ProviderID      string               `json:"provider_id"`
	AgentID         string               `json:"agent_id"`
	WrappedKey      WrappedAgentStateKey `json:"wrapped_key"`
}

func decodeSealedAgentStateEnvelope(raw []byte, envelope *sealedAgentStateEnvelope) error {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return invalidSealedState("envelope contains duplicate object fields")
	}
	if err := strictDecodeJSON(raw, envelope); err != nil {
		return invalidSealedState("decode envelope")
	}
	if envelope.Version != sealedAgentStateVersion || envelope.Purpose != sealedAgentStatePurpose {
		return invalidSealedState("unsupported envelope purpose or version")
	}
	if _, err := normalizeSealedAgentID(envelope.AgentID); err != nil {
		return invalidSealedState("invalid outer agent id")
	}
	if err := validateProviderID(envelope.ProviderID); err != nil {
		return invalidSealedState("invalid envelope provider id")
	}
	if err := validateWrappedAgentStateKey(envelope.WrappedKey); err != nil {
		return invalidSealedState("invalid wrapped-key record")
	}
	if len(envelope.Nonce) != 12 {
		return invalidSealedState("invalid AES-GCM nonce length")
	}
	if len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > maxSealedAgentStateBytes+16 {
		return invalidSealedState("invalid ciphertext length")
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeUniqueJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxSealedEnvelopeJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func validateWrappedAgentStateKey(wrapped WrappedAgentStateKey) error {
	if wrapped.Version <= 0 {
		return errors.New("wrapper version must be positive")
	}
	if len(wrapped.Ciphertext) == 0 || len(wrapped.Ciphertext) > maxWrappedAgentStateKeyBytes {
		return errors.New("wrapped key length is invalid")
	}
	if len(wrapped.Metadata) > maxWrappedAgentStateMetadata {
		return errors.New("wrapped key metadata is too large")
	}
	if len(wrapped.Metadata) > 0 && !json.Valid(wrapped.Metadata) {
		return errors.New("wrapped key metadata is not valid JSON")
	}
	return nil
}

func newSealedAgentStateGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func openSealedAgentState(dek, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newSealedAgentStateGCM(dek)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func compactJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return bytes.Clone(raw) // validation reports malformed metadata before this helper
	}
	return compact.Bytes()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("expected end of JSON input")
	}
	return nil
}

func invalidSealedState(reason string) error {
	return fmt.Errorf("%w: sealed agent state %s", ErrInvalidAgentState, reason)
}

func cloneWrappedAgentStateKey(in WrappedAgentStateKey) WrappedAgentStateKey {
	return WrappedAgentStateKey{Version: in.Version, Ciphertext: bytes.Clone(in.Ciphertext), Metadata: bytes.Clone(in.Metadata)}
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
