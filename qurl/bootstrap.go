package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidBootstrapConfig is returned when durable agent-state configuration
// or native enrollment inputs are invalid.
var ErrInvalidBootstrapConfig = errors.New("qurl: invalid bootstrap config")

// ErrAgentStateNotFound is returned when an AgentStateStore has no saved state.
// It is part of the AgentStateStore implementor contract: LoadAgentState returns
// it when no state has been persisted, allowing RegisterAgentRuntime to start a
// fresh native enrollment.
var ErrAgentStateNotFound = errors.New("qurl: agent state not found")

// ErrInvalidAgentState is the implementor-contract sibling of ErrAgentStateNotFound:
// an AgentStateStore returns it (or wraps it) from LoadAgentState when persisted
// state EXISTS but cannot be read back — a corrupt or undecodable blob, distinct
// from the not-yet-persisted ErrAgentStateNotFound. The file-backed store returns
// it for a corrupt or malformed state file; a custom store (for example a
// Secrets Manager-backed one) should return it for the same condition. It is a
// store-neutral sentinel: lifecycle front doors re-wrap a load failure in their
// own config-error class, so a caller can match either sentinel.
var ErrInvalidAgentState = errors.New("qurl: agent state is present but unreadable or corrupt")

// ErrInsecureAgentStatePermissions is returned when file-backed agent state is
// readable by group or other users.
var ErrInsecureAgentStatePermissions = errors.New("qurl: insecure agent state permissions")

// ErrAgentSetupLock reports that the mandatory local-file setup lock could not
// be acquired or released. Registration fails closed because continuing could
// mint competing identities against the same durable state path. A release
// failure can occur after a successful durable save; load the stored state
// before retrying. Open completed native state with OpenRegisteredAgentRuntime;
// resume durable PendingActivation through RegisterAgentRuntime with the same
// enrollment credential, or PendingCompletion without one. OpenRegisteredAgent
// is the resource-client-only path.
var ErrAgentSetupLock = errors.New("qurl: agent state setup lock failed")

// ErrBootstrapSetupKeyConsumed is returned when an incomplete local bootstrap
// retry is rejected because the one-time setup key appears to have already been
// used. Surface this to operators instead of retrying indefinitely: run the
// LayerV setup flow again or restore the completed AgentState.
var ErrBootstrapSetupKeyConsumed = errors.New("qurl: bootstrap setup key already consumed")

// AgentState is the protected local agent identity created by the native UDP
// registered-agent lifecycle.
//
// SECURITY: once registration completes, AgentState is a CREDENTIAL FILE — it
// holds DeviceAPIKey, the bearer token the returned Client authorizes with. Treat
// it as secret: keep it out of logs, crash dumps, and support bundles, and keep
// the FileAgentState 0600 / 0700-dir posture. On a shared host, back it with a
// secret manager (for example AWS Secrets Manager via a custom AgentStateStore)
// rather than a world-readable path.
//
// The state schema is native-only. Unknown JSON fields fail closed; no retired
// HTTP enrollment schema is accepted or migrated. SchemaVersion is
// informational; readiness comes from validated native fields.
type AgentState struct {
	AgentID       string     `json:"agent_id,omitempty"`
	PrivateKeyB64 string     `json:"private_key_b64"`
	PublicKeyB64  string     `json:"public_key_b64"`
	RegisteredAt  *time.Time `json:"registered_at,omitempty"`

	// SchemaVersion is the AgentState schema version. RegisterAgentRuntime writes
	// agentStateSchemaVersion. Informational only.
	SchemaVersion int `json:"schema_version,omitempty"`
	// DeviceAPIKey is the device REST bearer credential minted at registration
	// completion. Its presence alongside RegisteredAt marks a state ready to back
	// a Client without another qURL registration call. SENSITIVE — see the type doc.
	DeviceAPIKey string `json:"device_api_key,omitempty"`
	// Assignment is the authoritative native-UDP cell assignment (cell,
	// generation, endpoint revision, lease expiry, and LayerV-owned DNS endpoint)
	// returned by the hub and persisted so a native registration/knock survives a
	// restart. It is additive and json:",omitempty", so a pre-assignment state
	// file loads unchanged. A resolved IP is never persisted here — the endpoint
	// host is resolved fresh on every exchange.
	Assignment *AgentAssignment `json:"assignment,omitempty"`

	// --- v4+ additive fields (native UDP crash-safe activation/completion) ---

	// DeviceAPIKeyID is the public identifier paired with DeviceAPIKey by native
	// UDP completion. It is never a secret.
	DeviceAPIKeyID string `json:"device_api_key_id,omitempty"`

	// PendingActivation is durably persisted through the configured
	// AgentStateStore before the first assigned-cell REG. It retains the exact
	// non-secret activation proof and placement needed to recover an
	// ambiguous/lost RAK without asking the Hub for another one-shot ticket.
	// Enrollment credentials, OTP codes, and device credentials are never stored
	// here.
	PendingActivation *PendingAgentActivation `json:"pending_activation,omitempty"`

	// PendingCompletion is written only after an authenticated assigned-cell RAK
	// and before the first completion LST. It keeps the SDK-generated device
	// secret crash-safe across an ambiguous/lost LRT. A retry must reuse this
	// exact candidate; generating a replacement could mint a second credential.
	PendingCompletion *PendingAgentCompletion `json:"pending_completion,omitempty"`
}

type agentStateJSON AgentState

// UnmarshalJSON keeps the native-only persisted schema strict at the type
// boundary, so file, sealed, AWS, and custom JSON stores cannot disagree about
// duplicate, unknown, nested, or trailing input. The generic error deliberately
// does not reflect credential-file field names or values.
func (s *AgentState) UnmarshalJSON(raw []byte) error {
	if _, err := exactObjectFields(raw); err != nil {
		return errors.New("qurl: invalid agent state JSON")
	}
	var decoded agentStateJSON
	if err := strictDecodeJSON(raw, &decoded); err != nil {
		return errors.New("qurl: invalid agent state JSON")
	}
	*s = AgentState(decoded)
	return nil
}

// PendingAgentCompletion is sensitive durable state for one in-flight native
// registration completion. CellID and AssignmentGeneration bind the candidate
// to the authority state that accepted REG, so a moved assignment cannot replay
// it in another cell or generation.
type PendingAgentCompletion struct {
	DeviceAPIKey         string `json:"device_api_key"`
	CellID               string `json:"cell_id"`
	AssignmentGeneration int64  `json:"assignment_generation"`
}

// PendingAgentActivation is the exact durable input for one assigned-cell REG.
// Assignment deliberately duplicates AgentState.Assignment so loading can fail
// closed if a store or caller changes the cell, generation, endpoint revision,
// lease, host, port, or pinned server identity around an in-flight ticket.
// AgentPublicKeyB64 likewise duplicates AgentState.PublicKeyB64 so loading can
// reject keypair/state desynchronization before replaying the authority-bound
// ticket.
// EnrollmentCredentialFingerprintB64 is a domain-separated SHA-256 identity of
// the high-entropy caller-supplied enrollment credential. It permits only that
// same credential to resume the record without retaining the bearer value.
// RegisterAgentRuntime enforces an encoded-token total-length floor; the
// producer remains responsible for cryptographically random minting. This
// fingerprint is an equality tag for a server-minted secret, never a password
// verifier.
// The REG credential itself is never persisted: unattended kinds re-derive it
// from the corroborated enrollment credential, while account recovery asks the
// explicit OTP provider for the original code and never dispatches another OTP.
type PendingAgentActivation struct {
	AssignmentTicket                   string                 `json:"assignment_ticket"`
	AssignmentTicketExpiresAt          time.Time              `json:"assignment_ticket_expires_at"`
	AgentID                            string                 `json:"agent_id"`
	AgentPublicKeyB64                  string                 `json:"agent_public_key_b64"`
	Assignment                         AgentAssignment        `json:"assignment"`
	Registration                       AssignmentRegistration `json:"registration"`
	Hostname                           string                 `json:"hostname,omitempty"`
	AgentVersion                       string                 `json:"agent_version,omitempty"`
	EnrollmentCredentialFingerprintB64 string                 `json:"enrollment_credential_fingerprint_b64"`
}

// validateLoadedAgentAssignment checks persisted trust-boundary structure but
// deliberately permits an expired lease so the caller can refresh it. Concrete
// stores call it directly; lifecycle loaders repeat it for custom stores.
func validateLoadedAgentAssignment(state *AgentState) error {
	if state == nil {
		return nil
	}
	// Assignment, pending activation/completion, and native credential-id fields
	// are durable native-runtime markers. Once any marker exists, the identity
	// authenticated by the Hub and assigned cell must already be persisted in
	// canonical wire form. Never let a later lifecycle call manufacture or
	// normalize a different identity around those authority-bound fields.
	if isNativeAgentRuntimeState(state) {
		if err := validateAssignmentAgentID(state.AgentID); err != nil {
			return fmt.Errorf("%w: persisted native agent id is missing or non-canonical", ErrInvalidAgentState)
		}
	}
	if state.Assignment != nil {
		if err := validatePersistedAgentAssignment(state.Assignment); err != nil {
			return fmt.Errorf("%w: persisted assignment: %w", ErrInvalidAgentState, err)
		}
	}
	if state.PendingActivation != nil {
		pending := state.PendingActivation
		if state.Assignment == nil {
			return fmt.Errorf("%w: pending activation requires an assignment", ErrInvalidAgentState)
		}
		if err := validatePendingAgentActivation(pending, state); err != nil {
			return err
		}
		if state.PendingCompletion != nil || state.RegisteredAt != nil || state.DeviceAPIKey != "" || state.DeviceAPIKeyID != "" {
			return fmt.Errorf("%w: pending activation cannot coexist with completion or a completed device credential", ErrInvalidAgentState)
		}
	}
	if state.PendingCompletion != nil {
		pending := state.PendingCompletion
		if state.Assignment == nil {
			return fmt.Errorf("%w: pending completion requires an assignment", ErrInvalidAgentState)
		}
		if err := validateNativeDeviceCredential(pending.DeviceAPIKey, "pending device credential", ErrInvalidAgentState); err != nil {
			return err
		}
		if pending.CellID != state.Assignment.CellID || pending.AssignmentGeneration != state.Assignment.AssignmentGeneration {
			return fmt.Errorf("%w: pending completion does not match the persisted assignment", ErrInvalidAgentState)
		}
		if state.PendingActivation != nil || state.RegisteredAt != nil || state.DeviceAPIKey != "" || state.DeviceAPIKeyID != "" {
			return fmt.Errorf("%w: pending completion cannot coexist with a completed device credential", ErrInvalidAgentState)
		}
	}
	return nil
}

// clone returns an independent mutable snapshot. Strings and scalar fields copy
// by value; every pointer field is copied explicitly so lifecycle transitions
// cannot mutate the loaded state through an alias. Keep this method aligned with
// future pointer, slice, or map fields added to AgentState.
func (s *AgentState) clone() *AgentState {
	if s == nil {
		return nil
	}
	cloned := *s
	if s.RegisteredAt != nil {
		registeredAt := *s.RegisteredAt
		cloned.RegisteredAt = &registeredAt
	}
	if s.Assignment != nil {
		cloned.Assignment = s.Assignment.clone()
	}
	if s.PendingActivation != nil {
		pending := *s.PendingActivation
		pending.Assignment = *s.PendingActivation.Assignment.clone()
		cloned.PendingActivation = &pending
	}
	if s.PendingCompletion != nil {
		pending := *s.PendingCompletion
		cloned.PendingCompletion = &pending
	}
	return &cloned
}

// agentStateSchemaVersion is the current native AgentState schema version.
const agentStateSchemaVersion = 5

// AgentStateStore loads and saves the bootstrapped local identity. The
// file-backed store writes plaintext JSON protected by filesystem permissions;
// implement this with KMS or a secret manager when that is not appropriate.
//
// Ownership contract: the registration engine takes ownership of the *AgentState
// that LoadAgentState returns. Initial enrollment may mutate that pointer in
// place; refresh/recovery deliberately clone it and may pass a different
// candidate pointer to SaveAgentState. A custom store must therefore return a
// fresh, caller-owned *AgentState from every load — never a pointer it retains,
// caches, or shares — and must not rely on load/save pointer identity.
// SaveAgentState must snapshot (encode) eagerly rather than retain its argument,
// or later engine mutation could corrupt the store's own copy. The file-backed
// store decodes a fresh value per load and encodes on save, so it satisfies this
// by construction.
type AgentStateStore interface {
	LoadAgentState(context.Context) (*AgentState, error)
	SaveAgentState(context.Context, *AgentState) error
}

// FileAgentState stores bootstrap state in a local plaintext JSON file written
// 0600. Local filesystem I/O is synchronous; the context passed to LoadAgentState
// or SaveAgentState cannot interrupt a read or write once it has started.
func FileAgentState(path string) AgentStateStore {
	return fileAgentStateStore{fileSetupLock: fileSetupLock{path: path, lockFile: lockFileExclusive}}
}

type fileAgentStateStore struct {
	fileSetupLock
}

func (s fileAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	// Corrupt-content faults use the store-neutral ErrInvalidAgentState class;
	// lifecycle front doors re-wrap it in their own config-error class.
	raw, err := readPrivateStateFileBounded(s.path, "agent state", maxAgentStateBytes, privateStateDirExact0700, ErrAgentStateNotFound, ErrInvalidAgentState, ErrInsecureAgentStatePermissions)
	if err != nil {
		return nil, err
	}
	var state AgentState
	if err := strictDecodeJSON(raw, &state); err != nil {
		// The decoder's detail can contain producer-controlled field names or
		// fragments from a credential file. Preserve only the stable sentinel.
		return nil, fmt.Errorf("%w: decode agent state", ErrInvalidAgentState)
	}
	if err := validateLoadedAgentAssignment(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s fileAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	if strings.TrimSpace(s.path) == "" {
		return fmt.Errorf("%w: state path must not be empty", ErrInvalidBootstrapConfig)
	}
	if state == nil {
		return fmt.Errorf("%w: state must not be nil", ErrInvalidBootstrapConfig)
	}
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("qurl: encode agent state: %w", err)
	}
	defer wipeBytes(raw)
	if len(raw) > maxAgentStateBytes {
		return fmt.Errorf("%w: encoded agent state exceeds %d bytes", ErrInvalidBootstrapConfig, maxAgentStateBytes)
	}
	return writePrivateStateFileAtomic(ctx, s.path, "agent state", ".qurl-agent-state-*", raw, defaultPrivateStateFileOps)
}

// validateCompletedAgentIdentity checks the durable identity fields required by
// completed native runtime state.
func validateCompletedAgentIdentity(state *AgentState, errKind error) error {
	if err := validatePersistedAgentID(state, errKind); err != nil {
		return err
	}
	if state.RegisteredAt == nil {
		return fmt.Errorf("%w: registered agent state missing registration time", errKind)
	}
	return nil
}

func validatePersistedAgentID(state *AgentState, errKind error) error {
	if state == nil {
		return fmt.Errorf("%w: registered agent state is nil", errKind)
	}
	if strings.TrimSpace(state.AgentID) == "" {
		return fmt.Errorf("%w: registered agent state missing agent id", errKind)
	}
	return nil
}

// prepareLoadedAgentState applies the lifecycle trust boundary to every load.
// Built-in stores validate too, but public custom AgentStateStore implementations
// are not trusted to do so before returning state.
func prepareLoadedAgentState(state *AgentState, errKind error) error {
	if state == nil {
		return fmt.Errorf("%w: agent state store returned nil state", errKind)
	}
	if err := validateLoadedAgentAssignment(state); err != nil {
		return fmt.Errorf("%w: %w", errKind, err)
	}
	return state.ensureKeypair(errKind)
}

// loadOrCreateAgentState loads the persisted state (creating a fresh keypair when
// none exists), validating a loaded keypair. The underlying store sentinel stays
// matchable through the front-door error wrap.
func loadOrCreateAgentState(ctx context.Context, store AgentStateStore, invalidConfigErr error) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if err := prepareLoadedAgentState(state, invalidConfigErr); err != nil {
			return nil, err
		}
		return state, nil
	case errors.Is(err, ErrAgentStateNotFound):
		return newAgentState()
	default:
		return nil, fmt.Errorf("%w: load agent state: %w", invalidConfigErr, err)
	}
}

func newAgentState() (*AgentState, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("qurl: generate agent keypair: %w", err)
	}
	return &AgentState{
		PrivateKeyB64: base64.StdEncoding.EncodeToString(key.Bytes()),
		PublicKeyB64:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

// ensureKeypair validates the loaded keypair, deriving the public key when
// absent. invalidConfigErr is the caller's front-door config-error class wrapped
// into every failure so the entry point keeps its documented class.
func (s *AgentState) ensureKeypair(invalidConfigErr error) error {
	if s == nil {
		return fmt.Errorf("%w: state must not be nil", invalidConfigErr)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s.PrivateKeyB64)
	if err != nil {
		return fmt.Errorf("%w: decode agent private key: %w", invalidConfigErr, err)
	}
	defer wipeBytes(raw)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return fmt.Errorf("%w: agent private key must be X25519", invalidConfigErr)
	}
	publicKey := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if s.PublicKeyB64 == "" {
		s.PublicKeyB64 = publicKey
	}
	if s.PublicKeyB64 != publicKey {
		return fmt.Errorf("%w: agent public key does not match private key", invalidConfigErr)
	}
	return nil
}
