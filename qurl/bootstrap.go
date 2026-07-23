package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
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
// HTTP enrollment schema is accepted or migrated. SchemaVersion selects the
// closed legacy/current recovery-field grammar; readiness still comes from the
// validated native fields rather than the number alone.
type AgentState struct {
	AgentID       string     `json:"agent_id,omitempty"`
	PrivateKeyB64 string     `json:"private_key_b64"`
	PublicKeyB64  string     `json:"public_key_b64"`
	RegisteredAt  *time.Time `json:"registered_at,omitempty"`

	// SchemaVersion is the AgentState schema version. RegisterAgentRuntime and
	// RecoverAgentRuntime write agentStateSchemaVersion (currently v7). Legacy
	// schema-v5 state must not populate v6 finite-registration-recovery or v7
	// credential-recovery fields.
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
	// Schema v6 adds its authority-anchored finite recovery deadline. Enrollment
	// credentials, OTP codes, and device credentials are never stored here.
	PendingActivation *PendingAgentActivation `json:"pending_activation,omitempty"`

	// PendingCompletion is written only after an authenticated assigned-cell RAK
	// and before the first completion LST. It keeps the SDK-generated device
	// secret crash-safe across an ambiguous/lost LRT. A retry must reuse this
	// exact candidate before the same schema-v6 recovery deadline; generating a
	// replacement could mint a second credential.
	PendingCompletion *PendingAgentCompletion `json:"pending_completion,omitempty"`

	// PendingCredentialRecovery is the crash-safe explicit same-agent device
	// credential replacement. It owns the Authority-issued grant, one SDK-
	// generated replacement candidate, and the exact assigned-cell trust binding.
	// The recovery credential is never persisted. While this field exists,
	// ordinary open/register/refresh paths fail closed even if the old device key
	// remains in state.
	PendingCredentialRecovery *PendingAgentCredentialRecovery `json:"pending_credential_recovery,omitempty"`

	// PendingCredentialRecoveryIssue is durable intent for one exact Hub
	// IssueCredentialRecovery logical operation. It is saved before the first
	// datagram so a lost response or process crash reuses the same request nonce
	// and semantic credential identity. It never contains the raw recovery
	// credential. During grant renewal it coexists only with a rejected pending
	// grant whose immutable episode anchor remains authoritative.
	PendingCredentialRecoveryIssue *PendingAgentCredentialRecoveryIssue `json:"pending_credential_recovery_issue,omitempty"`
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
	// RecoveryAnchorTicketExpiresAt retains the first authenticated Hub ticket
	// expiry for this recovery episode. Completion never reuses the ticket; the
	// timestamp exists only to validate the copied immutable deadline.
	RecoveryAnchorTicketExpiresAt time.Time `json:"recovery_anchor_ticket_expires_at,omitempty"`
	// RecoveryExpiresAt is the absolute deadline inherited unchanged from the
	// activation ticket. It is never reset by RAK, restart, assignment refresh,
	// retry, or completion response.
	RecoveryExpiresAt time.Time `json:"recovery_expires_at,omitempty"`
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
	AssignmentTicket          string    `json:"assignment_ticket"`
	AssignmentTicketExpiresAt time.Time `json:"assignment_ticket_expires_at"`
	// RecoveryAnchorTicketExpiresAt is the first authenticated ticket expiry in
	// this recovery episode. An authenticated non-commit verdict may replace the
	// current ticket, but it cannot replace this non-secret authority anchor.
	RecoveryAnchorTicketExpiresAt time.Time `json:"recovery_anchor_ticket_expires_at,omitempty"`
	// RecoveryExpiresAt is exactly RecoveryAnchorTicketExpiresAt plus the released
	// AgentRegistrationRecoveryHorizon. The first authenticated Hub timestamp,
	// rather than a local process timestamp, anchors the finite recovery contract.
	RecoveryExpiresAt                  time.Time              `json:"recovery_expires_at,omitempty"`
	AgentID                            string                 `json:"agent_id"`
	AgentPublicKeyB64                  string                 `json:"agent_public_key_b64"`
	Assignment                         AgentAssignment        `json:"assignment"`
	Registration                       AssignmentRegistration `json:"registration"`
	Hostname                           string                 `json:"hostname,omitempty"`
	AgentVersion                       string                 `json:"agent_version,omitempty"`
	EnrollmentCredentialFingerprintB64 string                 `json:"enrollment_credential_fingerprint_b64"`
}

// PendingAgentCredentialRecovery is one explicit operator-started credential
// replacement episode. RecoveryGrant and DeviceAPIKey are secrets and receive
// the same custody as AgentState. Assignment duplicates AgentState.Assignment so
// a custom store cannot retarget the assigned-cell completion. The first
// authenticated grant expiry is the immutable episode anchor; later grants may
// replace only the current grant/times and assignment, never the candidate,
// anchor, or recovery deadline.
type PendingAgentCredentialRecovery struct {
	RecoveryGrant                string          `json:"recovery_grant"`
	RecoveryGrantIssuedAt        time.Time       `json:"recovery_grant_issued_at"`
	RecoveryGrantExpiresAt       time.Time       `json:"recovery_grant_expires_at"`
	RecoveryAnchorGrantExpiresAt time.Time       `json:"recovery_anchor_grant_expires_at"`
	RecoveryExpiresAt            time.Time       `json:"recovery_expires_at"`
	DeviceAPIKey                 string          `json:"device_api_key"`
	Assignment                   AgentAssignment `json:"assignment"`
	// NeedsFreshGrant is set only after an authenticated 52411. The next
	// explicit call asks Hub for a new grant but reuses the same candidate and
	// immutable episode anchor. Transport ambiguity never sets it.
	NeedsFreshGrant bool `json:"needs_fresh_grant,omitempty"`
}

// PendingAgentCredentialRecoveryIssue is the secret-free replay identity for
// an in-flight Hub IssueCredentialRecovery call. RecoveryCredentialFingerprintB64
// is a domain-separated SHA-256 equality tag for a server-minted, high-entropy
// bearer credential; it is not a password verifier.
type PendingAgentCredentialRecoveryIssue struct {
	RequestNonce string `json:"request_nonce"`
	// ReplayNotAfter is a local conservative cutoff persisted before the first
	// authenticated Authority grant expiry is known. It bounds exact Issue replay
	// to less than the released Authority horizon; once a result is persisted, the
	// Authority-derived RecoveryExpiresAt replaces it as the write boundary.
	ReplayNotAfter                   time.Time `json:"replay_not_after"`
	RecoveryCredentialFingerprintB64 string    `json:"recovery_credential_fingerprint_b64"`
	AgentID                          string    `json:"agent_id"`
	AgentPublicKeyB64                string    `json:"agent_public_key_b64"`
	HubHost                          string    `json:"hub_host"`
	HubPort                          int       `json:"hub_port"`
	HubServerPublicKeyB64            string    `json:"hub_server_public_key_b64"`
}

// validateLoadedAgentAssignment checks persisted trust-boundary structure but
// deliberately permits an expired lease so the caller can refresh it. Concrete
// stores call it directly; lifecycle loaders repeat it for custom stores.
func validateLoadedAgentAssignment(state *AgentState) error {
	if state == nil {
		return nil
	}
	// Zero is the original, pre-versioned state shape and versions through the
	// current one remain readable for the explicit migrations below. Negative
	// versions are invalid, while a greater version belongs to a newer SDK whose
	// invariants this binary cannot safely interpret.
	if state.SchemaVersion < 0 || state.SchemaVersion > agentStateSchemaVersion {
		return fmt.Errorf("%w: unsupported agent state schema version %d", ErrInvalidAgentState, state.SchemaVersion)
	}
	// Assignment, pending activation/completion, and native credential-id fields
	// are durable native-runtime markers. Once any marker exists, the identity
	// authenticated by the Hub and assigned cell must already be persisted in
	// canonical wire form. Never let a later lifecycle call manufacture or
	// normalize a different identity around those authority-bound fields.
	if isNativeAgentRuntimeState(state) {
		if err := validatePersistedNativeAgentID(state.AgentID); err != nil {
			return err
		}
	}
	if state.Assignment != nil {
		if err := validatePersistedAgentAssignment(state.Assignment); err != nil {
			return fmt.Errorf("%w: persisted assignment: %w", ErrInvalidAgentState, err)
		}
	}
	if state.PendingActivation != nil {
		if err := validatePendingAgentActivation(state.PendingActivation, state); err != nil {
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
		if err := validatePendingCompletionRecoveryDeadline(pending, state); err != nil {
			return err
		}
		if state.RegisteredAt != nil || state.DeviceAPIKey != "" || state.DeviceAPIKeyID != "" {
			return fmt.Errorf("%w: pending completion cannot coexist with a completed device credential", ErrInvalidAgentState)
		}
	}
	if state.PendingCredentialRecoveryIssue != nil {
		if state.PendingActivation != nil || state.PendingCompletion != nil {
			return fmt.Errorf("%w: credential recovery issue cannot coexist with registration recovery", ErrInvalidAgentState)
		}
		if state.SchemaVersion < credentialRecoveryStateSchemaVersion || state.RegisteredAt == nil || state.Assignment == nil {
			return fmt.Errorf("%w: credential recovery issue requires current completed state", ErrInvalidAgentState)
		}
		if err := validatePendingCredentialRecoveryIssue(state.PendingCredentialRecoveryIssue); err != nil {
			return err
		}
		if state.PendingCredentialRecoveryIssue.AgentID != state.AgentID || state.PendingCredentialRecoveryIssue.AgentPublicKeyB64 != state.PublicKeyB64 {
			return fmt.Errorf("%w: credential recovery issue identity does not match state", ErrInvalidAgentState)
		}
		if state.PendingCredentialRecovery != nil && !state.PendingCredentialRecovery.NeedsFreshGrant {
			return fmt.Errorf("%w: credential recovery issue may coexist only with a rejected grant", ErrInvalidAgentState)
		}
		if state.PendingCredentialRecovery != nil && state.PendingCredentialRecoveryIssue.ReplayNotAfter.After(state.PendingCredentialRecovery.RecoveryExpiresAt) {
			return fmt.Errorf("%w: credential recovery issue cutoff exceeds its Authority episode", ErrInvalidAgentState)
		}
	}
	if state.PendingCredentialRecovery != nil {
		if state.PendingActivation != nil || state.PendingCompletion != nil {
			return fmt.Errorf("%w: credential recovery cannot coexist with registration recovery", ErrInvalidAgentState)
		}
		if state.SchemaVersion < credentialRecoveryStateSchemaVersion {
			return fmt.Errorf("%w: legacy state contains credential recovery fields", ErrInvalidAgentState)
		}
		if state.RegisteredAt == nil {
			return fmt.Errorf("%w: credential recovery requires a completed agent identity", ErrInvalidAgentState)
		}
		if state.DeviceAPIKey != "" || state.DeviceAPIKeyID != "" {
			return fmt.Errorf("%w: pending credential recovery must not retain the revoked device credential", ErrInvalidAgentState)
		}
		if err := validatePendingAgentCredentialRecovery(state.PendingCredentialRecovery, state); err != nil {
			return err
		}
	}
	return nil
}

func validatePersistedNativeAgentID(agentID string) error {
	if err := validateAssignmentAgentID(agentID); err != nil {
		return fmt.Errorf("%w: persisted native agent id is missing or non-canonical", ErrInvalidAgentState)
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
	if s.PendingCredentialRecovery != nil {
		pending := *s.PendingCredentialRecovery
		pending.Assignment = *s.PendingCredentialRecovery.Assignment.clone()
		cloned.PendingCredentialRecovery = &pending
	}
	if s.PendingCredentialRecoveryIssue != nil {
		pending := *s.PendingCredentialRecoveryIssue
		cloned.PendingCredentialRecoveryIssue = &pending
	}
	return &cloned
}

// agentStateSchemaVersion is the current native AgentState schema version.
const (
	agentStateSchemaVersion                = 7
	registrationRecoveryStateSchemaVersion = 6
	credentialRecoveryStateSchemaVersion   = 7
)

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

// OpenFileAgentState pins the complete no-follow path to a trusted 0700
// state directory and returns a plaintext local store whose state and mandatory
// setup lock are always accessed relative to that retained directory capability.
// The caller owns the returned handle and must Close it after every Client and
// native lifecycle operation that can use the store has finished.
//
// Linux and Darwin are supported, excluding Android and iOS. Mobile and other
// platforms fail before filesystem mutation until they have reviewed ACL,
// locking, and durability primitives.
func OpenFileAgentState(path string) (*FileAgentStateStore, error) {
	dir, name, err := openPinnedStatePath(path, "agent state")
	if err != nil {
		return nil, err
	}
	store := &FileAgentStateStore{dir: dir, name: name, path: path}
	cleanup := runtime.AddCleanup(store, closePinnedStateDir, dir)
	store.cleanup = &cleanup
	return store, nil
}

// FileAgentState stores bootstrap state in a local plaintext JSON file written
// 0600. It is retained for source compatibility with early SDK releases.
// New process-lifetime integrations such as qURL Connector must use
// OpenFileAgentState so construction errors and Close ownership are explicit.
//
// This compatibility constructor still pins immediately. If construction fails,
// it returns a store whose operations deterministically return that error; it
// never falls back to pathname I/O. Its dynamic value implements io.Closer and
// should be closed after its last use; a runtime cleanup is only a leak-safety
// fallback for legacy callers whose static AgentStateStore value hides Close.
func FileAgentState(path string) AgentStateStore {
	store, err := OpenFileAgentState(path)
	if err != nil {
		return &FileAgentStateStore{initErr: err}
	}
	return store
}

// FileAgentStateStore is an SDK-owned pinned plaintext AgentState store.
// Do not copy it; retain the constructor-returned pointer and Close it once.
type FileAgentStateStore struct {
	dir     *pinnedStateDir
	name    string
	path    string
	initErr error
	closeMu sync.Mutex
	cleanup *runtime.Cleanup
}

func closePinnedStateDir(dir *pinnedStateDir) { _ = dir.close() }

func (s *FileAgentStateStore) operationalError() error {
	if s == nil {
		return fmt.Errorf("%w: plaintext agent state store is nil", ErrAgentStateContinuity)
	}
	return s.initErr
}

// Close releases the retained state-directory capability. It is idempotent and
// waits for an in-flight store or setup-lock operation to release its reference.
func (s *FileAgentStateStore) Close() (resultErr error) {
	if err := s.operationalError(); err != nil {
		return err
	}
	s.closeMu.Lock()
	if s.cleanup != nil {
		s.cleanup.Stop()
		s.cleanup = nil
	}
	s.closeMu.Unlock()
	resultErr = s.dir.close()
	runtime.KeepAlive(s)
	return resultErr
}

// ValidateContinuity proves that the configured path still resolves through
// no-follow traversal to the directory retained by OpenFileAgentState.
func (s *FileAgentStateStore) ValidateContinuity() (resultErr error) {
	if err := s.operationalError(); err != nil {
		return err
	}
	resultErr = s.dir.validate()
	runtime.KeepAlive(s)
	return resultErr
}

func (s *FileAgentStateStore) retainContinuity() (AgentStateStore, func() error, error) {
	if err := s.operationalError(); err != nil {
		return nil, nil, err
	}
	retained, release, err := s.dir.retainOperation(s)
	runtime.KeepAlive(s)
	return retained, release, err
}

func (s *FileAgentStateStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	if err := s.operationalError(); err != nil {
		return nil, err
	}
	lock, err := s.dir.lock(ctx, s.name+agentSetupLockSuffix)
	runtime.KeepAlive(s)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire pinned setup lock: %w", ErrAgentSetupLock, err)
	}
	return lock, nil
}

// LoadAgentState loads and validates a fresh caller-owned state snapshot from
// the pinned plaintext file.
func (s *FileAgentStateStore) LoadAgentState(ctx context.Context) (state *AgentState, resultErr error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	state, resultErr = withAgentStoreContinuity(s, func(*AgentState) {}, func(retained AgentStateStore) (*AgentState, error) {
		return retained.LoadAgentState(ctx)
	})
	runtime.KeepAlive(s)
	return state, resultErr
}

func (s *FileAgentStateStore) loadAgentStateRetained(ctx context.Context, op *pinnedStateOperation) (*AgentState, error) {
	if err := s.operationalError(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	// Corrupt-content faults use the store-neutral ErrInvalidAgentState class;
	// lifecycle front doors re-wrap it in their own config-error class.
	raw, err := op.load(ctx, s.name, "agent state", maxAgentStateBytes, ErrAgentStateNotFound)
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

// SaveAgentState atomically replaces the pinned plaintext file after continuity
// and descriptor-to-entry validation.
func (s *FileAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) (resultErr error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return err
	}
	if err := rejectSetupLockReentry(ctx, s); err != nil {
		return err
	}
	_, resultErr = withAgentStoreContinuity(s, func(struct{}) {}, func(retained AgentStateStore) (struct{}, error) {
		return withAgentSetupLock(ctx, retained, func(struct{}) {}, func(lockedCtx context.Context, locked AgentStateStore) (struct{}, error) {
			return struct{}{}, locked.SaveAgentState(lockedCtx, state)
		})
	})
	runtime.KeepAlive(s)
	return resultErr
}

func (s *FileAgentStateStore) saveAgentStateRetained(ctx context.Context, state *AgentState, op *pinnedStateOperation, setup *pinnedSetupLockToken) error {
	if err := s.operationalError(); err != nil {
		return err
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
	return op.save(ctx, setup, s.name, "agent state", ".qurl-agent-state-", raw)
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
