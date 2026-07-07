package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultBootstrapBaseURL is the LayerV API origin BootstrapAgent uses for the
// NHP registration pre-flight and completion endpoints. It matches the default
// RegisterAgent base URL; WithBootstrapBaseURL overrides it. (Before the NHP
// reimplementation this pointed at a dedicated bootstrap origin; the enrollment
// endpoints now live on the qurl-service API origin.)
const defaultBootstrapBaseURL = defaultAPIBaseURL

// ErrInvalidBootstrapConfig is returned when bootstrap inputs are invalid.
var ErrInvalidBootstrapConfig = errors.New("qurl: invalid bootstrap config")

// ErrAgentStateNotFound is returned when an AgentStateStore has no saved state.
// It is part of the AgentStateStore implementor contract: LoadAgentState returns
// it (and RegisterAgent/BootstrapAgent treat it as "not registered yet", starting
// a fresh enrollment) when no state has been persisted.
var ErrAgentStateNotFound = errors.New("qurl: agent state not found")

// ErrInvalidAgentState is the implementor-contract sibling of ErrAgentStateNotFound:
// an AgentStateStore returns it (or wraps it) from LoadAgentState when persisted
// state EXISTS but cannot be read back — a corrupt or undecodable blob, distinct
// from the not-yet-persisted ErrAgentStateNotFound. The file-backed store returns
// it for a corrupt or malformed state file; a custom store (for example a
// Secrets Manager-backed one) should return it for the same condition. It is a
// store-neutral sentinel: RegisterAgent/BootstrapAgent re-wrap a load failure in
// their own front-door config-error class, so a caller can match either this or
// the front-door sentinel.
var ErrInvalidAgentState = errors.New("qurl: agent state is present but unreadable or corrupt")

// ErrInsecureAgentStatePermissions is returned when file-backed agent state is
// readable by group or other users.
var ErrInsecureAgentStatePermissions = errors.New("qurl: insecure agent state permissions")

// ErrBootstrapSetupKeyConsumed is returned when an incomplete local bootstrap
// retry is rejected because the one-time setup key appears to have already been
// used. Surface this to operators instead of retrying indefinitely: run the
// LayerV setup flow again or restore the completed AgentState.
var ErrBootstrapSetupKeyConsumed = errors.New("qurl: bootstrap setup key already consumed")

// NHPServerPeerInfo is the LayerV peer returned by the bootstrap service.
type NHPServerPeerInfo struct {
	PublicKeyB64 string `json:"public_key_b64"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	// ExpireTime is a Unix timestamp for finite peer leases. The current
	// LayerV bootstrap flow returns 0 for durable peers; a nonzero expired peer
	// is rejected so callers do not continue with stale routing state.
	ExpireTime int64 `json:"expire_time"`
}

// AgentState is the protected local agent identity created during registration
// or bootstrap.
//
// SECURITY: once registration completes, AgentState is a CREDENTIAL FILE — it
// holds DeviceAPIKey, the bearer token the returned Client authorizes with. Treat
// it as secret: keep it out of logs, crash dumps, and support bundles, and keep
// the FileAgentState 0600 / 0700-dir posture. On a shared host, back it with a
// secret manager (for example AWS Secrets Manager via a custom AgentStateStore)
// rather than a world-readable path.
//
// Schema evolution (additive, backward compatible): the v2 fields SchemaVersion,
// DeviceAPIKey, RelayURL, KeyID, and OTPRequestedAt were added for RegisterAgent.
// They are all json:",omitempty" and the pre-v2 fields are unchanged, so a legacy
// (bootstrap-era) state file loads and validates without migration, and a v2 file
// written by RegisterAgent is still readable by older code that ignores the new
// fields. SchemaVersion is informational; the runtime derives readiness from the
// fields themselves (RegisteredAt + DeviceAPIKey), never from the version number.
type AgentState struct {
	AgentID       string             `json:"agent_id,omitempty"`
	PrivateKeyB64 string             `json:"private_key_b64"`
	PublicKeyB64  string             `json:"public_key_b64"`
	RegisteredAt  *time.Time         `json:"registered_at,omitempty"`
	NHPPeer       *NHPServerPeerInfo `json:"nhp_server_peer,omitempty"`

	// --- v2 additive fields (RegisterAgent) ---

	// SchemaVersion is the AgentState schema version. Absent/0 in legacy files;
	// RegisterAgent writes agentStateSchemaVersion. Informational only.
	SchemaVersion int `json:"schema_version,omitempty"`
	// DeviceAPIKey is the device REST bearer credential minted at registration
	// completion. Its presence alongside RegisteredAt marks a state ready to back
	// a Client with zero network. SENSITIVE — see the type doc.
	DeviceAPIKey string `json:"device_api_key,omitempty"`
	// RelayURL records the NHP relay base URL from the most recent
	// registration-info pre-flight. A resume re-fetches registration-info (the
	// authoritative, side-effect-free source) rather than reading this back, so it
	// is a record of the last-known relay, not the source of truth on resume.
	RelayURL string `json:"relay_url,omitempty"`
	// KeyID is the enrollment key id (key_...) from registration-info, carried as
	// the NHP usrId; like RelayURL it is refreshed from a fresh pre-flight on resume.
	KeyID string `json:"key_id,omitempty"`
	// OTPRequestedAt marks the account-key otp_pending state: an email one-time
	// code has been requested and RegisterAgent is waiting for WithOTP. Cleared
	// implicitly once RegisteredAt is set.
	OTPRequestedAt *time.Time `json:"otp_requested_at,omitempty"`
}

// agentStateSchemaVersion is the current AgentState schema version RegisterAgent
// stamps into SchemaVersion. Bumped only on an additive field change that older
// readers can still ignore.
const agentStateSchemaVersion = 2

// AgentStateStore loads and saves the bootstrapped local identity. The
// file-backed store writes plaintext JSON protected by filesystem permissions;
// implement this with KMS or a secret manager when that is not appropriate.
type AgentStateStore interface {
	LoadAgentState(context.Context) (*AgentState, error)
	SaveAgentState(context.Context, *AgentState) error
}

// FileAgentState stores bootstrap state in a local plaintext JSON file written
// 0600. Local filesystem I/O is synchronous; the context passed to LoadAgentState
// or SaveAgentState cannot interrupt a read or write once it has started.
func FileAgentState(path string) AgentStateStore {
	return fileAgentStateStore{path: path}
}

type fileAgentStateStore struct {
	path string
}

func (s fileAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	// Corrupt-content faults use the store-neutral ErrInvalidAgentState class (not
	// a front-door bootstrap/register class): RegisterAgent and BootstrapAgent
	// re-wrap a load failure in their own class, so the front-door match comes
	// from the wrap while this sentinel stays matchable through the chain.
	raw, err := readPrivateStateFile(s.path, "agent state", ErrAgentStateNotFound, ErrInvalidAgentState, ErrInsecureAgentStatePermissions)
	if err != nil {
		return nil, err
	}
	var state AgentState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("%w: decode agent state: %w", ErrInvalidAgentState, err)
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
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("qurl: create agent state dir: %w", err)
	}
	if err := validatePrivateStateDir(dir, "agent state", ErrInvalidBootstrapConfig, ErrInsecureAgentStatePermissions); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".qurl-agent-state-*")
	if err != nil {
		return fmt.Errorf("qurl: create temp agent state: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: write temp agent state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: chmod temp agent state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: sync temp agent state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("qurl: close temp agent state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("qurl: replace agent state: %w", err)
	}
	if err := syncPrivateStateDir(dir, "agent state"); err != nil {
		return err
	}
	return nil
}

// BootstrapOption customizes BootstrapAgent.
type BootstrapOption interface {
	applyBootstrapOption(*bootstrapOptions) error
}

type bootstrapOptionFunc func(*bootstrapOptions) error

func (f bootstrapOptionFunc) applyBootstrapOption(o *bootstrapOptions) error {
	return f(o)
}

type bootstrapOptions struct {
	baseURL    string
	httpClient HTTPDoer
	agentID    string
	hostname   string
	version    string
}

// WithBootstrapBaseURL points BootstrapAgent at a non-default bootstrap origin.
func WithBootstrapBaseURL(rawURL string) BootstrapOption {
	return bootstrapOptionFunc(func(o *bootstrapOptions) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "bootstrap URL", ErrInvalidBootstrapConfig); err != nil {
			return err
		}
		o.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithBootstrapHTTPClient injects the HTTP client used for bootstrap requests.
// Without this option, BootstrapAgent uses a shared client with a 30-second
// timeout and no redirect following; injected clients own their own timeout and
// redirect behavior. Callers can still set shorter deadlines on ctx.
func WithBootstrapHTTPClient(client HTTPDoer) BootstrapOption {
	return bootstrapOptionFunc(func(o *bootstrapOptions) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidBootstrapConfig)
		}
		o.httpClient = client
		return nil
	})
}

// WithAgentID sets the stable local agent id sent during bootstrap.
func WithAgentID(agentID string) BootstrapOption {
	return bootstrapOptionFunc(func(o *bootstrapOptions) error {
		if strings.TrimSpace(agentID) == "" {
			return fmt.Errorf("%w: agent id must not be empty", ErrInvalidBootstrapConfig)
		}
		o.agentID = agentID
		return nil
	})
}

// WithHostname records the local hostname in bootstrap audit metadata.
func WithHostname(hostname string) BootstrapOption {
	return bootstrapOptionFunc(func(o *bootstrapOptions) error {
		if strings.TrimSpace(hostname) == "" {
			return fmt.Errorf("%w: hostname must not be empty", ErrInvalidBootstrapConfig)
		}
		o.hostname = hostname
		return nil
	})
}

// WithVersion records the local build version in bootstrap audit metadata.
func WithVersion(version string) BootstrapOption {
	return bootstrapOptionFunc(func(o *bootstrapOptions) error {
		if strings.TrimSpace(version) == "" {
			return fmt.Errorf("%w: version must not be empty", ErrInvalidBootstrapConfig)
		}
		o.version = version
		return nil
	})
}

// BootstrapAgent consumes a temporary LayerV setup key, enrolls a local X25519
// identity over NHP, and saves that identity in store. The setup key is used for
// this call only; future restarts load the saved AgentState.
//
// Prefer RegisterAgent for new code: it returns a ready-to-use Client and covers
// both the pre-issued-key and email-OTP paths. BootstrapAgent is the pre-issued
// (bootstrap) key path specialized to return the raw AgentState, kept for callers
// that manage the Client separately. It runs the same NHP enrollment engine as
// RegisterAgent's bootstrap path: a registration-info pre-flight, an NHP_REG
// carrying the setup key as the enrollment credential (proving the device key via
// the Noise handshake), and a completion fetch that mints the durable state.
//
// If store already contains a registered AgentState, BootstrapAgent returns it
// without sending the setup key again. If a prior attempt saved only the local
// keypair before enrollment completed, RegisteredAt is nil and calling
// BootstrapAgent again retries with the same device key. That retry depends on
// LayerV treating repeated enrollment for the same device key as idempotent. If
// LayerV instead reports that the one-time setup key was already consumed,
// BootstrapAgent returns ErrBootstrapSetupKeyConsumed so setup code can ask for a
// fresh setup flow instead of retrying forever.
//
// Registered state is validated on load. LayerV bootstrap peers are normally
// durable (ExpireTime is 0); if a future peer record carries a finite expiry and
// has expired, BootstrapAgent fails closed so the caller can run the LayerV setup
// or refresh flow instead of using stale routing state.
//
// Call BootstrapAgent from one setup path at a time for a given store. The SDK
// makes each file write atomic, but it does not lock across concurrent callers or
// processes that share the same state file.
func BootstrapAgent(ctx context.Context, setupKey string, store AgentStateStore, opts ...BootstrapOption) (*AgentState, error) {
	if strings.TrimSpace(setupKey) == "" {
		return nil, fmt.Errorf("%w: setup key must not be empty", ErrInvalidBootstrapConfig)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidBootstrapConfig)
	}
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	cfg := bootstrapOptions{
		baseURL:    defaultBootstrapBaseURL,
		httpClient: defaultAPIHTTPClient,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil BootstrapOption", ErrInvalidBootstrapConfig)
		}
		if err := opt.applyBootstrapOption(&cfg); err != nil {
			return nil, err
		}
	}

	// BootstrapAgent is PATH A specialized: map its options onto the shared
	// registration engine. requireDeviceKey stays false so a legacy bootstrap-era
	// state (registered, no device key) still returns from the fast path.
	rcfg := &registerConfig{
		baseURL:          cfg.baseURL,
		httpClient:       cfg.httpClient,
		deviceID:         cfg.agentID,
		hostname:         cfg.hostname,
		version:          cfg.version,
		invalidConfigErr: ErrInvalidBootstrapConfig,
		clock:            time.Now,
	}
	state, err := rcfg.run(ctx, setupKey, store)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// validateRegisteredAgentState checks a loaded, already-registered state. errKind
// is the caller-facing sentinel wrapped into failures so each front door keeps
// its class (BootstrapAgent → ErrInvalidBootstrapConfig, RegisterAgent →
// ErrInvalidRegisterConfig).
func validateRegisteredAgentState(state *AgentState, now time.Time, errKind error) error {
	if state == nil {
		return fmt.Errorf("%w: registered agent state is nil", errKind)
	}
	if strings.TrimSpace(state.AgentID) == "" {
		return fmt.Errorf("%w: registered agent state missing agent id", errKind)
	}
	if state.RegisteredAt == nil {
		return fmt.Errorf("%w: registered agent state missing registration time", errKind)
	}
	if state.NHPPeer == nil {
		return fmt.Errorf("%w: registered agent state missing NHP peer", errKind)
	}
	return validateNHPServerPeerInfo(*state.NHPPeer, now, "registered agent state", errKind)
}

// validateNHPServerPeerInfo checks an NHP peer record. errKind is the sentinel
// wrapped into every failure so the caller's error class flows through: bootstrap
// callers pass ErrInvalidBootstrapConfig, registration callers pass
// ErrInvalidRegisterConfig.
func validateNHPServerPeerInfo(peer NHPServerPeerInfo, now time.Time, label string, errKind error) error {
	if strings.TrimSpace(peer.PublicKeyB64) == "" {
		return fmt.Errorf("%w: %s missing NHP peer public key", errKind, label)
	}
	peerKey, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("%w: %s NHP peer public key is not standard base64: %w", errKind, label, err)
	}
	if _, err := ecdh.X25519().NewPublicKey(peerKey); err != nil {
		return fmt.Errorf("%w: %s NHP peer public key is not X25519: %w", errKind, label, err)
	}
	if strings.TrimSpace(peer.Host) == "" {
		return fmt.Errorf("%w: %s missing NHP peer host", errKind, label)
	}
	if peer.Port <= 0 {
		return fmt.Errorf("%w: %s missing NHP peer port", errKind, label)
	}
	if peer.Port > 65535 {
		return fmt.Errorf("%w: %s NHP peer port out of range", errKind, label)
	}
	if peer.ExpireTime != 0 && peer.ExpireTime <= now.Unix() {
		return fmt.Errorf("%w: %s NHP peer is expired", errKind, label)
	}
	return nil
}

// loadOrCreateAgentState loads the persisted state (creating a fresh keypair when
// none exists), validating a loaded keypair. invalidConfigErr is the caller's
// front-door config-error class wrapped into a load or keypair failure, so each
// entry point keeps its documented class (RegisterAgent → ErrInvalidRegisterConfig,
// BootstrapAgent → ErrInvalidBootstrapConfig) while the underlying store sentinel
// (ErrInvalidAgentState / ErrInsecureAgentStatePermissions / …) stays matchable
// through the double-wrap.
func loadOrCreateAgentState(ctx context.Context, store AgentStateStore, invalidConfigErr error) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if err := state.ensureKeypair(invalidConfigErr); err != nil {
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
