package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultBootstrapBaseURL = "https://bootstrap.layerv.ai"

// ErrInvalidBootstrapConfig is returned when bootstrap inputs are invalid.
var ErrInvalidBootstrapConfig = errors.New("qurl: invalid bootstrap config")

// ErrAgentStateNotFound is returned when an AgentStateStore has no saved state.
var ErrAgentStateNotFound = errors.New("qurl: agent state not found")

// ErrInsecureAgentStatePermissions is returned when file-backed agent state is
// readable by group or other users.
var ErrInsecureAgentStatePermissions = errors.New("qurl: insecure agent state permissions")

// NHPServerPeerInfo is the LayerV peer returned by the bootstrap service.
type NHPServerPeerInfo struct {
	PublicKeyB64 string `json:"public_key_b64"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ExpireTime   int64  `json:"expire_time"`
}

// AgentState is the protected local identity created during bootstrap.
type AgentState struct {
	AgentID       string             `json:"agent_id,omitempty"`
	PrivateKeyB64 string             `json:"private_key_b64"`
	PublicKeyB64  string             `json:"public_key_b64"`
	RegisteredAt  *time.Time         `json:"registered_at,omitempty"`
	NHPPeer       *NHPServerPeerInfo `json:"nhp_server_peer,omitempty"`
}

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

func (s fileAgentStateStore) LoadAgentState(context.Context) (*AgentState, error) {
	raw, err := readPrivateStateFile(s.path, "agent state", ErrAgentStateNotFound, ErrInvalidBootstrapConfig, ErrInsecureAgentStatePermissions)
	if err != nil {
		return nil, err
	}
	var state AgentState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("qurl: decode agent state: %w", err)
	}
	return &state, nil
}

func (s fileAgentStateStore) SaveAgentState(_ context.Context, state *AgentState) error {
	if strings.TrimSpace(s.path) == "" {
		return fmt.Errorf("%w: state path must not be empty", ErrInvalidBootstrapConfig)
	}
	if state == nil {
		return fmt.Errorf("%w: state must not be nil", ErrInvalidBootstrapConfig)
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

// BootstrapAgent consumes a temporary LayerV setup key, registers a local
// X25519 identity, and saves that identity in store. The setup key is used for
// this call only; future restarts load the saved AgentState.
//
// If store already contains a registered AgentState, BootstrapAgent returns it
// without sending the setup key again. If a prior attempt saved only the local
// keypair before receiving the API response, RegisteredAt is nil and calling
// BootstrapAgent again retries registration with the same public key. That
// lost-response retry depends on LayerV treating repeated registration for the
// same public key as idempotent.
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
	cfg := bootstrapOptions{
		baseURL:    defaultBootstrapBaseURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil BootstrapOption", ErrInvalidBootstrapConfig)
		}
		if err := opt.applyBootstrapOption(&cfg); err != nil {
			return nil, err
		}
	}

	state, err := loadOrCreateAgentState(ctx, store)
	if err != nil {
		return nil, err
	}
	if state.RegisteredAt != nil {
		if state.NHPPeer == nil {
			return nil, fmt.Errorf("%w: registered agent state is missing NHP peer", ErrInvalidBootstrapConfig)
		}
		if cfg.agentID != "" && state.AgentID != "" && cfg.agentID != state.AgentID {
			return nil, fmt.Errorf("%w: saved agent id %q does not match requested agent id %q", ErrInvalidBootstrapConfig, state.AgentID, cfg.agentID)
		}
		return state, nil
	}
	if cfg.agentID != "" {
		state.AgentID = cfg.agentID
	}
	// Persist the generated keypair before the network call so a failed or
	// interrupted bootstrap retry uses the same local identity. Until the API
	// response is saved, nil RegisteredAt/NHPPeer means registration is not yet
	// complete and BootstrapAgent should be retried.
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}

	reqBody := agentBootstrapRequest{
		PublicKey: state.PublicKeyB64,
		AgentID:   cfg.agentID,
		Hostname:  cfg.hostname,
		Version:   cfg.version,
	}
	var env apiEnvelope[agentBootstrapResponse]
	if err := doAuthorizedJSON(ctx, cfg.httpClient, cfg.baseURL, BearerToken(setupKey).Authorize, http.MethodPost, "/v1/agent/bootstrap", reqBody, &env); err != nil {
		return nil, err
	}
	if err := env.Data.validate(); err != nil {
		return nil, err
	}

	state.AgentID = env.Data.AgentID
	state.RegisteredAt = env.Data.RegisteredAt
	state.NHPPeer = &env.Data.NHPPeer
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}
	return state, nil
}

type agentBootstrapRequest struct {
	PublicKey string `json:"public_key"`
	AgentID   string `json:"agent_id,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Version   string `json:"version,omitempty"`
}

type agentBootstrapResponse struct {
	AgentID      string            `json:"agent_id"`
	RegisteredAt *time.Time        `json:"registered_at"`
	NHPPeer      NHPServerPeerInfo `json:"nhp_server_peer"`
}

func (r agentBootstrapResponse) validate() error {
	if strings.TrimSpace(r.AgentID) == "" {
		return fmt.Errorf("%w: bootstrap response missing agent id", ErrInvalidBootstrapConfig)
	}
	if r.RegisteredAt == nil {
		return fmt.Errorf("%w: bootstrap response missing registration time", ErrInvalidBootstrapConfig)
	}
	if strings.TrimSpace(r.NHPPeer.PublicKeyB64) == "" {
		return fmt.Errorf("%w: bootstrap response missing NHP peer public key", ErrInvalidBootstrapConfig)
	}
	peerKey, err := base64.StdEncoding.Strict().DecodeString(r.NHPPeer.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("%w: bootstrap response NHP peer public key is not standard base64: %w", ErrInvalidBootstrapConfig, err)
	}
	if _, err := ecdh.X25519().NewPublicKey(peerKey); err != nil {
		return fmt.Errorf("%w: bootstrap response NHP peer public key is not X25519: %w", ErrInvalidBootstrapConfig, err)
	}
	if strings.TrimSpace(r.NHPPeer.Host) == "" {
		return fmt.Errorf("%w: bootstrap response missing NHP peer host", ErrInvalidBootstrapConfig)
	}
	if r.NHPPeer.Port <= 0 {
		return fmt.Errorf("%w: bootstrap response missing NHP peer port", ErrInvalidBootstrapConfig)
	}
	return nil
}

func loadOrCreateAgentState(ctx context.Context, store AgentStateStore) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if err := state.ensureKeypair(); err != nil {
			return nil, err
		}
		return state, nil
	case errors.Is(err, ErrAgentStateNotFound):
		return newAgentState()
	default:
		return nil, err
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

func (s *AgentState) ensureKeypair() error {
	if s == nil {
		return fmt.Errorf("%w: state must not be nil", ErrInvalidBootstrapConfig)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s.PrivateKeyB64)
	if err != nil {
		return fmt.Errorf("%w: decode agent private key: %w", ErrInvalidBootstrapConfig, err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return fmt.Errorf("%w: agent private key must be X25519", ErrInvalidBootstrapConfig)
	}
	publicKey := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if s.PublicKeyB64 == "" {
		s.PublicKeyB64 = publicKey
	}
	if s.PublicKeyB64 != publicKey {
		return fmt.Errorf("%w: agent public key does not match private key", ErrInvalidBootstrapConfig)
	}
	return nil
}
