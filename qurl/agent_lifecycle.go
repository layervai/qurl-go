package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

// OpenRegisteredAgent opens a Client from a completed AgentState without making
// enrollment or resource API calls. Loading a custom network-backed store may
// still perform the store's own I/O, and loading a sealed store may call its key
// wrapper or KMS.
// The device credential is read from store behind a one-minute cache. A later
// explicit credential recovery is observed after that cache expires; callers
// that need the replacement immediately should use the Client returned by
// RecoverAgentCredential. NHP peer absence, corruption, or expiry does not
// invalidate this REST client; callers that will knock must validate the peer or
// run RefreshAgentRegistration separately. The persisted agent id and X25519
// keypair are still required and validated as the durable device identity.
//
// WithAgentClientBaseURL and WithAgentClientHTTPClient are dual-purpose options
// accepted here and by RegisterAgent/RecoverAgentCredential, so one resource
// origin/transport configuration can be reused across the lifecycle. Ordinary
// WithBaseURL and WithHTTPClient ClientOptions remain supported here too.
func OpenRegisteredAgent(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, error) {
	cfg, err := validateRegisteredAgentOpenInputs(ctx, store, opts)
	if err != nil {
		return nil, err
	}
	if _, err := loadCompletedRegisteredState(ctx, store, ErrInvalidClientConfig); err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.baseURL, cfg.httpClient), nil
}

// OpenRegisteredAgentRuntime opens both a store-backed resource Client and the
// validated runtime binding needed for an immediate relay knock. It performs one
// AgentStateStore load, no enrollment/resource API calls, requires a live NHP
// peer plus valid relay/key metadata, and primes the Client's one-minute
// credential cache from that same state so its first request does not reload or
// unseal the store. The caller must immediately defer binding.Destroy, then take
// and eventually wipe the runtime private key.
func OpenRegisteredAgentRuntime(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, *AgentRuntimeBinding, error) {
	cfg, err := validateRegisteredAgentOpenInputs(ctx, store, opts)
	if err != nil {
		return nil, nil, err
	}
	state, err := loadCompletedRegisteredState(ctx, store, ErrInvalidClientConfig)
	if err != nil {
		return nil, nil, err
	}
	if err := validateAgentRuntimeMetadata(state, time.Now(), ErrInvalidClientConfig); err != nil {
		return nil, nil, err
	}
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidClientConfig)
	if err != nil {
		return nil, nil, err
	}
	client := newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey)
	return client, newAgentRuntimeBinding(state, privateKey), nil
}

func validateRegisteredAgentOpenInputs(ctx context.Context, store AgentStateStore, opts []ClientOption) (clientOptions, error) {
	if store == nil {
		return clientOptions{}, fmt.Errorf("%w: agent state store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return clientOptions{}, err
	}
	cfg, err := applyClientOptions(opts)
	if err != nil {
		return clientOptions{}, err
	}
	if cfg.issuerStatePath != "" {
		return clientOptions{}, fmt.Errorf("%w: WithIssuerStatePath is not valid with registered-agent open APIs", ErrInvalidClientConfig)
	}
	return cfg, nil
}

// AgentRuntimeBinding is a registered or refreshed identity and NHP endpoint
// needed for an immediate relay knock. It deliberately excludes DeviceAPIKey,
// schema, and OTP state. The private key remains sensitive. Treat the returned
// pointer as the owning handle: do not copy or log the binding. Accidental value
// copies share one synchronized key owner, so they cannot duplicate the one-shot
// transfer. Immediately defer Destroy after a successful lifecycle call,
// transfer key ownership exactly once with TakeDeviceStaticPrivateKey, and wipe
// those bytes after use. A runtime cleanup best-effort wipes a retained key only
// after every accidental copy becomes unreachable; it is defense in depth, not
// a substitute for deterministic Destroy.
type AgentRuntimeBinding struct {
	AgentID      string
	PublicKeyB64 string
	RegisteredAt time.Time
	NHPPeer      NHPServerPeerInfo
	RelayURL     string
	KeyID        string

	deviceStaticPrivateKey *agentRuntimePrivateKey
}

// agentRuntimePrivateKey centralizes one-shot ownership across accidental
// AgentRuntimeBinding value copies. A conventional noCopy marker on the binding
// is intentionally unsuitable: go vet would reject the value-receiver
// String/GoString methods required to redact explicitly dereferenced formatting.
// Sharing this synchronized cell makes the underlying copy hazard safe instead.
type agentRuntimePrivateKey struct {
	mu      sync.Mutex
	value   []byte
	cleanup *runtime.Cleanup
}

func newAgentRuntimePrivateKey(value []byte) *agentRuntimePrivateKey {
	key := &agentRuntimePrivateKey{value: value}
	cleanup := runtime.AddCleanup(key, wipeBytes, value)
	key.cleanup = &cleanup
	return key
}

func (k *agentRuntimePrivateKey) stopCleanupLocked() {
	if k.cleanup == nil {
		return
	}
	k.cleanup.Stop()
	k.cleanup = nil
}

func (k *agentRuntimePrivateKey) take() []byte {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopCleanupLocked()
	value := k.value
	k.value = nil
	return value
}

func (k *agentRuntimePrivateKey) destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopCleanupLocked()
	wipeBytes(k.value)
	k.value = nil
}

// String returns a redacted runtime summary. The value receiver deliberately
// protects both pointer and dereferenced-value formatting; its copy contains
// only a pointer to the synchronized key owner and does not transfer key
// ownership. Callers must still avoid making binding copies.
func (b AgentRuntimeBinding) String() string {
	return fmt.Sprintf("qurl.AgentRuntimeBinding{AgentID:%q, RelayURL:%q, KeyID:%q, DeviceStaticPrivateKey:[REDACTED]}", b.AgentID, b.RelayURL, b.KeyID)
}

// GoString returns a redacted runtime summary for pointer or value %#v
// formatting.
func (b AgentRuntimeBinding) GoString() string { return b.String() }

// TakeDeviceStaticPrivateKey transfers ownership of the retained 32-byte X25519
// private key for relayknock.KnockOptions and clears it from the binding. It
// returns nil after the first call. The caller must wipe the returned slice
// after the knocker no longer needs it.
func (b *AgentRuntimeBinding) TakeDeviceStaticPrivateKey() []byte {
	if b == nil {
		return nil
	}
	return b.deviceStaticPrivateKey.take()
}

// Destroy best-effort wipes the private-key bytes retained by the binding. It
// is idempotent and becomes a no-op after TakeDeviceStaticPrivateKey transfers
// ownership. It is synchronized with TakeDeviceStaticPrivateKey across
// accidental value copies, though callers should still keep the pointer-owned
// lifecycle explicit.
func (b *AgentRuntimeBinding) Destroy() {
	if b == nil {
		return
	}
	b.deviceStaticPrivateKey.destroy()
}

// RefreshAgentRegistration forces registration-info plus an authenticated
// NHP_REG/NHP_RAK exchange for an existing completed agent. It commits refreshed
// binding metadata after RAK but never calls completion or changes DeviceAPIKey.
// It returns a narrow AgentRuntimeBinding for an immediate knock without another
// store/KMS load; the preserved DeviceAPIKey remains only in the configured
// store.
//
// An account key may pause with OTPPendingError. Its durable OTPRequestedAt
// marker intentionally remains on the completed state across a paused or
// abandoned attempt to throttle repeat dispatches; OpenRegisteredAgent ignores
// it, and a successful resumed RAK clears it. Refresh defaults to bootstrap
// keys so routine fleet repair cannot fan out OTP email; an interactive account
// flow requires an explicit WithAllowedRegistrationKeyKinds opt-in.
func RefreshAgentRegistration(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*AgentRuntimeBinding, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	cfg.applyLifecycleDefaultKeyPolicy()
	var privateKey []byte
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
		wipeBytes(privateKey)
		return nil, err
	}
	return newAgentRuntimeBinding(state, privateKey), nil
}

func decodeRuntimePrivateKey(state *AgentState, errKind error) ([]byte, error) {
	// Device private keys are generated and persisted only by this SDK using
	// padded StdEncoding. Unlike server public keys received across the wire,
	// accepting RawStdEncoding here would expand a local custody format that has
	// no legitimate raw producer and could conceal state corruption.
	privateKey, err := base64.StdEncoding.Strict().DecodeString(state.PrivateKeyB64)
	if err != nil {
		wipeBytes(privateKey)
		return nil, fmt.Errorf("%w: decode agent runtime private key: %w", errKind, err)
	}
	if len(privateKey) != 32 {
		wipeBytes(privateKey)
		return nil, fmt.Errorf("%w: agent runtime private key must be 32 bytes", errKind)
	}
	return privateKey, nil
}

// newAgentRuntimeBinding is deliberately infallible: callers decode the
// retained private key before any lifecycle network I/O and validate runtime
// metadata before calling it. Mutating lifecycle paths additionally wait until
// state is durably saved and the setup lock is released. Preconditions:
// state, state.RegisteredAt, and state.NHPPeer are non-nil, and privateKey is a
// validated 32-byte X25519 key owned by this constructor.
func newAgentRuntimeBinding(state *AgentState, privateKey []byte) *AgentRuntimeBinding {
	return &AgentRuntimeBinding{
		AgentID:                state.AgentID,
		PublicKeyB64:           state.PublicKeyB64,
		RegisteredAt:           *state.RegisteredAt,
		NHPPeer:                *state.NHPPeer,
		RelayURL:               state.RelayURL,
		KeyID:                  state.KeyID,
		deviceStaticPrivateKey: newAgentRuntimePrivateKey(privateKey),
	}
}

// loadCompletedRegisteredState enforces the completed identity and intact
// credential precondition shared by OpenRegisteredAgent and binding refresh.
// Recovery intentionally does not use it: it repairs the missing-credential
// state and requires only the persisted device identity/keypair.
func loadCompletedRegisteredState(ctx context.Context, store AgentStateStore, errKind error) (*AgentState, error) {
	state, err := loadExistingAgentState(ctx, store, errKind)
	if err != nil {
		return nil, err
	}
	if err := validateCompletedAgentIdentity(state, errKind); err != nil {
		return nil, err
	}
	if err := validatePersistedDeviceCredential(state, errKind); err != nil {
		return nil, err
	}
	return state, nil
}

// RecoverAgentCredential explicitly replaces a revoked/lost device credential
// while preserving the persisted device id and X25519 keypair. Once enrollment
// authorization is available, it sends REG and calls completion exactly once.
// An account key may first dispatch email OTP and return OTPPendingError; resume
// with the received code via WithOTP, or use a WithOTPProvider that awaits the
// newly dispatched code. Recovery defaults to bootstrap keys; an interactive
// account flow requires explicit WithAllowedRegistrationKeyKinds opt-in, so
// routine repair cannot fan out operator OTP emails.
//
// Recovery is never invoked implicitly after a 401. The owner must first revoke
// agent:<device_id>, which clears qurl-service's first-issue sentinel; otherwise
// completion returns ErrCredentialRecoveryRequired.
// Recovery still proceeds when local state contains DeviceAPIKey: owner-side
// revocation is authoritative, and the retained local value may already be
// revoked. A local healthy-key no-op guard would prevent valid replacement.
// Recovery deliberately does not run a completion probe: completion is the
// first-issue operation itself. If the process dies after replacement mint but
// before durable persistence, the next recovery fails already-issued; the owner
// must revoke the active device key again before another explicit recovery cycle.
// If this returns ErrAgentSetupLock after lock release, load the durable state or
// call OpenRegisteredAgent before retrying: completion and persistence may have
// succeeded even though the lock could not be released cleanly.
// RegisteredAt is not required: this API also repairs the post-completion state
// where the service may have minted a credential but its local save failed.
// On success, immediately discard every pre-existing Client for this agent and
// use the returned Client: older Clients may cache the revoked credential for up
// to one minute, while the returned Client observes the replacement immediately.
func RecoverAgentCredential(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*Client, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	cfg.applyLifecycleDefaultKeyPolicy()
	state, err := withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadExistingAgentState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if err := validatePersistedAgentID(state, cfg.invalidConfigErr); err != nil {
			return nil, err
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, true)
	})
	if err != nil {
		return nil, err
	}
	// Lock release has succeeded, so state is the exact replacement credential
	// now committed to the authoritative store. Prime the new Client from it for
	// immediate cutover without a second store/KMS load; older Clients still keep
	// their prior cache until expiry and must be discarded by the caller.
	return newPrimedStoreBackedClient(store, cfg.clientBaseURL, cfg.clientHTTPClient, state.DeviceAPIKey), nil
}

func loadExistingAgentState(ctx context.Context, store AgentStateStore, errKind error) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: load agent state: %w", errKind, err)
	}
	if state == nil {
		return nil, fmt.Errorf("%w: agent state store returned nil state", errKind)
	}
	if err := state.ensureKeypair(errKind); err != nil {
		return nil, err
	}
	return state, nil
}

// withAgentSetupLock holds the SDK local-file setup lock across an entire state
// transition and makes release failure override a nominal success. It is shared
// by initial registration, refresh, and recovery. Custom and network stores
// retain the documented caller-serialization requirement.
func withAgentSetupLock(ctx context.Context, store AgentStateStore, fn func() (*AgentState, error)) (result *AgentState, resultErr error) {
	release, err := acquireAgentSetupLock(ctx, store)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := release(); err != nil {
			lockErr := fmt.Errorf("%w: release setup lock: %w", ErrAgentSetupLock, err)
			result = nil
			if resultErr == nil {
				resultErr = lockErr
			} else {
				resultErr = errors.Join(resultErr, lockErr)
			}
		}
	}()
	return fn()
}

// forceRegistration is the shared refresh/recovery engine. recovery controls
// the sole semantic difference: refresh commits metadata after RAK and stops;
// recovery then calls completion exactly once and persists its replacement key.
func (cfg *registerConfig) forceRegistration(ctx context.Context, key string, store AgentStateStore, state *AgentState, recovery bool) (*AgentState, error) {
	info, peer, relayURL, err := cfg.preflight(ctx, key)
	if err != nil {
		return nil, err
	}

	// Isolate every mutable field from the loaded state before the transition
	// decides what to persist. The peer is replaced immediately below, while
	// registration time and an OTP marker may survive paused/error paths.
	candidate := state.clone()
	candidate.NHPPeer = peer
	candidate.RelayURL = relayURL
	candidate.KeyID = info.KeyID
	candidate.SchemaVersion = agentStateSchemaVersion

	credential, path, err := cfg.forcedRegistrationCredential(ctx, key, store, state, candidate, info)
	if err != nil {
		return nil, err
	}
	if recovery {
		// Recovery REGs and then mints the replacement credential exactly once,
		// through the same REG -> success-check -> completion tail enrollment uses.
		return cfg.registerAndComplete(ctx, key, store, candidate, peer, relayURL, credential, path)
	}
	// Refresh commits the refreshed binding metadata after an authenticated RAK
	// and stops: DeviceAPIKey and RegisteredAt are copied from the prior state and
	// never touched.
	if err := cfg.registerExchangeChecked(ctx, candidate, peer, relayURL, credential, path); err != nil {
		return nil, err
	}
	candidate.OTPRequestedAt = nil

	if err := store.SaveAgentState(ctx, candidate); err != nil {
		return nil, fmt.Errorf("%w: persist refreshed binding: %w", ErrAgentBindingPersistence, err)
	}
	return candidate, nil
}

func (cfg *registerConfig) forcedRegistrationCredential(ctx context.Context, key string, store AgentStateStore, persisted, candidate *AgentState, info *registrationInfoResponse) (string, pathKind, error) {
	switch strings.TrimSpace(info.KeyKind) {
	case keyKindBootstrap:
		return key, pathBootstrap, nil
	case keyKindAccount:
		if err := requireAccountKeyEmail(info); err != nil {
			return "", pathAccount, err
		}
		code, err := cfg.accountCredentialOrPause(ctx, key, store, persisted, candidate, info.MaskedEmail)
		return code, pathAccount, err
	default:
		return "", pathBootstrap, cfg.errUnknownKeyKind(info.KeyKind)
	}
}
