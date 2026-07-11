package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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
	if store == nil {
		return nil, fmt.Errorf("%w: agent state store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return nil, err
	}
	cfg, err := applyClientOptions(opts)
	if err != nil {
		return nil, err
	}
	if cfg.issuerStatePath != "" {
		return nil, fmt.Errorf("%w: WithIssuerStatePath is not valid with OpenRegisteredAgent", ErrInvalidClientConfig)
	}
	if _, err := loadCompletedRegisteredState(ctx, store, ErrInvalidClientConfig); err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.baseURL, cfg.httpClient), nil
}

// AgentRuntimeBinding is the refreshed identity and NHP endpoint needed for an
// immediate relay knock. It deliberately excludes DeviceAPIKey, schema, and OTP
// state. The private key remains sensitive: obtain a caller-owned copy with
// DeviceStaticPrivateKey, wipe that copy after use, and call Destroy when the
// binding is no longer needed. Do not copy or log the binding.
type AgentRuntimeBinding struct {
	AgentID      string
	PublicKeyB64 string
	RegisteredAt time.Time
	NHPPeer      NHPServerPeerInfo
	RelayURL     string
	KeyID        string

	deviceStaticPrivateKey []byte
}

// String returns a redacted runtime summary.
func (b AgentRuntimeBinding) String() string {
	return fmt.Sprintf("qurl.AgentRuntimeBinding{AgentID:%q, RelayURL:%q, KeyID:%q, DeviceStaticPrivateKey:[REDACTED]}", b.AgentID, b.RelayURL, b.KeyID)
}

// GoString returns a redacted runtime summary for %#v formatting.
func (b AgentRuntimeBinding) GoString() string { return b.String() }

// DeviceStaticPrivateKey returns a fresh caller-owned copy of the 32-byte
// X25519 private key suitable for relayknock.KnockOptions. The caller must wipe
// the returned slice after the knocker no longer needs it.
func (b *AgentRuntimeBinding) DeviceStaticPrivateKey() []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b.deviceStaticPrivateKey...)
}

// Destroy best-effort wipes the private-key bytes retained by the binding. It
// is idempotent. The binding must not be used concurrently with Destroy.
func (b *AgentRuntimeBinding) Destroy() {
	if b == nil {
		return
	}
	wipeBytes(b.deviceStaticPrivateKey)
	b.deviceStaticPrivateKey = nil
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
// it, and a successful resumed RAK clears it. Fleet connectors should normally
// allow only RegistrationKeyKindBootstrap so refresh cannot fan out OTP email.
func RefreshAgentRegistration(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*AgentRuntimeBinding, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	state, err := withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadCompletedRegisteredState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, false)
	})
	if err != nil {
		return nil, err
	}
	return newAgentRuntimeBinding(state)
}

func newAgentRuntimeBinding(state *AgentState) (*AgentRuntimeBinding, error) {
	if state == nil || state.RegisteredAt == nil || state.NHPPeer == nil {
		return nil, fmt.Errorf("%w: refreshed agent state is incomplete", ErrInvalidRegisterConfig)
	}
	privateKey, err := base64.StdEncoding.Strict().DecodeString(state.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refreshed agent private key: %w", ErrInvalidRegisterConfig, err)
	}
	if len(privateKey) != 32 {
		wipeBytes(privateKey)
		return nil, fmt.Errorf("%w: refreshed agent private key must be 32 bytes", ErrInvalidRegisterConfig)
	}
	return &AgentRuntimeBinding{
		AgentID:                state.AgentID,
		PublicKeyB64:           state.PublicKeyB64,
		RegisteredAt:           *state.RegisteredAt,
		NHPPeer:                *state.NHPPeer,
		RelayURL:               state.RelayURL,
		KeyID:                  state.KeyID,
		deviceStaticPrivateKey: privateKey,
	}, nil
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
// newly dispatched code. Fleet connectors should normally enforce
// RegistrationKeyKindBootstrap with WithAllowedRegistrationKeyKinds so recovery
// cannot fan out operator OTP emails. Recovery is never invoked implicitly after
// a 401. The owner must first revoke agent:<device_id>, which clears qurl-service's
// first-issue sentinel; otherwise completion returns ErrCredentialRecoveryRequired.
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
func RecoverAgentCredential(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*Client, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	_, err = withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadExistingAgentState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(state.AgentID) == "" {
			return nil, fmt.Errorf("%w: agent state missing persisted device id", cfg.invalidConfigErr)
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, true)
	})
	if err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.clientBaseURL, cfg.clientHTTPClient), nil
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

	// Isolate the candidate's retained pointer fields from the loaded state. The
	// peer is replaced immediately below, but registration time and an existing
	// OTP marker survive until the transition decides what to persist. Cloning the
	// marker is defensive even though success later clears it: paused/error paths
	// return earlier, and no future candidate mutation may alias the loaded state.
	candidate := *state
	candidate.RegisteredAt = cloneLifecycleTime(state.RegisteredAt)
	candidate.OTPRequestedAt = cloneLifecycleTime(state.OTPRequestedAt)
	candidate.NHPPeer = peer
	candidate.RelayURL = relayURL
	candidate.KeyID = info.KeyID
	candidate.SchemaVersion = agentStateSchemaVersion

	credential, path, err := cfg.forcedRegistrationCredential(ctx, key, store, state, &candidate, info)
	if err != nil {
		return nil, err
	}
	if recovery {
		// Recovery REGs and then mints the replacement credential exactly once,
		// through the same REG -> success-check -> completion tail enrollment uses.
		return cfg.registerAndComplete(ctx, key, store, &candidate, peer, relayURL, credential, path)
	}
	// Refresh commits the refreshed binding metadata after an authenticated RAK
	// and stops: DeviceAPIKey and RegisteredAt are copied from the prior state and
	// never touched.
	if err := cfg.registerExchangeChecked(ctx, &candidate, peer, relayURL, credential, path); err != nil {
		return nil, err
	}
	candidate.OTPRequestedAt = nil

	if err := store.SaveAgentState(ctx, &candidate); err != nil {
		return nil, err
	}
	return &candidate, nil
}

func cloneLifecycleTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (cfg *registerConfig) forcedRegistrationCredential(ctx context.Context, key string, store AgentStateStore, persisted, candidate *AgentState, info *registrationInfoResponse) (string, pathKind, error) {
	switch strings.TrimSpace(info.KeyKind) {
	case keyKindBootstrap:
		return key, pathBootstrap, nil
	case keyKindAccount:
		if err := requireAccountKeyEmail(info); err != nil {
			return "", pathAccount, err
		}
		now := cfg.clock()
		freshRequest := persisted.OTPRequestedAt == nil
		dispatchDue := persisted.OTPRequestedAt == nil || now.Sub(*persisted.OTPRequestedAt) >= otpResendCooldown
		// A provider may await the email from this call, so dispatch first. A
		// literal on a fresh lifecycle call cannot match the newly dispatched code:
		// persist/send, then pause so the caller can resume with the received code.
		if dispatchDue && (cfg.otp == "" || freshRequest) {
			// candidate carries the refreshed coordinates; requestOTPAt sends over
			// them rather than the persisted (possibly stale) binding.
			if err := cfg.requestOTPAt(ctx, store, persisted, candidate, key, now); err != nil {
				return "", pathAccount, err
			}
		}
		if freshRequest && cfg.otp != "" {
			return "", pathAccount, cfg.otpPending(persisted, info.MaskedEmail)
		}
		code, err := cfg.resolveOTP(ctx)
		if err != nil {
			return "", pathAccount, err
		}
		if code != "" {
			return code, pathAccount, nil
		}
		return "", pathAccount, cfg.otpPending(persisted, info.MaskedEmail)
	default:
		return "", pathBootstrap, cfg.errUnknownKeyKind(info.KeyKind)
	}
}
