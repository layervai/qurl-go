package qurl

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// run RefreshAgentRegistration separately.
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

// RefreshAgentRegistration forces a real registration-info + NHP_REG/NHP_RAK
// exchange for an existing completed agent. It never calls registration
// completion and therefore never mints or replaces DeviceAPIKey. Relay, peer,
// and key metadata are committed only after an authenticated successful RAK.
// The returned AgentState includes the live plaintext DeviceAPIKey and must be
// handled as sensitive credential material.
// An account key follows the email-OTP flow and may require a dispatch plus a
// second call with WithOTP/WithOTPProvider. Fleet connectors should normally
// enforce RegistrationKeyKindBootstrap with WithAllowedRegistrationKeyKinds so
// a binding refresh cannot fan out operator OTP emails.
func RefreshAgentRegistration(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*AgentState, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	return withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadCompletedRegisteredState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, false)
	})
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

// validateCompletedAgentIdentity checks only the durable identity/credential
// fields a forced refresh needs. It deliberately does not require the old peer
// or relay: replacing missing, expired, or rotated binding metadata is the
// purpose of RefreshAgentRegistration.
func validateCompletedAgentIdentity(state *AgentState, errKind error) error {
	if state == nil {
		return fmt.Errorf("%w: registered agent state is nil", errKind)
	}
	if strings.TrimSpace(state.AgentID) == "" {
		return fmt.Errorf("%w: registered agent state missing agent id", errKind)
	}
	if state.RegisteredAt == nil {
		return fmt.Errorf("%w: registered agent state missing registration time", errKind)
	}
	return nil
}

// RecoverAgentCredential explicitly replaces a revoked/lost device credential
// while preserving the persisted device id and X25519 keypair. It always sends
// REG and calls completion exactly once. It is never invoked implicitly after a
// 401. The owner must first revoke agent:<device_id>, which clears qurl-service's
// first-issue sentinel; otherwise completion returns ErrCredentialRecoveryRequired.
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
	info, err := cfg.fetchRegistrationInfo(ctx, key)
	if err != nil {
		return nil, err
	}
	if err := cfg.requireAllowedKeyKind(info.KeyKind); err != nil {
		return nil, err
	}
	if err := cfg.assertServerIDMatches(info.Relay.ServerID, &info.NHPServerPeer); err != nil {
		return nil, err
	}
	peer := cfg.resolvePeer(info)
	relayURL := cfg.resolveRelayURL(info)

	// Shallow copy is intentional: pointer fields may alias the loaded state, but
	// lifecycle code only reassigns those pointers and never mutates pointees.
	candidate := *state
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

func (cfg *registerConfig) forcedRegistrationCredential(ctx context.Context, key string, store AgentStateStore, persisted, candidate *AgentState, info *registrationInfoResponse) (string, pathKind, error) {
	switch strings.TrimSpace(info.KeyKind) {
	case keyKindBootstrap:
		return key, pathBootstrap, nil
	case keyKindAccount:
		if strings.TrimSpace(info.MaskedEmail) == "" {
			return "", pathAccount, errAccountKeyMissingEmail()
		}
		now := cfg.clock()
		dispatchDue := persisted.OTPRequestedAt == nil || now.Sub(*persisted.OTPRequestedAt) >= otpResendCooldown
		// A literal OTP is necessarily from a prior dispatch, so use it directly.
		// A provider may be waiting for the email from this call, so dispatch first.
		if cfg.otp == "" && dispatchDue {
			// candidate carries the refreshed coordinates; send over them rather
			// than the persisted (possibly stale) binding.
			if err := cfg.requestOTPAt(ctx, store, persisted, candidate, candidate.NHPPeer, candidate.RelayURL, key, now); err != nil {
				return "", pathAccount, err
			}
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
