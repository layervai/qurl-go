package qurl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OpenRegisteredAgent opens a zero-network Client from a completed AgentState.
// The device credential is read from store on demand, so a later explicit
// credential recovery is observed without rebuilding the client. NHP peer
// expiry does not invalidate this REST client; callers that will knock must
// separately require a live peer or run RefreshAgentRegistration.
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
	state, err := loadExistingAgentState(ctx, store, ErrInvalidClientConfig)
	if err != nil {
		return nil, err
	}
	if err := validateRegisteredAgentState(state, time.Now(), false, ErrInvalidClientConfig); err != nil {
		return nil, err
	}
	if strings.TrimSpace(state.DeviceAPIKey) == "" {
		return nil, &CredentialRecoveryRequiredError{DeviceID: state.AgentID, Cause: ErrDeviceCredentialMissing}
	}
	return newStoreBackedClient(store, cfg.baseURL, cfg.httpClient), nil
}

// RefreshAgentRegistration forces a real registration-info + NHP_REG/NHP_RAK
// exchange for an existing completed agent. It never calls registration
// completion and therefore never mints or replaces DeviceAPIKey. Relay, peer,
// and key metadata are committed only after an authenticated successful RAK.
func RefreshAgentRegistration(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*AgentState, error) {
	cfg, err := validateLifecycleInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	return withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		state, err := loadExistingAgentState(ctx, store, cfg.invalidConfigErr)
		if err != nil {
			return nil, err
		}
		if err := validateCompletedAgentIdentity(state, cfg.invalidConfigErr); err != nil {
			return nil, err
		}
		if strings.TrimSpace(state.DeviceAPIKey) == "" {
			return nil, &CredentialRecoveryRequiredError{DeviceID: state.AgentID, Cause: ErrDeviceCredentialMissing}
		}
		if err := cfg.reconcileDeviceID(state); err != nil {
			return nil, err
		}
		return cfg.forceRegistration(ctx, key, store, state, false)
	})
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
func RecoverAgentCredential(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*Client, error) {
	cfg, err := validateLifecycleInputs(ctx, key, store, opts)
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

func validateLifecycleInputs(ctx context.Context, key string, store AgentStateStore, opts []RegisterOption) (*registerConfig, error) {
	cfg, err := newRegisterConfig(opts)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("%w: API key must not be empty", ErrInvalidRegisterConfig)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	return cfg, nil
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
// transition and makes release failure override a nominal success. Custom and
// network stores retain the documented caller-serialization requirement.
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

	candidate := *state
	candidate.NHPPeer = peer
	candidate.RelayURL = relayURL
	candidate.KeyID = info.KeyID
	candidate.SchemaVersion = agentStateSchemaVersion

	credential, path, err := cfg.forcedRegistrationCredential(ctx, key, store, state, &candidate, peer, relayURL, info)
	if err != nil {
		return nil, err
	}
	ack, err := cfg.registerExchange(ctx, &candidate, peer, relayURL, credential)
	if err != nil {
		return nil, err
	}
	if !ack.isSuccess() {
		return nil, mapRAKError(ack, path)
	}
	candidate.OTPRequestedAt = nil

	if !recovery {
		// DeviceAPIKey and RegisteredAt are copied from the prior state and never
		// touched by a binding refresh.
		if err := store.SaveAgentState(ctx, &candidate); err != nil {
			return nil, err
		}
		return &candidate, nil
	}
	return cfg.completeAndPersist(ctx, key, store, &candidate, path)
}

func (cfg *registerConfig) forcedRegistrationCredential(ctx context.Context, key string, store AgentStateStore, persisted, candidate *AgentState, peer *NHPServerPeerInfo, relayURL string, info *registrationInfoResponse) (string, pathKind, error) {
	switch strings.TrimSpace(info.KeyKind) {
	case keyKindBootstrap:
		return key, pathBootstrap, nil
	case keyKindAccount:
		if strings.TrimSpace(info.MaskedEmail) == "" {
			return "", pathAccount, fmt.Errorf("%w: the account key has no email on file for the one-time code; add an email or use a pre-issued key", ErrNoAccountEmail)
		}
		now := cfg.clock()
		dispatchDue := persisted.OTPRequestedAt == nil || now.Sub(*persisted.OTPRequestedAt) >= otpResendCooldown
		// A literal OTP is necessarily from a prior dispatch, so use it directly.
		// A provider may be waiting for the email from this call, so dispatch first.
		if cfg.otp == "" && dispatchDue {
			previous := persisted.OTPRequestedAt
			persisted.OTPRequestedAt = &now
			if err := store.SaveAgentState(ctx, persisted); err != nil {
				persisted.OTPRequestedAt = previous
				return "", pathAccount, err
			}
			if err := cfg.sendOTP(ctx, candidate, peer, relayURL, key); err != nil {
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
		return "", pathBootstrap, fmt.Errorf("%w: registration-info returned unknown key_kind %q", cfg.invalidConfigErr, info.KeyKind)
	}
}
