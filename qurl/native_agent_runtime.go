package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	completionQuery   = "agent_registration_completion"
	completionVersion = 1
	// The assigned-cell account-OTP contract rejects a ticket with less than
	// this much lifetime remaining. Because OTP is one-way, enforce the same
	// inclusive boundary before dispatch so the caller never waits for a code
	// that the cell could not have issued. The v0.5 assignment golden freezes
	// both the 630-second acceptance case and 629-second rejection; the SDK test
	// reads that metadata so this constant cannot drift silently.
	nativeAccountOTPMinimumTicketRemaining = 630 * time.Second
	// qurl-conformance v1 freezes this as the native Connector knock deny. Other
	// values are producer-contract violations, not open-ended diagnostic text.
	nativeKnockResourceNotFoundCode  = "52004"
	nativeRegisterTicketInvalidCode  = "52110"
	nativeRegisterTicketExpiredCode  = "52111"
	nativeRegisterQuotaExceededCode  = "52112"
	completionUnavailableCode        = "52300"
	completionIdentityRejectedCode   = "52301"
	completionQuotaExceededCode      = "52302"
	completionCredentialConflictCode = "52303"
	completionRequestRejectedCode    = "52304"
	// Native completion follows the authority's current production mint
	// contract. This prefix is not inferred from the enrollment credential,
	// hostname, cell, or environment; no such selector exists on this wire.
	deviceKeyPrefix       = "lv_live_"
	deviceKeyRandomLength = 32
	// Persisted enrollment-credential fingerprints are safe only for
	// producer-minted high-entropy tokens. Current qURL credentials carry 32
	// random bytes; this lower bound also remains compatible with deterministic
	// conformance fixtures without coupling the SDK to one public prefix.
	minimumRecoverableEnrollmentCredentialBytes = 32
)

var (
	// ErrAgentOTPRequired marks account enrollment attempted without an explicit OTP callback.
	ErrAgentOTPRequired = errors.New("qurl: account enrollment requires an OTP provider")
	// ErrAssignmentTicketInvalid marks an assigned-cell rejection of the Hub ticket.
	ErrAssignmentTicketInvalid = errors.New("qurl: assignment ticket invalid")
	// ErrAssignmentTicketExpired marks a ticket that cannot authorize assigned-cell REG.
	ErrAssignmentTicketExpired = errors.New("qurl: assignment ticket expired")
	// ErrCompletionUnavailable marks the sole retryable completion application result.
	ErrCompletionUnavailable = errors.New("qurl: registration completion unavailable")
	// ErrCompletionIdentityRejected marks a completion peer or agent identity mismatch.
	ErrCompletionIdentityRejected = errors.New("qurl: registration completion identity rejected")
	// ErrCompletionCredentialConflict marks a different candidate already committed by the authority.
	ErrCompletionCredentialConflict = errors.New("qurl: registration completion credential conflict")
	// ErrCompletionRequestRejected marks a structurally valid but rejected completion request.
	ErrCompletionRequestRejected = errors.New("qurl: registration completion request rejected")
	// ErrCompletionRecoveryRequired marks exhaustion that must resume from persisted pending state.
	ErrCompletionRecoveryRequired = errors.New("qurl: registration completion recovery required")
	// ErrRegistrationRecoveryRequired marks bounded REG transport exhaustion. The
	// exact PendingActivation remains durable and must be resumed with the same
	// caller-supplied enrollment credential before any new Hub assignment.
	ErrRegistrationRecoveryRequired = errors.New("qurl: assigned-cell registration recovery required")
	// ErrAssignmentEndpointContinuity marks unsafe same-generation endpoint revision drift.
	ErrAssignmentEndpointContinuity = errors.New("qurl: assignment endpoint continuity violation")
)

// AgentOTPChallenge is the bounded, non-secret context passed to an optional
// account-enrollment OTP provider. The assignment ticket and account credential
// are intentionally excluded.
type AgentOTPChallenge struct {
	AgentID                   string
	CredentialKeyID           string
	CellID                    string
	AssignmentTicketExpiresAt time.Time
	// PendingActivationRecovery is true only when an earlier REG had an
	// ambiguous/lost RAK and the SDK needs the original code again. No NHP_OTP is
	// dispatched in this mode; the provider must return the code issued for the
	// persisted ticket. The field is bounded non-secret context.
	PendingActivationRecovery bool
}

// agentRuntimeOption is the private base shared by the closed public option
// subsets. External packages can pass constructor results but cannot implement
// or widen any subset.
type agentRuntimeOption interface {
	applyAgentRuntimeOption(*nativeAgentRuntimeConfig) error
}

// AgentRuntimeRegistrationOption is the closed option set for the UDP-only
// RegisterAgentRuntime API. Only closed native lifecycle options implement it.
type AgentRuntimeRegistrationOption interface {
	agentRuntimeOption
	isAgentRuntimeRegistrationOption()
}

// AgentRuntimeRefreshOption is the closed option set for RefreshAgentRuntime.
// Enrollment identity, metadata, Hub, and OTP options do not implement it.
type AgentRuntimeRefreshOption interface {
	agentRuntimeOption
	isAgentRuntimeRefreshOption()
}

// AgentRuntimeLifecycleOption can configure both native registration and
// refresh, but is still broader than one knock exchange.
type AgentRuntimeLifecycleOption interface {
	AgentRuntimeRegistrationOption
	AgentRuntimeRefreshOption
}

// AgentRuntimeUDPOption is the closed subset of runtime options that can alter
// one native UDP exchange. Assignment, enrollment, OTP, and resource-client
// options cannot be passed to KnockRegisteredAgent.
type AgentRuntimeUDPOption interface {
	AgentRuntimeLifecycleOption
	isAgentRuntimeUDPOption()
}

type nativeAgentRuntimeConfig struct {
	hub               *HubBootstrap
	agentID           string
	hostname          string
	version           string
	baseURL           string
	httpClient        HTTPDoer
	resolver          nativeudp.Resolver
	dialer            nativeudp.Dialer
	timeout           time.Duration
	maxAddresses      int
	assignmentOptions []AssignmentOption
	allowedKeyKinds   map[RegistrationKeyKind]struct{}
	otpProvider       func(context.Context, AgentOTPChallenge) (string, error)
	clock             func() time.Time
	random            io.Reader
	deviceCredential  string
}

type nativeRuntimeOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeOptionFunc) isAgentRuntimeRegistrationOption() {}

type nativeRuntimeUDPOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeUDPOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeUDPOptionFunc) isAgentRuntimeRegistrationOption() {}
func (nativeRuntimeUDPOptionFunc) isAgentRuntimeRefreshOption()      {}
func (nativeRuntimeUDPOptionFunc) isAgentRuntimeUDPOption()          {}

type nativeRuntimeLifecycleOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeLifecycleOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeLifecycleOptionFunc) isAgentRuntimeRegistrationOption() {}
func (nativeRuntimeLifecycleOptionFunc) isAgentRuntimeRefreshOption()      {}

// WithAgentRuntimeHub configures the single pinned LayerV Hub trust root used
// for initial assignment. It is mandatory for RegisterAgentRuntime.
func WithAgentRuntimeHub(hub HubBootstrap) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		hubCopy := hub
		c.hub = &hubCopy
		return nil
	})
}

// WithAgentRuntimeIdentity requests a stable agent id. When omitted, the SDK
// generates and persists one before network I/O.
func WithAgentRuntimeIdentity(agentID string) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if err := validateAssignmentAgentID(agentID); err != nil {
			return fmt.Errorf("%w: runtime agent identity: %w", ErrInvalidRegisterConfig, err)
		}
		c.agentID = agentID
		return nil
	})
}

// WithAgentRuntimeMetadata supplies the bounded hostname/version audit fields
// carried in assigned-cell REG.
func WithAgentRuntimeMetadata(hostname, version string) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if err := validateRuntimeMetadata("hostname", hostname); err != nil {
			return err
		}
		if err := validateRuntimeMetadata("version", version); err != nil {
			return err
		}
		c.hostname, c.version = hostname, version
		return nil
	})
}

// WithAgentRuntimeOTPProvider opts into account-credential enrollment. The
// callback runs only after one fire-and-forget assigned-cell NHP_OTP dispatch.
func WithAgentRuntimeOTPProvider(provider func(context.Context, AgentOTPChallenge) (string, error)) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if provider == nil {
			return fmt.Errorf("%w: OTP provider must not be nil", ErrInvalidRegisterConfig)
		}
		c.otpProvider = provider
		return nil
	})
}

// WithAgentRuntimeAllowedRegistrationKeyKinds restricts the authenticated Hub
// assignment key kinds accepted by RegisterAgentRuntime. The native default
// accepts connector_bootstrap, bootstrap, and agent for unattended enrollment
// and rejects account. Account enrollment requires both an explicit account
// opt-in here and WithAgentRuntimeOTPProvider.
func WithAgentRuntimeAllowedRegistrationKeyKinds(kinds ...RegistrationKeyKind) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if len(kinds) == 0 {
			return fmt.Errorf("%w: at least one native registration key kind is required", ErrInvalidRegisterConfig)
		}
		allowed := make(map[RegistrationKeyKind]struct{}, len(kinds))
		for _, kind := range kinds {
			switch kind {
			case RegistrationKeyKindConnectorBootstrap, RegistrationKeyKindBootstrap, RegistrationKeyKindAgent, RegistrationKeyKindAccount:
				allowed[kind] = struct{}{}
			default:
				return fmt.Errorf("%w: unknown native registration key kind %q", ErrInvalidRegisterConfig, kind)
			}
		}
		c.allowedKeyKinds = allowed
		return nil
	})
}

// WithAgentRuntimeUDPResolver injects native endpoint DNS resolution.
func WithAgentRuntimeUDPResolver(resolver nativeudp.Resolver) AgentRuntimeUDPOption {
	return nativeRuntimeUDPOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if resolver == nil {
			return fmt.Errorf("%w: UDP resolver must not be nil", ErrInvalidRegisterConfig)
		}
		c.resolver = resolver
		return nil
	})
}

// WithAgentRuntimeUDPDialer injects native UDP socket dialing.
func WithAgentRuntimeUDPDialer(dialer nativeudp.Dialer) AgentRuntimeUDPOption {
	return nativeRuntimeUDPOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if dialer == nil {
			return fmt.Errorf("%w: UDP dialer must not be nil", ErrInvalidRegisterConfig)
		}
		c.dialer = dialer
		return nil
	})
}

// WithAgentRuntimeUDPBounds bounds one address attempt and DNS address fan-out.
func WithAgentRuntimeUDPBounds(timeout time.Duration, maxAddresses int) AgentRuntimeUDPOption {
	return nativeRuntimeUDPOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if timeout <= 0 || maxAddresses < 1 {
			return fmt.Errorf("%w: UDP timeout and max addresses must be positive", ErrInvalidRegisterConfig)
		}
		c.timeout, c.maxAddresses = timeout, maxAddresses
		return nil
	})
}

// WithAgentRuntimeAssignmentRetryBudget bounds Hub and completion transactions.
func WithAgentRuntimeAssignmentRetryBudget(maxAttempts int, budget time.Duration) AgentRuntimeLifecycleOption {
	return nativeRuntimeLifecycleOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		opt := WithAssignmentRetryBudget(maxAttempts, budget)
		if _, err := newAssignmentConfig([]AssignmentOption{opt}); err != nil {
			return fmt.Errorf("%w: assignment retry budget: %w", ErrInvalidRegisterConfig, err)
		}
		c.assignmentOptions = append(c.assignmentOptions, opt)
		return nil
	})
}

func withAgentRuntimeClock(clock func() time.Time) AgentRuntimeLifecycleOption {
	return nativeRuntimeLifecycleOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if clock == nil {
			return fmt.Errorf("%w: runtime clock must not be nil", ErrInvalidRegisterConfig)
		}
		c.clock = clock
		c.assignmentOptions = append(c.assignmentOptions, withAssignmentClock(clock))
		return nil
	})
}

func withAgentRuntimeDeviceCredential(candidate string) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if err := validateNativeDeviceCredential(candidate, "injected device credential", ErrInvalidRegisterConfig); err != nil {
			return err
		}
		c.deviceCredential = candidate
		return nil
	})
}

func defaultNativeAgentRuntimeConfig() *nativeAgentRuntimeConfig {
	return &nativeAgentRuntimeConfig{
		baseURL:      defaultAPIBaseURL,
		httpClient:   defaultAPIHTTPClient,
		timeout:      nativeudp.DefaultTimeout,
		maxAddresses: nativeudp.DefaultMaxAddresses,
		clock:        time.Now,
		random:       rand.Reader,
	}
}

func newNativeAgentRuntimeConfig(opts []AgentRuntimeRegistrationOption) (*nativeAgentRuntimeConfig, error) {
	c := defaultNativeAgentRuntimeConfig()
	c.allowedKeyKinds = map[RegistrationKeyKind]struct{}{
		RegistrationKeyKindConnectorBootstrap: {},
		RegistrationKeyKindBootstrap:          {},
		RegistrationKeyKindAgent:              {},
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil runtime option", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(c); err != nil {
			return nil, err
		}
	}
	if c.hub == nil {
		return nil, fmt.Errorf("%w: WithAgentRuntimeHub is required", ErrInvalidRegisterConfig)
	}
	if _, err := c.hub.nativeEndpoint(); err != nil {
		return nil, fmt.Errorf("%w: Hub trust root: %w", ErrInvalidRegisterConfig, err)
	}
	return c, nil
}

func validateRuntimeMetadata(label, value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 255 {
		return fmt.Errorf("%w: runtime %s must be 1-255 characters without surrounding whitespace", ErrInvalidRegisterConfig, label)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: runtime %s must not contain control characters", ErrInvalidRegisterConfig, label)
		}
	}
	return nil
}

func (c *nativeAgentRuntimeConfig) udpOptions(privateKey []byte) nativeudp.Options {
	return nativeudp.Options{DeviceStaticPriv: privateKey, Resolver: c.resolver, Dialer: c.dialer, Timeout: c.timeout, MaxAddresses: c.maxAddresses}
}

func registerNativeAgentRuntime(ctx context.Context, enrollmentCredential string, store AgentStateStore, opts []AgentRuntimeRegistrationOption) (*Client, *AgentRuntimeBinding, error) {
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	if store == nil {
		return nil, nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	cfg, err := newNativeAgentRuntimeConfig(opts)
	if err != nil {
		return nil, nil, err
	}

	state, found, err := loadNativeAgentStateIfPresent(ctx, store)
	if err != nil {
		return nil, nil, err
	}
	if found && state.RegisteredAt != nil {
		return finishNativeRuntime(store, state, cfg)
	}
	result, err := withAgentSetupLock(ctx, store, func() (*nativeRuntimeResult, error) {
		return cfg.registerLocked(ctx, enrollmentCredential, store)
	})
	if err != nil {
		return nil, nil, err
	}
	return result.split()
}

type nativeRuntimeResult struct {
	client  *Client
	binding *AgentRuntimeBinding
}

func (r *nativeRuntimeResult) split() (*Client, *AgentRuntimeBinding, error) {
	if r == nil {
		return nil, nil, fmt.Errorf("%w: runtime transition returned nil", ErrInvalidRegisterConfig)
	}
	return r.client, r.binding, nil
}

func finishNativeRuntime(store AgentStateStore, state *AgentState, cfg *nativeAgentRuntimeConfig) (*Client, *AgentRuntimeBinding, error) {
	if err := validateCompletedAgentIdentity(state, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	if err := reconcileNativeAgentIdentity(state, cfg.agentID); err != nil {
		return nil, nil, err
	}
	if err := validatePersistedNativeDeviceCredential(state, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	if err := validateAgentRuntimeMetadata(state, cfg.clock(), ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	// Always decode a fresh binding-owned buffer. Registration and refresh may
	// already hold a separate working copy whose deferred wipe must not erase the
	// private key transferred to the returned binding. By contrast,
	// openRegisteredAgentRuntime transfers its only decoded slice and nils that
	// local owner before the deferred wipe.
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, nil, err
	}
	client := newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey, cfg.clock)
	binding := newAgentRuntimeBinding(state, privateKey)
	return client, binding, nil
}

func finishNativeRuntimeResult(store AgentStateStore, state *AgentState, cfg *nativeAgentRuntimeConfig) (*nativeRuntimeResult, error) {
	client, binding, err := finishNativeRuntime(store, state, cfg)
	return &nativeRuntimeResult{client: client, binding: binding}, err
}

func (c *nativeAgentRuntimeConfig) registerLocked(ctx context.Context, enrollmentCredential string, store AgentStateStore) (*nativeRuntimeResult, error) {
	state, err := loadOrCreateAgentState(ctx, store, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	if state.RegisteredAt != nil {
		return finishNativeRuntimeResult(store, state, c)
	}
	if err := validateIncompleteNativeState(state); err != nil {
		return nil, err
	}
	nativeMarker := isNativeAgentRuntimeState(state)
	if nativeMarker {
		// validateLoadedAgentAssignment has already required the persisted id to be
		// canonical. A caller-supplied identity may only corroborate it.
		if err := reconcileNativeAgentIdentity(state, c.agentID); err != nil {
			return nil, err
		}
	}
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(privateKey)

	if state.PendingCompletion != nil {
		if state.Assignment == nil {
			return nil, fmt.Errorf("%w: pending completion has no assignment", ErrInvalidAgentState)
		}
		if state.Assignment.LeaseExpired(c.clock()) {
			fresh, err := c.refreshAssignmentLifecycle(ctx, *c.hub, state.AgentID, privateKey)
			if err != nil {
				return nil, err
			}
			if err := ensureAssignmentContinuity(state.Assignment, fresh); err != nil {
				return nil, err
			}
			// The previous lease is expired and fresh is validated as live, so the
			// assignment necessarily changed. Persist it before resuming completion.
			state.Assignment = fresh.clone()
			if err := store.SaveAgentState(ctx, state); err != nil {
				return nil, fmt.Errorf("%w: save refreshed pending assignment: %w", ErrAgentBindingPersistence, err)
			}
		}
		if err := c.completePending(ctx, store, state, privateKey); err != nil {
			return nil, err
		}
		return finishNativeRuntimeResult(store, state, c)
	}
	// Enrollment credentials are attempt-scoped Hub inputs. Completed and
	// pending-completion paths above do not need one. A pending activation (a
	// native marker, so the save block below is skipped) requires the same
	// credential to corroborate its durable fingerprint; a transaction with no
	// pending activation needs it to obtain a fresh Hub assignment.
	if err := validateRecoverableEnrollmentCredential(enrollmentCredential); err != nil {
		return nil, err
	}
	if !nativeMarker {
		if err := ensureNativeAgentIdentity(state, c.agentID); err != nil {
			return nil, err
		}
		state.SchemaVersion = agentStateSchemaVersion
		if err := store.SaveAgentState(ctx, state); err != nil {
			return nil, fmt.Errorf("%w: save initial native identity: %w", ErrAgentBindingPersistence, err)
		}
	}

	return c.activateAndComplete(ctx, enrollmentCredential, store, state, privateKey)
}

// activateAndComplete recovers an existing pending REG before asking the Hub
// for anything new. Only an authenticated 52111, or account 52101, proves that
// exact attempt was not committed and permits one replacement assignment. The
// old pending record remains durable until the replacement is itself saved, so
// a crash, Hub error, or consumed-credential denial cannot erase the only
// replay proof.
func (c *nativeAgentRuntimeConfig) activateAndComplete(ctx context.Context, enrollmentCredential string, store AgentStateStore, state *AgentState, privateKey []byte) (*nativeRuntimeResult, error) {
	forceFresh := state.PendingActivation == nil
	// At most one replacement attempt: the first REG either commits, fails
	// terminally, or returns an authenticated verdict permitting exactly one
	// replacement (attempt 0 only). Attempt 1 therefore always returns.
	for attempt := 0; ; attempt++ {
		var credential string
		var err error
		if forceFresh {
			credential, err = c.persistFreshPendingActivation(ctx, enrollmentCredential, store, state, privateKey)
		} else {
			credential, err = c.pendingRegistrationCredential(ctx, state, enrollmentCredential)
		}
		if err != nil {
			return nil, err
		}
		err = c.registerPendingActivation(ctx, state, credential, privateKey)
		if err == nil {
			if err := c.transitionPendingActivation(ctx, store, state); err != nil {
				return nil, err
			}
			if err := c.completePending(ctx, store, state, privateKey); err != nil {
				return nil, err
			}
			return finishNativeRuntimeResult(store, state, c)
		}
		if attempt == 0 && registrationVerdictPermitsReplacement(err) {
			// Fetch a replacement only after an authenticated non-commit verdict,
			// and retain the old record until persistFreshPendingActivation commits
			// the replacement.
			forceFresh = true
			continue
		}
		return nil, err
	}
}

// registrationVerdictPermitsReplacement reports whether an authenticated
// assigned-cell REG verdict proves the resumed one-shot ticket did not commit,
// the sole condition that authorizes fetching one replacement assignment.
// qurl-conformance v0.5 reserves 52111 (ticket expired, marker-absent) and
// account 52101 (OTP expired) for this; every other authenticated denial is
// terminal.
func registrationVerdictPermitsReplacement(err error) bool {
	return errors.Is(err, ErrAssignmentTicketExpired) || errors.Is(err, ErrOTPExpired)
}

func (c *nativeAgentRuntimeConfig) persistFreshPendingActivation(ctx context.Context, enrollmentCredential string, store AgentStateStore, state *AgentState, privateKey []byte) (string, error) {
	initial, err := c.fetchInitialAssignmentLifecycle(ctx, *c.hub, state.AgentID, enrollmentCredential, privateKey)
	if err != nil {
		return "", err
	}
	if err := c.requireAllowedRegistrationKeyKind(initial.Registration.KeyKind); err != nil {
		return "", err
	}
	candidateState := state.clone()
	candidateState.Assignment = initial.Assignment.clone()
	credential, err := c.registrationCredential(ctx, candidateState, initial, enrollmentCredential, privateKey)
	if err != nil {
		return "", err
	}
	pending, err := newPendingAgentActivation(initial, candidateState, c.hostname, c.version, enrollmentCredential)
	if err != nil {
		return "", err
	}
	candidateState.PendingActivation = pending
	candidateState.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(ctx, candidateState); err != nil {
		return "", fmt.Errorf("%w: save pending assigned-cell activation before REG: %w", ErrAgentBindingPersistence, err)
	}
	*state = *candidateState
	return credential, nil
}

func (c *nativeAgentRuntimeConfig) pendingRegistrationCredential(ctx context.Context, state *AgentState, enrollmentCredential string) (string, error) {
	if state == nil || state.PendingActivation == nil {
		return "", fmt.Errorf("%w: pending activation is missing", ErrInvalidAgentState)
	}
	pending := state.PendingActivation
	if err := c.requireAllowedRegistrationKeyKind(pending.Registration.KeyKind); err != nil {
		return "", err
	}
	if c.hostname != pending.Hostname || c.version != pending.AgentVersion {
		return "", fmt.Errorf("%w: runtime metadata does not match pending activation", ErrInvalidRegisterConfig)
	}
	want := enrollmentCredentialFingerprint(enrollmentCredential)
	if subtle.ConstantTimeCompare([]byte(want), []byte(pending.EnrollmentCredentialFingerprintB64)) != 1 {
		return "", fmt.Errorf("%w: enrollment credential does not match pending activation", ErrInvalidRegisterConfig)
	}
	switch pending.Registration.KeyKind {
	case assignmentKeyKindConnectorBootstrap, keyKindBootstrap, assignmentKeyKindAgent:
		return enrollmentCredential, nil
	case keyKindAccount:
		if c.otpProvider == nil {
			return "", fmt.Errorf("%w: pending account activation requires the original code through WithAgentRuntimeOTPProvider", ErrAgentOTPRequired)
		}
		code, err := c.otpProvider(ctx, AgentOTPChallenge{
			AgentID: pending.AgentID, CredentialKeyID: pending.Registration.KeyID,
			CellID: pending.Assignment.CellID, AssignmentTicketExpiresAt: pending.AssignmentTicketExpiresAt,
			PendingActivationRecovery: true,
		})
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("qurl: pending activation OTP provider: %w", err)
		}
		if err := validateNativeOTPCode(code); err != nil {
			return "", err
		}
		return code, nil
	default:
		return "", fmt.Errorf("%w: unsupported pending registration key kind", ErrInvalidAgentState)
	}
}

func (c *nativeAgentRuntimeConfig) transitionPendingActivation(ctx context.Context, store AgentStateStore, state *AgentState) error {
	if state == nil || state.PendingActivation == nil || state.Assignment == nil {
		return fmt.Errorf("%w: authenticated RAK requires pending activation and assignment", ErrInvalidAgentState)
	}
	candidate, err := c.generateDeviceCredential()
	if err != nil {
		return err
	}
	next := state.clone()
	next.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey: candidate, CellID: state.Assignment.CellID,
		AssignmentGeneration: state.Assignment.AssignmentGeneration,
	}
	next.PendingActivation = nil
	next.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(ctx, next); err != nil {
		return &AgentCompletionCandidatePersistenceError{AgentID: state.AgentID, Cause: err}
	}
	*state = *next
	return nil
}

func loadNativeAgentStateIfPresent(ctx context.Context, store AgentStateStore) (*AgentState, bool, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if state == nil {
			return nil, false, fmt.Errorf("%w: agent state store returned nil state", ErrInvalidRegisterConfig)
		}
		if err := validateLoadedAgentAssignment(state); err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrInvalidRegisterConfig, err)
		}
		if err := state.ensureKeypair(ErrInvalidRegisterConfig); err != nil {
			return nil, false, err
		}
		return state, true, nil
	case errors.Is(err, ErrAgentStateNotFound):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("%w: load agent state: %w", ErrInvalidRegisterConfig, err)
	}
}

func reconcileNativeAgentIdentity(state *AgentState, requested string) error {
	if state == nil {
		return fmt.Errorf("%w: agent state is nil", ErrInvalidRegisterConfig)
	}
	if requested != "" && state.AgentID != "" && requested != state.AgentID {
		return fmt.Errorf("%w: saved agent id %q does not match requested agent id %q", ErrInvalidRegisterConfig, state.AgentID, requested)
	}
	return nil
}

func ensureNativeAgentIdentity(state *AgentState, requested string) error {
	if err := reconcileNativeAgentIdentity(state, requested); err != nil {
		return err
	}
	if requested != "" {
		state.AgentID = requested
		return nil
	}
	if state.AgentID != "" {
		return nil
	}
	id, err := generateDeviceID()
	if err != nil {
		return fmt.Errorf("%w: generate agent id: %w", ErrInvalidRegisterConfig, err)
	}
	state.AgentID = id
	return nil
}

func generateDeviceID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("qurl: generate agent id: %w", err)
	}
	return "agent-" + hex.EncodeToString(random[:]), nil
}

// runAssignmentLifecycle owns inter-transaction 52204 handling. One Hub
// transaction deliberately returns an authenticated rate limit immediately;
// this outer gate honors RetryAfter while keeping the whole lifecycle bounded by
// the same configured budget, context, clock, and sleep policy. Attempt caps are
// per level, but the retry classes are deliberately disjoint: authenticated
// 52204 is inner-terminal, while transport/52200 failures are outer-terminal.
// Therefore the caps cannot multiply; the shared elapsed budget is the final
// hard bound. Keep that separation if another retryable class is introduced.
func runAssignmentLifecycle[T any](ctx context.Context, options []AssignmentOption, exchange func(context.Context) (*T, error)) (*T, error) {
	cfg, err := newAssignmentConfig(options)
	if err != nil {
		return nil, err
	}
	start := cfg.clock()
	lifecycleCtx, cancel := context.WithTimeout(ctx, cfg.budget)
	defer cancel()
	for attempt := 1; ; attempt++ {
		result, err := exchange(lifecycleCtx)
		if err == nil {
			return result, nil
		}
		var appErr *AssignmentError
		if !errors.As(err, &appErr) || !errors.Is(appErr, ErrAssignmentRateLimited) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		elapsed := cfg.elapsedSince(start)
		if attempt == cfg.maxAttempts || elapsed >= cfg.budget || appErr.RetryAfter > cfg.budget-elapsed {
			return nil, newAssignmentRecovery(attempt, elapsed, err)
		}
		if sleepErr := cfg.sleep(lifecycleCtx, appErr.RetryAfter); sleepErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if lifecycleCtx.Err() != nil {
				return nil, cfg.recoveryRequired(newAssignmentRecovery, attempt, start, errors.Join(err, lifecycleCtx.Err()))
			}
			return nil, sleepErr
		}
	}
}

// The lifecycle wrappers intentionally keep transaction construction and
// validation in the public Fetch/Refresh operations. AssignmentOption is
// closed to this package and its constructors are pure configuration setters,
// so their repeated parse is deterministic; runAssignmentLifecycle's parse
// owns only the shared inter-transaction budget.
func (c *nativeAgentRuntimeConfig) fetchInitialAssignmentLifecycle(ctx context.Context, hub HubBootstrap, agentID, enrollmentCredential string, privateKey []byte) (*InitialAgentAssignment, error) {
	return runAssignmentLifecycle(ctx, c.assignmentOptions, func(transactionCtx context.Context) (*InitialAgentAssignment, error) {
		return FetchInitialAgentAssignment(transactionCtx, hub, agentID, enrollmentCredential, c.udpOptions(privateKey), c.assignmentOptions...)
	})
}

func (c *nativeAgentRuntimeConfig) refreshAssignmentLifecycle(ctx context.Context, hub HubBootstrap, agentID string, privateKey []byte) (*AgentAssignment, error) {
	return runAssignmentLifecycle(ctx, c.assignmentOptions, func(transactionCtx context.Context) (*AgentAssignment, error) {
		return RefreshAgentAssignment(transactionCtx, hub, agentID, c.udpOptions(privateKey), c.assignmentOptions...)
	})
}

func (c *nativeAgentRuntimeConfig) requireAllowedRegistrationKeyKind(raw string) error {
	kind := RegistrationKeyKind(strings.TrimSpace(raw))
	switch kind {
	case RegistrationKeyKindConnectorBootstrap, RegistrationKeyKindBootstrap, RegistrationKeyKindAgent, RegistrationKeyKindAccount:
	default:
		return fmt.Errorf("%w: unsupported registration key kind", ErrAssignmentInvalidResponse)
	}
	if _, ok := c.allowedKeyKinds[kind]; ok {
		return nil
	}
	allowed := make([]RegistrationKeyKind, 0, len(c.allowedKeyKinds))
	for candidate := range c.allowedKeyKinds {
		allowed = append(allowed, candidate)
	}
	slices.Sort(allowed)
	return &RegistrationKeyKindDisallowedError{Kind: kind, Allowed: allowed}
}

func validateIncompleteNativeState(state *AgentState) error {
	if state == nil {
		return fmt.Errorf("%w: agent state is nil", ErrInvalidAgentState)
	}
	if state.DeviceAPIKey != "" || state.DeviceAPIKeyID != "" {
		return fmt.Errorf("%w: incomplete native runtime state must not contain a completed device credential or credential id", ErrInvalidAgentState)
	}
	return nil
}

func newPendingAgentActivation(initial *InitialAgentAssignment, state *AgentState, hostname, version, enrollmentCredential string) (*PendingAgentActivation, error) {
	if initial == nil || state == nil || state.Assignment == nil {
		return nil, fmt.Errorf("%w: pending activation requires initial assignment and state", ErrInvalidRegisterConfig)
	}
	pending := &PendingAgentActivation{
		AssignmentTicket: initial.AssignmentTicket, AssignmentTicketExpiresAt: initial.AssignmentTicketExpiresAt,
		AgentID: state.AgentID, AgentPublicKeyB64: state.PublicKeyB64,
		Assignment: *initial.Assignment.clone(), Registration: initial.Registration,
		Hostname: hostname, AgentVersion: version,
		EnrollmentCredentialFingerprintB64: enrollmentCredentialFingerprint(enrollmentCredential),
	}
	if err := validatePendingAgentActivation(pending, state); err != nil {
		return nil, fmt.Errorf("%w: construct pending activation: %w", ErrInvalidRegisterConfig, err)
	}
	return pending, nil
}

func validatePendingAgentActivation(pending *PendingAgentActivation, state *AgentState) error {
	invalid := func(reason string) error {
		return fmt.Errorf("%w: pending activation %s", ErrInvalidAgentState, reason)
	}
	if pending == nil || state == nil || state.Assignment == nil {
		return invalid("requires complete state and assignment")
	}
	if err := validateOpaqueAssignmentTicket(pending.AssignmentTicket); err != nil {
		return invalid("ticket is invalid")
	}
	if pending.AssignmentTicketExpiresAt.IsZero() {
		return invalid("ticket expiry is missing")
	}
	if err := validateAssignmentAgentID(pending.AgentID); err != nil || pending.AgentID != state.AgentID {
		return invalid("agent identity does not match state")
	}
	publicKey, err := x25519key.DecodeCanonicalBase64(pending.AgentPublicKeyB64)
	wipeBytes(publicKey)
	if err != nil || pending.AgentPublicKeyB64 != state.PublicKeyB64 {
		return invalid("agent public key does not match state")
	}
	if err := validatePersistedAgentAssignment(&pending.Assignment); err != nil || !sameAgentAssignment(&pending.Assignment, state.Assignment) {
		return invalid("assignment binding does not match state")
	}
	if !pending.Assignment.LeaseExpiresAt.After(pending.AssignmentTicketExpiresAt) {
		return invalid("ticket expiry must precede the assignment lease")
	}
	if !validAPIKeyID(pending.Registration.KeyID) || !validPublicRegistrationKeyKind(pending.Registration.KeyKind) {
		return invalid("registration identity or kind is invalid")
	}
	if validateOptionalRuntimeMetadata("hostname", pending.Hostname) != nil || validateOptionalRuntimeMetadata("version", pending.AgentVersion) != nil {
		return invalid("registration metadata is invalid")
	}
	fingerprint, err := base64.RawURLEncoding.Strict().DecodeString(pending.EnrollmentCredentialFingerprintB64)
	defer wipeBytes(fingerprint)
	if err != nil || len(fingerprint) != sha256.Size {
		return invalid("enrollment credential identity is invalid")
	}
	return nil
}

func validateOptionalRuntimeMetadata(label, value string) error {
	if value == "" {
		// WithAgentRuntimeMetadata is optional and the wire fields are omitempty;
		// when present, reuse its exact canonical validator rather than maintaining
		// a second persisted-state grammar.
		return nil
	}
	return validateRuntimeMetadata(label, value)
}

func validateRecoverableEnrollmentCredential(value string) error {
	if err := validateExactBearerToken(value, "enrollment credential", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	if len(value) < minimumRecoverableEnrollmentCredentialBytes {
		return fmt.Errorf("%w: enrollment credential must be a server-minted high-entropy token of at least %d bytes", ErrInvalidRegisterConfig, minimumRecoverableEnrollmentCredentialBytes)
	}
	return nil
}

func enrollmentCredentialFingerprint(value string) string {
	const domain = "qurl-go/pending-activation-enrollment-credential-v1\x00"
	material := make([]byte, len(domain)+len(value))
	copy(material, domain)
	copy(material[len(domain):], value)
	digest := sha256.Sum256(material)
	wipeBytes(material)
	encoded := base64.RawURLEncoding.EncodeToString(digest[:])
	wipeBytes(digest[:])
	return encoded
}

func (c *nativeAgentRuntimeConfig) registrationCredential(ctx context.Context, state *AgentState, initial *InitialAgentAssignment, enrollmentCredential string, privateKey []byte) (string, error) {
	switch initial.Registration.KeyKind {
	case assignmentKeyKindConnectorBootstrap, keyKindBootstrap, assignmentKeyKindAgent:
		return enrollmentCredential, nil
	case keyKindAccount:
		if c.otpProvider == nil {
			return "", fmt.Errorf("%w: install WithAgentRuntimeOTPProvider before account enrollment", ErrAgentOTPRequired)
		}
		now := c.clock()
		if initial.AssignmentTicketExpiresAt.Sub(now) < nativeAccountOTPMinimumTicketRemaining {
			return "", fmt.Errorf("%w: assignment ticket has less than the minimum account OTP lifetime remaining", ErrAssignmentTicketExpired)
		}
		deadline := initial.AssignmentTicketExpiresAt.Add(-time.Second)
		if !deadline.After(now) {
			return "", fmt.Errorf("%w: assignment ticket has no safe OTP callback window", ErrAssignmentTicketExpired)
		}
		// Start the one bounded window before any packet construction or dispatch,
		// so time spent sending the one-way OTP is deducted from the callback's
		// budget without sampling the injected clock a second time.
		providerCtx, cancel := context.WithTimeout(ctx, deadline.Sub(now))
		defer cancel()
		body, err := marshalNativeOTPBody(initial.Registration.KeyID, state.AgentID, enrollmentCredential, initial.AssignmentTicket)
		if err != nil {
			return "", err
		}
		defer wipeBytes(body)
		endpoint, err := assignmentNativeEndpoint(state.Assignment)
		if err != nil {
			return "", err
		}
		if err := nativeudp.SendOTP(providerCtx, endpoint, body, c.udpOptions(privateKey)); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if providerCtx.Err() != nil {
				return "", fmt.Errorf("%w: OTP dispatch exceeded the assignment ticket's safe registration window: %w", ErrAssignmentTicketExpired, providerCtx.Err())
			}
			return "", err
		}
		code, err := c.otpProvider(providerCtx, AgentOTPChallenge{
			AgentID: state.AgentID, CredentialKeyID: initial.Registration.KeyID,
			CellID: state.Assignment.CellID, AssignmentTicketExpiresAt: initial.AssignmentTicketExpiresAt,
		})
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if providerCtx.Err() != nil {
				return "", fmt.Errorf("%w: OTP provider did not supply a code before the assignment ticket's safe registration window closed: %w", ErrAssignmentTicketExpired, err)
			}
			return "", fmt.Errorf("qurl: OTP provider: %w", err)
		}
		if err := validateNativeOTPCode(code); err != nil {
			return "", err
		}
		return code, nil
	default:
		return "", fmt.Errorf("%w: unsupported registration key kind", ErrAssignmentInvalidResponse)
	}
}

type nativeOTPBody struct {
	UsrID      string            `json:"usrId"`
	DevID      string            `json:"devId"`
	AspID      string            `json:"aspId"`
	Credential string            `json:"pass"`
	UsrData    nativeOTPUserData `json:"usrData"`
}

type nativeOTPUserData struct {
	Query            string `json:"query"`
	Version          int    `json:"version"`
	AssignmentTicket string `json:"assignment_ticket"`
}

func marshalNativeOTPBody(keyID, agentID, credential, ticket string) ([]byte, error) {
	// The protocol intentionally names this AEAD-protected credential field
	// "pass"; it is wiped with the encoded body immediately after dispatch.
	//nolint:gosec // G117 flags the required wire key even though this is not a logged response type.
	body, err := json.Marshal(nativeOTPBody{
		UsrID: keyID, DevID: agentID, AspID: agentAspID, Credential: credential,
		UsrData: nativeOTPUserData{Query: "agent_registration_otp", Version: 1, AssignmentTicket: ticket},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode OTP request: %w", ErrInvalidRegisterConfig, err)
	}
	if len(body) > nhpcontract.MaxApplicationBodySize {
		wipeBytes(body)
		return nil, fmt.Errorf("%w: encoded OTP request exceeds NHP application limit", ErrInvalidRegisterConfig)
	}
	return body, nil
}

func validateNativeOTPCode(code string) error {
	if len(code) != 8 {
		return fmt.Errorf("%w: OTP provider must return exactly 8 decimal digits", ErrInvalidRegisterConfig)
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return fmt.Errorf("%w: OTP provider must return exactly 8 decimal digits", ErrInvalidRegisterConfig)
		}
	}
	return nil
}

// RegistrationRecoveryRequiredError reports bounded ambiguous REG transport
// exhaustion. PendingActivation remains the sole recovery authority; retrying
// with the same enrollment credential re-drives its exact body and pinned cell
// before the Hub can be consulted.
type RegistrationRecoveryRequiredError struct {
	Attempts int
	Elapsed  time.Duration
	Last     error
}

func (e *RegistrationRecoveryRequiredError) Error() string {
	if e == nil {
		return ErrRegistrationRecoveryRequired.Error()
	}
	return fmt.Sprintf("qurl: assigned-cell registration retry budget exhausted after %d attempts over %s; resume the exact pending activation with the same enrollment credential: %v", e.Attempts, e.Elapsed, e.Last)
}

func (e *RegistrationRecoveryRequiredError) Unwrap() []error {
	if e == nil || e.Last == nil {
		return []error{ErrRegistrationRecoveryRequired}
	}
	return []error{ErrRegistrationRecoveryRequired, e.Last}
}

func newRegistrationRecovery(attempts int, elapsed time.Duration, last error) error {
	return &RegistrationRecoveryRequiredError{Attempts: attempts, Elapsed: elapsed, Last: last}
}

func registrationRetryInfo(err error) (time.Duration, bool) {
	return 0, nativeTransportRetryable(err)
}

func (c *nativeAgentRuntimeConfig) registerPendingActivation(ctx context.Context, state *AgentState, credential string, privateKey []byte) error {
	if state == nil || state.PendingActivation == nil {
		return fmt.Errorf("%w: assigned-cell REG requires pending activation", ErrInvalidAgentState)
	}
	pending := state.PendingActivation
	// Do not reject locally when the persisted ticket has expired. The pinned
	// cell must distinguish an exact committed replay from marker-absent 52111;
	// only that authenticated verdict can authorize one replacement assignment.
	body, err := marshalRegisterRequestBody(pending.Registration.KeyID, pending.AgentID, credential, registerUserData{
		Hostname: pending.Hostname, Version: pending.AgentVersion, AssignmentTicket: pending.AssignmentTicket,
	})
	if err != nil {
		return err
	}
	defer wipeBytes(body)
	endpoint, err := assignmentNativeEndpoint(&pending.Assignment)
	if err != nil {
		return err
	}
	retry, err := newAssignmentConfig(c.assignmentOptions)
	if err != nil {
		return err
	}
	_, err = runNativeExchange(ctx, retry, endpoint, body, c.udpOptions(privateKey), nativeudp.Register, registrationRetryInfo, newRegistrationRecovery, func(reply []byte, _ time.Time) (*struct{}, error) {
		ack, parseErr := parseNativeRegisterAck(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		if ack.isSuccess() {
			return &struct{}{}, nil
		}
		return nil, classifyNativeRegisterError(ack, pending.Registration.KeyKind)
	})
	return err
}

func classifyNativeRegisterError(ack *registerAckBody, keyKind string) error {
	if ack == nil {
		return fmt.Errorf("%w: assigned-cell registration error is nil", ErrRegisterReplyMalformed)
	}
	var kind error
	switch ack.ErrCode {
	case rakCredentialInvalid:
		if keyKind == keyKindAccount {
			kind = ErrOTPIncorrect
		} else {
			kind = ErrKeyRejected
		}
	case rakCredentialExpired:
		if keyKind == keyKindAccount {
			kind = ErrOTPExpired
		} else {
			// 52101 is defined only for account OTP. An unattended producer that
			// emits it is out of contract and must not gain replacement authority.
			kind = ErrKeyRejected
		}
	case rakAttemptsExceeded, rakRateLimited:
		kind = ErrRegistrationRateLimited
	case rakIdentityConflict:
		kind = ErrAgentIdentityConflict
	case rakEmailUnavailable:
		kind = ErrNoAccountEmail
	case rakInvalidAPIKey:
		kind = ErrKeyRejected
	case rakRegistrationOff:
		kind = ErrRegistrationDisabled
	case rakBootstrapConsumed:
		kind = ErrBootstrapSetupKeyConsumed
	case rakInvalidInput:
		kind = ErrRegistrationInvalidInput
	case nativeRegisterTicketInvalidCode:
		kind = ErrAssignmentTicketInvalid
	case nativeRegisterTicketExpiredCode:
		kind = ErrAssignmentTicketExpired
	case nativeRegisterQuotaExceededCode:
		kind = ErrAssignmentQuotaExceeded
	default:
		return fmt.Errorf("%w: unknown assigned-cell registration errCode", ErrRegisterReplyMalformed)
	}
	switch ack.ErrCode {
	case rakCredentialExpired:
		if keyKind == keyKindAccount {
			return fmt.Errorf("qurl: native account OTP expired after the bounded fresh-assignment recovery attempt (errCode=%q); start a new explicit RegisterAgentRuntime call only when another OTP attempt is intended: %w", ack.ErrCode, kind)
		}
		return fmt.Errorf("qurl: assigned-cell registration denied (errCode=%q): %w", ack.ErrCode, kind)
	case rakIdentityConflict:
		return fmt.Errorf("qurl: native assigned-cell identity conflict (errCode=%q); stop and use explicit NHP-native reprovisioning because takeover is not supported by this runtime: %w", ack.ErrCode, kind)
	case rakInvalidInput:
		return fmt.Errorf("qurl: native assigned-cell registration input rejected (errCode=%q); correct WithAgentRuntimeIdentity, WithAgentRuntimeMetadata, or the producer contract before retrying: %w", ack.ErrCode, kind)
	default:
		return fmt.Errorf("qurl: assigned-cell registration denied (errCode=%q): %w", ack.ErrCode, kind)
	}
}

func (c *nativeAgentRuntimeConfig) generateDeviceCredential() (string, error) {
	if c.deviceCredential != "" {
		return c.deviceCredential, nil
	}
	random := make([]byte, deviceKeyRandomLength)
	defer wipeBytes(random)
	if _, err := io.ReadFull(c.random, random); err != nil {
		return "", fmt.Errorf("qurl: generate device credential: %w", err)
	}
	candidate := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(random)
	if err := validateNativeDeviceCredential(candidate, "generated device credential", ErrInvalidRegisterConfig); err != nil {
		return "", err
	}
	return candidate, nil
}

func validateNativeDeviceCredential(value, label string, errKind error) error {
	malformed := fmt.Errorf("%w: %s must match %s plus canonical unpadded base64url of %d bytes", errKind, label, deviceKeyPrefix, deviceKeyRandomLength)
	encodedLength := base64.RawURLEncoding.EncodedLen(deviceKeyRandomLength)
	if len(value) != len(deviceKeyPrefix)+encodedLength || !strings.HasPrefix(value, deviceKeyPrefix) {
		return malformed
	}
	encoded := value[len(deviceKeyPrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	defer wipeBytes(decoded)
	if err != nil {
		return malformed
	}
	if len(decoded) != deviceKeyRandomLength || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return malformed
	}
	return nil
}

type completionRequest struct {
	UsrID   string             `json:"usrId"`
	DevID   string             `json:"devId"`
	AspID   string             `json:"aspId"`
	UsrData completionUserData `json:"usrData"`
}

type completionUserData struct {
	Query        string `json:"query"`
	Version      int    `json:"version"`
	DeviceAPIKey string `json:"device_api_key"`
}

type completionList struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

// CompletionError is an authenticated closed-taxonomy completion denial.
type CompletionError struct {
	Code       string
	RetryAfter time.Duration
	kind       error
}

func (e *CompletionError) Error() string {
	if e == nil {
		return "qurl: completion error"
	}
	if errors.Is(e.kind, ErrCompletionCredentialConflict) {
		return fmt.Sprintf("qurl: completion error %s; the authority already committed a different credential: stop and use explicit NHP-native credential recovery or reprovisioning; do not delete the persisted candidate or mint a replacement locally", e.Code)
	}
	return fmt.Sprintf("qurl: completion error %s", e.Code)
}

func (e *CompletionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// CompletionRecoveryRequiredError reports bounded retry exhaustion while the
// exact candidate remains durable for an explicit resume.
type CompletionRecoveryRequiredError struct {
	Attempts int
	Elapsed  time.Duration
	Last     error
}

func (e *CompletionRecoveryRequiredError) Error() string {
	if e == nil {
		return ErrCompletionRecoveryRequired.Error()
	}
	return fmt.Sprintf("qurl: completion retry budget exhausted after %d attempts over %s; reopen the persisted pending candidate: %v", e.Attempts, e.Elapsed, e.Last)
}

func (e *CompletionRecoveryRequiredError) Unwrap() []error {
	if e == nil || e.Last == nil {
		return []error{ErrCompletionRecoveryRequired}
	}
	return []error{ErrCompletionRecoveryRequired, e.Last}
}

func (c *nativeAgentRuntimeConfig) completePending(ctx context.Context, store AgentStateStore, state *AgentState, privateKey []byte) error {
	if state.PendingCompletion == nil || state.Assignment == nil {
		return fmt.Errorf("%w: completion requires pending candidate and assignment", ErrInvalidAgentState)
	}
	body, err := json.Marshal(completionRequest{
		UsrID: "", DevID: state.AgentID, AspID: agentAspID,
		UsrData: completionUserData{Query: completionQuery, Version: completionVersion, DeviceAPIKey: state.PendingCompletion.DeviceAPIKey},
	})
	if err != nil {
		return fmt.Errorf("%w: encode completion request: %w", ErrInvalidRegisterConfig, err)
	}
	defer wipeBytes(body)
	endpoint, err := assignmentNativeEndpoint(state.Assignment)
	if err != nil {
		return err
	}
	keyID, err := c.runCompletionExchange(ctx, endpoint, body, c.udpOptions(privateKey))
	if err != nil {
		return err
	}
	previous := state.clone()
	state.DeviceAPIKey = state.PendingCompletion.DeviceAPIKey
	state.DeviceAPIKeyID = keyID
	state.PendingCompletion = nil
	registeredAt := c.clock().UTC()
	state.RegisteredAt = &registeredAt
	state.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(ctx, state); err != nil {
		*state = *previous
		return fmt.Errorf("%w: persist completed native credential: %w", ErrAgentBindingPersistence, err)
	}
	return nil
}

func (c *nativeAgentRuntimeConfig) runCompletionExchange(ctx context.Context, endpoint nativeudp.Endpoint, body []byte, transport nativeudp.Options) (string, error) {
	retry, err := newAssignmentConfig(c.assignmentOptions)
	if err != nil {
		return "", err
	}
	// Pending-credential completion shares the bounded assignment retry driver;
	// only its retry classifier, recovery type, and reply parser differ.
	keyID, err := runNativeExchange(ctx, retry, endpoint, body, transport, nativeudp.List, completionRetryInfo, newCompletionRecovery, func(reply []byte, _ time.Time) (*string, error) {
		id, parseErr := parseCompletionReply(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		return &id, nil
	})
	if err != nil {
		return "", err
	}
	return *keyID, nil
}

func newCompletionRecovery(attempts int, elapsed time.Duration, last error) error {
	return &CompletionRecoveryRequiredError{Attempts: attempts, Elapsed: elapsed, Last: last}
}

func completionRetryInfo(err error) (time.Duration, bool) {
	if nativeTransportRetryable(err) {
		return 0, true
	}
	var appErr *CompletionError
	if errors.As(err, &appErr) && errors.Is(appErr, ErrCompletionUnavailable) {
		return appErr.RetryAfter, true
	}
	return 0, false
}

func invalidNativeProducerReply(kind error, phase string) error {
	// Authenticated producers have seen credentials used in this lifecycle and a
	// buggy implementation can reflect them in values, JSON field names, or raw
	// parser diagnostics. Only code-owned phase text crosses the public boundary.
	return fmt.Errorf("%w: invalid %s", kind, phase)
}

func parseCompletionReply(body []byte) (string, error) {
	fields, err := exactObjectFields(body)
	if err != nil {
		return "", invalidNativeProducerReply(ErrRegisterReplyMalformed, "completion LRT envelope")
	}
	if _, ok := fields["errCode"]; !ok {
		return "", fmt.Errorf("%w: completion LRT missing errCode", ErrRegisterReplyMalformed)
	}
	var envelope assignmentEnvelope
	if err := strictDecodeJSON(body, &envelope); err != nil {
		return "", invalidNativeProducerReply(ErrRegisterReplyMalformed, "completion LRT envelope")
	}
	if envelope.ErrCode == "0" {
		if _, ok := fields["list"]; len(fields) != 2 || !ok || isJSONNull(envelope.List) {
			return "", fmt.Errorf("%w: completion success must contain exactly errCode and object list", ErrRegisterReplyMalformed)
		}
		var list completionList
		if err := decodeExactObject(envelope.List, &list, []string{"query", "version", "device_api_key_id"}); err != nil {
			return "", invalidNativeProducerReply(ErrRegisterReplyMalformed, "completion list")
		}
		if list.Query != completionQuery || list.Version != completionVersion {
			return "", fmt.Errorf("%w: completion query/version mismatch", ErrRegisterReplyMalformed)
		}
		if err := validateAPIKeyID(list.DeviceAPIKeyID, "completion device_api_key_id", ErrRegisterReplyMalformed); err != nil {
			return "", err
		}
		return list.DeviceAPIKeyID, nil
	}
	if _, ok := fields["list"]; ok {
		return "", fmt.Errorf("%w: completion error must not contain list", ErrRegisterReplyMalformed)
	}
	return "", classifyCompletionError(envelope, fields)
}

func classifyCompletionError(envelope assignmentEnvelope, fields map[string]json.RawMessage) error {
	if raw, ok := fields["errMsg"]; ok && isJSONNull(raw) {
		return fmt.Errorf("%w: completion errMsg must be a string", ErrRegisterReplyMalformed)
	}
	var kind error
	retryPermitted := false
	switch envelope.ErrCode {
	case completionUnavailableCode:
		kind, retryPermitted = ErrCompletionUnavailable, true
	case completionIdentityRejectedCode:
		kind = ErrCompletionIdentityRejected
	case completionQuotaExceededCode:
		kind = ErrDeviceKeyQuotaExceeded
	case completionCredentialConflictCode:
		kind = ErrCompletionCredentialConflict
	case completionRequestRejectedCode:
		kind = ErrCompletionRequestRejected
	default:
		return fmt.Errorf("%w: unknown completion errCode", ErrRegisterReplyMalformed)
	}
	retryAfter, err := parseEnvelopeRetryAfter(envelope, fields, retryPermitted, false)
	if err != nil {
		return fmt.Errorf("%w: completion %s", ErrRegisterReplyMalformed, err.Error())
	}
	return &CompletionError{Code: envelope.ErrCode, RetryAfter: retryAfter, kind: kind}
}

func assignmentNativeEndpoint(assignment *AgentAssignment) (nativeudp.Endpoint, error) {
	if assignment == nil {
		return nativeudp.Endpoint{}, fmt.Errorf("%w: assignment is nil", ErrAssignmentInvalidResponse)
	}
	key, err := assignment.DecodedServerKey()
	if err != nil {
		return nativeudp.Endpoint{}, err
	}
	return nativeudp.Endpoint{Host: assignment.Endpoint.Host, Port: assignment.Endpoint.Port, ServerStaticPub: key}, nil
}

// AgentAssignmentChangedError reports an authority-directed cell/generation
// move. The SDK never selects or silently adopts a different cell.
type AgentAssignmentChangedError struct {
	Previous *AgentAssignment
	Current  *AgentAssignment
}

func (e *AgentAssignmentChangedError) Error() string {
	return "qurl: authoritative assignment changed cell or generation; explicit reassignment handling is required"
}

func (e *AgentAssignmentChangedError) Unwrap() error { return ErrAssignmentReassignmentRequired }

func ensureAssignmentContinuity(previous, current *AgentAssignment) error {
	if previous == nil || current == nil {
		return fmt.Errorf("%w: assignment is missing", ErrAssignmentEndpointContinuity)
	}
	if previous.CellID != current.CellID || previous.AssignmentGeneration != current.AssignmentGeneration {
		return &AgentAssignmentChangedError{Previous: previous.clone(), Current: current.clone()}
	}
	if current.EndpointRevision < previous.EndpointRevision {
		return fmt.Errorf("%w: endpoint revision regressed from %d to %d", ErrAssignmentEndpointContinuity, previous.EndpointRevision, current.EndpointRevision)
	}
	if current.EndpointRevision == previous.EndpointRevision && current.Endpoint != previous.Endpoint {
		return fmt.Errorf("%w: endpoint changed without a revision advance", ErrAssignmentEndpointContinuity)
	}
	return nil
}

// NativeKnockResult is the authenticated, resource-specific admission returned
// by KnockRegisteredAgent. ACToken is a bearer credential and is redacted from
// String and GoString; callers remain responsible for explicit field access or
// serialization.
type NativeKnockResult struct {
	ACToken      string
	ResourceHost string
	OpenTime     uint32
	AgentAddr    string
}

func (r NativeKnockResult) String() string {
	return fmt.Sprintf("qurl.NativeKnockResult{ACToken:[REDACTED], ResourceHost:%q, OpenTime:%d, AgentAddr:%q}", r.ResourceHost, r.OpenTime, r.AgentAddr)
}

// GoString provides the same token redaction for %#v formatting.
func (r NativeKnockResult) GoString() string { return r.String() }

// KnockRegisteredAgent sends one caller-correlated NHP_KNK directly to the
// binding's assigned cell and returns only the requested resource's admission.
// It validates the live authority-provided assignment before DNS or socket I/O
// and authenticates the reply against that assignment's server public key.
func KnockRegisteredAgent(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte, knockResourceID string, opts NativeKnockOptions, transportOpts ...AgentRuntimeUDPOption) (*NativeKnockResult, error) {
	if binding == nil {
		return nil, fmt.Errorf("%w: runtime binding must not be nil", ErrInvalidNativeKnockInput)
	}
	if len(deviceStaticPrivateKey) != x25519key.Size {
		return nil, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidNativeKnockInput, x25519key.Size)
	}
	if err := validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey); err != nil {
		return nil, err
	}
	cfg := defaultNativeAgentRuntimeConfig()
	for _, opt := range transportOpts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil native UDP transport option", ErrInvalidNativeKnockInput)
		}
		if err := opt.applyAgentRuntimeOption(cfg); err != nil {
			return nil, fmt.Errorf("%w: native UDP transport option: %w", ErrInvalidNativeKnockInput, err)
		}
	}
	assignment := binding.assignment()
	if assignment == nil || assignment.CellID != binding.CellID || assignment.AssignmentGeneration != binding.AssignmentGeneration || assignment.EndpointRevision != binding.EndpointRevision || assignment.Endpoint != binding.NHPUDPEndpoint {
		return nil, fmt.Errorf("%w: runtime binding does not match its authoritative assignment", ErrInvalidNativeKnockInput)
	}
	if err := assignment.Validate(cfg.clock()); err != nil {
		return nil, fmt.Errorf("%w: runtime assignment: %w", ErrInvalidNativeKnockInput, err)
	}
	body, err := marshalNativeKnockApplicationBody(binding.AgentID, knockResourceID, opts)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	endpoint, err := assignmentNativeEndpoint(assignment)
	if err != nil {
		return nil, err
	}
	reply, err := nativeudp.Knock(ctx, endpoint, body, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	return consumeNativeAgentKnockReply(reply, knockResourceID)
}

func validateRuntimeBindingIdentity(binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte) error {
	if binding.authoritativeAgentID == "" || binding.AgentID != binding.authoritativeAgentID ||
		binding.authoritativePublicKeyB64 == "" || binding.PublicKeyB64 != binding.authoritativePublicKeyB64 {
		return fmt.Errorf("%w: runtime binding identity does not match its authoritative snapshot", ErrInvalidNativeKnockInput)
	}
	authoritativePublic, err := base64.StdEncoding.Strict().DecodeString(binding.authoritativePublicKeyB64)
	defer wipeBytes(authoritativePublic)
	if err != nil || len(authoritativePublic) != x25519key.Size || base64.StdEncoding.EncodeToString(authoritativePublic) != binding.authoritativePublicKeyB64 {
		return fmt.Errorf("%w: runtime binding has a malformed authoritative public key", ErrInvalidNativeKnockInput)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(deviceStaticPrivateKey)
	if err != nil {
		return fmt.Errorf("%w: device static private key is not X25519", ErrInvalidNativeKnockInput)
	}
	derivedPublic := privateKey.PublicKey().Bytes()
	defer wipeBytes(derivedPublic)
	if subtle.ConstantTimeCompare(derivedPublic, authoritativePublic) != 1 {
		return fmt.Errorf("%w: device static private key does not match the runtime binding", ErrInvalidNativeKnockInput)
	}
	return nil
}

type nativeAgentKnockACK struct {
	ErrCode          nativeJSONValue[string] `json:"errCode"`
	ErrMsg           nativeJSONValue[string] `json:"errMsg"`
	ResourceHost     nativeJSONStringMap     `json:"resHost"`
	OpenTime         nativeJSONValue[uint32] `json:"opnTime"`
	ASPToken         nativeJSONValue[string] `json:"aspToken"`
	AgentAddr        nativeJSONValue[string] `json:"agentAddr"`
	ACTokens         nativeJSONStringMap     `json:"acTokens"`
	PreAccessActions nativePreAccessActions  `json:"preActions"`
	RedirectURL      nativeJSONValue[string] `json:"redirectUrl"`
}

type nativeJSONValue[T any] struct {
	Value   T
	Present bool
}

func (v *nativeJSONValue[T]) UnmarshalJSON(data []byte) error {
	v.Present = true
	if isJSONNull(data) {
		return errors.New("must not be JSON null")
	}
	return json.Unmarshal(data, &v.Value)
}

type nativeJSONStringMap struct {
	Value   map[string]string
	Present bool
}

func (v *nativeJSONStringMap) UnmarshalJSON(data []byte) error {
	v.Present = true
	if isJSONNull(data) {
		// Keep null distinguishable from an omitted field, but normalize it to an
		// empty map. The downstream exact-key lookup then rejects it as malformed;
		// null is never accepted as resource authorization data.
		v.Value = nil
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	v.Value = make(map[string]string, len(raw))
	for key, valueJSON := range raw {
		var value nativeJSONValue[string]
		if err := json.Unmarshal(valueJSON, &value); err != nil {
			return fmt.Errorf("map entry %q: %w", key, err)
		}
		v.Value[key] = value.Value
	}
	return nil
}

type nativePreAccessActions struct {
	RequiresAction bool
}

func (v *nativePreAccessActions) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		return errors.New("must be a JSON object, not null")
	}
	var actions map[string]json.RawMessage
	if err := json.Unmarshal(data, &actions); err != nil {
		return err
	}
	if actions == nil {
		return errors.New("must be a JSON object")
	}
	for _, actionJSON := range actions {
		if !isJSONNull(actionJSON) {
			v.RequiresAction = true
		}
	}
	return nil
}

func interpretNativeAgentKnockReply(reply *relayknock.Reply, knockResourceID string) (*NativeKnockResult, error) {
	if reply == nil {
		return nil, fmt.Errorf("%w: native knock reply is nil", ErrMalformedReply)
	}
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, fmt.Errorf("%w: unexpected native knock reply type %d", ErrMalformedReply, reply.Type)
	}
	if err := rejectDuplicateJSONFields(reply.Body); err != nil {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock ACK")
	}
	var ack *nativeAgentKnockACK
	if err := strictDecodeJSON(reply.Body, &ack); err != nil {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock ACK")
	}
	if ack == nil {
		return nil, fmt.Errorf("%w: native knock ACK must be an object", ErrMalformedReply)
	}
	if !ack.ErrCode.Present {
		return nil, fmt.Errorf("%w: native knock ACK field errCode is missing", ErrMalformedReply)
	}
	if ack.ErrCode.Value != strings.TrimSpace(ack.ErrCode.Value) {
		return nil, fmt.Errorf("%w: native knock ACK errCode is not canonical", ErrMalformedReply)
	}
	if ack.ErrCode.Value == nativeKnockResourceNotFoundCode {
		return nil, &ServerDenyError{ErrCode: ack.ErrCode.Value}
	}
	if ack.ErrCode.Value != errSuccess {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock ACK errCode")
	}
	for _, required := range []struct {
		name    string
		present bool
	}{
		{"resHost", ack.ResourceHost.Present},
		{"opnTime", ack.OpenTime.Present},
		{"agentAddr", ack.AgentAddr.Present},
		{"acTokens", ack.ACTokens.Present},
	} {
		if !required.present {
			return nil, fmt.Errorf("%w: native knock ACK field %s is missing", ErrMalformedReply, required.name)
		}
	}
	if ack.PreAccessActions.RequiresAction {
		return nil, fmt.Errorf("%w: native knock ACK requires an unsupported pre-access action", ErrMalformedReply)
	}
	token := ack.ACTokens.Value[knockResourceID]
	host := ack.ResourceHost.Value[knockResourceID]
	if token == "" || host == "" || token != strings.TrimSpace(token) || host != strings.TrimSpace(host) {
		return nil, fmt.Errorf("%w: success ACK missing canonical token or resource host for requested resource", ErrMalformedReply)
	}
	return &NativeKnockResult{ACToken: token, ResourceHost: host, OpenTime: ack.OpenTime.Value, AgentAddr: ack.AgentAddr.Value}, nil
}

func consumeNativeAgentKnockReply(reply *relayknock.Reply, knockResourceID string) (*NativeKnockResult, error) {
	if reply != nil {
		defer wipeBytes(reply.Body)
	}
	return interpretNativeAgentKnockReply(reply, knockResourceID)
}

// RefreshAgentRuntime refreshes a completed binding only through the pinned Hub
// using the registered Noise identity and final agent id. It sends no enrollment
// or device credential and performs no public HTTP request.
func RefreshAgentRuntime(ctx context.Context, hub HubBootstrap, store AgentStateStore, opts ...AgentRuntimeRefreshOption) (*Client, *AgentRuntimeBinding, error) {
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	if store == nil {
		return nil, nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.hub = &hub
	for _, opt := range opts {
		if opt == nil {
			return nil, nil, fmt.Errorf("%w: nil runtime option", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(cfg); err != nil {
			return nil, nil, err
		}
	}
	if _, err := hub.nativeEndpoint(); err != nil {
		return nil, nil, fmt.Errorf("%w: Hub trust root: %w", ErrInvalidRegisterConfig, err)
	}
	result, err := withAgentSetupLock(ctx, store, func() (*nativeRuntimeResult, error) {
		state, err := loadCompletedRegisteredState(ctx, store, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}
		if state.Assignment == nil {
			return nil, fmt.Errorf("%w: completed state has no assignment", ErrInvalidRegisterConfig)
		}
		privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}
		defer wipeBytes(privateKey)
		fresh, err := cfg.refreshAssignmentLifecycle(ctx, hub, state.AgentID, privateKey)
		if err != nil {
			return nil, err
		}
		if err := ensureAssignmentContinuity(state.Assignment, fresh); err != nil {
			return nil, err
		}
		if !sameAgentAssignment(state.Assignment, fresh) {
			state.Assignment = fresh.clone()
			if err := store.SaveAgentState(ctx, state); err != nil {
				return nil, fmt.Errorf("%w: save refreshed assignment: %w", ErrAgentBindingPersistence, err)
			}
		}
		return finishNativeRuntimeResult(store, state, cfg)
	})
	if err != nil {
		return nil, nil, err
	}
	return result.split()
}
