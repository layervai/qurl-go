package qurl

import (
	"bytes"
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

	"github.com/layervai/qurl-go/internal/agentstatecontract"
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
	// sessionLeaseRenewalLead is how far ahead of lease expiry a held binding
	// renews. It must comfortably exceed one bounded Hub operation (30s default)
	// so a renewal that starts in the window still finishes against a live lease,
	// and must stay far below a lease lifetime so renewal happens about once per
	// lease rather than on every knock. Renewing inside this window is best
	// effort: the current lease is still valid, so a Hub failure is not fatal.
	sessionLeaseRenewalLead          = 5 * time.Minute
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
	// Persisted enrollment-credential fingerprints are safe only for tokens
	// minted with cryptographic randomness. The SDK can enforce only this total
	// encoded-token byte-length floor, including any prefix; it is not an entropy
	// measurement. The floor remains compatible with deterministic conformance
	// fixtures without coupling the SDK to one public prefix.
	minimumRecoverableEnrollmentCredentialEncodedLength = 32
)

var (
	// ErrAgentOTPRequired marks OTP enrollment — the default — attempted without
	// an OTP callback. Runtimes that cannot receive a code opt out with
	// WithAgentRuntimeHeadlessEnrollment instead of installing a provider.
	ErrAgentOTPRequired = errors.New("qurl: OTP enrollment requires an OTP provider")
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

// AgentOTPChallenge is the bounded, non-secret context passed to the
// OTP-enrollment provider. Whoever holds the mailbox — a person, an agent with
// its own address, a shared operations alias — receives the code out of band;
// the SDK only asks the provider to return it. The assignment ticket and the
// enrollment credential are intentionally excluded.
type AgentOTPChallenge struct {
	AgentID                   string
	CredentialKeyID           string
	CellID                    string
	AssignmentTicketExpiresAt time.Time
	// PendingActivationRecovery is true only when an earlier REG had an
	// ambiguous/lost RAK and the SDK needs the original code again. No NHP_OTP is
	// dispatched in this mode; the provider must return the code issued for the
	// persisted ticket. Recovery therefore skips the fresh-registration minimum
	// ticket-lifetime gate and lets the assigned cell decide replay validity. The
	// field is bounded non-secret context.
	PendingActivationRecovery bool
}

// agentRuntimeOption is the private base shared by the closed public option
// subsets. External packages can pass constructor results but cannot implement
// or widen any subset.
type agentRuntimeOption interface {
	applyAgentRuntimeOption(*nativeAgentRuntimeConfig) error
}

// AgentRuntimeRegistrationOption is the closed option set for the UDP-only
// ConnectAgentRuntime API. Only closed native lifecycle options implement it.
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

// AgentRuntimeRecoveryOption is the closed option set for RecoverAgentRuntime.
// It deliberately excludes caller-selected identity, enrollment metadata, OTP,
// and registration-key policy: recovery preserves the persisted X25519 identity
// and obtains placement only from the authenticated Hub result. Callers may
// assert the expected persisted agent id, but cannot select or change it.
type AgentRuntimeRecoveryOption interface {
	agentRuntimeOption
	isAgentRuntimeRecoveryOption()
}

// AgentRuntimeLifecycleOption configures registration, refresh, and explicit
// credential recovery, but is still broader than one knock exchange.
type AgentRuntimeLifecycleOption interface {
	AgentRuntimeRegistrationOption
	AgentRuntimeRefreshOption
	AgentRuntimeRecoveryOption
}

// AgentRuntimeRenewalOption configures how the entry points that renew a
// completed registration's assignment — ConnectAgentRuntime and
// RefreshAgentRuntime — treat the renewed placement. A binding produced by
// either call carries the same policy into its own lease renewals. Recovery is
// deliberately excluded: RecoverAgentRuntime exists to adopt the authenticated
// Hub placement, so a renewal policy cannot apply there.
type AgentRuntimeRenewalOption interface {
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
	hub *HubBootstrap
	// hubErr records why no Hub trust root is available when hub is nil. It is
	// surfaced only by requireHub, so a call that needs no Hub exchange — a warm
	// or offline open of completed state — still succeeds without one.
	hubErr                   error
	agentID                  string
	recoveryAgentID          string
	hostname                 string
	version                  string
	pinAssignment            bool
	offlineOpen              bool
	baseURL                  string
	httpClient               HTTPDoer
	resolver                 nativeudp.Resolver
	dialer                   nativeudp.Dialer
	timeout                  time.Duration
	maxAddresses             int
	assignmentOptions        []AssignmentOption
	allowedKeyKinds          map[RegistrationKeyKind]struct{}
	otpProvider              func(context.Context, AgentOTPChallenge) (string, error)
	clock                    func() time.Time
	random                   io.Reader
	deviceCredential         string
	enrollCredential         string
	enrollCredentialSet      bool
	enrollCredentialProvider AgentEnrollmentCredentialProvider
	continuityStore          AgentStateStore
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
func (nativeRuntimeUDPOptionFunc) isAgentRuntimeRecoveryOption()     {}
func (nativeRuntimeUDPOptionFunc) isAgentRuntimeUDPOption()          {}

type nativeRuntimeLifecycleOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeLifecycleOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeLifecycleOptionFunc) isAgentRuntimeRegistrationOption() {}
func (nativeRuntimeLifecycleOptionFunc) isAgentRuntimeRefreshOption()      {}
func (nativeRuntimeLifecycleOptionFunc) isAgentRuntimeRecoveryOption()     {}

type nativeRuntimeRenewalOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeRenewalOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeRenewalOptionFunc) isAgentRuntimeRegistrationOption() {}
func (nativeRuntimeRenewalOptionFunc) isAgentRuntimeRefreshOption()      {}

type nativeRuntimeRecoveryOptionFunc func(*nativeAgentRuntimeConfig) error

func (f nativeRuntimeRecoveryOptionFunc) applyAgentRuntimeOption(c *nativeAgentRuntimeConfig) error {
	return f(c)
}

func (nativeRuntimeRecoveryOptionFunc) isAgentRuntimeRecoveryOption() {}

// WithAgentRuntimeHub configures the single pinned LayerV Hub trust root used
// by ConnectAgentRuntime. It is optional, and is the override for callers
// running their own LayerV deployment: without it the trust root comes from
// the deployment — the file named by QURL_DEPLOYMENT today, embedded in GA
// builds later.
func WithAgentRuntimeHub(hub HubBootstrap) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		hubCopy := hub
		c.hub = &hubCopy
		return nil
	})
}

// WithAgentRuntimeRecoveryHub configures the pinned LayerV Hub trust root used
// by RecoverAgentRuntime. Recovery obtains placement only from the authenticated
// Hub result; this option never supplies or derives an assigned cell.
func WithAgentRuntimeRecoveryHub(hub HubBootstrap) AgentRuntimeRecoveryOption {
	return nativeRuntimeRecoveryOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		hubCopy := hub
		c.hub = &hubCopy
		return nil
	})
}

// WithExpectedAgentRuntimeRecoveryAgentID requires RecoverAgentRuntime to load
// the exact persisted agent id. The assertion is checked while the SDK setup
// lock is held and before private-key decoding, DNS resolution, or UDP I/O. It
// never selects, creates, or changes an identity.
func WithExpectedAgentRuntimeRecoveryAgentID(agentID string) AgentRuntimeRecoveryOption {
	return nativeRuntimeRecoveryOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if err := validateAssignmentAgentID(agentID); err != nil {
			return fmt.Errorf("%w: expected recovery agent identity: %w", ErrInvalidRegisterConfig, err)
		}
		c.recoveryAgentID = agentID
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

// WithAgentRuntimeOTPProvider supplies the callback that returns the emailed
// one-time code. OTP is the default enrollment path, so this is the option a
// normal enrolling ConnectAgentRuntime call installs; nothing about it is
// specific to a human enrolling.
//
// It requires an enrollment policy that accepts the account kind, which is the
// default. Installing it under a policy that rejects OTP — most obviously
// WithAgentRuntimeHeadlessEnrollment — is contradictory and fails with
// ErrInvalidRegisterConfig rather than leaving a callback that can never fire.
//
// A fresh callback follows one fire-and-forget assigned-cell
// NHP_OTP dispatch and is bounded by the ticket window. Pending-activation
// recovery instead sets AgentOTPChallenge.PendingActivationRecovery, dispatches
// no OTP, and receives the caller context clamped to the persisted recovery
// deadline. Callers may set an earlier outer deadline when the provider could
// block.
func WithAgentRuntimeOTPProvider(provider func(context.Context, AgentOTPChallenge) (string, error)) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if provider == nil {
			return fmt.Errorf("%w: OTP provider must not be nil", ErrInvalidRegisterConfig)
		}
		c.otpProvider = provider
		return nil
	})
}

// WithAgentRuntimeHeadlessEnrollment opts out of OTP enrollment for a runtime
// that has no mailbox to receive a code in — the escape hatch, not the norm.
// It accepts exactly the one-shot enrollment token kinds that carry their own
// proof: connector_bootstrap and bootstrap. An account credential is rejected
// under this policy, because honoring it would require a code this runtime has
// already said it cannot obtain. The retired durable agent kind is not
// admitted here either; a legacy qurl:agent-scoped key needs the explicit
// WithAgentRuntimeAllowedRegistrationKeyKinds.
//
// It contradicts WithAgentRuntimeOTPProvider and cannot be combined with it:
// one says no code can be read, the other says how to read one. Passing both
// fails with ErrInvalidRegisterConfig. A binary that must accept either kind of
// credential keeps the provider and widens the policy with
// WithAgentRuntimeAllowedRegistrationKeyKinds instead.
//
// Prefer OTP. Reach for this only when no address — the runtime's own, an
// operator's, or a shared alias — can receive the code.
func WithAgentRuntimeHeadlessEnrollment() AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.allowedKeyKinds = headlessRegistrationKeyKinds()
		return nil
	})
}

// headlessRegistrationKeyKinds is the set of one-shot enrollment token kinds
// that enroll with no one-time code.
func headlessRegistrationKeyKinds() map[RegistrationKeyKind]struct{} {
	return map[RegistrationKeyKind]struct{}{
		RegistrationKeyKindConnectorBootstrap: {},
		RegistrationKeyKindBootstrap:          {},
	}
}

// WithAgentRuntimeAllowedRegistrationKeyKinds restricts the authenticated Hub
// assignment key kinds accepted by ConnectAgentRuntime. It is the low-level
// form of the same policy WithAgentRuntimeHeadlessEnrollment sets; reach for it
// when one binary must accept both an OTP credential and a pre-issued one. It
// is also the only policy that still admits the retired agent kind, for a
// caller holding a legacy durable qurl:agent-scoped key.
//
// The native default is account alone, so OTP enrollment is what a plain
// enrolling ConnectAgentRuntime call performs. Policy and provider must agree in
// both directions: accepting account without WithAgentRuntimeOTPProvider fails with
// ErrAgentOTPRequired before any network I/O, and installing a provider while
// excluding account fails with ErrInvalidRegisterConfig. Later options
// overwrite earlier ones; the last policy option wins.
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
// KNK and a possible RKN are independent exchanges, so their worst-case
// transport budget is roughly 2 * maxAddresses * timeout. Callers that need one
// aggregate deadline must set it on the context.
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

// WithAgentRuntimePinnedAssignment makes assignment renewal fail closed with an
// AgentAssignmentChangedError instead of following a cell or generation move,
// leaving durable state untouched. It is accepted by ConnectAgentRuntime and
// RefreshAgentRuntime, and a binding either call returns applies the same
// policy when it renews its own lease. Reach for it only when placement is an
// input to something outside the SDK — an egress allowlist pinned to a cell, or
// a change-control process that must see the move first. Ordinary callers
// should omit it: the adopted placement is still accepted only from that call's
// authenticated Hub LRT, and the SDK never derives a cell endpoint, accepts
// caller-supplied placement, or contacts the newly assigned cell during refresh.
func WithAgentRuntimePinnedAssignment() AgentRuntimeRenewalOption {
	return nativeRuntimeRenewalOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.pinAssignment = true
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
	// OTP is the default enrollment path: a durable API key (the account kind)
	// enrolls by answering an emailed one-time code. The one-shot enrollment
	// tokens (bootstrap, connector_bootstrap) stay out because minting them IS
	// the authorization — the token is its own proof, so demanding a code as
	// well buys nothing; they say so with WithAgentRuntimeHeadlessEnrollment.
	//
	// The durable agent kind is retired: the platform no longer mints keys
	// that classify as it, so no default path admits it. Its wire token stays
	// reserved (see RegistrationKeyKindAgent), and a caller holding a legacy
	// key can still admit it explicitly with
	// WithAgentRuntimeAllowedRegistrationKeyKinds.
	c.allowedKeyKinds = map[RegistrationKeyKind]struct{}{
		RegistrationKeyKindAccount: {},
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil runtime option", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(c); err != nil {
			return nil, err
		}
	}
	if err := c.validateEnrollmentCredentialOptions(); err != nil {
		return nil, err
	}
	if err := c.validateEnrollmentPolicyOptions(); err != nil {
		return nil, err
	}
	if err := c.validateOfflineOpenOptions(); err != nil {
		return nil, err
	}
	if c.hub == nil {
		// Fall back to the deployment's hub: the file named by QURL_DEPLOYMENT
		// today, the deployment embedded in GA builds later. An explicit option
		// still wins, so nothing that already passes WithAgentRuntimeHub changes
		// behavior; this only removes the requirement that every integrator
		// retype the Hub host, port, and X25519 key it had to source out of
		// band. Only the legitimately hub-less class defers: a deployment with
		// no "hub" records ErrNoDeploymentHub instead of failing the call,
		// because serving completed state with a live lease needs no Hub
		// exchange, and requireHub surfaces the error on any path that does. A
		// deployment file the operator explicitly named but that cannot be read
		// or parsed is a config fault and fails here, so a warm start cannot
		// silently return a binding that will never renew. requireHub therefore
		// only ever surfaces the ErrNoDeploymentHub class.
		hub, err := deploymentHub()
		switch {
		case err == nil:
			c.hub = hub
		case errors.Is(err, ErrNoDeploymentHub):
			c.hubErr = fmt.Errorf("%w: %w", ErrInvalidRegisterConfig, err)
		default:
			return nil, fmt.Errorf("%w: %w", ErrInvalidRegisterConfig, err)
		}
	}
	if c.hub != nil {
		if _, err := c.hub.nativeEndpoint(); err != nil {
			return nil, fmt.Errorf("%w: Hub trust root: %w", ErrInvalidRegisterConfig, err)
		}
	}
	return c, nil
}

// validateEnrollmentCredentialOptions keeps the eager, lazy, and OTP callback
// paths mutually exclusive. Treat an explicitly supplied empty credential as
// eager configuration too: option ordering must not silently make a
// contradictory provider configuration valid.
func (c *nativeAgentRuntimeConfig) validateEnrollmentCredentialOptions() error {
	if c.enrollCredentialProvider == nil {
		return nil
	}
	if c.enrollCredentialSet {
		return fmt.Errorf("%w: WithAgentRuntimeEnrollmentCredentialProvider contradicts WithAgentRuntimeEnrollmentCredential; pass one enrollment credential source", ErrInvalidRegisterConfig)
	}
	if c.otpProvider != nil {
		return fmt.Errorf("%w: WithAgentRuntimeEnrollmentCredentialProvider contradicts WithAgentRuntimeOTPProvider; a lazy one-shot credential provider cannot use the account OTP path", ErrInvalidRegisterConfig)
	}
	return nil
}

// requireHub returns the pinned Hub trust root, or the recorded resolution
// failure for a config that has none. Callers invoke it exactly where a Hub
// exchange becomes necessary, so opening completed state never demands a trust
// root it would not use.
func (c *nativeAgentRuntimeConfig) requireHub() (HubBootstrap, error) {
	if c.hub != nil {
		return *c.hub, nil
	}
	if c.hubErr != nil {
		return HubBootstrap{}, c.hubErr
	}
	return HubBootstrap{}, fmt.Errorf("%w: %w", ErrInvalidRegisterConfig, ErrNoDeploymentHub)
}

// validateOfflineOpenOptions rejects enrollment inputs combined with
// WithAgentRuntimeOfflineOpen. An offline open can only serve an existing
// completed registration, so an enrollment credential could never be sent and
// an OTP callback could never fire; accepting either would silently disarm it.
func (c *nativeAgentRuntimeConfig) validateOfflineOpenOptions() error {
	if !c.offlineOpen {
		return nil
	}
	if c.enrollCredentialSet {
		return fmt.Errorf("%w: WithAgentRuntimeOfflineOpen contradicts WithAgentRuntimeEnrollmentCredential; enrollment needs the network an offline open forbids, so pass one or the other", ErrInvalidRegisterConfig)
	}
	if c.enrollCredentialProvider != nil {
		return fmt.Errorf("%w: WithAgentRuntimeOfflineOpen contradicts WithAgentRuntimeEnrollmentCredentialProvider; enrollment needs the network an offline open forbids, so pass one or the other", ErrInvalidRegisterConfig)
	}
	if c.otpProvider != nil {
		return fmt.Errorf("%w: WithAgentRuntimeOfflineOpen contradicts WithAgentRuntimeOTPProvider; OTP enrollment needs the network an offline open forbids, so pass one or the other", ErrInvalidRegisterConfig)
	}
	return nil
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

func (c *nativeAgentRuntimeConfig) validateStateContinuity() error {
	if c == nil {
		return fmt.Errorf("%w: native runtime config is nil", ErrAgentStateContinuity)
	}
	return validateAgentStateStoreContinuity(c.continuityStore)
}

func registerNativeAgentRuntime(ctx context.Context, store AgentStateStore, opts []AgentRuntimeRegistrationOption) (*Client, *AgentRuntimeBinding, error) {
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

	result, err := withAgentStoreContinuity(store, destroyNativeRuntimeResult, func(retained AgentStateStore) (*nativeRuntimeResult, error) {
		state, found, err := loadNativeAgentStateIfPresent(ctx, retained)
		if err != nil {
			return nil, err
		}
		// Re-running ConnectAgentRuntime on every start is a supported pattern:
		// a caller restarting in production cannot know whether this is the first
		// enrollment. A completed registration whose lease is still live returns
		// its binding here with no setup lock and no packet. An expired lease
		// falls through to the locked path, which renews it rather than failing
		// the way an unconditional re-register used to after any outage longer
		// than the lease.
		if found && state.RegisteredAt != nil && !state.Assignment.LeaseExpired(cfg.clock()) {
			return finishNativeRuntimeResult(store, state, cfg)
		}
		// WithAgentRuntimeOfflineOpen: the live-lease path above is the only
		// success, and it took no lock and sent no packet. What remains is
		// absent, incomplete, or lease-expired state; run the same completed-state
		// validation the online path would, so an expired lease fails with
		// ErrAssignmentLeaseExpired and everything else fails closed identically —
		// still without lock, Hub, or store mutation.
		if cfg.offlineOpen {
			if !found {
				return nil, fmt.Errorf("%w: offline open requires an existing completed registration: %w", ErrInvalidRegisterConfig, ErrAgentStateNotFound)
			}
			return finishNativeRuntimeResult(store, state, cfg)
		}
		return withAgentSetupLock(ctx, retained, destroyNativeRuntimeResult, func(lockedCtx context.Context, locked AgentStateStore) (*nativeRuntimeResult, error) {
			return cfg.registerLocked(lockedCtx, locked)
		})
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

func destroyNativeRuntimeResult(result *nativeRuntimeResult) {
	if result == nil {
		return
	}
	// Only the one-shot binding owns in-memory-only key material. The client
	// holds the already-persisted device API credential and owns no live handle.
	result.binding.Destroy()
}

func (r *nativeRuntimeResult) split() (*Client, *AgentRuntimeBinding, error) {
	if r == nil {
		return nil, nil, fmt.Errorf("%w: runtime transition returned nil", ErrInvalidRegisterConfig)
	}
	return r.client, r.binding, nil
}

func finishNativeRuntime(store AgentStateStore, state *AgentState, cfg *nativeAgentRuntimeConfig) (*Client, *AgentRuntimeBinding, error) {
	defer clearOwnedAgentState(state)
	store = baseAgentStateStore(store)
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
	// already hold a separate working copy whose deferred wipe must not erase
	// the private key transferred to the returned binding.
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, nil, err
	}
	client := newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey, state.AgentID, cfg.clock)
	binding := newAgentRuntimeBinding(state, privateKey)
	return client, binding, nil
}

func finishNativeRuntimeResult(store AgentStateStore, state *AgentState, cfg *nativeAgentRuntimeConfig) (*nativeRuntimeResult, error) {
	client, binding, err := finishNativeRuntime(store, state, cfg)
	// Every lifecycle-produced binding can renew its own lease, so a held binding
	// keeps working past expiry instead of failing every later knock. An offline
	// open opts out: renewal happens only on the caller's schedule, so the
	// binding must not renew behind its back on the first knock either.
	if !cfg.offlineOpen {
		binding.attachRenewal(store, cfg)
	}
	return &nativeRuntimeResult{client: client, binding: binding}, err
}

// renewSessionAssignment refreshes and durably persists the assignment for a
// completed registration and returns the fresh placement. It is the narrow
// renewal a held binding performs; it deliberately builds no Client and reuses
// the same locked, adoption-aware path as every other renewal.
// now is the session clock that decided a renewal was due; freshness is judged
// against that same instant here so one decision never straddles two clocks.
func (c *nativeAgentRuntimeConfig) renewSessionAssignment(ctx context.Context, hub HubBootstrap, store AgentStateStore, agentID string, privateKey []byte, now time.Time) (*AgentAssignment, error) {
	return withAgentSetupLock(ctx, store, func(*AgentAssignment) {}, func(lockedCtx context.Context, locked AgentStateStore) (*AgentAssignment, error) {
		state, err := loadCompletedRegisteredState(lockedCtx, locked, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}
		defer clearOwnedAgentState(state)
		if state.AgentID != agentID {
			return nil, fmt.Errorf("%w: persisted agent id changed under a held binding", ErrInvalidRegisterConfig)
		}
		if state.Assignment == nil {
			return nil, fmt.Errorf("%w: completed state has no assignment", ErrInvalidRegisterConfig)
		}
		// Another process may already have renewed this shared state file. Adopt
		// that result rather than spending a redundant Hub exchange.
		if now.Add(sessionLeaseRenewalLead).Before(state.Assignment.LeaseExpiresAt) {
			return state.Assignment.clone(), nil
		}
		fresh, err := c.refreshAssignmentLifecycle(lockedCtx, hub, state.AgentID, privateKey)
		if err != nil {
			return nil, err
		}
		if err := ensureRefreshAssignmentContinuity(state.Assignment, fresh, !c.pinAssignment); err != nil {
			return nil, err
		}
		if !sameAgentAssignment(state.Assignment, fresh) {
			candidate := state.clone()
			candidate.Assignment = fresh.clone()
			if err := locked.SaveAgentState(lockedCtx, candidate); err != nil {
				return nil, fmt.Errorf("%w: save renewed assignment: %w", ErrAgentBindingPersistence, err)
			}
		}
		return fresh.clone(), nil
	})
}

func (c *nativeAgentRuntimeConfig) registerLocked(ctx context.Context, store AgentStateStore) (*nativeRuntimeResult, error) {
	enrollmentCredential := c.enrollCredential
	c.continuityStore = store
	defer func() { c.continuityStore = nil }()
	state, err := loadOrCreateAgentState(ctx, store, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	if state.RegisteredAt != nil {
		// Renew only a structurally sound assignment whose lease ran out. Missing
		// or malformed assignment state keeps its original terminal error from
		// finishNativeRuntimeResult rather than reaching for the network.
		if state.Assignment != nil && state.Assignment.LeaseExpired(c.clock()) {
			hub, err := c.requireHub()
			if err != nil {
				return nil, err
			}
			return c.renewCompletedAssignment(ctx, hub, store, state)
		}
		return finishNativeRuntimeResult(store, state, c)
	}
	// Nothing is registered, nothing is resumable, and the option set carries no
	// way to enroll. Saying "install an OTP provider" here would be a lie: this
	// call promises that without a credential it can never create a
	// registration, so the missing piece is the registration itself, not the
	// callback. Name what is actually absent and every real way to supply it.
	if state.PendingActivation == nil && state.PendingCompletion == nil &&
		!c.enrollCredentialSet && c.enrollCredentialProvider == nil && c.otpProvider == nil {
		return nil, fmt.Errorf("%w: nothing is registered in this state store and no enrollment credential or OTP provider is configured; enroll out of band (an installer) and reuse its store, or pass WithAgentRuntimeEnrollmentCredential or WithAgentRuntimeEnrollmentCredentialProvider — with WithAgentRuntimeOTPProvider for the default account one-time-code enrollment: %w", ErrInvalidRegisterConfig, ErrAgentStateNotFound)
	}
	// Only an attempt that will actually enroll needs the provider, so a completed
	// state still reopens with no options. Checking here keeps the failure ahead
	// of the Hub round trip that would otherwise burn an assignment ticket to
	// learn what the option set already proves.
	if err := c.requireOTPProviderForPolicy(); err != nil {
		return nil, err
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
	if err := c.preparePendingRecovery(ctx, store, state); err != nil {
		return nil, err
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
		// Finish the registration at the placement its candidate is bound to,
		// whatever the lease says.
		//
		// A pending completion lives for the 90-day recovery horizon anchored to
		// the activation ticket, while a lease lasts hours, so a resumed
		// registration almost always meets an expired lease. Refreshing first used
		// to turn that ordinary resume into a dead end whenever LayerV had moved
		// the agent in between: the fresh placement fails continuity, and the
		// candidate — bound by PendingAgentCompletion to the cell and generation
		// that minted it — can never be replayed anywhere else.
		//
		// Completing first is correct rather than merely convenient. The
		// completion request carries no lease, ticket, or placement field, the
		// closed 523xx taxonomy has no lease-expiry rejection, and
		// RecoveryExpiresAt is defined never to be reset by an assignment refresh.
		// The lease governs which placement is current, not whether the cell that
		// minted this candidate will still commit it. Replaying the same candidate
		// to that same cell is the designed one-shot replay, so this cannot mint a
		// second credential; if the cell no longer holds it, the answer is an
		// authenticated 52301/52303 rather than a guess.
		if err := c.completePending(ctx, store, state, privateKey); err != nil {
			return nil, err
		}
		// Registration is now complete and durable. Reconcile placement with the
		// ordinary completed-state path, which renews an expired lease and adopts
		// any move LayerV made while this registration was in flight.
		if state.Assignment.LeaseExpired(c.clock()) {
			hub, err := c.requireHub()
			if err != nil {
				return nil, err
			}
			return c.renewCompletedAssignment(ctx, hub, store, state)
		}
		return finishNativeRuntimeResult(store, state, c)
	}
	// Enrollment credentials are attempt-scoped Hub inputs. Completed and
	// pending-completion paths above do not need one. A pending activation (a
	// native marker, so the save block below is skipped) requires the same
	// credential to corroborate its durable fingerprint; a transaction with no
	// pending activation needs it to obtain a fresh Hub assignment.
	//
	// Validate an explicit credential before any fresh identity save, preserving
	// the eager option's fail-before-mutation contract. A provider is different:
	// its request needs the stable agent id, so that id is saved first and its
	// result is validated immediately after the one callback.
	if c.enrollCredentialProvider == nil {
		if err := validateRecoverableEnrollmentCredential(enrollmentCredential); err != nil {
			return nil, err
		}
	}
	// With no pending activation to resume, the very next step after the save
	// below is a fresh Hub assignment. Require the trust root now, while nothing
	// durable has happened: a config-class fault must not leave a minted
	// identity behind in the store. A pending-activation resume stays out of
	// this check because its REG replays against the assigned cell and needs no
	// Hub unless a replacement is authorized, where requireHub already runs.
	if state.PendingActivation == nil {
		if _, err := c.requireHub(); err != nil {
			return nil, err
		}
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
	if c.enrollCredentialProvider != nil {
		request := AgentEnrollmentCredentialRequest{
			AgentID:                   state.AgentID,
			PendingActivationRecovery: state.PendingActivation != nil,
		}
		enrollmentCredential, err = c.enrollCredentialProvider(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("qurl: enrollment credential provider: %w", err)
		}
		if err := validateRecoverableEnrollmentCredential(enrollmentCredential); err != nil {
			return nil, err
		}
	}

	return c.activateAndComplete(ctx, enrollmentCredential, store, state, privateKey)
}

// preparePendingRecovery performs the only supported pre-v6 pending-state
// migration while the setup lock is held and before any UDP I/O. A legacy
// activation has the authenticated assignment-ticket expiry needed to derive
// its exact finite deadline. A legacy completion does not retain that anchor;
// inventing one from the upgrade clock would make server retention unbounded,
// so it fails closed for explicit recovery or reprovisioning.
func (c *nativeAgentRuntimeConfig) preparePendingRecovery(ctx context.Context, store AgentStateStore, state *AgentState) error {
	if state == nil {
		return fmt.Errorf("%w: pending recovery state is nil", ErrInvalidAgentState)
	}
	if state.PendingActivation != nil && state.PendingActivation.RecoveryExpiresAt.IsZero() {
		anchor := state.PendingActivation.AssignmentTicketExpiresAt
		deadline, err := agentRecoveryDeadline(anchor)
		if err != nil {
			return err
		}
		next := state.clone()
		next.PendingActivation.RecoveryAnchorTicketExpiresAt = anchor
		next.PendingActivation.RecoveryExpiresAt = deadline
		next.SchemaVersion = agentStateSchemaVersion
		if err := validatePendingActivationRecoveryDeadline(next.PendingActivation, next); err != nil {
			return fmt.Errorf("%w: validate migrated pending activation recovery deadline: %w", ErrInvalidRegisterConfig, err)
		}
		// Persist the authoritative v6 anchor even when it is already expired, so
		// later starts fail the same closed deadline without reinterpreting v5 state.
		if err := store.SaveAgentState(ctx, next); err != nil {
			return fmt.Errorf("%w: migrate legacy pending activation recovery deadline: %w", ErrAgentBindingPersistence, err)
		}
		*state = *next
	}
	if state.PendingCompletion != nil && state.PendingCompletion.RecoveryExpiresAt.IsZero() {
		return &AgentRecoveryMigrationRequiredError{
			Phase: AgentRecoveryPhaseCompletion, SchemaVersion: state.SchemaVersion,
		}
	}
	return c.requirePendingRecoveryLive(state)
}

func (c *nativeAgentRuntimeConfig) requirePendingRecoveryLive(state *AgentState) error {
	_, _, pending := pendingRecoveryDeadline(state)
	if !pending {
		return nil
	}
	_, err := newAgentRecoveryBoundary(state, c.clock)
	return err
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
	// replacement (attempt 0 only). The structural bound prevents a future edit
	// from accidentally turning replacement into an unbounded loop.
	for attempt := 0; attempt < 2; attempt++ {
		var credential string
		var err error
		operationCtx := ctx
		var boundary *agentRecoveryBoundary
		cancel := func() {}
		if forceFresh {
			credential, err = c.persistFreshPendingActivation(ctx, enrollmentCredential, store, state, privateKey)
			if err == nil {
				boundary, operationCtx, cancel, err = boundedRecovery(ctx, state, c.clock)
				if err != nil {
					return nil, err
				}
			}
		} else {
			boundary, operationCtx, cancel, err = boundedRecovery(ctx, state, c.clock)
			if err != nil {
				return nil, err
			}
			credential, err = c.pendingRegistrationCredential(operationCtx, state, enrollmentCredential)
		}
		if boundary != nil {
			if boundaryErr := boundary.check(); boundaryErr != nil {
				cancel()
				return nil, boundaryErr
			}
		}
		if err != nil {
			if boundary != nil {
				err = boundary.mapError(ctx, operationCtx, err)
			}
			cancel()
			return nil, err
		}
		if boundary == nil {
			cancel()
			return nil, fmt.Errorf("%w: activation recovery boundary is missing before REG", ErrInvalidAgentState)
		}
		err = c.registerPendingActivation(operationCtx, state, credential, privateKey)
		if boundaryErr := boundary.check(); boundaryErr != nil {
			cancel()
			return nil, boundaryErr
		}
		if err == nil {
			if err := c.transitionPendingActivation(operationCtx, store, state); err != nil {
				err = boundary.mapError(ctx, operationCtx, err)
				cancel()
				return nil, err
			}
			cancel()
			if err := c.completePending(ctx, store, state, privateKey); err != nil {
				return nil, err
			}
			return finishNativeRuntimeResult(store, state, c)
		}
		err = boundary.mapError(ctx, operationCtx, err)
		cancel()
		if attempt == 0 && registrationVerdictPermitsReplacement(err) {
			// Fetch a replacement only after an authenticated non-commit verdict,
			// and retain the old record until persistFreshPendingActivation commits
			// the replacement.
			forceFresh = true
			continue
		}
		return nil, err
	}
	// The second attempt always returns through the terminal branch above. Keep
	// this fail-closed invariant guard in case future control flow changes.
	return nil, fmt.Errorf("%w: activation attempts exhausted without a terminal result", ErrInvalidAgentState)
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
	operationCtx := ctx
	var boundary *agentRecoveryBoundary
	var cancel context.CancelFunc
	var err error
	if state.PendingActivation != nil {
		boundary, operationCtx, cancel, err = boundedRecovery(ctx, state, c.clock)
		if err != nil {
			return "", err
		}
		defer cancel()
	}
	mapRecoveryError := func(err error) error {
		if boundary == nil {
			return err
		}
		return boundary.mapError(ctx, operationCtx, err)
	}

	hub, err := c.requireHub()
	if err != nil {
		return "", err
	}
	initial, err := c.fetchInitialAssignmentLifecycle(operationCtx, hub, state.AgentID, enrollmentCredential, privateKey)
	if err != nil {
		return "", mapRecoveryError(err)
	}
	if boundary != nil {
		if err := boundary.check(); err != nil {
			return "", err
		}
	}
	if err := c.requireAllowedRegistrationKeyKind(initial.Registration.KeyKind); err != nil {
		return "", err
	}
	candidateState := state.clone()
	candidateState.Assignment = initial.Assignment.clone()
	// Account OTP is intentionally dispatched before PendingActivation commits.
	// Persisting a "dispatched" record first could strand the ticket if the
	// process exits before the one-way send. A later save failure is safe: no REG
	// occurred and a new explicit attempt may obtain a new ticket and its one OTP.
	credential, err := c.registrationCredential(operationCtx, candidateState, initial, enrollmentCredential, privateKey)
	if err != nil {
		return "", mapRecoveryError(err)
	}
	var pending *PendingAgentActivation
	if boundary != nil {
		pending, err = newPendingAgentActivationWithRecoveryAnchor(
			initial, candidateState, c.hostname, c.version, enrollmentCredential,
			state.PendingActivation.RecoveryAnchorTicketExpiresAt,
		)
	} else {
		pending, err = newPendingAgentActivation(initial, candidateState, c.hostname, c.version, enrollmentCredential)
	}
	if err != nil {
		return "", err
	}
	if boundary != nil {
		if err := boundary.check(); err != nil {
			return "", err
		}
	}
	candidateState.PendingActivation = pending
	candidateState.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(operationCtx, candidateState); err != nil {
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
		return "", fmt.Errorf("%w: runtime metadata does not match pending activation; resume with the original hostname and version because no replacement or fallback is permitted, or explicitly reprovision if those values cannot be restored", ErrInvalidRegisterConfig)
	}
	want := enrollmentCredentialFingerprint(enrollmentCredential)
	// The equality tag is not itself a secret, but the negligible constant-time
	// comparison keeps credential corroboration timing-independent if the stored
	// representation evolves later.
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
		// Exact replay may outlive the local ticket window, so the assigned cell
		// decides validity. The pending-recovery context is clamped to the durable
		// recovery deadline without inventing a fresh OTP window.
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
		DeviceAPIKey:                  candidate,
		CellID:                        state.Assignment.CellID,
		AssignmentGeneration:          state.Assignment.AssignmentGeneration,
		RecoveryAnchorTicketExpiresAt: state.PendingActivation.RecoveryAnchorTicketExpiresAt,
		RecoveryExpiresAt:             state.PendingActivation.RecoveryExpiresAt,
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
		if err := prepareLoadedAgentState(state, ErrInvalidRegisterConfig); err != nil {
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

// The lifecycle wrappers delegate one logical operation to the public
// Fetch/Refresh functions. Their single bounded exchange loop owns DNS and UDP
// recovery plus authenticated 52200/52204 waits, so one request_nonce and one
// serialized LST body cover the whole operation without nested retry budgets.
func (c *nativeAgentRuntimeConfig) fetchInitialAssignmentLifecycle(ctx context.Context, hub HubBootstrap, agentID, enrollmentCredential string, privateKey []byte) (*InitialAgentAssignment, error) {
	return fetchInitialAgentAssignment(ctx, hub, agentID, enrollmentCredential, c.udpOptions(privateKey), c.validateStateContinuity, c.assignmentOptions...)
}

func (c *nativeAgentRuntimeConfig) refreshAssignmentLifecycle(ctx context.Context, hub HubBootstrap, agentID string, privateKey []byte) (*AgentAssignment, error) {
	return refreshAgentAssignment(ctx, hub, agentID, c.udpOptions(privateKey), c.validateStateContinuity, c.assignmentOptions...)
}

// Enrollment policy and OTP provider must agree: a provider is installed
// exactly when the resolved policy accepts the account kind. The two halves of
// that invariant are checked in different places on purpose.
//
// validateEnrollmentPolicyOptions catches the contradictory half — a provider
// under a policy that rejects OTP — at config construction, because no
// enrollment, resumption, or reopen ever makes that option set correct.
//
// requireOTPProviderForPolicy catches the missing half at the point of
// enrollment instead, because a completed registration still reopens through
// ConnectAgentRuntime with no options at all, and that path needs no provider.
func (c *nativeAgentRuntimeConfig) validateEnrollmentPolicyOptions() error {
	if _, otpAllowed := c.allowedKeyKinds[RegistrationKeyKindAccount]; otpAllowed || c.otpProvider == nil {
		return nil
	}
	return fmt.Errorf("%w: WithAgentRuntimeOTPProvider contradicts an enrollment policy that rejects the account kind; WithAgentRuntimeHeadlessEnrollment declares this runtime cannot receive a code, so pass one or the other", ErrInvalidRegisterConfig)
}

func (c *nativeAgentRuntimeConfig) requireOTPProviderForPolicy() error {
	if _, otpAllowed := c.allowedKeyKinds[RegistrationKeyKindAccount]; !otpAllowed || c.otpProvider != nil {
		return nil
	}
	return fmt.Errorf("%w: install WithAgentRuntimeOTPProvider, or pass WithAgentRuntimeHeadlessEnrollment if this runtime cannot receive a code", ErrAgentOTPRequired)
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
	if initial == nil {
		return nil, fmt.Errorf("%w: pending activation requires initial assignment", ErrInvalidRegisterConfig)
	}
	return newPendingAgentActivationWithRecoveryAnchor(initial, state, hostname, version, enrollmentCredential, initial.AssignmentTicketExpiresAt)
}

func newPendingAgentActivationWithRecoveryAnchor(initial *InitialAgentAssignment, state *AgentState, hostname, version, enrollmentCredential string, recoveryAnchor time.Time) (*PendingAgentActivation, error) {
	if initial == nil || state == nil || state.Assignment == nil {
		return nil, fmt.Errorf("%w: pending activation requires initial assignment and state", ErrInvalidRegisterConfig)
	}
	if !sameAgentAssignment(&initial.Assignment, state.Assignment) {
		return nil, fmt.Errorf("%w: pending activation state assignment does not match initial assignment", ErrInvalidRegisterConfig)
	}
	// state.Assignment is already the isolated fresh clone. Copy its value into
	// the pending record instead of cloning the same assignment a second time.
	assignment := *state.Assignment
	pending := &PendingAgentActivation{
		AssignmentTicket: initial.AssignmentTicket, AssignmentTicketExpiresAt: initial.AssignmentTicketExpiresAt,
		RecoveryAnchorTicketExpiresAt: recoveryAnchor,
		AgentID:                       state.AgentID, AgentPublicKeyB64: state.PublicKeyB64,
		Assignment: assignment, Registration: initial.Registration,
		Hostname: hostname, AgentVersion: version,
		EnrollmentCredentialFingerprintB64: enrollmentCredentialFingerprint(enrollmentCredential),
	}
	deadline, err := agentRecoveryDeadline(pending.RecoveryAnchorTicketExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: construct pending activation recovery deadline: %w", ErrInvalidRegisterConfig, err)
	}
	pending.RecoveryExpiresAt = deadline
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
	if err := validatePendingActivationRecoveryDeadline(pending, state); err != nil {
		return err
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
	// qurl-conformance v0.5 requires the assignment lease to outlive its
	// one-shot ticket strictly. Repeat that producer invariant at the durable
	// boundary so a corrupted pending record cannot outlive its authority.
	if !pending.Assignment.LeaseExpiresAt.After(pending.AssignmentTicketExpiresAt) {
		return invalid("ticket expiry must precede the assignment lease")
	}
	if !validAPIKeyID(pending.Registration.KeyID) || !validPublicRegistrationKeyKind(pending.Registration.KeyKind) {
		return invalid("registration identity or kind is invalid")
	}
	if (pending.Hostname == "") != (pending.AgentVersion == "") {
		return invalid("registration metadata must contain both hostname and version or neither")
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
	if len(value) < minimumRecoverableEnrollmentCredentialEncodedLength {
		return fmt.Errorf("%w: enrollment credential encoded token must be at least %d bytes in total length", ErrInvalidRegisterConfig, minimumRecoverableEnrollmentCredentialEncodedLength)
	}
	return nil
}

func enrollmentCredentialFingerprint(value string) string {
	return fingerprintWithDomain(agentstatecontract.PendingActivationEnrollmentCredentialFingerprintDomain, value)
}

func fingerprintWithDomain(domain, value string) string {
	material := make([]byte, len(domain)+len(value))
	copy(material, domain)
	copy(material[len(domain):], value)
	digest := sha256.Sum256(material)
	wipeBytes(material)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (c *nativeAgentRuntimeConfig) registrationCredential(ctx context.Context, state *AgentState, initial *InitialAgentAssignment, enrollmentCredential string, privateKey []byte) (string, error) {
	switch initial.Registration.KeyKind {
	case assignmentKeyKindConnectorBootstrap, keyKindBootstrap, assignmentKeyKindAgent:
		return enrollmentCredential, nil
	case keyKindAccount:
		// requireOTPProviderForPolicy already rejects this combination before any
		// network I/O. Keep the check as a fail-closed guard for callers that
		// reach this path with a config built another way.
		if c.otpProvider == nil {
			return "", fmt.Errorf("%w: install WithAgentRuntimeOTPProvider before OTP enrollment", ErrAgentOTPRequired)
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
		if err := c.validateStateContinuity(); err != nil {
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
				// Name both causes. The assigned-cell OTP dispatch is one-way — it
				// carries no acknowledgement — so a code LayerV never sent and a
				// callback that never returned one are the same observation here, and
				// blaming the callback alone sends integrators to debug working code.
				return "", fmt.Errorf("%w: no one-time code arrived before the assignment ticket's safe registration window closed. Either the OTP provider did not return one in time, or LayerV never delivered a code to the address on this credential; the OTP dispatch is one-way, so the SDK cannot tell those apart. Check that address before assuming the callback is at fault: %w", ErrAssignmentTicketExpired, err)
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
	return recoveryBudgetErrorString("assigned-cell registration", "resume the exact pending activation with the same enrollment credential", e.Attempts, e.Elapsed, e.Last)
}

func (e *RegistrationRecoveryRequiredError) Unwrap() []error {
	if e == nil {
		return []error{ErrRegistrationRecoveryRequired}
	}
	return unwrapWithCause(e.Last, ErrRegistrationRecoveryRequired)
}

func newRegistrationRecovery(attempts int, elapsed time.Duration, last error) error {
	return &RegistrationRecoveryRequiredError{Attempts: attempts, Elapsed: elapsed, Last: last}
}

func registrationRetryInfo(err error) (time.Duration, bool) {
	// Only network ambiguity is safe to retry automatically. An authenticated
	// REG rate limit is terminal for this call; after any authority-required wait,
	// callers may re-invoke the exact pinned activation, never seek Hub or
	// cross-cell fallback. RAK has no retry-after field in this wire contract.
	return 0, nativeTransportRetryable(err)
}

func (c *nativeAgentRuntimeConfig) registerPendingActivation(ctx context.Context, state *AgentState, credential string, privateKey []byte) error {
	if state == nil || state.PendingActivation == nil {
		return fmt.Errorf("%w: assigned-cell REG requires pending activation", ErrInvalidAgentState)
	}
	pending := state.PendingActivation
	boundary, recoveryCtx, cancel, err := boundedRecovery(ctx, state, c.clock)
	if err != nil {
		return err
	}
	defer cancel()
	// Within the finite SDK recovery horizon, do not reject locally merely because
	// the one-shot ticket has expired. The pinned cell must distinguish an exact
	// committed replay from marker-absent 52111; only that authenticated verdict
	// can authorize one replacement assignment.
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
	_, err = runNativeExchange(recoveryCtx, retry, endpoint, body, c.udpOptions(privateKey), c.validateStateContinuity, nativeudp.Register, registrationRetryInfo, newRegistrationRecovery, func(reply []byte, _ time.Time) (*struct{}, error) {
		ack, parseErr := parseNativeRegisterAck(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		if ack.isSuccess() {
			return &struct{}{}, nil
		}
		return nil, classifyNativeRegisterError(ack, pending.Registration.KeyKind)
	})
	if err == nil {
		// Fail closed if the deadline is observed after an authenticated RAK; do
		// not promote the activation into a new completion mutation.
		return boundary.check()
	}
	return boundary.mapError(ctx, recoveryCtx, err)
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
			return fmt.Errorf("qurl: native account OTP expired after the bounded fresh-assignment recovery attempt (errCode=%q); start a new explicit ConnectAgentRuntime call only when another OTP attempt is intended: %w", ack.ErrCode, kind)
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
	return recoveryBudgetErrorString("completion", "reopen the persisted pending candidate", e.Attempts, e.Elapsed, e.Last)
}

func (e *CompletionRecoveryRequiredError) Unwrap() []error {
	if e == nil {
		return []error{ErrCompletionRecoveryRequired}
	}
	return unwrapWithCause(e.Last, ErrCompletionRecoveryRequired)
}

func (c *nativeAgentRuntimeConfig) completePending(ctx context.Context, store AgentStateStore, state *AgentState, privateKey []byte) error {
	if state.PendingCompletion == nil || state.Assignment == nil {
		return fmt.Errorf("%w: completion requires pending candidate and assignment", ErrInvalidAgentState)
	}
	boundary, recoveryCtx, cancel, err := boundedRecovery(ctx, state, c.clock)
	if err != nil {
		return err
	}
	defer cancel()
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
	keyID, err := c.runCompletionExchange(recoveryCtx, endpoint, body, c.udpOptions(privateKey))
	if err != nil {
		return boundary.mapError(ctx, recoveryCtx, err)
	}
	previous := state.clone()
	state.DeviceAPIKey = state.PendingCompletion.DeviceAPIKey
	state.DeviceAPIKeyID = keyID
	state.PendingCompletion = nil
	registeredAt := c.clock().UTC()
	state.RegisteredAt = &registeredAt
	state.SchemaVersion = agentStateSchemaVersion
	// The authenticated cell may already have committed even if the caller is
	// canceled or the recovery horizon closes as the LRT arrives. The per-write
	// UDP fence remains authoritative; after success, persist that irreversible
	// result under a small detached deadline while the setup lock is still held.
	persistCtx, cancelPersist := credentialRecoveryPersistenceContext(recoveryCtx)
	defer cancelPersist()
	if err := store.SaveAgentState(persistCtx, state); err != nil {
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
	keyID, err := runNativeExchange(ctx, retry, endpoint, body, transport, c.validateStateContinuity, nativeudp.List, completionRetryInfo, newCompletionRecovery, func(reply []byte, _ time.Time) (*string, error) {
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
// move that was not adopted. Assignment renewal — through ConnectAgentRuntime,
// RefreshAgentRuntime, or a held binding's own lease renewal — follows such a
// move by default, so this surfaces only for a caller that passed
// WithAgentRuntimePinnedAssignment. The SDK never selects a cell itself;
// adoption only ever follows an authenticated Hub result.
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

// ensureRefreshAssignmentContinuity narrows adoption to a fresh,
// authority-versioned move. The caller has already authenticated and strictly
// decoded current through RefreshAgentAssignment. Requiring the generation to
// advance is what keeps adoption safe once it is the default: it prevents a
// replayed or stale same-generation result from rolling the agent back or
// sideways into another cell. A new generation owns its endpoint revision, so
// revision continuity is intentionally enforced only within one generation.
func ensureRefreshAssignmentContinuity(previous, current *AgentAssignment, adoptReassignment bool) error {
	err := ensureAssignmentContinuity(previous, current)
	if adoptReassignment && errors.Is(err, ErrAssignmentReassignmentRequired) {
		if current.AssignmentGeneration <= previous.AssignmentGeneration {
			return invalidAssignmentResponse("refresh reassignment generation must advance", nil)
		}
		return nil
	}
	return err
}

// NativeKnockResult is the authenticated, resource-specific admission returned
// by KnockRegisteredAgent. ACToken is a bearer credential and is redacted from
// String and GoString; callers remain responsible for explicit field access or
// serialization.
type NativeKnockResult struct {
	ACToken        string
	ResourceHost   string
	OpenTime       uint32
	SessionID      uint64
	SessionReceipt NativeSessionReceipt
	AgentAddr      string
}

func (r NativeKnockResult) String() string {
	return fmt.Sprintf("qurl.NativeKnockResult{ACToken:[REDACTED], ResourceHost:%q, OpenTime:%d, SessionID:%d, AgentAddr:%q}", r.ResourceHost, r.OpenTime, r.SessionID, r.AgentAddr)
}

// GoString provides the same token redaction for %#v formatting.
func (r NativeKnockResult) GoString() string { return r.String() }

// NativeSessionReceipt is the immutable server-owned authority for retiring
// exactly one admitted session. The routing snapshot is intentionally private:
// retirement returns to the server identity that issued the receipt even if a
// later Hub refresh moves the binding to another cell.
type NativeSessionReceipt struct {
	CellID                string
	SessionID             uint64
	SessionIssuedAtMillis int64
	RunID                 string
	RunAttempt            uint64

	agentID  string
	endpoint nativeudp.Endpoint
}

// NativeSessionRetirement reports the durable close accepted by the server.
// State is "closing" while AC cleanup is in progress and "closed" after the
// replay-safe terminal transition.
type NativeSessionRetirement struct {
	SessionReceipt NativeSessionReceipt
	CloseEventID   string
	State          string
}

// KnockRegisteredAgent sends one caller-correlated NHP_KNK directly to the
// binding's assigned cell and returns only the requested resource's admission.
// An authenticated COK produces exactly one RKN using the same immutable
// agent/resource/RunID session identity and a body headerType of RKN; there is
// no retry loop, HTTP fallback, or cross-cell fallback. It validates the live
// authority-provided assignment before DNS or socket I/O and authenticates the
// reply against that assignment's server public key. KNK and RKN each resolve
// the assigned host, so cell replicas must share the stateless COK-signing key;
// the pinned server key plus COK cookie/trxId continuity keeps a cross-replica
// RKN bound to the initiating KNK.
func KnockRegisteredAgent(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte, knockResourceID string, opts NativeKnockOptions, transportOpts ...AgentRuntimeUDPOption) (*NativeKnockResult, error) {
	cfg, endpoint, assignment, err := registeredAgentSessionEndpointWithAssignment(ctx, binding, deviceStaticPrivateKey, transportOpts)
	if err != nil {
		return nil, err
	}
	body, err := marshalNativeKnockApplicationBody(binding.AgentID, knockResourceID, opts)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	// Build the possible RKN body before I/O: the bounded transport only owns
	// packet exchange, while qurl keeps the immutable session identity and body
	// policy at this trust boundary even when the usual KNK receives an ACK.
	reknockBody, err := marshalNativeSessionApplicationBody(binding.AgentID, knockResourceID, opts, nhpRKNHeaderType)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(reknockBody)
	reply, err := nativeudp.KnockWithReknock(ctx, endpoint, body, reknockBody, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	result, err := consumeNativeAgentKnockReply(reply, knockResourceID, nativeAgentKnockExpectation{
		CellID: assignment.CellID, RunID: opts.RunID, RunAttempt: opts.RunAttempt,
	})
	if err != nil {
		return nil, err
	}
	result.SessionReceipt.agentID = binding.authoritativeAgentID
	result.SessionReceipt.endpoint = cloneNativeUDPEndpoint(endpoint)
	return result, nil
}

// RetireRegisteredAgentSession sends one authenticated exact-session NHP_EXT
// using the immutable receipt returned by KnockRegisteredAgent. It never opens
// a replacement admission and never follows a later assignment to another cell.
func RetireRegisteredAgentSession(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	receipt NativeSessionReceipt, transportOpts ...AgentRuntimeUDPOption,
) (*NativeSessionRetirement, error) {
	cfg, endpoint, err := registeredAgentRetirementEndpoint(binding, deviceStaticPrivateKey, receipt, transportOpts)
	if err != nil {
		return nil, err
	}
	body, err := marshalNativeExactSessionCloseBody(receipt)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	reply, err := nativeudp.Exit(ctx, endpoint, body, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	return consumeNativeExactSessionCloseReply(reply, receipt)
}

func cloneNativeUDPEndpoint(endpoint nativeudp.Endpoint) nativeudp.Endpoint {
	return nativeudp.Endpoint{Host: endpoint.Host, Port: endpoint.Port, ServerStaticPub: bytes.Clone(endpoint.ServerStaticPub)}
}

func validateNativeSessionReceipt(receipt NativeSessionReceipt) error {
	if receipt.CellID == "" || receipt.SessionID == 0 || receipt.SessionIssuedAtMillis <= 0 ||
		receipt.RunAttempt == 0 || ValidateCycleRunID(receipt.RunID) != nil || receipt.agentID == "" ||
		receipt.endpoint.Host == "" || receipt.endpoint.Port <= 0 || len(receipt.endpoint.ServerStaticPub) != x25519key.Size {
		return fmt.Errorf("%w: invalid immutable session receipt", ErrInvalidNativeKnockInput)
	}
	return nil
}

func registeredAgentRetirementEndpoint(binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	receipt NativeSessionReceipt, transportOpts []AgentRuntimeUDPOption,
) (*nativeAgentRuntimeConfig, nativeudp.Endpoint, error) {
	if binding == nil {
		return nil, nativeudp.Endpoint{}, fmt.Errorf("%w: runtime binding must not be nil", ErrInvalidNativeKnockInput)
	}
	if len(deviceStaticPrivateKey) != x25519key.Size {
		return nil, nativeudp.Endpoint{}, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidNativeKnockInput, x25519key.Size)
	}
	if err := validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey); err != nil {
		return nil, nativeudp.Endpoint{}, err
	}
	if err := validateNativeSessionReceipt(receipt); err != nil {
		return nil, nativeudp.Endpoint{}, err
	}
	if receipt.agentID != binding.authoritativeAgentID {
		return nil, nativeudp.Endpoint{}, fmt.Errorf("%w: session receipt belongs to another agent", ErrInvalidNativeKnockInput)
	}
	cfg := defaultNativeAgentRuntimeConfig()
	for _, opt := range transportOpts {
		if opt == nil {
			return nil, nativeudp.Endpoint{}, fmt.Errorf("%w: nil native UDP transport option", ErrInvalidNativeKnockInput)
		}
		if err := opt.applyAgentRuntimeOption(cfg); err != nil {
			return nil, nativeudp.Endpoint{}, fmt.Errorf("%w: native UDP transport option: %w", ErrInvalidNativeKnockInput, err)
		}
	}
	return cfg, cloneNativeUDPEndpoint(receipt.endpoint), nil
}

// registeredAgentSessionEndpoint is the common no-I/O admission gate for
// native KNK/RKN and EXT. It intentionally validates the binding snapshot
// before body construction, DNS, or socket creation so every session-control
// operation has the same trust and placement boundary.
func registeredAgentSessionEndpoint(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte, transportOpts []AgentRuntimeUDPOption) (*nativeAgentRuntimeConfig, nativeudp.Endpoint, error) {
	cfg, endpoint, _, err := registeredAgentSessionEndpointWithAssignment(ctx, binding, deviceStaticPrivateKey, transportOpts)
	return cfg, endpoint, err
}

func registeredAgentSessionEndpointWithAssignment(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	transportOpts []AgentRuntimeUDPOption,
) (*nativeAgentRuntimeConfig, nativeudp.Endpoint, *AgentAssignment, error) {
	if binding == nil {
		return nil, nativeudp.Endpoint{}, nil, fmt.Errorf("%w: runtime binding must not be nil", ErrInvalidNativeKnockInput)
	}
	if len(deviceStaticPrivateKey) != x25519key.Size {
		return nil, nativeudp.Endpoint{}, nil, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidNativeKnockInput, x25519key.Size)
	}
	if err := validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey); err != nil {
		return nil, nativeudp.Endpoint{}, nil, err
	}
	cfg := defaultNativeAgentRuntimeConfig()
	for _, opt := range transportOpts {
		if opt == nil {
			return nil, nativeudp.Endpoint{}, nil, fmt.Errorf("%w: nil native UDP transport option", ErrInvalidNativeKnockInput)
		}
		if err := opt.applyAgentRuntimeOption(cfg); err != nil {
			return nil, nativeudp.Endpoint{}, nil, fmt.Errorf("%w: native UDP transport option: %w", ErrInvalidNativeKnockInput, err)
		}
	}
	// Renewal and the tamper check happen together against one placement. A
	// caller holding a single binding for weeks never has to think about the
	// lease; only an expired lease the Hub could not renew fails the exchange.
	assignment, err := binding.liveSessionAssignment(ctx, deviceStaticPrivateKey, cfg.clock())
	if err != nil {
		return nil, nativeudp.Endpoint{}, nil, err
	}
	if err := assignment.Validate(cfg.clock()); err != nil {
		return nil, nativeudp.Endpoint{}, nil, fmt.Errorf("%w: runtime assignment: %w", ErrInvalidNativeKnockInput, err)
	}
	endpoint, err := assignmentNativeEndpoint(assignment)
	if err != nil {
		return nil, nativeudp.Endpoint{}, nil, err
	}
	return cfg, endpoint, assignment, nil
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
	ErrCode               nativeJSONValue[string] `json:"errCode"`
	SessionID             nhpSessionIDJSON        `json:"sessId"`
	CellID                nativeJSONValue[string] `json:"cellId"`
	SessionIssuedAtMillis nativeJSONValue[int64]  `json:"sessIssuedAtMillis"`
	RunID                 nativeJSONValue[string] `json:"runId"`
	RunAttempt            nhpSessionIDJSON        `json:"runAttempt"`
	ErrMsg                nativeJSONValue[string] `json:"errMsg"`
	ResourceHost          nativeJSONStringMap     `json:"resHost"`
	OpenTime              nhpOpenTimeJSON         `json:"opnTime"`
	ASPToken              nativeJSONValue[string] `json:"aspToken"`
	AgentAddr             nativeJSONValue[string] `json:"agentAddr"`
	ACTokens              nativeJSONStringMap     `json:"acTokens"`
	PreAccessActions      nativePreAccessActions  `json:"preActions"`
	RedirectURL           nativeJSONValue[string] `json:"redirectUrl"`
}

type nativeAgentKnockExpectation struct {
	CellID     string
	RunID      string
	RunAttempt uint64
}

type nativeExactSessionCloseACK struct {
	ErrCode               nativeJSONValue[string] `json:"errCode"`
	ErrMsg                nativeJSONValue[string] `json:"errMsg"`
	CellID                nativeJSONValue[string] `json:"cellId"`
	SessionID             nhpSessionIDJSON        `json:"sessId"`
	SessionIssuedAtMillis nativeJSONValue[int64]  `json:"sessIssuedAtMillis"`
	RunID                 nativeJSONValue[string] `json:"runId"`
	RunAttempt            nhpSessionIDJSON        `json:"runAttempt"`
	CloseEventID          nativeJSONValue[string] `json:"closeEventId"`
	State                 nativeJSONValue[string] `json:"state"`
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

func interpretNativeAgentKnockReply(reply *relayknock.Reply, knockResourceID string,
	expectations ...nativeAgentKnockExpectation,
) (*NativeKnockResult, error) {
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
	if !isSuccessErrCode(ack.ErrCode.Value) {
		if ack.SessionID.Present || ack.CellID.Present || ack.SessionIssuedAtMillis.Present ||
			ack.RunID.Present || ack.RunAttempt.Present {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock deny ACK session id")
		}
		if !ack.OpenTime.Present || ack.OpenTime.Value != 0 {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock deny ACK open time")
		}
		// Any canonical non-success errCode is an authenticated server deny and
		// must reach the caller carrying its code. The deny vocabulary belongs to
		// the producer and may grow (qurl-conformance pins the server-legal codes
		// in its agent-knock deny vectors), so there is no client-side allowlist:
		// reclassifying an unrecognized deny as malformed would strip the only
		// actionable diagnostic from a legitimate, authenticated denial. Canonical
		// means the producer's decimal-digit code grammar: ServerDenyError renders
		// its code into public error text, and the digit gate is what keeps a
		// buggy authenticated producer from reflecting credentials through that
		// channel, so free-form values stay behind the redacting malformed
		// classification below.
		if !isCanonicalKnockDenyCode(ack.ErrCode.Value) {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock ACK errCode")
		}
		return nil, &ServerDenyError{ErrCode: ack.ErrCode.Value}
	}
	for _, required := range []struct {
		name    string
		present bool
	}{
		{"resHost", ack.ResourceHost.Present},
		{"sessId", ack.SessionID.Present},
		{"opnTime", ack.OpenTime.Present},
		{"agentAddr", ack.AgentAddr.Present},
		{"acTokens", ack.ACTokens.Present},
	} {
		if !required.present {
			return nil, fmt.Errorf("%w: native knock ACK field %s is missing", ErrMalformedReply, required.name)
		}
	}
	if ack.SessionID.Value == 0 {
		return nil, fmt.Errorf("%w: success ACK carried a zero NHP session id", ErrMalformedReply)
	}
	if ack.OpenTime.Value == 0 {
		return nil, fmt.Errorf("%w: success ACK carried an invalid open time", ErrMalformedReply)
	}
	if ack.PreAccessActions.RequiresAction {
		return nil, fmt.Errorf("%w: native knock ACK requires an unsupported pre-access action", ErrMalformedReply)
	}
	token := ack.ACTokens.Value[knockResourceID]
	host := ack.ResourceHost.Value[knockResourceID]
	if token == "" || host == "" || token != strings.TrimSpace(token) || host != strings.TrimSpace(host) {
		return nil, fmt.Errorf("%w: success ACK missing canonical token or resource host for requested resource", ErrMalformedReply)
	}
	result := &NativeKnockResult{ACToken: token, ResourceHost: host, OpenTime: ack.OpenTime.Value, SessionID: ack.SessionID.Value, AgentAddr: ack.AgentAddr.Value}
	if len(expectations) > 1 {
		return nil, fmt.Errorf("%w: multiple native knock expectations", ErrMalformedReply)
	}
	if len(expectations) == 1 {
		expected := expectations[0]
		if !ack.CellID.Present || !ack.SessionIssuedAtMillis.Present || !ack.RunID.Present || !ack.RunAttempt.Present ||
			ack.CellID.Value != expected.CellID || ack.CellID.Value == "" || ack.SessionIssuedAtMillis.Value <= 0 ||
			ack.RunID.Value != expected.RunID || ack.RunAttempt.Value != expected.RunAttempt || expected.RunAttempt == 0 {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native knock ACK session receipt")
		}
		result.SessionReceipt = NativeSessionReceipt{
			CellID: ack.CellID.Value, SessionID: ack.SessionID.Value,
			SessionIssuedAtMillis: ack.SessionIssuedAtMillis.Value,
			RunID:                 ack.RunID.Value, RunAttempt: ack.RunAttempt.Value,
		}
	}
	return result, nil
}

// isCanonicalKnockDenyCode reports whether a non-success knock-ACK errCode is
// in the producer's decimal-digit code grammar. Every legal NHP deny code is a
// digit string, and digit strings cannot embed reflected credentials, so this
// is a grammar gate, not an allowlist: codes the SDK has never seen still
// classify as authenticated denies.
func isCanonicalKnockDenyCode(code string) bool {
	if code == "" {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

func consumeNativeAgentKnockReply(reply *relayknock.Reply, knockResourceID string,
	expectations ...nativeAgentKnockExpectation,
) (*NativeKnockResult, error) {
	if reply != nil {
		defer wipeBytes(reply.Body)
	}
	return interpretNativeAgentKnockReply(reply, knockResourceID, expectations...)
}

func consumeNativeExactSessionCloseReply(reply *relayknock.Reply,
	receipt NativeSessionReceipt,
) (*NativeSessionRetirement, error) {
	if reply != nil {
		defer wipeBytes(reply.Body)
	}
	if reply == nil || !reply.IsACK() {
		return nil, fmt.Errorf("%w: missing exact session retirement ACK", ErrMalformedReply)
	}
	if err := rejectDuplicateJSONFields(reply.Body); err != nil {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "exact session retirement ACK")
	}
	var ack *nativeExactSessionCloseACK
	if err := strictDecodeJSON(reply.Body, &ack); err != nil || ack == nil || !ack.ErrCode.Present {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "exact session retirement ACK")
	}
	if !isSuccessErrCode(ack.ErrCode.Value) {
		if ack.CellID.Present || ack.SessionID.Present || ack.SessionIssuedAtMillis.Present ||
			ack.RunID.Present || ack.RunAttempt.Present || ack.CloseEventID.Present || ack.State.Present ||
			!isCanonicalKnockDenyCode(ack.ErrCode.Value) {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "exact session retirement deny ACK")
		}
		return nil, &ServerDenyError{ErrCode: ack.ErrCode.Value}
	}
	if !ack.CellID.Present || !ack.SessionID.Present || !ack.SessionIssuedAtMillis.Present ||
		!ack.RunID.Present || !ack.RunAttempt.Present || !ack.CloseEventID.Present || !ack.State.Present ||
		ack.CellID.Value != receipt.CellID || ack.SessionID.Value != receipt.SessionID ||
		ack.SessionIssuedAtMillis.Value != receipt.SessionIssuedAtMillis || ack.RunID.Value != receipt.RunID ||
		ack.RunAttempt.Value != receipt.RunAttempt || !validNativeCloseEventID(ack.CloseEventID.Value) ||
		(ack.State.Value != "closing" && ack.State.Value != "closed") {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "exact session retirement success ACK")
	}
	return &NativeSessionRetirement{SessionReceipt: receipt, CloseEventID: ack.CloseEventID.Value, State: ack.State.Value}, nil
}

func validNativeCloseEventID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

// RefreshAgentRuntime refreshes a completed binding only through the pinned Hub
// using the registered Noise identity and final agent id. It sends no enrollment
// or device credential and performs no public HTTP request.
//
// If LayerV has moved the agent to another cell or generation, this call follows
// the move and persists it, so a relocation is indistinguishable from an ordinary
// lease renewal and needs no code change. Placement is still taken only from this
// call's freshly authenticated Hub result, the assignment generation must strictly
// advance, and the endpoint must sit below a LayerV-owned apex with a live lease —
// a replayed or rolled-back placement is rejected, not adopted. Pass
// WithAgentRuntimePinnedAssignment to fail closed on a move instead.
func RefreshAgentRuntime(ctx context.Context, hub HubBootstrap, store AgentStateStore, opts ...AgentRuntimeRefreshOption) (*Client, *AgentRuntimeBinding, error) {
	cfg, hub, err := newAgentRuntimeRefreshConfig(ctx, hub, store, opts)
	if err != nil {
		return nil, nil, err
	}
	result, err := refreshAgentRuntimeLocked(ctx, hub, store, cfg)
	if err != nil {
		return nil, nil, err
	}
	return result.split()
}

// newAgentRuntimeRefreshConfig validates the shared refresh inputs and resolves
// the effective Hub.
func newAgentRuntimeRefreshConfig(ctx context.Context, hub HubBootstrap, store AgentStateStore, opts []AgentRuntimeRefreshOption) (*nativeAgentRuntimeConfig, HubBootstrap, error) {
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, hub, err
	}
	if store == nil {
		return nil, hub, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	cfg := defaultNativeAgentRuntimeConfig()
	// A zero-value hub means "use the deployment's trust root" — QURL_DEPLOYMENT
	// today, embedded in GA builds later — matching ConnectAgentRuntime. Refresh
	// otherwise forced every caller to carry the host, port, and key around
	// purely to hand them back on renewal.
	if hub == (HubBootstrap{}) {
		shipped, err := deploymentHub()
		if err != nil {
			return nil, hub, fmt.Errorf("%w: %w", ErrInvalidRegisterConfig, err)
		}
		hub = *shipped
	}
	cfg.hub = &hub
	for _, opt := range opts {
		if opt == nil {
			return nil, hub, fmt.Errorf("%w: nil runtime option", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(cfg); err != nil {
			return nil, hub, err
		}
	}
	if _, err := hub.nativeEndpoint(); err != nil {
		return nil, hub, fmt.Errorf("%w: Hub trust root: %w", ErrInvalidRegisterConfig, err)
	}
	return cfg, hub, nil
}

func refreshAgentRuntimeLocked(ctx context.Context, hub HubBootstrap, store AgentStateStore, cfg *nativeAgentRuntimeConfig) (*nativeRuntimeResult, error) {
	return withAgentSetupLock(ctx, store, destroyNativeRuntimeResult, func(lockedCtx context.Context, locked AgentStateStore) (*nativeRuntimeResult, error) {
		cfg.continuityStore = locked
		defer func() { cfg.continuityStore = nil }()
		state, err := loadCompletedRegisteredState(lockedCtx, locked, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}
		return cfg.renewCompletedAssignment(lockedCtx, hub, locked, state)
	})
}

// renewCompletedAssignment refreshes a completed registration's assignment
// through the Hub and persists the result before finishing the runtime. It runs
// only with the setup lock held. Every entry point that can meet an expired
// lease on already-completed state routes through here — explicit refresh and
// every online ConnectAgentRuntime start — so none of them can drift on trust
// root, move adoption, or persistence ordering.
func (c *nativeAgentRuntimeConfig) renewCompletedAssignment(ctx context.Context, hub HubBootstrap, locked AgentStateStore, state *AgentState) (*nativeRuntimeResult, error) {
	if state.Assignment == nil {
		return nil, fmt.Errorf("%w: completed state has no assignment", ErrInvalidRegisterConfig)
	}
	// Run the completed-state guards finishNativeRuntime would apply before any
	// packet leaves. A caller-asserted identity that does not match the persisted
	// one, or a corrupt device credential, must fail closed rather than spend a
	// Hub exchange first. These are the same checks, only earlier, so no path
	// that used to succeed changes.
	if err := validateCompletedAgentIdentity(state, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	if err := reconcileNativeAgentIdentity(state, c.agentID); err != nil {
		return nil, err
	}
	if err := validatePersistedNativeDeviceCredential(state, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(privateKey)
	fresh, err := c.refreshAssignmentLifecycle(ctx, hub, state.AgentID, privateKey)
	if err != nil {
		return nil, err
	}
	if err := ensureRefreshAssignmentContinuity(state.Assignment, fresh, !c.pinAssignment); err != nil {
		return nil, err
	}
	if !sameAgentAssignment(state.Assignment, fresh) {
		candidate := state.clone()
		candidate.Assignment = fresh.clone()
		if err := locked.SaveAgentState(ctx, candidate); err != nil {
			return nil, fmt.Errorf("%w: save refreshed assignment: %w", ErrAgentBindingPersistence, err)
		}
		state = candidate
	}
	return finishNativeRuntimeResult(locked, state, c)
}
