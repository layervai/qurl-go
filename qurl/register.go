package qurl

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ConnectAgentRuntime is the single call a service makes on every start. It
// enrolls when there is nothing registered yet and an enrollment credential is
// available, resumes an interrupted enrollment, and otherwise returns the
// existing registration — renewing an expired lease and following any relocation
// on the way. A process does not need to know which of those happened.
//
// Supply the credential with WithAgentRuntimeEnrollmentCredential when this
// process is the one that enrolls, or use
// WithAgentRuntimeEnrollmentCredentialProvider when the credential must be
// minted lazily for the durable agent identity. Omit both when enrollment
// happens elsewhere, such as an installer: without a credential this call can
// renew and serve an existing registration but can never create one, which is
// the property a service that deliberately holds no enrollment secret wants.
// Pass WithAgentRuntimeOfflineOpen to additionally forbid renewal, so the call
// performs no network I/O at all.
//
// The lifecycle is UDP-only: Hub assignment, assigned-cell OTP, assigned-cell
// REG/RAK, and assigned-cell completion LST/LRT. It never calls a public
// enrollment, assignment, or completion HTTP endpoint. Only options explicitly
// documented for this runtime are accepted.
//
// Enrollment defaults to the one-time code, so a call that may enroll installs
// WithAgentRuntimeOTPProvider. The OTP leg is skipped only for a runtime that
// declares it cannot receive a code with WithAgentRuntimeHeadlessEnrollment.
// The Hub trust root comes from the deployment: the file named by
// QURL_DEPLOYMENT today, embedded in GA builds later. Callers running their
// own LayerV deployment pass WithAgentRuntimeHub here (RefreshAgentRuntime
// takes a HubBootstrap argument instead). A deployment that names no hub can
// still serve an existing registration whose lease is live, but any start that
// actually needs a Hub exchange fails with ErrNoDeploymentHub — reliably that
// sentinel, because a QURL_DEPLOYMENT file that cannot be read or parsed is
// instead rejected as a config error on every start — until QURL_DEPLOYMENT
// names a deployment with a "hub" or WithAgentRuntimeHub is passed.
//
// The setup lock spans every incomplete-state transition. After RAK the SDK
// durably persists one pending device-secret candidate before sending completion,
// so a crash or lost LRT reuses the same candidate and cannot mint a second
// credential. A completed registration whose lease is live is returned with one
// store load, no lock, and no packet, so this call is safe and cheap on every
// start. Such a warm open needs no Hub trust root; with none resolvable the
// binding completes the open but cannot renew its own lease, deliberately
// matching the old Open contract.
func ConnectAgentRuntime(ctx context.Context, store AgentStateStore, opts ...AgentRuntimeRegistrationOption) (*Client, *AgentRuntimeBinding, error) {
	return registerNativeAgentRuntime(ctx, store, opts)
}

// WithAgentRuntimeEnrollmentCredential supplies the credential LayerV issued for
// first-time enrollment. It is used only when nothing is registered yet; a start
// that finds an existing registration ignores it and sends no credential to the
// Hub.
// The credential is deliberately not validated here. A start that finds an
// existing registration never looks at it, so a service that keeps calling with
// a credential that has since rotated or expired must keep starting cleanly.
// Validation happens where the credential is actually used: an enrolling start
// requires a server-minted encoded token whose total string length, including
// any prefix, is at least 32 bytes. User-chosen passwords are not valid
// enrollment credentials; the SDK enforces syntax and this length floor, while
// the minting authority must guarantee cryptographic randomness.
func WithAgentRuntimeEnrollmentCredential(credential string) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.enrollCredential = credential
		c.enrollCredentialSet = true
		return nil
	})
}

// AgentEnrollmentCredentialRequest is the bounded, non-secret context passed
// to an AgentEnrollmentCredentialProvider. AgentID is already durable in the
// AgentStateStore before the provider is called, so it is safe to use as the
// stable target of an idempotent enrollment-token mint.
type AgentEnrollmentCredentialRequest struct {
	AgentID string
	// PendingActivationRecovery is true when an earlier assigned-cell REG has
	// an ambiguous outcome. The provider must recover the exact credential used
	// for that activation, for example by replaying the original idempotent mint;
	// returning a newly minted credential fails the persisted fingerprint check.
	// False means only that the SDK has no pending REG: an earlier provider mint
	// may still have committed before its result reached the SDK.
	PendingActivationRecovery bool
}

// AgentEnrollmentCredentialProvider lazily returns a first-time enrollment
// credential for a durable agent identity. The callback must honor ctx and make
// every mint idempotent against its own durable or deterministically derived,
// non-secret transaction identity.
// A process or provider failure can happen after the authority commits a mint
// but before the SDK creates pending activation, so PendingActivationRecovery
// being false does not authorize a fresh mint. When it is true, replay must also
// return the exact credential whose fingerprint is already persisted.
type AgentEnrollmentCredentialProvider func(context.Context, AgentEnrollmentCredentialRequest) (string, error)

// WithAgentRuntimeEnrollmentCredentialProvider supplies enrollment capability
// lazily. ConnectAgentRuntime calls provider exactly once while holding the
// AgentStateStore setup lock, and only for a fresh enrollment or pending-
// activation recovery that has no explicit credential. It first generates and
// durably saves AgentEnrollmentCredentialRequest.AgentID. Completed state,
// pending completion, lease renewal, and offline open never invoke it.
//
// A pending activation stores only the credential fingerprint, never the raw
// credential. The provider must therefore replay the original idempotent mint
// and return the same credential during recovery. The returned credential is
// attempt-scoped and is not retained by the binding used for later renewals.
// Persist or deterministically derive the non-secret mint identity before
// contacting its authority, and reuse it on every callback until enrollment is
// known complete; never persist the raw credential in AgentStateStore.
//
// This option cannot be combined with WithAgentRuntimeEnrollmentCredential,
// WithAgentRuntimeOTPProvider, or WithAgentRuntimeOfflineOpen. A provider for a
// one-shot bootstrap token normally pairs this option with
// WithAgentRuntimeHeadlessEnrollment.
func WithAgentRuntimeEnrollmentCredentialProvider(provider AgentEnrollmentCredentialProvider) AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		if provider == nil {
			return fmt.Errorf("%w: enrollment credential provider must not be nil", ErrInvalidRegisterConfig)
		}
		c.enrollCredentialProvider = provider
		return nil
	})
}

func validateAgentRuntimeMetadata(state *AgentState, now time.Time, errKind error) error {
	if state == nil || state.Assignment == nil {
		return fmt.Errorf("%w: agent runtime state missing native assignment", errKind)
	}
	if err := state.Assignment.Validate(now); err != nil {
		return fmt.Errorf("%w: agent runtime assignment: %w", errKind, err)
	}
	return nil
}

// newPrimedStoreBackedClient is deliberately infallible after callers validate
// the exact credential as part of their pre-commit state/completion contract.
// Keeping construction infallible prevents a committed lifecycle mutation from
// acquiring a new post-commit error tail merely while materializing its Client.
func newPrimedStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer, validatedDeviceAPIKey, expectedAgentID string, now func() time.Time) *Client {
	return newStoreBackedClientWithCredential(store, baseURL, httpClient, validatedDeviceAPIKey, expectedAgentID, now)
}

// newStoreBackedClientWithCredential optionally primes the one-minute cache from
// an already validated AgentState so a combined runtime open does not unseal or
// reload the same store on its first resource request. The wrapped store provider
// remains authoritative after the cache expires.
func newStoreBackedClientWithCredential(store AgentStateStore, baseURL string, httpClient HTTPDoer, deviceAPIKey, expectedAgentID string, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	provider := &cachedCredentialProvider{
		provider: &storeCredentialProvider{store: store, expectedAgentID: expectedAgentID},
		ttl:      storeCredentialCacheTTL,
		now:      now,
	}
	if deviceAPIKey != "" {
		provider.authorization = "Bearer " + deviceAPIKey
		provider.expiresAt = provider.now().Add(provider.ttl)
	}
	return &Client{
		credentials: provider,
		baseURL:     baseURL,
		httpClient:  httpClient,
	}
}

// storeCredentialCacheTTL bounds how long a device API key read from the store
// is reused before being re-read, so a server-side revocation or explicit
// NHP-native replacement is observed promptly.
const storeCredentialCacheTTL = time.Minute

// storeCredentialProvider authorizes steady-state resource requests with the
// completed device credential in AgentStateStore. It is not an enrollment,
// assignment, completion, refresh, or knock transport.
type storeCredentialProvider struct {
	store           AgentStateStore
	expectedAgentID string
}

func (p *storeCredentialProvider) Authorize(ctx context.Context, req *http.Request) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("%w: credential store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	state, err := p.store.LoadAgentState(ctx)
	if state != nil {
		defer clearOwnedAgentState(state)
	}
	if err != nil {
		return fmt.Errorf("qurl: load device credential for authorization: %w", err)
	}
	if state == nil {
		return fmt.Errorf("%w: agent state store returned no state", ErrDeviceCredentialMissing)
	}
	if err := validatePersistedCredentialForState(state, ErrInvalidClientConfig); err != nil {
		return err
	}
	if state.AgentID != p.expectedAgentID {
		return fmt.Errorf("%w: agent state identity changed after client open", ErrInvalidClientConfig)
	}
	req.Header.Set("Authorization", "Bearer "+state.DeviceAPIKey)
	return nil
}

// AgentResourceClientOption configures the steady-state HTTPS resource Client
// returned by native registration, refresh, explicit credential recovery, or
// opened from completed state. These options never configure Hub, assigned-cell,
// enrollment, recovery, or relay lifecycle transport.
type AgentResourceClientOption interface {
	ClientOption
	AgentRuntimeLifecycleOption
}

// RegistrationKeyKind is the credential class reported by an authenticated Hub
// assignment. Callers can restrict enrollment before OTP dispatch or REG.
// RegistrationKeyKindAccount is the default; the one-shot enrollment token
// kinds are reached through WithAgentRuntimeHeadlessEnrollment.
type RegistrationKeyKind string

const (
	// RegistrationKeyKindBootstrap is a pre-issued headless enrollment key. It
	// carries its own proof and needs no one-time code.
	RegistrationKeyKindBootstrap RegistrationKeyKind = keyKindBootstrap
	// RegistrationKeyKindConnectorBootstrap is a Connector-specific pre-issued
	// headless enrollment key.
	RegistrationKeyKindConnectorBootstrap RegistrationKeyKind = assignmentKeyKindConnectorBootstrap
	// RegistrationKeyKindAgent is the retired durable qurl:agent-scoped
	// enrollment key kind. The platform no longer mints keys that classify as
	// it, and no default enrollment path admits it; the wire token stays
	// reserved so retirement is reversible without a protocol change. New
	// integrations mint a one-shot enrollment token and enroll with
	// WithAgentRuntimeHeadlessEnrollment. A legacy key
	// can still be admitted explicitly through
	// WithAgentRuntimeAllowedRegistrationKeyKinds.
	RegistrationKeyKindAgent RegistrationKeyKind = assignmentKeyKindAgent
	// RegistrationKeyKindAccount enrolls with an assigned-cell one-time code sent
	// to the credential's address. It is the default enrollment kind, and it is
	// not specific to a human enrolling: any runtime that can read a mailbox uses
	// it.
	RegistrationKeyKindAccount RegistrationKeyKind = keyKindAccount
)

// WithAgentClientBaseURL points only the completed agent's steady-state resource
// Client at a non-default API origin. It is accepted by ConnectAgentRuntime,
// OpenRegisteredAgent, OpenRegisteredAgentWithIdentity, RefreshAgentRuntime,
// and RecoverAgentRuntime.
func WithAgentClientBaseURL(rawURL string) AgentResourceClientOption {
	return agentClientBaseURLOption(rawURL)
}

type agentClientBaseURLOption string

func validateAgentClientBaseURL(rawURL string, errKind error) (string, error) {
	if err := validateHTTPSOrLoopbackURL(rawURL, "agent client base URL", errKind); err != nil {
		return "", err
	}
	return strings.TrimRight(rawURL, "/"), nil
}

func (o agentClientBaseURLOption) applyClientOption(cfg *clientOptions) error {
	normalized, err := validateAgentClientBaseURL(string(o), ErrInvalidClientConfig)
	if err != nil {
		return err
	}
	if err := claimClientOptionSource(&cfg.baseURLSource, clientOptionSourceAgent, "WithBaseURL", "WithAgentClientBaseURL"); err != nil {
		return err
	}
	cfg.baseURL = normalized
	return nil
}

func (o agentClientBaseURLOption) applyAgentRuntimeOption(cfg *nativeAgentRuntimeConfig) error {
	normalized, err := validateAgentClientBaseURL(string(o), ErrInvalidRegisterConfig)
	if err != nil {
		return err
	}
	cfg.baseURL = normalized
	return nil
}

func (agentClientBaseURLOption) isAgentRuntimeRegistrationOption() {}
func (agentClientBaseURLOption) isAgentRuntimeRefreshOption()      {}
func (agentClientBaseURLOption) isAgentRuntimeRecoveryOption()     {}

// WithAgentClientHTTPClient injects only the completed agent's steady-state
// resource Client transport. Native lifecycle UDP never uses this HTTP client.
func WithAgentClientHTTPClient(client HTTPDoer) AgentResourceClientOption {
	return agentClientHTTPClientOption{client: client}
}

type agentClientHTTPClientOption struct {
	client HTTPDoer
}

func (o agentClientHTTPClientOption) applyClientOption(cfg *clientOptions) error {
	if o.client == nil {
		return fmt.Errorf("%w: agent Client HTTP client must not be nil", ErrInvalidClientConfig)
	}
	if err := claimClientOptionSource(&cfg.httpClientSource, clientOptionSourceAgent, "WithHTTPClient", "WithAgentClientHTTPClient"); err != nil {
		return err
	}
	cfg.httpClient = o.client
	return nil
}

func (o agentClientHTTPClientOption) applyAgentRuntimeOption(cfg *nativeAgentRuntimeConfig) error {
	if o.client == nil {
		return fmt.Errorf("%w: agent Client HTTP client must not be nil", ErrInvalidRegisterConfig)
	}
	cfg.httpClient = o.client
	return nil
}

func (agentClientHTTPClientOption) isAgentRuntimeRegistrationOption() {}
func (agentClientHTTPClientOption) isAgentRuntimeRefreshOption()      {}
func (agentClientHTTPClientOption) isAgentRuntimeRecoveryOption()     {}
