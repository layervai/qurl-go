package qurl

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RegisterAgentRuntime performs the qURL Connector's UDP-only enrollment
// lifecycle: Hub assignment, optional assigned-cell OTP, assigned-cell REG/RAK,
// and assigned-cell completion LST/LRT. It never calls a public enrollment,
// assignment, or completion HTTP endpoint. WithAgentRuntimeHub is required;
// only options explicitly documented for this runtime are accepted.
//
// The setup lock spans every incomplete-state transition. After RAK the SDK
// durably persists one pending device-secret candidate before sending completion,
// so a crash or lost LRT reuses the same candidate and cannot mint a second
// credential. A completed warm open should normally call
// OpenRegisteredAgentRuntime, which performs no network I/O. Both warm-open
// paths require a live assignment lease; after expiry, call RefreshAgentRuntime
// instead of expecting RegisterAgentRuntime to return the completed binding.
func RegisterAgentRuntime(ctx context.Context, enrollmentCredential string, store AgentStateStore, opts ...AgentRuntimeRegistrationOption) (*Client, *AgentRuntimeBinding, error) {
	return registerNativeAgentRuntime(ctx, enrollmentCredential, store, opts)
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

// newStoreBackedClient returns a Client authorized by the device API key
// persisted in store. Construction makes no qURL API calls; loading a
// network-backed store can still perform I/O on the first resource request.
func newStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer) *Client {
	return newStoreBackedClientWithCredential(store, baseURL, httpClient, "", time.Now)
}

// newPrimedStoreBackedClient is deliberately infallible after callers validate
// the exact credential as part of their pre-commit state/completion contract.
// Keeping construction infallible prevents a committed lifecycle mutation from
// acquiring a new post-commit error tail merely while materializing its Client.
func newPrimedStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer, validatedDeviceAPIKey string, now func() time.Time) *Client {
	return newStoreBackedClientWithCredential(store, baseURL, httpClient, validatedDeviceAPIKey, now)
}

// newStoreBackedClientWithCredential optionally primes the one-minute cache from
// an already validated AgentState so a combined runtime open does not unseal or
// reload the same store on its first resource request. The wrapped store provider
// remains authoritative after the cache expires.
func newStoreBackedClientWithCredential(store AgentStateStore, baseURL string, httpClient HTTPDoer, deviceAPIKey string, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	provider := &cachedCredentialProvider{
		provider: &storeCredentialProvider{store: store},
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
	store AgentStateStore
}

func (p *storeCredentialProvider) Authorize(ctx context.Context, req *http.Request) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("%w: credential store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	state, err := p.store.LoadAgentState(ctx)
	if err != nil {
		return fmt.Errorf("qurl: load device credential for authorization: %w", err)
	}
	if state == nil {
		return fmt.Errorf("%w: agent state store returned no state", ErrDeviceCredentialMissing)
	}
	if err := validatePersistedCredentialForState(state, ErrInvalidClientConfig); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+state.DeviceAPIKey)
	return nil
}

// AgentResourceClientOption configures the steady-state HTTPS resource Client
// returned by native registration/refresh or opened from completed state. These
// options never configure Hub, assigned-cell, enrollment, or relay transport.
type AgentResourceClientOption interface {
	ClientOption
	AgentRuntimeLifecycleOption
}

// RegistrationKeyKind is the credential class reported by an authenticated Hub
// assignment. Callers can restrict enrollment before OTP dispatch or REG.
type RegistrationKeyKind string

const (
	// RegistrationKeyKindBootstrap is a pre-issued headless enrollment key.
	RegistrationKeyKindBootstrap RegistrationKeyKind = keyKindBootstrap
	// RegistrationKeyKindConnectorBootstrap is a Connector-specific pre-issued
	// headless enrollment key.
	RegistrationKeyKindConnectorBootstrap RegistrationKeyKind = assignmentKeyKindConnectorBootstrap
	// RegistrationKeyKindAgent is a durable qurl:agent-scoped enrollment key.
	RegistrationKeyKindAgent RegistrationKeyKind = assignmentKeyKindAgent
	// RegistrationKeyKindAccount is an account API key requiring assigned-cell OTP.
	RegistrationKeyKindAccount RegistrationKeyKind = keyKindAccount
)

// WithAgentClientBaseURL points only the completed agent's steady-state resource
// Client at a non-default API origin. It is accepted by OpenRegisteredAgent,
// OpenRegisteredAgentRuntime, RegisterAgentRuntime, and RefreshAgentRuntime.
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
