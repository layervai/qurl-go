package qurl

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultAPIBaseURL        = "https://api.layerv.ai"
	defaultAPIHTTPTimeout    = 30 * time.Second
	maxAPIResponseBodyBytes  = 1 << 20
	maxAPIResponseDrainBytes = 512 << 10
	maxAPIErrorSnippetBytes  = 512
)

var defaultAPIHTTPClient = &http.Client{
	Timeout:       defaultAPIHTTPTimeout,
	CheckRedirect: refuseRedirects,
}

func refuseRedirects(_ *http.Request, _ []*http.Request) error {
	// Return 3xx responses to the caller as APIError values instead of
	// forwarding credentials to a different URL.
	return http.ErrUseLastResponse
}

// DefaultIssuerStatePath is the default local LayerV credential path used by
// OpenClient. Most applications should call OpenClient rather than reading this
// file directly.
const DefaultIssuerStatePath = "/var/lib/layerv/qurl/issuer-state.json"

// ErrInvalidClientConfig is returned when a Client cannot be configured.
var ErrInvalidClientConfig = errors.New("qurl: invalid client config")

// ErrInvalidResourceRequest is returned before an API request when a resource
// input is invalid.
var ErrInvalidResourceRequest = errors.New("qurl: invalid resource request")

// ErrInvalidAPIResponse is returned when a successful LayerV API response is
// empty, cannot be decoded, or violates an endpoint response contract.
// Endpoint-specific methods may wrap this with a narrower response-contract
// sentinel.
var ErrInvalidAPIResponse = errors.New("qurl: invalid API response")

// ErrInvalidPortalRequest is returned before an API request when a portal input
// is invalid.
var ErrInvalidPortalRequest = errors.New("qurl: invalid portal request")

// ErrCredentialStateNotFound is returned when FileCredentials cannot find the
// LayerV credential file.
var ErrCredentialStateNotFound = errors.New("qurl: credential state not found")

// ErrInsecureCredentialStatePermissions is returned when file-backed issuer
// credentials are readable by group or other users.
var ErrInsecureCredentialStatePermissions = errors.New("qurl: insecure credential state permissions")

// CredentialProvider authorizes Client requests.
//
// Implement this interface with credentials loaded from protected local state,
// KMS, or a secret manager. Authorize may be called for a local validation
// request that is never sent, such as OpenClientContext's startup check, so
// providers should avoid spending one-time credentials merely because Authorize
// was invoked.
type CredentialProvider interface {
	Authorize(context.Context, *http.Request) error
}

// CredentialProviderFunc adapts a function into a CredentialProvider.
type CredentialProviderFunc func(context.Context, *http.Request) error

// Authorize calls f.
func (f CredentialProviderFunc) Authorize(ctx context.Context, req *http.Request) error {
	if f == nil {
		return fmt.Errorf("%w: nil credential provider", ErrInvalidClientConfig)
	}
	return f(ctx, req)
}

type bearerTokenCredential string

func (c bearerTokenCredential) Authorize(_ context.Context, req *http.Request) error {
	return setBearer(req, string(c))
}

// BearerToken returns a CredentialProvider backed by one bearer token.
//
// It is useful for tests and controlled tooling that already received a LayerV
// bearer credential from a protected credential path. The token is stored as a
// Go string; production services should prefer OpenClient, FileCredentials, or
// a custom provider that loads credentials from protected state.
func BearerToken(token string) CredentialProvider {
	return bearerTokenCredential(token)
}

type fileCredentialProvider struct {
	path string
}

// FileCredentials reads LayerV issuer credentials from path on every request so
// rotated local credentials are picked up without rebuilding the client. Most
// applications should use OpenClient; use FileCredentials only when wiring a
// custom runtime path. High-throughput callers that rarely rotate credentials
// can wrap it with CachedCredentials. The default favors hot-reload
// correctness over syscall minimization. The context passed to Authorize cannot
// interrupt local filesystem I/O after it has started. If the state file
// contains an "authorization" field, its value is trusted as the raw
// Authorization header.
func FileCredentials(path string) CredentialProvider {
	return fileCredentialProvider{path: path}
}

// CachedCredentials caches a reusable Authorization header produced by provider
// for ttl. It is meant for FileCredentials and other providers whose
// Authorization value is reusable across requests. Do not wrap providers that
// sign request-specific fields or set non-Authorization headers; those providers
// should run on every request. Failed refreshes are not cached; if a provider
// keeps failing, later callers retry rather than reusing a stale error, and
// callers that were waiting on a failed refresh may each attempt the next
// refresh until one succeeds. The usual production shape is
// CachedCredentials(FileCredentials(path), ttl).
func CachedCredentials(provider CredentialProvider, ttl time.Duration) CredentialProvider {
	return newCachedCredentials(provider, ttl, time.Now)
}

func newCachedCredentials(provider CredentialProvider, ttl time.Duration, now func() time.Time) CredentialProvider {
	if now == nil {
		now = time.Now
	}
	return &cachedCredentialProvider{
		provider: provider,
		ttl:      ttl,
		now:      now,
	}
}

type cachedCredentialProvider struct {
	provider CredentialProvider
	ttl      time.Duration
	now      func() time.Time

	mu            sync.Mutex
	authorization string
	expiresAt     time.Time
	refreshDone   chan struct{}
}

func (p *cachedCredentialProvider) Authorize(ctx context.Context, req *http.Request) error {
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	if req == nil {
		return fmt.Errorf("%w: request must not be nil", ErrInvalidClientConfig)
	}
	if p.provider == nil {
		return fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}
	if p.ttl <= 0 {
		return fmt.Errorf("%w: credential cache ttl must be positive", ErrInvalidClientConfig)
	}

	for {
		now := p.now()
		p.mu.Lock()
		if p.authorization != "" && now.Before(p.expiresAt) {
			req.Header.Set("Authorization", p.authorization)
			p.mu.Unlock()
			return nil
		}
		if p.refreshDone == nil {
			p.refreshDone = make(chan struct{})
			p.mu.Unlock()
			return p.refresh(ctx, req)
		}
		done := p.refreshDone
		p.mu.Unlock()

		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *cachedCredentialProvider) refresh(ctx context.Context, req *http.Request) error {
	finished := false
	defer func() {
		if !finished {
			p.finishRefresh("", false)
		}
	}()
	if err := p.provider.Authorize(ctx, req); err != nil {
		return err
	}
	authorization := req.Header.Get("Authorization")
	if strings.TrimSpace(authorization) == "" {
		return fmt.Errorf("%w: cached credential provider did not set Authorization", ErrInvalidClientConfig)
	}
	if err := validateHeaderValue(authorization, "authorization header"); err != nil {
		return err
	}
	p.finishRefresh(authorization, true)
	finished = true
	return nil
}

func (p *cachedCredentialProvider) finishRefresh(authorization string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		// Set the expiry after the wrapped provider returns so slow refreshes do
		// not consume the caller's full TTL while I/O is in flight.
		p.authorization = authorization
		p.expiresAt = p.now().Add(p.ttl)
	}
	done := p.refreshDone
	p.refreshDone = nil
	if done != nil {
		close(done)
	}
}

func (p fileCredentialProvider) Authorize(ctx context.Context, req *http.Request) error {
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	raw, err := readPrivateStateFile(p.path, "credential state", ErrCredentialStateNotFound, ErrInvalidClientConfig, ErrInsecureCredentialStatePermissions)
	if err != nil {
		return err
	}
	var state credentialState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("qurl: decode credential state: %w", err)
	}
	return state.authorize(req)
}

type credentialState struct {
	Authorization string `json:"authorization,omitempty"`
	BearerToken   string `json:"bearer_token,omitempty"`
}

func (s credentialState) authorize(req *http.Request) error {
	authorization := strings.TrimSpace(s.Authorization)
	bearer := strings.TrimSpace(s.BearerToken)
	switch {
	case authorization != "" && bearer != "":
		return fmt.Errorf("%w: credential state has both authorization and bearer_token", ErrInvalidClientConfig)
	case authorization != "":
		if err := validateHeaderValue(authorization, "authorization header"); err != nil {
			return err
		}
		req.Header.Set("Authorization", authorization)
		return nil
	case bearer != "":
		return setBearer(req, bearer)
	default:
		return fmt.Errorf("%w: credential state cannot authorize requests", ErrInvalidClientConfig)
	}
}

func setBearer(req *http.Request, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: bearer token must not be empty", ErrInvalidClientConfig)
	}
	authorization := "Bearer " + token
	if err := validateHeaderValue(authorization, "bearer token"); err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	return nil
}

// validateExactBearerToken validates a credential without normalizing it. This
// is required for server-minted or dual-channel enrollment credentials: the
// exact bytes persisted or sent inside NHP must be the bytes authenticated over
// HTTPS, and an invalid value must never be silently repaired with TrimSpace.
func validateExactBearerToken(token, label string, errKind error) error {
	if token == "" {
		return fmt.Errorf("%w: %s must not be empty", errKind, label)
	}
	if token != strings.TrimSpace(token) {
		return fmt.Errorf("%w: %s must not contain surrounding whitespace", errKind, label)
	}
	// The token is carried verbatim in the Authorization header; the fixed
	// "Bearer " scheme prefix is all printable ASCII, so validating the raw token
	// bytes is equivalent to validating the assembled header value.
	return validateHeaderValueWithKind(token, label, errKind)
}

func validateHeaderValue(value, label string) error {
	return validateHeaderValueWithKind(value, label, ErrInvalidClientConfig)
}

func validateHeaderValueWithKind(value, label string, errKind error) error {
	for _, b := range []byte(value) {
		// Authorization credentials do not need HTAB or obs-text, so keep this
		// intentionally stricter than the generic HTTP header grammar.
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("%w: %s contains invalid header characters", errKind, label)
		}
	}
	return nil
}

// Client calls the LayerV qURL API. Protect a URL once with ProtectURL, then
// mint portals for that resource with Resource.CreatePortal.
type Client struct {
	credentials CredentialProvider
	baseURL     string
	httpClient  HTTPDoer
}

// ClientOption customizes a Client.
type ClientOption interface {
	applyClientOption(*clientOptions) error
}

type clientOptionFunc func(*clientOptions) error

func (f clientOptionFunc) applyClientOption(o *clientOptions) error {
	return f(o)
}

type clientOptions struct {
	baseURL          string
	httpClient       HTTPDoer
	issuerStatePath  string
	baseURLSource    clientOptionSource
	httpClientSource clientOptionSource
}

type clientOptionSource uint8

const (
	clientOptionSourceUnset clientOptionSource = iota
	clientOptionSourceGeneric
	clientOptionSourceAgent
)

func claimClientOptionSource(current *clientOptionSource, next clientOptionSource, genericName, agentName string) error {
	if *current != clientOptionSourceUnset && *current != next {
		return fmt.Errorf("%w: set only one of %s or %s", ErrInvalidClientConfig, genericName, agentName)
	}
	*current = next
	return nil
}

func applyClientOptions(opts []ClientOption) (clientOptions, error) {
	cfg := clientOptions{
		baseURL:    defaultAPIBaseURL,
		httpClient: defaultAPIHTTPClient,
	}
	for _, opt := range opts {
		if opt == nil {
			return clientOptions{}, fmt.Errorf("%w: nil ClientOption", ErrInvalidClientConfig)
		}
		if err := opt.applyClientOption(&cfg); err != nil {
			return clientOptions{}, err
		}
	}
	return cfg, nil
}

// WithBaseURL points the client at a non-default LayerV API origin. Most
// applications do not need this.
func WithBaseURL(rawURL string) ClientOption {
	return clientOptionFunc(func(o *clientOptions) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "base URL", ErrInvalidClientConfig); err != nil {
			return err
		}
		if err := claimClientOptionSource(&o.baseURLSource, clientOptionSourceGeneric, "WithBaseURL", "WithAgentClientBaseURL"); err != nil {
			return err
		}
		o.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithHTTPClient injects the HTTP client used for API requests. Without this
// option, the SDK uses a shared client with a 30-second timeout and no redirect
// following; injected clients own their own timeout and redirect behavior. Callers
// can still set shorter per-call deadlines on ctx.
func WithHTTPClient(client HTTPDoer) ClientOption {
	return clientOptionFunc(func(o *clientOptions) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidClientConfig)
		}
		if err := claimClientOptionSource(&o.httpClientSource, clientOptionSourceGeneric, "WithHTTPClient", "WithAgentClientHTTPClient"); err != nil {
			return err
		}
		o.httpClient = client
		return nil
	})
}

// WithIssuerStatePath makes OpenClient/OpenClientContext read LayerV issuer
// credentials from path while preserving their eager startup validation. Most
// applications should use the default state path created by LayerV setup.
func WithIssuerStatePath(path string) ClientOption {
	return clientOptionFunc(func(o *clientOptions) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%w: issuer state path must not be empty", ErrInvalidClientConfig)
		}
		o.issuerStatePath = path
		return nil
	})
}

// NewClient returns a qURL API client backed by a credential provider. It
// validates built-in bearer credentials immediately, but does not eagerly
// authorize arbitrary providers; custom provider errors surface on the request
// that uses them. Use OpenClientContext when startup code needs eager validation
// for LayerV's default file-backed issuer credential.
func NewClient(provider CredentialProvider, opts ...ClientOption) (*Client, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}
	cfg, err := applyClientOptions(opts)
	if err != nil {
		return nil, err
	}
	if cfg.issuerStatePath != "" {
		return nil, fmt.Errorf("%w: WithIssuerStatePath is only valid with OpenClient", ErrInvalidClientConfig)
	}
	if err := validateClientCredentialProvider(provider, cfg.baseURL); err != nil {
		return nil, err
	}
	return &Client{
		credentials: provider,
		baseURL:     cfg.baseURL,
		httpClient:  cfg.httpClient,
	}, nil
}

// OpenClient returns a qURL API client using the default LayerV credential.
// It eagerly checks that the local credential source can authorize a request;
// it does not call the LayerV API until the returned client is used. Use
// OpenClientContext when startup code needs to bound that eager check. Use
// WithIssuerStatePath only when LayerV setup wrote issuer state to a non-default
// path.
func OpenClient(opts ...ClientOption) (*Client, error) {
	return OpenClientContext(context.Background(), opts...)
}

// OpenClientContext is OpenClient with a context for the eager credential
// authorization check. The check authorizes a synthetic request that is never
// sent, so credential code should not spend one-time material during Authorize.
// File-backed credentials are read once for this startup check and then read
// again on each real request so local rotations are observed.
// For file-backed credentials, the context can cancel before the request is
// built or while custom credential code runs, but it cannot interrupt a local
// filesystem read once it has started.
func OpenClientContext(ctx context.Context, opts ...ClientOption) (*Client, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidClientConfig)
	}
	cfg, err := applyClientOptions(opts)
	if err != nil {
		return nil, err
	}
	statePath := DefaultIssuerStatePath
	if cfg.issuerStatePath != "" {
		statePath = cfg.issuerStatePath
	}
	provider := FileCredentials(statePath)
	client := &Client{
		credentials: provider,
		baseURL:     cfg.baseURL,
		httpClient:  cfg.httpClient,
	}
	if err := validateCredentials(ctx, provider, client.baseURL); err != nil {
		return nil, err
	}
	return client, nil
}

// Resource is a protected target registered in the LayerV qURL Platform. Fields
// are exported for inspection and JSON persistence; CreatePortal reads ID at
// call time, and JSON cannot preserve the unexported client binding. Use
// ResourceByID for a new handle instead of mutating or round-tripping a bound
// one.
type Resource struct {
	client *Client

	// ID is the protected-resource identifier returned by LayerV. Current
	// producers use a canonical unpadded-base64url DER SPKI public key; the
	// legacy Resource surface treats the value as opaque and does not validate
	// that format. ConnectorResource provides the strictly validated identity.
	ID string `json:"resource_id"`
	// TargetURL is the private URL protected by this resource.
	TargetURL string `json:"target_url"`
	// Status is the resource lifecycle status returned by LayerV.
	Status string `json:"status,omitempty"`
	// Description is optional resource-level metadata.
	Description string `json:"description,omitempty"`
	// Tags are optional resource-level metadata.
	Tags []string `json:"tags,omitempty"`
	// CustomDomain is set when this resource is bound to a verified domain.
	CustomDomain *string `json:"custom_domain,omitempty"`
	// Alias is an optional owner-scoped handle for the resource.
	Alias *string `json:"alias,omitempty"`
	// QURLCount is the number of active qURL links LayerV reports for the resource.
	QURLCount int `json:"qurl_count"`
	// CreatedAt is the server creation time, when returned by the API.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// ExpiresAt is the server expiration time, when returned by the API.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ResourceByID returns a resource handle bound to this client. Use it when you
// stored a LayerV resource id and want to mint more portals for it.
func (c *Client) ResourceByID(id string) *Resource {
	return &Resource{client: c, ID: id}
}

// ResourceOption customizes ProtectURL and CreateResource.
type ResourceOption interface {
	applyResourceOption(*resourceOptions) error
}

type resourceOptionFunc func(*resourceOptions) error

func (f resourceOptionFunc) applyResourceOption(o *resourceOptions) error {
	return f(o)
}

type resourceOptions struct {
	description  string
	tags         []string
	customDomain string
	alias        string
}

// WithDescription attaches resource-level metadata.
func WithDescription(description string) ResourceOption {
	return resourceOptionFunc(func(o *resourceOptions) error {
		if strings.TrimSpace(description) == "" {
			return fmt.Errorf("%w: description must not be empty", ErrInvalidResourceRequest)
		}
		o.description = description
		return nil
	})
}

// WithTags attaches resource-level tags.
func WithTags(tags ...string) ResourceOption {
	return resourceOptionFunc(func(o *resourceOptions) error {
		if len(tags) == 0 {
			return fmt.Errorf("%w: at least one tag is required", ErrInvalidResourceRequest)
		}
		for i, tag := range tags {
			if strings.TrimSpace(tag) == "" {
				return fmt.Errorf("%w: tag %d must not be empty", ErrInvalidResourceRequest, i)
			}
		}
		o.tags = slices.Clone(tags)
		return nil
	})
}

// WithCustomDomain binds the resource to a custom domain already verified in
// LayerV.
func WithCustomDomain(domain string) ResourceOption {
	return resourceOptionFunc(func(o *resourceOptions) error {
		if strings.TrimSpace(domain) == "" {
			return fmt.Errorf("%w: custom domain must not be empty", ErrInvalidResourceRequest)
		}
		o.customDomain = domain
		return nil
	})
}

// WithAlias assigns an owner-scoped handle to the resource.
func WithAlias(alias string) ResourceOption {
	return resourceOptionFunc(func(o *resourceOptions) error {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("%w: alias must not be empty", ErrInvalidResourceRequest)
		}
		o.alias = alias
		return nil
	})
}

// ProtectURL creates or reuses a LayerV resource for targetURL. The SDK rejects
// malformed URLs and embedded credentials; LayerV validates and registers the
// target when the request reaches the platform.
func (c *Client) ProtectURL(ctx context.Context, targetURL string, opts ...ResourceOption) (*Resource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTargetURL(targetURL, ErrInvalidResourceRequest); err != nil {
		return nil, err
	}

	var cfg resourceOptions
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil ResourceOption", ErrInvalidResourceRequest)
		}
		if err := opt.applyResourceOption(&cfg); err != nil {
			return nil, err
		}
	}

	reqBody := createResourceRequest{
		TargetURL:    targetURL,
		Description:  cfg.description,
		Tags:         cfg.tags,
		CustomDomain: cfg.customDomain,
		Alias:        cfg.alias,
	}

	var env apiEnvelope[createResourceResponse]
	if err := c.doJSON(ctx, http.MethodPost, "/v1/resources", reqBody, &env); err != nil {
		return nil, err
	}
	resource, err := env.Data.resource()
	if err != nil {
		return nil, err
	}
	resource.client = c
	return resource, nil
}

// CreateResource is the API-shaped alias for ProtectURL.
func (c *Client) CreateResource(ctx context.Context, targetURL string, opts ...ResourceOption) (*Resource, error) {
	return c.ProtectURL(ctx, targetURL, opts...)
}

// Portal is the qURL link returned by the LayerV qURL API.
type Portal struct {
	// ResourceID identifies the protected resource this link opens.
	ResourceID string
	// Link is the shareable qURL link.
	Link string
	// Site is the qURL-hosted site for this resource, when returned by the API.
	Site string
	// ExpiresAt is the link expiration time, when returned by the API.
	ExpiresAt *time.Time
	// QURLID identifies the specific access token, when returned by the API.
	QURLID string
	// Label is the token label, when returned by the API.
	Label string
}

// PortalOption customizes CreatePortal.
type PortalOption interface {
	applyPortalOption(*portalOptions) error
}

type portalOptionFunc func(*portalOptions) error

func (f portalOptionFunc) applyPortalOption(o *portalOptions) error {
	return f(o)
}

type portalOptions struct {
	expiresIn       string
	label           string
	oneTimeUse      *bool
	maxSessions     *int
	sessionDuration string
}

// ValidFor sets how long the qURL link should be valid. The SDK requires at
// least one minute as a client-side guardrail; the LayerV API remains the
// source of truth for account limits. There is intentionally no SDK-side maximum
// because an account may allow longer-lived portals. If omitted, the API applies
// its default lifetime. Values are serialized with hours as the largest unit so
// all API duration fields use the same h/m/s grammar.
func ValidFor(d time.Duration) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		expiresIn, err := formatAPIDuration(d, time.Minute)
		if err != nil {
			return err
		}
		o.expiresIn = expiresIn
		return nil
	})
}

// WithLabel attaches a human-readable label to the qURL link.
func WithLabel(label string) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		if strings.TrimSpace(label) == "" {
			return fmt.Errorf("%w: label must not be empty", ErrInvalidPortalRequest)
		}
		o.label = label
		return nil
	})
}

// OneTimeUse makes the qURL link expire after its first successful use.
func OneTimeUse() PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		v := true
		o.oneTimeUse = &v
		return nil
	})
}

// MaxSessions limits concurrent sessions for this qURL link. Use 0 for
// unlimited sessions; the SDK sends an explicit max_sessions:0, while omitting
// this option leaves the server default in effect. The LayerV API remains the
// source of truth for account limits.
func MaxSessions(n int) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		if n < 0 {
			return fmt.Errorf("%w: max sessions must not be negative", ErrInvalidPortalRequest)
		}
		o.maxSessions = &n
		return nil
	})
}

// WithSessionDuration sets how long access lasts after someone opens the link.
// Durations must be at least one second and whole seconds. Omit this option to
// use the server default; zero is rejected rather than treated as default. The
// LayerV API remains the source of truth for account limits. Values are
// serialized with hours as the largest unit, so all API duration fields use the
// same h/m/s grammar.
func WithSessionDuration(d time.Duration) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		sessionDuration, err := formatAPIDuration(d, time.Second)
		if err != nil {
			return err
		}
		o.sessionDuration = sessionDuration
		return nil
	})
}

// CreatePortal asks LayerV to mint a qURL link for an existing resource.
func (c *Client) CreatePortal(ctx context.Context, resource *Resource, opts ...PortalOption) (*Portal, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if resource == nil {
		return nil, fmt.Errorf("%w: resource must not be nil", ErrInvalidPortalRequest)
	}
	if resource.client != nil && resource.client != c {
		return nil, fmt.Errorf("%w: resource is bound to a different client", ErrInvalidPortalRequest)
	}
	if strings.TrimSpace(resource.ID) == "" {
		return nil, fmt.Errorf("%w: resource id must not be empty", ErrInvalidPortalRequest)
	}
	reqBody, err := buildCreatePortalRequest(opts)
	if err != nil {
		return nil, err
	}

	path := "/v1/resources/" + url.PathEscape(resource.ID) + "/qurls"
	var env apiEnvelope[createPortalResponse]
	if err := c.doJSON(ctx, http.MethodPost, path, reqBody, &env); err != nil {
		return nil, err
	}
	return env.Data.portal()
}

// CreatePortal asks LayerV to mint a qURL link for this resource.
func (r *Resource) CreatePortal(ctx context.Context, opts ...PortalOption) (*Portal, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: resource must not be nil", ErrInvalidPortalRequest)
	}
	if r.client == nil {
		return nil, fmt.Errorf("%w: resource is not bound to a client", ErrInvalidPortalRequest)
	}
	return r.client.CreatePortal(ctx, r, opts...)
}

// CreatePortalForURL creates or reuses the resource for targetURL and returns a
// portal in one API call. The returned resource is bound to this client and can
// be stored or reused to mint more portals; only its ID and caller-supplied
// TargetURL are populated. Use ProtectURL when you need the full
// server-populated resource metadata.
func (c *Client) CreatePortalForURL(ctx context.Context, targetURL string, opts ...PortalOption) (*Portal, *Resource, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTargetURL(targetURL, ErrInvalidPortalRequest); err != nil {
		return nil, nil, err
	}
	reqBody, err := buildCreatePortalForURLRequest(targetURL, opts)
	if err != nil {
		return nil, nil, err
	}

	var env apiEnvelope[createPortalResponse]
	if err := c.doJSON(ctx, http.MethodPost, "/v1/qurls", reqBody, &env); err != nil {
		return nil, nil, err
	}
	portal, err := env.Data.portal()
	if err != nil {
		return nil, nil, err
	}
	resource := &Resource{
		client:    c,
		ID:        portal.ResourceID,
		TargetURL: targetURL,
	}
	return portal, resource, nil
}

type createResourceRequest struct {
	TargetURL    string   `json:"target_url"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	CustomDomain string   `json:"custom_domain,omitempty"`
	Alias        string   `json:"alias,omitempty"`
}

type createResourceResponse struct {
	ID           string     `json:"resource_id"`
	TargetURL    string     `json:"target_url"`
	Status       string     `json:"status"`
	Description  string     `json:"description"`
	Tags         []string   `json:"tags"`
	CustomDomain *string    `json:"custom_domain"`
	Alias        *string    `json:"alias"`
	QURLCount    int        `json:"qurl_count"`
	CreatedAt    *time.Time `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

func (r createResourceResponse) resource() (*Resource, error) {
	if strings.TrimSpace(r.ID) == "" {
		return nil, fmt.Errorf("%w: missing resource_id", ErrInvalidAPIResponse)
	}
	return &Resource{
		ID:           r.ID,
		TargetURL:    r.TargetURL,
		Status:       r.Status,
		Description:  r.Description,
		Tags:         slices.Clone(r.Tags),
		CustomDomain: r.CustomDomain,
		Alias:        r.Alias,
		QURLCount:    r.QURLCount,
		CreatedAt:    r.CreatedAt,
		ExpiresAt:    r.ExpiresAt,
	}, nil
}

type createPortalRequest struct {
	ExpiresIn       string `json:"expires_in,omitempty"`
	Label           string `json:"label,omitempty"`
	OneTimeUse      *bool  `json:"one_time_use,omitempty"`
	MaxSessions     *int   `json:"max_sessions,omitempty"`
	SessionDuration string `json:"session_duration,omitempty"`
}

type createPortalForURLRequest struct {
	TargetURL string `json:"target_url"`
	createPortalRequest
}

type createPortalResponse struct {
	ResourceID string     `json:"resource_id"`
	QURLLink   string     `json:"qurl_link"`
	QURLSite   string     `json:"qurl_site"`
	ExpiresAt  *time.Time `json:"expires_at"`
	QURLID     string     `json:"qurl_id"`
	Label      string     `json:"label"`
}

func (r createPortalResponse) portal() (*Portal, error) {
	if strings.TrimSpace(r.ResourceID) == "" {
		return nil, fmt.Errorf("%w: missing resource_id", ErrInvalidAPIResponse)
	}
	if strings.TrimSpace(r.QURLLink) == "" {
		return nil, fmt.Errorf("%w: missing qurl_link", ErrInvalidAPIResponse)
	}
	return &Portal{
		ResourceID: r.ResourceID,
		Link:       r.QURLLink,
		Site:       r.QURLSite,
		ExpiresAt:  r.ExpiresAt,
		QURLID:     r.QURLID,
		Label:      r.Label,
	}, nil
}

type apiEnvelope[T any] struct {
	Data T `json:"data"`
}

func buildCreatePortalRequest(opts []PortalOption) (createPortalRequest, error) {
	cfg, err := applyPortalOptions(opts)
	if err != nil {
		return createPortalRequest{}, err
	}
	return createPortalRequest{
		ExpiresIn:       cfg.expiresIn,
		Label:           cfg.label,
		OneTimeUse:      cfg.oneTimeUse,
		MaxSessions:     cfg.maxSessions,
		SessionDuration: cfg.sessionDuration,
	}, nil
}

func buildCreatePortalForURLRequest(targetURL string, opts []PortalOption) (createPortalForURLRequest, error) {
	req, err := buildCreatePortalRequest(opts)
	if err != nil {
		return createPortalForURLRequest{}, err
	}
	return createPortalForURLRequest{
		TargetURL:           targetURL,
		createPortalRequest: req,
	}, nil
}

func applyPortalOptions(opts []PortalOption) (portalOptions, error) {
	var cfg portalOptions
	for _, opt := range opts {
		if opt == nil {
			return portalOptions{}, fmt.Errorf("%w: nil PortalOption", ErrInvalidPortalRequest)
		}
		if err := opt.applyPortalOption(&cfg); err != nil {
			return portalOptions{}, err
		}
	}
	return cfg, nil
}

func validateTargetURL(targetURL string, errKind error) error {
	// Protected targets may be private http:// services. Credential-bearing API
	// and bootstrap origins layer validateHTTPSOrLoopbackURL on top instead.
	// This client only rejects malformed URLs and embedded credentials; LayerV
	// performs the server-side resource checks when the target is registered.
	_, err := parseHTTPURL(targetURL, "target URL", errKind)
	return err
}

func validateHTTPSOrLoopbackURL(rawURL, label string, errKind error) error {
	u, err := parseHTTPURL(rawURL, label, errKind)
	if err != nil {
		return err
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%w: %s must use https unless it targets localhost", errKind, label)
	}
	// Callers append fixed endpoint paths to the original string. A query or
	// fragment would capture or hide that suffix instead of extending the path.
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%w: %s must not include a query", errKind, label)
	}
	// url.Parse represents an explicit empty fragment ("https://host/#") with
	// Fragment == ""; inspect the raw input as well so that suffix-capture form
	// cannot become indistinguishable from a URL with no fragment delimiter.
	if u.Fragment != "" || strings.Contains(rawURL, "#") {
		return fmt.Errorf("%w: %s must not include a fragment", errKind, label)
	}
	return nil
}

func parseHTTPURL(rawURL, label string, errKind error) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("%w: %s must not be empty", errKind, label)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errKind, label, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s must use http or https", errKind, label)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: %s must include a host", errKind, label)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: %s must not include userinfo", errKind, label)
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	return doAuthorizedJSON(ctx, c.httpClient, c.baseURL, c.credentials.Authorize, method, path, body, out)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body any, contract apiResponseContract) error {
	return doAuthorizedRequest(ctx, c.httpClient, c.baseURL, c.credentials.Authorize, method, path, body, contract)
}

// doJSONStatus requires one exact successful status and a non-empty JSON body.
// It is used when an endpoint's documented status is part of its contract.
func (c *Client) doJSONStatus(ctx context.Context, method, path string, body, out any, expectedStatus int) error {
	return c.doRequest(ctx, method, path, body, apiResponseContract{
		expectedStatus: expectedStatus,
		bodyMode:       apiResponseBodyJSON,
		out:            out,
	})
}

// doNoContent requires one exact successful status and a byte-empty body.
// Whitespace is still protocol content and deliberately fails this contract.
func (c *Client) doNoContent(ctx context.Context, method, path string, expectedStatus int) error {
	return c.doRequest(ctx, method, path, nil, apiResponseContract{
		expectedStatus: expectedStatus,
		bodyMode:       apiResponseBodyEmpty,
	})
}

func validateCredentials(ctx context.Context, provider CredentialProvider, baseURL string) error {
	if provider == nil {
		return fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("qurl: build credential validation request: %w", err)
	}
	return provider.Authorize(ctx, req)
}

func validateClientCredentialProvider(provider CredentialProvider, baseURL string) error {
	switch p := provider.(type) {
	case CredentialProviderFunc:
		if p == nil {
			return fmt.Errorf("%w: nil credential provider", ErrInvalidClientConfig)
		}
	case bearerTokenCredential:
		if err := validateCredentials(context.Background(), p, baseURL); err != nil {
			return err
		}
	case *cachedCredentialProvider:
		if p == nil {
			return fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
		}
		if p.ttl <= 0 {
			return fmt.Errorf("%w: credential cache ttl must be positive", ErrInvalidClientConfig)
		}
		return validateClientCredentialProvider(p.provider, baseURL)
	}
	return nil
}

type requestAuthorizer func(context.Context, *http.Request) error

// doAuthorizedJSON preserves the SDK's generic contract: when out is nil, any
// 2xx status and body are accepted and ignored. Endpoint-specific callers that
// require an exact JSON or no-content response use doAuthorizedRequest with an
// explicit apiResponseContract instead.
func doAuthorizedJSON(ctx context.Context, httpClient HTTPDoer, baseURL string, authorize requestAuthorizer, method, path string, body, out any) error {
	bodyMode := apiResponseBodyIgnored
	if out != nil {
		bodyMode = apiResponseBodyJSON
	}
	return doAuthorizedRequest(ctx, httpClient, baseURL, authorize, method, path, body, apiResponseContract{
		bodyMode: bodyMode,
		out:      out,
	})
}

type apiResponseBodyMode uint8

const (
	apiResponseBodyIgnored apiResponseBodyMode = iota
	apiResponseBodyJSON
	apiResponseBodyEmpty
)

type apiResponseContract struct {
	expectedStatus int
	bodyMode       apiResponseBodyMode
	out            any
}

func doAuthorizedRequest(ctx context.Context, httpClient HTTPDoer, baseURL string, authorize requestAuthorizer, method, path string, body any, contract apiResponseContract) error {
	if httpClient == nil {
		return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidClientConfig)
	}
	if authorize == nil {
		return fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}

	reqBody := io.Reader(http.NoBody)
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("qurl: encode API request: %w", err)
		}
		// Do not wipe raw when Do returns: net/http may return an early response
		// while its write goroutine is still consuming the request body.
		reqBody = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("qurl: build API request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", sdkUserAgent())
	if err := authorize(ctx, req); err != nil {
		return fmt.Errorf("qurl: authorize API request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return &apiRequestOutcomeUnknownError{err: fmt.Errorf("qurl: API request failed: %w", err)}
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	defer drainResponseBody(resp.Body)

	respBody, err := readCappedBody(resp.Body, maxAPIResponseBodyBytes, "API response body")
	if err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &APIError{
				StatusCode: resp.StatusCode,
				Detail:     fmt.Sprintf("read API response: %v", err),
				err:        err,
			}
		}
		return invalidAPIResponseOutcome("read API response after successful status", err)
	}
	defer wipeBytes(respBody)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiErrorFromResponse(resp.StatusCode, respBody)
	}
	if contract.expectedStatus != 0 && resp.StatusCode != contract.expectedStatus {
		return invalidAPIResponseOutcome(fmt.Sprintf("API returned HTTP %d, want %d", resp.StatusCode, contract.expectedStatus), nil)
	}

	switch contract.bodyMode {
	case apiResponseBodyIgnored:
		return nil
	case apiResponseBodyJSON:
		if len(bytes.TrimSpace(respBody)) == 0 {
			return invalidAPIResponseOutcome("empty API response body after successful status", nil)
		}
		if err := json.Unmarshal(respBody, contract.out); err != nil {
			return invalidAPIResponseOutcome("decode API response after successful status", err)
		}
		return nil
	case apiResponseBodyEmpty:
		if len(respBody) != 0 {
			return invalidAPIResponseOutcome(fmt.Sprintf("HTTP %d response body must be empty", resp.StatusCode), nil)
		}
		return nil
	}
	return invalidAPIResponseOutcome("unknown API response body contract", nil)
}

func invalidAPIResponseOutcome(detail string, cause error) error {
	if cause != nil {
		return &apiRequestOutcomeUnknownError{err: fmt.Errorf("%w: %s: %w", ErrInvalidAPIResponse, detail, cause)}
	}
	return &apiRequestOutcomeUnknownError{err: fmt.Errorf("%w: %s", ErrInvalidAPIResponse, detail)}
}

// apiRequestOutcomeUnknownError marks failures after an HTTP request was handed
// to the transport, or after a 2xx response arrived but could not be consumed.
// Reads intentionally share this transport/post-2xx marker so the common JSON
// helper has one failure contract; they pass it through like any other request
// failure. Mutation callers may additionally interpret it as possible committed
// side-effect ambiguity and refuse to replay. The underlying error remains
// matchable.
type apiRequestOutcomeUnknownError struct {
	err error
}

func (e *apiRequestOutcomeUnknownError) Error() string { return e.err.Error() }
func (e *apiRequestOutcomeUnknownError) Unwrap() error { return e.err }

// sdkUserAgent returns the cached SDK User-Agent header. The value is derived
// from build info, which is fixed for the process lifetime, so it is computed
// once rather than on every request.
var sdkUserAgent = sync.OnceValue(computeSDKUserAgent)

func computeSDKUserAgent() string {
	const name = "qurl-go-sdk"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return name
	}
	if info.Main.Path == "github.com/layervai/qurl-go" && usableBuildVersion(info.Main.Version) {
		return name + "/" + info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/layervai/qurl-go" && usableBuildVersion(dep.Version) {
			return name + "/" + dep.Version
		}
	}
	return name
}

func usableBuildVersion(version string) bool {
	return version != "" && version != "(devel)"
}

// readCappedBody reads at most max bytes from r, returning an error if the source
// held more rather than silently truncating it. It reads one byte past max so an
// over-limit body is detectable; otherwise oversized input can fail later as a
// confusing decode, parse, or pin mismatch. what names the body in errors.
func readCappedBody(r io.Reader, limit int, what string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		wipeBytes(raw)
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(raw) > limit {
		wipeBytes(raw)
		return nil, &inputExceedsCapError{what: what, limit: limit}
	}
	return raw, nil
}

type inputExceedsCapError struct {
	what  string
	limit int
}

func (e *inputExceedsCapError) Error() string {
	return fmt.Sprintf("%s exceeds %d-byte cap", e.what, e.limit)
}

func drainResponseBody(body io.Reader) {
	// The drain cap is best-effort connection reuse, not a second body-size
	// limit. After an oversized body, unread bytes may still prevent reuse; the
	// precise failure is more important than keeping that one connection hot.
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxAPIResponseDrainBytes))
}

// APIError is returned when the LayerV API responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Code       string
	Type       string
	Title      string
	Detail     string
	err        error
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail != "" {
		return fmt.Sprintf("qurl: API error %d: %s", e.StatusCode, e.Detail)
	}
	if e.Title != "" {
		return fmt.Sprintf("qurl: API error %d: %s", e.StatusCode, e.Title)
	}
	return fmt.Sprintf("qurl: API error %d", e.StatusCode)
}

func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func apiErrorFromResponse(status int, body []byte) error {
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Title   string `json:"title"`
			Detail  string `json:"detail"`
			Message string `json:"message"`
		} `json:"error"`
		Code    string `json:"code"`
		Type    string `json:"type"`
		Title   string `json:"title"`
		Detail  string `json:"detail"`
		Message string `json:"message"`
	}
	// Some upstream failures are plain text, HTML, or invalid JSON. Treat that
	// as an unstructured API error and fall back to a capped body snippet below.
	_ = json.Unmarshal(body, &parsed)
	// LayerV and intermediate infrastructure can return either JSON:API-style
	// {"error": {...}} bodies or flat problem fields; preserve both shapes.
	code := cmp.Or(parsed.Error.Code, parsed.Code)
	apiType := cmp.Or(parsed.Error.Type, parsed.Type)
	title := apiErrorTextField(cmp.Or(parsed.Error.Title, parsed.Title))
	detail := apiErrorTextField(cmp.Or(parsed.Error.Detail, parsed.Detail, parsed.Error.Message, parsed.Message))
	if code == "" && apiType == "" && title == "" && detail == "" {
		detail = apiErrorBodySnippet(body)
	}
	return &APIError{
		StatusCode: status,
		Code:       code,
		Type:       apiType,
		Title:      title,
		Detail:     detail,
	}
}

func apiErrorTextField(value string) string {
	// Keep APIError.Error single-line and bounded even when structured problem
	// fields contain newlines or large prose details.
	return apiErrorBodySnippet([]byte(value))
}

func apiErrorBodySnippet(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return ""
	}
	snippet := strings.Join(strings.Fields(string(body)), " ")
	if len(snippet) <= maxAPIErrorSnippetBytes {
		return snippet
	}
	return truncateUTF8(snippet, maxAPIErrorSnippetBytes) + "..."
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func formatAPIDuration(d time.Duration, minDuration time.Duration) (string, error) {
	if d < minDuration {
		return "", fmt.Errorf("%w: duration must be at least %s", ErrInvalidPortalRequest, minDuration)
	}
	if d%time.Second != 0 {
		return "", fmt.Errorf("%w: duration must be whole seconds", ErrInvalidPortalRequest)
	}
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour), nil
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute), nil
	default:
		return fmt.Sprintf("%ds", d/time.Second), nil
	}
}

func validateContext(ctx context.Context, invalidConfig error) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", invalidConfig)
	}
	return ctx.Err()
}
