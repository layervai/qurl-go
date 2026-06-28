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
)

const (
	defaultAPIBaseURL        = "https://api.layerv.ai"
	maxAPIResponseBodyBytes  = 1 << 20
	maxAPIResponseDrainBytes = 512 << 10
	maxAPIErrorSnippetBytes  = 512
)

// DefaultIssuerStatePath is the default local LayerV credential path used by
// OpenClient. Most applications should call OpenClient rather than reading this
// file directly.
const DefaultIssuerStatePath = "/var/lib/layerv/qurl/issuer-state.json"

// ErrInvalidClientConfig is returned when a Client cannot be configured.
var ErrInvalidClientConfig = errors.New("qurl: invalid client config")

// ErrInvalidResourceRequest is returned before an API request when a resource
// input is invalid.
var ErrInvalidResourceRequest = errors.New("qurl: invalid resource request")

// ErrInvalidPortalRequest is returned before an API request when a portal input
// is invalid.
var ErrInvalidPortalRequest = errors.New("qurl: invalid portal request")

// ErrCredentialStateNotFound is returned when FileCredentials cannot find the
// LayerV credential file.
var ErrCredentialStateNotFound = errors.New("qurl: credential state not found")

// ErrInsecureCredentialStatePermissions is returned when file-backed issuer
// credentials are readable by group or other users.
var ErrInsecureCredentialStatePermissions = errors.New("qurl: insecure credential state permissions")

// ErrResourceNotFound is returned when a requested LayerV resource does not
// exist for the current issuer.
var ErrResourceNotFound = errors.New("qurl: resource not found")

// ErrAmbiguousResource is returned when LayerV returns multiple resources for a
// lookup that must resolve to exactly one.
var ErrAmbiguousResource = errors.New("qurl: ambiguous resource")

// CredentialProvider authorizes Client requests.
//
// Implement this interface with credentials loaded from protected local state,
// KMS, or a secret manager.
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
	token := strings.TrimSpace(string(c))
	if token == "" {
		return fmt.Errorf("%w: bearer token must not be empty", ErrInvalidClientConfig)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// BearerToken returns a CredentialProvider backed by one bearer token.
//
// It is useful for tests and controlled tooling that already received a LayerV
// bearer credential from a protected credential path.
func BearerToken(token string) CredentialProvider {
	return bearerTokenCredential(token)
}

type fileCredentialProvider struct {
	path string
}

// FileCredentials reads LayerV issuer credentials from path on every request so
// rotated local credentials are picked up without rebuilding the client. Most
// applications should use OpenClient; use FileCredentials only when wiring a
// custom runtime path. The context passed to Authorize cannot interrupt local
// filesystem I/O after it has started.
func FileCredentials(path string) CredentialProvider {
	return fileCredentialProvider{path: path}
}

func (p fileCredentialProvider) Authorize(_ context.Context, req *http.Request) error {
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
	case authorization != "":
		req.Header.Set("Authorization", authorization)
		return nil
	case bearer != "":
		req.Header.Set("Authorization", "Bearer "+bearer)
		return nil
	default:
		return fmt.Errorf("%w: credential state cannot authorize requests", ErrInvalidClientConfig)
	}
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
	baseURL    string
	httpClient HTTPDoer
}

// WithBaseURL points the client at a non-default LayerV API origin. Most
// applications do not need this.
func WithBaseURL(rawURL string) ClientOption {
	return clientOptionFunc(func(o *clientOptions) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "base URL", ErrInvalidClientConfig); err != nil {
			return err
		}
		o.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithHTTPClient injects the HTTP client used for API requests.
func WithHTTPClient(client HTTPDoer) ClientOption {
	return clientOptionFunc(func(o *clientOptions) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidClientConfig)
		}
		o.httpClient = client
		return nil
	})
}

// NewClient returns a qURL API client backed by a credential provider.
func NewClient(provider CredentialProvider, opts ...ClientOption) (*Client, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}
	cfg := clientOptions{
		baseURL:    defaultAPIBaseURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil ClientOption", ErrInvalidClientConfig)
		}
		if err := opt.applyClientOption(&cfg); err != nil {
			return nil, err
		}
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
// OpenClientContext when startup code needs to bound that eager check.
func OpenClient(opts ...ClientOption) (*Client, error) {
	return OpenClientContext(context.Background(), opts...)
}

// defaultCredentialProvider is an OpenClientContext test seam. Production code
// must not swap it, and tests must not mutate it concurrently with OpenClient.
var defaultCredentialProvider = FileCredentials

// OpenClientContext is OpenClient with a context for the eager credential
// authorization check. For file-backed credentials, the context can cancel
// before the request is built or while custom credential code runs, but it
// cannot interrupt a local filesystem read once it has started.
func OpenClientContext(ctx context.Context, opts ...ClientOption) (*Client, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidClientConfig)
	}
	provider := defaultCredentialProvider(DefaultIssuerStatePath)
	client, err := NewClient(provider, opts...)
	if err != nil {
		return nil, err
	}
	if err := validateCredentials(ctx, provider, client.baseURL); err != nil {
		return nil, err
	}
	return client, nil
}

// Resource is a protected target registered in the LayerV qURL Platform. Fields
// are exported for inspection and serialization; CreatePortal reads ID at call
// time, and JSON cannot preserve the unexported client binding. Use ResourceByID
// for a new handle instead of mutating or round-tripping a bound one.
type Resource struct {
	client *Client

	// ID is the LayerV resource id, for example r_abc123...
	ID string
	// TargetURL is the private URL protected by this resource.
	TargetURL string
	// Status is the resource lifecycle status returned by LayerV.
	Status string
	// Description is optional resource-level metadata.
	Description string
	// Tags are optional resource-level metadata.
	Tags []string
	// CustomDomain is set when this resource is bound to a verified domain.
	CustomDomain *string
	// Alias is an optional owner-scoped handle for the resource.
	Alias *string
	// QURLCount is the number of active qURL links LayerV reports for the resource.
	QURLCount int
	// CreatedAt is the server creation time, when returned by the API.
	CreatedAt *time.Time
	// ExpiresAt is the server expiration time, when returned by the API.
	ExpiresAt *time.Time
}

// ResourceByID returns a resource handle bound to this client. Use it when you
// stored a LayerV resource id and want to mint more portals for it.
func (c *Client) ResourceByID(id string) *Resource {
	return &Resource{client: c, ID: id}
}

// ConnectorResource returns the resource created for connectorID by qURL
// Connector. The connector id is the resource slug LayerV stores for that
// connector. Use this when qURL Connector already protects the service; do not
// call ProtectURL again for the same service.
func (c *Client) ConnectorResource(ctx context.Context, connectorID string) (*Resource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return nil, fmt.Errorf("%w: connector id must not be empty", ErrInvalidResourceRequest)
	}

	query := url.Values{}
	query.Set("slug", connectorID)
	var env apiEnvelope[[]createResourceResponse]
	if err := c.doJSON(ctx, http.MethodGet, "/v1/resources?"+query.Encode(), nil, &env); err != nil {
		return nil, err
	}
	if len(env.Data) == 0 {
		return nil, fmt.Errorf("%w: connector %q", ErrResourceNotFound, connectorID)
	}
	if len(env.Data) > 1 {
		return nil, fmt.Errorf("%w: connector %q returned %d resources", ErrAmbiguousResource, connectorID, len(env.Data))
	}
	resource, err := env.Data[0].resource()
	if err != nil {
		return nil, err
	}
	resource.client = c
	return resource, nil
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

// ProtectURL creates or reuses a LayerV resource for targetURL.
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
// least one minute as a client-side guardrail; the LayerV API remains
// authoritative for policy. If omitted, the API applies its default lifetime.
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

// MaxSessions limits concurrent sessions for this qURL link. The SDK caps this
// at 1000 as a client-side guardrail; the LayerV API remains authoritative for
// policy. Use 0 for unlimited sessions; the SDK sends an explicit
// max_sessions:0, while omitting this option leaves the server default in
// effect.
func MaxSessions(n int) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		if n < 0 || n > 1000 {
			return fmt.Errorf("%w: max sessions must be between 0 and 1000", ErrInvalidPortalRequest)
		}
		o.maxSessions = &n
		return nil
	})
}

// WithSessionDuration sets how long access lasts after someone opens the link.
// The SDK caps this at 24 hours as a client-side guardrail; the LayerV API
// remains authoritative for policy. Omit this option to use the server default;
// zero is rejected rather than treated as default.
func WithSessionDuration(d time.Duration) PortalOption {
	return portalOptionFunc(func(o *portalOptions) error {
		if d > 24*time.Hour {
			return fmt.Errorf("%w: session duration must be at most 24 hours", ErrInvalidPortalRequest)
		}
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
// be stored or reused to mint more portals; only its ID and TargetURL are
// populated. Use ProtectURL when you need the full server-populated resource
// metadata.
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
		return nil, fmt.Errorf("qurl: invalid API response: missing resource_id")
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
		return nil, fmt.Errorf("qurl: invalid API response: missing resource_id")
	}
	if strings.TrimSpace(r.QURLLink) == "" {
		return nil, fmt.Errorf("qurl: invalid API response: missing qurl_link")
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
	_, err := parseHTTPURL(targetURL, "target URL", errKind)
	return err
}

func validateHTTPSOrLoopbackURL(rawURL, label string, errKind error) error {
	u, err := parseHTTPURL(rawURL, label, errKind)
	if err != nil {
		return err
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s must not include userinfo", errKind, label)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%w: %s must use https unless it targets localhost", errKind, label)
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

func validateCredentials(ctx context.Context, provider CredentialProvider, baseURL string) error {
	if provider == nil {
		return fmt.Errorf("%w: credential provider must not be nil", ErrInvalidClientConfig)
	}
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidClientConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("qurl: build credential validation request: %w", err)
	}
	return provider.Authorize(ctx, req)
}

type requestAuthorizer func(context.Context, *http.Request) error

func doAuthorizedJSON(ctx context.Context, httpClient HTTPDoer, baseURL string, authorize requestAuthorizer, method, path string, body, out any) error {
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
		return fmt.Errorf("qurl: API request failed: %w", err)
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
			}
		}
		return fmt.Errorf("qurl: read API response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiErrorFromResponse(resp.StatusCode, respBody)
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return fmt.Errorf("qurl: empty API response body")
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("qurl: decode API response: %w", err)
	}
	return nil
}

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
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte cap", what, limit)
	}
	return raw, nil
}

func drainResponseBody(body io.Reader) {
	// The drain cap is best-effort connection reuse, not a second body-size
	// policy. Larger error bodies are simply closed instead of fully drained.
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxAPIResponseDrainBytes))
}

// APIError is returned when the LayerV API responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Code       string
	Type       string
	Title      string
	Detail     string
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
	_ = json.Unmarshal(body, &parsed)
	code := cmp.Or(parsed.Error.Code, parsed.Code)
	apiType := cmp.Or(parsed.Error.Type, parsed.Type)
	title := cmp.Or(parsed.Error.Title, parsed.Title)
	detail := cmp.Or(parsed.Error.Detail, parsed.Detail, parsed.Error.Message, parsed.Message)
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

func apiErrorBodySnippet(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return ""
	}
	truncated := len(body) > maxAPIErrorSnippetBytes
	if truncated {
		body = body[:maxAPIErrorSnippetBytes]
	}
	snippet := strings.Join(strings.Fields(string(body)), " ")
	if truncated {
		snippet += "..."
	}
	return snippet
}

func formatAPIDuration(d time.Duration, minDuration time.Duration) (string, error) {
	if d < minDuration {
		return "", fmt.Errorf("%w: duration must be at least %s", ErrInvalidPortalRequest, minDuration)
	}
	if d%time.Second != 0 {
		return "", fmt.Errorf("%w: duration must be whole seconds", ErrInvalidPortalRequest)
	}
	const day = 24 * time.Hour
	switch {
	case d%day == 0:
		return fmt.Sprintf("%dd", d/day), nil
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour), nil
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute), nil
	default:
		return fmt.Sprintf("%ds", d/time.Second), nil
	}
}
