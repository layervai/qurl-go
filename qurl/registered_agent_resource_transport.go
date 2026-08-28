package qurl

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrRegisteredAgentResourceRequestDenied marks a request outside the exact
// steady-state HTTPS authority of a registered agent device credential. The
// request is rejected before authorization or network I/O.
var ErrRegisteredAgentResourceRequestDenied = errors.New("qurl: registered-agent resource request denied")

// RegisteredAgentResourceHTTPDoer returns a narrow HTTP bridge for platform
// resource operations that are not yet modeled by Client methods. It is
// available only on a Client opened or returned by the registered-agent
// lifecycle APIs.
//
// The bridge accepts only the owner-scoped resource, sharing, resolve, portal
// creation, and identity-echo routes used by a registered qURL client. Account,
// billing, key-management, enrollment, and session-control routes fail closed.
// It also requires the Client's exact API origin and path prefix. The caller's
// request is never mutated, and the device Authorization header is removed from
// the returned response metadata.
func (c *Client) RegisteredAgentResourceHTTPDoer() (HTTPDoer, error) {
	if c == nil || !c.registered || c.credentials == nil || c.httpClient == nil {
		return nil, fmt.Errorf("%w: client is not a registered agent resource client", ErrInvalidClientConfig)
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse registered-agent resource base URL: %w", ErrInvalidClientConfig, err)
	}
	return &registeredAgentResourceHTTPDoer{client: c, base: base}, nil
}

type registeredAgentResourceHTTPDoer struct {
	client *Client
	base   *url.URL
}

func (d *registeredAgentResourceHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	if d == nil || d.client == nil || d.base == nil || req == nil || req.URL == nil {
		return nil, fmt.Errorf("%w: request and registered client must not be nil", ErrRegisteredAgentResourceRequestDenied)
	}
	ctx := req.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateRegisteredAgentResourceRequest(d.base, req); err != nil {
		return nil, err
	}

	// Authorize a private clone. Neither the caller's request nor the response's
	// Request field may become a way to read the durable device credential.
	wire := req.Clone(ctx)
	wire.Header = req.Header.Clone()
	if wire.Header == nil {
		wire.Header = make(http.Header)
	}
	wire.Header.Del("Authorization")
	if err := d.client.credentials.Authorize(ctx, wire); err != nil {
		return nil, err
	}
	resp, err := d.client.httpClient.Do(wire)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("%w: registered-agent HTTP transport returned no response", ErrInvalidAPIResponse)
	}
	public := *resp
	publicReq := req.Clone(ctx)
	publicReq.Header = req.Header.Clone()
	if publicReq.Header == nil {
		publicReq.Header = make(http.Header)
	}
	publicReq.Header.Del("Authorization")
	public.Request = publicReq
	return &public, nil
}

func validateRegisteredAgentResourceRequest(base *url.URL, req *http.Request) error {
	if base == nil || req == nil || req.URL == nil {
		return fmt.Errorf("%w: request URL is missing", ErrRegisteredAgentResourceRequestDenied)
	}
	if req.URL.User != nil || req.URL.Fragment != "" || req.URL.RawFragment != "" || req.URL.RawPath != "" || req.URL.Opaque != "" || (req.Host != "" && !strings.EqualFold(req.Host, base.Host)) {
		return fmt.Errorf("%w: request URL has unsupported authority or encoding", ErrRegisteredAgentResourceRequestDenied)
	}
	if !strings.EqualFold(req.URL.Scheme, base.Scheme) || !strings.EqualFold(req.URL.Host, base.Host) {
		return fmt.Errorf("%w: request origin does not match the registered client", ErrRegisteredAgentResourceRequestDenied)
	}
	basePath := strings.TrimRight(base.Path, "/")
	if !strings.HasPrefix(req.URL.Path, basePath+"/") {
		return fmt.Errorf("%w: request path is outside the registered client base path", ErrRegisteredAgentResourceRequestDenied)
	}
	path := strings.TrimPrefix(req.URL.Path, basePath)
	if !registeredAgentResourceRouteAllowed(req.Method, path) {
		return fmt.Errorf("%w: %s %s", ErrRegisteredAgentResourceRequestDenied, req.Method, path)
	}
	if (req.URL.RawQuery != "" || req.URL.ForceQuery) && (req.Method != http.MethodGet || path != "/v1/resources") {
		return fmt.Errorf("%w: query is not allowed on %s %s", ErrRegisteredAgentResourceRequestDenied, req.Method, path)
	}
	return nil
}

func registeredAgentResourceRouteAllowed(method, path string) bool {
	switch path {
	case "/v1/resources":
		return method == http.MethodGet || method == http.MethodPost
	case "/v1/qurls":
		return method == http.MethodPost
	case "/v1/me":
		return method == http.MethodGet
	}
	const prefix = "/v1/resources/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(segments) == 0 || !registeredAgentResourceIDAllowed(segments[0]) {
		return false
	}
	switch len(segments) {
	case 1:
		return method == http.MethodGet || method == http.MethodPatch || method == http.MethodDelete
	case 2:
		switch segments[1] {
		case "sharing":
			return method == http.MethodGet || method == http.MethodPut
		case "resolve", "qurls":
			return method == http.MethodPost
		}
	case 3:
		return segments[1] == "sharing" && segments[2] == "restart" && method == http.MethodPost
	}
	return false
}

func registeredAgentResourceIDAllowed(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
