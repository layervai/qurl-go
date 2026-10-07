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
// The bridge accepts only owner-scoped resource and nested qURL/session
// management, Connector sharing-state, share-link mint
// (POST /v1/resources/{id}/share), portal creation, Connector-enrollment-token
// mint, account linking (POST /v1/account/link), identity-echo, and
// publisher-profile (GET and PATCH /v1/me/publisher, exactly, with no query)
// routes used by a registered qURL client. The service independently restricts
// a device key's POST /v1/api-keys authority to a Connector-target one-shot
// token. Other account, billing, usage, and key-management routes fail closed.
//
// The publisher-profile write is the one owner-profile route in scope, and it
// is deliberate: a device that publishes without an account holds no other
// credential, so without it that owner could never set the name shown beside
// its own resources. The write changes a self-declared display name only. It
// cannot change the verification status, which the service computes and no
// request can set.
//
// The bridge also accepts the five routes an owner uses to answer people who
// ask for access to a private resource, for the same reason: a device that
// publishes without an account is the only credential that owner holds. Each is
// accepted exactly, with no query:
//
//   - GET /v1/access-requests lists the waiting requests for all of the owner's
//     resources, and GET /v1/resources/{id}/access-requests for one resource.
//   - POST /v1/resources/{id}/access-requests/{code}/approve approves one
//     request, and DELETE /v1/resources/{id}/access-requests/{code} denies it.
//   - DELETE /v1/resources/{id}/allowed-passkeys/{device_id} removes a device
//     that was approved earlier.
//
// {code} is the request's code, exactly six ASCII digits. {device_id} is the
// approved device's identifier as it is shown: four groups of four lowercase
// base32 characters (a to z, 2 to 7) joined by hyphens. A segment of any other
// shape is refused like any other route outside this list.
//
// The bridge also requires the Client's exact API origin and path prefix. The
// caller's request is never mutated, and the device Authorization header is
// removed from the returned response metadata.
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
	// Resource and nested qURL lists accept pagination; the service's session
	// list is unpaginated, and so are both access-request lists. A resource
	// named "qurls" remains a single-resource route and must not gain query
	// authority.
	listQuery := req.Method == http.MethodGet && (path == "/v1/resources" ||
		(strings.Count(path, "/") == 4 && strings.HasSuffix(path, "/qurls")))
	if (req.URL.RawQuery != "" || req.URL.ForceQuery) && !listQuery {
		return fmt.Errorf("%w: query is not allowed on %s %s", ErrRegisteredAgentResourceRequestDenied, req.Method, path)
	}
	return nil
}

func registeredAgentResourceRouteAllowed(method, path string) bool {
	switch path {
	case "/v1/account/link":
		return method == http.MethodPost
	case "/v1/resources":
		return method == http.MethodGet || method == http.MethodPost
	case "/v1/api-keys":
		return method == http.MethodPost
	case "/v1/qurls":
		return method == http.MethodPost
	case "/v1/me":
		return method == http.MethodGet
	case "/v1/me/publisher":
		return method == http.MethodGet || method == http.MethodPatch
	case "/v1/access-requests":
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
		case "share":
			return method == http.MethodPost
		case "qurls":
			return method == http.MethodGet || method == http.MethodPost
		case "sessions":
			return method == http.MethodGet || method == http.MethodDelete
		case "access-requests":
			return method == http.MethodGet
		}
	case 3:
		switch segments[1] {
		case "sharing":
			return segments[2] == "restart" && method == http.MethodPost
		case "qurls":
			return registeredAgentResourceIDAllowed(segments[2]) && (method == http.MethodPatch || method == http.MethodDelete)
		case "sessions":
			return registeredAgentResourceIDAllowed(segments[2]) && method == http.MethodDelete
		case "access-requests":
			return registeredAgentAccessRequestCodeAllowed(segments[2]) && method == http.MethodDelete
		case "allowed-passkeys":
			return registeredAgentPasskeyDeviceIDAllowed(segments[2]) && method == http.MethodDelete
		}
	case 4:
		// The only four-segment route. Approval is a POST on the request's own
		// code; nothing else nests this deep.
		return segments[1] == "access-requests" && registeredAgentAccessRequestCodeAllowed(segments[2]) &&
			segments[3] == "approve" && method == http.MethodPost
	}
	return false
}

const (
	registeredAgentAccessRequestCodeLength = 6
	// Four groups of four characters and the three hyphens between them.
	registeredAgentPasskeyDeviceIDGroup  = 4
	registeredAgentPasskeyDeviceIDLength = 4*registeredAgentPasskeyDeviceIDGroup + 3
)

// registeredAgentAccessRequestCodeAllowed reports whether value is exactly six
// ASCII digits. It compares bytes, so a digit from any other script, a sign, and
// surrounding space are all refused.
func registeredAgentAccessRequestCodeAllowed(value string) bool {
	if len(value) != registeredAgentAccessRequestCodeLength {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// registeredAgentPasskeyDeviceIDAllowed reports whether value is a device
// identifier in its one displayed form, xxxx-xxxx-xxxx-xxxx, where each x is a
// lowercase base32 character (a to z, 2 to 7). Upper case, the digits outside
// that alphabet, padding, and any other grouping are refused.
func registeredAgentPasskeyDeviceIDAllowed(value string) bool {
	if len(value) != registeredAgentPasskeyDeviceIDLength {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if i%(registeredAgentPasskeyDeviceIDGroup+1) == registeredAgentPasskeyDeviceIDGroup {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
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
