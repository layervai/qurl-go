package qurl

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type registeredAgentResourceCapture struct {
	calls int
	want  string
}

func (c *registeredAgentResourceCapture) Do(req *http.Request) (*http.Response, error) {
	c.calls++
	if got := req.Header.Get("Authorization"); got != "Bearer "+c.want {
		return nil, errors.New("wire request did not carry the registered device credential")
	}
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestRegisteredAgentResourceHTTPDoer_ExactSurfaceAndCredentialCustody(t *testing.T) {
	state := completedNativeTestState(t)
	store := &memoryAgentStateStore{state: state}
	capture := &registeredAgentResourceCapture{want: state.DeviceAPIKey}
	client, err := OpenRegisteredAgent(context.Background(), store,
		WithAgentClientBaseURL("https://api.example.test/prefix"),
		WithAgentClientHTTPClient(capture),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	doer, err := client.RegisteredAgentResourceHTTPDoer()
	if err != nil {
		t.Fatalf("RegisteredAgentResourceHTTPDoer: %v", err)
	}

	allowed := []struct{ method, path string }{
		{http.MethodPost, "/v1/account/link"},
		{http.MethodPost, "/v1/api-keys"},
		{http.MethodGet, "/v1/resources?limit=20&cursor=next"},
		{http.MethodPost, "/v1/resources"},
		{http.MethodGet, "/v1/resources/qcrid"},
		{http.MethodPatch, "/v1/resources/qcrid"},
		{http.MethodDelete, "/v1/resources/qcrid"},
		{http.MethodGet, "/v1/resources/qcrid/sharing"},
		{http.MethodPut, "/v1/resources/qcrid/sharing"},
		{http.MethodPost, "/v1/resources/qcrid/sharing/restart"},
		{http.MethodPost, "/v1/resources/qcrid/share"},
		{http.MethodPost, "/v1/resources/qcrid/qurls"},
		{http.MethodGet, "/v1/resources/qcrid/qurls"},
		{http.MethodGet, "/v1/resources/qcrid/qurls?limit=100&cursor=next"},
		{http.MethodPatch, "/v1/resources/qcrid/qurls/at_link-1"},
		{http.MethodDelete, "/v1/resources/qcrid/qurls/at_link-1"},
		{http.MethodGet, "/v1/resources/qcrid/sessions"},
		{http.MethodDelete, "/v1/resources/qcrid/sessions"},
		{http.MethodDelete, "/v1/resources/qcrid/sessions/session_1"},
		{http.MethodPost, "/v1/qurls"},
		{http.MethodGet, "/v1/me"},
		{http.MethodGet, "/v1/me/publisher"},
		{http.MethodPatch, "/v1/me/publisher"},
		{http.MethodGet, "/v1/access-requests"},
		{http.MethodGet, "/v1/resources/qcrid/access-requests"},
		{http.MethodPost, "/v1/resources/qcrid/access-requests/012345/approve"},
		{http.MethodDelete, "/v1/resources/qcrid/access-requests/012345"},
		{http.MethodDelete, "/v1/resources/qcrid/access-requests/abcd-efgh-ijkl-mnop"},
		{http.MethodDelete, "/v1/resources/qcrid/allowed-passkeys/abcd-efgh-ijkl-mnop"},
	}
	for _, test := range allowed {
		req, requestErr := http.NewRequestWithContext(context.Background(), test.method,
			"https://api.example.test/prefix"+test.path, http.NoBody)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer caller-value-must-not-win")
		resp, requestErr := doer.Do(req)
		if requestErr != nil {
			t.Errorf("%s %s: %v", test.method, test.path, requestErr)
			continue
		}
		_ = resp.Body.Close()
		if got := req.Header.Get("Authorization"); got != "Bearer caller-value-must-not-win" {
			t.Errorf("%s %s mutated caller Authorization to %q", test.method, test.path, got)
		}
		if resp.Request == nil || resp.Request.Header.Get("Authorization") != "" {
			t.Errorf("%s %s returned device authorization in response metadata", test.method, test.path)
		}
	}
	if capture.calls != len(allowed) {
		t.Fatalf("wire calls = %d, want %d", capture.calls, len(allowed))
	}
}

func TestRegisteredAgentResourceHTTPDoer_DeniesBeforeCredentialOrNetwork(t *testing.T) {
	state := completedNativeTestState(t)
	capture := &registeredAgentResourceCapture{want: state.DeviceAPIKey}
	client, err := OpenRegisteredAgent(context.Background(), &memoryAgentStateStore{state: state},
		WithAgentClientBaseURL("https://api.example.test/prefix"),
		WithAgentClientHTTPClient(capture),
	)
	if err != nil {
		t.Fatal(err)
	}
	doer, err := client.RegisteredAgentResourceHTTPDoer()
	if err != nil {
		t.Fatal(err)
	}

	denied := []struct{ method, target string }{
		{http.MethodGet, "https://api.example.test/prefix/v1/account/link"},
		{http.MethodPost, "https://api.example.test/prefix/v1/account/link?x=1"},
		{http.MethodPost, "https://api.example.test/prefix/v1/account/owners"},
		{http.MethodGet, "https://other.example.test/prefix/v1/resources"},
		{http.MethodGet, "https://api.example.test/v1/resources"},
		{http.MethodGet, "https://api.example.test/prefix/v1/api-keys"},
		{http.MethodGet, "https://api.example.test/prefix/v1/customer"},
		{http.MethodGet, "https://api.example.test/prefix/v1/account/owners"},
		{http.MethodPost, "https://api.example.test/prefix/v1/billing/checkout"},
		{http.MethodGet, "https://api.example.test/prefix/v1/qurls"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qurls?limit=100"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/bad.id/qurls?limit=100"},
		{http.MethodGet, "https://api.example.test/prefix/v1/usage/current-period"},
		{http.MethodGet, "https://api.example.test/prefix/v1/quota"},
		{http.MethodGet, "https://other.example.test/prefix/v1/resources/qcrid/qurls"},
		{http.MethodPost, "https://api.example.test/prefix/v1/resources/qcrid/qurls?limit=100"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/qurls"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/resources/qcrid/qurls/at_link?extra=true"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/qurls/at_link?"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/qurls/at_link"},
		{http.MethodPut, "https://api.example.test/prefix/v1/resources/qcrid/qurls/at_link"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/qurls/bad.id"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/qurls/%2e%2e"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/qurls/at_link/extra"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/sessions?limit=100"},
		{http.MethodPost, "https://api.example.test/prefix/v1/resources/qcrid/sessions"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/resources/qcrid/sessions"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/sessions/session_1"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/resources/qcrid/sessions/session_1"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/sessions/bad.id"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/sessions/session_1?"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/sessions/session_1/extra"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/sharing"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/share"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/resolve"},
		{http.MethodPost, "https://api.example.test/prefix/v1/resources/qcrid/resolve"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me?extra=true"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/me"},
		{http.MethodPut, "https://api.example.test/prefix/v1/me/publisher"},
		{http.MethodPost, "https://api.example.test/prefix/v1/me/publisher"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/me/publisher"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me/publisher?extra=true"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/me/publisher?verified=true"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/me/publisher?"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me/publisher/"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me/publisher/x"},
		{http.MethodPatch, "https://api.example.test/prefix/v1/me/publisher/x"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me/publishers"},
		{http.MethodGet, "https://api.example.test/v1/me/publisher"},
		{http.MethodPatch, "https://other.example.test/prefix/v1/me/publisher"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/bad.id"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/%2e%2e"},
	}
	for _, test := range denied {
		req, requestErr := http.NewRequestWithContext(context.Background(), test.method, test.target, http.NoBody)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		resp, requestErr := doer.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(requestErr, ErrRegisteredAgentResourceRequestDenied) {
			t.Errorf("%s %s = %v, want request denied", test.method, test.target, requestErr)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("denied request gained Authorization: %s %s", test.method, test.target)
		}
	}
	mutated := []*http.Request{
		{Method: http.MethodGet, URL: mustParseURL(t, "https://api.example.test/prefix/v1/me"), Host: "other.example.test", Header: make(http.Header)},
		{Method: http.MethodGet, URL: mustParseURL(t, "https://api.example.test/prefix/v1/me"), Header: make(http.Header)},
	}
	mutated[1].URL.Opaque = "/prefix/v1/api-keys"
	for _, req := range mutated {
		resp, requestErr := doer.Do(req.WithContext(context.Background()))
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(requestErr, ErrRegisteredAgentResourceRequestDenied) {
			t.Errorf("mutated authority request = %v, want request denied", requestErr)
		}
	}
	if capture.calls != 0 {
		t.Fatalf("denied requests reached network %d times", capture.calls)
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestRegisteredAgentResourceHTTPDoer_RejectsOrdinaryClient(t *testing.T) {
	client, err := NewClient(BearerToken("lv_test_ordinary"))
	if err != nil {
		t.Fatal(err)
	}
	if doer, err := client.RegisteredAgentResourceHTTPDoer(); doer != nil || !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("ordinary client bridge = %T, %v; want nil invalid config", doer, err)
	}
}

func TestRegisteredAgentResourceHTTPDoer_AllowsNilHeader(t *testing.T) {
	state := completedNativeTestState(t)
	capture := &registeredAgentResourceCapture{want: state.DeviceAPIKey}
	client, err := OpenRegisteredAgent(context.Background(), &memoryAgentStateStore{state: state},
		WithAgentClientBaseURL("https://api.example.test"), WithAgentClientHTTPClient(capture))
	if err != nil {
		t.Fatal(err)
	}
	doer, err := client.RegisteredAgentResourceHTTPDoer()
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodGet, URL: mustParseURL(t, "https://api.example.test/v1/me"),
		Body: http.NoBody,
	}
	resp, err := doer.Do(req.WithContext(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req.Header != nil || resp.Request == nil || resp.Request.Header == nil ||
		resp.Request.Header.Get("Authorization") != "" {
		t.Fatalf("nil caller header changed or credential leaked: caller=%v response=%v", req.Header, resp.Request)
	}
}

const registeredAgentResourceTestBase = "https://api.example.test/prefix"

// newRegisteredAgentResourceTestDoer opens a registered device client under a
// path prefix and returns its bridge with the transport that counts what
// reached the wire.
func newRegisteredAgentResourceTestDoer(t *testing.T) (HTTPDoer, *registeredAgentResourceCapture) {
	t.Helper()
	state := completedNativeTestState(t)
	capture := &registeredAgentResourceCapture{want: state.DeviceAPIKey}
	client, err := OpenRegisteredAgent(context.Background(), &memoryAgentStateStore{state: state},
		WithAgentClientBaseURL(registeredAgentResourceTestBase),
		WithAgentClientHTTPClient(capture),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	doer, err := client.RegisteredAgentResourceHTTPDoer()
	if err != nil {
		t.Fatalf("RegisteredAgentResourceHTTPDoer: %v", err)
	}
	return doer, capture
}

// Every access route answers exactly one method. Each accepted spelling of
// each route is tried with every method a caller could send, so a route that
// gains a second method, or loses its own, fails here.
func TestRegisteredAgentResourceHTTPDoer_AccessRoutesAllowOneMethodEach(t *testing.T) {
	doer, capture := newRegisteredAgentResourceTestDoer(t)

	routes := []struct {
		name   string
		method string
		paths  []string
	}{
		{
			name: "list for every resource", method: http.MethodGet,
			paths: []string{"/v1/access-requests"},
		},
		{
			name: "list for one resource", method: http.MethodGet,
			paths: []string{
				"/v1/resources/qcrid/access-requests",
				"/v1/resources/Resource_ID-9/access-requests",
			},
		},
		{
			name: "approve", method: http.MethodPost,
			paths: []string{
				"/v1/resources/qcrid/access-requests/000000/approve",
				"/v1/resources/qcrid/access-requests/999999/approve",
				"/v1/resources/Resource_ID-9/access-requests/012345/approve",
			},
		},
		{
			name: "deny by code", method: http.MethodDelete,
			paths: []string{
				"/v1/resources/qcrid/access-requests/000000",
				"/v1/resources/qcrid/access-requests/999999",
				"/v1/resources/Resource_ID-9/access-requests/012345",
			},
		},
		{
			name: "deny by device id", method: http.MethodDelete,
			paths: []string{
				"/v1/resources/qcrid/access-requests/abcd-efgh-ijkl-mnop",
				"/v1/resources/qcrid/access-requests/aaaa-zzzz-2222-7777",
				"/v1/resources/Resource_ID-9/access-requests/2345-67qr-s2t3-u4v5",
				// Every character is a digit, and it is still a device id.
				"/v1/resources/qcrid/access-requests/2345-6723-4567-2345",
			},
		},
		{
			name: "remove an approved device", method: http.MethodDelete,
			paths: []string{
				"/v1/resources/qcrid/allowed-passkeys/abcd-efgh-ijkl-mnop",
				"/v1/resources/qcrid/allowed-passkeys/aaaa-zzzz-2222-7777",
				"/v1/resources/Resource_ID-9/allowed-passkeys/2345-67qr-s2t3-u4v5",
			},
		},
	}
	methods := []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect,
		"get", "post", "delete",
	}

	wantCalls := 0
	for _, route := range routes {
		for _, path := range route.paths {
			for _, method := range methods {
				req, err := http.NewRequestWithContext(context.Background(), method,
					registeredAgentResourceTestBase+path, http.NoBody)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := doer.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if method == route.method {
					wantCalls++
					if err != nil {
						t.Errorf("%s: %s %s = %v, want allowed", route.name, method, path, err)
					}
					continue
				}
				if !errors.Is(err, ErrRegisteredAgentResourceRequestDenied) {
					t.Errorf("%s: %s %s = %v, want request denied", route.name, method, path, err)
				}
			}
		}
	}
	if capture.calls != wantCalls {
		t.Fatalf("wire calls = %d, want %d: a refused method reached the network or an allowed one did not", capture.calls, wantCalls)
	}
}

// Each request below is one edit away from an access route. Every one is
// refused before the device credential is attached and before any network I/O.
func TestRegisteredAgentResourceHTTPDoer_AccessRouteNearMissesAreRefused(t *testing.T) {
	doer, capture := newRegisteredAgentResourceTestDoer(t)

	const (
		base     = registeredAgentResourceTestBase
		requests = base + "/v1/resources/qcrid/access-requests"
		passkeys = base + "/v1/resources/qcrid/allowed-passkeys"
	)
	nearMisses := []struct{ name, method, target string }{
		// The list for every resource.
		{"all: trailing slash", http.MethodGet, base + "/v1/access-requests/"},
		{"all: extra segment", http.MethodGet, base + "/v1/access-requests/012345"},
		{"all: query", http.MethodGet, base + "/v1/access-requests?limit=20"},
		{"all: empty query", http.MethodGet, base + "/v1/access-requests?"},
		{"all: singular", http.MethodGet, base + "/v1/access-request"},
		{"all: longer name", http.MethodGet, base + "/v1/access-requestsx"},
		{"all: other case", http.MethodGet, base + "/v1/Access-Requests"},
		{"all: underscore", http.MethodGet, base + "/v1/access_requests"},
		{"all: doubled slash", http.MethodGet, base + "/v1//access-requests"},
		{"all: outside the client's path prefix", http.MethodGet, "https://api.example.test/v1/access-requests"},
		{"all: other host", http.MethodGet, "https://other.example.test/prefix/v1/access-requests"},
		{"all: approve with no resource", http.MethodPost, base + "/v1/access-requests/012345/approve"},
		{"all: deny with no resource", http.MethodDelete, base + "/v1/access-requests/012345"},

		// The list for one resource.
		{"one: trailing slash", http.MethodGet, requests + "/"},
		{"one: page size", http.MethodGet, requests + "?limit=20"},
		{"one: cursor", http.MethodGet, requests + "?cursor=next"},
		{"one: empty query", http.MethodGet, requests + "?"},
		{"one: read a single request", http.MethodGet, requests + "/012345"},
		{"one: singular", http.MethodGet, base + "/v1/resources/qcrid/access-request"},
		{"one: other case", http.MethodGet, base + "/v1/resources/qcrid/Access-Requests"},
		{"one: underscore", http.MethodGet, base + "/v1/resources/qcrid/access_requests"},
		{"one: resource id with a dot", http.MethodGet, base + "/v1/resources/bad.id/access-requests"},
		{"one: empty resource id", http.MethodGet, base + "/v1/resources//access-requests"},
		{"one: nested one level deeper", http.MethodGet, base + "/v1/resources/qcrid/x/access-requests"},
		{"one: clear every request", http.MethodDelete, requests},
		{"one: create a request", http.MethodPost, requests},
		{"one: a resource with this name gains no query", http.MethodGet, base + "/v1/resources/access-requests?limit=20"},

		// Approve.
		{"approve: trailing slash", http.MethodPost, requests + "/012345/approve/"},
		{"approve: extra segment", http.MethodPost, requests + "/012345/approve/extra"},
		{"approve: query", http.MethodPost, requests + "/012345/approve?x=1"},
		{"approve: empty query", http.MethodPost, requests + "/012345/approve?"},
		{"approve: five digits", http.MethodPost, requests + "/01234/approve"},
		{"approve: seven digits", http.MethodPost, requests + "/0123456/approve"},
		{"approve: letter in the code", http.MethodPost, requests + "/01234a/approve"},
		{"approve: signed code", http.MethodPost, requests + "/-12345/approve"},
		{"approve: plus sign", http.MethodPost, requests + "/+12345/approve"},
		{"approve: hexadecimal", http.MethodPost, requests + "/0x1234/approve"},
		{"approve: exponent", http.MethodPost, requests + "/1e5000/approve"},
		{"approve: escaped digit", http.MethodPost, requests + "/01234%35/approve"},
		{"approve: empty code", http.MethodPost, requests + "//approve"},
		{"approve: no code", http.MethodPost, requests + "/approve"},
		{"approve: device id for a code", http.MethodPost, requests + "/abcd-efgh-ijkl-mnop/approve"},
		{"approve: device id made of digits for a code", http.MethodPost, requests + "/2345-6723-4567-2345/approve"},
		{"approve: other verb", http.MethodPost, requests + "/012345/deny"},
		{"approve: longer verb", http.MethodPost, requests + "/012345/approved"},
		{"approve: other case", http.MethodPost, requests + "/012345/Approve"},
		{"approve: post to the code", http.MethodPost, requests + "/012345"},
		{"approve: resource id with a dot", http.MethodPost, base + "/v1/resources/bad.id/access-requests/012345/approve"},
		{"approve: under approved devices", http.MethodPost, passkeys + "/abcd-efgh-ijkl-mnop/approve"},
		{"approve: under sessions", http.MethodPost, base + "/v1/resources/qcrid/sessions/012345/approve"},
		{"approve: under links", http.MethodPost, base + "/v1/resources/qcrid/qurls/012345/approve"},

		// Deny.
		{"deny: trailing slash", http.MethodDelete, requests + "/012345/"},
		{"deny: extra segment", http.MethodDelete, requests + "/012345/extra"},
		{"deny: delete the approval", http.MethodDelete, requests + "/012345/approve"},
		{"deny: query", http.MethodDelete, requests + "/012345?x=1"},
		{"deny: empty query", http.MethodDelete, requests + "/012345?"},
		{"deny: five digits", http.MethodDelete, requests + "/01234"},
		{"deny: seven digits", http.MethodDelete, requests + "/0123456"},
		{"deny: letters", http.MethodDelete, requests + "/abcdef"},
		{"deny: trailing letter", http.MethodDelete, requests + "/01234x"},
		{"deny: escaped digit", http.MethodDelete, requests + "/01234%35"},
		{"deny: empty code", http.MethodDelete, requests + "/"},
		{"deny: id shape of sibling routes", http.MethodDelete, requests + "/at_link-1"},
		{"deny: resource id with a dot", http.MethodDelete, base + "/v1/resources/bad.id/access-requests/012345"},

		// Deny by the device id a listing shows.
		{"deny by device: trailing slash", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop/"},
		{"deny by device: extra segment", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop/extra"},
		{"deny by device: delete the approval", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop/approve"},
		{"deny by device: query", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop?x=1"},
		{"deny by device: empty query", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop?"},
		{"deny by device: upper case", http.MethodDelete, requests + "/ABCD-EFGH-IJKL-MNOP"},
		{"deny by device: one upper case letter", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnoP"},
		{"deny by device: digit 0", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno0"},
		{"deny by device: digit 1", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno1"},
		{"deny by device: digit 8", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno8"},
		{"deny by device: digit 9", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno9"},
		{"deny by device: short last group", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno"},
		{"deny by device: long last group", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnopq"},
		{"deny by device: short first group, long second", http.MethodDelete, requests + "/abc-defgh-ijkl-mnop"},
		{"deny by device: three groups", http.MethodDelete, requests + "/abcd-efgh-ijkl"},
		{"deny by device: five groups", http.MethodDelete, requests + "/abcd-efgh-ijkl-mnop-qrst"},
		{"deny by device: no hyphens", http.MethodDelete, requests + "/abcdefghijklmnop"},
		{"deny by device: nineteen letters", http.MethodDelete, requests + "/abcdefghijklmnopqrs"},
		{"deny by device: nineteen digits", http.MethodDelete, requests + "/2345672345672345672"},
		{"deny by device: nineteen characters of the sibling id shape", http.MethodDelete, requests + "/at_link-1_at_link-1"},
		{"deny by device: a code joined to groups, nineteen characters", http.MethodDelete, requests + "/234567-abcd-efgh-ij"},
		{"deny by device: underscores", http.MethodDelete, requests + "/abcd_efgh_ijkl_mnop"},
		{"deny by device: hyphen in a group", http.MethodDelete, requests + "/abcd-efgh-ijkl-mn-p"},
		{"deny by device: doubled hyphen", http.MethodDelete, requests + "/abcd--fgh-ijkl-mnop"},
		{"deny by device: padding", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno="},
		{"deny by device: escaped letter", http.MethodDelete, requests + "/abcd-efgh-ijkl-mno%70"},
		{"deny by device: with no resource", http.MethodDelete, base + "/v1/access-requests/abcd-efgh-ijkl-mnop"},
		{"deny by device: resource id with a dot", http.MethodDelete, base + "/v1/resources/bad.id/access-requests/abcd-efgh-ijkl-mnop"},

		// Remove an approved device.
		{"device: list", http.MethodGet, passkeys},
		{"device: clear every device", http.MethodDelete, passkeys},
		{"device: add", http.MethodPost, passkeys},
		{"device: empty id", http.MethodDelete, passkeys + "/"},
		{"device: trailing slash", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnop/"},
		{"device: extra segment", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnop/extra"},
		{"device: query", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnop?x=1"},
		{"device: empty query", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnop?"},
		{"device: upper case", http.MethodDelete, passkeys + "/ABCD-EFGH-IJKL-MNOP"},
		{"device: one upper case letter", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnoP"},
		{"device: digit 0", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno0"},
		{"device: digit 1", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno1"},
		{"device: digit 8", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno8"},
		{"device: digit 9", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno9"},
		{"device: short last group", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno"},
		{"device: long last group", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnopq"},
		{"device: three groups", http.MethodDelete, passkeys + "/abcd-efgh-ijkl"},
		{"device: five groups", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mnop-qrst"},
		{"device: no hyphens", http.MethodDelete, passkeys + "/abcdefghijklmnop"},
		{"device: no hyphens, padded to length", http.MethodDelete, passkeys + "/abcdefghijklmnopqrs"},
		{"device: underscores", http.MethodDelete, passkeys + "/abcd_efgh_ijkl_mnop"},
		{"device: hyphen one place early", http.MethodDelete, passkeys + "/abc-defgh-ijkl-mnop"},
		{"device: hyphen in a group", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mn-p"},
		{"device: doubled hyphen", http.MethodDelete, passkeys + "/abcd--fgh-ijkl-mnop"},
		{"device: padding", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno="},
		{"device: escaped letter", http.MethodDelete, passkeys + "/abcd-efgh-ijkl-mno%70"},
		{"device: code for a device id", http.MethodDelete, passkeys + "/012345"},
		{"device: id shape of sibling routes", http.MethodDelete, passkeys + "/at_link-1"},
		{"device: singular", http.MethodDelete, base + "/v1/resources/qcrid/allowed-passkey/abcd-efgh-ijkl-mnop"},
		{"device: underscore", http.MethodDelete, base + "/v1/resources/qcrid/allowed_passkeys/abcd-efgh-ijkl-mnop"},
		{"device: with no resource", http.MethodDelete, base + "/v1/allowed-passkeys/abcd-efgh-ijkl-mnop"},
		{"device: resource id with a dot", http.MethodDelete, base + "/v1/resources/bad.id/allowed-passkeys/abcd-efgh-ijkl-mnop"},
	}
	for _, test := range nearMisses {
		req, err := http.NewRequestWithContext(context.Background(), test.method, test.target, http.NoBody)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		resp, err := doer.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrRegisteredAgentResourceRequestDenied) {
			t.Errorf("%s: %s %s = %v, want request denied", test.name, test.method, test.target, err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("%s: refused request gained Authorization", test.name)
		}
	}

	// A URL built by hand can carry characters that a parsed URL would have
	// reported as an escaped path and been refused for. These reach the route
	// check itself: digits and letters that are not ASCII, in segments of
	// exactly the accepted byte length.
	unparsed := []struct{ name, method, path string }{
		{"approve: fullwidth digits, six bytes", http.MethodPost, "/v1/resources/qcrid/access-requests/１２/approve"},
		{"approve: Arabic-Indic digits, six bytes", http.MethodPost, "/v1/resources/qcrid/access-requests/٠١٢/approve"},
		{"approve: space around the code", http.MethodPost, "/v1/resources/qcrid/access-requests/ 1234 /approve"},
		{"approve: newline in the code", http.MethodPost, "/v1/resources/qcrid/access-requests/12345\n/approve"},
		{"deny: fullwidth digits, six bytes", http.MethodDelete, "/v1/resources/qcrid/access-requests/１２"},
		{"deny: NUL in the code", http.MethodDelete, "/v1/resources/qcrid/access-requests/12345\x00"},
		{"deny by device: accented letter, nineteen bytes", http.MethodDelete, "/v1/resources/qcrid/access-requests/abcd-efgh-ijkl-mn\u00f6"},
		{"deny by device: non-breaking hyphens", http.MethodDelete, "/v1/resources/qcrid/access-requests/abcd\u2011efgh\u2011ijkl\u2011mnop"},
		{"deny by device: space for a letter", http.MethodDelete, "/v1/resources/qcrid/access-requests/abcd-efgh-ijkl-mno "},
		{"approve: device id with a space for a letter", http.MethodPost, "/v1/resources/qcrid/access-requests/abcd-efgh-ijkl-mno /approve"},
		{"device: accented letter, nineteen bytes", http.MethodDelete, "/v1/resources/qcrid/allowed-passkeys/abcd-efgh-ijkl-mnö"},
		{"device: non-breaking hyphens", http.MethodDelete, "/v1/resources/qcrid/allowed-passkeys/abcd‑efgh‑ijkl‑mnop"},
		{"device: space for a letter", http.MethodDelete, "/v1/resources/qcrid/allowed-passkeys/abcd-efgh-ijkl-mno "},
	}
	for _, test := range unparsed {
		req := &http.Request{
			Method: test.method,
			URL:    &url.URL{Scheme: "https", Host: "api.example.test", Path: "/prefix" + test.path},
			Header: make(http.Header),
		}
		resp, err := doer.Do(req.WithContext(context.Background()))
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrRegisteredAgentResourceRequestDenied) {
			t.Errorf("%s: %s %q = %v, want request denied", test.name, test.method, test.path, err)
		}
	}

	if capture.calls != 0 {
		t.Fatalf("refused requests reached the network %d times", capture.calls)
	}
}

// The request code is exactly six ASCII digits. Every length around six and
// every single-byte change to a valid code is tried, so the accepted set is
// pinned from both sides.
func TestRegisteredAgentAccessRequestCodeIsExactlySixASCIIDigits(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"000000", "012345", "999999", "480213"} {
		if !registeredAgentAccessRequestCodeAllowed(code) {
			t.Errorf("code %q refused, want allowed", code)
		}
	}
	for length := range 13 {
		code := strings.Repeat("7", length)
		if got, want := registeredAgentAccessRequestCodeAllowed(code), length == 6; got != want {
			t.Errorf("%d digits allowed = %t, want %t", length, got, want)
		}
	}
	const valid = "012345"
	for position := range len(valid) {
		for b := range 256 {
			mutated := []byte(valid)
			mutated[position] = byte(b)
			want := b >= '0' && b <= '9'
			if got := registeredAgentAccessRequestCodeAllowed(string(mutated)); got != want {
				t.Errorf("byte 0x%02x at position %d allowed = %t, want %t", b, position, got, want)
			}
		}
	}
}

// The device identifier is four groups of four lowercase base32 characters
// joined by hyphens, and nothing else of the same length or a nearby one.
func TestRegisteredAgentPasskeyDeviceIDIsExactlyTheDisplayedForm(t *testing.T) {
	t.Parallel()

	for _, id := range []string{
		"abcd-efgh-ijkl-mnop",
		"qrst-uvwx-yz23-4567",
		"aaaa-aaaa-aaaa-aaaa",
		"7777-7777-7777-7777",
		"a2z7-7z2a-2a7z-z7a2",
	} {
		if !registeredAgentPasskeyDeviceIDAllowed(id) {
			t.Errorf("device id %q refused, want allowed", id)
		}
	}

	const valid = "abcd-efgh-ijkl-mnop"
	for length := range len(valid) + 6 {
		if length == len(valid) {
			continue
		}
		// Extend or cut the valid form, keeping its grouping where it has one.
		id := (valid + "-qrst-")[:length]
		if registeredAgentPasskeyDeviceIDAllowed(id) {
			t.Errorf("device id %q of length %d allowed, want refused", id, length)
		}
	}
	for position := range len(valid) {
		for b := range 256 {
			mutated := []byte(valid)
			mutated[position] = byte(b)
			var want bool
			if valid[position] == '-' {
				want = b == '-'
			} else {
				want = (b >= 'a' && b <= 'z') || (b >= '2' && b <= '7')
			}
			if got := registeredAgentPasskeyDeviceIDAllowed(string(mutated)); got != want {
				t.Errorf("byte 0x%02x at position %d allowed = %t, want %t", b, position, got, want)
			}
		}
	}
	// A hyphen is a separator only: it is refused in every character position.
	for _, id := range []string{
		"-bcd-efgh-ijkl-mnop", "abc--efgh-ijkl-mnop", "abcd-efgh-ijkl-mno-",
		"abcde-fgh-ijkl-mnop", "abcdefgh-ijkl-mnop-", "-------------------",
	} {
		if registeredAgentPasskeyDeviceIDAllowed(id) {
			t.Errorf("device id %q allowed, want refused", id)
		}
	}
}

// A waiting request is refused by its code or by the device id a listing
// shows; it is approved by its code only. The route check is asked directly,
// with every single-byte change to each accepted shape and every nearby
// length, so the accepted set of each route is pinned from both sides.
func TestRegisteredAgentAccessRequestRoutesTakeTheirOwnShapesOnly(t *testing.T) {
	t.Parallel()

	const (
		prefix   = "/v1/resources/qcrid/access-requests/"
		code     = "012345"
		deviceID = "abcd-efgh-ijkl-mnop"
	)
	deny := func(segment string) bool {
		return registeredAgentResourceRouteAllowed(http.MethodDelete, prefix+segment)
	}
	approve := func(segment string) bool {
		return registeredAgentResourceRouteAllowed(http.MethodPost, prefix+segment+"/approve")
	}

	if !deny(code) || !deny(deviceID) {
		t.Fatalf("deny by code = %t, by device id = %t; want both allowed", deny(code), deny(deviceID))
	}
	if !approve(code) {
		t.Fatal("approve by code refused, want allowed")
	}
	if approve(deviceID) {
		t.Fatal("approve accepted a device id; approval takes a code only")
	}

	for position := range len(code) {
		for b := range 256 {
			mutated := []byte(code)
			mutated[position] = byte(b)
			want := b >= '0' && b <= '9'
			if got := deny(string(mutated)); got != want {
				t.Errorf("deny: code with byte 0x%02x at position %d allowed = %t, want %t", b, position, got, want)
			}
			if got := approve(string(mutated)); got != want {
				t.Errorf("approve: code with byte 0x%02x at position %d allowed = %t, want %t", b, position, got, want)
			}
		}
	}
	for position := range len(deviceID) {
		for b := range 256 {
			mutated := []byte(deviceID)
			mutated[position] = byte(b)
			var want bool
			if deviceID[position] == '-' {
				want = b == '-'
			} else {
				want = (b >= 'a' && b <= 'z') || (b >= '2' && b <= '7')
			}
			if got := deny(string(mutated)); got != want {
				t.Errorf("deny: device id with byte 0x%02x at position %d allowed = %t, want %t", b, position, got, want)
			}
			if approve(string(mutated)) {
				t.Errorf("approve accepted a device id with byte 0x%02x at position %d", b, position)
			}
		}
	}

	// Length alone never qualifies a segment. "7" is both a digit and a base32
	// character, so a run of them is the hardest case for either shape.
	for length := range 26 {
		sevens := strings.Repeat("7", length)
		if got, want := deny(sevens), length == len(code); got != want {
			t.Errorf("deny: %d sevens allowed = %t, want %t", length, got, want)
		}
		if got, want := approve(sevens), length == len(code); got != want {
			t.Errorf("approve: %d sevens allowed = %t, want %t", length, got, want)
		}
		letters := strings.Repeat("a", length)
		if deny(letters) || approve(letters) {
			t.Errorf("%d letters allowed: deny = %t, approve = %t", length, deny(letters), approve(letters))
		}
		grouped := (deviceID + "-qrst-")[:length]
		if got, want := deny(grouped), len(grouped) == len(deviceID); got != want {
			t.Errorf("deny: %q allowed = %t, want %t", grouped, got, want)
		}
		if approve(grouped) {
			t.Errorf("approve accepted %q", grouped)
		}
	}

	// Neither shape is accepted with another method on the refusal route.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch} {
		for _, segment := range []string{code, deviceID} {
			if registeredAgentResourceRouteAllowed(method, prefix+segment) {
				t.Errorf("%s %s%s allowed, want refused", method, prefix, segment)
			}
		}
	}
}
