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
		{http.MethodPost, "/v1/resources/qcrid/resolve"},
		{http.MethodPost, "/v1/resources/qcrid/qurls"},
		{http.MethodPost, "/v1/qurls"},
		{http.MethodGet, "/v1/me"},
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
		{http.MethodGet, "https://other.example.test/prefix/v1/resources"},
		{http.MethodGet, "https://api.example.test/v1/resources"},
		{http.MethodGet, "https://api.example.test/prefix/v1/api-keys"},
		{http.MethodGet, "https://api.example.test/prefix/v1/customer"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/qurls"},
		{http.MethodDelete, "https://api.example.test/prefix/v1/resources/qcrid/sharing"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/share"},
		{http.MethodGet, "https://api.example.test/prefix/v1/resources/qcrid/resolve"},
		{http.MethodGet, "https://api.example.test/prefix/v1/me?extra=true"},
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
