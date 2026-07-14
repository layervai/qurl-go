package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestDoAuthorizedJSON_EarlyResponseDoesNotCorruptInFlightRequestBody(t *testing.T) {
	var requestBody io.ReadCloser
	httpClient := doerFunc(func(req *http.Request) (*http.Response, error) {
		requestBody = req.Body
		// Model an early response: a real transport may return while its write
		// goroutine is still consuming req.Body.
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})
	body := struct {
		DeviceID string `json:"device_id"`
	}{DeviceID: "agent-early-response"}
	err := doAuthorizedJSON(context.Background(), httpClient, "https://api.example.test", func(context.Context, *http.Request) error {
		return nil
	}, http.MethodPost, "/v1/test", body, nil)
	if err != nil {
		t.Fatalf("doAuthorizedJSON: %v", err)
	}
	if requestBody == nil {
		t.Fatal("HTTP client did not capture request body")
	}
	defer requestBody.Close()
	raw, err := io.ReadAll(requestBody)
	if err != nil {
		t.Fatalf("read request body after early response: %v", err)
	}
	if got, want := string(raw), `{"device_id":"agent-early-response"}`; got != want {
		t.Fatalf("request body after early response = %q, want %q", got, want)
	}
}

func TestDoAuthorizedJSON_NilOutputPreservesLegacyIgnoreContract(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			httpClient := doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Body:       io.NopCloser(strings.NewReader(`not JSON and intentionally ignored`)),
					Header:     make(http.Header),
				}, nil
			})
			err := doAuthorizedJSON(context.Background(), httpClient, "https://api.example.test", func(context.Context, *http.Request) error {
				return nil
			}, http.MethodPost, "/v1/test", nil, nil)
			if err != nil {
				t.Fatalf("doAuthorizedJSON status %d with nil output: %v", status, err)
			}
		})
	}
}

func TestDoAuthorizedJSON_OversizedSuccessIsDrainedAndClosed(t *testing.T) {
	t.Parallel()

	raw := strings.Repeat("x", maxAPIResponseBodyBytes+100)
	body := &trackingReadCloser{reader: strings.NewReader(raw)}
	httpClient := doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header:     make(http.Header),
		}, nil
	})
	var out map[string]any
	err := doAuthorizedJSON(context.Background(), httpClient, "https://api.example.test", func(context.Context, *http.Request) error {
		return nil
	}, http.MethodGet, "/v1/test", nil, &out)
	if !errors.Is(err, ErrInvalidAPIResponse) {
		t.Fatalf("error = %v, want ErrInvalidAPIResponse", err)
	}
	var outcomeUnknown *apiRequestOutcomeUnknownError
	if !errors.As(err, &outcomeUnknown) {
		t.Fatalf("error = %v, want outcome marker", err)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
	if body.bytesRead != len(raw) {
		t.Fatalf("response bytes read = %d, want %d (capped read plus deferred drain)", body.bytesRead, len(raw))
	}
}

type trackingReadCloser struct {
	reader    *strings.Reader
	bytesRead int
	closed    bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += n
	return n, err
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestClient_ProtectURLThenPortal(t *testing.T) {
	var requestCount atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_test_123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "qurl-go-sdk") {
			t.Fatalf("User-Agent = %q, want qurl-go-sdk prefix", got)
		}
		w.Header().Set("Content-Type", "application/json")

		switch requestCount.Add(1) {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/v1/resources" {
				t.Fatalf("first request = %s %s, want POST /v1/resources", r.Method, r.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create resource body: %v", err)
			}
			assertJSONField(t, body, "target_url", "https://internal.example.com/dashboard")
			assertJSONField(t, body, "description", "Admin dashboard")
			assertJSONField(t, body, "alias", "dev-dashboard")
			fmt.Fprint(w, `{"data":{"resource_id":"r_demo1234567","target_url":"https://internal.example.com/dashboard","status":"active","description":"Admin dashboard","alias":"dev-dashboard","qurl_count":0,"created_at":"2026-06-28T20:00:00Z"}}`)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/r_demo1234567/qurls" {
				t.Fatalf("second request = %s %s, want POST /v1/resources/r_demo1234567/qurls", r.Method, r.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create portal body: %v", err)
			}
			assertJSONField(t, body, "expires_in", "5m")
			assertJSONField(t, body, "label", "Alice")
			assertJSONField(t, body, "one_time_use", true)
			assertJSONField(t, body, "max_sessions", float64(2))
			assertJSONField(t, body, "session_duration", "30s")
			fmt.Fprint(w, `{"data":{"resource_id":"r_demo1234567","qurl_id":"q_demo1234567","qurl_link":"https://qurl.link/at_demo123","qurl_site":"https://r_demo1234567.qurl.site","expires_at":"2026-06-28T20:05:00Z","label":"Alice"}}`)
		default:
			t.Fatalf("unexpected request %d: %s %s", requestCount.Load(), r.Method, r.URL.Path)
		}
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resource, err := client.ProtectURL(context.Background(),
		"https://internal.example.com/dashboard",
		WithDescription("Admin dashboard"),
		WithAlias("dev-dashboard"),
	)
	if err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
	if resource.ID != "r_demo1234567" || resource.TargetURL != "https://internal.example.com/dashboard" {
		t.Fatalf("resource = %#v", resource)
	}
	if resource.Alias == nil || *resource.Alias != "dev-dashboard" {
		t.Fatalf("resource alias = %v, want dev-dashboard", resource.Alias)
	}

	portal, err := resource.CreatePortal(context.Background(),
		ValidFor(5*time.Minute),
		WithLabel("Alice"),
		OneTimeUse(),
		MaxSessions(2),
		WithSessionDuration(30*time.Second),
	)
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if portal.ResourceID != resource.ID || portal.Link != "https://qurl.link/at_demo123" || portal.QURLID != "q_demo1234567" {
		t.Fatalf("portal = %#v", portal)
	}
	if requestCount.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requestCount.Load())
	}
}

func TestClient_CreatePortalForURL(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/qurls" {
			t.Fatalf("request = %s %s, want POST /v1/qurls", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		assertJSONField(t, body, "target_url", "https://internal.example.com/report")
		assertJSONField(t, body, "expires_in", "1h")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_report12345","qurl_link":"https://qurl.link/at_report"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	portal, resource, err := client.CreatePortalForURL(context.Background(), "https://internal.example.com/report", ValidFor(time.Hour))
	if err != nil {
		t.Fatalf("CreatePortalForURL: %v", err)
	}
	if portal.ResourceID != "r_report12345" || portal.Link != "https://qurl.link/at_report" {
		t.Fatalf("portal = %#v", portal)
	}
	if resource.ID != "r_report12345" || resource.TargetURL != "https://internal.example.com/report" {
		t.Fatalf("resource = %#v", resource)
	}
	if resource.client != client {
		t.Fatalf("resource is not bound to client")
	}
}

func TestResourceJSONUsesAPINames(t *testing.T) {
	alias := "dev-dashboard"
	resource := &Resource{
		ID:        "r_demo1234567",
		TargetURL: "https://internal.example.com/dashboard",
		Status:    "active",
		Tags:      []string{"prod"},
		Alias:     &alias,
		QURLCount: 2,
	}

	raw, err := json.Marshal(resource)
	if err != nil {
		t.Fatalf("Marshal Resource: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("Unmarshal Resource JSON: %v", err)
	}
	assertJSONField(t, body, "resource_id", "r_demo1234567")
	assertJSONField(t, body, "target_url", "https://internal.example.com/dashboard")
	assertJSONField(t, body, "status", "active")
	assertJSONField(t, body, "alias", "dev-dashboard")
	assertJSONField(t, body, "qurl_count", float64(2))
	if _, ok := body["ID"]; ok {
		t.Fatalf("Resource JSON used Go field name ID: %s", raw)
	}

	resource.QURLCount = 0
	raw, err = json.Marshal(resource)
	if err != nil {
		t.Fatalf("Marshal zero-count Resource: %v", err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("Unmarshal zero-count Resource JSON: %v", err)
	}
	assertJSONField(t, body, "qurl_count", float64(0))
}

func TestClient_ResourceByIDCreatePortal(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/r_stored12345/qurls" {
			t.Fatalf("request = %s %s, want POST /v1/resources/r_stored12345/qurls", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_stored12345","qurl_link":"https://qurl.link/at_stored"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resource := client.ResourceByID("r_stored12345")
	portal, err := resource.CreatePortal(context.Background(), ValidFor(5*time.Minute))
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if portal.Link != "https://qurl.link/at_stored" {
		t.Fatalf("portal link = %q", portal.Link)
	}
}

func TestClient_CreatePortalRejectsResourceFromDifferentClient(t *testing.T) {
	clientA, err := NewClient(BearerToken("lv_test_a"), WithBaseURL("https://api-a.example.com"))
	if err != nil {
		t.Fatalf("NewClient A: %v", err)
	}
	clientB, err := NewClient(BearerToken("lv_test_b"), WithBaseURL("https://api-b.example.com"))
	if err != nil {
		t.Fatalf("NewClient B: %v", err)
	}

	_, err = clientA.CreatePortal(context.Background(), clientB.ResourceByID("r_demo12345"))
	if !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("CreatePortal with foreign resource: want ErrInvalidPortalRequest, got %v", err)
	}
}

func TestClient_CreatePortalSendsExplicitZeroMaxSessions(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/r_demo1234567/qurls" {
			t.Fatalf("request = %s %s, want POST /v1/resources/r_demo1234567/qurls", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode create portal body: %v", err)
		}
		assertJSONField(t, body, "max_sessions", float64(0))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_demo1234567","qurl_link":"https://qurl.link/at_zero"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.CreatePortal(context.Background(), &Resource{ID: "r_demo1234567"}, MaxSessions(0)); err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
}

func TestClient_CredentialProvider(t *testing.T) {
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_dynamic_1"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_demo1234567","target_url":"https://example.com","status":"active"}}`)
	}))
	defer api.Close()

	client, err := NewClient(CredentialProviderFunc(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+fmt.Sprintf("lv_dynamic_%d", calls.Add(1)))
		return nil
	}), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("credential provider calls = %d, want 1", calls.Load())
	}
}

func TestNewClientUsesDefaultHTTPTimeout(t *testing.T) {
	client, err := NewClient(BearerToken("lv_test"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	httpClient, ok := client.httpClient.(*http.Client)
	if !ok {
		t.Fatalf("default HTTP client type = %T, want *http.Client", client.httpClient)
	}
	if httpClient.Timeout != defaultAPIHTTPTimeout {
		t.Fatalf("default HTTP timeout = %s, want %s", httpClient.Timeout, defaultAPIHTTPTimeout)
	}
	if err := httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("default redirect behavior = %v, want http.ErrUseLastResponse", err)
	}
}

func TestClient_DefaultHTTPClientSurfacesRedirectAsAPIError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources" {
			t.Fatalf("request = %s %s, want POST /v1/resources", r.Method, r.URL.Path)
		}
		http.Redirect(w, r, "https://api.example.com/v1/resources", http.StatusMovedPermanently)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("redirect: want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("redirect status = %d, want %d", apiErr.StatusCode, http.StatusMovedPermanently)
	}
}

func TestClient_FileCredentials(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(statePath, []byte(`{"authorization":"Bearer lv_state_123"}`), 0o600); err != nil {
		t.Fatalf("write credential state: %v", err)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_state_123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_state12345","target_url":"https://example.com","status":"active"}}`)
	}))
	defer api.Close()

	client, err := NewClient(FileCredentials(statePath), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
}

func TestClient_FileCredentialsErrors(t *testing.T) {
	client, err := NewClient(FileCredentials(filepath.Join(t.TempDir(), "missing.json")), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrCredentialStateNotFound) {
		t.Fatalf("missing state: want ErrCredentialStateNotFound, got %v", err)
	}

	emptyPath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(emptyPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write empty state: %v", err)
	}
	client, err = NewClient(FileCredentials(emptyPath), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient empty state: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("empty state: want ErrInvalidClientConfig, got %v", err)
	}

	ambiguousPath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(ambiguousPath, []byte(`{"authorization":"Bearer lv_state_123","bearer_token":"lv_state_456"}`), 0o600); err != nil {
		t.Fatalf("write ambiguous state: %v", err)
	}
	client, err = NewClient(FileCredentials(ambiguousPath), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient ambiguous state: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("ambiguous state: want ErrInvalidClientConfig, got %v", err)
	}

	insecurePath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(insecurePath, []byte(`{"authorization":"Bearer lv_state_123"}`), 0o644); err != nil {
		t.Fatalf("write insecure state: %v", err)
	}
	client, err = NewClient(FileCredentials(insecurePath), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient insecure state: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInsecureCredentialStatePermissions) {
		t.Fatalf("insecure state: want ErrInsecureCredentialStatePermissions, got %v", err)
	}

	badHeaderPath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(badHeaderPath, []byte(`{"authorization":"Bearer lv_state_123\r\nX-Bad: yes"}`), 0o600); err != nil {
		t.Fatalf("write bad header state: %v", err)
	}
	client, err = NewClient(FileCredentials(badHeaderPath), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient bad header state: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("bad authorization header: want ErrInvalidClientConfig, got %v", err)
	}

	oversizedPath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("x", maxCredentialStateBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized state: %v", err)
	}
	client, err = NewClient(FileCredentials(oversizedPath), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient oversized state: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("oversized state: want ErrInvalidClientConfig, got %v", err)
	}
}

func TestClient_FileCredentialsRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	err = FileCredentials(filepath.Join(t.TempDir(), "missing.json")).Authorize(ctx, req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FileCredentials canceled context: want context.Canceled, got %v", err)
	}
}

func TestCachedCredentialsCachesReusableAuthorizationHeader(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	provider := CredentialProviderFunc(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer cached_%d", calls.Add(1)))
		return nil
	})
	cached := newCachedCredentials(provider, time.Minute, func() time.Time {
		return now
	})

	req1 := newCredentialTestRequest(t)
	if err := cached.Authorize(context.Background(), req1); err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	if got, want := req1.Header.Get("Authorization"), "Bearer cached_1"; got != want {
		t.Fatalf("first Authorization = %q, want %q", got, want)
	}

	req2 := newCredentialTestRequest(t)
	if err := cached.Authorize(context.Background(), req2); err != nil {
		t.Fatalf("second Authorize: %v", err)
	}
	if got, want := req2.Header.Get("Authorization"), "Bearer cached_1"; got != want {
		t.Fatalf("cached Authorization = %q, want %q", got, want)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1 before ttl expiry", calls.Load())
	}

	now = now.Add(time.Minute + time.Second)
	req3 := newCredentialTestRequest(t)
	if err := cached.Authorize(context.Background(), req3); err != nil {
		t.Fatalf("third Authorize: %v", err)
	}
	if got, want := req3.Header.Get("Authorization"), "Bearer cached_2"; got != want {
		t.Fatalf("refreshed Authorization = %q, want %q", got, want)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls = %d, want 2 after ttl expiry", calls.Load())
	}
}

func TestCachedCredentialsSingleflightsRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	provider := CredentialProviderFunc(func(_ context.Context, req *http.Request) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		req.Header.Set("Authorization", "Bearer refreshed")
		return nil
	})
	cached := CachedCredentials(provider, time.Minute)

	req1 := newCredentialTestRequest(t)
	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- cached.Authorize(context.Background(), req1)
	}()
	<-started

	req2 := newCredentialTestRequest(t)
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- cached.Authorize(context.Background(), req2)
	}()

	close(release)
	if err := <-errCh1; err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	if err := <-errCh2; err != nil {
		t.Fatalf("second Authorize: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", calls.Load())
	}
	if got := req1.Header.Get("Authorization"); got != "Bearer refreshed" {
		t.Fatalf("first Authorization = %q", got)
	}
	if got := req2.Header.Get("Authorization"); got != "Bearer refreshed" {
		t.Fatalf("second Authorization = %q", got)
	}
}

func TestCachedCredentialsPanicDuringRefreshUnblocksWaiters(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	provider := CredentialProviderFunc(func(_ context.Context, req *http.Request) error {
		switch calls.Add(1) {
		case 1:
			close(started)
			<-release
			panic("provider panic")
		default:
			req.Header.Set("Authorization", "Bearer recovered")
			return nil
		}
	})
	cached := CachedCredentials(provider, time.Minute)

	firstReq := newCredentialTestRequest(t)
	panicCh := make(chan any, 1)
	go func() {
		defer func() {
			panicCh <- recover()
		}()
		_ = cached.Authorize(context.Background(), firstReq)
	}()
	<-started

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := newCredentialTestRequest(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- cached.Authorize(waitCtx, req)
	}()

	close(release)
	if got := <-panicCh; got != "provider panic" {
		t.Fatalf("recovered panic = %#v, want provider panic", got)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("waiter Authorize after panic: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer recovered" {
		t.Fatalf("waiter Authorization = %q, want Bearer recovered", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls = %d, want 2", calls.Load())
	}
}

func TestCachedCredentialsValidation(t *testing.T) {
	req := newCredentialTestRequest(t)
	if err := CachedCredentials(nil, time.Minute).Authorize(context.Background(), req); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil provider: want ErrInvalidClientConfig, got %v", err)
	}
	if err := CachedCredentials(BearerToken("lv_test"), 0).Authorize(context.Background(), req); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("zero ttl: want ErrInvalidClientConfig, got %v", err)
	}
	provider := CredentialProviderFunc(func(context.Context, *http.Request) error {
		return nil
	})
	if err := CachedCredentials(provider, time.Minute).Authorize(context.Background(), req); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("missing Authorization: want ErrInvalidClientConfig, got %v", err)
	}
}

func TestClient_Validation(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil credentials: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(CredentialProviderFunc(nil)); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil credential func: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken(""), WithBaseURL("https://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("blank bearer: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test\nbad"), WithBaseURL("https://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("bad bearer header: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test\xff"), WithBaseURL("https://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("high-byte bearer header: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(CachedCredentials(BearerToken(""), time.Minute), WithBaseURL("https://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("cached blank bearer: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(CachedCredentials(BearerToken("lv_test"), 0), WithBaseURL("https://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("cached zero ttl: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("ftp://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("bad base URL: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("http://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("plaintext non-loopback base URL: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://user:pass@api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("base URL with userinfo: want ErrInvalidClientConfig, got %v", err)
	}
	for _, rawURL := range []string{
		"https://api.example.com/prefix?route=wrong",
		"https://api.example.com/prefix?",
		"https://api.example.com/prefix#wrong",
		"https://api.example.com/prefix#",
	} {
		if _, err := NewClient(BearerToken("lv_test"), WithBaseURL(rawURL)); !errors.Is(err, ErrInvalidClientConfig) {
			t.Fatalf("base URL %q: want ErrInvalidClientConfig, got %v", rawURL, err)
		}
	}
	prefixed, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://api.example.com/custom/prefix/"))
	if err != nil {
		t.Fatalf("base URL path prefix: %v", err)
	}
	if prefixed.baseURL != "https://api.example.com/custom/prefix" {
		t.Fatalf("base URL path prefix = %q", prefixed.baseURL)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithIssuerStatePath(filepath.Join(t.TempDir(), "issuer-state.json"))); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("issuer state path on NewClient: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := OpenClientContext(context.Background(), WithIssuerStatePath(" ")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("blank issuer state path: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("http://localhost:8080")); err != nil {
		t.Fatalf("loopback base URL: %v", err)
	}

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "ftp://example.com"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("bad target URL: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("empty target host: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://user:pass@example.com"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("target URL with userinfo: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.CreatePortal(context.Background(), nil); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("nil resource: want ErrInvalidPortalRequest, got %v", err)
	}
	if _, err := client.CreatePortal(context.Background(), &Resource{}); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("empty resource id: want ErrInvalidPortalRequest, got %v", err)
	}
	if _, _, err := client.CreatePortalForURL(context.Background(), "https://example.com", ValidFor(30*time.Second)); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("short expiry: want ErrInvalidPortalRequest, got %v", err)
	}
	if _, err := client.CreatePortal(context.Background(), &Resource{ID: "r_demo1234567"}, WithSessionDuration(500*time.Millisecond)); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("subsecond session duration: want ErrInvalidPortalRequest, got %v", err)
	}
	req, err := buildCreatePortalRequest([]PortalOption{WithSessionDuration(24 * time.Hour)})
	if err != nil {
		t.Fatalf("WithSessionDuration 24h: %v", err)
	}
	if req.SessionDuration != "24h" {
		t.Fatalf("WithSessionDuration 24h = %q, want 24h", req.SessionDuration)
	}
	req, err = buildCreatePortalRequest([]PortalOption{
		MaxSessions(2000),
		WithSessionDuration(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("large server-governed portal options: %v", err)
	}
	if req.MaxSessions == nil || *req.MaxSessions != 2000 {
		t.Fatalf("MaxSessions(2000) = %v, want 2000", req.MaxSessions)
	}
	if req.SessionDuration != "48h" {
		t.Fatalf("WithSessionDuration 48h = %q, want 48h", req.SessionDuration)
	}
	if _, err := client.CreatePortal(context.Background(), &Resource{ID: "r_demo1234567"}, MaxSessions(-1)); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("negative max sessions: want ErrInvalidPortalRequest, got %v", err)
	}
	if _, err := (&Resource{ID: "r_demo1234567"}).CreatePortal(context.Background()); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("unbound resource: want ErrInvalidPortalRequest, got %v", err)
	}
}

func TestValidateCredentialsUsesBaseURL(t *testing.T) {
	const wantURL = "https://api.example.test"
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "validation")
	provider := CredentialProviderFunc(func(ctx context.Context, req *http.Request) error {
		if got := ctx.Value(contextKey{}); got != "validation" {
			t.Fatalf("credential validation context value = %v, want validation", got)
		}
		if got := req.Context().Value(contextKey{}); got != "validation" {
			t.Fatalf("request context value = %v, want validation", got)
		}
		if got := req.URL.String(); got != wantURL {
			t.Fatalf("credential validation URL = %q, want %q", got, wantURL)
		}
		req.Header.Set("Authorization", "Bearer lv_test")
		return nil
	})

	if err := validateCredentials(ctx, provider, wantURL); err != nil {
		t.Fatalf("validateCredentials: %v", err)
	}
}

func TestOpenClientContextValidatesIssuerStatePath(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	if err := os.WriteFile(statePath, []byte(`{"authorization":"Bearer lv_state_123"}`), 0o600); err != nil {
		t.Fatalf("write credential state: %v", err)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_state_123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"resource_id":"r_state12345","target_url":"https://example.com","status":"active"}}`)
	}))
	defer api.Close()

	client, err := OpenClientContext(context.Background(), WithIssuerStatePath(statePath), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("OpenClientContext: %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
}

func TestClient_APIError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"access_denied","title":"Forbidden","detail":"API key cannot create resources"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "access_denied" || !strings.Contains(apiErr.Error(), "API key cannot create resources") {
		t.Fatalf("api error = %#v", apiErr)
	}
}

func TestClient_APIErrorPlainTextBody(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "upstream unavailable\ntry again later")
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadGateway || !strings.Contains(apiErr.Error(), "upstream unavailable try again later") {
		t.Fatalf("api error = %#v", apiErr)
	}
}

func TestClient_APIErrorStructuredDetailIsCapped(t *testing.T) {
	longDetail := strings.Repeat("x", maxAPIErrorSnippetBytes+20)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadGateway)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"detail": longDetail,
			},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if len(apiErr.Detail) != maxAPIErrorSnippetBytes+len("...") || !strings.HasSuffix(apiErr.Detail, "...") {
		t.Fatalf("APIError detail was not capped: len=%d suffix=%q", len(apiErr.Detail), apiErr.Detail[len(apiErr.Detail)-3:])
	}
}

func TestClient_APIErrorSnippetDoesNotSplitUTF8(t *testing.T) {
	longDetail := strings.Repeat("€", maxAPIErrorSnippetBytes)
	snippet := apiErrorBodySnippet([]byte(longDetail))
	if !utf8.ValidString(snippet) {
		t.Fatalf("snippet is not valid UTF-8: %q", snippet)
	}
	if !strings.HasSuffix(snippet, "...") {
		t.Fatalf("snippet suffix = %q, want ellipsis", snippet[len(snippet)-3:])
	}
	if got := strings.TrimSuffix(snippet, "..."); len(got) > maxAPIErrorSnippetBytes {
		t.Fatalf("snippet body length = %d, want <= %d", len(got), maxAPIErrorSnippetBytes)
	}
}

func TestClient_OversizedAPIErrorPreservesStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIResponseBodyBytes+1)))
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("oversized API error: want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadGateway || !strings.Contains(apiErr.Error(), "API response body exceeds") {
		t.Fatalf("oversized API error = %#v", apiErr)
	}
}

type readErrorCloser struct {
	err error
}

func (r readErrorCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r readErrorCloser) Close() error {
	return nil
}

func TestClient_APIErrorReadFailureUnwrapsCause(t *testing.T) {
	client, err := NewClient(
		BearerToken("lv_test"),
		WithBaseURL("https://api.example.com"),
		WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       readErrorCloser{err: context.Canceled},
			}, nil
		})),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ProtectURL(context.Background(), "https://example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("read failure API error: want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("APIError status = %d, want %d", apiErr.StatusCode, http.StatusBadGateway)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("APIError should unwrap context.Canceled, got %v", err)
	}
}

func TestClient_EmptySuccessBodyFailsClosed(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	if !errors.Is(err, ErrInvalidAPIResponse) || !strings.Contains(err.Error(), "empty API response body") {
		t.Fatalf("ProtectURL empty response: want ErrInvalidAPIResponse and empty body detail, got %v", err)
	}
}

func TestClient_IncompleteResourceSuccessFailsClosed(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"target_url":"https://example.com","status":"active"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), "https://example.com")
	if !errors.Is(err, ErrInvalidAPIResponse) || !strings.Contains(err.Error(), "missing resource_id") {
		t.Fatalf("ProtectURL incomplete response: want ErrInvalidAPIResponse and missing resource_id detail, got %v", err)
	}
}

func TestClient_IncompletePortalSuccessFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		body string
		run  func(context.Context, *Client) error
		want string
	}{
		{
			name: "missing portal link",
			body: `{"data":{"resource_id":"r_demo12345"}}`,
			run: func(ctx context.Context, client *Client) error {
				_, err := client.CreatePortal(ctx, &Resource{ID: "r_demo12345"}, ValidFor(5*time.Minute))
				return err
			},
			want: "missing qurl_link",
		},
		{
			name: "missing resource id",
			body: `{"data":{"qurl_link":"https://qurl.link/at_demo"}}`,
			run: func(ctx context.Context, client *Client) error {
				_, _, err := client.CreatePortalForURL(ctx, "https://example.com", ValidFor(5*time.Minute))
				return err
			},
			want: "missing resource_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.body)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			err = tt.run(context.Background(), client)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("incomplete portal response: want %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestClient_APIResponseTooLarge(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIResponseBodyBytes+1)))
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ProtectURL(context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "API response body exceeds") {
		t.Fatalf("too-large response: want precise cap error, got %v", err)
	}
}

func TestFormatAPIDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		min  time.Duration
		want string
	}{
		{name: "seconds", in: 30 * time.Second, min: time.Second, want: "30s"},
		{name: "minutes", in: 5 * time.Minute, min: time.Minute, want: "5m"},
		{name: "hours", in: 24 * time.Hour, min: time.Minute, want: "24h"},
		{name: "long hours", in: 7 * 24 * time.Hour, min: time.Minute, want: "168h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatAPIDuration(tt.in, tt.min)
			if err != nil {
				t.Fatalf("formatAPIDuration: %v", err)
			}
			if got != tt.want {
				t.Fatalf("formatAPIDuration = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := formatAPIDuration(30*time.Second, time.Minute); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("below minimum: want ErrInvalidPortalRequest, got %v", err)
	}
	if _, err := formatAPIDuration(time.Second+time.Millisecond, time.Second); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("subsecond: want ErrInvalidPortalRequest, got %v", err)
	}
}

func assertJSONField(t *testing.T, body map[string]any, key string, want any) {
	t.Helper()
	got, ok := body[key]
	if !ok {
		t.Fatalf("body missing %q: %#v", key, body)
	}
	if got != want {
		t.Fatalf("body[%q] = %#v, want %#v", key, got, want)
	}
}

func newCredentialTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}
