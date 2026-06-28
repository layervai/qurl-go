package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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

func TestClient_ConnectorResourceCreatePortal(t *testing.T) {
	var requestCount atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_test_123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")

		switch requestCount.Add(1) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/resources" {
				t.Fatalf("first request = %s %s, want GET /v1/resources", r.Method, r.URL.Path)
			}
			if got, want := r.URL.Query().Get("slug"), "prod-dashboard"; got != want {
				t.Fatalf("slug query = %q, want %q", got, want)
			}
			if got := r.Header.Get("Content-Type"); got != "" {
				t.Fatalf("GET Content-Type = %q, want empty", got)
			}
			fmt.Fprint(w, `{"data":[{"resource_id":"r_connector12","type":"tunnel","status":"active"}]}`)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/r_connector12/qurls" {
				t.Fatalf("second request = %s %s, want POST /v1/resources/r_connector12/qurls", r.Method, r.URL.Path)
			}
			fmt.Fprint(w, `{"data":{"resource_id":"r_connector12","qurl_link":"https://qurl.link/at_connector"}}`)
		default:
			t.Fatalf("unexpected request %d: %s %s", requestCount.Load(), r.Method, r.URL.Path)
		}
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resource, err := client.ConnectorResource(context.Background(), "prod-dashboard")
	if err != nil {
		t.Fatalf("ConnectorResource: %v", err)
	}
	if resource.ID != "r_connector12" || resource.Status != "active" {
		t.Fatalf("resource = %#v", resource)
	}

	portal, err := resource.CreatePortal(context.Background(), ValidFor(5*time.Minute))
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if portal.Link != "https://qurl.link/at_connector" {
		t.Fatalf("portal link = %q", portal.Link)
	}
	if requestCount.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requestCount.Load())
	}
}

func TestClient_ConnectorResourceNotFound(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/resources" || r.URL.Query().Get("slug") != "missing-dashboard" {
			t.Fatalf("request = %s %s?%s, want GET /v1/resources?slug=missing-dashboard", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ConnectorResource(context.Background(), "missing-dashboard")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("ConnectorResource missing: want ErrResourceNotFound, got %v", err)
	}
}

func TestClient_ConnectorResourceAmbiguous(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/resources" || r.URL.Query().Get("slug") != "prod-dashboard" {
			t.Fatalf("request = %s %s?%s, want GET /v1/resources?slug=prod-dashboard", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"resource_id":"r_first12345","status":"active"},{"resource_id":"r_second1234","status":"active"}]}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ConnectorResource(context.Background(), "prod-dashboard")
	if !errors.Is(err, ErrAmbiguousResource) {
		t.Fatalf("ConnectorResource ambiguous: want ErrAmbiguousResource, got %v", err)
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
		t.Fatalf("default redirect policy = %v, want http.ErrUseLastResponse", err)
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
}

func TestClient_Validation(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil credentials: want ErrInvalidClientConfig, got %v", err)
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
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("http://localhost:8080")); err != nil {
		t.Fatalf("loopback base URL: %v", err)
	}

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	blankClient, err := NewClient(BearerToken(""), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient blank bearer: %v", err)
	}
	if _, err := blankClient.ProtectURL(context.Background(), "https://example.com"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("blank bearer: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "ftp://example.com"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("bad target URL: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ProtectURL(context.Background(), "https://"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("empty target host: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ConnectorResource(context.Background(), " "); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("empty connector id: want ErrInvalidResourceRequest, got %v", err)
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
	if _, err := client.CreatePortal(context.Background(), &Resource{ID: "r_demo1234567"}, MaxSessions(1001)); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("max sessions: want ErrInvalidPortalRequest, got %v", err)
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

func TestOpenClientContextValidatesDefaultCredentials(t *testing.T) {
	const wantURL = "https://api.example.test"
	type contextKey struct{}

	oldProvider := defaultCredentialProvider
	t.Cleanup(func() {
		defaultCredentialProvider = oldProvider
	})

	var validated bool
	defaultCredentialProvider = func(path string) CredentialProvider {
		if path != DefaultIssuerStatePath {
			t.Fatalf("credential path = %q, want %q", path, DefaultIssuerStatePath)
		}
		return CredentialProviderFunc(func(ctx context.Context, req *http.Request) error {
			validated = true
			if got := ctx.Value(contextKey{}); got != "open-client" {
				t.Fatalf("OpenClientContext context value = %v, want open-client", got)
			}
			if got := req.Context().Value(contextKey{}); got != "open-client" {
				t.Fatalf("validation request context value = %v, want open-client", got)
			}
			if got := req.URL.String(); got != wantURL {
				t.Fatalf("validation URL = %q, want %q", got, wantURL)
			}
			req.Header.Set("Authorization", "Bearer lv_test")
			return nil
		})
	}

	ctx := context.WithValue(context.Background(), contextKey{}, "open-client")
	client, err := OpenClientContext(ctx, WithBaseURL(wantURL))
	if err != nil {
		t.Fatalf("OpenClientContext: %v", err)
	}
	if client == nil || !validated {
		t.Fatalf("OpenClientContext did not validate default credentials")
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
	if err == nil || !strings.Contains(err.Error(), "empty API response body") {
		t.Fatalf("ProtectURL empty response: want empty body error, got %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "missing resource_id") {
		t.Fatalf("ProtectURL incomplete response: want missing resource_id error, got %v", err)
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
		{name: "hours", in: 24 * time.Hour, min: time.Minute, want: "1d"},
		{name: "days", in: 7 * 24 * time.Hour, min: time.Minute, want: "7d"},
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
