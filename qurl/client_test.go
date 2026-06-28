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
}

func TestClient_Validation(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil credentials: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := NewClient(BearerToken("lv_test"), WithBaseURL("ftp://api.example.com")); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("bad base URL: want ErrInvalidClientConfig, got %v", err)
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
