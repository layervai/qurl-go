package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClient_Publisher(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_test_123"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/me/publisher" || r.URL.RawQuery != "" {
			t.Errorf("request = %s %s, want GET /v1/me/publisher with no query", r.Method, r.URL.RequestURI())
		}
		if body, err := io.ReadAll(r.Body); err != nil || len(body) != 0 {
			t.Errorf("GET body = %q, %v; want empty", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"name":"Acme Docs","verified":false},"meta":{"request_id":"req_1"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	publisher, err := client.Publisher(context.Background())
	if err != nil {
		t.Fatalf("Publisher: %v", err)
	}
	if want := (Publisher{Name: "Acme Docs"}); *publisher != want {
		t.Fatalf("publisher = %#v, want %#v", *publisher, want)
	}
}

// TestClient_PublisherDecodeFailsClosed pins the trust rule on the profile
// read: Verified is true only when the service says so with the JSON literal
// true, and every gap — absent, null, or an unnamed publisher — decodes to the
// unverified zero values. Unknown members are tolerated so a newer service
// keeps working.
func TestClient_PublisherDecodeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want Publisher
	}{
		{"no name", `{"data":{"verified":false}}`, Publisher{}},
		{"null name", `{"data":{"name":null,"verified":false}}`, Publisher{}},
		{"missing verified", `{"data":{"name":"Acme Docs"}}`, Publisher{Name: "Acme Docs"}},
		{"null verified", `{"data":{"name":"Acme Docs","verified":null}}`, Publisher{Name: "Acme Docs"}},
		{"empty object", `{"data":{}}`, Publisher{}},
		{"verified true is reported", `{"data":{"name":"Acme Docs","verified":true}}`, Publisher{Name: "Acme Docs", Verified: true}},
		{"unknown members", `{"data":{"name":"Acme Docs","verified":false,"verified_at":"2026-09-30T00:00:00Z","badge":{"kind":"none"}},"meta":{"request_id":"req_1"},"links":{}}`, Publisher{Name: "Acme Docs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			publisher, err := client.Publisher(context.Background())
			if err != nil {
				t.Fatalf("Publisher: %v", err)
			}
			if *publisher != tc.want {
				t.Fatalf("publisher = %#v, want %#v", *publisher, tc.want)
			}
		})
	}
}

// A successful response that carries no profile at all, or a verified flag that
// is not a JSON boolean, is a contract breach rather than a profile. Neither
// may come back as a Publisher — least of all a verified one.
func TestClient_PublisherRejectsMalformedProfile(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing data", `{"meta":{"request_id":"req_1"}}`},
		{"null data", `{"data":null}`},
		{"string verified", `{"data":{"name":"Acme Docs","verified":"true"}}`},
		{"numeric verified", `{"data":{"name":"Acme Docs","verified":1}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			publisher, err := client.Publisher(context.Background())
			if publisher != nil || !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("publisher = %#v, err = %v; want nil and ErrInvalidAPIResponse", publisher, err)
			}
		})
	}
}

func TestClient_PublisherAPIErrorPassthrough(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"not_found","title":"Not Found","detail":"no such route"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// A service that predates the route answers 404; that is an API error, not
	// an unnamed publisher.
	publisher, err := client.Publisher(context.Background())
	var apiErr *APIError
	if publisher != nil || !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("publisher = %#v, err = %v; want nil and a 404 *APIError", publisher, err)
	}
}

// TestClient_SetPublisherName pins the request the service contract defines:
// PATCH with a body of exactly {"name": ...}. The request schema has no other
// member — in particular no verified flag — so the body is compared as bytes.
func TestClient_SetPublisherName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		set      string
		wantBody string
		response string
		want     Publisher
	}{
		{
			name:     "set",
			set:      "Acme Docs",
			wantBody: `{"name":"Acme Docs"}`,
			response: `{"data":{"name":"Acme Docs","verified":false},"meta":{"request_id":"req_1"}}`,
			want:     Publisher{Name: "Acme Docs"},
		},
		{
			// An empty name is the explicit request to remove it, so the member
			// must still be sent; the service then omits name from the profile.
			name:     "clear",
			set:      "",
			wantBody: `{"name":""}`,
			response: `{"data":{"verified":false},"meta":{"request_id":"req_2"}}`,
			want:     Publisher{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got, want := r.Header.Get("Authorization"), "Bearer lv_test_123"; got != want {
					t.Errorf("Authorization = %q, want %q", got, want)
				}
				if r.Method != http.MethodPatch || r.URL.Path != "/v1/me/publisher" || r.URL.RawQuery != "" {
					t.Errorf("request = %s %s, want PATCH /v1/me/publisher with no query", r.Method, r.URL.RequestURI())
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", got)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
				}
				if string(body) != tc.wantBody {
					t.Errorf("body = %s, want exactly %s", body, tc.wantBody)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.response)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			publisher, err := client.SetPublisherName(context.Background(), tc.set)
			if err != nil {
				t.Fatalf("SetPublisherName: %v", err)
			}
			if *publisher != tc.want {
				t.Fatalf("publisher = %#v, want %#v", *publisher, tc.want)
			}
		})
	}
}

// The name reaches the service as the caller wrote it, and the body never
// grows a second member whatever the name contains.
func TestClient_SetPublisherNameSendsOnlyTheName(t *testing.T) {
	const name = `Acme & Co. (R+D) "verified":true`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if len(body) != 1 || body["name"] != name {
			t.Errorf("body = %#v, want only name=%q", body, name)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"verified":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.SetPublisherName(context.Background(), name); err != nil {
		t.Fatalf("SetPublisherName: %v", err)
	}
}

// TestClient_SetPublisherNameRejectedByService pins the 400 mapping: the
// service is the authority on naming rules, its rejection is branchable as
// ErrInvalidPublisherName, and the *APIError with the service's reason stays
// matchable.
func TestClient_SetPublisherNameRejectedByService(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"code":"invalid_input","title":"Bad Request","detail":"name must not contain the word verified"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	publisher, err := client.SetPublisherName(context.Background(), "Acme Verified")
	if publisher != nil || !errors.Is(err, ErrInvalidPublisherName) {
		t.Fatalf("publisher = %#v, err = %v; want nil and ErrInvalidPublisherName", publisher, err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("a service rejection must keep the *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest || apiErr.Code != "invalid_input" || !strings.Contains(apiErr.Detail, "verified") {
		t.Fatalf("api error = %#v", apiErr)
	}
}

// Only a 400 is a verdict on the name. Every other failure passes through as a
// plain *APIError so an auth or availability problem never reads as a bad name.
func TestClient_SetPublisherNameOtherAPIErrorsPassThrough(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"code":"denied","title":"Denied"}}`)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, err = client.SetPublisherName(context.Background(), "Acme Docs")
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Fatalf("want a %d *APIError, got %v", status, err)
			}
			if errors.Is(err, ErrInvalidPublisherName) {
				t.Fatalf("HTTP %d must not read as an invalid name: %v", status, err)
			}
		})
	}
}

// The SDK rejects only what can never be valid, and does so before any request.
// Everything else — including names the service will refuse — is forwarded, so
// the service's naming rules are never duplicated here.
func TestClient_SetPublisherNameLocalValidation(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"verified":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for name, value := range map[string]string{
		"invalid UTF-8": "Acme\xff",
		"over the cap":  strings.Repeat("a", maxPublisherNameBytes+1),
	} {
		publisher, err := client.SetPublisherName(context.Background(), value)
		if publisher != nil || !errors.Is(err, ErrInvalidPublisherName) {
			t.Errorf("%s: publisher = %#v, err = %v; want nil and ErrInvalidPublisherName", name, publisher, err)
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			t.Errorf("%s: a local rejection must not carry an *APIError: %v", name, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("locally rejected names reached the service %d times", got)
	}

	// Names the service may well refuse are still its decision to make.
	for name, value := range map[string]string{
		"at the cap":         strings.Repeat("a", maxPublisherNameBytes),
		"control character":  "Acme\x1b[2J",
		"reserved word":      "Verified Publisher",
		"surrounding spaces": "  Acme  ",
	} {
		if _, err := client.SetPublisherName(context.Background(), value); err != nil {
			t.Errorf("%s: forwarded name failed locally: %v", name, err)
		}
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("forwarded names reached the service %d times, want 4", got)
	}
}

func TestClient_PublisherNilClient(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Publisher(context.Background()); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("Publisher on a nil client: want ErrInvalidClientConfig, got %v", err)
	}
	if _, err := nilClient.SetPublisherName(context.Background(), "Acme Docs"); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("SetPublisherName on a nil client: want ErrInvalidClientConfig, got %v", err)
	}
}

func TestClient_PublisherHonorsContext(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"verified":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Publisher(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publisher with a canceled context: want context.Canceled, got %v", err)
	}
	if _, err := client.SetPublisherName(ctx, "Acme Docs"); !errors.Is(err, context.Canceled) {
		t.Fatalf("SetPublisherName with a canceled context: want context.Canceled, got %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("canceled calls reached the service %d times", got)
	}
}
