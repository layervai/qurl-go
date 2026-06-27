package qurl

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HTTPFetcher transport tests. The fetcher is transport-only (auth is the provider's
// job), so these assert the HTTPS-scheme construction guard, the GET/non-2xx/read-cap
// behavior, and that the nil-Client fallback carries a timeout — not any trust logic.

// TestNewHTTPFetcher_RequiresHTTPS proves the construction guard: an empty, malformed,
// or non-https URL is rejected with ErrDiscoveryConfig, while a well-formed https URL
// is accepted. The transport is not a trust boundary (the manifest is pinned/signed),
// but a plaintext http:// manifest URL is a misconfig caught here rather than shipping
// discovery bytes in the clear.
func TestNewHTTPFetcher_RequiresHTTPS(t *testing.T) {
	rejected := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"http", "http://manifest.example.com/m.json"},
		{"no scheme", "manifest.example.com/m.json"},
		{"ftp", "ftp://manifest.example.com/m.json"},
		{"control chars", "https://exa\x7fmple.com"},
	}
	for _, tc := range rejected {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if _, err := NewHTTPFetcher(tc.url, nil); !errors.Is(err, ErrDiscoveryConfig) {
				t.Fatalf("url %q: want ErrDiscoveryConfig, got %v", tc.url, err)
			}
		})
	}
	if _, err := NewHTTPFetcher("https://manifest.example.com/m.json", nil); err != nil {
		t.Fatalf("valid https URL: unexpected error %v", err)
	}
}

// TestHTTPFetcher_Fetch_Success proves the happy path: a 200 response body is returned
// verbatim. The test TLS server's own client is injected so no trust-store wiring is
// needed and no real network is touched.
func TestHTTPFetcher_Fetch_Success(t *testing.T) {
	const want = `{"manifest_b64":"abc"}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	f, err := NewHTTPFetcher(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestHTTPFetcher_Fetch_Non2xx proves a non-2xx status is an error, not a body.
func TestHTTPFetcher_Fetch_Non2xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	f, err := NewHTTPFetcher(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("non-2xx: want error, got nil")
	}
}

// TestHTTPFetcher_Fetch_CapsBody proves the read is capped at maxManifestBytes: a body
// larger than the cap is truncated to exactly the cap rather than read unbounded into
// memory before authentication can reject it.
func TestHTTPFetcher_Fetch_CapsBody(t *testing.T) {
	oversized := bytes.Repeat([]byte("a"), maxManifestBytes+4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	f, err := NewHTTPFetcher(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != maxManifestBytes {
		t.Fatalf("capped body = %d bytes, want %d", len(got), maxManifestBytes)
	}
}

// TestHTTPFetcher_Fetch_ContextCancel proves the fetch honors the caller's context so a
// caller can bound a slow endpoint even on the nil-client path (where the package
// default client's own timeout is the backstop).
func TestHTTPFetcher_Fetch_ContextCancel(t *testing.T) {
	f := &HTTPFetcher{URL: "https://manifest.example.com/m.json"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled
	_, err := f.Fetch(ctx)
	if err == nil {
		t.Fatal("canceled context: want error, got nil")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("error should be wrapped with manifest context, got %v", err)
	}
}

// TestDefaultFetchClient_HasTimeout proves the nil-Client fallback carries a timeout
// (http.DefaultClient does not), so a deadline-free context cannot hang Fetch on a
// slow-trickle endpoint.
func TestDefaultFetchClient_HasTimeout(t *testing.T) {
	if defaultFetchClient.Timeout <= 0 {
		t.Fatalf("defaultFetchClient.Timeout = %v, want a positive bound", defaultFetchClient.Timeout)
	}
}
