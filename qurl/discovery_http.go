package qurl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTP-backed manifest fetcher. Kept in the qurl layer (not qv2) so the qv2 crypto
// core stays standard-library-only and network-free; the discovery provider is the
// layer that does I/O.

// maxManifestBytes caps the discovery response read. A non-secret trust manifest is
// small (a handful of issuer keys + relay hosts); the cap bounds a hostile or
// misconfigured endpoint from streaming an unbounded body into memory before
// authentication has a chance to reject it.
const maxManifestBytes = 1 << 20 // 1 MiB

// defaultFetchTimeout bounds a manifest fetch on the nil-client path so a
// slow-trickle endpoint cannot hang Resolve when the caller passes a deadline-free
// context (e.g. context.Background()). A caller that wants a different bound injects
// its own Client; the cap is a floor of safety, not a tuned value.
const defaultFetchTimeout = 30 * time.Second

// defaultFetchClient is the nil-Client fallback: http.DefaultClient has NO timeout,
// so falling back to it would leave Fetch bounded only by ctx and the read cap. A
// shared package-level client (instead of one per Fetch) keeps the connection pool
// warm and covers both the constructor-nil and struct-literal-nil paths.
//
// CheckRedirect refuses redirects outright. The construction-time https guard only
// covers the FIRST hop, so a 3xx from the (deployment-configured) manifest URL to
// http:// or an internal host would otherwise be followed and silently defeat that
// guard. Trust is anchored on the pin/signature, so following a redirect can never
// admit a bad manifest — but refusing one keeps the transport posture honest and
// avoids surprising cross-origin fetches. A deployment that genuinely needs a CDN
// hop injects its own Client with a redirect policy it controls.
var defaultFetchClient = &http.Client{
	Timeout: defaultFetchTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// HTTPFetcher fetches the discovery envelope over HTTPS. The URL should be the
// published manifest location. Authentication of the fetched bytes is the
// DiscoveryProvider's job (pin or signature) — the fetcher is transport only and the
// transport is NOT a trust boundary here, which is exactly why the manifest is
// pinned/signed rather than trusted because it came from a particular URL.
type HTTPFetcher struct {
	URL    string
	Client HTTPDoer
}

// NewHTTPFetcher builds an HTTPFetcher for rawURL. A nil client uses a shared client
// with defaultFetchTimeout. rawURL is required and MUST be https — the transport is
// not a trust boundary (the manifest is pinned/signed), but rejecting a plaintext
// http:// manifest URL at construction catches a misconfig early and matches the
// "over HTTPS" contract, rather than shipping discovery bytes in the clear.
//
// This is the ONLY supported way to build an HTTPFetcher. The struct's URL/Client
// fields are exported (kept so tests can inject a Client without an https URL via a
// literal), so a struct literal — HTTPFetcher{URL: "http://..."} — SKIPS this scheme
// check entirely and Fetch will GET that plaintext URL. Always go through this
// constructor in production; a literal is a test-only escape hatch. The pin/signature
// is still the trust anchor, so a plaintext fetch cannot admit a bad manifest, but it
// would leak the (non-secret) discovery bytes in the clear, which this guard prevents.
func NewHTTPFetcher(rawURL string, client HTTPDoer) (*HTTPFetcher, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("%w: manifest URL is required", ErrDiscoveryConfig)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest URL is not a valid URL: %w", ErrDiscoveryConfig, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: manifest URL must be https (got %q)", ErrDiscoveryConfig, u.Scheme)
	}
	return &HTTPFetcher{URL: rawURL, Client: client}, nil
}

// Fetch GETs the manifest URL and returns the response body. A non-2xx status is an
// error, and a body larger than maxManifestBytes is rejected (not silently truncated)
// so an oversized response surfaces as a precise "too large" error rather than a
// downstream pin/parse mismatch. On the default (nil-Client) path a redirect is not
// followed: the client returns the 3xx response as-is, which is then rejected here as
// a non-2xx status. Fetch does NOT authenticate the bytes; the provider does.
//
// An injected non-nil Client owns its own timeout AND redirect policy — Fetch cannot
// re-impose either on it, so a caller supplying a Client is responsible for both.
func (f *HTTPFetcher) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("qurl: build manifest request: %w", err)
	}
	client := f.Client
	if client == nil {
		client = defaultFetchClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qurl: GET manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qurl: manifest endpoint returned HTTP %d", resp.StatusCode)
	}
	// Read one byte past the cap so an over-limit body is detectable: if the reader
	// yields maxManifestBytes+1 bytes, the real body was larger than the cap. This
	// gives a precise error instead of handing a truncated body downstream to fail as
	// a confusing pin/parse mismatch.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("qurl: read manifest body: %w", err)
	}
	if len(body) > maxManifestBytes {
		return nil, fmt.Errorf("qurl: manifest body exceeds %d-byte cap", maxManifestBytes)
	}
	return body, nil
}
