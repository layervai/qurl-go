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
var defaultFetchClient = &http.Client{Timeout: defaultFetchTimeout}

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

// Fetch GETs the manifest URL and returns the response body (capped at
// maxManifestBytes). A non-2xx status is an error. It does NOT authenticate the bytes;
// the provider does.
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("qurl: read manifest body: %w", err)
	}
	return body, nil
}
