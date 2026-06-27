package qurl

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// HTTP-backed manifest fetcher. Kept in the qurl layer (not qv2) so the qv2 crypto
// core stays standard-library-only and network-free; the discovery provider is the
// layer that does I/O.

// maxManifestBytes caps the discovery response read. A non-secret trust manifest is
// small (a handful of issuer keys + relay hosts); the cap bounds a hostile or
// misconfigured endpoint from streaming an unbounded body into memory before
// authentication has a chance to reject it.
const maxManifestBytes = 1 << 20 // 1 MiB

// HTTPFetcher fetches the discovery envelope over HTTPS. The URL should be the
// published manifest location. Authentication of the fetched bytes is the
// DiscoveryProvider's job (pin or signature) — the fetcher is transport only and the
// transport is NOT a trust boundary here, which is exactly why the manifest is
// pinned/signed rather than trusted because it came from a particular URL.
type HTTPFetcher struct {
	URL    string
	Client HTTPDoer
}

// NewHTTPFetcher builds an HTTPFetcher for url. A nil client uses http.DefaultClient.
// The url is required.
func NewHTTPFetcher(url string, client HTTPDoer) (*HTTPFetcher, error) {
	if url == "" {
		return nil, fmt.Errorf("%w: manifest URL is required", ErrDiscoveryConfig)
	}
	return &HTTPFetcher{URL: url, Client: client}, nil
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
		client = http.DefaultClient
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
