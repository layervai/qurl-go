package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// refusingDoer fails the test if the relay is contacted at all. It is the whole
// point of the native UDP path: not "HTTP was avoided when convenient" but "the
// relay was never reached".
type refusingDoer struct {
	t      *testing.T
	called bool
}

func (d *refusingDoer) Do(*http.Request) (*http.Response, error) {
	d.t.Helper()
	d.called = true
	return nil, errors.New("relay must not be contacted on the native UDP path")
}

// unreachableCellCatalog points a cell at loopback. nativeudp refuses to send to
// a non-public address, so the open dies inside the native transport with a
// "nativeudp:" error. That is exactly the signal these tests want: it proves
// WHICH transport took the open, without standing up a full NHP responder, and
// the refusal itself is a real control (a knock must never be aimed inward).
func unreachableCellCatalog(t *testing.T, cellKeyB64 string) *CellCatalog {
	t.Helper()
	catalog, err := NewCellCatalog([]CellEntry{{
		ServerPublicKeyB64: cellKeyB64,
		CellID:             "test-cell",
		Host:               "127.0.0.1",
		Port:               9,
	}})
	if err != nil {
		t.Fatalf("build cell catalog: %v", err)
	}
	return catalog
}

// vectorCellKeyB64 is the accept vector's cell key (32 bytes of 0x44), the key
// the vendored link's claims carry.
func vectorCellKeyB64(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x44
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

// otherCellKeyB64 is a well-formed key no link in these tests carries.
func otherCellKeyB64(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x11
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

// TestEnterPortalWith_KnownCellNeverContactsRelay proves that when the catalog
// covers the cell named in the SIGNED claims, the open goes over native UDP and
// the relay is never contacted — no HTTP request, and no relay allowlist needed,
// because there is no relay URL being acted on.
func TestEnterPortalWith_KnownCellNeverContactsRelay(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	doer := &refusingDoer{t: t}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// No RelayAllowlist at all: on the native UDP path there is nothing to allow.
	_, err := EnterPortalWith(ctx, link, Config{
		TrustStore: trust,
		Cells:      unreachableCellCatalog(t, vectorCellKeyB64(t)),
		HTTPClient: doer,
	})

	if doer.called {
		t.Fatal("native UDP path contacted the relay over HTTP")
	}
	if err == nil {
		t.Fatal("expected a native UDP transport error against an unreachable cell")
	}
	// The absent allowlist must not be what stopped us — that would mean the open
	// never reached the transport and this test proved nothing about routing.
	if errors.Is(err, ErrNotConfigured) {
		t.Fatalf("open failed on configuration, not transport: %v", err)
	}
	// Positively identify the transport rather than inferring it from the relay's
	// silence: the error must come from nativeudp itself.
	if !strings.Contains(err.Error(), "nativeudp:") {
		t.Fatalf("open did not reach the native UDP transport: %v", err)
	}
}

// TestEnterPortalWith_UnknownCellFallsBackToRelay proves the fallback is intact:
// a cell this build has never heard of still opens through the relay, so adding
// a catalog never strands a link.
func TestEnterPortalWith_UnknownCellFallsBackToRelay(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	doer := &refusingDoer{t: t}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := EnterPortalWith(ctx, link, Config{
		TrustStore:     trust,
		Cells:          unreachableCellCatalog(t, otherCellKeyB64(t)),
		RelayAllowlist: NewRelayAllowlist([]string{"relay.example.com"}),
		HTTPClient:     doer,
	})

	if !doer.called {
		t.Fatal("a cell outside the catalog did not fall back to the relay")
	}
	if err == nil {
		t.Fatal("expected the refusing relay doer to surface an error")
	}
}

// TestEnterPortalWith_NoTransportConfiguredFailsBeforeParsing proves a process
// with neither a catalog nor an allowlist reports a CONFIGURATION error rather
// than dragging the caller through a link-parse failure — the diagnostic that
// tells an integrator they forgot setup, not that their link is bad.
func TestEnterPortalWith_NoTransportConfiguredFailsBeforeParsing(t *testing.T) {
	_, trust, _ := vendoredAcceptLink(t)

	_, err := EnterPortalWith(context.Background(), "not-even-a-link", Config{
		TrustStore: trust,
	})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured for a transportless config, got %v", err)
	}
}

// cellAwareProvider is a Provider that also supplies a cell catalog, i.e. one
// that opts into native UDP through the CellProvider extension.
type cellAwareProvider struct {
	trust      *TrustStore
	allow      *RelayAllowlist
	cells      *CellCatalog
	cellsErr   error
	cellsCalls int
}

func (p *cellAwareProvider) Resolve(context.Context) (*TrustStore, *RelayAllowlist, error) {
	return p.trust, p.allow, nil
}

func (p *cellAwareProvider) ResolveCells(context.Context) (*CellCatalog, error) {
	p.cellsCalls++
	return p.cells, p.cellsErr
}

// TestEnterPortal_CellProviderRoutesOverNativeUDP proves the CellProvider
// extension actually reaches the transport: a provider that returns a catalog
// covering the link's cell gets a native UDP open, not a relay one.
func TestEnterPortal_CellProviderRoutesOverNativeUDP(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	provider := &cellAwareProvider{
		trust: trust,
		allow: NewRelayAllowlist([]string{"relay.example.com"}),
		cells: unreachableCellCatalog(t, vectorCellKeyB64(t)),
	}
	prior := DefaultProvider()
	SetDefaultProvider(provider)
	t.Cleanup(func() { SetDefaultProvider(prior) })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := EnterPortal(ctx, link)
	if provider.cellsCalls != 1 {
		t.Fatalf("ResolveCells called %d times, want 1", provider.cellsCalls)
	}
	if err == nil || !strings.Contains(err.Error(), "nativeudp:") {
		t.Fatalf("CellProvider did not route over native UDP: %v", err)
	}
}

// TestEnterPortal_CellProviderErrorFailsClosed proves a provider that cannot
// resolve its cells refuses the open instead of quietly falling back to the
// relay — a catalog that failed to load is unknown state, not "no cells".
func TestEnterPortal_CellProviderErrorFailsClosed(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	provider := &cellAwareProvider{
		trust:    trust,
		allow:    NewRelayAllowlist([]string{"relay.example.com"}),
		cellsErr: errors.New("catalog unavailable"),
	}
	prior := DefaultProvider()
	SetDefaultProvider(provider)
	t.Cleanup(func() { SetDefaultProvider(prior) })

	_, err := EnterPortal(context.Background(), link)
	if err == nil || !strings.Contains(err.Error(), "catalog unavailable") {
		t.Fatalf("a ResolveCells failure did not fail the open: %v", err)
	}
}

// TestNewCellCatalogRejectsDuplicateKeys proves two entries for one cell key is
// a construction error rather than a silent last-wins.
func TestNewCellCatalogRejectsDuplicateKeys(t *testing.T) {
	key := vectorCellKeyB64(t)
	_, err := NewCellCatalog([]CellEntry{
		{ServerPublicKeyB64: key, CellID: "cell-a", Host: "a.example.com", Port: 62206},
		{ServerPublicKeyB64: key, CellID: "cell-b", Host: "b.example.com", Port: 62206},
	})
	if err == nil {
		t.Fatal("duplicate cell keys were silently collapsed")
	}
	if !strings.Contains(err.Error(), "cell-a") || !strings.Contains(err.Error(), "cell-b") {
		t.Fatalf("error does not name both colliding cells: %v", err)
	}
}
