package qurl

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// installDefaultProvider sets the process-wide default provider for the duration of a
// test and restores the prior value on cleanup, so a settable global never bleeds
// across tests (and never leaves a non-empty default that would break
// TestEnterPortal_EmptyConfig_FailsClosed). All provider-swapping tests MUST go
// through this helper.
//
// CONCURRENCY: this mutates a package-level global, so a test using it (or any test in
// the same package while it runs) MUST NOT call t.Parallel() — doing so turns the
// swap+restore into a data race that -race would correctly flag. The whole package
// relies on Go's default sequential execution within a package; keep it that way.
func installDefaultProvider(t *testing.T, p Provider) {
	t.Helper()
	prev := DefaultProvider()
	SetDefaultProvider(p)
	t.Cleanup(func() { SetDefaultProvider(prev) })
}

// capturingTransport is an http.RoundTripper that records the request URL and then
// fails the transport, so a one-arg EnterPortal routing test can assert the derived
// relay POST target without any real network. The one-arg EnterPortal cannot inject an
// HTTPDoer (transport stays on the EnterPortalWith seam, by design), so the offline
// hook is the process-wide http.DefaultTransport, which relayknock falls back to for a
// nil HTTPClient. installCapturingTransport swaps it in scoped to one test.
type capturingTransport struct {
	gotURL string
}

func (c *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.gotURL = req.URL.String()
	return nil, errors.New("offline test transport")
}

// installCapturingTransport swaps http.DefaultTransport for a capturing-and-erroring
// transport for the duration of a test, restoring the prior value on cleanup. It is the
// only offline seam for the one-arg EnterPortal, whose nil HTTPClient routes through
// http.DefaultClient → http.DefaultTransport.
//
// CONCURRENCY: like installDefaultProvider, this mutates a process-wide global, so a
// test using it MUST NOT call t.Parallel() (nor may any concurrently-running test in
// the package). The scoped swap is only safe under Go's default sequential execution;
// adding t.Parallel() anywhere in this package would make this a -race-flagged data
// race on http.DefaultTransport.
func installCapturingTransport(t *testing.T) *capturingTransport {
	t.Helper()
	ct := &capturingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = prev })
	return ct
}

// installStaticProvider builds a StaticProvider from ts+allow (failing the test on a
// construction error) and installs it as the process-wide default for the test. It
// folds the construct → error-check → install prologue the one-arg EnterPortal tests
// share, leaving each test's distinct ts/allow pairing visible at the call site.
func installStaticProvider(t *testing.T, ts *qv2.TrustStore, allow *qv2.RelayAllowlist) {
	t.Helper()
	sp, err := NewStaticProvider(ts, allow)
	if err != nil {
		t.Fatalf("new static provider: %v", err)
	}
	installDefaultProvider(t, sp)
}

// --- StaticProvider construction -------------------------------------------

func TestNewStaticProvider_NilHalvesRejected(t *testing.T) {
	_, ts, _ := vendoredAcceptLink(t)
	allow := relayExampleAllowlist()

	if _, err := NewStaticProvider(nil, allow); err == nil {
		t.Fatal("nil trust store: want error, got nil")
	}
	if _, err := NewStaticProvider(ts, nil); err == nil {
		t.Fatal("nil allowlist: want error, got nil")
	}
	if _, err := NewStaticProvider(ts, allow); err != nil {
		t.Fatalf("valid static provider: %v", err)
	}
}

// TestStaticProvider_NilReceiver_FailsClosed proves a caller that ignored
// NewStaticProvider's construction error and installed the nil *StaticProvider fails
// closed with ErrNotConfigured rather than panicking on the field read.
func TestStaticProvider_NilReceiver_FailsClosed(t *testing.T) {
	var sp *StaticProvider // typed nil, e.g. from `sp, _ := NewStaticProvider(nil, allow)`
	_, _, err := sp.Resolve(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil StaticProvider receiver: want ErrNotConfigured, got %v", err)
	}
}

// --- One-arg EnterPortal lit up via a provider -----------------------------

// TestEnterPortal_StaticProvider_VerifiesAndRoutes is the headline "lit up" proof:
// the LOCKED one-argument EnterPortal(ctx, link) — no Config — verifies a valid qv2
// link and routes the knock to the derived relay URL, using only a process-wide
// StaticProvider for the trust anchors + allowlist. The capturing transport records the
// POST target and fails the transport, so reaching it proves EnterPortal got through
// parse → verify sig → validate relay_url → derive serverId → build knock with no
// per-call config.
func TestEnterPortal_StaticProvider_VerifiesAndRoutes(t *testing.T) {
	link, ts, cellFingerprint := vendoredAcceptLink(t)
	ct := installCapturingTransport(t)

	installStaticProvider(t, ts, relayExampleAllowlist())

	_, err := EnterPortal(context.Background(), link)

	var relayErr *relayknock.RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("want a *relayknock.RelayError after the POST, got %v", err)
	}
	wantURL := "https://relay.example.com/relay/" + cellFingerprint
	if ct.gotURL != wantURL {
		t.Fatalf("relay POST routed to %q, want %q", ct.gotURL, wantURL)
	}
}

// TestEnterPortal_NoProvider_FailsClosed re-asserts that with NO provider installed,
// the one-arg verb fails closed. It explicitly clears the default (and restores it),
// guarding the production posture independently of test ordering.
func TestEnterPortal_NoProvider_FailsClosed(t *testing.T) {
	installDefaultProvider(t, nil)
	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2.a.b.c")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no provider: want ErrNotConfigured, got %v", err)
	}
}

// TestEnterPortal_StaticProvider_UnknownKID_Rejected drives the unknown-kid rejection
// THROUGH the one-arg EnterPortal, so it exercises the real verify path (the provider
// only supplies anchors; it does not itself check the kid).
func TestEnterPortal_StaticProvider_UnknownKID_Rejected(t *testing.T) {
	link, _, _ := vendoredAcceptLink(t)
	// A provider whose trust store does NOT contain the vector's kid.
	installStaticProvider(t, freshTrustStore(t), relayExampleAllowlist())

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, qv2.ErrUnknownKID) {
		t.Fatalf("unknown kid via one-arg EnterPortal: want ErrUnknownKID, got %v", err)
	}
}

// TestEnterPortal_StaticProvider_RelayOffAllowlist_Rejected drives the off-allowlist
// rejection THROUGH the one-arg EnterPortal. The provider supplies a valid trust store
// (so the signature verifies) but an allowlist that does NOT contain the verified
// relay_url, proving the allowlist is enforced AFTER signature verification.
func TestEnterPortal_StaticProvider_RelayOffAllowlist_Rejected(t *testing.T) {
	link, ts, _ := vendoredAcceptLink(t)
	installStaticProvider(t, ts, qv2.NewRelayAllowlist([]string{"not-the-relay.example.org"}))

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, qv2.ErrRelayURL) {
		t.Fatalf("relay off allowlist via one-arg EnterPortal: want ErrRelayURL, got %v", err)
	}
}

// TestEnterPortal_ProviderError_Propagates proves a provider that itself fails closed
// (e.g. a stale discovery manifest) surfaces its error through EnterPortal unchanged,
// rather than being swallowed into a generic ErrNotConfigured.
func TestEnterPortal_ProviderError_Propagates(t *testing.T) {
	sentinel := errors.New("provider refused: stale")
	installDefaultProvider(t, providerFunc(func(context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error) {
		return nil, nil, sentinel
	}))

	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2.a.b.c")
	if !errors.Is(err, sentinel) {
		t.Fatalf("provider error: want the provider's sentinel, got %v", err)
	}
}

// providerFunc adapts a function to the Provider interface for tests.
type providerFunc func(context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error)

func (f providerFunc) Resolve(ctx context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error) {
	return f(ctx)
}
