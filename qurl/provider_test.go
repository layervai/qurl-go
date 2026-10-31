package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// installDefaultProvider sets the process-wide default provider for the duration of a
// test and restores the prior value on cleanup, so a settable global never bleeds
// across tests (and never leaves a non-empty default that would break
// TestEnterPortal_EmptyConfig_FailsClosed). All provider-swapping tests MUST go
// through this helper.
//
// The calling test and its ancestors must be non-parallel. guardProcessGlobals
// enforces that at runtime. Other tests can use t.Parallel: Go pauses them while
// a sequential test group owns these process-wide fixtures.
func installDefaultProvider(t *testing.T, p Provider) {
	t.Helper()
	guardProcessGlobals(t)
	prev := DefaultProvider()
	SetDefaultProvider(p)
	t.Cleanup(func() { SetDefaultProvider(prev) })
}

// Setenv supplies testing's ancestor-aware parallel guard and cleanup; the SDK
// never reads this sentinel. It also rejects a later t.Parallel on the same test.
func guardProcessGlobals(t *testing.T) {
	t.Helper()
	t.Setenv("QURL_GO_TEST_PROCESS_GLOBALS", "reserved")
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
// Like installDefaultProvider, this requires a non-parallel test ancestry;
// guardProcessGlobals rejects parallel use before the transport changes.
func installCapturingTransport(t *testing.T) *capturingTransport {
	t.Helper()
	guardProcessGlobals(t)
	ct := &capturingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = prev })
	return ct
}

// installStaticProvider builds a relay-only StaticProvider from ts+allow (failing the
// test on a construction error) and installs it as the process-wide default for the
// test. It folds the construct → error-check → install prologue the one-arg
// EnterPortal tests share, leaving each test's distinct ts/allow pairing visible at
// the call site. Tests that pin cells construct their StaticProvider explicitly.
func installStaticProvider(t *testing.T, ts *TrustStore, allow *RelayAllowlist) {
	t.Helper()
	sp, err := NewStaticProvider(ts, allow, nil)
	if err != nil {
		t.Fatalf("new static provider: %v", err)
	}
	installDefaultProvider(t, sp)
}

// --- StaticProvider construction -------------------------------------------

func TestNewStaticProvider_ConstructionRules(t *testing.T) {
	_, ts, _ := generatedAcceptLink(t)
	allow := relayExampleAllowlist()
	cells := []CellEntry{{
		ServerPublicKeyB64: vectorCellKeyB64(t),
		CellID:             "test-cell",
		Host:               "cell.example.com",
		Port:               standardNHPUDPPort,
	}}

	if _, err := NewStaticProvider(nil, allow, cells); err == nil {
		t.Fatal("nil trust store: want error, got nil")
	}
	// Neither transport: no allowlist and no cells means no open could ever be
	// carried, which must be a construction error rather than a later surprise.
	if _, err := NewStaticProvider(ts, nil, nil); err == nil {
		t.Fatal("no transport (nil allowlist, no cells): want error, got nil")
	}
	if _, err := NewStaticProvider(ts, allow, nil); err != nil {
		t.Fatalf("valid relay-only static provider: %v", err)
	}
	if _, err := NewStaticProvider(ts, nil, cells); err != nil {
		t.Fatalf("valid cells-only static provider: %v", err)
	}
	if _, err := NewStaticProvider(ts, allow, cells); err != nil {
		t.Fatalf("native static provider with an accepted but unused allowlist: %v", err)
	}
}

// TestNewStaticProvider_InvalidCellEntriesPropagate proves a bad pinned cell is
// a loud construction failure: NewStaticProvider validates its entries through
// NewCellCatalog, so the same missing-key/bad-port faults a deployment file
// would reject surface here rather than making that cell's links unusable.
func TestNewStaticProvider_InvalidCellEntriesPropagate(t *testing.T) {
	_, ts, _ := generatedAcceptLink(t)
	allow := relayExampleAllowlist()

	for _, tc := range []struct {
		name  string
		entry CellEntry
		want  string
	}{
		{"missing key", CellEntry{CellID: "c", Host: "cell.example.com", Port: standardNHPUDPPort}, "has no server public key"},
		{"bad port", CellEntry{CellID: "c", Host: "cell.example.com", Port: 62206, ServerPublicKeyB64: vectorCellKeyB64(t)}, "unsupported UDP port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewStaticProvider(ts, allow, []CellEntry{tc.entry})
			if err == nil {
				t.Fatal("invalid cell entry was accepted; its links would be unusable")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestStaticProvider_NilReceiver_FailsClosed proves a caller that ignored
// NewStaticProvider's construction error and installed the nil *StaticProvider fails
// closed with ErrNotConfigured rather than panicking on the field read — on both
// halves of the CellProvider contract.
func TestStaticProvider_NilReceiver_FailsClosed(t *testing.T) {
	var sp *StaticProvider // typed nil, e.g. from `sp, _ := NewStaticProvider(nil, allow, nil)`
	_, _, err := sp.Resolve(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil StaticProvider receiver: want ErrNotConfigured, got %v", err)
	}
	_, err = sp.ResolveCells(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil StaticProvider ResolveCells: want ErrNotConfigured, got %v", err)
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
	link, ts, cellFingerprint := generatedAcceptLink(t)
	ct := installCapturingTransport(t)

	installStaticProvider(t, ts, relayExampleAllowlist())

	_, err := EnterPortal(context.Background(), link)

	var relayErr *RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("want a *qurl.RelayError after the POST, got %v", err)
	}
	wantURL := "https://relay.example.com/relay/" + cellFingerprint
	if ct.gotURL != wantURL {
		t.Fatalf("relay POST routed to %q, want %q", ct.gotURL, wantURL)
	}
}

// TestEnterPortal_NoProvider_FailsClosed verifies an empty deployment fails
// closed when no provider is installed to supply a separate trust configuration.
func TestEnterPortal_NoProvider_FailsClosed(t *testing.T) {
	useEmptyDeployment(t)
	installDefaultProvider(t, nil)
	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no provider: want ErrNotConfigured, got %v", err)
	}
}

// TestEnterPortal_StaticProvider_UnknownKID_Rejected drives the unknown-kid rejection
// THROUGH the one-arg EnterPortal, so it exercises the real verify path (the provider
// only supplies anchors; it does not itself check the kid).
func TestEnterPortal_StaticProvider_UnknownKID_Rejected(t *testing.T) {
	link, _, _ := generatedAcceptLink(t)
	// A provider whose trust store does NOT contain the vector's kid.
	installStaticProvider(t, freshTrustStore(t), relayExampleAllowlist())

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("unknown kid via one-arg EnterPortal: want ErrUnknownKID, got %v", err)
	}
}

// TestEnterPortal_StaticProvider_RelayOffAllowlist_Rejected drives the off-allowlist
// rejection THROUGH the one-arg EnterPortal. The provider supplies a valid trust store
// (so the signature verifies) but an allowlist that does NOT contain the verified
// relay_url, proving the allowlist is enforced AFTER signature verification.
func TestEnterPortal_StaticProvider_RelayOffAllowlist_Rejected(t *testing.T) {
	link, ts, _ := generatedAcceptLink(t)
	installStaticProvider(t, ts, NewRelayAllowlist([]string{"not-the-relay.example.org"}))

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, ErrRelayURL) {
		t.Fatalf("relay off allowlist via one-arg EnterPortal: want ErrRelayURL, got %v", err)
	}
}

// TestEnterPortal_ProviderError_Propagates proves a provider that itself fails closed
// (e.g. a stale discovery manifest) surfaces its error through EnterPortal unchanged,
// rather than being swallowed into a generic ErrNotConfigured.
func TestEnterPortal_ProviderError_Propagates(t *testing.T) {
	sentinel := errors.New("provider refused: stale")
	installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
		return nil, nil, sentinel
	}))

	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ")
	if !errors.Is(err, sentinel) {
		t.Fatalf("provider error: want the provider's sentinel, got %v", err)
	}
}

// providerFunc adapts a function to the Provider interface for tests.
type providerFunc func(context.Context) (*TrustStore, *RelayAllowlist, error)

func (f providerFunc) Resolve(ctx context.Context) (*TrustStore, *RelayAllowlist, error) {
	return f(ctx)
}

func TestGlobalFixtureHelpersRejectParallel(t *testing.T) {
	helpers := []struct {
		name string
		call func(*testing.T)
	}{
		{"provider", func(t *testing.T) { installDefaultProvider(t, nil) }},
		{"transport", func(t *testing.T) { installCapturingTransport(t) }},
	}
	for _, helper := range helpers {
		for _, order := range []string{"before", "after"} {
			t.Run(helper.name+"/"+order, func(t *testing.T) {
				defer func() {
					result := recover()
					if result == nil || !strings.Contains(strings.ToLower(fmt.Sprint(result)), "parallel") {
						t.Errorf("global fixture must reject parallel use, got %v", result)
					}
				}()
				if order == "before" {
					helper.call(t)
					t.Parallel()
				} else {
					t.Parallel()
					helper.call(t)
				}
			})
		}
	}
}
