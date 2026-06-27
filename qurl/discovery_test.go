package qurl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qv2"
)

// Discovery-provider fail-closed matrix.
//
// Every guard in discovery.go has its own sentinel so each fault can be asserted
// independently and a removed guard reddens exactly one test. These exercise the
// PIN trust path (qv2.ManifestDigest + a FetcherFunc returning the envelope) so no
// manifest signer is needed for the freshness/schema/pin cases; the signed-path
// unknown-kid case is reachable with arbitrary signature bytes because the kid
// lookup precedes signature verification.
//
// KNOWN COVERAGE LIMIT: the signed-manifest ACCEPT path through Resolve (a valid
// signature under a known kid) is not exercised here. Producing a valid manifest
// signature needs qv2's manifestSigningDigest + derToRawLowS, which are unexported in
// the verify-only qv2 package; reimplementing the low-S/DER wire form in this test to
// fake one would duplicate exactly the domain-separated signing scaffolding that
// qv2/manifest.go's separation guard exists to protect, so it is deliberately avoided.
// qv2/manifest_test.go covers qv2.VerifyManifestSignature's accept path directly; only
// the provider's signed-accept WIRING (authenticate -> verifyManifestSig success) is
// uncovered. Open Decision #13 (signed vs pinned as the production default) will pin
// down the signed path; add a qv2 test-only signer then if signed becomes the default.

// fixedNow returns a clock function pinned to t, for deterministic expiry checks.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// issuerDERB64 mints a fresh P-256 issuer key and returns (kid, SPKI-DER base64url),
// the shape a manifest issuer entry carries.
func issuerDERB64(t *testing.T, kid string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return kid, b64url.EncodeToString(der)
}

// validManifest is an in-window, well-formed manifest with one issuer and one relay
// host. Tests mutate a copy to drive each fault.
func validManifest(t *testing.T) Manifest {
	t.Helper()
	kid, derB64 := issuerDERB64(t, "issuer-1")
	return Manifest{
		Profile:        "qurl-v2",
		Version:        7,
		IssuedAt:       1781910000,
		NotAfter:       9999999999, // far future
		Issuers:        []ManifestIssuer{{Kid: kid, SPKIDERB64: derB64}},
		RelayAllowlist: []string{"relay.example.com"},
	}
}

// envelopeBytes marshals m to its exact JSON bytes, wraps them base64url into a
// pin-only ManifestEnvelope, and returns (raw envelope JSON, pin over the exact
// manifest bytes). The pin is computed over the SAME bytes that are embedded, so the
// pin path authenticates by identity with zero re-serialization.
func envelopeBytes(t *testing.T, m Manifest) (raw []byte, pin []byte) {
	t.Helper()
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	env := ManifestEnvelope{ManifestB64: b64url.EncodeToString(manifestJSON)}
	raw, err = json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	digest := qv2.ManifestDigest(manifestJSON)
	return raw, digest[:]
}

// pinnedProvider builds a DiscoveryProvider whose fetcher returns raw and whose trust
// mode is the pin. now overrides the clock (zero value uses time.Now).
func pinnedProvider(t *testing.T, raw, pin []byte, now func() time.Time) *DiscoveryProvider {
	t.Helper()
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:   FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
		PinSHA256: pin,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("new discovery provider: %v", err)
	}
	return p
}

// --- Construction (config) fail-closed -------------------------------------

func TestNewDiscoveryProvider_AuthenticatesNothing_Rejected(t *testing.T) {
	fetch := FetcherFunc(func(context.Context) ([]byte, error) { return nil, nil })

	// No fetcher at all.
	if _, err := NewDiscoveryProvider(DiscoveryConfig{PinSHA256: make([]byte, 32)}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("no fetcher: want ErrDiscoveryConfig, got %v", err)
	}
	// Fetcher but neither pin nor signing keys: would trust blindly.
	if _, err := NewDiscoveryProvider(DiscoveryConfig{Fetcher: fetch}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("no trust mode: want ErrDiscoveryConfig, got %v", err)
	}
	// Wrong-length pin.
	if _, err := NewDiscoveryProvider(DiscoveryConfig{Fetcher: fetch, PinSHA256: []byte{1, 2, 3}}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("short pin: want ErrDiscoveryConfig, got %v", err)
	}
	// RequireSignature with no signing keys.
	if _, err := NewDiscoveryProvider(DiscoveryConfig{Fetcher: fetch, PinSHA256: make([]byte, 32), RequireSignature: true}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("require-sig without keys: want ErrDiscoveryConfig, got %v", err)
	}
}

// --- Happy path ------------------------------------------------------------

// TestDiscoveryProvider_PinnedManifest_Resolves proves the success path: a pinned,
// in-window, well-formed manifest resolves to a usable trust store + allowlist that
// EnterPortalWith accepts (verify a vendored link routed to the manifest's relay).
func TestDiscoveryProvider_PinnedManifest_Resolves(t *testing.T) {
	raw, pin := envelopeBytes(t, validManifest(t))
	p := pinnedProvider(t, raw, pin, nil)

	ts, allow, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve valid pinned manifest: %v", err)
	}
	if ts == nil || allow == nil {
		t.Fatal("resolve returned a nil trust store or allowlist on success")
	}
	// The manifest's relay host must be on the resolved allowlist; an off-list host
	// must be rejected.
	if err := qv2.ValidateRelayURL("https://relay.example.com", allow); err != nil {
		t.Fatalf("manifest relay host should be allowlisted: %v", err)
	}
	if err := qv2.ValidateRelayURL("https://not-the-relay.example.org", allow); !errors.Is(err, qv2.ErrRelayURL) {
		t.Fatalf("off-allowlist host should be rejected: %v", err)
	}
}

// --- Freshness fail-closed -------------------------------------------------

// TestDiscoveryProvider_Expired_FailsClosed is the PROOF's "stale/expired manifest
// fails closed" case: a manifest whose not_after is before the clock is rejected with
// ErrManifestExpired, never served.
func TestDiscoveryProvider_Expired_FailsClosed(t *testing.T) {
	m := validManifest(t)
	// A coherent but past validity window (issued_at < not_after), so the manifest is
	// schema-valid and the EXPIRY guard — not the not_after>issued_at ordering check —
	// is what rejects it once the clock is past not_after.
	m.IssuedAt = 500
	m.NotAfter = 1000
	raw, pin := envelopeBytes(t, m)
	p := pinnedProvider(t, raw, pin, fixedNow(time.Unix(2000, 0)))

	_, _, err := p.Resolve(context.Background())
	if !errors.Is(err, ErrManifestExpired) {
		t.Fatalf("expired manifest: want ErrManifestExpired, got %v", err)
	}
}

// TestDiscoveryProvider_Downgrade_FailsClosed proves the monotonic-version floor: once
// an under-floor manifest is rejected up front as a downgrade. A MinVersion floor
// above the manifest's version isolates the version guard from the pin (the bytes
// authenticate; only the version is wrong).
func TestDiscoveryProvider_Downgrade_FailsClosed(t *testing.T) {
	m := validManifest(t)
	m.Version = 5
	raw, pin := envelopeBytes(t, m)
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:    FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
		PinSHA256:  pin,
		MinVersion: 9, // floor above the manifest's version 5
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestDowngrade) {
		t.Fatalf("under-floor manifest: want ErrManifestDowngrade, got %v", err)
	}
}

// --- Authentication fail-closed --------------------------------------------

// TestDiscoveryProvider_PinMismatch_FailsClosed proves a manifest whose bytes do not
// match the configured pin is rejected — the substitution/downgrade structural guard.
func TestDiscoveryProvider_PinMismatch_FailsClosed(t *testing.T) {
	raw, _ := envelopeBytes(t, validManifest(t))
	wrongPin := make([]byte, 32) // all zeros, will not match
	p := pinnedProvider(t, raw, wrongPin, nil)

	if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestPinMismatch) {
		t.Fatalf("pin mismatch: want ErrManifestPinMismatch, got %v", err)
	}
}

// TestDiscoveryProvider_UnknownKID_FailsClosed drives the signed path: a manifest
// carrying a kid the provider does not know is rejected as unverified (wrapping
// ErrUnknownKID). The kid lookup precedes signature verification, so arbitrary
// signature bytes still reach the unknown-kid rejection.
func TestDiscoveryProvider_UnknownKID_FailsClosed(t *testing.T) {
	manifestJSON, err := json.Marshal(validManifest(t))
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	env := ManifestEnvelope{
		ManifestB64: b64url.EncodeToString(manifestJSON),
		SigB64:      b64url.EncodeToString(make([]byte, 64)), // shape-valid, never reached
		Kid:         "kid-we-do-not-have",
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// A signing key under a DIFFERENT kid, so the manifest's kid is unknown.
	signerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:      FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
		ManifestKeys: map[string]*ecdsa.PublicKey{"some-other-kid": &signerPriv.PublicKey},
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	_, _, err = p.Resolve(context.Background())
	if !errors.Is(err, ErrManifestUnverified) {
		t.Fatalf("unknown manifest kid: want ErrManifestUnverified, got %v", err)
	}
	if !errors.Is(err, qv2.ErrUnknownKID) {
		t.Fatalf("unknown manifest kid: error should wrap ErrUnknownKID, got %v", err)
	}
}

// TestDiscoveryProvider_RequireSignatureButPinOnly_FailsClosed proves RequireSignature
// makes a signature mandatory: a pin-only manifest (no SigB64) is rejected even though
// its pin would otherwise match, because the stronger anchor is required.
func TestDiscoveryProvider_RequireSignatureButPinOnly_FailsClosed(t *testing.T) {
	raw, pin := envelopeBytes(t, validManifest(t)) // pin-only envelope, no signature
	signerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:          FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
		PinSHA256:        pin,
		ManifestKeys:     map[string]*ecdsa.PublicKey{"k1": &signerPriv.PublicKey},
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestUnverified) {
		t.Fatalf("require-sig with pin-only manifest: want ErrManifestUnverified, got %v", err)
	}
}

// --- Schema fail-closed ----------------------------------------------------

// TestDiscoveryProvider_SchemaFaults_FailClosed table-drives the structural guards:
// each malformed manifest is rejected with ErrManifestSchema rather than partially
// accepted. The pin is recomputed per case so authentication passes and the schema
// guard is what bites.
func TestDiscoveryProvider_SchemaFaults_FailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m *Manifest)
	}{
		{"empty issuer set", func(m *Manifest) { m.Issuers = nil }},
		{"empty relay allowlist", func(m *Manifest) { m.RelayAllowlist = nil }},
		{"non-positive version", func(m *Manifest) { m.Version = 0 }},
		{"non-positive issued_at", func(m *Manifest) { m.IssuedAt = 0 }},
		{"non-positive not_after", func(m *Manifest) { m.NotAfter = 0 }},
		{"not_after before issued_at", func(m *Manifest) { m.IssuedAt = 2000; m.NotAfter = 1000 }},
		{"issuer missing kid", func(m *Manifest) { m.Issuers[0].Kid = "" }},
		{"issuer bad DER", func(m *Manifest) { m.Issuers[0].SPKIDERB64 = b64url.EncodeToString([]byte("not-a-key")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest(t)
			tc.mutate(&m)
			raw, pin := envelopeBytes(t, m)
			p := pinnedProvider(t, raw, pin, nil)
			if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestSchema) {
				t.Fatalf("%s: want ErrManifestSchema, got %v", tc.name, err)
			}
		})
	}
}

// TestDiscoveryProvider_ProfileMismatch_FailsClosed proves an ExpectedProfile guard:
// a manifest minted for a different profile/class is rejected as a schema fault.
func TestDiscoveryProvider_ProfileMismatch_FailsClosed(t *testing.T) {
	m := validManifest(t)
	m.Profile = "some-other-profile"
	raw, pin := envelopeBytes(t, m)
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:         FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
		PinSHA256:       pin,
		ExpectedProfile: "qurl-v2",
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestSchema) {
		t.Fatalf("profile mismatch: want ErrManifestSchema, got %v", err)
	}
}

// --- Relay allowlist enforced AFTER sig verify, end to end -----------------

// TestEnterPortal_DiscoveryProvider_RelayOffAllowlist_Rejected wires a DiscoveryProvider
// into the one-arg EnterPortal and proves the PROOF's "unallowlisted relay_url rejected
// (after sig verify)" through the full path: the discovery manifest is authenticated and
// supplies a VALID trust store (the vendored issuer kid, so the link's signature
// verifies) but an allowlist that does NOT contain the link's relay_url. The result is
// ErrRelayURL — reached only after the signature verified, since an unverified link
// would have failed on the kid first.
func TestEnterPortal_DiscoveryProvider_RelayOffAllowlist_Rejected(t *testing.T) {
	link, ts, _ := vendoredAcceptLink(t)

	// A discovery provider whose Resolve returns the vendored trust store (so the
	// signature verifies) and an allowlist missing the link's relay host. Using a
	// providerFunc keeps the focus on the post-verify ordering; the manifest
	// authentication itself is covered by the pin/sig tests above.
	offList := qv2.NewRelayAllowlist([]string{"not-the-relay.example.org"})
	installDefaultProvider(t, providerFunc(func(context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error) {
		return ts, offList, nil
	}))

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, qv2.ErrRelayURL) {
		t.Fatalf("off-allowlist relay after sig verify: want ErrRelayURL, got %v", err)
	}
}
