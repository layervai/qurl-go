package qurl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
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
// The signed-manifest ACCEPT path through Resolve (a valid signature under a known kid
// -> authenticate -> verifyManifestSig success -> trust material built) is covered by
// TestDiscoveryProvider_SignedManifest_Resolves below, which builds a real
// manifest-domain signature with qv2.SignManifest + a LocalSigner. Its companion
// TestDiscoveryProvider_SignedManifest_TamperedRejected serves the same signature over
// MUTATED manifest bytes and asserts the provider rejects it as ErrManifestUnverified,
// so the signed wiring goes red if a regression hands the wrong bytes to
// verifyManifestSig. These providers configure ONLY ManifestKeys (no pin) so the
// signature — not a pin compare — is what authenticates, which is exactly the wiring
// under test.

// fixedNow returns a clock function pinned to t, for deterministic expiry checks.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// issuerDERB64 mints a fresh P-256 issuer key and returns (kid, SPKI-DER base64url),
// the shape a manifest issuer entry carries.
func issuerDERB64(t *testing.T, kid string) (string, string) {
	t.Helper()
	return kid, b64url.EncodeToString(freshP256SPKIDER(t))
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
	// A nil ManifestKeys value is rejected at construction (would otherwise fail closed
	// only on the first signed fetch). Pin is also set so the config is otherwise valid
	// and the ManifestKeys validation is what bites.
	if _, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:      fetch,
		PinSHA256:    make([]byte, 32),
		ManifestKeys: map[string]*ecdsa.PublicKey{"k1": nil},
	}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("nil ManifestKeys value: want ErrDiscoveryConfig, got %v", err)
	}
	// A non-P-256 ManifestKeys value is rejected at construction.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-384 key: %v", err)
	}
	if _, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:      fetch,
		PinSHA256:    make([]byte, 32),
		ManifestKeys: map[string]*ecdsa.PublicKey{"k1": &p384.PublicKey},
	}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("non-P-256 ManifestKeys value: want ErrDiscoveryConfig, got %v", err)
	}
	// An empty kid in ManifestKeys is rejected at construction.
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256 key: %v", err)
	}
	if _, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:      fetch,
		PinSHA256:    make([]byte, 32),
		ManifestKeys: map[string]*ecdsa.PublicKey{"": &good.PublicKey},
	}); !errors.Is(err, ErrDiscoveryConfig) {
		t.Fatalf("empty kid in ManifestKeys: want ErrDiscoveryConfig, got %v", err)
	}
}

// TestDiscoveryProvider_NilReceiver_FailsClosed proves a caller that ignored
// NewDiscoveryProvider's construction error and installed the nil *DiscoveryProvider
// fails closed with ErrNotConfigured rather than panicking on the p.cfg field read —
// matching StaticProvider's nil-receiver guard.
func TestDiscoveryProvider_NilReceiver_FailsClosed(t *testing.T) {
	var dp *DiscoveryProvider // typed nil, e.g. from `dp, _ := NewDiscoveryProvider(badCfg)`
	_, _, err := dp.Resolve(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil DiscoveryProvider receiver: want ErrNotConfigured, got %v", err)
	}
}

// TestDiscoveryProvider_ConfigDefensivelyCopied proves NewDiscoveryProvider copies the
// trust-critical reference fields (PinSHA256 slice, ManifestKeys map) so a caller that
// mutates its own config AFTER construction cannot change the provider's trust anchor.
// Each sub-case mutates the caller-held value post-construction and asserts Resolve still
// behaves as configured at construction.
func TestDiscoveryProvider_ConfigDefensivelyCopied(t *testing.T) {
	t.Run("pin slice mutation ignored", func(t *testing.T) {
		raw, pin := envelopeBytes(t, validManifest(t))
		callerPin := append([]byte(nil), pin...) // the caller's own backing array
		p, err := NewDiscoveryProvider(DiscoveryConfig{
			Fetcher:   FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
			PinSHA256: callerPin,
		})
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		// Corrupt the caller's pin AFTER construction. If the provider aliased it, the pin
		// compare would now mismatch; with a defensive copy it still matches.
		for i := range callerPin {
			callerPin[i] = 0
		}
		if _, _, err := p.Resolve(context.Background()); err != nil {
			t.Fatalf("post-construction pin mutation changed trust behavior: %v", err)
		}
	})

	t.Run("keys map mutation ignored", func(t *testing.T) {
		signer, err := qv2.GenerateLocalSigner("manifest-signer-1")
		if err != nil {
			t.Fatalf("generate manifest signer: %v", err)
		}
		der, err := signer.PublicKeyDER()
		if err != nil {
			t.Fatalf("signer public key DER: %v", err)
		}
		pub, err := qv2.ParseP256PublicKeyDER(der)
		if err != nil {
			t.Fatalf("parse signer public key: %v", err)
		}
		manifestJSON, err := json.Marshal(validManifest(t))
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		raw := signedEnvelopeBytes(t, signer, manifestJSON, manifestJSON)

		callerKeys := map[string]*ecdsa.PublicKey{signer.KID(): pub}
		p, err := NewDiscoveryProvider(DiscoveryConfig{
			Fetcher:          FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }),
			ManifestKeys:     callerKeys,
			RequireSignature: true,
		})
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		// Remove the signing key from the caller's map AFTER construction. If the provider
		// aliased it, the kid lookup would now fail (ErrUnknownKID); with a defensive copy
		// the manifest still verifies.
		delete(callerKeys, signer.KID())
		if _, _, err := p.Resolve(context.Background()); err != nil {
			t.Fatalf("post-construction keys mutation changed trust behavior: %v", err)
		}
	})
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

// signedEnvelopeBytes signs manifestJSON in the MANIFEST domain with signer and wraps
// the EXACT bytes into a signed ManifestEnvelope (manifest_b64 + sig_b64 + kid). The
// signature is over the same bytes that are embedded, so the signed path authenticates
// by verifying the transmitted bytes with zero re-serialization. embedJSON is the
// manifest body actually placed in manifest_b64 — passing a DIFFERENT value than the
// signed bytes is how the tamper case drives a signature that no longer matches.
func signedEnvelopeBytes(t *testing.T, signer *qv2.LocalSigner, signedJSON, embedJSON []byte) []byte {
	t.Helper()
	sig, err := qv2.SignManifest(context.Background(), signer, signedJSON)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	env := ManifestEnvelope{
		ManifestB64: b64url.EncodeToString(embedJSON),
		SigB64:      b64url.EncodeToString(sig),
		Kid:         signer.KID(),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal signed envelope: %v", err)
	}
	return raw
}

// signedProviderFromFetcher builds a DiscoveryProvider whose ONLY trust mode is the
// signed mode: it trusts signer.KID() and requires a valid signature. No pin is
// configured, so the signature — not a pin compare — is what authenticates, isolating
// the signed-accept wiring (a pin would short-circuit verification before
// verifyManifestSig ran). The fetcher is injected so a test can drive a static body or
// a stateful sequence (e.g. the downgrade-after-accept case).
func signedProviderFromFetcher(t *testing.T, fetcher ManifestFetcher, signer *qv2.LocalSigner) *DiscoveryProvider {
	t.Helper()
	der, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("signer public key DER: %v", err)
	}
	pub, err := qv2.ParseP256PublicKeyDER(der)
	if err != nil {
		t.Fatalf("parse signer public key: %v", err)
	}
	p, err := NewDiscoveryProvider(DiscoveryConfig{
		Fetcher:          fetcher,
		ManifestKeys:     map[string]*ecdsa.PublicKey{signer.KID(): pub},
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("new signed discovery provider: %v", err)
	}
	return p
}

// signedProvider is the static-body convenience: a signed provider whose fetcher always
// returns raw.
func signedProvider(t *testing.T, raw []byte, signer *qv2.LocalSigner) *DiscoveryProvider {
	t.Helper()
	return signedProviderFromFetcher(t, FetcherFunc(func(context.Context) ([]byte, error) { return raw, nil }), signer)
}

// TestDiscoveryProvider_SignedManifest_Resolves closes the signed-accept coverage gap:
// a manifest signed in the manifest domain under a known kid (no pin configured)
// authenticates through verifyManifestSig and resolves to a usable trust store +
// allowlist. This exercises the provider's STRONGEST trust mode's happy-path wiring —
// authenticate -> verifyManifestSig success -> buildTrustMaterial — end to end.
func TestDiscoveryProvider_SignedManifest_Resolves(t *testing.T) {
	signer, err := qv2.GenerateLocalSigner("manifest-signer-1")
	if err != nil {
		t.Fatalf("generate manifest signer: %v", err)
	}
	manifestJSON, err := json.Marshal(validManifest(t))
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	raw := signedEnvelopeBytes(t, signer, manifestJSON, manifestJSON)
	p := signedProvider(t, raw, signer)

	ts, allow, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve valid signed manifest: %v", err)
	}
	if ts == nil || allow == nil {
		t.Fatal("resolve returned a nil trust store or allowlist on success")
	}
	if err := qv2.ValidateRelayURL("https://relay.example.com", allow); err != nil {
		t.Fatalf("manifest relay host should be allowlisted: %v", err)
	}
	if err := qv2.ValidateRelayURL("https://not-the-relay.example.org", allow); !errors.Is(err, qv2.ErrRelayURL) {
		t.Fatalf("off-allowlist host should be rejected: %v", err)
	}
}

// TestDiscoveryProvider_SignedManifest_TamperedRejected is the RED companion to the
// accept test: the SAME signature is served over MUTATED manifest bytes (a bumped
// version), so the detached signature no longer matches the embedded bytes. With no pin
// configured, the only thing that can reject this is the signed-path wiring — so this
// asserts the signature is verified over the EXACT embedded bytes (not some other
// copy). It fails closed as ErrManifestUnverified, wrapping qv2.ErrSignature. If a
// regression handed verifyManifestSig the signed-over bytes instead of the embedded
// bytes, this manifest would wrongly ACCEPT and this test would catch it.
func TestDiscoveryProvider_SignedManifest_TamperedRejected(t *testing.T) {
	signer, err := qv2.GenerateLocalSigner("manifest-signer-1")
	if err != nil {
		t.Fatalf("generate manifest signer: %v", err)
	}
	signed := validManifest(t)
	signedJSON, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed manifest: %v", err)
	}
	tampered := signed
	tampered.Version = signed.Version + 1 // a different in-window manifest
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered manifest: %v", err)
	}
	// Sign the original bytes but embed the tampered bytes: the signature does not
	// cover what is in manifest_b64.
	raw := signedEnvelopeBytes(t, signer, signedJSON, tamperedJSON)
	p := signedProvider(t, raw, signer)

	_, _, err = p.Resolve(context.Background())
	if !errors.Is(err, ErrManifestUnverified) {
		t.Fatalf("tampered signed manifest: want ErrManifestUnverified, got %v", err)
	}
	if !errors.Is(err, qv2.ErrSignature) {
		t.Fatalf("tampered signed manifest: error should wrap qv2.ErrSignature, got %v", err)
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

// TestDiscoveryProvider_NotYetValid_FailsClosed proves the lower-bound freshness guard
// with clock-skew tolerance: a manifest whose issued_at is in the future by MORE than
// manifestClockSkewLeeway is rejected as ErrManifestNotYetValid, while one within the
// leeway is accepted (so benign skew between issuer and client doesn't strand a viewer).
// A fixed clock makes the future-relative window deterministic; the pin authenticates
// the bytes so only the freshness bound bites.
func TestDiscoveryProvider_NotYetValid_FailsClosed(t *testing.T) {
	const nowUnix = 10000
	leewaySec := manifestClockSkewLeewaySec

	t.Run("beyond leeway rejected", func(t *testing.T) {
		m := validManifest(t)
		// issued_at sits one minute PAST the leeway window, so now+leeway < issued_at.
		m.IssuedAt = nowUnix + leewaySec + 60
		m.NotAfter = m.IssuedAt + 3600 // coherent window (not_after > issued_at)
		raw, pin := envelopeBytes(t, m)
		p := pinnedProvider(t, raw, pin, fixedNow(time.Unix(nowUnix, 0)))

		if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestNotYetValid) {
			t.Fatalf("future-dated beyond leeway: want ErrManifestNotYetValid, got %v", err)
		}
	})

	t.Run("within leeway accepted", func(t *testing.T) {
		m := validManifest(t)
		// issued_at is in the future but INSIDE the leeway window (now+leeway >= issued_at),
		// modeling a slightly-early publish or a lagging client clock — must be accepted.
		m.IssuedAt = nowUnix + (leewaySec / 2)
		m.NotAfter = m.IssuedAt + 3600
		raw, pin := envelopeBytes(t, m)
		p := pinnedProvider(t, raw, pin, fixedNow(time.Unix(nowUnix, 0)))

		ts, allow, err := p.Resolve(context.Background())
		if err != nil {
			t.Fatalf("future-dated within leeway should be accepted: %v", err)
		}
		if ts == nil || allow == nil {
			t.Fatal("within-leeway manifest resolved to a nil trust store or allowlist")
		}
	})
}

// TestDiscoveryProvider_Downgrade_FailsClosed proves the monotonic-version floor: an
// under-floor manifest is rejected up front as a downgrade. A MinVersion floor above
// the manifest's version isolates the version guard from the pin (the bytes
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

// TestDiscoveryProvider_FloorAdvances_RejectsRollback proves the DYNAMIC anti-rollback
// mechanism (distinct from the static MinVersion floor): after a provider ACCEPTS a
// manifest, p.floor advances to that version, so a later fetch of an OLDER — but still
// validly authenticated and in-window — manifest is rejected as a downgrade. This is
// the property a rollback attacker actually probes (replay a previously-valid older
// manifest), and the floor-advance line that enforces it had no direct coverage.
//
// Signed mode (not pin) is required: a pin authenticates one exact byte string, so it
// could not authenticate both the v8 and the v7 manifest. One signer signs both; a
// stateful fetcher returns v8 first, then v7, against the SAME provider instance.
func TestDiscoveryProvider_FloorAdvances_RejectsRollback(t *testing.T) {
	signer, err := qv2.GenerateLocalSigner("manifest-signer-1")
	if err != nil {
		t.Fatalf("generate manifest signer: %v", err)
	}

	newer := validManifest(t)
	newer.Version = 8
	newerJSON, err := json.Marshal(newer)
	if err != nil {
		t.Fatalf("marshal newer manifest: %v", err)
	}
	older := validManifest(t)
	older.Version = 7 // a LOWER version than the accepted one, but otherwise valid
	olderJSON, err := json.Marshal(older)
	if err != nil {
		t.Fatalf("marshal older manifest: %v", err)
	}

	// A stateful fetcher: first Resolve sees v8, second sees v7.
	bodies := [][]byte{
		signedEnvelopeBytes(t, signer, newerJSON, newerJSON),
		signedEnvelopeBytes(t, signer, olderJSON, olderJSON),
	}
	var calls int
	fetcher := FetcherFunc(func(context.Context) ([]byte, error) {
		body := bodies[calls]
		calls++
		return body, nil
	})
	p := signedProviderFromFetcher(t, fetcher, signer)

	// First Resolve accepts v8 and advances the floor to 8.
	if _, _, err := p.Resolve(context.Background()); err != nil {
		t.Fatalf("first resolve (v8) should accept: %v", err)
	}
	// Second Resolve fetches the older, still-valid v7 — it must be rejected as a
	// downgrade because the floor advanced past it.
	if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestDowngrade) {
		t.Fatalf("rollback to v7 after accepting v8: want ErrManifestDowngrade, got %v", err)
	}
}

// TestDiscoveryProvider_ConcurrentResolve_RaceClean locks the mutex contract on the
// downgrade floor: many goroutines Resolve the SAME valid manifest on one provider
// instance concurrently. All must succeed (the floor check + advance are atomic under
// the lock, so no resolve sees a torn floor), and the test must be clean under -race.
// Every goroutine uses the SAME version deliberately — varying versions would make
// some resolves legitimately lose the downgrade race nondeterministically and flake;
// the sequential rollback test above covers rejection. This is the concurrency check
// the race-sensitive floor path needs.
func TestDiscoveryProvider_ConcurrentResolve_RaceClean(t *testing.T) {
	raw, pin := envelopeBytes(t, validManifest(t))
	p := pinnedProvider(t, raw, pin, nil)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ts, allow, err := p.Resolve(context.Background())
			if err != nil {
				errs[idx] = err
				return
			}
			if ts == nil || allow == nil {
				errs[idx] = errors.New("nil trust store or allowlist on success")
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent resolve goroutine %d: %v", i, err)
		}
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
		// Blank-only allowlist: length-non-empty but every entry trims to "", so
		// NewRelayAllowlist would drop them all and reject every relay. parseManifest
		// must catch this as a schema fault, not pass the bare length check.
		{"blank-only relay allowlist", func(m *Manifest) { m.RelayAllowlist = []string{" ", "\t"} }},
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

// TestDiscoveryProvider_TrailingData_FailsClosed proves strictDecodeJSON rejects a
// second concatenated JSON value after the top-level object — at both the inner
// manifest and the outer envelope — rather than silently ignoring it the way a bare
// json.Decode would. The pin is computed over the EXACT (trailing-data) manifest bytes
// so authentication passes and the schema guard is what bites; json.Marshal cannot
// emit trailing bytes, so these cases build the JSON by hand. The bytes here are
// authenticated, so this is a strict-schema/cross-parser-consistency guard, not an
// attack surface.
func TestDiscoveryProvider_TrailingData_FailsClosed(t *testing.T) {
	t.Run("manifest trailing data", func(t *testing.T) {
		good, err := json.Marshal(validManifest(t))
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		manifestJSON := append(append([]byte{}, good...), []byte("{}")...) // a second object appended
		env := ManifestEnvelope{ManifestB64: b64url.EncodeToString(manifestJSON)}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		digest := qv2.ManifestDigest(manifestJSON)
		p := pinnedProvider(t, raw, digest[:], nil)
		if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestSchema) {
			t.Fatalf("manifest trailing data: want ErrManifestSchema, got %v", err)
		}
	})

	t.Run("envelope trailing data", func(t *testing.T) {
		manifestJSON, err := json.Marshal(validManifest(t))
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		env := ManifestEnvelope{ManifestB64: b64url.EncodeToString(manifestJSON)}
		envJSON, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		raw := append(append([]byte{}, envJSON...), []byte("{}")...) // trailing object after the envelope
		// The envelope decoder rejects the trailing data before authentication, so a pin
		// is configured only to build a valid provider; the schema guard fires first.
		digest := qv2.ManifestDigest(manifestJSON)
		p := pinnedProvider(t, raw, digest[:], nil)
		if _, _, err := p.Resolve(context.Background()); !errors.Is(err, ErrManifestSchema) {
			t.Fatalf("envelope trailing data: want ErrManifestSchema, got %v", err)
		}
	})
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
