package qurl_test

import (
	"context"
	"errors"
	"testing"

	"github.com/layervai/qurl-go/qurl"
)

// TestManifestFacadeRoundTrip exercises the re-exported discovery-manifest primitives
// end to end through the qurl front door — digest, sign, verify — so a publisher never
// has to reach past qurl. It also confirms the wrappers are wired to the right
// underlying functions (a mis-wired re-export would fail this round trip).
func TestManifestFacadeRoundTrip(t *testing.T) {
	signer, err := qurl.GenerateLocalSigner("manifest-key-2026")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	manifest := []byte(`{"profile":"qurl-trust","version":1}`)

	// ManifestDigest produces the value a deployment pins (a real, non-zero digest).
	if qurl.ManifestDigest(manifest) == ([32]byte{}) {
		t.Fatal("ManifestDigest returned the zero digest")
	}

	sig, err := qurl.SignManifest(context.Background(), signer, manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	pub, err := qurl.ParseP256PublicKeyDER(pubDER)
	if err != nil {
		t.Fatalf("ParseP256PublicKeyDER: %v", err)
	}

	if err := qurl.VerifyManifestSignature(pub, manifest, sig); err != nil {
		t.Fatalf("a freshly signed manifest should verify: %v", err)
	}

	// Tampered manifest bytes must not verify under the same signature.
	if err := qurl.VerifyManifestSignature(pub, append(manifest, '!'), sig); err == nil {
		t.Fatal("tampered manifest unexpectedly verified")
	}
}

// TestErrorSentinelsAreInternalIdentities confirms the re-exported error vars are the
// SAME values as the internal sentinels (re-export by value), so callers' errors.Is
// checks against qurl.Err* keep matching errors produced deep in the core.
func TestErrorSentinelsAreInternalIdentities(t *testing.T) {
	// A forged link surfaces ErrSignature from the core; matching qurl.ErrSignature
	// proves the identity is preserved across the façade boundary.
	trusted, err := qurl.GenerateLocalSigner("issuer-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	attacker, err := qurl.GenerateLocalSigner("issuer-key") // same kid, different key
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	forged, err := qurl.CreatePortal(context.Background(), attacker, qurl.CreateParams{
		CellPublicKey:     newX25519PublicKey(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: newP256SPKI(),
		JTI:               "qurl_facade_test",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if _, err := qurl.VerifyLink(forged, trustStoreFor(trusted)); !errors.Is(err, qurl.ErrSignature) {
		t.Fatalf("want qurl.ErrSignature, got %v", err)
	}
}
