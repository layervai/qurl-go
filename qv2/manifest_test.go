package qv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"testing"
)

// manifestSign is a local test helper: sign manifest bytes in the MANIFEST domain
// and return the pinned 64-byte raw r||s low-S wire signature. It drives the exported
// SignManifest through a LocalSigner so a test signature is produced by the SAME mint
// path a conformant manifest signer would run (no parallel signing implementation to
// drift from the verifier), and so every existing manifest test exercises SignManifest.
func manifestSign(t *testing.T, priv *ecdsa.PrivateKey, manifest []byte) []byte {
	t.Helper()
	signer, err := NewLocalSigner(priv, "manifest-test-kid")
	if err != nil {
		t.Fatalf("new local signer: %v", err)
	}
	raw, err := SignManifest(context.Background(), signer, manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	return raw
}

func TestVerifyManifestSignature_RoundTrip(t *testing.T) {
	priv := mustGenP256(t)
	manifest := []byte(`{"profile":"qurl-v2","version":7,"not_after":9999999999}`)
	sig := manifestSign(t, priv, manifest)

	if err := VerifyManifestSignature(&priv.PublicKey, manifest, sig); err != nil {
		t.Fatalf("valid manifest signature: %v", err)
	}
}

func TestVerifyManifestSignature_TamperedBytesRejected(t *testing.T) {
	priv := mustGenP256(t)
	manifest := []byte(`{"profile":"qurl-v2","version":7,"not_after":9999999999}`)
	sig := manifestSign(t, priv, manifest)

	tampered := []byte(`{"profile":"qurl-v2","version":8,"not_after":9999999999}`)
	if err := VerifyManifestSignature(&priv.PublicKey, tampered, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: want ErrSignature, got %v", err)
	}
}

// TestManifestSignature_DomainSeparation is the load-bearing guard: a signature made
// in the qURL CLAIMS domain (signingDigest) must NOT verify as a MANIFEST signature,
// and vice versa, even under the SAME key. The only thing enforcing that is the
// distinct domain-separation prefix; this test fails if the two preimages are ever
// unified.
func TestManifestSignature_DomainSeparation(t *testing.T) {
	priv := mustGenP256(t)
	payload := []byte(`{"v":2,"iss":"qurl-service"}`) // shape is irrelevant; bytes are the preimage

	// A signature produced over the CLAIMS digest of `payload`.
	claimsDigest := signingDigest(string(payload))
	claimsDER, err := ecdsa.SignASN1(rand.Reader, priv, claimsDigest[:])
	if err != nil {
		t.Fatalf("sign claims digest: %v", err)
	}
	claimsRaw, err := derToRawLowS(claimsDER)
	if err != nil {
		t.Fatalf("derToRawLowS: %v", err)
	}

	// It must NOT verify as a manifest signature over the same bytes.
	if err := VerifyManifestSignature(&priv.PublicKey, payload, claimsRaw); !errors.Is(err, ErrSignature) {
		t.Fatalf("claims-domain signature accepted as manifest signature (domain separation broken): %v", err)
	}

	// Symmetric direction: a manifest-domain signature must NOT verify as a claims
	// signature (verifyRawSignature is the claims-domain verifier).
	manifestRaw := manifestSign(t, priv, payload)
	if err := verifyRawSignature(&priv.PublicKey, string(payload), manifestRaw); !errors.Is(err, ErrSignature) {
		t.Fatalf("manifest-domain signature accepted as claims signature (domain separation broken): %v", err)
	}
}

// TestSignManifest_RoundTrip proves the exported mint path: a signature SignManifest
// produces over manifest bytes verifies under the signer's public key, and tampering
// the bytes after signing breaks verification. This pins the mint<->verify symmetry of
// the manifest signing domain end to end through the public API.
func TestSignManifest_RoundTrip(t *testing.T) {
	signer, err := GenerateLocalSigner("manifest-kid-1")
	if err != nil {
		t.Fatalf("generate local signer: %v", err)
	}
	manifest := []byte(`{"profile":"qurl-v2","version":7,"not_after":9999999999}`)

	sig, err := SignManifest(context.Background(), signer, manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := VerifyManifestSignature(&signer.priv.PublicKey, manifest, sig); err != nil {
		t.Fatalf("SignManifest output failed verification: %v", err)
	}
	// Tampering the signed bytes must break verification (the signature is over the
	// exact bytes, no re-serialization slack).
	tampered := []byte(`{"profile":"qurl-v2","version":8,"not_after":9999999999}`)
	if err := VerifyManifestSignature(&signer.priv.PublicKey, tampered, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: want ErrSignature, got %v", err)
	}
}

// TestSignManifest_NilAndEmpty proves SignManifest mirrors VerifyManifestSignature's
// fail-closed guards: a nil signer and empty manifest bytes are rejected rather than
// producing a signature over nothing.
func TestSignManifest_NilAndEmpty(t *testing.T) {
	signer, err := GenerateLocalSigner("manifest-kid-1")
	if err != nil {
		t.Fatalf("generate local signer: %v", err)
	}
	if _, err := SignManifest(context.Background(), nil, []byte(`{"version":1}`)); err == nil {
		t.Fatal("nil signer: want error, got nil")
	}
	if _, err := SignManifest(context.Background(), signer, nil); err == nil {
		t.Fatal("empty manifest: want error, got nil")
	}
}

// TestSignManifest_DomainSeparatedFromClaims proves SignManifest signs in the MANIFEST
// domain only: its output does NOT verify as a qURL claims signature over the same
// bytes. This is the mint-side complement to TestManifestSignature_DomainSeparation
// and guards against SignManifest ever being routed through the claims digest.
func TestSignManifest_DomainSeparatedFromClaims(t *testing.T) {
	signer, err := GenerateLocalSigner("manifest-kid-1")
	if err != nil {
		t.Fatalf("generate local signer: %v", err)
	}
	payload := []byte(`{"v":2,"iss":"qurl-service"}`)

	manifestSig, err := SignManifest(context.Background(), signer, payload)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := verifyRawSignature(&signer.priv.PublicKey, string(payload), manifestSig); !errors.Is(err, ErrSignature) {
		t.Fatalf("manifest-domain signature accepted as claims signature (domain separation broken): %v", err)
	}
}

func TestVerifyManifestSignature_NilAndEmpty(t *testing.T) {
	priv := mustGenP256(t)
	manifest := []byte(`{"profile":"qurl-v2"}`)
	sig := manifestSign(t, priv, manifest)

	if err := VerifyManifestSignature(nil, manifest, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("nil pub: want ErrSignature, got %v", err)
	}
	if err := VerifyManifestSignature(&priv.PublicKey, nil, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("empty manifest: want ErrSignature, got %v", err)
	}
	// A non-64-byte signature is rejected by the wire-shape check (wraps ErrSignature).
	if err := VerifyManifestSignature(&priv.PublicKey, manifest, []byte{1, 2, 3}); !errors.Is(err, ErrSignature) {
		t.Fatalf("short sig: want ErrSignature, got %v", err)
	}
}

func TestManifestDigest_StableAndDistinguishing(t *testing.T) {
	a := ManifestDigest([]byte("alpha"))
	again := ManifestDigest([]byte("alpha"))
	b := ManifestDigest([]byte("bravo"))
	if a != again {
		t.Fatal("ManifestDigest is not stable for identical input")
	}
	if a == b {
		t.Fatal("ManifestDigest collided for distinct input")
	}
}

func mustGenP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return priv
}
