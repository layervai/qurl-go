package qv2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"testing"
)

// manifestSign is a local test helper: sign manifest bytes in the MANIFEST domain
// and return the pinned 64-byte raw r||s low-S wire signature. It reuses the
// package's own manifestSigningDigest + derToRawLowS so a test signature is produced
// exactly as a conformant manifest signer would.
func manifestSign(t *testing.T, priv *ecdsa.PrivateKey, manifest []byte) []byte {
	t.Helper()
	digest := manifestSigningDigest(manifest)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	raw, err := derToRawLowS(der)
	if err != nil {
		t.Fatalf("derToRawLowS: %v", err)
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
