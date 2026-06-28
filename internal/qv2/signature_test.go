package qv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

// TestDerToRawLowS_RoundTrip proves the signer-side DER->raw conversion produces a
// 64-byte raw r||s signature the verifier accepts, closing the sign/verify loop
// with the package's own helpers (the golden vectors fence the verify side against
// external KMS output; this fences the internal DER->raw step).
func TestDerToRawLowS_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const claimsB64 = "eyJ2IjoyfQ" // arbitrary well-formed base64url; content irrelevant here
	digest := signingDigest(claimsB64)

	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := derToRawLowS(der)
	if err != nil {
		t.Fatalf("derToRawLowS: %v", err)
	}
	if len(raw) != p256SignatureBytes {
		t.Fatalf("raw sig length = %d, want %d", len(raw), p256SignatureBytes)
	}
	if err := verifyRawSignature(&priv.PublicKey, claimsB64, raw); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// TestDerToRawLowS_NormalizesHighS proves derToRawLowS converts a HIGH-S DER
// signature (the KMS case — KMS does not low-S normalize) into the canonical
// low-S raw form the verifier requires, so a verify over the normalized bytes
// succeeds even though the raw high-S form would be rejected by rawToScalars.
func TestDerToRawLowS_NormalizesHighS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const claimsB64 = "eyJ2IjoyfQ"
	digest := signingDigest(claimsB64)

	highSDER := signHighSDER(t, priv, digest[:])

	// The high-S DER, naively packed to raw r||s, must be rejected as high-S.
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(highSDER, &parsed); err != nil {
		t.Fatalf("unmarshal high-S der: %v", err)
	}
	naiveRaw := scalarsToRaw(parsed.R, parsed.S)
	if _, _, err := rawToScalars(naiveRaw); !errors.Is(err, ErrSignatureHighS) {
		t.Fatalf("naive high-S raw: want ErrSignatureHighS, got %v", err)
	}

	// derToRawLowS normalizes it, and the normalized signature verifies.
	norm, err := derToRawLowS(highSDER)
	if err != nil {
		t.Fatalf("derToRawLowS(high-S): %v", err)
	}
	if err := verifyRawSignature(&priv.PublicKey, claimsB64, norm); err != nil {
		t.Fatalf("normalized high-S sig failed to verify: %v", err)
	}
}

// signHighSDER signs digest and returns a guaranteed HIGH-S DER signature (S
// flipped to N - S when low), modeling the KMS case where the returned signature
// is high-S.
func signHighSDER(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatalf("unmarshal der: %v", err)
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(n, 1)
	if sig.S.Cmp(half) <= 0 {
		sig.S = new(big.Int).Sub(n, sig.S) // make it high-S
	}
	out, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal high-S der: %v", err)
	}
	return out
}
