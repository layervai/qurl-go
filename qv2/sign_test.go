package qv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// The signer seam is proved against the package's OWN verify path: a SignClaims
// output must be accepted by ParseAndVerify, and a post-sign tamper must be
// rejected with ErrSignature specifically (not a parser/encoding error). This is
// real round-trip symmetry — one mint path (SignClaims/derToRawLowS) checked by
// the production verifier, not a parallel signing implementation.

func newLocalSigner(t *testing.T) *LocalSigner {
	t.Helper()
	s, err := GenerateLocalSigner("qurl-issuer-key-sign-test")
	if err != nil {
		t.Fatalf("GenerateLocalSigner: %v", err)
	}
	return s
}

// signerTrustStore builds a single-key trust store from a LocalSigner's published
// DER SPKI public key — the same load path (NewTrustStoreFromDER) production uses
// for KMS GetPublicKey output.
func signerTrustStore(t *testing.T, s *LocalSigner) *TrustStore {
	t.Helper()
	der, err := s.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	ts, err := NewTrustStoreFromDER(map[string][]byte{s.KID(): der})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER: %v", err)
	}
	return ts
}

// TestSignClaims_RoundTripVerifies proves a fragment minted via the SignClaims
// seam parses and verifies through the real ParseAndVerify path, and that the
// signer kid is stamped onto the claims.
func TestSignClaims_RoundTripVerifies(t *testing.T) {
	signer := newLocalSigner(t)

	claimsB64, rawSig, err := SignClaims(context.Background(), signer, baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	frag, err := ParseAndVerify(body, signerTrustStore(t, signer))
	if err != nil {
		t.Fatalf("ParseAndVerify of SignClaims output: %v", err)
	}
	if frag.Claims.Kid != signer.KID() {
		t.Fatalf("kid not stamped: got %q, want %q", frag.Claims.Kid, signer.KID())
	}
	if frag.ClaimsB64 != claimsB64 {
		t.Fatal("transmitted claims bytes must equal the signed claims bytes")
	}
}

// TestSignClaims_DoesNotMutateCaller proves SignClaims stamps the kid on a COPY,
// leaving the caller's claims struct untouched (it signs a struct whose Kid is
// empty and must not write it back).
func TestSignClaims_DoesNotMutateCaller(t *testing.T) {
	signer := newLocalSigner(t)
	claims := baselineClaims(t)
	claims.Kid = "" // caller leaves kid unset; the signer is the sole writer

	if _, _, err := SignClaims(context.Background(), signer, claims); err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	if claims.Kid != "" {
		t.Fatalf("SignClaims mutated the caller's claims: Kid = %q", claims.Kid)
	}
}

// TestSignClaims_TamperRejected proves the signature binds the EXACT claims bytes:
// minting claim set A, then swapping in a different VALID claim set B under A's
// signature, fails verification with ErrSignature. Using a still-strict-parseable
// tamper (a changed jti) isolates the signature property from parser/encoding
// failures — the fragment is well-formed; only the binding is broken.
func TestSignClaims_TamperRejected(t *testing.T) {
	signer := newLocalSigner(t)

	// Sign claim set A.
	claimsAB64, rawSigA, err := SignClaims(context.Background(), signer, baselineClaims(t))
	if err != nil {
		t.Fatalf("SignClaims(A): %v", err)
	}

	// Claim set B: same shape, different jti — valid JSON, strict-parseable, but
	// different bytes (and therefore a different signing digest) than A.
	claimsB := baselineClaims(t)
	claimsB.Jti = claimsB.Jti + "-tampered"
	claimsBB64, _, err := SignClaims(context.Background(), signer, claimsB)
	if err != nil {
		t.Fatalf("SignClaims(B): %v", err)
	}
	if claimsBB64 == claimsAB64 {
		t.Fatal("fixture: tampered claims must differ from the signed claims")
	}

	// Fragment carries B's claims under A's signature.
	body, err := BuildFragment(claimsBB64, mintSecretB64(t), rawSigA)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	_, err = ParseAndVerify(body, signerTrustStore(t, signer))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered claims under original signature: want ErrSignature, got %v", err)
	}
}

// TestSignClaims_RefusesInvalidClaims proves the mint path validates the exact
// bytes about to be signed through the verifier's strict parser BEFORE signing, so
// an invalid claim (here nbf>exp) fails the mint as a wrapped ErrStrictParse rather
// than producing an artifact no verifier would accept.
func TestSignClaims_RefusesInvalidClaims(t *testing.T) {
	signer := newLocalSigner(t)
	claims := baselineClaims(t)
	claims.Nbf = claims.Exp + 1 // nbf>exp violates the clock-free ordering bound

	_, _, err := SignClaims(context.Background(), signer, claims)
	if !errors.Is(err, ErrStrictParse) {
		t.Fatalf("invalid claims: want wrapped ErrStrictParse, got %v", err)
	}
}

// TestSignClaims_NilGuards proves the mint path fails closed on a nil signer or
// nil claims rather than panicking.
func TestSignClaims_NilGuards(t *testing.T) {
	if _, _, err := SignClaims(context.Background(), nil, baselineClaims(t)); err == nil {
		t.Fatal("nil signer: want error, got nil")
	}
	if _, _, err := SignClaims(context.Background(), newLocalSigner(t), nil); err == nil {
		t.Fatal("nil claims: want error, got nil")
	}
}

// TestNewLocalSigner_Guards proves the local signer rejects a nil key, a non-P-256
// curve, and an empty kid at construction.
func TestNewLocalSigner_Guards(t *testing.T) {
	good, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := NewLocalSigner(nil, "kid"); err == nil {
		t.Fatal("nil key: want error, got nil")
	}
	if _, err := NewLocalSigner(good, ""); err == nil {
		t.Fatal("empty kid: want error, got nil")
	}
	if _, err := NewLocalSigner(good, "kid"); err != nil {
		t.Fatalf("valid local signer: unexpected error %v", err)
	}
}

// errSigner is a Signer whose SignDigest always fails, proving SignClaims
// surfaces a signer error (wrapped) rather than swallowing it.
type errSigner struct{}

func (errSigner) KID() string { return "err-kid" }
func (errSigner) SignDigest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("boom")
}

func TestSignClaims_SurfacesSignerError(t *testing.T) {
	_, _, err := SignClaims(context.Background(), errSigner{}, baselineClaims(t))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want wrapped signer error, got %v", err)
	}
}
