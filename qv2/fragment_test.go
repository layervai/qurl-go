package qv2

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
)

// TestParseAndVerify_MintedFragment mints a valid signed fragment with a local
// issuer key and proves the full parse + verify path accepts it and recovers the
// claim fields verbatim.
func TestParseAndVerify_MintedFragment(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	secretB64 := mintSecretB64(t)

	body, err := BuildFragment(claimsB64, secretB64, rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	frag, err := ParseAndVerify(body, signer.trustStore(t))
	if err != nil {
		t.Fatalf("ParseAndVerify: %v", err)
	}
	if frag.Claims.Iss != Issuer || frag.Claims.Kid != testIssuerKID {
		t.Fatalf("recovered claims wrong: iss=%q kid=%q", frag.Claims.Iss, frag.Claims.Kid)
	}
	if frag.ClaimsB64 != claimsB64 {
		t.Fatal("ClaimsB64 must be retained verbatim for signature re-checks")
	}
}

// TestParseAndVerify_DERTrustStore proves a trust store loaded from issuer DER
// SPKI (the KMS GetPublicKey / config form) verifies a minted fragment.
func TestParseAndVerify_DERTrustStore(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	ts, err := NewTrustStoreFromDER(map[string][]byte{testIssuerKID: signer.derSPKI(t)})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER: %v", err)
	}
	if _, err := ParseAndVerify(body, ts); err != nil {
		t.Fatalf("ParseAndVerify with DER trust store: %v", err)
	}
}

// TestVerify_TamperedClaims proves that a signature minted over one valid claim
// set does NOT verify against a DIFFERENT valid claim set: an attacker who swaps
// the (still strict-parseable) claims part but keeps the original signature is
// rejected with ErrSignature. This is the substantive anti-tamper property — the
// signature binds the exact claims bytes, not merely well-formedness.
func TestVerify_TamperedClaims(t *testing.T) {
	signer := newTestSigner(t)

	// Sign claim set A.
	claimsA := baselineClaims(t)
	claimsAB64, rawSigA := signer.signClaims(t, claimsA)

	// Build claim set B: same shape, different jti (so it is valid JSON and strict-
	// parses, but its bytes — and therefore the signing digest — differ from A).
	claimsB := baselineClaims(t)
	claimsB.Jti = claimsA.Jti + "-tampered"
	claimsBB64, _ := signer.signClaims(t, claimsB)
	if claimsBB64 == claimsAB64 {
		t.Fatal("fixture: tampered claims must differ from the signed claims")
	}

	// Fragment carries B's claims but A's signature.
	body, err := BuildFragment(claimsBB64, mintSecretB64(t), rawSigA)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	_, err = ParseAndVerify(body, signer.trustStore(t))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("swapped valid claims under old signature: want ErrSignature, got %v", err)
	}
}

// TestVerify_UnknownKID proves a fragment whose kid is not in the trust store is
// rejected with ErrUnknownKID before any curve math.
func TestVerify_UnknownKID(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	// A different signer's key registered under a DIFFERENT kid than the claim's.
	other := newTestSigner(t)
	ts, err := NewTrustStore(map[string]*ecdsa.PublicKey{"some-other-kid": &other.priv.PublicKey})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}
	_, err = ParseAndVerify(body, ts)
	if !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("unknown kid: want ErrUnknownKID, got %v", err)
	}
}

// TestVerify_WrongIssuerKey proves that a fragment whose kid IS in the store but
// whose signature was made by a different key fails with ErrSignature.
func TestVerify_WrongIssuerKey(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	// Register a DIFFERENT key under the SAME kid the claim carries.
	imposter := newTestSigner(t)
	ts, err := NewTrustStore(map[string]*ecdsa.PublicKey{testIssuerKID: &imposter.priv.PublicKey})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}
	_, err = ParseAndVerify(body, ts)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong issuer key: want ErrSignature, got %v", err)
	}
}

// TestFragmentFromLink_StripsScheme proves a full qURL link (scheme/host + #qv2…)
// is accepted and routed to the parser, and that a link with no fragment is a
// fragment-shape error.
func TestFragmentFromLink_StripsScheme(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	link := "https://qurl.link/#" + body

	frag, err := FragmentFromLinkAndVerify(link, signer.trustStore(t))
	if err != nil {
		t.Fatalf("FragmentFromLinkAndVerify: %v", err)
	}
	if frag.ClaimsB64 != claimsB64 {
		t.Fatal("claims not recovered from full link")
	}

	if _, err := FragmentFromLink("https://qurl.link/no-fragment"); !errors.Is(err, ErrFragment) {
		t.Fatalf("link without fragment: want ErrFragment, got %v", err)
	}
}

// TestBuildFragment_RejectsDottedPart proves BuildFragment fails closed when a
// caller passes a non-encodeB64 part containing the field separator ".", which
// would otherwise split into the wrong number of fields.
func TestBuildFragment_RejectsDottedPart(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	_, err := BuildFragment(claimsB64, "aaa.bbb", rawSig)
	if !errors.Is(err, ErrFragment) {
		t.Fatalf("dotted secret part: want ErrFragment, got %v", err)
	}
	if !strings.Contains(err.Error(), "secret") {
		t.Fatalf("error should name the offending part: %v", err)
	}
}
