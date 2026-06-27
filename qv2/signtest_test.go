package qv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// Local (KMS-free) test signer that implements the production Signer seam.
//
// testSigner is a thin wrapper over the real mint path: it provides KID +
// SignDigest (a local ecdsa key in place of a KMS handle) and lets SignClaims own
// the domain-separated digest and the DER->raw low-S conversion. Test signatures
// are therefore produced by the SAME code a conformant production signer runs —
// the only difference is the key custody — so the fragment/round-trip/tamper tests
// exercise mint↔verify symmetry rather than a parallel signing implementation. The
// committed golden vectors (testdata/issuer_signature_vectors.json) remain the
// cross-language CONTRACT that this package's verification agrees byte-for-byte
// with external KMS sign output.

// testIssuerKID is the kid every locally-signed test fragment is signed under.
const testIssuerKID = "qurl-issuer-key-test"

// testSigner mints qURL v2 issuer signatures with a local P-256 key.
type testSigner struct {
	priv *ecdsa.PrivateKey
	kid  string
}

// newTestSigner generates a fresh local P-256 issuer key under testIssuerKID.
func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	return &testSigner{priv: priv, kid: testIssuerKID}
}

// testSigner implements the production Signer seam so the test mint path and the
// real one are the SAME code: KID + SignDigest (sign the digest, return DER) feed
// SignClaims, which owns the domain-separated digest and the DER->raw low-S
// conversion. There is no parallel signing implementation to drift from the
// verifier.
func (s *testSigner) KID() string { return s.kid }

func (s *testSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, digest)
}

// signClaims mints via the production SignClaims seam and returns the exact signed
// claims bytes (Part 1) and the raw 64-byte low-S signature. It is a thin test
// convenience over SignClaims (which stamps the kid, strict-validates, and
// normalizes low-S) so the fragment/round-trip tests exercise the real mint path.
func (s *testSigner) signClaims(t *testing.T, c *Claims) (claimsB64 string, rawSig []byte) {
	t.Helper()
	claimsB64, rawSig, err := SignClaims(context.Background(), s, c)
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	return claimsB64, rawSig
}

// trustStore builds a single-key trust store for this signer's public key.
func (s *testSigner) trustStore(t *testing.T) *TrustStore {
	t.Helper()
	ts, err := NewTrustStore(map[string]*ecdsa.PublicKey{s.kid: &s.priv.PublicKey})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}
	return ts
}

// derSPKI returns the signer's issuer public key in DER SPKI form (the
// trust-store load form NewTrustStoreFromDER consumes).
func (s *testSigner) derSPKI(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return der
}

// mintSecretB64 builds a valid Part-2 secret: base64url of the JSON
// {"qurl_user_private_key_b64":"<32-byte key>"}. Part 2 is base64url-encoded JSON,
// not the raw key bytes, so this mirrors what an issuer emits.
func mintSecretB64(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(Secret{QurlUserPrivateKeyB64: testX25519B64(0x33)})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	return encodeB64(raw)
}

// testX25519B64 returns a deterministic 32-byte X25519-shaped public key as
// unpadded base64url (fill byte = seed). Not a real curve point — the parser
// length-checks shape, not curve membership, so this is sufficient for parse/
// verify tests.
func testX25519B64(seed byte) string {
	b := make([]byte, x25519PublicKeyBytes)
	for i := range b {
		b[i] = seed
	}
	return encodeB64(b)
}

// testResourceKeyB64 returns a real P-256 SPKI DER as unpadded base64url, so the
// resource-key length-window check passes with realistic bytes.
func testResourceKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resource key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource SPKI: %v", err)
	}
	return encodeB64(der)
}

// baselineClaims builds a valid claims value used as the starting point for
// tamper/round-trip cases. Kid is left unset so the signer is the single writer.
func baselineClaims(t *testing.T) *Claims {
	t.Helper()
	return &Claims{
		V:                    Version,
		Iss:                  Issuer,
		Iat:                  1781910000,
		Nbf:                  1781910000,
		Exp:                  1781910300,
		Jti:                  "qurl_01JABCDEF",
		CellPublicKeyB64:     testX25519B64(0x11),
		CellID:               "cell-a",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: testResourceKeyB64(t),
		QurlUserPublicKeyB64: testX25519B64(0x22),
	}
}
