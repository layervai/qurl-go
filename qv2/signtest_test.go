package qv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// Local (KMS-free) test signer for the verify-side port.
//
// qurl-go carries only the VERIFY side; it never mints production qURLs. The
// committed golden vectors (testdata/issuer_signature_vectors.json) are the
// cross-language CONTRACT proving this package's verification agrees byte-for-byte
// with the KMS sign output. These helpers exist only so the fragment/round-trip
// tests can mint fresh signed fragments to exercise the verify path against
// arbitrary claims (tamper, unknown-kid, round-trip). They reuse the package's
// OWN signing input (signingDigest) and DER->raw-low-S conversion (derToRawLowS),
// so a test signature is produced exactly as a conformant signer would — the only
// difference from production is a local ecdsa key rather than a KMS handle.

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

// signClaims stamps the issuer kid, marshals claims to canonical base64url, signs
// the package signing digest, and converts to the pinned 64-byte raw r||s low-S
// wire form. It returns the exact claims bytes that were signed (Part 1) and the
// raw signature.
func (s *testSigner) signClaims(t *testing.T, c *Claims) (claimsB64 string, rawSig []byte) {
	t.Helper()
	signed := *c
	signed.Kid = s.kid
	raw, err := json.Marshal(&signed)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	claimsB64 = encodeB64(raw)
	digest := signingDigest(claimsB64)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rawSig, err = derToRawLowS(der)
	if err != nil {
		t.Fatalf("derToRawLowS: %v", err)
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
