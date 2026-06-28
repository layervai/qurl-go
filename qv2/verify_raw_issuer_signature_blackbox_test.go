package qv2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/layervai/qurl-go/qv2"
)

// This file is the EXTERNAL-caller proof for VerifyRawIssuerSignature: package
// qv2_test imports github.com/layervai/qurl-go/qv2 and touches ONLY exported
// symbols. The white-box test (verify_raw_issuer_signature_test.go) pins the full
// error taxonomy via unexported helpers; this one proves the actual purpose of the
// export — that a cross-language conformance verifier living outside the package
// can mint a signed claims+signature and exercise the signature class (accept plus
// rejects) through the public surface alone. The claims construction below
// deliberately re-derives valid wire values from the standard library rather than
// reusing the package-internal test helpers, because an external caller cannot
// import them; that separation is the point of the test.

// blackBoxClaims builds a claims value whose field shapes pass SignClaims's strict
// pre-sign validation, using only the standard library + exported qv2 symbols. The
// key fields mirror what an issuer emits: 32-byte raw X25519 public keys and a
// P-256 SPKI DER resource key, all unpadded base64url. Liveness (nbf/exp) is not
// checked at sign time, so fixed timestamps are fine.
func blackBoxClaims(t *testing.T) *qv2.Claims {
	t.Helper()
	return &qv2.Claims{
		V:                    qv2.Version,
		Iss:                  qv2.Issuer,
		Iat:                  1781910000,
		Nbf:                  1781910000,
		Exp:                  1781910300,
		Jti:                  "qurl_01JBLACKBOX",
		CellPublicKeyB64:     rawKeyB64(0x11),
		CellID:               "cell-bb",
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: resourceKeyB64(t),
		QurlUserPublicKeyB64: rawKeyB64(0x22),
	}
}

// rawKeyB64 returns a deterministic 32-byte raw key as unpadded base64url. The
// strict parser length-checks shape (32 bytes), not curve membership, so a fill
// pattern suffices for the X25519-shaped public-key fields.
func rawKeyB64(fill byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// resourceKeyB64 returns a real P-256 SPKI DER as unpadded base64url, so the
// resource-key DER length window in the strict parser passes with realistic bytes.
func resourceKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resource key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource SPKI: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// TestVerifyRawIssuerSignature_BlackBox proves an external caller can drive the
// signature class entirely through exported symbols: mint with GenerateLocalSigner
// + SignClaims, recover the verifying key via PublicKeyDER + ParseP256PublicKeyDER,
// then accept a valid signature and reject the canonical fault cases against the
// exported sentinels (ErrSignature / ErrSignatureLength) via errors.Is.
func TestVerifyRawIssuerSignature_BlackBox(t *testing.T) {
	signer, err := qv2.GenerateLocalSigner("qurl-issuer-key-blackbox")
	if err != nil {
		t.Fatalf("GenerateLocalSigner: %v", err)
	}

	claimsB64, rawSig, err := qv2.SignClaims(context.Background(), signer, blackBoxClaims(t))
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}

	// Recover the issuer public key the only way an external caller can: through the
	// exported DER round-trip (LocalSigner.priv is unexported by design).
	der, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	pub, err := qv2.ParseP256PublicKeyDER(der)
	if err != nil {
		t.Fatalf("ParseP256PublicKeyDER: %v", err)
	}

	t.Run("accept", func(t *testing.T) {
		if err := qv2.VerifyRawIssuerSignature(pub, claimsB64, rawSig); err != nil {
			t.Fatalf("valid signature must verify, got %v", err)
		}
	})

	t.Run("tamper", func(t *testing.T) {
		// A valid signature over the wrong message: flip the first base64url char of
		// the claims so the signing digest changes. Must fail at the curve check with
		// the bare ErrSignature sentinel.
		repl := byte('A')
		if claimsB64[0] == 'A' {
			repl = 'B'
		}
		tampered := string(repl) + claimsB64[1:]
		if err := qv2.VerifyRawIssuerSignature(pub, tampered, rawSig); !errors.Is(err, qv2.ErrSignature) {
			t.Fatalf("tampered claims must return ErrSignature, got %v", err)
		}
	})

	t.Run("wrong_length", func(t *testing.T) {
		// A non-64-byte signature is rejected at the length gate, before any curve
		// math, with ErrSignatureLength (which wraps ErrSignature).
		if err := qv2.VerifyRawIssuerSignature(pub, claimsB64, rawSig[:len(rawSig)-1]); !errors.Is(err, qv2.ErrSignatureLength) {
			t.Fatalf("short signature must return ErrSignatureLength, got %v", err)
		}
	})

	t.Run("nil_key", func(t *testing.T) {
		if err := qv2.VerifyRawIssuerSignature(nil, claimsB64, rawSig); !errors.Is(err, qv2.ErrSignature) {
			t.Fatalf("nil public key must return a wrapped ErrSignature, got %v", err)
		}
	})
}
