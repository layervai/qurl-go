package qurl_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/layervai/qurl-go/qurl"
)

// This file is the EXTERNAL-caller proof for VerifyRawIssuerSignature: package
// qurl_test imports github.com/layervai/qurl-go/qurl and touches ONLY exported
// symbols. The white-box test (verify_raw_issuer_signature_test.go) pins the full
// error taxonomy via unexported helpers; this one proves the actual purpose of the
// export — that a cross-language conformance verifier living outside the package
// can mint a signed claims+signature and exercise the signature class (accept plus
// rejects) through the public surface alone. The claims construction below
// deliberately re-derives valid wire values from the standard library rather than
// reusing the package-internal test helpers, because an external caller cannot
// import them; that separation is the point of the test.

func blackBoxCreateParams(t *testing.T) qurl.CreateParams {
	t.Helper()
	return qurl.CreateParams{
		CellPublicKey:     bytes.Repeat([]byte{0x11}, 32),
		CellID:            "cell-bb",
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: resourceKeyDER(t),
		JTI:               "qurl_01JBLACKBOX",
		IssuedAt:          1781910000,
		NotBefore:         1781910000,
		Expiry:            1781910300,
	}
}

func resourceKeyDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resource key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource SPKI: %v", err)
	}
	return der
}

// TestVerifyRawIssuerSignature_BlackBox proves an external caller can drive the
// signature class entirely through exported symbols.
func TestVerifyRawIssuerSignature_BlackBox(t *testing.T) {
	signer, err := qurl.GenerateLocalSigner("qurl-issuer-key-blackbox")
	if err != nil {
		t.Fatalf("GenerateLocalSigner: %v", err)
	}

	link, err := qurl.CreatePortalWithParams(context.Background(), signer, blackBoxCreateParams(t))
	if err != nil {
		t.Fatalf("CreatePortalWithParams: %v", err)
	}

	// Recover the issuer public key the only way an external caller can: through the
	// exported DER round-trip (LocalSigner.priv is unexported by design).
	der, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	pub, err := qurl.ParseP256PublicKeyDER(der)
	if err != nil {
		t.Fatalf("ParseP256PublicKeyDER: %v", err)
	}
	trust, err := qurl.NewTrustStore(map[string]*ecdsa.PublicKey{signer.KID(): pub})
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	fragment, err := qurl.VerifyLink(link, trust)
	if err != nil {
		t.Fatalf("VerifyLink: %v", err)
	}
	claimsB64 := fragment.ClaimsB64
	rawSig, err := base64.RawURLEncoding.DecodeString(fragment.SigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	t.Run("accept", func(t *testing.T) {
		if err := qurl.VerifyRawIssuerSignature(pub, claimsB64, rawSig); err != nil {
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
		if err := qurl.VerifyRawIssuerSignature(pub, tampered, rawSig); !errors.Is(err, qurl.ErrSignature) {
			t.Fatalf("tampered claims must return ErrSignature, got %v", err)
		}
	})

	t.Run("wrong_length", func(t *testing.T) {
		if err := qurl.VerifyRawIssuerSignature(pub, claimsB64, rawSig[:len(rawSig)-1]); !errors.Is(err, qurl.ErrSignature) {
			t.Fatalf("short signature must return ErrSignature, got %v", err)
		}
	})

	t.Run("nil_key", func(t *testing.T) {
		if err := qurl.VerifyRawIssuerSignature(nil, claimsB64, rawSig); !errors.Is(err, qurl.ErrSignature) {
			t.Fatalf("nil public key must return a wrapped ErrSignature, got %v", err)
		}
	})
}
