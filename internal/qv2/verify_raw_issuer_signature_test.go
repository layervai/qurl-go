package qv2

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

// TestVerifyRawIssuerSignature pins the exported signature-class entry point's
// error taxonomy across the conformance signature class's cases (accept / high-S /
// wrong-length / scalar-range / tamper) plus the nil-key guard. This is the public
// surface cross-language conformance tooling calls, so the sentinel each fault maps
// to must not drift. It is white-box: the high-S, wrong-length, and scalar-range
// cases construct their malformed inputs with the unexported wire-format helpers.
func TestVerifyRawIssuerSignature(t *testing.T) {
	signer := newTestSigner(t)
	pub := &signer.priv.PublicKey
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))

	t.Run("accept", func(t *testing.T) {
		if err := VerifyRawIssuerSignature(pub, claimsB64, rawSig); err != nil {
			t.Fatalf("valid signature must verify, got %v", err)
		}
	})

	t.Run("high_s", func(t *testing.T) {
		// Re-spell the valid low-S signature as its high-S complement (s -> N-s,
		// same r): structurally well-formed but rejected before the curve check.
		n := elliptic.P256().Params().N
		r := new(big.Int).SetBytes(rawSig[:p256ScalarBytes])
		s := new(big.Int).SetBytes(rawSig[p256ScalarBytes:])
		highS := scalarsToRaw(r, new(big.Int).Sub(n, s))
		if err := VerifyRawIssuerSignature(pub, claimsB64, highS); !errors.Is(err, ErrSignatureHighS) {
			t.Fatalf("high-S signature must return ErrSignatureHighS, got %v", err)
		}
	})

	t.Run("wrong_length", func(t *testing.T) {
		// Directly exercise the len(raw) != 64 gate with off-by-one slices...
		for _, bad := range [][]byte{rawSig[:p256SignatureBytes-1], append(append([]byte{}, rawSig...), 0)} {
			if err := VerifyRawIssuerSignature(pub, claimsB64, bad); !errors.Is(err, ErrSignatureLength) {
				t.Fatalf("%d-byte signature must return ErrSignatureLength, got %v", len(bad), err)
			}
		}
		// ...and the realistic wrong-wire-form case: a DER blob (never exactly 64 bytes).
		der, err := asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(rawSig[:p256ScalarBytes]),
			new(big.Int).SetBytes(rawSig[p256ScalarBytes:]),
		})
		if err != nil {
			t.Fatalf("marshal DER: %v", err)
		}
		if err := VerifyRawIssuerSignature(pub, claimsB64, der); !errors.Is(err, ErrSignatureLength) {
			t.Fatalf("DER (non-64-byte) signature must return ErrSignatureLength, got %v", err)
		}
	})

	t.Run("scalar_range", func(t *testing.T) {
		// r = 0 is outside the valid scalar range [1, N-1]; rejected before the
		// curve check with ErrSignatureScalarRange (the taxonomy the godoc advertises).
		zeroR := scalarsToRaw(big.NewInt(0), new(big.Int).SetBytes(rawSig[p256ScalarBytes:]))
		if err := VerifyRawIssuerSignature(pub, claimsB64, zeroR); !errors.Is(err, ErrSignatureScalarRange) {
			t.Fatalf("zero r must return ErrSignatureScalarRange, got %v", err)
		}
	})

	t.Run("tamper", func(t *testing.T) {
		// A valid, well-formed signature over the wrong message: flip the first
		// base64url char of the claims (changes decoded byte 0). Must fail at the
		// curve check with the bare ErrSignature sentinel, NOT a length/high-S fault.
		repl := byte('A')
		if claimsB64[0] == 'A' {
			repl = 'B'
		}
		tampered := string(repl) + claimsB64[1:]
		err := VerifyRawIssuerSignature(pub, tampered, rawSig)
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("tampered claims must return ErrSignature, got %v", err)
		}
		if errors.Is(err, ErrSignatureHighS) || errors.Is(err, ErrSignatureLength) {
			t.Fatalf("payload tamper must fail at the curve check, not the encoding gate, got %v", err)
		}
	})

	t.Run("nil_key", func(t *testing.T) {
		if err := VerifyRawIssuerSignature(nil, claimsB64, rawSig); !errors.Is(err, ErrSignature) {
			t.Fatalf("nil public key must return a wrapped ErrSignature, got %v", err)
		}
	})
}
