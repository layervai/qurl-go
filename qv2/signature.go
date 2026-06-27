package qv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ECDSA P-256 signature handling for the pinned qURL v2 wire format.
//
// The pinned wire signature is fixed-width raw r||s: exactly 64 bytes, each of r
// and s left-zero-padded to 32 bytes, with s low-S normalized (s <= N/2). AWS
// KMS returns ASN.1 DER and does NOT low-S normalize, so the issuer signer must
// convert DER -> low-S raw at signing time. Verifiers convert raw -> (r, s) and
// MUST reject any signature that is not exactly 64 bytes or not low-S normalized,
// so the encoding is enforced and not merely produced.

// p256SignatureBytes is the exact length of a raw r||s P-256 signature.
const p256SignatureBytes = 64

// p256ScalarBytes is the fixed width of each of r and s for P-256.
const p256ScalarBytes = 32

var (
	// ErrSignatureLength is returned when a wire signature is not exactly 64
	// bytes. It wraps ErrSignature so callers can match either.
	ErrSignatureLength = fmt.Errorf("%w: wire signature must be exactly %d bytes (raw r||s)", ErrSignature, p256SignatureBytes)
	// ErrSignatureHighS is returned when s is not low-S normalized (s > N/2).
	ErrSignatureHighS = fmt.Errorf("%w: signature is not low-S normalized", ErrSignature)
	// ErrSignatureScalarRange is returned when r or s is not in [1, N-1].
	ErrSignatureScalarRange = fmt.Errorf("%w: signature scalar out of range [1, N-1]", ErrSignature)
	// ErrSignatureMalformedDER is returned when a DER signature cannot be parsed.
	ErrSignatureMalformedDER = errors.New("qv2: malformed ASN.1 DER ECDSA signature")
)

// curve is the single pinned curve. There is no algorithm negotiation.
var curve = elliptic.P256()

// halfOrder is N/2 for P-256, the low-S threshold: a signature is low-S iff
// s <= halfOrder. Computed once at init from the curve parameters.
var halfOrder = new(big.Int).Rsh(curve.Params().N, 1)

// ecdsaDERSignature mirrors the ASN.1 SEQUENCE { INTEGER r, INTEGER s } that AWS
// KMS (and Go's ecdsa.SignASN1) produce for an ECDSA signature.
type ecdsaDERSignature struct {
	R *big.Int
	S *big.Int
}

// derToRawLowS converts an ASN.1 DER ECDSA signature (as returned by AWS KMS) to
// the pinned fixed-width raw r||s wire format, low-S normalized. This is the
// signer-side conversion; it is exported via no public API here, but kept so the
// raw/DER round-trip is verifiable in tests against the golden vectors.
func derToRawLowS(der []byte) ([]byte, error) {
	var sig ecdsaDERSignature
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureMalformedDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrSignatureMalformedDER, len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("%w: nil scalar", ErrSignatureMalformedDER)
	}
	if !scalarInRange(sig.R) || !scalarInRange(sig.S) {
		return nil, ErrSignatureScalarRange
	}

	s := sig.S
	if s.Cmp(halfOrder) > 0 {
		// High-S: replace s with N - s. The negation maps to the same valid
		// signature (ECDSA's two-valued s) and yields the canonical low-S form.
		s = new(big.Int).Sub(curve.Params().N, s)
	}
	return scalarsToRaw(sig.R, s), nil
}

// rawToScalars validates a 64-byte raw r||s wire signature and returns (r, s).
// It enforces the full verifier contract: exact length, scalars in [1, N-1], and
// low-S. A high-S, wrong-length, or out-of-range signature is rejected here
// BEFORE any curve math, so the pinned encoding is enforced and not merely
// expected.
func rawToScalars(raw []byte) (r, s *big.Int, err error) {
	if len(raw) != p256SignatureBytes {
		return nil, nil, fmt.Errorf("%w (got %d)", ErrSignatureLength, len(raw))
	}
	r = new(big.Int).SetBytes(raw[:p256ScalarBytes])
	s = new(big.Int).SetBytes(raw[p256ScalarBytes:])
	if !scalarInRange(r) || !scalarInRange(s) {
		return nil, nil, ErrSignatureScalarRange
	}
	if s.Cmp(halfOrder) > 0 {
		return nil, nil, ErrSignatureHighS
	}
	return r, s, nil
}

// scalarInRange reports whether x is in [1, N-1] (a valid ECDSA scalar). Zero and
// values >= N are rejected.
func scalarInRange(x *big.Int) bool {
	if x.Sign() <= 0 {
		return false
	}
	return x.Cmp(curve.Params().N) < 0
}

// scalarsToRaw renders r and s as a fixed-width 64-byte raw signature, each
// scalar left-zero-padded to 32 bytes. FillBytes panics if a scalar exceeds 32
// bytes, which cannot happen for in-range P-256 scalars (callers validate range).
func scalarsToRaw(r, s *big.Int) []byte {
	out := make([]byte, p256SignatureBytes)
	r.FillBytes(out[:p256ScalarBytes])
	s.FillBytes(out[p256ScalarBytes:])
	return out
}

// verifyRawSignature verifies a raw r||s wire signature over the qURL v2 signing
// digest for claimsB64 using pub. It rejects non-64-byte, out-of-range, and
// high-S signatures before the ECDSA check. Returns nil on success, a wrapped
// ErrSignature otherwise.
func verifyRawSignature(pub *ecdsa.PublicKey, claimsB64 string, rawSig []byte) error {
	if pub == nil {
		return fmt.Errorf("%w: nil public key", ErrSignature)
	}
	r, s, err := rawToScalars(rawSig)
	if err != nil {
		return err
	}
	digest := signingDigest(claimsB64)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrSignature
	}
	return nil
}
