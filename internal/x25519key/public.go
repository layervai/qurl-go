// Package x25519key validates X25519 public identities at control-plane and
// transport trust boundaries.
package x25519key

import (
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Size is the encoded X25519 key size in bytes. Public and private values use
// the same fixed-width encoding.
const Size = 32

var canonicalUPrime = func() (prime [Size]byte) {
	for i := range prime {
		prime[i] = 0xff
	}
	prime[0] = 0xed
	prime[Size-1] = 0x7f
	return prime
}()

// lowOrderProbeScalar is read-only input to X25519. X25519 copies and clamps
// the scalar internally, so one shared zero-value array avoids a per-validation
// allocation without introducing mutable operation state.
var lowOrderProbeScalar [Size]byte

// DecodeCanonicalBase64 decodes the single padded standard-base64 spelling of
// a usable, canonical X25519 public key. Durable public identities deliberately
// reject alternate text encodings and alternate field representatives because
// byte fingerprints and equality checks must have one meaning.
func DecodeCanonicalBase64(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode padded standard base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("public key is not canonical padded standard base64")
	}
	if err := ValidatePublic(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ValidatePublic rejects wrong-length, non-canonical, and low-order X25519
// public keys. RFC 7748 permits generic implementations to accept non-canonical
// u-coordinates for interoperability, but a pinned server identity must have one
// byte representation and must be capable of a nonzero key agreement.
func ValidatePublic(raw []byte) error {
	if len(raw) != Size {
		return fmt.Errorf("X25519 public key must be %d bytes, got %d", Size, len(raw))
	}
	if !isCanonicalU(raw) {
		return errors.New("X25519 public key has a non-canonical u-coordinate")
	}
	// The scalar is arbitrary: X25519 clamps it to a valid nonzero scalar, and
	// every low-order public input produces the forbidden all-zero secret.
	if _, err := curve25519.X25519(lowOrderProbeScalar[:], raw); err != nil {
		return fmt.Errorf("X25519 public key is low-order: %w", err)
	}
	return nil
}

func isCanonicalU(raw []byte) bool {
	// p = 2^255-19, encoded little-endian as ed ff ... ff 7f. Compare from the
	// most-significant byte without allocating a big.Int.
	for i := Size - 1; i >= 0; i-- {
		if raw[i] != canonicalUPrime[i] {
			return raw[i] < canonicalUPrime[i]
		}
	}
	return false // raw == p is non-canonical.
}
