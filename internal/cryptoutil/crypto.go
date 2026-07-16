// Package cryptoutil owns the module's small cryptographic-randomness and
// secret-buffer primitives. Keeping these operations here prevents the relay,
// native UDP, and control-plane paths from drifting at security boundaries.
package cryptoutil

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
)

// RandomBytes returns n bytes from the operating system's cryptographic random
// source.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomUint64 returns a cryptographically random uint64.
func RandomUint64() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// RandomUint32 returns a cryptographically random uint32.
func RandomUint32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// RandomInt64n returns a cryptographically random integer in [0, upperBound)
// without modulo bias. A non-positive bound is a programming error.
func RandomInt64n(upperBound int64) (int64, error) {
	if upperBound <= 0 {
		return 0, errors.New("cryptoutil: random bound must be positive")
	}
	bound := uint64(upperBound)
	// Reject the incomplete range below 2^64 mod bound. The remaining uint64
	// values divide evenly into bound buckets, avoiding modulo bias without a
	// per-draw big.Int allocation.
	threshold := -bound % bound
	for {
		value, err := RandomUint64()
		if err != nil {
			return 0, err
		}
		if value >= threshold {
			// #nosec G115 -- the remainder is < bound, which came from a positive int64.
			return int64(value % bound), nil
		}
	}
}

// Wipe zeroes a sensitive buffer. KeepAlive prevents the clear from being
// optimized away before the bytes become unreachable.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
