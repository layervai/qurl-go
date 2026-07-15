// Package cryptoutil owns the module's small cryptographic-randomness and
// secret-buffer primitives. Keeping these operations here prevents the relay,
// native UDP, and control-plane paths from drifting at security boundaries.
package cryptoutil

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"
)

// RandomBytes returns n bytes from the operating system's cryptographic random
// source.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomUint64 returns a cryptographically random uint64.
func RandomUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// RandomUint32 returns a cryptographically random uint32.
func RandomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// Wipe zeroes a sensitive buffer. KeepAlive prevents the clear from being
// optimized away before the bytes become unreachable.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
