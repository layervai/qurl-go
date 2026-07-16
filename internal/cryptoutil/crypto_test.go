package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

func TestRandomValues(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("RandomBytes length = %d, want 32", len(b))
	}
	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })
	rand.Reader = bytes.NewReader([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
	})
	value64, err := RandomUint64()
	if err != nil {
		t.Fatalf("RandomUint64: %v", err)
	}
	if value64 != 0x0102030405060708 {
		t.Fatalf("RandomUint64 = %#x, want %#x", value64, uint64(0x0102030405060708))
	}
	value32, err := RandomUint32()
	if err != nil {
		t.Fatalf("RandomUint32: %v", err)
	}
	if value32 != 0x090a0b0c {
		t.Fatalf("RandomUint32 = %#x, want %#x", value32, uint32(0x090a0b0c))
	}
	rand.Reader = originalReader
	for _, upperBound := range []int64{1, 2, 7, math.MaxInt64} {
		for range 100 {
			value, err := RandomInt64n(upperBound)
			if err != nil {
				t.Fatalf("RandomInt64n(%d): %v", upperBound, err)
			}
			if value < 0 || value >= upperBound {
				t.Fatalf("RandomInt64n(%d) = %d", upperBound, value)
			}
		}
	}
	for _, upperBound := range []int64{0, -1, math.MinInt64} {
		if _, err := RandomInt64n(upperBound); err == nil {
			t.Fatalf("RandomInt64n(%d) succeeded", upperBound)
		}
	}
}

func TestRandomInt64nRejectsIncompleteRange(t *testing.T) {
	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })
	// For bound 3 the rejection threshold is 1: zero must be discarded, while
	// the following value 5 is accepted and maps to 2.
	source := bytes.NewReader(append(make([]byte, 15), 5))
	rand.Reader = source
	value, err := RandomInt64n(3)
	if err != nil {
		t.Fatal(err)
	}
	if value != 2 || source.Len() != 0 {
		t.Fatalf("RandomInt64n(3) = %d with %d unread bytes, want 2 after two draws", value, source.Len())
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, want 0", i, v)
		}
	}
	Wipe(nil) // must not panic
}
