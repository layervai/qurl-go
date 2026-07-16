package x25519key

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
)

func TestDecodeCanonicalBase64(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if _, err := DecodeCanonicalBase64(encoded); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := DecodeCanonicalBase64(base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes())); err == nil {
		t.Fatal("unpadded identity must be rejected")
	}
	if _, err := DecodeCanonicalBase64("not-base64!"); err == nil || !strings.Contains(err.Error(), "decode padded standard base64") {
		t.Fatalf("invalid-alphabet error = %v, want base64 decode error", err)
	}
	withNewline := encoded[:4] + "\n" + encoded[4:]
	if _, err := DecodeCanonicalBase64(withNewline); err == nil || !strings.Contains(err.Error(), "not canonical padded standard base64") {
		t.Fatalf("alternate-spelling error = %v, want canonicalization error", err)
	}
}

func TestValidatePublicRejectsUnusableOrNonCanonicalKeys(t *testing.T) {
	valid, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	highBitAlias := append([]byte(nil), valid.PublicKey().Bytes()...)
	highBitAlias[Size-1] |= 0x80

	nonCanonical := make([]byte, Size)
	nonCanonical[0] = 0xed
	for i := 1; i < Size-1; i++ {
		nonCanonical[i] = 0xff
	}
	nonCanonical[Size-1] = 0x7f // exactly p, not the representative [0,p)

	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{name: "wrong length", key: make([]byte, Size-1)},
		{name: "low order", key: make([]byte, Size)},
		{name: "non canonical", key: nonCanonical},
		{name: "high bit alias", key: highBitAlias},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePublic(tc.key); err == nil {
				t.Fatal("invalid public key accepted")
			}
		})
	}
}

func TestValidatePublicSharedProbeScalarConcurrent(t *testing.T) {
	valid, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before := lowOrderProbeScalar
	errors := make(chan error, 32)
	var workers sync.WaitGroup
	for range cap(errors) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				if err := ValidatePublic(valid.PublicKey().Bytes()); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent validation: %v", err)
	}
	if lowOrderProbeScalar != before {
		t.Fatal("X25519 mutated the shared low-order probe scalar")
	}
}
