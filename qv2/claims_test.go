package qv2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

// TestPublicKeyHashFromB64 proves the canonical revocation-index hash is the
// lowercase-hex SHA-256 of the DECODED key bytes (not of the base64url string),
// computed independently here. This format must match the nhp/qurl-service
// revocation indexes, so it is pinned against a hand-computed digest.
func TestPublicKeyHashFromB64(t *testing.T) {
	raw := make([]byte, x25519PublicKeyBytes)
	for i := range raw {
		raw[i] = 0x44
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	got, err := PublicKeyHashFromB64(b64)
	if err != nil {
		t.Fatalf("PublicKeyHashFromB64: %v", err)
	}

	sum := sha256.Sum256(raw) // digest of the DECODED bytes, not the string
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("hash = %q, want %q (lowercase hex SHA-256 of decoded bytes)", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(got))
	}
}

// TestPublicKeyHashFromB64_RejectsBadEncoding proves a non-base64url input is
// rejected (ErrEncoding) rather than hashed — the preimage must be exactly the
// decoded signed bytes, so a malformed encoding cannot silently produce a hash.
func TestPublicKeyHashFromB64_RejectsBadEncoding(t *testing.T) {
	if _, err := PublicKeyHashFromB64("not valid base64url!!"); !errors.Is(err, ErrEncoding) {
		t.Fatalf("bad encoding: want ErrEncoding, got %v", err)
	}
}
