package qurl

import "encoding/base64"

// validTestNHPServerPublicKeyB64 is the canonical X25519 base point (u = 9).
// It is deterministic test data, not a private key or production identity.
const validTestNHPServerPublicKeyB64 = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func nonCanonicalTestNHPServerPublicKeyB64() string {
	key := make([]byte, 32)
	key[0] = 0xed
	for i := 1; i < len(key)-1; i++ {
		key[i] = 0xff
	}
	key[len(key)-1] = 0x7f // p = 2^255-19 is not a canonical representative.
	return base64.StdEncoding.EncodeToString(key)
}
