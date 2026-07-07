// Package nhpwire is the internal NHP Noise wire codec shared by the public
// relayknock package (client/initiator API) and the relayknocktest test-support
// package (server/responder helpers). It owns the role-symmetric transcript —
// BuildMessage seals a message, DecryptMessage opens one — with no header-type
// restriction; the type-gating that distinguishes initiator from reply messages
// lives in the wrapping packages.
//
// This package is under internal/ so nothing outside the relayknock module tree
// can import it: a client SDK's public surface never ships these responder-role
// wire ops. The wire format is fenced byte-for-byte by the golden vectors that
// exercise it through relayknock.BuildKnock / relayknock.DecryptReply.
package nhpwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// Crypto primitives for the NHP Noise wire profile (the reference NHP relay
// implementation's scheme/curve and kdf). Every helper here is fenced by the
// golden vectors via the handshake it feeds; do not "modernize" one (e.g. swap
// HMAC for keyed-BLAKE2s) without re-deriving the vectors from the reference
// implementation — a silent divergence breaks server interop.

const (
	// PublicKeySize is the X25519 public/private key length. Exported because the
	// wrapping packages validate key sizes before building a message.
	PublicKeySize = 32

	gcmNonceSize  = 12
	gcmTagSize    = 16
	timestampSize = 8
	hashSize      = 32 // BLAKE2s-256 / SHA-256 digest
)

// Noise init constants (from the reference NHP relay implementation) — the
// literal UTF-8 bytes the chain hash / chain key seed from.
var (
	initialHash     = []byte("NHP hashgen v.20230421@deepcloudsdp.com")
	initialChainKey = []byte("NHP keygen v.20230421@clouddeep.cn")

	// KDF domain-separation tags (reference NHP relay implementation kdfTag1/2).
	kdfTag1 = []byte{0x01}
	kdfTag2 = []byte{0x02}
)

// newBlake2s returns a fresh BLAKE2s-256 hash. The nil-key form never errors.
func newBlake2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("blake2s.New256: %v", err)) // unreachable with a nil key
	}
	return h
}

// blake2sHash is the one-shot H(in0 ‖ in1 ‖ …).
func blake2sHash(inputs ...[]byte) []byte {
	h := newBlake2s()
	for _, in := range inputs {
		h.Write(in)
	}
	return h.Sum(nil)
}

// mac is HMAC(key, in0 ‖ in1 ‖ …) over the *unkeyed* BLAKE2s (Go
// NoiseFactory.HMAC1/2). NOT keyed-BLAKE2s — the two differ and the keyed form
// would silently break server interop. Fenced by the golden vectors.
func mac(key []byte, inputs ...[]byte) []byte {
	m := hmac.New(newBlake2s, key)
	for _, in := range inputs {
		m.Write(in)
	}
	return m.Sum(nil)
}

// keyGen1 / keyGen2 are hand-rolled HKDF (RFC 5869) mirroring Go
// NoiseFactory.KeyGen1/2: extract prk = HMAC(key, input), then chain
// HMAC(prk, prev ‖ counter) with counter bytes 0x01/0x02.
func keyGen1(key, input []byte) []byte {
	prk := mac(key, input)
	return mac(prk, kdfTag1)
}

func keyGen2(key, input []byte) (dst0, dst1 []byte) {
	prk := mac(key, input)
	dst0 = mac(prk, kdfTag1)
	dst1 = mac(prk, dst0, kdfTag2)
	return dst0, dst1
}

// mixKey is KeyGen1 (Go NoiseFactory.MixKey).
func mixKey(key, input []byte) []byte { return keyGen1(key, input) }

// X25519Public derives the X25519 public key: X25519(priv, basepoint). Matches
// the js-agent (@noble) and Go curve25519 — scalar clamping is internal.
// Exported so the golden-vector test can recompute the pinned public keys.
func X25519Public(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// x25519Shared is the ECDH shared secret X25519(priv, peerPub). Returns an error
// on a low-order point (all-zero output), matching the js-agent's throw.
func x25519Shared(priv, peerPub []byte) ([]byte, error) {
	return curve25519.X25519(priv, peerPub)
}

// aeadSeal is AES-256-GCM Seal → ciphertext ‖ 16-byte tag (NHP default suite
// GCM_AES256). key must be 32 bytes; nonce 12.
func aeadSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// aeadOpen is AES-256-GCM Open; errors if the tag fails to verify.
func aeadOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key) // 32-byte key ⇒ AES-256
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block) // 12-byte nonce, 16-byte tag
}
