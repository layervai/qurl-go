package relayknock

import (
	"crypto/sha256"
	"encoding/base64"
)

// Relay routing-id derivation. The NHP Noise wire crypto (curve/aead/kdf) lives
// in the internal nhpwire package; only the public relay {serverId} fingerprint
// stays here, because it is part of the public relayknock API (relay.go composes
// the POST path from it and callers derive it directly).

// PubKeyFingerprint is the {serverId} in POST /relay/{serverId}:
// base64url(SHA-256(rawPubKey)[0:8]) with no padding. Byte-identical to the Go
// reference utils.PubKeyFingerprint and the browser NHP agent's fingerprint
// derivation, so it is the single source of the relay routing id every NHP
// caller derives.
func PubKeyFingerprint(rawPubKey []byte) string {
	digest := sha256.Sum256(rawPubKey)
	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

// PubKeyFingerprintLen is the character length of a PubKeyFingerprint:
// base64url of 8 bytes, unpadded, is 11 characters.
const PubKeyFingerprintLen = 11
