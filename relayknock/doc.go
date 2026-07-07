// Package relayknock is the low-level NHP relay-knock layer of the qURL Go SDK.
// Most users do not import it directly — the qurl package drives it as part of
// EnterPortal; reach for relayknock only to perform a raw NHP knock outside the
// qURL flow.
//
// It is a dependency-light, clean-room Go implementation of the generic NHP
// relay-knock wire profile: an NHP Noise knock (X25519 /
// AES-256-GCM / BLAKE2s) carried as a binary POST {relayBaseURL}/relay/{serverId}
// to an internet-facing NHP relay, which forwards it to a now-private NHP server.
// The server authorizes, opens access for the caller IP, and replies with an
// NHP_ACK whose body the caller decrypts.
//
// The wire format is fenced byte-for-byte by the golden vectors in
// knock_golden_test.go, which are shared with the other NHP implementations. If this
// package reproduces those bytes, it is wire-compatible with the deployed relay by
// construction.
//
// # Dependency policy
//
// The only non-stdlib dependency is golang.org/x/crypto (curve25519, blake2s).
// Keeping the full server stack out of this package keeps the SDK small; every
// constant and offset is pinned by the golden vectors instead.
//
// # Scope
//
// Generic wire profile only: this package knows packet framing and the Noise
// handshake, NOT any application body shape (e.g. qURL claims). A
// caller supplies an already-serialized body and interprets the decrypted reply
// body itself. Single messages only: it builds the initiator types NHP_KNK
// (knock), NHP_REG (register), and the one-way NHP_OTP — which the server never
// replies to; a conforming relay acknowledges dispatch at the HTTP layer — and
// decrypts the reply types NHP_ACK, NHP_COK, and NHP_RAK. No multi-packet
// flows: the re-knock/cookie-challenge answer (NHP_RKN) stays out of scope, so
// a caller treats NHP_COK as "retry later".
//
// # Egress-IP invariant
//
// The NHP server opens access for the source IP of the relay POST. The knock
// and the subsequent resource request MUST therefore share an egress IP, or the
// resource request will hit a server that opened access for a different address.
package relayknock
