// Package relayknock is the low-level NHP relay-knock layer of the qURL Go SDK.
// Most users do not import it directly — the qurl package drives it as part of
// EnterPortal; reach for relayknock only to perform a raw NHP knock outside the
// qURL flow.
//
// It is a dependency-light, clean-room Go implementation of the generic NHP
// wire profile: NHP Noise messages (X25519 / AES-256-GCM / BLAKE2s) plus the
// browser-relay transport that carries selected messages as a binary POST to
// {relayBaseURL}/relay/{serverId}. The relay forwards them to a now-private NHP
// server. The package speaks three initiator messages over that HTTP transport:
// a knock (NHP_KNK) the server answers with an NHP_ACK — authorizing, opening
// access for the caller IP, and returning a reply body the caller decrypts; a
// one-way OTP (NHP_OTP) fire-and-forget dispatch the server never replies to (a
// conforming relay acknowledges it at the HTTP layer); and a registration
// (NHP_REG) round trip the server answers with an NHP_RAK. A round trip under
// overload comes back as an NHP_COK cookie-challenge ("retry later") instead.
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
// body itself. Single messages only: its transport-neutral builder emits the
// initiator types NHP_KNK (knock), NHP_LST (list/query), NHP_REG (register), and
// the one-way NHP_OTP. Its decoder admits the reply types NHP_ACK, NHP_LRT,
// NHP_COK, and NHP_RAK. The HTTP helpers intentionally do not transport
// NHP_LST/NHP_LRT; native assignment carries those packets directly over UDP.
// No multi-packet flows: the re-knock/cookie-challenge answer (NHP_RKN) stays out
// of scope, so a caller treats NHP_COK as "retry later".
//
// # Egress-IP invariant
//
// The NHP server opens access for the source IP of the relay POST. The knock
// and the subsequent resource request MUST therefore share an egress IP, or the
// resource request will hit a server that opened access for a different address.
package relayknock
