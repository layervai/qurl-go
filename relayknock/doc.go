// Package relayknock is the low-level NHP relay-knock layer of the qURL Go SDK.
// Most users do not import it directly — the qurl package drives it as part of
// EnterPortal; reach for relayknock only to perform a raw NHP knock outside the
// qURL flow.
//
// It is a dependency-light, clean-room Go implementation of the generic NHP
// wire profile: NHP Noise messages (X25519 / AES-256-GCM / BLAKE2s) plus the
// browser-relay transport that carries the browser knock family as a binary POST
// to {relayBaseURL}/relay/{serverId}. The relay forwards them to a now-private NHP
// server. Knock sends NHP_KNK, which the server answers with NHP_ACK or, under
// overload, NHP_COK. Advanced callers can combine BuildMessage with
// RelayPost for the other browser relay types NHP_RKN and NHP_EXT. Agent
// lifecycle messages NHP_OTP, NHP_REG, and NHP_LST use native UDP through the
// relayknock/nativeudp package and never the browser HTTP relay.
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
// initiator types NHP_KNK (knock), NHP_LST (list/query), NHP_RKN (re-knock),
// NHP_REG (register), NHP_EXT (clean exit), and the one-way NHP_OTP. Its decoder
// admits the reply types NHP_ACK, NHP_LRT, NHP_COK, and NHP_RAK. The typed Knock
// path transports only NHP_KNK/NHP_ACK/NHP_COK; raw RelayPost remains
// available for caller-built NHP_RKN and NHP_EXT packets. Native UDP carries
// assignment and registered-agent lifecycle directly with the Hub or assigned
// cell.
//
// # Egress-IP invariant
//
// The NHP server opens access for the source IP of the relay POST. The knock
// and the subsequent resource request MUST therefore share an egress IP, or the
// resource request will hit a server that opened access for a different address.
package relayknock
