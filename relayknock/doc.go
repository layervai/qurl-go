// Package relayknock is a dependency-light, clean-room Go implementation of the
// generic NHP relay-knock wire profile: an NHP Noise knock (X25519 /
// AES-256-GCM / BLAKE2s) carried as a binary POST {relayBaseURL}/relay/{serverId}
// to an internet-facing NHP relay, which forwards it to a now-private NHP server.
// The server authorizes, opens its access-control firewall for the caller IP, and
// replies with an NHP_ACK whose body the caller decrypts.
//
// It is a port of the browser JS NHP agent's crypto/handshake code and a
// clean-room smoke client. The wire format is fenced byte-for-byte by the golden
// vectors in knock_golden_test.go, which come from the browser agent's
// cross-language fixtures (themselves pinned to the reference NHP relay server
// output). If this port reproduces those bytes, it is wire-compatible with the
// deployed server by construction.
//
// # Dependency policy
//
// The only non-stdlib dependency is golang.org/x/crypto (curve25519, blake2s).
// This package MUST NOT import the full NHP core module, which would drag
// gin/grpc/quic/etcd/mongo/wazero into the module graph. Every constant and
// offset is pinned to the reference server wire format via the browser agent and
// fenced by the golden vectors.
//
// # Scope
//
// Generic wire profile only: this package knows packet framing and the Noise
// handshake, NOT any application body shape (qURL access tokens, qv2 claims). A
// caller supplies an already-serialized body and interprets the decrypted reply
// body itself. Initial knock (NHP_KNK) only — no re-knock/cookie-challenge answer
// (NHP_RKN), matching what a single resolve needs.
//
// # Egress-IP invariant
//
// The NHP server opens its firewall for the source IP of the relay POST. The knock
// and the subsequent resource request MUST therefore share an egress IP, or the
// resource request will hit a firewall that was opened for a different address.
package relayknock
