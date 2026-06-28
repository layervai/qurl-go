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
// It is a port of the browser JS NHP agent (nhp endpoints/js-agent/src/crypto/* +
// agent/*) and the clean-room smoke client (qurl-service tests/smoke). The wire
// format is fenced byte-for-byte by the golden vectors in knock_golden_test.go,
// which are copied from the js-agent's cross-language fixtures (themselves pinned
// to the Go nhp/core server output). If this port reproduces those bytes, it is
// wire-compatible with the deployed server by construction.
//
// # Dependency policy
//
// The only non-stdlib dependency is golang.org/x/crypto (curve25519, blake2s).
// This package MUST NOT import nhp/core, which would drag gin/grpc/quic/etcd/mongo
// /wazero into the module graph. Every constant and offset is pinned to the Go
// server wire format via the js-agent and fenced by the golden vectors.
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
// The NHP server opens access for the source IP of the relay POST. The knock
// and the subsequent resource request MUST therefore share an egress IP, or the
// resource request will hit a server that opened access for a different address.
package relayknock
