// Package nativeudp is the native NHP-over-UDP transport of the qURL Go SDK.
//
// It is the direct-to-server sibling of the relayknock HTTP relay transport: the
// same NHP Noise messages (X25519 / AES-256-GCM / BLAKE2s), the same
// byte-for-byte packet framing fenced by the shared qurl-conformance vectors, but
// carried in a UDP datagram sent straight to an assigned cell's public native NHP
// endpoint instead of POSTed to an internet-facing relay. A registered qURL
// Connector uses this transport once qurl-service has handed it an authoritative
// cell assignment; it never derives, probes, or lists an endpoint itself.
//
// # Scope
//
// Round-trip initiator messages only: NHP_LST (answered exactly by NHP_LRT),
// NHP_KNK (answered by NHP_ACK/NHP_COK), and NHP_REG (answered by
// NHP_RAK/NHP_COK). LST never accepts a cookie challenge; handler-budget or
// pre-handler overload shedding is a timeout owned by the caller's bounded
// transaction retry. Every reply, including COK, must echo the request counter.
// The re-knock/cookie-answer NHP_RKN and any exit message stay out of scope here.
// The application body is opaque — a caller supplies already-serialized bytes
// and interprets the decrypted authenticated reply body itself.
//
// # Server authentication
//
// A reply is accepted only when the NHP handshake authenticates the assignment's
// configured server public key: DecryptReply pins the recovered server static key
// to the expected key and completes authentication at the ss-keyed AEAD open, so
// only the holder of that server static private key can produce an accepted reply.
// DNS agreement and the datagram's source address are NOT a substitute for this
// server-key authentication — a datagram that does not open as an authenticated
// reply from the pinned key is rejected (ErrServerUnauthenticated), and the source
// address is never trusted. The endpoint host is resolved fresh on every exchange
// and a resolved IP is never persisted, preserving DNS/NLB replacement and
// multi-address behavior.
//
// # Dependency policy
//
// Like relayknock, the only non-stdlib dependency reached from here is
// golang.org/x/crypto (via the internal nhpwire codec). The transport reuses the
// public relayknock initiator/reply API for all crypto; it adds only the UDP
// socket handling, DNS resolution, deadlines, packet-size bounds, request/reply
// correlation, cookie-challenge surfacing, cancellation, and secret scrubbing.
package nativeudp
