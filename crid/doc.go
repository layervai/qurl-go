// Package crid implements the client side of CRID v1, the Cryptographic
// Resource ID served by the LayerV qURL Platform.
//
// A CRID is a fingerprint of a resource public key. It commits to the exact
// DER SubjectPublicKeyInfo bytes of that key:
//
//	digest  = SHA-256("NHP-QURL-CRID-V1" || 0x00 || der_spki_bytes)
//	payload = version_byte || digest[:digest_length]
//	crid    = base32(payload || crc32c(payload))
//
// encoded with the RFC 4648 base32 alphabet in lowercase, unpadded. Because
// the identifier commits to the key bytes, any party that later receives the
// key can re-derive the identifier and detect substitution without trusting
// the channel that delivered the key. That check is [KeyMatches], and it is
// the one rule every consumer MUST apply: a delivered resource key is used
// only if it hashes to the CRID already held. On a mismatch the consumer
// fails closed — no fallback to the delivered key, no partial trust.
//
// The trailing CRC32C is typo detection, not security: it catches
// transcription slips locally so they do not surface as a confusing
// authoritative miss, while the security property is the digest itself.
// Likewise the identifier is a commitment, never an address: routing labels
// and placement identifiers are separate, server-issued values, and a client
// must not derive them from a CRID or from the key behind it.
//
// # Local validation is a gate, not an oracle
//
// [Parse] and [Validate] implement the local validation gate frozen by the
// public conformance artifact (qurl-crid-v1-vectors in
// github.com/layervai/qurl-conformance). Only permanently invalid values
// reject locally, each with a typed sentinel: a character outside the
// alphabet ([ErrCharset] — nothing is trimmed or case-folded first), a length
// that is neither registered encoded length ([ErrLength]), a checksum failure
// ([ErrChecksum]), non-zero trailing pad bits ([ErrNonCanonical]), or the
// permanently forbidden version byte 0x00 ([ErrForbiddenVersion]).
//
// Everything beyond those checks is the server's decision. A value that
// parses may still name a resource that does not exist, so a local accept
// must be forwarded to the authoritative validator, and a structurally valid
// CRID whose version byte is not in this release's registry parses with
// [CRID.Known] reporting false rather than failing: rejecting unknown
// versions locally would turn every future version activation into a
// breaking change for deployed clients. Treat findings about unknown
// versions as warnings at most; the server is authoritative.
//
// The first character of a CRID encodes the top five bits of its version
// byte, so production full CRIDs start with 'a' and test ones with 'q'.
// That property is for humans scanning logs; programs should use
// [CRID.Environment], which reports "unknown" for unregistered versions
// instead of guessing from the environment bit.
package crid
