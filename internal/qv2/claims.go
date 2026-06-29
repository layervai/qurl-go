// Package qv2 is the internal cryptographic core of the qURL Go SDK: it verifies
// incoming qURL links and mints new ones. It is an internal package — integrations
// never import it directly; they use the public qurl package, which re-exports the
// surface callers need (the strict parser, issuer-signature sign/verify, the
// published-key trust store, the Signer seam, and post-verify relay validation).
//
// It implements the qURL keyed-identity wire format and issuer-signature crypto per
// the public qURL keyed-identity design.
//
// This is the security core for a qURL link (#qv2.<claims>.<secret>.<sig>): a
// strict allowlist parser, the issuer signing input + raw r||s low-S signature
// verification, a published-key trust store, post-verify relay_url validation, and
// the matching mint side (sign.go: the Signer seam + SignClaims) that signs the
// EXACT bytes the verifier checks. It is a dependency-light Go implementation that
// agrees byte-for-byte with the published qURL v2 conformance vectors; it imports
// only the standard library — the issuer signing key is reached through the Signer
// interface, never a baked-in KMS client.
//
// Design invariants enforced here:
//   - The issuer signature is computed/verified over the EXACT base64url bytes of
//     the claims part as they appear on the wire, never over a re-serialized
//     object. Re-canonicalization is a classic signature-bypass vector.
//   - The wire signature is fixed-width raw ECDSA r||s (64 bytes, low-S
//     normalized). Verifiers reject any non-64-byte or non-low-S signature.
//   - The parser is a strict allowlist: duplicate keys, unknown fields, missing
//     required fields, null, wrong types, arrays-for-scalars, out-of-range
//     numbers, and non-integer time fields are all rejected.
//   - relay_url is validated (HTTPS + allowlist) ONLY after the issuer signature
//     verifies, because it is attacker-controlled until then.
//
// Liveness (exp/nbf vs the current clock) is intentionally NOT enforced here: this
// package has no trusted clock, and the design assigns expiry/liveness to the
// admission layer. The strict parser only checks the clock-free iat<=exp / nbf<=exp
// ordering bounds. A caller that admits traffic MUST itself reject expired or
// not-yet-valid claims.
package qv2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Version is the only supported qURL artifact version. The version is pinned;
// there is no negotiation from the payload.
const Version = 2

// FragmentPrefix is the literal first dot-token of a qURL v2 fragment.
const FragmentPrefix = "qv2"

// Issuer is the expected value of the claims `iss` field.
const Issuer = "qurl-service"

// domainSeparationPrefix is the fixed signing-input prefix. The signing input is
// this prefix + a single 0x00 byte + the exact unpadded-base64url claims bytes.
// The 0x00 is one literal byte, not the two ASCII characters backslash-zero.
const domainSeparationPrefix = "NHP-QURL-V2-ISSUER"

// domainSeparator is the single 0x00 separator byte between the prefix and the
// claims bytes. Kept as a named constant so the signer and verifier cannot drift.
const domainSeparator byte = 0x00

// Key length constants. Cell and per-qURL user keys are raw X25519 public keys
// (exactly 32 bytes). The resource public key is a different algorithm (a P-256
// KMS key in DER SPKI form) and is length-checked against its OWN window, per the
// design's "Parsing rules" ("length-check each field against its own expected
// size").
const (
	// x25519PublicKeyBytes is the exact decoded length of a raw X25519 public
	// key (cell_public_key_b64 and qurl_user_public_key_b64).
	x25519PublicKeyBytes = 32

	// x25519PrivateKeyBytes is the exact decoded length of a raw X25519 private
	// key (qurl_user_private_key_b64 in the secret). X25519 scalars are 32 bytes;
	// it equals x25519PublicKeyBytes but is named separately so the secret-key
	// length check reads intentionally rather than reusing the public constant.
	x25519PrivateKeyBytes = 32

	// minResourcePublicKeyDERBytes / maxResourcePublicKeyDERBytes bound the DER
	// SPKI encoding of the ECC_NIST_P256 resource public key. The canonical
	// length AWS KMS returns is 91 bytes; a small window (not an exact pin)
	// tolerates a future encoding nuance while still rejecting obviously-wrong
	// blobs (empty, a raw 32-byte X25519 key, a multi-kilobyte RSA key).
	minResourcePublicKeyDERBytes = 80
	maxResourcePublicKeyDERBytes = 160
)

// maxUnixSeconds bounds integer time fields so a hostile payload cannot inject an
// absurd value. It is well past any plausible qURL expiry (year ~2286) yet small
// enough to stay safely within int64 arithmetic downstream.
const maxUnixSeconds int64 = 9_999_999_999

// Claims is the signed qURL v2 claim set (Part 1 of the fragment). Field order
// here is irrelevant: the signature is over the received bytes, never over a
// re-serialization of this struct. Only cell_id is optional; every other field
// is required-present and is enforced by the strict parser.
type Claims struct {
	V   int    `json:"v"`
	Iss string `json:"iss"`
	Kid string `json:"kid"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`

	CellPublicKeyB64 string `json:"cell_public_key_b64"`
	// CellID is the one optional claim. omitempty so an unset cell_id is OMITTED
	// at mint rather than emitted as "cell_id":"" — keeping "absent" and "empty"
	// distinct at signing time (the strict parser accepts both an absent cell_id,
	// since it is not required, and a present one).
	CellID   string `json:"cell_id,omitempty"`
	RelayURL string `json:"relay_url"`

	ResourcePublicKeyB64 string `json:"resource_public_key_b64"`

	QurlUserPublicKeyB64 string `json:"qurl_user_public_key_b64"`
}

// Secret is the unsigned secret payload (Part 2 of the fragment). It carries the
// per-qURL private key. It needs no signature: swapping it for an attacker key
// makes proof-of-possession fail because the signed public key no longer matches.
type Secret struct {
	QurlUserPrivateKeyB64 string `json:"qurl_user_private_key_b64"`
}

// fieldQurlUserPrivateKeyB64 is the single source of the secret field name, reused
// by the Secret struct tag and the secret allowlists below so the wire field name
// lives in exactly one place (mirroring the claim field-name constants).
const fieldQurlUserPrivateKeyB64 = "qurl_user_private_key_b64"

// Claim field-name constants. Defined once and reused by the allowlist and the
// validators so the wire field names live in exactly one place.
const (
	fieldV                    = "v"
	fieldIss                  = "iss"
	fieldKid                  = "kid"
	fieldIat                  = "iat"
	fieldNbf                  = "nbf"
	fieldExp                  = "exp"
	fieldJti                  = "jti"
	fieldCellPublicKeyB64     = "cell_public_key_b64"
	fieldCellID               = "cell_id"
	fieldRelayURL             = "relay_url"
	fieldResourcePublicKeyB64 = "resource_public_key_b64"
	fieldQurlUserPublicKeyB64 = "qurl_user_public_key_b64"
)

// requiredClaimKeys is the allowlist of claim keys that MUST be present. cell_id
// is intentionally excluded — it is the one optional claim per the design.
var requiredClaimKeys = []string{
	fieldV, fieldIss, fieldKid, fieldIat, fieldNbf, fieldExp, fieldJti,
	fieldCellPublicKeyB64, fieldRelayURL,
	fieldResourcePublicKeyB64, fieldQurlUserPublicKeyB64,
}

// allowedClaimKeys is the full allowlist (required plus the optional cell_id).
// Any key not in this set is rejected as an unknown field.
var allowedClaimKeys = func() map[string]struct{} {
	m := make(map[string]struct{}, len(requiredClaimKeys)+1)
	for _, k := range requiredClaimKeys {
		m[k] = struct{}{}
	}
	m[fieldCellID] = struct{}{}
	return m
}()

// requiredSecretKeys / allowedSecretKeys mirror the claim allowlists for the
// unsigned secret object. The secret schema is exactly one required field.
var (
	requiredSecretKeys = []string{fieldQurlUserPrivateKeyB64}
	allowedSecretKeys  = map[string]struct{}{fieldQurlUserPrivateKeyB64: {}}
)

// Sentinel errors. Callers (and tests) match on these with errors.Is rather than
// on message text.
var (
	// ErrEncoding is returned when a part is not valid unpadded base64url.
	ErrEncoding = errors.New("qurl: value is not valid unpadded base64url")
	// ErrStrictParse is returned for any strict-schema violation (duplicate key,
	// unknown field, missing required field, null, wrong type, array-for-scalar,
	// non-integer or out-of-range time, etc.).
	ErrStrictParse = errors.New("qurl: strict parse failed")
	// ErrKeyLength is returned when a decoded key field is not its expected size.
	ErrKeyLength = errors.New("qurl: key field has unexpected length")
	// ErrFragment is returned when the fragment shape is invalid (wrong prefix,
	// wrong part count, empty part).
	ErrFragment = errors.New("qurl: invalid fragment")
	// ErrSignature is returned when issuer-signature verification fails.
	ErrSignature = errors.New("qurl: issuer signature verification failed")
	// ErrRelayURL is returned when relay_url is not HTTPS or not on the allowlist.
	ErrRelayURL = errors.New("qurl: relay_url rejected")
	// ErrUnknownKID is returned when a claim's kid is not in the trust store.
	ErrUnknownKID = errors.New("qurl: unknown issuer kid")
)

// encodeB64 encodes raw bytes as unpadded base64url — the single pinned wire
// encoding for every qURL v2 part and key field. Using one encoding everywhere
// removes the "base64 vs base64url" and "padded vs unpadded" canonicalization
// hazards the design calls out. Strict() is a decode-only concern, so encoding
// uses plain RawURLEncoding; decodeB64's canonical check re-encodes through this
// same function's encoding for an apples-to-apples comparison.
func encodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeB64 decodes an unpadded-base64url string and accepts it ONLY if the input
// is the unique canonical encoding of the bytes it decodes to — the guarantee that
// keeps this decoder in lockstep with the WebCrypto/JS port (both sides must agree
// on which STRINGS are well-formed, not merely on which bytes a lenient decoder
// recovers, so a non-canonical variant of a signed part is rejected here rather
// than silently normalized).
//
// Canonicality rests on the re-encode-and-compare below: it is what makes
// acceptance equivalent to "input == EncodeToString(decoded)", which covers BOTH
// non-canonical trailing bits AND embedded '\r'/'\n' (Go's base64 decoder silently
// skips those in every mode, including Strict). Strict() on the decode is kept as
// a first-line filter that fails fast with a precise decoder error for the
// trailing-bits and bad-alphabet cases (padding, non-base64url characters); the
// re-encode check is the authoritative backstop for everything else.
func decodeB64(s string) ([]byte, error) {
	b, err := strictRawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	// Authoritative canonicality check: a genuinely canonical input round-trips
	// byte-for-byte, so any string the lenient parts of the decoder would have
	// accepted (notably embedded '\r'/'\n', which make signed parts malleable by
	// decoding distinct strings to the same sig/secret bytes) is rejected here.
	if encodeB64(b) != s {
		return nil, fmt.Errorf("%w: non-canonical base64url encoding", ErrEncoding)
	}
	return b, nil
}

// strictRawURLEncoding is RawURLEncoding with strict canonical-trailing-bit
// enforcement, built once at init (base64.Encoding.Strict() allocates a fresh
// *Encoding on every call, so it is hoisted rather than rebuilt per decode). It is
// used only for DECODING; encoding goes through encodeB64's plain RawURLEncoding.
// Strict() is now a fast first-line filter only — the authoritative canonicality
// guarantee is decodeB64's re-encode-and-compare.
var strictRawURLEncoding = base64.RawURLEncoding.Strict()

// decodeX25519PublicKey decodes a base64url X25519 public key and enforces the
// exact 32-byte length.
func decodeX25519PublicKey(field, b64 string) ([]byte, error) {
	raw, err := decodeB64(b64)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(raw) != x25519PublicKeyBytes {
		return nil, fmt.Errorf("%w: %s decoded to %d bytes, want %d",
			ErrKeyLength, field, len(raw), x25519PublicKeyBytes)
	}
	return raw, nil
}

// decodeX25519PrivateKey decodes a base64url X25519 private key and enforces the
// exact 32-byte length. The per-qURL private key is the proof-of-possession
// credential, so the crypto core rejects a wrong-length secret directly rather
// than deferring to the downstream PoP path.
func decodeX25519PrivateKey(field, b64 string) ([]byte, error) {
	raw, err := decodeB64(b64)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(raw) != x25519PrivateKeyBytes {
		return nil, fmt.Errorf("%w: %s decoded to %d bytes, want %d",
			ErrKeyLength, field, len(raw), x25519PrivateKeyBytes)
	}
	return raw, nil
}

// decodeResourcePublicKey decodes a base64url resource public key (DER SPKI) and
// length-checks it against its own window (a different algorithm/length than the
// X25519 keys).
//
// Deliberate scope: this performs ONLY a base64url-decode + length-window check on
// resource_public_key_b64. It intentionally does NOT parse the bytes as a real
// P-256 SPKI here. On the verify path this is safe: the claims are issuer-signed,
// so a verifier that has checked the signature is trusting the issuer to have
// minted a structurally valid resource key; the field is not attacker-chosen
// there. The structural P-256 parse is deferred to the admission/resource-key
// consumer, where the key is actually used for ECDH (see the package liveness
// note).
func decodeResourcePublicKey(b64 string) ([]byte, error) {
	der, err := decodeB64(b64)
	if err != nil {
		return nil, fmt.Errorf("resource_public_key_b64: %w", err)
	}
	if len(der) < minResourcePublicKeyDERBytes || len(der) > maxResourcePublicKeyDERBytes {
		return nil, fmt.Errorf("%w: resource_public_key_b64 decoded to %d bytes, want %d..%d",
			ErrKeyLength, len(der), minResourcePublicKeyDERBytes, maxResourcePublicKeyDERBytes)
	}
	return der, nil
}

// PublicKeyHashFromB64 is the canonical revocation-index hash of a qURL v2
// public key: lowercase-hex SHA-256 of the DECODED key bytes. The input is the
// unpadded base64url form carried in the signed claims (qurl_user_public_key_b64
// and resource_public_key_b64), decoded with the same strict base64url decoder
// the parser uses, so the hash preimage is exactly the bytes the issuer signed.
// It mirrors the format the server-side revocation indexes key off, so a
// second hasher must never compute a different digest.
func PublicKeyHashFromB64(b64 string) (string, error) {
	raw, err := decodeB64(b64)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// signingInput builds the exact bytes the issuer signs and verifiers verify:
// domainSeparationPrefix + 0x00 + the EXACT unpadded-base64url claims bytes from
// the wire. The claims bytes are passed in verbatim (never re-serialized).
func signingInput(claimsB64 string) []byte {
	prefix := []byte(domainSeparationPrefix)
	out := make([]byte, 0, len(prefix)+1+len(claimsB64))
	out = append(out, prefix...)
	out = append(out, domainSeparator)
	out = append(out, claimsB64...)
	return out
}

// signingDigest returns the SHA-256 of the signing input. The signer and every
// verifier MUST use this one helper so the preimage can never drift between them.
func signingDigest(claimsB64 string) [32]byte {
	return sha256.Sum256(signingInput(claimsB64))
}
