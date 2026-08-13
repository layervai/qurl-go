package crid

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
)

// Derivation constants frozen by the public conformance artifact
// (qurl-crid-v1-vectors). The always-run conformance test pins each of these
// against the artifact's contract block, so a contract revision fails the
// suite here rather than silently diverging.
const (
	// domainSeparationPrefix starts every digest input, followed by one
	// domainSeparator byte and the resource key's DER SubjectPublicKeyInfo
	// bytes.
	domainSeparationPrefix = "NHP-QURL-CRID-V1"
	domainSeparator        = byte(0x00)

	// alphabet is the RFC 4648 base32 alphabet in lowercase; the encoding is
	// unpadded. Uppercase input is invalid, never folded.
	alphabet = "abcdefghijklmnopqrstuvwxyz234567"

	// checksumLength is the byte length of the big-endian CRC32C (Castagnoli)
	// appended after the payload. Go's crc32.Castagnoli table constant is the
	// bit-reversed representation of the contract's normal-form polynomial
	// 0x1edc6f41.
	checksumLength = 4

	// forbiddenVersion is permanently invalid and rejects locally. Every
	// other version byte — registered or not — passes the local gate.
	forbiddenVersion = byte(0x00)

	fullDigestLength      = 32
	truncatedDigestLength = 24
	// fullLength and truncatedLength are the exact encoded lengths implied by
	// the two digest widths: 1 version byte + digest + 4 checksum bytes,
	// base32-encoded without padding.
	fullLength      = 60
	truncatedLength = 47
)

var (
	encoding = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	crcTable = crc32.MakeTable(crc32.Castagnoli)
)

// The typed local-rejection sentinels, one per class in the closed reject
// vocabulary of the CRID v1 conformance artifact (charset, length, checksum,
// non_canonical, version). The vocabulary is closed by contract: a new class
// requires a coordinated artifact schema bump, so callers may exhaustively
// match on these five.
var (
	// ErrCharset reports a byte outside the lowercase unpadded base32
	// alphabet. Nothing is trimmed first, so surrounding whitespace is a
	// charset error, and charset is checked before length, so a wrong-length
	// value containing a foreign byte reports ErrCharset.
	ErrCharset = errors.New("crid: byte outside the crid alphabet")
	// ErrLength reports a value whose length is neither of the two registered
	// encoded lengths (47 or 60).
	ErrLength = errors.New("crid: length is not a crid length")
	// ErrChecksum reports a decoded CRC32C that does not match the payload.
	// The checksum is typo detection, not security; see the package
	// documentation.
	ErrChecksum = errors.New("crid: checksum mismatch")
	// ErrNonCanonical reports non-zero trailing pad bits. Such a value
	// decodes to the same bytes as its canonical spelling, so it is caught by
	// re-encoding the decoded bytes, never by the checksum.
	ErrNonCanonical = errors.New("crid: non-canonical base32 encoding")
	// ErrForbiddenVersion reports the permanently invalid version byte 0x00.
	// Merely unregistered version bytes do NOT reject: they parse with
	// Known reporting false and must be forwarded to the authoritative
	// validator.
	ErrForbiddenVersion = errors.New("crid: forbidden version byte 0x00")
)

// Environment classifies which qURL environment a CRID's version byte was
// registered for. The registry reserves the 0x80 bit of the version byte for
// non-production environments, but consumers do not classify by that bit
// alone: an unregistered version byte reports EnvironmentUnknown regardless
// of its bits, because only a registry row makes the classification
// authoritative.
type Environment string

const (
	// EnvironmentProduction is a version byte registered for production.
	EnvironmentProduction Environment = "production"
	// EnvironmentTest is a version byte registered for test environments.
	EnvironmentTest Environment = "test"
	// EnvironmentUnknown is reported for structurally valid CRIDs whose
	// version byte is not registered at the digest length the value carries.
	// Such values are forwarded to the authoritative validator, never
	// rejected locally.
	EnvironmentUnknown Environment = "unknown"
)

// versionRegistry pins the version bytes this release knows and the digest
// length each one registers. 0x02/0x82 are registered but reserved (not yet
// minted); they still classify here so a future activation is not an error
// for deployed clients. A version byte observed at a digest length other
// than its registered one is reported unknown rather than rejected: the
// local gate's reject vocabulary is closed, and unknown-but-forwardable is
// the contract's stance on everything the gate does not permanently forbid.
var versionRegistry = map[byte]struct {
	digestLength int
	environment  Environment
}{
	0x01: {fullDigestLength, EnvironmentProduction},
	0x81: {fullDigestLength, EnvironmentTest},
	0x02: {truncatedDigestLength, EnvironmentProduction},
	0x82: {truncatedDigestLength, EnvironmentTest},
}

// CRID is one parsed, locally valid Cryptographic Resource ID. The zero
// value is not a valid CRID; obtain one from [Parse]. A CRID is a parse
// result, not an address — see the package documentation for what it may and
// may not be used for.
type CRID struct {
	value       string
	version     byte
	known       bool
	environment Environment
	digest      []byte
}

// String returns the canonical encoded form, which for a parsed CRID is
// byte-identical to the accepted input.
func (c CRID) String() string { return c.value }

// Version returns the version byte.
func (c CRID) Version() byte { return c.version }

// Known reports whether the version byte is registered at this value's
// digest length. A false Known is not an error: the value passed the local
// gate and must be forwarded to the authoritative validator, which decides
// whether the version is real.
func (c CRID) Known() bool { return c.known }

// Environment reports the registered environment of the version byte, or
// EnvironmentUnknown when Known is false.
func (c CRID) Environment() Environment { return c.environment }

// DigestLength returns the number of digest bytes the value carries (32 for
// a full CRID, 24 for a truncated one).
func (c CRID) DigestLength() int { return len(c.digest) }

// Parse runs the full local validation gate over s and returns its parsed
// form. It is strict: nothing is trimmed, case-folded, or normalized, and a
// rejection wraps exactly one of the five typed sentinels. An unregistered
// version byte is not a rejection — it parses with Known reporting false so
// the value can be forwarded to the authoritative validator.
//
// A nil error means only that s is structurally a CRID. It does not mean the
// resource exists; the server remains authoritative.
func Parse(s string) (*CRID, error) {
	// Charset before length, matching the conformance gate's classification:
	// a 61-character value containing a space is a charset rejection, not a
	// length one. Bytes are checked, not runes, so any non-ASCII byte is
	// outside the alphabet.
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return nil, fmt.Errorf("%w: byte %#02x at index %d", ErrCharset, s[i], i)
		}
	}
	if len(s) != fullLength && len(s) != truncatedLength {
		return nil, fmt.Errorf("%w: %d characters, want %d or %d", ErrLength, len(s), truncatedLength, fullLength)
	}
	decoded, err := encoding.DecodeString(s)
	// Decoding plus exact re-encoding rejects non-zero trailing pad bits:
	// Go's decoder does not police them, and the charset and length gates
	// above have already excluded every other non-canonical spelling. The
	// decode error branch is defense in depth — both accepted lengths are
	// valid unpadded base32 shapes once the charset has passed.
	if err != nil || encoding.EncodeToString(decoded) != s {
		return nil, fmt.Errorf("%w: trailing pad bits are not zero", ErrNonCanonical)
	}
	payload, checksum := decoded[:len(decoded)-checksumLength], decoded[len(decoded)-checksumLength:]
	if binary.BigEndian.Uint32(checksum) != crc32.Checksum(payload, crcTable) {
		return nil, fmt.Errorf("%w: crc32c does not match the payload", ErrChecksum)
	}
	version := payload[0]
	if version == forbiddenVersion {
		return nil, ErrForbiddenVersion
	}
	c := &CRID{
		value:       s,
		version:     version,
		environment: EnvironmentUnknown,
		digest:      append([]byte(nil), payload[1:]...),
	}
	if row, ok := versionRegistry[version]; ok && row.digestLength == len(c.digest) {
		c.known = true
		c.environment = row.environment
	}
	return c, nil
}

// Validate runs the full local validation gate over s. A nil error means s
// is structurally a CRID and safe to forward; it asserts nothing about
// whether the resource exists. A non-nil error wraps exactly one of the five
// typed sentinels and is permanent — retrying or forwarding the value cannot
// help.
func Validate(s string) error {
	_, err := Parse(s)
	return err
}

// MatchesShape reports whether s has the charset and exact length of a CRID.
// It is the cheap dispatch predicate for surfaces that accept either a CRID
// or another identifier form: shape decides "treat this as a CRID", while
// [Validate] decides whether it is one. A value can match the shape and
// still fail the gate (bad checksum, non-canonical spelling, forbidden
// version), so MatchesShape must never stand in for Validate.
func MatchesShape(s string) bool {
	if len(s) != fullLength && len(s) != truncatedLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

// KeyMatches reports whether derSPKI — a resource public key in DER
// SubjectPublicKeyInfo form, exactly as delivered — is the key the held CRID
// commits to. This is the consumer MUST-rule of the CRID contract: use a
// delivered key only if KeyMatches reports true for the CRID you already
// hold, and on false fail closed — no fallback to the delivered key, no
// partial trust. A well-formed key that simply is not the committed one is
// precisely the substitution the identifier exists to detect.
//
// The digest prefixes are compared in constant time. The version byte and
// checksum are pure functions of the digest prefix, so prefix equality at
// the held CRID's digest length is exactly re-derive-and-compare equality.
//
// The error reports a held CRID that fails the local gate (it wraps the
// [Parse] sentinels); (false, nil) is the fail-closed "do not use this key"
// outcome for a valid CRID.
func KeyMatches(crid string, derSPKI []byte) (bool, error) {
	c, err := Parse(crid)
	if err != nil {
		return false, err
	}
	message := make([]byte, 0, len(domainSeparationPrefix)+1+len(derSPKI))
	message = append(message, domainSeparationPrefix...)
	message = append(message, domainSeparator)
	message = append(message, derSPKI...)
	digest := sha256.Sum256(message)
	return subtle.ConstantTimeCompare(c.digest, digest[:len(c.digest)]) == 1, nil
}
