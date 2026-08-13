package crid

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

// TestConformanceCRIDV1 is the always-run, every-case contract test. It loads
// the released CRID v1 artifact and drives EVERY case — producer, consumer
// value, version, and key-match — through this package's REAL entry points,
// asserting the declared outcome and, for rejects, the mapped typed sentinel.
// It FAILS (never skips) if the artifact is missing or unparseable, so the
// contract can never silently drop out of the suite.
//
// The artifact bytes come from the public qurl-conformance package and are
// pinned by the dependency version (go.sum); adopting a newer revision is a
// dependency bump, and this test needs no change. Per the artifact's lockstep
// rule, the cases run through Parse/Validate/KeyMatches — the stored
// expectations are asserted against re-derived behavior, never trusted as
// booleans.
func TestConformanceCRIDV1(t *testing.T) {
	cf, err := conformance.CRIDV1()
	if err != nil {
		t.Fatalf("conformance artifact must load: %v", err)
	}
	if cf.Artifact != conformance.CRIDV1ArtifactID {
		t.Fatalf("unexpected artifact id %q", cf.Artifact)
	}

	t.Run("contract", func(t *testing.T) { runCRIDContractPins(t, cf.Contract) })
	t.Run("versions", func(t *testing.T) { runCRIDVersionRegistryPins(t, cf.Versions) })
	t.Run("producer_cases", func(t *testing.T) { runCRIDProducerCases(t, cf.ProducerCases) })
	t.Run("consumer_value_cases", func(t *testing.T) { runCRIDValueCases(t, cf.ConsumerValueCases) })
	t.Run("version_cases", func(t *testing.T) { runCRIDVersionCases(t, cf.VersionCases) })
	t.Run("key_match_cases", func(t *testing.T) { runCRIDKeyMatchCases(t, cf.KeyMatchCases) })
}

// runCRIDContractPins asserts this package's unexported derivation constants
// against the artifact's contract block, so a contract revision (new
// alphabet, prefix, width, or polynomial) fails here instead of silently
// diverging behind a green dependency bump.
func runCRIDContractPins(t *testing.T, contract conformance.CRIDV1Contract) {
	pins := []struct {
		name      string
		got, want any
	}{
		{"domain_separation_prefix", domainSeparationPrefix, contract.DomainSeparationPrefix},
		{"domain_separator", hex.EncodeToString([]byte{domainSeparator}), contract.DomainSeparatorHex},
		{"digest", "SHA-256", contract.Digest},
		{"checksum", "CRC32C", contract.Checksum},
		// crcTable is built from crc32.Castagnoli, the bit-reversed form of
		// the contract's normal-form polynomial; the producer cases below
		// prove the checksums agree byte-for-byte.
		{"checksum_polynomial_hex", "1edc6f41", contract.ChecksumPolynomialHex},
		{"checksum_byte_order", "big-endian", contract.ChecksumByteOrder},
		{"checksum_length", checksumLength, contract.ChecksumLength},
		{"alphabet", alphabet, contract.Alphabet},
		{"forbidden_version", hex.EncodeToString([]byte{forbiddenVersion}), contract.ForbiddenVersionHex},
		{"full_digest_length", fullDigestLength, contract.FullDigestLength},
		{"full_crid_length", fullLength, contract.FullCRIDLength},
		{"truncated_digest_length", truncatedDigestLength, contract.TruncatedDigestLength},
		{"truncated_crid_length", truncatedLength, contract.TruncatedCRIDLength},
	}
	for _, pin := range pins {
		if pin.got != pin.want {
			t.Errorf("%s: package constant %v, artifact pins %v", pin.name, pin.got, pin.want)
		}
	}
}

// runCRIDVersionRegistryPins keeps versionRegistry in lockstep with the
// artifact's registry: every artifact row must be represented with the same
// digest length and environment, and this package must register nothing the
// artifact does not.
func runCRIDVersionRegistryPins(t *testing.T, rows []conformance.CRIDV1Version) {
	if len(rows) == 0 {
		t.Fatal("artifact version registry is empty")
	}
	if len(rows) != len(versionRegistry) {
		t.Fatalf("package registers %d versions, artifact registers %d", len(versionRegistry), len(rows))
	}
	for _, row := range rows {
		raw, err := hex.DecodeString(row.VersionHex)
		if err != nil || len(raw) != 1 {
			t.Fatalf("artifact version_hex %q is not one byte (%v)", row.VersionHex, err)
		}
		got, ok := versionRegistry[raw[0]]
		if !ok {
			t.Errorf("artifact registers version %q; package registry is missing it", row.VersionHex)
			continue
		}
		if got.digestLength != row.DigestLength || string(got.environment) != row.Environment {
			t.Errorf("version %q: package registers %d/%s, artifact pins %d/%s",
				row.VersionHex, got.digestLength, got.environment, row.DigestLength, row.Environment)
		}
	}
}

// runCRIDProducerCases consumes every producer case through this package's
// consumer surface: the expected CRID must parse as a known value with the
// case's version byte and environment, KeyMatches must re-derive it from the
// frozen DER key, the carried digest must be the stored digest's prefix, and
// the documented first-character property must hold.
func runCRIDProducerCases(t *testing.T, cases []conformance.CRIDV1ProducerCase) {
	if len(cases) == 0 {
		t.Fatal("artifact has no producer cases")
	}
	for _, pc := range cases {
		t.Run(pc.Name, func(t *testing.T) {
			c, err := Parse(pc.ExpectedCRID)
			if err != nil {
				t.Fatalf("expected_crid failed the local gate: %v", err)
			}
			if got := hex.EncodeToString([]byte{c.Version()}); got != pc.VersionByte {
				t.Fatalf("version = %q, want %q", got, pc.VersionByte)
			}
			if !c.Known() {
				t.Fatal("producer fixtures mint registered versions; Known() = false")
			}
			if string(c.Environment()) != pc.Environment {
				t.Fatalf("environment = %q, want %q", c.Environment(), pc.Environment)
			}
			wantDigest, err := hex.DecodeString(pc.DigestHex)
			if err != nil {
				t.Fatalf("decode digest_hex: %v", err)
			}
			if !bytes.Equal(c.digest, wantDigest[:c.DigestLength()]) {
				t.Fatal("carried digest is not the stored digest's prefix")
			}
			der, err := base64.RawURLEncoding.Strict().DecodeString(pc.DERSPKIB64URL)
			if err != nil {
				t.Fatalf("decode der_spki_b64url: %v", err)
			}
			ok, err := KeyMatches(pc.ExpectedCRID, der)
			if err != nil {
				t.Fatalf("KeyMatches: %v", err)
			}
			if !ok {
				t.Fatal("KeyMatches did not re-derive the producer's own CRID from its key")
			}
			// The documented first-character property: production full CRIDs
			// start with 'a', test ones with 'q'.
			wantFirst := map[string]byte{"production": 'a', "test": 'q'}[pc.Environment]
			if pc.ExpectedCRID[0] != wantFirst {
				t.Fatalf("first char = %q, want %q for %s", pc.ExpectedCRID[0], wantFirst, pc.Environment)
			}
		})
	}
}

// sentinelForRejectClass maps the artifact's closed reject vocabulary to this
// package's typed sentinels, one-to-one. An unknown class fails loudly: a new
// class is a coordinated schema bump this package must be taught, never
// silently skipped.
func sentinelForRejectClass(t *testing.T, class string) error {
	t.Helper()
	switch class {
	case conformance.CRIDV1RejectCharset:
		return ErrCharset
	case conformance.CRIDV1RejectLength:
		return ErrLength
	case conformance.CRIDV1RejectChecksum:
		return ErrChecksum
	case conformance.CRIDV1RejectNonCanonical:
		return ErrNonCanonical
	case conformance.CRIDV1RejectVersion:
		return ErrForbiddenVersion
	default:
		t.Fatalf("reject_class %q is not in the closed CRID v1 vocabulary", class)
		return nil
	}
}

// runCRIDValueCases drives every consumer value case through Validate and
// Parse. Accepts must parse to the verbatim canonical string; rejects must
// wrap exactly the sentinel their class maps to. MatchesShape's expectation
// is derived per case from the class semantics (shape = charset + length
// only), so the cheap predicate is proven against the same fixtures.
func runCRIDValueCases(t *testing.T, cases []conformance.CRIDV1ValueCase) {
	if len(cases) == 0 {
		t.Fatal("artifact has no consumer value cases")
	}
	for _, vc := range cases {
		t.Run(vc.Name, func(t *testing.T) {
			verr := Validate(vc.Value)
			c, perr := Parse(vc.Value)
			if (verr == nil) != (perr == nil) {
				t.Fatalf("Validate (%v) and Parse (%v) disagree", verr, perr)
			}
			switch vc.Outcome {
			case conformance.ExpectAccept:
				if verr != nil {
					t.Fatalf("accept value failed the local gate: %v", verr)
				}
				if c.String() != vc.Value {
					t.Fatalf("String() = %q, want the verbatim input", c.String())
				}
			case conformance.ExpectReject:
				want := sentinelForRejectClass(t, vc.RejectClass)
				if !errors.Is(verr, want) {
					t.Fatalf("reject class %q: got %v, want %v", vc.RejectClass, verr, want)
				}
			default:
				t.Fatalf("unknown outcome %q", vc.Outcome)
			}
			// Shape = charset + length only: accepts match it, and so do the
			// classes the shape cannot see (checksum, non-canonical spelling,
			// forbidden version). Charset and length rejects must not.
			wantShape := vc.Outcome == conformance.ExpectAccept ||
				vc.RejectClass == conformance.CRIDV1RejectChecksum ||
				vc.RejectClass == conformance.CRIDV1RejectNonCanonical ||
				vc.RejectClass == conformance.CRIDV1RejectVersion
			if got := MatchesShape(vc.Value); got != wantShape {
				t.Fatalf("MatchesShape = %v, want %v for class %q", got, wantShape, vc.RejectClass)
			}
		})
	}
}

// runCRIDVersionCases pins what this package reports for the version byte of
// a locally valid CRID: the byte itself, whether it is registered, the
// environment, and the carried digest length.
func runCRIDVersionCases(t *testing.T, cases []conformance.CRIDV1VersionCase) {
	if len(cases) == 0 {
		t.Fatal("artifact has no version cases")
	}
	for _, vc := range cases {
		t.Run(vc.Name, func(t *testing.T) {
			c, err := Parse(vc.Value)
			if err != nil {
				t.Fatalf("version-case value failed the local gate: %v", err)
			}
			if got := hex.EncodeToString([]byte{c.Version()}); got != vc.VersionHex {
				t.Fatalf("version = %q, want %q", got, vc.VersionHex)
			}
			if c.Known() != vc.Known {
				t.Fatalf("Known() = %v, want %v", c.Known(), vc.Known)
			}
			if string(c.Environment()) != vc.Environment {
				t.Fatalf("environment = %q, want %q", c.Environment(), vc.Environment)
			}
			if c.DigestLength() != vc.DigestLength {
				t.Fatalf("DigestLength() = %d, want %d", c.DigestLength(), vc.DigestLength)
			}
		})
	}
}

// runCRIDKeyMatchCases drives the consumer MUST-rule through KeyMatches. The
// mismatch fixtures deliver a real, well-formed key that is simply not the
// committed one — exactly the substitution the identifier exists to detect —
// and the assertion is that KeyMatches fails closed on it.
func runCRIDKeyMatchCases(t *testing.T, cases []conformance.CRIDV1KeyMatchCase) {
	if len(cases) == 0 {
		t.Fatal("artifact has no key-match cases")
	}
	sawMatch, sawMismatch := false, false
	for _, kc := range cases {
		t.Run(kc.Name, func(t *testing.T) {
			der, err := base64.RawURLEncoding.Strict().DecodeString(kc.DERSPKIB64URL)
			if err != nil {
				t.Fatalf("decode der_spki_b64url: %v", err)
			}
			ok, err := KeyMatches(kc.CRID, der)
			if err != nil {
				t.Fatalf("KeyMatches: %v", err)
			}
			switch kc.Outcome {
			case conformance.CRIDV1OutcomeMatch:
				sawMatch = true
				if !ok {
					t.Fatal("declared match reported false")
				}
			case conformance.CRIDV1OutcomeMismatch:
				sawMismatch = true
				if ok {
					t.Fatal("declared mismatch reported true; a substituted key would be trusted")
				}
			default:
				t.Fatalf("unknown outcome %q", kc.Outcome)
			}
		})
	}
	if !sawMatch || !sawMismatch {
		t.Fatalf("key-match cases must exercise both outcomes (match=%v mismatch=%v)", sawMatch, sawMismatch)
	}
}

// reencode is the test-local producer: it derives the canonical encoding of
// version || digest || crc32c(version || digest). The fuzz target uses it to
// prove accepted values re-encode to themselves; unit tests use it to build
// shapes the artifact has no fixture for.
func reencode(version byte, digest []byte) string {
	payload := append([]byte{version}, digest...)
	crc := make([]byte, checksumLength)
	binary.BigEndian.PutUint32(crc, crc32.Checksum(payload, crcTable))
	return encoding.EncodeToString(append(payload, crc...))
}

// TestParseRegisteredVersionAtForeignDigestLengthIsUnknown pins a judgment
// call the artifact leaves undefined for consumers: version 0x01 registers
// the 32-byte digest, so a checksum-valid value carrying it at 24 bytes is
// not what the registry row describes. The closed local gate has no class
// for it, so this package reports it unknown-but-forwardable (Known false,
// EnvironmentUnknown) rather than inventing a local rejection; the
// authoritative validator decides.
func TestParseRegisteredVersionAtForeignDigestLengthIsUnknown(t *testing.T) {
	t.Parallel()

	value := reencode(0x01, bytes.Repeat([]byte{0x5a}, truncatedDigestLength))
	c, err := Parse(value)
	if err != nil {
		t.Fatalf("checksum-valid value failed the local gate: %v", err)
	}
	if c.Known() {
		t.Fatal("version 0x01 at a 24-byte digest must not be Known; its registry row pins 32")
	}
	if c.Environment() != EnvironmentUnknown {
		t.Fatalf("environment = %q, want %q", c.Environment(), EnvironmentUnknown)
	}
	if c.DigestLength() != truncatedDigestLength {
		t.Fatalf("DigestLength() = %d, want %d", c.DigestLength(), truncatedDigestLength)
	}
}

// TestKeyMatchesReportsInvalidHeldCRID pins the error split: the error names
// a held CRID that fails the local gate (wrapping the Parse sentinels), while
// (false, nil) is the fail-closed outcome for a valid CRID and a foreign key.
func TestKeyMatchesReportsInvalidHeldCRID(t *testing.T) {
	t.Parallel()

	if _, err := KeyMatches("", nil); !errors.Is(err, ErrLength) {
		t.Fatalf("empty held CRID: got %v, want ErrLength", err)
	}
	if _, err := KeyMatches("Not A CRID!", nil); !errors.Is(err, ErrCharset) {
		t.Fatalf("foreign-charset held CRID: got %v, want ErrCharset", err)
	}

	valid := reencode(0x01, bytes.Repeat([]byte{0x11}, fullDigestLength))
	ok, err := KeyMatches(valid, nil)
	if err != nil {
		t.Fatalf("valid CRID with nil key: %v", err)
	}
	if ok {
		t.Fatal("nil delivered key must fail closed, not match")
	}
}
