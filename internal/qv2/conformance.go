package qv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// qURL v2 conformance-vector artifact loader.
//
// The conformance vectors are the language-agnostic wire-truth for the qURL v2
// verify path. Every qURL v2 verifier re-runs the SAME bytes against its OWN
// implementation: a consumer feeds each class's input through its real
// parser/validator and asserts the declared accept/reject outcome (and, where the
// class is about the distinction, the reject_class). The vectors are BEHAVIORAL —
// a consumer recomputes/re-verifies rather than trusting a stored boolean — so a
// verifier that drifts from the contract fails its own run.
//
// This file is the schema + loader. conformance_test.go is the always-run test
// that drives every class (including negatives) through this package's real entry
// points. The bytes themselves are consumed from the public qurl-conformance
// package (github.com/layervai/qurl-conformance), whose go:embed accessors return
// the canonical artifact; the dependency version pins the bytes via go.sum.

// reject_class vocabulary. The accept/reject expect values reuse the exported
// signature-vector vocabulary directly (ExpectAccept / ExpectReject); only the
// reject_class values that have no existing constant are defined here.
// reject_class is pinned precisely ONLY where the class is about the distinction
// (encoding; key_length; the signature high_s / wrong_length live in the composed
// file); JSON-schema faults use the coarse "parse" because a conformant verifier
// may surface any of several internal sentinels for them.
const (
	// rejectClassParse is the coarse class for a JSON-schema violation (duplicate
	// key, unknown field, null, wrong type, missing required, out-of-range/ordering).
	rejectClassParse = "parse"
	// rejectClassEncoding is a base64url encoding-layer rejection.
	rejectClassEncoding = "encoding"
	// rejectClassKeyLength is a decoded-key wrong-length rejection.
	rejectClassKeyLength = "key_length"
	// rejectClassFragment is a fragment wire-shape rejection.
	rejectClassFragment = "fragment"
	// rejectClassRelayURL is a relay_url HTTPS/allowlist rejection.
	rejectClassRelayURL = "relay_url"
	// rejectClassTamper is the signature-class payload-tamper rejection: a valid
	// signature verified against a flipped claims input (derived, not stored).
	rejectClassTamper = "tamper"
)

// Signature-class tamper derivation identifiers. These pin the artifact's
// language-agnostic derivation so this verifier applies exactly what the JSON
// specifies (rather than a hardcoded rule a vendoring consumer could not see).
const (
	// tamperDeriveFromAccept is the only supported derive_from: start from the
	// composed file's accept vector.
	tamperDeriveFromAccept = "accept_vector"
	// tamperTransformFlipFirstB64 flips the FIRST base64url character of the accept
	// vector's claims_b64 between 'A' and 'B' ('A'->'B', any other char->'A'). The
	// first symbol encodes the top 6 bits of decoded byte 0, so this changes the
	// DECODED claims (not just don't-care tail bits) AND keeps the string canonical
	// base64url. That makes the derived tamper identical for every consumer
	// regardless of whether it hashes the base64 string, decodes-then-hashes, or
	// strict-decodes before verifying.
	tamperTransformFlipFirstB64 = "flip_first_base64url_char_A_B"
)

// ConformanceFile is the top-level conformance artifact document.
type ConformanceFile struct {
	Artifact       string                      `json:"artifact"`
	SchemaVersion  int                         `json:"schema_version"`
	Description    string                      `json:"description"`
	SourceOfTruth  string                      `json:"source_of_truth"`
	Notes          []string                    `json:"notes"`
	SignatureClass ConformanceSignatureClass   `json:"signature_class"`
	Classes        map[string]ConformanceClass `json:"classes"`
}

// ConformanceSignatureClass records that the signature class is composed from a
// separate file rather than carrying its own bytes, plus the language-agnostic
// payload-tamper derivation every consumer synthesizes from the composed file's
// accept vector (so the tamper negative is vendorable without a third copy of
// signature bytes).
type ConformanceSignatureClass struct {
	EntryPoint string `json:"entry_point"`
	Composes   string `json:"composes"`
	Comment    string `json:"comment"`
	// TamperDerivation specifies the derived payload-tamper reject. It is optional
	// in the schema's struct but the test asserts it is present and well-formed.
	TamperDerivation *ConformanceTamperDerivation `json:"tamper_derivation,omitempty"`
}

// ConformanceTamperDerivation specifies how a consumer derives the payload-tamper
// reject from the composed signature file's accept vector. It is a derivation, not
// stored bytes, so every qURL v2 verifier across languages
// synthesizes the SAME negative: take the accept vector's UNCHANGED signature and
// verify it against a claims input formed by applying the transform named in
// ClaimsTransform, which must keep the string canonical base64url yet decode to
// different bytes, so the case fails only at the curve check.
type ConformanceTamperDerivation struct {
	RejectClass     string `json:"reject_class"`
	Comment         string `json:"comment"`
	DeriveFrom      string `json:"derive_from"`
	ClaimsTransform string `json:"claims_transform"`
}

// ConformanceClass is one named class: an entry-point label, the input field
// name, an optional human comment, and the ordered vectors.
type ConformanceClass struct {
	EntryPoint string              `json:"entry_point"`
	Input      string              `json:"input"`
	Comment    string              `json:"comment"`
	Vectors    []ConformanceVector `json:"vectors"`
}

// ConformanceVector is one case. Only the fields relevant to a vector's class are
// populated; the loader does not interpret them — the test routes each class to
// the matching entry point and reads the fields that class uses.
type ConformanceVector struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	// Composed conformance classes keep reject_class as a string because their
	// accept vectors do not need the absent-vs-empty distinction SignatureVector
	// enforces for issuer-signature JSON.
	RejectClass string `json:"reject_class"`
	Reason      string `json:"reason"`

	// claims_parse / secret_parse: raw JSON text fed directly to the parser.
	ClaimsJSON string `json:"claims_json"`
	SecretJSON string `json:"secret_json"`

	// strict_base64: the base64url string verbatim.
	ValueB64 string `json:"value_b64"`

	// fragment: a full fragment body.
	Fragment string `json:"fragment"`

	// relay_allowlist: the allowlist entries and the URL to validate.
	Entries []string `json:"entries"`
	URL     string   `json:"url"`

	// server_id: the cell public key (base64url) and its expected routing id.
	CellPublicKeyB64 string `json:"cell_public_key_b64"`
	ServerID         string `json:"server_id"`
}

// LoadConformanceBytes strictly parses the conformance artifact bytes. It returns
// an error (never an empty/zero document) when the bytes are empty or malformed,
// so a consumer test FAILS rather than silently skipping the contract.
// DisallowUnknownFields keeps a typo'd or stale schema field from being ignored.
func LoadConformanceBytes(data []byte) (*ConformanceFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cf ConformanceFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("qurl: parse conformance file: %w", err)
	}
	if cf.SchemaVersion == 0 {
		return nil, errors.New("qurl: conformance file missing schema_version")
	}
	if len(cf.Classes) == 0 {
		return nil, errors.New("qurl: conformance file has no classes")
	}
	return &cf, nil
}
