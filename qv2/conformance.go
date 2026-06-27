package qv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// qURL v2 conformance-vector artifact loader.
//
// qv2_conformance_vectors.json is the nhp-OWNED, language-agnostic wire-truth for
// the qURL v2 verify path. Every qURL v2 verifier (the nhp Go package, the
// TypeScript js-agent, and this qurl-go package) re-runs the SAME bytes against
// its OWN implementation: a consumer feeds each class's input through its real
// parser/validator and asserts the declared accept/reject outcome (and, where the
// class is about the distinction, the reject_class). The vectors are BEHAVIORAL —
// a consumer recomputes/re-verifies rather than trusting a stored boolean — so a
// verifier that drifts from the contract fails its own run.
//
// This file is the schema + loader. conformance_test.go is the always-run test
// that drives every class (including negatives) through this package's real entry
// points.
//
// PROVISIONAL: the vendored qv2/testdata/qv2_conformance_vectors.json is copied
// from the in-flight nhp branch feat/qv2-conformance-vectors. Adopting the merged
// full-class artifact is a verbatim FILE SWAP — this loader and the test are
// structured so no Go changes are needed when the artifact is re-vendored.

// Expect / reject_class vocabulary. The accept/reject values reuse the exported
// signature-vector vocabulary (ExpectAccept / ExpectReject); only the reject_class
// values that have no existing constant are defined here. reject_class is pinned
// precisely ONLY where the class is about the distinction (encoding; key_length;
// the signature high_s / wrong_length live in the composed file); JSON-schema
// faults use the coarse "parse" because a conformant verifier may surface any of
// several internal sentinels for them.
const (
	conformanceAccept = ExpectAccept
	conformanceReject = ExpectReject

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
// separate file rather than carrying its own bytes.
type ConformanceSignatureClass struct {
	EntryPoint string `json:"entry_point"`
	Composes   string `json:"composes"`
	Comment    string `json:"comment"`
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
	Name        string `json:"name"`
	Expect      string `json:"expect"`
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

// LoadConformanceFile reads and strictly parses the conformance artifact. It
// returns an error (never an empty/zero document) when the file is missing or
// malformed, so a consumer test FAILS rather than silently skipping the contract.
// DisallowUnknownFields keeps a typo'd or stale schema field from being ignored.
func LoadConformanceFile(path string) (*ConformanceFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path, not user input
	if err != nil {
		return nil, fmt.Errorf("qv2: read conformance file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cf ConformanceFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("qv2: parse conformance file: %w", err)
	}
	if cf.SchemaVersion == 0 {
		return nil, fmt.Errorf("qv2: conformance file %s missing schema_version", path)
	}
	if len(cf.Classes) == 0 {
		return nil, fmt.Errorf("qv2: conformance file %s has no classes", path)
	}
	return &cf, nil
}
