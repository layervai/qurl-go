package nativeudp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func canonicalTypedEvidenceJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func typedEvidenceDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func runTypedEvidenceVerifier(t *testing.T, observations []byte, allowIncomplete bool) ([]byte, error) {
	t.Helper()
	root := t.TempDir()
	inventory := filepath.Join(root, "inventory.json")
	contract := filepath.Join(root, "contract.json")
	observationPath := filepath.Join(root, "observations.jsonl")
	output := filepath.Join(root, "output.json")
	if err := os.WriteFile(inventory, []byte(`{"gate":"test_gate","scenarios":[{"id":"alpha"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contract, []byte(`{"evidence_kinds":{"wire_trace":{"exact_observation":{"verified":true}}},"gate":"test_gate","scenario_key_field":"id","scenarios":{"alpha":["wire_trace"]},"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if observations != nil {
		if err := os.WriteFile(observationPath, observations, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{
		"verify_typed_evidence.py",
		"--inventory", inventory,
		"--contract", contract,
		"--observations", observationPath,
		"--output", output,
	}
	if allowIncomplete {
		args = append(args, "--allow-incomplete")
	}
	command := exec.CommandContext(t.Context(), "python3", args...)
	command.Dir = "."
	combined, err := command.CombinedOutput()
	if err != nil {
		return combined, err
	}
	raw, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return raw, nil
}

func validTypedEvidenceRecord(t *testing.T) []byte {
	t.Helper()
	observation := map[string]any{"verified": true}
	canonicalObservation := canonicalTypedEvidenceJSON(t, observation)
	return canonicalTypedEvidenceJSON(t, map[string]any{
		"kind":               "wire_trace",
		"observation":        observation,
		"observation_sha256": typedEvidenceDigest(canonicalObservation),
		"scenario_key":       "alpha",
	})
}

func TestTypedEvidenceVerifierAcceptsExactCanonicalEvidence(t *testing.T) {
	raw, err := runTypedEvidenceVerifier(t, validTypedEvidenceRecord(t), false)
	if err != nil {
		t.Fatalf("verifier rejected valid evidence: %v: %s", err, raw)
	}
	var result struct {
		Complete  bool `json:"complete"`
		Scenarios []struct {
			Evidence []struct {
				Observation       map[string]any `json:"observation"`
				ObservationSHA256 string         `json:"observation_sha256"`
			} `json:"evidence"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Scenarios) != 1 || len(result.Scenarios[0].Evidence) != 1 {
		t.Fatalf("unexpected typed evidence result: %s", raw)
	}
	if result.Scenarios[0].Evidence[0].ObservationSHA256 == "" || result.Scenarios[0].Evidence[0].Observation["verified"] != true {
		t.Fatalf("sanitized observation or digest was not retained: %s", raw)
	}
}

func TestTypedEvidenceVerifierFailsClosed(t *testing.T) {
	valid := validTypedEvidenceRecord(t)
	var record map[string]any
	if err := json.Unmarshal(valid, &record); err != nil {
		t.Fatal(err)
	}

	badDigest := make(map[string]any, len(record))
	for key, value := range record {
		badDigest[key] = value
	}
	badDigest["observation_sha256"] = string(make([]byte, 64))

	extraKind := make(map[string]any, len(record))
	for key, value := range record {
		extraKind[key] = value
	}
	extraKind["kind"] = "unexpected_kind"

	secretObservation := map[string]any{"value": "lv_live_must_not_escape"}
	secret := map[string]any{
		"kind":               "wire_trace",
		"observation":        secretObservation,
		"observation_sha256": typedEvidenceDigest(canonicalTypedEvidenceJSON(t, secretObservation)),
		"scenario_key":       "alpha",
	}
	secretKeyObservation := map[string]any{"api_key": "short-secret"}
	secretKey := map[string]any{
		"kind":               "wire_trace",
		"observation":        secretKeyObservation,
		"observation_sha256": typedEvidenceDigest(canonicalTypedEvidenceJSON(t, secretKeyObservation)),
		"scenario_key":       "alpha",
	}
	falseObservation := map[string]any{"verified": false}
	falseEvidence := map[string]any{
		"kind":               "wire_trace",
		"observation":        falseObservation,
		"observation_sha256": typedEvidenceDigest(canonicalTypedEvidenceJSON(t, falseObservation)),
		"scenario_key":       "alpha",
	}
	opaqueObservation := map[string]any{"payload": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "verified": true}
	opaqueEvidence := map[string]any{
		"kind":               "wire_trace",
		"observation":        opaqueObservation,
		"observation_sha256": typedEvidenceDigest(canonicalTypedEvidenceJSON(t, opaqueObservation)),
		"scenario_key":       "alpha",
	}

	tests := map[string][]byte{
		"missing":             nil,
		"extra kind":          canonicalTypedEvidenceJSON(t, extraKind),
		"duplicate kind":      append(append(valid, '\n'), valid...),
		"bad digest":          canonicalTypedEvidenceJSON(t, badDigest),
		"noncanonical object": append([]byte(" "), valid...),
		"secret value":        canonicalTypedEvidenceJSON(t, secret),
		"secret key":          canonicalTypedEvidenceJSON(t, secretKey),
		"false success":       canonicalTypedEvidenceJSON(t, falseEvidence),
		"opaque payload":      canonicalTypedEvidenceJSON(t, opaqueEvidence),
		"duplicate key":       []byte(`{"kind":"wire_trace","kind":"wire_trace","observation":{"verified":true},"observation_sha256":"00","scenario_key":"alpha"}`),
	}
	for name, observations := range tests {
		t.Run(name, func(t *testing.T) {
			if output, err := runTypedEvidenceVerifier(t, observations, false); err == nil {
				t.Fatalf("verifier accepted %s: %s", name, output)
			}
		})
	}
}

func TestTypedEvidenceVerifierAllowsHonestIncompleteArtifact(t *testing.T) {
	raw, err := runTypedEvidenceVerifier(t, nil, true)
	if err != nil {
		t.Fatalf("allow-incomplete rejected missing evidence: %v: %s", err, raw)
	}
	var result struct {
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("missing typed evidence was marked complete: %s", raw)
	}
}

func TestRepositoryTypedEvidenceContractCoversEveryScenario(t *testing.T) {
	output := filepath.Join(t.TempDir(), "typed-evidence.json")
	command := exec.CommandContext(
		t.Context(),
		"python3", "verify_typed_evidence.py",
		"--inventory", "pre_retirement_scenarios.json",
		"--contract", "typed_evidence_contract.json",
		"--observations", filepath.Join(t.TempDir(), "missing.jsonl"),
		"--output", output,
		"--allow-incomplete",
	)
	command.Dir = "."
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("repository typed evidence contract is invalid: %v: %s", err, combined)
	}
	var result struct {
		Complete  bool             `json:"complete"`
		Scenarios []map[string]any `json:"scenarios"`
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Scenarios) != 68 {
		t.Fatalf("repository typed evidence coverage = complete %t, scenarios %d, want false/68", result.Complete, len(result.Scenarios))
	}
}

func TestWorkflowMakesTypedEvidenceARequiredGateInput(t *testing.T) {
	workflow, err := os.ReadFile("../../../.github/workflows/native-udp-sandbox.yml")
	if err != nil {
		t.Fatal(err)
	}
	required := [][]byte{
		[]byte("QURL_GO_SANDBOX_TYPED_EVIDENCE_PATH:"),
		[]byte("python3 tests/e2e/nativeudp/verify_typed_evidence.py"),
		[]byte(`"${typed_evidence_complete}" == "true"`),
		[]byte("--argjson typed_evidence_complete"),
		[]byte("--argjson typed_evidence"),
		[]byte(".typed_evidence_complete == true"),
	}
	for _, snippet := range required {
		if !bytes.Contains(workflow, snippet) {
			t.Errorf("workflow does not bind typed evidence with %q", snippet)
		}
	}
	if bytes.Contains(workflow, []byte("native-udp-sandbox.typed-observations.jsonl\n            ${{ runner.temp }}")) {
		t.Fatal("raw typed observations must not be uploaded as proof evidence")
	}
}
