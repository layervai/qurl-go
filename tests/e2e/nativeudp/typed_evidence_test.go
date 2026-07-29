package nativeudp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var approvedArtifactUploadPaths = []string{
	"${{ runner.temp }}/deployment-runtime-inputs.json",
	"${{ runner.temp }}/native-udp-sandbox.evidence.json",
	"${{ runner.temp }}/sandbox-deployment-manifest.json",
	"${{ runner.temp }}/pre_retirement_scenarios.json",
	"${{ runner.temp }}/retired_lifecycle_surface.json",
	"${{ runner.temp }}/typed_evidence_contract.json",
}

const reviewedTypedEvidenceContractRawSHA256 = "f4b37aceb2dd55f2c1cf6d7ec4e955cfeb69297ff6151b565935d03d01f65d08"

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

func wireTraceRecord(t *testing.T, observation map[string]any) map[string]any {
	t.Helper()
	return map[string]any{
		"kind":               "wire_trace",
		"observation":        observation,
		"observation_sha256": typedEvidenceDigest(canonicalTypedEvidenceJSON(t, observation)),
		"scenario_key":       "alpha",
	}
}

func alphaBoundObservation() map[string]any {
	return map[string]any{
		"evidence_kind": "wire_trace",
		"outcome":       "pass",
		"producer":      "layervai/qurl-go",
		"scenario_key":  "alpha",
		"test_name":     "TestAlpha",
		"verified":      true,
	}
}

func runTypedEvidenceVerifier(t *testing.T, observations []byte, allowIncomplete bool) ([]byte, error) {
	t.Helper()
	root := t.TempDir()
	inventory := filepath.Join(root, "inventory.json")
	contract := filepath.Join(root, "contract.json")
	observationPath := filepath.Join(root, "observations.jsonl")
	output := filepath.Join(root, "output.json")
	if err := os.WriteFile(inventory, []byte(`{"gate":"test_gate","scenarios":[{"id":"alpha","owner":"qurl-go","test_name":"TestAlpha"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contract, []byte(`{"evidence_kinds":{"wire_trace":{"observation_schema":"owner_bound_v1"}},"gate":"test_gate","scenario_key_field":"id","scenarios":{"alpha":["wire_trace"]},"schema_version":1}`), 0o600); err != nil {
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
	return canonicalTypedEvidenceJSON(t, wireTraceRecord(t, alphaBoundObservation()))
}

func TestTypedEvidenceVerifierAcceptsExactCanonicalEvidence(t *testing.T) {
	raw, err := runTypedEvidenceVerifier(t, validTypedEvidenceRecord(t), false)
	if err != nil {
		t.Fatalf("verifier rejected valid evidence: %v: %s", err, raw)
	}
	var result struct {
		AggregateComplete bool `json:"aggregate_complete"`
		ProducerComplete  bool `json:"producer_complete"`
		Scenarios         []struct {
			Evidence []struct {
				Observation       map[string]any `json:"observation"`
				ObservationSHA256 string         `json:"observation_sha256"`
			} `json:"evidence"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.AggregateComplete || !result.ProducerComplete ||
		len(result.Scenarios) != 1 || len(result.Scenarios[0].Evidence) != 1 {
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

	badDigest := maps.Clone(record)
	badDigest["observation_sha256"] = string(make([]byte, 64))

	extraKind := maps.Clone(record)
	extraKind["kind"] = "unexpected_kind"

	secretObservation := map[string]any{"value": "lv_live_must_not_escape"}
	secret := wireTraceRecord(t, secretObservation)
	secretKeyObservation := map[string]any{"api_key": "short-secret"}
	secretKey := wireTraceRecord(t, secretKeyObservation)
	falseObservation := map[string]any{"verified": false}
	falseEvidence := wireTraceRecord(t, falseObservation)
	opaqueObservation := map[string]any{"payload": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "verified": true}
	opaqueEvidence := wireTraceRecord(t, opaqueObservation)

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
		AggregateComplete bool `json:"aggregate_complete"`
		ProducerComplete  bool `json:"producer_complete"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.AggregateComplete || result.ProducerComplete {
		t.Fatalf("missing typed evidence was marked complete: %s", raw)
	}
}

func TestRepositoryTypedEvidenceContractCoversEveryScenario(t *testing.T) {
	contractRaw, err := os.ReadFile("typed_evidence_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := typedEvidenceDigest(contractRaw); got != reviewedTypedEvidenceContractRawSHA256 {
		t.Fatalf("typed evidence contract raw SHA-256 = %s, want reviewed %s", got, reviewedTypedEvidenceContractRawSHA256)
	}
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
		AggregateComplete bool             `json:"aggregate_complete"`
		ProducerComplete  bool             `json:"producer_complete"`
		Scenarios         []map[string]any `json:"scenarios"`
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.AggregateComplete || result.ProducerComplete || len(result.Scenarios) != 68 {
		t.Fatalf("repository typed evidence coverage = producer_complete %t, scenarios %d, want false/68", result.ProducerComplete, len(result.Scenarios))
	}
}

func TestRepositoryTypedEvidenceSeparates46Owned4Static18Unobserved(t *testing.T) {
	var inventory scenarioInventory
	raw, err := os.ReadFile("pre_retirement_scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Scenarios map[string][]string `json:"scenarios"`
	}
	raw, err = os.ReadFile("typed_evidence_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}

	staticNHP := map[string]struct{}{
		"orchestrator.real_hub_authority_and_two_cells":  {},
		"retirement.generated_artifact_parity":           {},
		"retirement.nhp_registrar_surface_state":         {},
		"retirement.terraform_saved_plan_and_live_state": {},
	}
	var observations bytes.Buffer
	appendRecord := func(scenario scenarioInventoryRow, observation map[string]any) {
		t.Helper()
		kinds := contract.Scenarios[scenario.ID]
		if len(kinds) != 1 {
			t.Fatalf("scenario %q evidence kinds = %q, want exactly one", scenario.ID, kinds)
		}
		observationRaw := canonicalTypedEvidenceJSON(t, observation)
		record := map[string]any{
			"kind":               kinds[0],
			"observation":        observation,
			"observation_sha256": typedEvidenceDigest(observationRaw),
			"scenario_key":       scenario.ID,
		}
		observations.Write(canonicalTypedEvidenceJSON(t, record))
		observations.WriteByte('\n')
	}

	var connectorRow scenarioInventoryRow
	for _, scenario := range inventory.Scenarios {
		kind := contract.Scenarios[scenario.ID][0]
		switch scenario.Owner {
		case "qurl-go":
			appendRecord(scenario, map[string]any{
				"evidence_kind": kind,
				"outcome":       "pass",
				"producer":      "layervai/qurl-go",
				"scenario_key":  scenario.ID,
				"test_name":     scenario.TestName,
				"verified":      true,
			})
		case "nhp-orchestrator":
			if _, ok := staticNHP[scenario.ID]; ok {
				appendRecord(scenario, map[string]any{
					"evidence_kind":   kind,
					"producer":        "layervai/nhp",
					"producer_run_id": 999,
					"row_sha256":      strings.Repeat("d", 64),
					"scenario_key":    scenario.ID,
					"source_sha":      strings.Repeat("b", 40),
					"verified":        true,
				})
			}
		case "qurl-connector":
			if connectorRow.ID == "" {
				connectorRow = scenario
			}
		}
	}

	result := runRepositoryTypedEvidenceVerifier(t, observations.Bytes(), true)
	if !result.AggregateComplete || !result.ProducerComplete || len(result.Scenarios) != 68 {
		t.Fatalf("aggregate shape = aggregate_complete %t, producer_complete %t, rows %d",
			result.AggregateComplete, result.ProducerComplete, len(result.Scenarios))
	}
	owned, externalStatic, empty := 0, 0, 0
	for _, row := range result.Scenarios {
		switch len(row.Evidence) {
		case 0:
			empty++
		case 1:
			if _, ok := staticNHP[row.ScenarioKey]; ok {
				externalStatic++
			} else {
				owned++
			}
		default:
			t.Fatalf("scenario %q emitted %d evidence items", row.ScenarioKey, len(row.Evidence))
		}
	}
	if owned != 46 || externalStatic != 4 || empty != 18 {
		t.Fatalf("typed evidence partition = %d owned/%d static/%d empty, want 46/4/18", owned, externalStatic, empty)
	}

	lines := bytes.Split(bytes.TrimSpace(observations.Bytes()), []byte{'\n'})
	missingStatic := make([][]byte, 0, len(lines)-1)
	removedStatic := false
	for _, line := range lines {
		if !removedStatic && bytes.Contains(line, []byte(`"scenario_key":"orchestrator.real_hub_authority_and_two_cells"`)) {
			removedStatic = true
			continue
		}
		missingStatic = append(missingStatic, line)
	}
	if !removedStatic {
		t.Fatal("did not find static NHP observation to remove")
	}
	incomplete := runRepositoryTypedEvidenceVerifier(
		t,
		append(bytes.Join(missingStatic, []byte{'\n'}), '\n'),
		true,
	)
	if !incomplete.ProducerComplete || incomplete.AggregateComplete {
		t.Fatalf("missing static NHP evidence = aggregate %t producer %t, want false/true",
			incomplete.AggregateComplete, incomplete.ProducerComplete)
	}

	kind := contract.Scenarios[connectorRow.ID][0]
	appendRecord(connectorRow, map[string]any{
		"evidence_kind": kind,
		"outcome":       "pass",
		"producer":      "layervai/qurl-go",
		"scenario_key":  connectorRow.ID,
		"test_name":     connectorRow.TestName,
		"verified":      true,
	})
	runRepositoryTypedEvidenceVerifier(t, observations.Bytes(), false)
}

type repositoryTypedEvidenceResult struct {
	AggregateComplete bool `json:"aggregate_complete"`
	ProducerComplete  bool `json:"producer_complete"`
	Scenarios         []struct {
		ScenarioKey string           `json:"scenario_key"`
		Evidence    []map[string]any `json:"evidence"`
	} `json:"scenarios"`
}

func runRepositoryTypedEvidenceVerifier(
	t *testing.T,
	observations []byte,
	wantSuccess bool,
) repositoryTypedEvidenceResult {
	t.Helper()
	observationPath := filepath.Join(t.TempDir(), "observations.jsonl")
	output := filepath.Join(t.TempDir(), "typed-evidence.json")
	if err := os.WriteFile(observationPath, observations, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(
		t.Context(),
		"python3", "verify_typed_evidence.py",
		"--inventory", "pre_retirement_scenarios.json",
		"--contract", "typed_evidence_contract.json",
		"--observations", observationPath,
		"--output", output,
		"--allow-incomplete",
	)
	command.Dir = "."
	combined, err := command.CombinedOutput()
	if !wantSuccess {
		if err == nil {
			t.Fatalf("repository typed evidence verifier accepted forbidden Connector evidence: %s", combined)
		}
		return repositoryTypedEvidenceResult{}
	}
	if err != nil {
		t.Fatalf("repository typed evidence verifier failed: %v: %s", err, combined)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result repositoryTypedEvidenceResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
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
	for _, obsolete := range [][]byte{
		[]byte(`.observation == {"verified": true}`),
		[]byte("348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9"),
	} {
		if bytes.Contains(workflow, obsolete) {
			t.Errorf("workflow retains placeholder-only typed evidence contract %q", obsolete)
		}
	}
	if err := validateArtifactUploadPaths(workflow); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactUploadPathsRejectsBroadGlobWhenPathPrecedesUses(t *testing.T) {
	workflow := []byte(`steps:
  - name: Upload proof
    with:
      path: |-
          ${{ runner.temp }}/native-udp-sandbox.evidence.json
          ${{ runner.temp }}/sandbox-deployment-manifest.json
          ${{ runner.temp }}/pre_retirement_scenarios.json
          ${{ runner.temp }}/retired_lifecycle_surface.json
          ${{ runner.temp }}/*
      retention-days: 30
    uses: "actions/upload-artifact@deadbeef"
`)
	paths, err := artifactUploadPaths(workflow)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := paths[len(paths)-1], "${{ runner.temp }}/*"; got != want {
		t.Fatalf("last upload path = %q, want %q", got, want)
	}
	if err := validateArtifactUploadPaths(workflow); err == nil {
		t.Fatal("broad runner.temp upload unexpectedly passed the artifact allowlist")
	}
}

func TestArtifactUploadPathsRejectsMultipleActionsIncludingQuotedAction(t *testing.T) {
	workflow := []byte(`steps:
  - name: Upload proof
    uses: actions/upload-artifact@deadbeef
    with:
      path: |
        ${{ runner.temp }}/native-udp-sandbox.evidence.json
        ${{ runner.temp }}/sandbox-deployment-manifest.json
        ${{ runner.temp }}/pre_retirement_scenarios.json
        ${{ runner.temp }}/retired_lifecycle_surface.json
  - name: Upload broad state
    uses: "actions/upload-artifact@deadbeef"
    with:
      path: ${{ runner.temp }}/*
`)
	if err := validateArtifactUploadPaths(workflow); err == nil {
		t.Fatal("multiple upload-artifact actions unexpectedly passed the artifact allowlist")
	}
}

func validateArtifactUploadPaths(workflow []byte) error {
	paths, err := artifactUploadPaths(workflow)
	if err != nil {
		return err
	}
	got := append([]string(nil), paths...)
	want := append([]string(nil), approvedArtifactUploadPaths...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("upload-artifact paths = %q, want exact allowlist %q", got, want)
	}
	return nil
}

func artifactUploadPaths(workflow []byte) ([]string, error) {
	lines := strings.Split(string(workflow), "\n")
	var paths []string
	actionCount := 0
	for usesLine, line := range lines {
		trimmedUses := strings.TrimSpace(line)
		if !strings.Contains(trimmedUses, "actions/upload-artifact@") {
			continue
		}
		actionCount++
		usesIndent := yamlIndent(line)
		stepStart := -1
		stepIndent := -1
		if strings.HasPrefix(trimmedUses, "- ") {
			stepStart = usesLine
			stepIndent = usesIndent
		} else {
			for index := usesLine - 1; index >= 0; index-- {
				trimmed := strings.TrimSpace(lines[index])
				if strings.HasPrefix(trimmed, "- ") && yamlIndent(lines[index]) < usesIndent {
					stepStart = index
					stepIndent = yamlIndent(lines[index])
					break
				}
			}
		}
		if stepIndent < 0 {
			return nil, fmt.Errorf("upload-artifact action at line %d has no enclosing step", usesLine+1)
		}
		stepEnd := len(lines)
		for index := stepStart + 1; index < len(lines); index++ {
			if strings.HasPrefix(strings.TrimSpace(lines[index]), "- ") && yamlIndent(lines[index]) == stepIndent {
				stepEnd = index
				break
			}
		}
		var withLines []int
		for index := stepStart + 1; index < stepEnd; index++ {
			if strings.TrimSpace(lines[index]) == "with:" && yamlIndent(lines[index]) > stepIndent {
				withLines = append(withLines, index)
			}
		}
		if len(withLines) != 1 {
			return nil, fmt.Errorf("upload-artifact action at line %d has %d with blocks, want 1", usesLine+1, len(withLines))
		}
		withLine := withLines[0]
		withIndent := yamlIndent(lines[withLine])
		withEnd := stepEnd
		for index := withLine + 1; index < stepEnd; index++ {
			if strings.TrimSpace(lines[index]) != "" && yamlIndent(lines[index]) <= withIndent {
				withEnd = index
				break
			}
		}
		pathKeys := 0
		for index := withLine + 1; index < withEnd; index++ {
			trimmed := strings.TrimSpace(lines[index])
			if (trimmed != "path:" && !strings.HasPrefix(trimmed, "path: ")) || yamlIndent(lines[index]) <= withIndent {
				continue
			}
			pathKeys++
			pathIndent := yamlIndent(lines[index])
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "path:"))
			isBlockScalar := value == "" || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">")
			if !isBlockScalar {
				paths = append(paths, value)
				continue
			}
			for index++; index < withEnd; index++ {
				if strings.TrimSpace(lines[index]) == "" {
					continue
				}
				if yamlIndent(lines[index]) <= pathIndent {
					break
				}
				paths = append(paths, strings.TrimSpace(lines[index]))
			}
		}
		if pathKeys != 1 {
			return nil, fmt.Errorf("upload-artifact action at line %d has %d with.path keys, want 1", usesLine+1, pathKeys)
		}
	}
	if actionCount != 1 {
		return nil, fmt.Errorf("workflow has %d upload-artifact actions, want exactly 1", actionCount)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("workflow has no upload-artifact path inventory")
	}
	return paths, nil
}

func yamlIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}
