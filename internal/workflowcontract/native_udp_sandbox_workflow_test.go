package workflowcontract

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	nativeUDPWorkflowID                   = "4242"
	reviewedInventoryMappingSHA256Fixture = "1dff59c8188ca1cb72847135b5e4a9e2c2bba4f737d788379c93a568152dc88d"
	reviewedConnectorScenarioNamesSHA256  = "b59ce836704174518c3c66a79f49a51487379bd7efbd9db09e50f829a7d8bb3c"
)

type nativeUDPProofFixture struct {
	repository string
	preSHA     string
	postSHA    string
}

type connectorProofZIPOptions struct {
	phase    string
	mutation string
}

type connectorScenarioNameContract struct {
	SchemaVersion int      `json:"schema_version"`
	Gate          string   `json:"gate"`
	ScenarioNames []string `json:"scenario_names"`
}

func TestNativeUDPSandboxWorkflowIsAttendedStrictAndEvidenceBearing(t *testing.T) {
	workflow := readWorkflow(t, "native-udp-sandbox.yml")

	requireContains(t, workflow,
		"workflow_dispatch:",
		"proof_phase:",
		"deployment_manifest_b64:",
		"connector_proof_run_id:",
		"pre_removal_run_id:",
		"- pre_removal",
		"- post_removal",
		"environment: sandbox",
		"permissions:\n  actions: read\n  contents: read",
		"QURL_GO_SANDBOX_STRICT: \"true\"",
		"QURL_GO_SANDBOX_EXPECTED_SHA: ${{ github.sha }}",
		"QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL: ${{ secrets.QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL }}",
		"Mint read-only proof-attestation token",
		"actions/create-github-app-token@",
		"permission-actions: read",
		"permission-contents: read",
		"            frp\n            nhp\n            qurl-connector\n            qurl-go\n            qurl-integrations\n            qurl-mcp\n            qurl-python\n            qurl-reverse-tunnel-server\n            qurl-service\n            qurl-typescript\n            website",
		"test \"$(git rev-parse HEAD)\" = \"${QURL_GO_SANDBOX_EXPECTED_SHA}\"",
		"test -z \"$(git status --short)\"",
		"canonicalize_json()",
		"reject_duplicate_keys",
		".qurl_go == $qurl_go_sha",
		`(keys | sort) == ["frp", "qurl_go"]`,
		`.frp == $root.repositories.frp`,
		`actual_sha="$(gh api "repos/layervai/${repository}/commits/${expected_sha}" --jq '.sha')"`,
		"qurl_connector\tqurl-connector",
		"website\twebsite",
		`gh api "repos/${GITHUB_REPOSITORY}/pulls/93"`,
		`.head.sha == $sha`,
		`.base.ref == "main"`,
		`.commit.verification.verified == true`,
		"QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256",
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256",
		"retired_lifecycle_surface.json",
		`type == "number" and isfinite and . == floor and . >= 1 and . <= 9007199254740991`,
		"compute_proof_harness_sha256()",
		"QURL_GO_SANDBOX_INVENTORY_SHA256",
		"QURL_GO_SANDBOX_PROOF_HARNESS_SHA256",
		"pre_removal|post_removal",
		"Verify exact proof inputs",
		"Attest exact same-phase Connector proof",
		"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID",
		"connector_workflow_file=\"sandbox-smoke.yml\"",
		"connector_workflow_path=\".github/workflows/sandbox-smoke.yml\"",
		`gh api "repos/${connector_repository}/pulls/452"`,
		`.number == 452 and .state == "open"`,
		`gh api "repos/${connector_repository}/commits/${connector_sha}"`,
		"connector_scenario_contract_sha256()",
		"actions/workflows/${connector_workflow_file}",
		"strict-sandbox-proof-${QURL_GO_SANDBOX_PROOF_PHASE}-${connector_sha}-${connector_attempt}",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_PATH",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256",
		"base64 --decode",
		"http_lifecycle_present",
		"http_lifecycle_removed",
		"actions/workflows/native-udp-sandbox.yml",
		"--json attempt,conclusion,event,headSha,workflowDatabaseId",
		"native-udp-sandbox-pre_removal-${pre_head_sha}-${pre_attempt}",
		"actions/runs/${QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID}/artifacts?name=${pre_artifact_name}&per_page=100",
		"actions/artifacts/${pre_artifact_id}/zip",
		"extract_exact_qurl_go_artifact",
		".gate_passed == true",
		".inputs_unchanged == true",
		".two_cell_provenance == true",
		".scenario_contract_sha256 == $contract",
		".proof_harness_sha256 == $harness",
		"pre_protected=\"$(jq -cS '{connector_modules: {frp: .connector_modules.frp}, repositories: {frp: .repositories.frp, qurl_reverse_tunnel_server: .repositories.qurl_reverse_tunnel_server}",
		"pre_retirement_cut=\"$(jq -cS '{connector_modules: {qurl_go: .connector_modules.qurl_go}, repositories: {nhp: .repositories.nhp, qurl_connector: .repositories.qurl_connector, qurl_go: .repositories.qurl_go",
		"test \"${pre_protected}\" = \"${post_protected}\"",
		"test \"${pre_retirement_cut}\" != \"${post_retirement_cut}\"",
		"Validate exact retirement inventory",
		"go test -count=1 ./tests/e2e/nativeudp -run '^(TestPreRetirementScenarioInventory|TestRetiredLifecycleSurfaceContract)$'",
		"timeout-minutes: 75",
		"go test -count=1 -timeout=60m -json ./tests/e2e/nativeudp",
		"id: strict",
		"STRICT_OUTCOME: ${{ steps.strict.outcome }}",
		"TestSandboxConnectorUDP|TestSandboxWireEvidence|TestSandboxTopology",
		"Enforce full retirement scenario inventory",
		"pre_retirement_scenarios.json",
		".all_scenarios_required",
		"select(.status == \"implemented\")",
		".Action == \"pass\"",
		".Action == \"skip\"",
		"select(.status != \"implemented\")",
		"required retirement-gate scenarios remain unproven; every retirement and removal remains blocked",
		"Build allowlisted evidence manifest",
		"native-udp-sandbox.raw.json",
		"native-udp-sandbox.evidence.json",
		"deployment_manifest_sha256",
		"inventory_sha256",
		"scenario_contract_sha256",
		"proof_harness_sha256",
		"inputs_unchanged",
		"gate_passed",
		"provenance_valid",
		"two_cell_provenance",
		"enforcement_outcome",
		"scenario_results",
		"trap 'rm -f \"${raw}\" \"${typed_observations}\" \"${typed_evidence_summary}\"' EXIT",
		"${{ runner.temp }}/sandbox-deployment-manifest.json",
		"${{ runner.temp }}/pre_retirement_scenarios.json",
		"if-no-files-found: error",
		"retention-days: 30",
		"Require complete published proof gate",
		"Remove credential state",
	)
	requireContains(t, workflow, "          qurl_typescript\tqurl-typescript\n          website\twebsite\n          REPOSITORIES")
	requireNotContains(t, workflow,
		"schedule:",
		"pull_request:",
		"push:",
		"continue-on-error:",
		"QURL_GO_SANDBOX_ATTESTATION_TOKEN",
		" | tee ",
		"test \"${pre_head_sha}\" = \"${GITHUB_SHA}\"",
		"pre_protected=\"$(jq -cS '{repositories: {frp: .repositories.frp, qurl_connector: .repositories.qurl_connector, qurl_go:",
	)
	requireBefore(t, workflow,
		"Mint read-only proof-attestation token",
		"Verify exact proof inputs",
		"Attest exact same-phase Connector proof",
		"Validate exact retirement inventory",
		"Run strict direct UDP proof",
		"Enforce full retirement scenario inventory",
		"Build allowlisted evidence manifest",
		"Upload non-secret JSON evidence",
		"Require complete published proof gate",
		"Remove credential state",
	)
	if got := strings.Count(workflow, "def valid_counter:"); got != 3 {
		t.Fatalf("valid_counter definition count = %d, want 3", got)
	}
}

func TestNativeUDPSandboxCurrentTenCannotOpenRetirementGate(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	runnerTemp := t.TempDir()
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)

	artifact := filepath.Join(runnerTemp, "native-udp-sandbox.raw.json")
	testNames := []string{
		"TestSandboxNativeUDPLifecycle/provenance_and_hub_trust",
		"TestSandboxNativeUDPLifecycle/hub_dns_failure",
		"TestSandboxNativeUDPLifecycle/packet_timeout",
		"TestSandboxNativeUDPLifecycle/fresh_registration_via_hub_and_assigned_cell",
		"TestSandboxNativeUDPLifecycle/persisted_runtime_warm_open",
		"TestSandboxNativeUDPLifecycle/authenticated_hub_refresh",
		"TestSandboxNativeUDPLifecycle/assigned_cell_knock",
		"TestSandboxNativeUDPLifecycle/assigned_cell_clean_exit",
		"TestSandboxNativeUDPLifecycle/zero_lifecycle_http",
	}
	var evidence bytes.Buffer
	encoder := json.NewEncoder(&evidence)
	for _, testName := range testNames {
		if err := encoder.Encode(map[string]string{"Action": "pass", "Test": testName}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(artifact, evidence.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Enforce full retirement scenario inventory")
	runScript(t, fixture.repository, script, proofHashEnvironment(runnerTemp, inputs), false)
}

func TestNativeUDPSandboxNestedRequiredScenarioEventsFailClosed(t *testing.T) {
	fixture := newCompleteNativeUDPProofFixture(t)
	for _, action := range []string{"skip", "fail"} {
		t.Run(action, func(t *testing.T) {
			runnerTemp := t.TempDir()
			manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
			inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
			inventory := readScenarioTestNames(t, inputs["QURL_GO_SANDBOX_INVENTORY_PATH"])
			var raw bytes.Buffer
			encoder := json.NewEncoder(&raw)
			for _, testName := range inventory {
				if err := encoder.Encode(map[string]string{"Action": "pass", "Test": testName}); err != nil {
					t.Fatal(err)
				}
			}
			if err := encoder.Encode(map[string]string{"Action": action, "Test": inventory[0] + "/required-child"}); err != nil {
				t.Fatal(err)
			}
			artifact := filepath.Join(runnerTemp, "native-udp-sandbox.raw.json")
			if err := os.WriteFile(artifact, raw.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			runScript(t, fixture.repository,
				stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Enforce full retirement scenario inventory"),
				proofHashEnvironment(runnerTemp, inputs), false)

			agentID := "qurl-go-sandbox-nested-1"
			writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID)
			connectorAttestation := []byte(`{"schema_version":1,"gate_passed":true}`)
			if err := os.WriteFile(filepath.Join(runnerTemp, "connector-proof-attestation.json"), connectorAttestation, 0o444); err != nil {
				t.Fatal(err)
			}
			environment := proofHashEnvironment(runnerTemp, inputs)
			for key, value := range map[string]string{
				"GITHUB_REPOSITORY":                            "layervai/qurl-go",
				"GITHUB_SHA":                                   fixture.postSHA,
				"GITHUB_RUN_ID":                                "7654",
				"GITHUB_RUN_ATTEMPT":                           "1",
				"QURL_GO_SANDBOX_AGENT_ID":                     agentID,
				"QURL_GO_SANDBOX_PROOF_PHASE":                  "pre_removal",
				"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":           "",
				"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID":       "777",
				"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256": sha256Hex(connectorAttestation),
				"STRICT_OUTCOME":                               "success",
				"ENFORCEMENT_OUTCOME":                          "failure",
			} {
				environment[key] = value
			}
			runScript(t, fixture.repository,
				stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest"),
				environment, true)
			var evidence map[string]any
			body, err := os.ReadFile(filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &evidence); err != nil {
				t.Fatal(err)
			}
			counts := evidence["counts"].(map[string]any)
			countKey := map[string]string{"skip": "skips", "fail": "failures"}[action]
			if got := counts[countKey]; got != float64(1) {
				t.Fatalf("nested %s count = %v, want 1", action, got)
			}
			if evidence["gate_passed"] != false {
				t.Fatalf("nested %s did not close the gate", action)
			}
		})
	}
}

func readScenarioTestNames(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Scenarios []struct {
			TestName string `json:"test_name"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(inventory.Scenarios))
	for _, scenario := range inventory.Scenarios {
		names = append(names, scenario.TestName)
	}
	return names
}

func TestNativeUDPSandboxVerifiesManifestBytes(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	runnerTemp := t.TempDir()
	outputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)

	publishedManifest, err := os.ReadFile(filepath.Join(runnerTemp, "sandbox-deployment-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedManifest, manifest) {
		t.Fatalf("published manifest is not the canonical submitted manifest:\n got %s\nwant %s", publishedManifest, manifest)
	}
	if outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"] != sha256Hex(manifest) {
		t.Fatalf("deployment hash = %q, want %q", outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"], sha256Hex(manifest))
	}
	if outputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"] != runProofHarness(t, fixture.repository) {
		t.Fatalf("workflow did not bind the fixture's complete proof harness: %v", outputs)
	}
	if status := runGit(t, fixture.repository, "status", "--short"); status != "" {
		t.Fatalf("proof fixture became dirty: %s", status)
	}
}

func TestNativeUDPSandboxRejectsMalformedDeploymentManifests(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	valid := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "duplicate JSON key",
			mutate: func(manifest []byte) []byte {
				return append([]byte(`{"schema_version":1,`), manifest[1:]...)
			},
		},
		{
			name: "qurl_go commit mismatch",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					value["repositories"].(map[string]any)["qurl_go"] = strings.Repeat("f", 40)
				})
			},
		},
		{
			name: "missing connector modules",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					delete(value, "connector_modules")
				})
			},
		},
		{
			name: "connector frp module mismatch",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					value["connector_modules"].(map[string]any)["frp"] = strings.Repeat("f", 40)
				})
			},
		},
		{
			name: "trailing-hyphen cell id",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					value["cells"].([]any)[0].(map[string]any)["cell_id"] = "cell0-"
				})
			},
		},
		{
			name: "duplicate cell host",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					cells := value["cells"].([]any)
					cells[1].(map[string]any)["host"] = cells[0].(map[string]any)["host"]
				})
			},
		},
		{
			name: "duplicate cell public-key fingerprint",
			mutate: func(manifest []byte) []byte {
				return mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					cells := value["cells"].([]any)
					cells[1].(map[string]any)["server_public_key_sha256"] = cells[0].(map[string]any)["server_public_key_sha256"]
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", test.mutate(valid), nil, false)
			if _, err := os.Stat(filepath.Join(runnerTemp, "sandbox-deployment-manifest.json")); !os.IsNotExist(err) {
				t.Fatalf("invalid manifest was published: %v", err)
			}
		})
	}
}

func TestNativeUDPSandboxRejectsMissingRepositoryCommit(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	verifyNativeUDPManifest(
		t,
		fixture,
		fixture.postSHA,
		t.TempDir(),
		"pre_removal",
		"",
		manifest,
		map[string]string{"MOCK_MISSING_REPOSITORY": "website"},
		false,
	)
}

func TestNativeUDPSandboxRejectsMissingConnectorModuleCommit(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	verifyNativeUDPManifest(
		t,
		fixture,
		fixture.postSHA,
		t.TempDir(),
		"pre_removal",
		"",
		manifest,
		map[string]string{"MOCK_MISSING_SHA": strings.Repeat("d", 40)},
		false,
	)
}

func TestNativeUDPSandboxRejectsWrongOrUnverifiedPR93Candidate(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	for name, extra := range map[string]map[string]string{
		"wrong PR number":       {"MOCK_CANDIDATE_NUMBER": "94"},
		"closed PR":             {"MOCK_CANDIDATE_STATE": "closed"},
		"fork head":             {"MOCK_CANDIDATE_HEAD_REPO": "someone/qurl-go"},
		"wrong base repository": {"MOCK_CANDIDATE_BASE_REPO": "someone/qurl-go"},
		"wrong base branch":     {"MOCK_CANDIDATE_BASE_REF": "release"},
		"wrong current head":    {"MOCK_CANDIDATE_HEAD_SHA": strings.Repeat("f", 40)},
		"unverified commit":     {"MOCK_CANDIDATE_VERIFIED": "false"},
	} {
		t.Run(name, func(t *testing.T) {
			verifyNativeUDPManifest(
				t,
				fixture,
				fixture.postSHA,
				t.TempDir(),
				"pre_removal",
				"",
				manifest,
				extra,
				false,
			)
		})
	}
}

func TestNativeUDPSandboxAttestsExactConnectorProof(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	connectorSHA := strings.Repeat("3", 40)

	tests := []struct {
		name           string
		phase          string
		headSHA        string
		runWorkflowID  string
		mutation       string
		artifactSize   string
		artifactDigest string
		candidateEnv   map[string]string
		wantSuccess    bool
	}{
		{name: "valid exact artifact", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", wantSuccess: true},
		{name: "valid exact post artifact", phase: "post_removal", headSHA: connectorSHA, runWorkflowID: "9001", wantSuccess: true},
		{name: "wrong run head", phase: "pre_removal", headSHA: strings.Repeat("f", 40), runWorkflowID: "9001"},
		{name: "wrong workflow id", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9002"},
		{name: "wrong PR number", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_NUMBER": "453"}},
		{name: "closed PR", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_STATE": "closed"}},
		{name: "fork PR head", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_HEAD_REPO": "someone/qurl-connector"}},
		{name: "wrong PR base repository", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_BASE_REPO": "someone/qurl-connector"}},
		{name: "wrong PR base branch", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_BASE_REF": "release"}},
		{name: "wrong PR current head", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_HEAD_SHA": strings.Repeat("f", 40)}},
		{name: "unverified PR commit", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", candidateEnv: map[string]string{"MOCK_CONNECTOR_CANDIDATE_VERIFIED": "false"}},
		{name: "extra zip file", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "extra_zip_file"},
		{name: "unsafe zip path", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "unsafe_zip_path"},
		{name: "zip symlink", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "zip_symlink"},
		{name: "truncated scenarios", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "truncate_inventory"},
		{name: "duplicate scenarios", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "duplicate_inventory"},
		{name: "noncanonical inventory", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "noncanonical_inventory"},
		{name: "wrong scenario contract digest", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "wrong_scenario_contract"},
		{name: "blocking count", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "blocking_count"},
		{name: "skip count", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "skip_count"},
		{name: "failure count", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "failure_count"},
		{name: "one cell provenance", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "one_cell"},
		{name: "wrong cell provenance", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "wrong_cell"},
		{name: "wrong observation order", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "wrong_order"},
		{name: "warm tuple drift", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "warm_mismatch"},
		{name: "stale reassignment generation", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "stale_generation"},
		{name: "refresh tuple drift", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "refresh_drift"},
		{name: "stale refresh generation", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "stale_refresh_generation"},
		{name: "stale refresh revision", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "stale_refresh_revision"},
		{name: "wrong image digest", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "wrong_image"},
		{name: "wrong qurl-go module", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "wrong_module"},
		{name: "malformed post pairing", phase: "post_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "malformed_post_pairing"},
		{name: "mismatched connector pre baseline", phase: "post_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "mismatched_pre_baseline"},
		{name: "artifact API oversize", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", artifactSize: "5242881"},
		{name: "artifact digest mismatch", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", artifactDigest: strings.Repeat("f", 64)},
		{name: "deployment manifest mismatch", phase: "pre_removal", headSHA: connectorSHA, runWorkflowID: "9001", mutation: "manifest_mismatch"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			manifest := deploymentManifestBytes(t, test.phase, fixture.postSHA)
			artifactManifest := manifest
			if test.mutation == "manifest_mismatch" {
				artifactManifest = mutateDeploymentManifest(t, manifest, func(value map[string]any) {
					value["repositories"].(map[string]any)["qurl_service"] = strings.Repeat("e", 40)
				})
			}
			manifestPath := filepath.Join(runnerTemp, "sandbox-deployment-manifest.json")
			if err := os.WriteFile(manifestPath, manifest, 0o444); err != nil {
				t.Fatal(err)
			}
			archivePath := filepath.Join(runnerTemp, "connector-proof.zip")
			writeConnectorProofZIP(t, archivePath, artifactManifest, connectorSHA, connectorProofZIPOptions{
				phase:    test.phase,
				mutation: test.mutation,
			})
			archive, err := os.ReadFile(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			artifactSize := fmt.Sprint(len(archive))
			if test.artifactSize != "" {
				artifactSize = test.artifactSize
			}
			artifactDigest := sha256Hex(archive)
			if test.artifactDigest != "" {
				artifactDigest = test.artifactDigest
			}
			mockBin := writeConnectorProofGHMock(t)
			githubEnv := filepath.Join(runnerTemp, "connector.env")
			environment := map[string]string{
				"PATH":                                   mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"RUNNER_TEMP":                            runnerTemp,
				"GITHUB_ENV":                             githubEnv,
				"GH_TOKEN":                               "workflow-only-test-token",
				"QURL_GO_SANDBOX_PROOF_PHASE":            test.phase,
				"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID": "777",
				"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_PATH": manifestPath,
				"MOCK_CONNECTOR_WORKFLOW_ID":               "9001",
				"MOCK_CONNECTOR_RUN_WORKFLOW_ID":           test.runWorkflowID,
				"MOCK_CONNECTOR_HEAD_SHA":                  test.headSHA,
				"MOCK_CONNECTOR_PHASE":                     test.phase,
				"MOCK_CONNECTOR_ARTIFACT_ZIP":              archivePath,
				"MOCK_CONNECTOR_ARTIFACT_SHA256":           artifactDigest,
				"MOCK_CONNECTOR_ARTIFACT_SIZE":             artifactSize,
			}
			if test.phase == "post_removal" {
				environment["QURL_GO_SANDBOX_PRE_REMOVAL_CONNECTOR_PROOF_RUN_ID"] = "456"
			}
			for key, value := range test.candidateEnv {
				environment[key] = value
			}
			script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Attest exact same-phase Connector proof")
			runScript(t, fixture.repository, script, environment, test.wantSuccess)
			if !test.wantSuccess {
				return
			}
			outputs := readStepOutputs(t, githubEnv)
			attestationPath := outputs["QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_PATH"]
			attestation, err := os.ReadFile(attestationPath)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := outputs["QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256"], sha256Hex(attestation); got != want {
				t.Fatalf("Connector attestation digest = %q, want %q", got, want)
			}
			if bytes.Contains(attestation, []byte(environment["GH_TOKEN"])) {
				t.Fatal("allowlisted Connector attestation exposed the workflow token")
			}
			var decoded map[string]any
			if err := json.Unmarshal(attestation, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["connector_commit_sha"] != connectorSHA || decoded["phase"] != test.phase || decoded["gate_passed"] != true {
				t.Fatalf("Connector attestation did not bind the exact successful proof: %v", decoded)
			}
			if test.phase == "post_removal" && decoded["pre_removal_run_id"] != "456" {
				t.Fatalf("post-removal Connector attestation omitted its paired pre-removal baseline: %v", decoded)
			}
			if test.phase == "pre_removal" && decoded["pre_removal_run_id"] != nil {
				t.Fatalf("pre-removal Connector attestation carried an impossible prior baseline: %v", decoded)
			}
		})
	}
}

func TestNativeUDPSandboxPostRemovalRequiresPairedSuccessfulRun(t *testing.T) {
	fixture := newCompleteNativeUDPProofFixture(t)
	preRunnerTemp := t.TempDir()
	preManifest := deploymentManifestBytes(t, "pre_removal", fixture.preSHA)
	preOutputs := verifyNativeUDPManifest(t, fixture, fixture.preSHA, preRunnerTemp, "pre_removal", "", preManifest, nil, true)

	preEvidence := filepath.Join(preRunnerTemp, "pre-removal.evidence.json")
	writeJSONFile(t, preEvidence, validPreRemovalEvidence(t, fixture.preSHA, preOutputs))
	preArchive := filepath.Join(preRunnerTemp, "native-udp-sandbox-pre.zip")
	writeQURLGoProofZIP(t, preArchive, preEvidence,
		filepath.Join(preRunnerTemp, "sandbox-deployment-manifest.json"),
		filepath.Join(preRunnerTemp, "pre_retirement_scenarios.json"), "")
	preArchiveBytes, err := os.ReadFile(preArchive)
	if err != nil {
		t.Fatal(err)
	}

	mockBin := writeNativeUDPGHMock(t)
	postRunnerTemp := t.TempDir()
	postManifest := mutateDeploymentManifest(t, deploymentManifestBytes(t, "post_removal", fixture.postSHA), func(value map[string]any) {
		value["repositories"].(map[string]any)["qurl_connector"] = strings.Repeat("c", 40)
		value["repositories"].(map[string]any)["website"] = strings.Repeat("d", 40)
		value["connector_modules"].(map[string]any)["qurl_go"] = strings.Repeat("e", 40)
		value["images"].(map[string]any)["qurl_connector"] = "sha256:" + strings.Repeat("f", 64)
	})
	extra := map[string]string{
		"PATH":                     mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_TOKEN":                 "test-token",
		"MOCK_HEAD_SHA":            fixture.preSHA,
		"MOCK_PRE_RUN_ID":          "987",
		"MOCK_PRE_ARTIFACT_ZIP":    preArchive,
		"MOCK_PRE_ARTIFACT_SHA256": sha256Hex(preArchiveBytes),
		"MOCK_PRE_ARTIFACT_SIZE":   fmt.Sprint(len(preArchiveBytes)),
		"MOCK_WORKFLOW_ID":         nativeUDPWorkflowID,
	}
	postOutputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, postRunnerTemp, "post_removal", "987", postManifest, extra, true)
	if fixture.preSHA == fixture.postSHA {
		t.Fatal("paired proof fixture did not use distinct qurl-go commits")
	}
	if preOutputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"] != postOutputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"] ||
		preOutputs["QURL_GO_SANDBOX_INVENTORY_SHA256"] != postOutputs["QURL_GO_SANDBOX_INVENTORY_SHA256"] ||
		preOutputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"] != postOutputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"] {
		t.Fatalf("paired proof did not preserve the harness, inventory, and scenario contract:\npre=%v\npost=%v", preOutputs, postOutputs)
	}

	if !strings.HasSuffix(postOutputs["QURL_GO_SANDBOX_PRE_REMOVAL_EVIDENCE_PATH"], "native-udp-sandbox.evidence.json") {
		t.Fatalf("post-removal proof did not bind the downloaded pre-removal evidence: %v", postOutputs)
	}
	preEvidenceBytes, err := os.ReadFile(preEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := postOutputs["QURL_GO_SANDBOX_PRE_REMOVAL_EVIDENCE_SHA256"], sha256Hex(preEvidenceBytes); got != want {
		t.Fatalf("paired evidence hash = %q, want %q", got, want)
	}
	if got, want := postOutputs["QURL_GO_SANDBOX_PRE_REMOVAL_DEPLOYMENT_SHA256"], sha256Hex(preManifest); got != want {
		t.Fatalf("paired deployment hash = %q, want %q", got, want)
	}
}

func TestNativeUDPSandboxPostRemovalRejectsUntrustedPairedArtifacts(t *testing.T) {
	fixture := newCompleteNativeUDPProofFixture(t)
	tests := []struct {
		name           string
		mutation       string
		oversize       bool
		badHash        bool
		mutateManifest func(map[string]any)
	}{
		{name: "extra archive file", mutation: "extra_zip_file"},
		{name: "unsafe archive path", mutation: "unsafe_zip_path"},
		{name: "noncanonical evidence", mutation: "noncanonical_evidence"},
		{name: "noncanonical inventory", mutation: "noncanonical_inventory"},
		{name: "noncanonical retired lifecycle surface", mutation: "noncanonical_retired_surface"},
		{name: "changed retired lifecycle surface", mutation: "changed_retired_surface"},
		{name: "pre-removal strict step failed", mutation: "strict_failed"},
		{name: "artifact API oversize", oversize: true},
		{name: "artifact digest mismatch", badHash: true},
		{name: "FRP repository and Connector module repinned", mutateManifest: func(value map[string]any) {
			value["repositories"].(map[string]any)["frp"] = strings.Repeat("c", 40)
			value["connector_modules"].(map[string]any)["frp"] = strings.Repeat("c", 40)
		}},
		{name: "qRTS repository repinned", mutateManifest: func(value map[string]any) {
			value["repositories"].(map[string]any)["qurl_reverse_tunnel_server"] = strings.Repeat("c", 40)
		}},
		{name: "qRTS image repinned", mutateManifest: func(value map[string]any) {
			value["images"].(map[string]any)["qurl_reverse_tunnel_server"] = "sha256:" + strings.Repeat("c", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preRunnerTemp := t.TempDir()
			preManifest := deploymentManifestBytes(t, "pre_removal", fixture.preSHA)
			preOutputs := verifyNativeUDPManifest(t, fixture, fixture.preSHA, preRunnerTemp, "pre_removal", "", preManifest, nil, true)
			preEvidence := filepath.Join(preRunnerTemp, "pre-removal.evidence.json")
			writeJSONFile(t, preEvidence, validPreRemovalEvidence(t, fixture.preSHA, preOutputs))
			preArchive := filepath.Join(preRunnerTemp, "native-udp-sandbox-pre.zip")
			writeQURLGoProofZIP(t, preArchive, preEvidence,
				filepath.Join(preRunnerTemp, "sandbox-deployment-manifest.json"),
				filepath.Join(preRunnerTemp, "pre_retirement_scenarios.json"), test.mutation)
			archive, err := os.ReadFile(preArchive)
			if err != nil {
				t.Fatal(err)
			}
			size := fmt.Sprint(len(archive))
			if test.oversize {
				size = "5242881"
			}
			digest := sha256Hex(archive)
			if test.badHash {
				digest = strings.Repeat("f", 64)
			}
			extra := map[string]string{
				"PATH":                     writeNativeUDPGHMock(t) + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GH_TOKEN":                 "test-token",
				"MOCK_HEAD_SHA":            fixture.preSHA,
				"MOCK_PRE_RUN_ID":          "987",
				"MOCK_PRE_ARTIFACT_ZIP":    preArchive,
				"MOCK_PRE_ARTIFACT_SHA256": digest,
				"MOCK_PRE_ARTIFACT_SIZE":   size,
				"MOCK_WORKFLOW_ID":         nativeUDPWorkflowID,
			}
			postManifest := deploymentManifestBytes(t, "post_removal", fixture.postSHA)
			if test.mutateManifest != nil {
				postManifest = mutateDeploymentManifest(t, postManifest, test.mutateManifest)
			}
			verifyNativeUDPManifest(t, fixture, fixture.postSHA, t.TempDir(), "post_removal", "987", postManifest, extra, false)
		})
	}
}

func validPreRemovalEvidence(t *testing.T, commitSHA string, outputs map[string]string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(outputs["QURL_GO_SANDBOX_INVENTORY_PATH"])
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Scenarios []struct {
			ID       string `json:"id"`
			TestName string `json:"test_name"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	scenarioResults := make([]any, 0, len(inventory.Scenarios))
	typedEvidence := make([]any, 0, len(inventory.Scenarios))
	for _, scenario := range inventory.Scenarios {
		scenarioResults = append(scenarioResults, map[string]any{
			"test_name":       scenario.TestName,
			"action":          "pass",
			"elapsed_seconds": 1.0,
		})
		typedEvidence = append(typedEvidence, map[string]any{
			"scenario_key": scenario.ID,
			"evidence": []any{map[string]any{
				"kind":               "wire_trace",
				"observation":        map[string]any{"verified": true},
				"observation_sha256": "348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9",
			}},
		})
	}
	return map[string]any{
		"schema_version":                   1,
		"phase":                            "pre_removal",
		"repository":                       "layervai/qurl-go",
		"commit_sha":                       commitSHA,
		"run_id":                           "987",
		"run_attempt":                      "3",
		"connector_proof_run_id":           "777",
		"connector_attestation_sha256":     strings.Repeat("c", 64),
		"pre_removal_run_id":               nil,
		"pre_removal_evidence_sha256":      nil,
		"pre_removal_deployment_sha256":    nil,
		"enforcement_outcome":              "success",
		"inputs_unchanged":                 true,
		"gate_passed":                      true,
		"provenance_valid":                 true,
		"two_cell_provenance":              true,
		"typed_evidence_complete":          true,
		"typed_evidence":                   typedEvidence,
		"deployment_manifest_sha256":       outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
		"inventory_sha256":                 outputs["QURL_GO_SANDBOX_INVENTORY_SHA256"],
		"inventory_mapping_sha256":         outputs["QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256"],
		"scenario_contract_sha256":         outputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"],
		"retired_lifecycle_surface_sha256": outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256"],
		"typed_evidence_contract_sha256":   outputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
		"proof_harness_sha256":             outputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
		"strict_outcome":                   "success",
		"counts":                           map[string]int{"implemented": len(inventory.Scenarios), "blocking": 0, "failures": 0, "skips": 0, "exact_passes": len(inventory.Scenarios)},
		"provenance":                       proofProvenanceValue(commitSHA, "qurl-go-sandbox-pre-proof"),
		"scenario_results":                 scenarioResults,
	}
}

func TestNativeUDPSandboxEvidenceManifestIsAllowlisted(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	runnerTemp := t.TempDir()
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
	agentID := "qurl-go-sandbox-1234-2"
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID)

	rawPath := filepath.Join(runnerTemp, "native-udp-sandbox.raw.json")
	const reflectedSecret = "server-minted-enrollment-secret-must-not-upload"
	raw := []byte(`{"Action":"output","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure","Output":"` + reflectedSecret + `\n"}` + "\n" +
		`{"Action":"pass","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure","Elapsed":0.25}` + "\n")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	connectorAttestationPath := filepath.Join(runnerTemp, "connector-proof-attestation.json")
	connectorAttestation := []byte(`{"schema_version":1,"gate_passed":true}`)
	if err := os.WriteFile(connectorAttestationPath, connectorAttestation, 0o444); err != nil {
		t.Fatal(err)
	}

	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest")
	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                            "layervai/qurl-go",
		"GITHUB_SHA":                                   fixture.postSHA,
		"GITHUB_RUN_ID":                                "1234",
		"GITHUB_RUN_ATTEMPT":                           "2",
		"QURL_GO_SANDBOX_AGENT_ID":                     agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":                  "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":           "",
		"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID":       "777",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256": sha256Hex(connectorAttestation),
		"STRICT_OUTCOME":                               "success",
		"ENFORCEMENT_OUTCOME":                          "failure",
	} {
		environment[key] = value
	}
	runScript(t, fixture.repository, script, environment, true)

	if _, err := os.Stat(rawPath); !os.IsNotExist(err) {
		t.Fatalf("raw go-test artifact was not removed: %v", err)
	}
	evidence, err := os.ReadFile(filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), reflectedSecret) || strings.Contains(string(evidence), "Output") {
		t.Fatalf("allowlisted evidence retained raw output or a reflected secret: %s", evidence)
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evidence, canonical) {
		t.Fatalf("allowlisted evidence is not canonical JSON: %s", evidence)
	}
	for name, want := range map[string]any{
		"phase":                        "pre_removal",
		"repository":                   "layervai/qurl-go",
		"commit_sha":                   fixture.postSHA,
		"deployment_manifest_sha256":   sha256Hex(manifest),
		"proof_harness_sha256":         inputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
		"strict_outcome":               "success",
		"inputs_unchanged":             true,
		"gate_passed":                  false,
		"connector_proof_run_id":       "777",
		"connector_attestation_sha256": sha256Hex(connectorAttestation),
		"provenance_valid":             true,
		"two_cell_provenance":          true,
	} {
		if got := decoded[name]; got != want {
			t.Errorf("evidence %s = %v, want %v", name, got, want)
		}
	}
	counts := decoded["counts"].(map[string]any)
	if counts["blocking"] != float64(58) {
		t.Fatalf("evidence blocking count = %v, want 58", counts["blocking"])
	}
	results := decoded["scenario_results"].([]any)
	if len(results) != 1 {
		t.Fatalf("scenario result count = %d, want 1", len(results))
	}
	result := results[0].(map[string]any)
	if result["test_name"] != "TestSandboxNativeUDPLifecycle/hub_dns_failure" || result["action"] != "pass" {
		t.Fatalf("unexpected scenario result: %v", result)
	}
	provenance := decoded["provenance"].(map[string]any)
	if provenance["agent_id"] != agentID {
		t.Fatalf("provenance agent_id = %v, want %q", provenance["agent_id"], agentID)
	}
	assignedCells := provenance["assigned_cells"].([]any)
	phases := make([]string, 0, len(assignedCells))
	for _, value := range assignedCells {
		phases = append(phases, value.(map[string]any)["phase"].(string))
	}
	if strings.Join(phases, ",") != "registration,warm_open,reassignment,refresh" {
		t.Fatalf("provenance phases = %v", phases)
	}
}

func TestNativeUDPSandboxEvidenceFailsClosedWhenInventorySnapshotIsReplaced(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	runnerTemp := t.TempDir()
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
	agentID := "qurl-go-sandbox-4321-1"
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID)

	snapshot := inputs["QURL_GO_SANDBOX_INVENTORY_PATH"]
	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, []byte(`{"schema_version":1}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runnerTemp, "native-udp-sandbox.raw.json"),
		[]byte(`{"Action":"pass","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	connectorAttestation := []byte(`{"schema_version":1,"gate_passed":true}`)
	if err := os.WriteFile(filepath.Join(runnerTemp, "connector-proof-attestation.json"), connectorAttestation, 0o444); err != nil {
		t.Fatal(err)
	}

	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                            "layervai/qurl-go",
		"GITHUB_SHA":                                   fixture.postSHA,
		"GITHUB_RUN_ID":                                "4321",
		"GITHUB_RUN_ATTEMPT":                           "1",
		"QURL_GO_SANDBOX_AGENT_ID":                     agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":                  "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":           "",
		"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID":       "777",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256": sha256Hex(connectorAttestation),
		"STRICT_OUTCOME":                               "success",
		"ENFORCEMENT_OUTCOME":                          "success",
	} {
		environment[key] = value
	}
	runScript(t, fixture.repository, stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest"), environment, true)

	var evidence map[string]any
	raw, err := os.ReadFile(filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["inputs_unchanged"] != false || evidence["gate_passed"] != false {
		t.Fatalf("replaced inventory snapshot did not fail closed: %v", evidence)
	}
}

func TestNativeUDPSandboxEvidenceRequiresStrictStepSuccess(t *testing.T) {
	fixture := newCompleteNativeUDPProofFixture(t)
	runnerTemp := t.TempDir()
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	for _, testName := range readScenarioTestNames(t, inputs["QURL_GO_SANDBOX_INVENTORY_PATH"]) {
		if err := encoder.Encode(map[string]string{"Action": "pass", "Test": testName}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(runnerTemp, "native-udp-sandbox.raw.json"), raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	agentID := "qurl-go-sandbox-strict-1"
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID)
	connectorAttestation := []byte(`{"schema_version":1,"gate_passed":true}`)
	if err := os.WriteFile(filepath.Join(runnerTemp, "connector-proof-attestation.json"), connectorAttestation, 0o444); err != nil {
		t.Fatal(err)
	}
	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                            "layervai/qurl-go",
		"GITHUB_SHA":                                   fixture.postSHA,
		"GITHUB_RUN_ID":                                "1111",
		"GITHUB_RUN_ATTEMPT":                           "1",
		"QURL_GO_SANDBOX_AGENT_ID":                     agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":                  "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":           "",
		"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID":       "777",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256": sha256Hex(connectorAttestation),
		"STRICT_OUTCOME":                               "failure",
		"ENFORCEMENT_OUTCOME":                          "success",
	} {
		environment[key] = value
	}
	runScript(t, fixture.repository,
		stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest"),
		environment, true)
	var evidence map[string]any
	body, err := os.ReadFile(filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &evidence); err != nil {
		t.Fatal(err)
	}
	counts := evidence["counts"].(map[string]any)
	if evidence["strict_outcome"] != "failure" || evidence["gate_passed"] != false ||
		counts["blocking"] != float64(0) || counts["exact_passes"] != counts["implemented"] ||
		evidence["provenance_valid"] != true || evidence["two_cell_provenance"] != true {
		t.Fatalf("strict-step failure was not independently bound fail-closed: %v", evidence)
	}
}

func TestNativeUDPSandboxOperationalProvenanceRequiresExactTransition(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	tests := map[string]func([]any){
		"wrong phase order": func(cells []any) { cells[0], cells[1] = cells[1], cells[0] },
		"warm tuple drift": func(cells []any) {
			cells[1] = proofCell("warm_open", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 1)
		},
		"stale reassignment generation": func(cells []any) {
			cells[2] = proofCell("reassignment", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
		},
		"refresh tuple drift": func(cells []any) {
			cells[3] = proofCell("refresh", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 2, 3)
		},
		"stale refresh generation": func(cells []any) {
			cells[3] = proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
		},
		"stale refresh revision": func(cells []any) {
			cells[3] = proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
			inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
			agentID := "qurl-go-sandbox-transition-1"
			provenance := proofProvenanceValue(fixture.postSHA, agentID)
			mutate(provenance["assigned_cells"].([]any))
			writeProofProvenanceValue(t, runnerTemp, provenance)
			if err := os.WriteFile(filepath.Join(runnerTemp, "native-udp-sandbox.raw.json"),
				[]byte(`{"Action":"pass","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			connectorAttestation := []byte(`{"schema_version":1,"gate_passed":true}`)
			if err := os.WriteFile(filepath.Join(runnerTemp, "connector-proof-attestation.json"), connectorAttestation, 0o444); err != nil {
				t.Fatal(err)
			}
			environment := proofHashEnvironment(runnerTemp, inputs)
			for key, value := range map[string]string{
				"GITHUB_REPOSITORY":                            "layervai/qurl-go",
				"GITHUB_SHA":                                   fixture.postSHA,
				"GITHUB_RUN_ID":                                "8765",
				"GITHUB_RUN_ATTEMPT":                           "1",
				"QURL_GO_SANDBOX_AGENT_ID":                     agentID,
				"QURL_GO_SANDBOX_PROOF_PHASE":                  "pre_removal",
				"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":           "",
				"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID":       "777",
				"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256": sha256Hex(connectorAttestation),
				"STRICT_OUTCOME":                               "success",
				"ENFORCEMENT_OUTCOME":                          "failure",
			} {
				environment[key] = value
			}
			runScript(t, fixture.repository,
				stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest"),
				environment, true)
			var evidence map[string]any
			body, err := os.ReadFile(filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &evidence); err != nil {
				t.Fatal(err)
			}
			if evidence["provenance_valid"] != false || evidence["two_cell_provenance"] != false || evidence["gate_passed"] != false {
				t.Fatalf("invalid transition provenance did not fail closed: %v", evidence)
			}
		})
	}
}

func TestNativeUDPSandboxRequiresCompletePublishedProof(t *testing.T) {
	typedEvidence := make([]any, 68)
	for index := range typedEvidence {
		typedEvidence[index] = map[string]any{
			"scenario_key": fmt.Sprintf("scenario-%d", index),
			"evidence": []any{map[string]any{
				"kind":               "wire_trace",
				"observation":        map[string]any{"verified": true},
				"observation_sha256": "348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9",
			}},
		}
	}
	base := map[string]any{
		"gate_passed":                    true,
		"strict_outcome":                 "success",
		"enforcement_outcome":            "success",
		"inputs_unchanged":               true,
		"counts":                         map[string]any{"implemented": 68, "blocking": 0, "failures": 0, "skips": 0, "exact_passes": 68},
		"provenance_valid":               true,
		"two_cell_provenance":            true,
		"typed_evidence_complete":        true,
		"typed_evidence":                 typedEvidence,
		"typed_evidence_contract_sha256": "e15008760ea838875de9c75561726c86e9d2e7f7f507247e55a588fa3ac65fe5",
	}
	tests := []struct {
		name        string
		mutate      func(map[string]any)
		wantSuccess bool
	}{
		{name: "complete", wantSuccess: true},
		{name: "gate false", mutate: func(value map[string]any) { value["gate_passed"] = false }},
		{name: "strict failed", mutate: func(value map[string]any) { value["strict_outcome"] = "failure" }},
		{name: "enforcement failed", mutate: func(value map[string]any) { value["enforcement_outcome"] = "failure" }},
		{name: "inputs changed", mutate: func(value map[string]any) { value["inputs_unchanged"] = false }},
		{name: "blocking", mutate: func(value map[string]any) { value["counts"].(map[string]any)["blocking"] = 1 }},
		{name: "zero implemented", mutate: func(value map[string]any) {
			value["counts"].(map[string]any)["implemented"] = 0
			value["counts"].(map[string]any)["exact_passes"] = 0
			value["typed_evidence"] = []any{}
		}},
		{name: "failure", mutate: func(value map[string]any) { value["counts"].(map[string]any)["failures"] = 1 }},
		{name: "skip", mutate: func(value map[string]any) { value["counts"].(map[string]any)["skips"] = 1 }},
		{name: "pass mismatch", mutate: func(value map[string]any) { value["counts"].(map[string]any)["exact_passes"] = 63 }},
		{name: "provenance false", mutate: func(value map[string]any) { value["provenance_valid"] = false }},
		{name: "two-cell false", mutate: func(value map[string]any) { value["two_cell_provenance"] = false }},
		{name: "typed evidence incomplete", mutate: func(value map[string]any) { value["typed_evidence_complete"] = false }},
		{name: "typed evidence missing row", mutate: func(value map[string]any) {
			value["typed_evidence"] = value["typed_evidence"].([]any)[:67]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			value := cloneJSONMap(t, base)
			if test.mutate != nil {
				test.mutate(value)
			}
			writeJSONFile(t, filepath.Join(runnerTemp, "native-udp-sandbox.evidence.json"), value)
			runScript(t, t.TempDir(), stepRun(t, readWorkflow(t, "native-udp-sandbox.yml"), "Require complete published proof gate"),
				map[string]string{"RUNNER_TEMP": runnerTemp}, test.wantSuccess)
		})
	}
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func newNativeUDPProofFixture(t *testing.T) nativeUDPProofFixture {
	return newNativeUDPProofFixtureWithInventory(t, false)
}

func newCompleteNativeUDPProofFixture(t *testing.T) nativeUDPProofFixture {
	return newNativeUDPProofFixtureWithInventory(t, true)
}

func readNativeUDPFixtureWorkflow(t *testing.T, fixture nativeUDPProofFixture) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(fixture.repository, ".github", "workflows", "native-udp-sandbox.yml"))
	if err != nil {
		t.Fatalf("read native UDP fixture workflow: %v", err)
	}
	return string(contents)
}

func newNativeUDPProofFixtureWithInventory(t *testing.T, completeInventory bool) nativeUDPProofFixture {
	t.Helper()
	sourceRoot := filepath.Clean(filepath.Join(workflowDir(t), "..", ".."))
	repository := t.TempDir()

	copyProofFile := func(relativePath string) {
		t.Helper()
		source := filepath.Join(sourceRoot, relativePath)
		contents, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read proof fixture %s: %v", relativePath, err)
		}
		info, err := os.Stat(source)
		if err != nil {
			t.Fatalf("stat proof fixture %s: %v", relativePath, err)
		}
		destination := filepath.Join(repository, relativePath)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatalf("create proof fixture directory: %v", err)
		}
		if err := os.WriteFile(destination, contents, info.Mode().Perm()); err != nil {
			t.Fatalf("write proof fixture %s: %v", relativePath, err)
		}
	}

	copyProofFile(filepath.Join(".github", "workflows", "native-udp-sandbox.yml"))
	copyProofFile(filepath.Join("internal", "workflowcontract", "native_udp_sandbox_workflow_test.go"))
	nativeUDPSource := filepath.Join(sourceRoot, "tests", "e2e", "nativeudp")
	if err := filepath.WalkDir(nativeUDPSource, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		extension := filepath.Ext(path)
		if extension != ".go" && extension != ".json" && extension != ".py" {
			return nil
		}
		relativePath, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		copyProofFile(relativePath)
		return nil
	}); err != nil {
		t.Fatalf("copy native UDP proof files: %v", err)
	}
	if completeInventory {
		inventoryPath := filepath.Join(repository, "tests", "e2e", "nativeudp", "pre_retirement_scenarios.json")
		raw, err := os.ReadFile(inventoryPath)
		if err != nil {
			t.Fatal(err)
		}
		var inventory map[string]any
		if err := json.Unmarshal(raw, &inventory); err != nil {
			t.Fatal(err)
		}
		for _, item := range inventory["scenarios"].([]any) {
			item.(map[string]any)["status"] = "implemented"
		}
		canonical, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inventoryPath, canonical, 0o644); err != nil {
			t.Fatal(err)
		}
		completeMappingSHA := normalizedInventoryMappingSHA256(t, canonical)
		for _, path := range []string{
			filepath.Join(repository, ".github", "workflows", "native-udp-sandbox.yml"),
			filepath.Join(repository, "tests", "e2e", "nativeudp", "inventory_test.go"),
		} {
			replaceFixtureLiteral(t, path, reviewedInventoryMappingSHA256Fixture, completeMappingSHA)
		}
	}

	runGit(t, repository, "init", "--quiet", "--initial-branch=main")
	runGit(t, repository, "config", "user.name", "workflow test")
	runGit(t, repository, "config", "user.email", "workflow@example.invalid")
	runGit(t, repository, "add", ".")
	runGit(t, repository, "commit", "--quiet", "-m", "proof fixture")
	preSHA := runGit(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "commit", "--quiet", "--allow-empty", "-m", "post-removal qurl-go cut")
	fixture := nativeUDPProofFixture{repository: repository, preSHA: preSHA, postSHA: runGit(t, repository, "rev-parse", "HEAD")}
	if status := runGit(t, repository, "status", "--short"); status != "" {
		t.Fatalf("proof fixture is not clean: %s", status)
	}
	if got := runProofHarness(t, repository); len(got) != 64 {
		t.Fatalf("proof fixture harness hash = %q", got)
	}
	return fixture
}

func normalizedInventoryMappingSHA256(t *testing.T, raw []byte) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "jq", "-cS", "-j",
		`{schema_version, gate, proof_phases, all_scenarios_required, scenarios: ([.scenarios[] | {id, owner, status, test_name, requirement}] | sort_by(.id))}`)
	command.Stdin = bytes.NewReader(raw)
	encoded, err := command.Output()
	if err != nil {
		t.Fatalf("normalize inventory mapping: %v", err)
	}
	return sha256Hex(encoded)
}

func replaceFixtureLiteral(t *testing.T, path, old, replacement string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := bytes.ReplaceAll(raw, []byte(old), []byte(replacement))
	if bytes.Equal(raw, updated) {
		t.Fatalf("fixture %s did not contain reviewed literal %s", path, old)
	}
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		t.Fatal(err)
	}
}

func verifyNativeUDPManifest(
	t *testing.T,
	fixture nativeUDPProofFixture,
	buildSHA string,
	runnerTemp, phase, preRemovalRunID string,
	manifest []byte,
	extra map[string]string,
	wantSuccess bool,
) map[string]string {
	t.Helper()
	runGit(t, fixture.repository, "checkout", "--detach", "--quiet", buildSHA)
	githubEnv := filepath.Join(runnerTemp, "github.env")
	commitMockBin := writeManifestCommitGHMock(t)
	environment := map[string]string{
		"PATH":                         commitMockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"RUNNER_TEMP":                  runnerTemp,
		"GITHUB_ENV":                   githubEnv,
		"GITHUB_REPOSITORY":            "layervai/qurl-go",
		"GITHUB_SHA":                   buildSHA,
		"QURL_GO_SANDBOX_EXPECTED_SHA": buildSHA,
		"QURL_GO_SANDBOX_PROOF_PHASE":  phase,
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_B64":   base64.StdEncoding.EncodeToString(manifest),
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":        preRemovalRunID,
		"QURL_GO_SANDBOX_HUB_HOST":                  "hub.nhp.layerv.ai",
		"QURL_GO_SANDBOX_HUB_PORT":                  "62206",
		"QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64": base64.StdEncoding.EncodeToString(nativeUDPProofHubKey()),
	}
	for key, value := range extra {
		environment[key] = value
	}
	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Verify exact proof inputs")
	runScript(t, fixture.repository, script, environment, wantSuccess)
	if !wantSuccess {
		return nil
	}
	return readStepOutputs(t, githubEnv)
}

func writeManifestCommitGHMock(t *testing.T) string {
	t.Helper()
	mockBin := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
test "$1" = "api"
case "$2" in
  repos/layervai/qurl-go/pulls/93)
    printf '{"number":%s,"state":"%s","head":{"sha":"%s","repo":{"full_name":"%s"}},"base":{"ref":"%s","repo":{"full_name":"%s"}}}\n' \
      "${MOCK_CANDIDATE_NUMBER:-93}" "${MOCK_CANDIDATE_STATE:-open}" "${MOCK_CANDIDATE_HEAD_SHA:-${GITHUB_SHA}}" \
      "${MOCK_CANDIDATE_HEAD_REPO:-layervai/qurl-go}" "${MOCK_CANDIDATE_BASE_REF:-main}" "${MOCK_CANDIDATE_BASE_REPO:-layervai/qurl-go}"
    ;;
  repos/layervai/*/commits/*)
    repository="${2#repos/layervai/}"
    repository="${repository%%/*}"
    test "${repository}" != "${MOCK_MISSING_REPOSITORY:-}"
    test "${2##*/}" != "${MOCK_MISSING_SHA:-}"
    if [[ "$#" == "2" ]]; then
      printf '{"sha":"%s","commit":{"verification":{"verified":%s}}}\n' "${2##*/}" "${MOCK_CANDIDATE_VERIFIED:-true}"
    else
      test "$3" = "--jq"
      test "$4" = ".sha"
      printf '%s\n' "${2##*/}"
    fi
    ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return mockBin
}

func proofHashEnvironment(runnerTemp string, outputs map[string]string) map[string]string {
	return map[string]string{
		"RUNNER_TEMP": runnerTemp,
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_PATH":         outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_PATH"],
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256":       outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
		"QURL_GO_SANDBOX_INVENTORY_PATH":                   outputs["QURL_GO_SANDBOX_INVENTORY_PATH"],
		"QURL_GO_SANDBOX_INVENTORY_SHA256":                 outputs["QURL_GO_SANDBOX_INVENTORY_SHA256"],
		"QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256":         outputs["QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256"],
		"QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256":         outputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"],
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_PATH":   outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_PATH"],
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256": outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256"],
		"QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256":   outputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
		"QURL_GO_SANDBOX_PROOF_HARNESS_SHA256":             outputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
	}
}

func deploymentManifestBytes(t *testing.T, phase, qurlGoSHA string) []byte {
	t.Helper()
	retirementState := "http_lifecycle_present"
	qurlServiceSHA := strings.Repeat("8", 40)
	qurlServiceAuthorityImage := "sha256:" + strings.Repeat("6", 64)
	if phase == "post_removal" {
		retirementState = "http_lifecycle_removed"
		qurlServiceSHA = strings.Repeat("a", 40)
		qurlServiceAuthorityImage = "sha256:" + strings.Repeat("a", 64)
	}
	manifest := map[string]any{
		"schema_version":   1,
		"phase":            phase,
		"retirement_state": retirementState,
		"connector_modules": map[string]string{
			"frp":     strings.Repeat("1", 40),
			"qurl_go": strings.Repeat("d", 40),
		},
		"repositories": map[string]string{
			"frp":                        strings.Repeat("1", 40),
			"nhp":                        strings.Repeat("2", 40),
			"qurl_connector":             strings.Repeat("3", 40),
			"qurl_go":                    qurlGoSHA,
			"qurl_integrations":          strings.Repeat("4", 40),
			"qurl_mcp":                   strings.Repeat("5", 40),
			"qurl_python":                strings.Repeat("6", 40),
			"qurl_reverse_tunnel_server": strings.Repeat("7", 40),
			"qurl_service":               qurlServiceSHA,
			"qurl_typescript":            strings.Repeat("9", 40),
			"website":                    strings.Repeat("b", 40),
		},
		"images": map[string]string{
			"nhp_cell0":                  "sha256:" + strings.Repeat("1", 64),
			"nhp_cell1":                  "sha256:" + strings.Repeat("2", 64),
			"nhp_hub":                    "sha256:" + strings.Repeat("3", 64),
			"qurl_connector":             "sha256:" + strings.Repeat("4", 64),
			"qurl_reverse_tunnel_server": "sha256:" + strings.Repeat("5", 64),
			"qurl_service_authority":     qurlServiceAuthorityImage,
			"qurl_service_cell0":         "sha256:" + strings.Repeat("7", 64),
			"qurl_service_cell1":         "sha256:" + strings.Repeat("8", 64),
		},
		"hub": map[string]any{
			"host":                     "hub.nhp.layerv.ai",
			"port":                     62206,
			"server_public_key_sha256": sha256Hex(nativeUDPProofHubKey()),
		},
		"cells": []any{
			map[string]any{"cell_id": "cell0", "host": "cell0.nhp.layerv.ai", "port": 62206, "server_public_key_sha256": strings.Repeat("0", 64)},
			map[string]any{"cell_id": "cell1", "host": "cell1.nhp.layerv.ai", "port": 62206, "server_public_key_sha256": strings.Repeat("1", 64)},
		},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mutateDeploymentManifest(t *testing.T, manifest []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(manifest, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func writeProofProvenance(t *testing.T, runnerTemp, buildSHA, agentID string) {
	t.Helper()
	writeProofProvenanceValue(t, runnerTemp, proofProvenanceValue(buildSHA, agentID))
}

func writeProofProvenanceValue(t *testing.T, runnerTemp string, value map[string]any) {
	t.Helper()
	directory := filepath.Join(runnerTemp, "qurl-go-native-udp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(directory, "provenance.json"), value)
}

func proofProvenanceValue(buildSHA, agentID string) map[string]any {
	return map[string]any{
		"schema_version": 1,
		"build_sha":      buildSHA,
		"agent_id":       agentID,
		"hub": map[string]any{
			"host":                     "hub.nhp.layerv.ai",
			"port":                     62206,
			"server_public_key_sha256": sha256Hex(nativeUDPProofHubKey()),
		},
		"assigned_cells": []any{
			proofCell("registration", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
			proofCell("warm_open", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
			proofCell("reassignment", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 2),
			proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 2),
		},
	}
}

func proofCell(phase, cellID, host, key string, generation, revision int) map[string]any {
	return map[string]any{
		"phase":                    phase,
		"cell_id":                  cellID,
		"assignment_generation":    generation,
		"endpoint_revision":        revision,
		"lease_expires_at":         "2026-07-22T12:00:00Z",
		"host":                     host,
		"port":                     62206,
		"server_public_key_sha256": key,
	}
}

func writeNativeUDPGHMock(t *testing.T) string {
	t.Helper()
	mockBin := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "api" ]]; then
  if [[ "$2" == "repos/layervai/qurl-go/pulls/93" ]]; then
    printf '{"number":%s,"state":"%s","head":{"sha":"%s","repo":{"full_name":"%s"}},"base":{"ref":"%s","repo":{"full_name":"%s"}}}\n' \
      "${MOCK_CANDIDATE_NUMBER:-93}" "${MOCK_CANDIDATE_STATE:-open}" "${MOCK_CANDIDATE_HEAD_SHA:-${GITHUB_SHA}}" \
      "${MOCK_CANDIDATE_HEAD_REPO:-layervai/qurl-go}" "${MOCK_CANDIDATE_BASE_REF:-main}" "${MOCK_CANDIDATE_BASE_REPO:-layervai/qurl-go}"
    exit 0
  fi
  if [[ "$2" == repos/layervai/*/commits/* ]]; then
    repository="${2#repos/layervai/}"
    repository="${repository%%/*}"
    test "${repository}" != "${MOCK_MISSING_REPOSITORY:-}"
    test "${2##*/}" != "${MOCK_MISSING_SHA:-}"
    if [[ "$#" == "2" ]]; then
      printf '{"sha":"%s","commit":{"verification":{"verified":%s}}}\n' "${2##*/}" "${MOCK_CANDIDATE_VERIFIED:-true}"
    else
      test "$3" = "--jq"
      test "$4" = ".sha"
      printf '%s\n' "${2##*/}"
    fi
    exit 0
  fi
  case "$2" in
    repos/layervai/qurl-go/actions/workflows/native-udp-sandbox.yml)
      test "$3" = "--jq"
      test "$4" = ".id"
      printf '%s\n' "${MOCK_WORKFLOW_ID}"
      ;;
    repos/layervai/qurl-go/actions/runs/987/artifacts*)
      printf '{"total_count":1,"artifacts":[{"id":42424,"name":"native-udp-sandbox-pre_removal-%s-3","expired":false,"size_in_bytes":%s,"digest":"sha256:%s"}]}\n' \
        "${MOCK_HEAD_SHA}" "${MOCK_PRE_ARTIFACT_SIZE}" "${MOCK_PRE_ARTIFACT_SHA256}"
      ;;
    repos/layervai/qurl-go/actions/artifacts/42424/zip)
      cat "${MOCK_PRE_ARTIFACT_ZIP}"
      ;;
    *) exit 2 ;;
  esac
  exit 0
fi
if [[ "$1 $2" == "run view" ]]; then
  test "$3" = "${MOCK_PRE_RUN_ID}"
  printf '{"attempt":3,"conclusion":"success","event":"workflow_dispatch","headSha":"%s","workflowDatabaseId":%s}\n' "${MOCK_HEAD_SHA}" "${MOCK_WORKFLOW_ID}"
  exit 0
fi
exit 2
`
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return mockBin
}

func writeQURLGoProofZIP(t *testing.T, path, evidencePath, manifestPath, inventoryPath, mutation string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := zip.NewWriter(file)
	for _, item := range []struct {
		name string
		path string
	}{
		{name: "native-udp-sandbox.evidence.json", path: evidencePath},
		{name: "sandbox-deployment-manifest.json", path: manifestPath},
		{name: "pre_retirement_scenarios.json", path: inventoryPath},
		{name: "retired_lifecycle_surface.json", path: filepath.Join(filepath.Dir(inventoryPath), "retired_lifecycle_surface.json")},
	} {
		body, err := os.ReadFile(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if (mutation == "noncanonical_evidence" && item.name == "native-udp-sandbox.evidence.json") ||
			(mutation == "noncanonical_inventory" && item.name == "pre_retirement_scenarios.json") ||
			(mutation == "noncanonical_retired_surface" && item.name == "retired_lifecycle_surface.json") {
			var indented bytes.Buffer
			if err := json.Indent(&indented, body, "", "  "); err != nil {
				t.Fatal(err)
			}
			body = indented.Bytes()
		}
		if mutation == "changed_retired_surface" && item.name == "retired_lifecycle_surface.json" {
			var surface map[string]any
			if err := json.Unmarshal(body, &surface); err != nil {
				t.Fatal(err)
			}
			surface["schema_version"] = 2
			body, err = json.Marshal(surface)
			if err != nil {
				t.Fatal(err)
			}
		}
		if mutation == "strict_failed" && item.name == "native-udp-sandbox.evidence.json" {
			var evidence map[string]any
			if err := json.Unmarshal(body, &evidence); err != nil {
				t.Fatal(err)
			}
			evidence["strict_outcome"] = "failure"
			body, err = json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
		}
		name := item.name
		if mutation == "unsafe_zip_path" && item.name == "native-udp-sandbox.evidence.json" {
			name = "../native-udp-sandbox.evidence.json"
		}
		writer, err := bundle.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if mutation == "extra_zip_file" {
		writer, err := bundle.Create("unexpected.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("not allowlisted")); err != nil {
			t.Fatal(err)
		}
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeConnectorProofZIP(t *testing.T, path string, manifest []byte, connectorSHA string, options connectorProofZIPOptions) {
	t.Helper()
	var deployment map[string]any
	if err := json.Unmarshal(manifest, &deployment); err != nil {
		t.Fatal(err)
	}
	phase := options.phase
	if phase == "" {
		phase = "pre_removal"
	}
	scenarioNames := connectorStrictScenarioNames(t)
	scenarios := make([]any, 0, len(scenarioNames)+1)
	scenarioResults := make([]any, 0, len(scenarioNames)+1)
	contractScenarios := make([]any, 0, len(scenarioNames)+1)
	for _, name := range scenarioNames {
		testName := "TestSandboxConnectorStrict/" + name
		scenario := map[string]any{
			"name":         name,
			"status":       "implemented",
			"test":         testName,
			"requires_env": []string{},
			"reason":       "Complete exact Connector proof fixture for " + name + ".",
		}
		scenarios = append(scenarios, scenario)
		contractScenarios = append(contractScenarios, map[string]any{
			"name":         scenario["name"],
			"status":       scenario["status"],
			"reason":       scenario["reason"],
			"test":         scenario["test"],
			"requires_env": scenario["requires_env"],
		})
		scenarioResults = append(scenarioResults, map[string]any{
			"test_name":       testName,
			"action":          "pass",
			"elapsed_seconds": 1.25,
		})
	}
	switch options.mutation {
	case "truncate_inventory":
		scenarios = scenarios[:len(scenarios)-1]
		contractScenarios = contractScenarios[:len(contractScenarios)-1]
		scenarioResults = scenarioResults[:len(scenarioResults)-1]
	case "duplicate_inventory":
		scenarios = append(scenarios, scenarios[0])
		contractScenarios = append(contractScenarios, contractScenarios[0])
		scenarioResults = append(scenarioResults, scenarioResults[0])
	}
	inventory := map[string]any{
		"schema":                 1,
		"gate":                   "udp_lifecycle_retirement",
		"proof_phases":           []string{"pre_removal", "post_removal"},
		"all_scenarios_required": true,
		"scenarios":              scenarios,
	}
	inventoryBytes, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if options.mutation == "noncanonical_inventory" {
		inventoryBytes, err = json.MarshalIndent(inventory, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(contractScenarios, func(i, j int) bool {
		return contractScenarios[i].(map[string]any)["name"].(string) < contractScenarios[j].(map[string]any)["name"].(string)
	})
	contractBytes, err := json.Marshal(contractScenarios)
	if err != nil {
		t.Fatal(err)
	}
	images := deployment["images"].(map[string]any)
	connectorModules := deployment["connector_modules"].(map[string]any)
	imageDigest := images["qurl_connector"].(string)
	imageReference := "ghcr.io/layervai/qurl-connector@" + imageDigest
	observations := []any{
		connectorProofObservation("registration", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
		connectorProofObservation("warm_open", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
		connectorProofObservation("reassignment", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 2),
		connectorProofObservation("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 2),
	}
	switch options.mutation {
	case "one_cell":
		observations = []any{
			connectorProofObservation("registration", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
			connectorProofObservation("warm_open", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 1, 1),
			connectorProofObservation("reassignment", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 2, 2),
			connectorProofObservation("refresh", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 2, 3),
		}
	case "wrong_cell":
		observations[len(observations)-1] = connectorProofObservation("refresh", "cell9", "cell9.nhp.layerv.ai", strings.Repeat("9", 64), 2, 3)
	case "wrong_order":
		observations[0], observations[1] = observations[1], observations[0]
	case "warm_mismatch":
		observations[1] = connectorProofObservation("warm_open", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 1)
	case "stale_generation":
		observations[2] = connectorProofObservation("reassignment", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
	case "refresh_drift":
		observations[3] = connectorProofObservation("refresh", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 2, 3)
	case "stale_refresh_generation":
		observations[3] = connectorProofObservation("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
	case "stale_refresh_revision":
		observations[3] = connectorProofObservation("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 1)
	}
	module := func(path, sha string) map[string]any {
		return map[string]any{
			"git_ref":        "v0.0.0-test",
			"git_sha":        sha,
			"path":           path,
			"requested_path": path,
			"sum":            "h1:test-proof-sum",
			"version":        "v0.0.0-test",
		}
	}
	implementedCount := len(scenarios)
	counts := map[string]int{"implemented": implementedCount, "blocking": 0, "failures": 0, "skips": 0, "exact_passes": implementedCount}
	typedEvidence := make([]any, 0, len(scenarios))
	for _, item := range scenarios {
		typedEvidence = append(typedEvidence, map[string]any{
			"scenario_key": item.(map[string]any)["name"],
			"evidence": []any{map[string]any{
				"kind":               "wire_trace",
				"observation":        map[string]any{"verified": true},
				"observation_sha256": "348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9",
			}},
		})
	}
	switch options.mutation {
	case "blocking_count":
		counts["blocking"] = 1
	case "skip_count":
		counts["skips"] = 1
	case "failure_count":
		counts["failures"] = 1
	}
	preRemovalRunID, preRemovalEvidenceSHA, preRemovalDeploymentSHA := any(nil), any(nil), any(nil)
	if phase == "post_removal" && options.mutation != "malformed_post_pairing" {
		preRemovalRunID = "456"
		preRemovalEvidenceSHA = strings.Repeat("c", 64)
		preRemovalDeploymentSHA = strings.Repeat("d", 64)
	}
	if options.mutation == "mismatched_pre_baseline" {
		preRemovalRunID = "455"
	}
	evidence := map[string]any{
		"schema_version":                 1,
		"phase":                          phase,
		"repository":                     "layervai/qurl-connector",
		"commit_sha":                     connectorSHA,
		"run_id":                         "777",
		"run_attempt":                    "2",
		"pre_removal_run_id":             preRemovalRunID,
		"pre_removal_evidence_sha256":    preRemovalEvidenceSHA,
		"pre_removal_deployment_sha256":  preRemovalDeploymentSHA,
		"deployment_manifest_sha256":     sha256Hex(manifest),
		"inventory_sha256":               sha256Hex(inventoryBytes),
		"scenario_contract_sha256":       sha256Hex(contractBytes),
		"proof_harness_sha256":           strings.Repeat("a", 64),
		"input_outcome":                  "success",
		"enforcement_outcome":            "success",
		"inputs_unchanged":               true,
		"gate_passed":                    true,
		"counts":                         counts,
		"provenance_valid":               true,
		"two_cell_provenance":            true,
		"typed_evidence_complete":        true,
		"typed_evidence":                 typedEvidence,
		"typed_evidence_contract_sha256": "27782f1b8591ef08cd08eb555c643d309ed317da69e63ade714c04489385b063",
		"provenance": map[string]any{
			"schema":    1,
			"connector": map[string]any{"git_sha": connectorSHA},
			"modules": map[string]any{
				"qurl_go": module("github.com/layervai/qurl-go", connectorModules["qurl_go"].(string)),
				"frp":     module("github.com/fatedier/frp", connectorModules["frp"].(string)),
			},
			"image": map[string]any{
				"image_id":            "sha256:" + strings.Repeat("b", 64),
				"oci_manifest_digest": imageDigest,
				"reference":           imageReference,
				"repo_digests":        []string{imageReference},
				"source_revision":     connectorSHA,
			},
			"operational": map[string]any{
				"schema_version": 1,
				"connector_sha":  connectorSHA,
				"hub":            deployment["hub"],
				"observations":   observations,
			},
		},
		"scenario_results": scenarioResults,
	}
	if options.mutation == "wrong_scenario_contract" {
		evidence["scenario_contract_sha256"] = strings.Repeat("f", 64)
	}
	provenance := evidence["provenance"].(map[string]any)
	image := provenance["image"].(map[string]any)
	modules := provenance["modules"].(map[string]any)
	switch options.mutation {
	case "wrong_image":
		image["oci_manifest_digest"] = "sha256:" + strings.Repeat("f", 64)
	case "wrong_module":
		modules["qurl_go"].(map[string]any)["git_sha"] = strings.Repeat("e", 40)
	}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := zip.NewWriter(file)
	files := []struct {
		name string
		body []byte
	}{
		{name: "sandbox-deployment-manifest.json", body: manifest},
		{name: "strict-proof-scenarios.json", body: inventoryBytes},
		{name: "strict-sandbox-proof.evidence.json", body: evidenceBytes},
	}
	if options.mutation == "extra_zip_file" {
		files = append(files, struct {
			name string
			body []byte
		}{name: "unexpected.txt", body: []byte("not allowlisted")})
	}
	for _, item := range files {
		entryName := item.name
		if options.mutation == "unsafe_zip_path" && item.name == "strict-sandbox-proof.evidence.json" {
			entryName = "../strict-sandbox-proof.evidence.json"
		}
		if options.mutation == "zip_symlink" && item.name == "strict-sandbox-proof.evidence.json" {
			header := &zip.FileHeader{Name: item.name}
			header.SetMode(os.ModeSymlink | 0o777)
			writer, err := bundle.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("sandbox-deployment-manifest.json")); err != nil {
				t.Fatal(err)
			}
			continue
		}
		writer, err := bundle.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(item.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func connectorStrictScenarioNames(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(workflowDir(t), "..", "..", "tests", "e2e", "nativeudp", "connector_strict_scenario_names.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contract, digest, err := normalizedConnectorScenarioNameContract(raw)
	if err != nil {
		t.Fatal(err)
	}
	if digest != reviewedConnectorScenarioNamesSHA256 {
		t.Fatalf("Connector scenario-name contract digest = %s, want %s", digest, reviewedConnectorScenarioNamesSHA256)
	}
	if contract.SchemaVersion != 1 || contract.Gate != "udp_lifecycle_retirement" || len(contract.ScenarioNames) != 60 {
		t.Fatalf("invalid Connector scenario-name contract: schema=%d gate=%q names=%d", contract.SchemaVersion, contract.Gate, len(contract.ScenarioNames))
	}
	if !sort.StringsAreSorted(contract.ScenarioNames) {
		t.Fatal("Connector scenario-name contract must be sorted")
	}
	for index := 1; index < len(contract.ScenarioNames); index++ {
		if contract.ScenarioNames[index] == contract.ScenarioNames[index-1] {
			t.Fatalf("duplicate Connector scenario name: %q", contract.ScenarioNames[index])
		}
	}
	return contract.ScenarioNames
}

func TestNormalizedConnectorScenarioNameContractIgnoresObjectKeyOrder(t *testing.T) {
	first := []byte(`{"schema_version":1,"gate":"udp_lifecycle_retirement","scenario_names":["alpha","beta"]}`)
	second := []byte(`{"scenario_names":["alpha","beta"],"schema_version":1,"gate":"udp_lifecycle_retirement"}`)
	_, firstDigest, err := normalizedConnectorScenarioNameContract(first)
	if err != nil {
		t.Fatal(err)
	}
	_, secondDigest, err := normalizedConnectorScenarioNameContract(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("semantic-equivalent contract digests differ: %s != %s", firstDigest, secondDigest)
	}
}

func TestNormalizedConnectorScenarioNameContractRejectsAmbiguousJSON(t *testing.T) {
	tests := map[string][]byte{
		"duplicate key": []byte(`{"schema_version":0,"schema_version":1,"gate":"udp_lifecycle_retirement","scenario_names":[]}`),
		"unknown key":   []byte(`{"schema_version":1,"gate":"udp_lifecycle_retirement","scenario_names":[],"extra":true}`),
		"trailing value": []byte(
			`{"schema_version":1,"gate":"udp_lifecycle_retirement","scenario_names":[]} {}`,
		),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := normalizedConnectorScenarioNameContract(raw); err == nil {
				t.Fatal("ambiguous Connector scenario-name contract unexpectedly passed")
			}
		})
	}
}

func normalizedConnectorScenarioNameContract(raw []byte) (connectorScenarioNameContract, string, error) {
	var contract connectorScenarioNameContract
	if err := rejectDuplicateTopLevelJSONKeys(raw); err != nil {
		return contract, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return contract, "", err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return contract, "", fmt.Errorf("Connector scenario-name contract must contain exactly one JSON value")
		}
		return contract, "", fmt.Errorf("Connector scenario-name contract must contain exactly one JSON value: %w", err)
	}
	normalized, err := json.Marshal(contract)
	if err != nil {
		return contract, "", err
	}
	digest := sha256.Sum256(normalized)
	return contract, fmt.Sprintf("%x", digest), nil
}

func rejectDuplicateTopLevelJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("Connector scenario-name contract must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("Connector scenario-name contract key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("Connector scenario-name contract contains duplicate key %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("Connector scenario-name contract object is not closed")
	}
	return nil
}

func connectorProofObservation(phase, cellID, host, key string, generation, revision int) map[string]any {
	return map[string]any{
		"phase":                    phase,
		"cell_id":                  cellID,
		"assignment_generation":    generation,
		"endpoint_revision":        revision,
		"lease_expires_at":         "2026-07-22T12:00:00Z",
		"host":                     host,
		"port":                     62206,
		"server_public_key_sha256": key,
	}
}

func writeConnectorProofGHMock(t *testing.T) string {
	t.Helper()
	mockBin := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
test "$1" = "api"
case "$2" in
  repos/layervai/qurl-connector/pulls/452)
    printf '{"number":%s,"state":"%s","head":{"sha":"%s","repo":{"full_name":"%s"}},"base":{"ref":"%s","repo":{"full_name":"%s"}}}\n' \
      "${MOCK_CONNECTOR_CANDIDATE_NUMBER:-452}" "${MOCK_CONNECTOR_CANDIDATE_STATE:-open}" \
      "${MOCK_CONNECTOR_CANDIDATE_HEAD_SHA:-${MOCK_CONNECTOR_HEAD_SHA}}" \
      "${MOCK_CONNECTOR_CANDIDATE_HEAD_REPO:-layervai/qurl-connector}" "${MOCK_CONNECTOR_CANDIDATE_BASE_REF:-main}" \
      "${MOCK_CONNECTOR_CANDIDATE_BASE_REPO:-layervai/qurl-connector}"
    ;;
  repos/layervai/qurl-connector/commits/*)
    printf '{"sha":"%s","commit":{"verification":{"verified":%s}}}\n' \
      "${2##*/}" "${MOCK_CONNECTOR_CANDIDATE_VERIFIED:-true}"
    ;;
  repos/layervai/qurl-connector/actions/workflows/sandbox-smoke.yml)
    printf '{"id":%s,"path":".github/workflows/sandbox-smoke.yml"}\n' "${MOCK_CONNECTOR_WORKFLOW_ID}"
    ;;
  repos/layervai/qurl-connector/actions/runs/777)
    printf '{"id":777,"workflow_id":%s,"event":"workflow_dispatch","conclusion":"success","head_sha":"%s","run_attempt":2,"html_url":"https://github.com/layervai/qurl-connector/actions/runs/777"}\n' \
      "${MOCK_CONNECTOR_RUN_WORKFLOW_ID}" "${MOCK_CONNECTOR_HEAD_SHA}"
    ;;
  repos/layervai/qurl-connector/actions/runs/777/artifacts*)
    printf '{"total_count":1,"artifacts":[{"id":31337,"name":"strict-sandbox-proof-%s-%s-2","expired":false,"size_in_bytes":%s,"digest":"sha256:%s"}]}\n' \
      "${MOCK_CONNECTOR_PHASE}" "${MOCK_CONNECTOR_HEAD_SHA}" "${MOCK_CONNECTOR_ARTIFACT_SIZE}" "${MOCK_CONNECTOR_ARTIFACT_SHA256}"
    ;;
  repos/layervai/qurl-connector/actions/artifacts/31337/zip)
    cat "${MOCK_CONNECTOR_ARTIFACT_ZIP}"
    ;;
  *)
    exit 2
    ;;
esac
`
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return mockBin
}

func runProofHarness(t *testing.T, repository string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "bash", "-c", `
set -euo pipefail
mapfile -d '' -t proof_files < <(
  {
    printf '%s\0' \
      .github/workflows/native-udp-sandbox.yml \
      internal/workflowcontract/native_udp_sandbox_workflow_test.go
    find tests/e2e/nativeudp -type f \( -name '*.go' -o -name '*.json' -o -name '*.py' \) -print0
  } | sort -z -u
)
{
  printf 'qurl-go-native-udp-proof-harness-v1\n'
  for proof_file in "${proof_files[@]}"; do
    printf '%s  %s\n' "$(sha256sum "${proof_file}" | cut -d' ' -f1)" "${proof_file}"
  done
} | sha256sum | cut -d' ' -f1
`)
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("hash native UDP proof harness: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func nativeUDPProofHubKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest)
}
