package workflowcontract

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nativeUDPWorkflowID                   = "4242"
	reviewedInventoryMappingSHA256Fixture = "2f974c2a8815a1d949b815a14b05fc157973778b255c66abb66e9588cc42b0d2"
)

type nativeUDPProofFixture struct {
	repository string
	preSHA     string
	postSHA    string
}

func TestNativeUDPSandboxWorkflowIsAttendedStrictAndEvidenceBearing(t *testing.T) {
	workflow := readWorkflow(t, "native-udp-sandbox.yml")

	requireContains(t, workflow,
		"run-name: UDP proof [corr:${{ inputs.dispatch_correlation_id }}]",
		"workflow_dispatch:",
		"dispatch_correlation_id:",
		"proof_phase:",
		"deployment_manifest_b64:",
		"deployment_runtime_inputs_b64:",
		"deployment_producer_run_id:",
		"deployment_producer_run_attempt:",
		"deployment_producer_head_sha:",
		"deployment_artifact_id:",
		"deployment_artifact_digest:",
		"nhp_controller_run_id:",
		"nhp_controller_run_attempt:",
		"pre_removal_run_id:",
		"- pre_removal",
		"- post_removal",
		"environment: sandbox",
		"runs-on:\n      group: udp-proof-sandbox\n      labels: run-${{ inputs.nhp_controller_run_id }}-attempt-${{ inputs.nhp_controller_run_attempt }}",
		"permissions:\n  actions: read\n  contents: read",
		"QURL_GO_SANDBOX_STRICT: \"true\"",
		"QURL_GO_SANDBOX_EXPECTED_SHA: ${{ github.sha }}",
		"QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID: ${{ inputs.dispatch_correlation_id }}",
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID: ${{ inputs.nhp_controller_run_id }}",
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT: ${{ inputs.nhp_controller_run_attempt }}",
		"QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL: ${{ secrets.QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL }}",
		"Mint read-only proof-attestation token",
		"actions/create-github-app-token@",
		"permission-actions: read",
		"permission-contents: read",
		"permission-pull-requests: read",
		"            frp\n            nhp\n            qurl-go\n            qurl-integrations\n            qurl-mcp\n            qurl-python\n            qurl-reverse-tunnel-server\n            qurl-service\n            qurl-typescript\n            website",
		"test \"$(git rev-parse HEAD)\" = \"${QURL_GO_SANDBOX_EXPECTED_SHA}\"",
		"test -z \"$(git status --short)\"",
		`[[ ! "${QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID}" =~ ^[1-9][0-9]{0,19}$ ]]`,
		`[[ ! "${QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT}" =~ ^[1-9][0-9]{0,9}$ ]]`,
		"invalid NHP controller run identity",
		"invalid dispatch correlation id",
		"-qurl_go-${QURL_GO_SANDBOX_PROOF_PHASE}-[0-9a-f]{32}$",
		"canonicalize_json()",
		"reject_duplicate_keys",
		".qurl_go == $qurl_go_sha",
		`(keys | sort) == ["frp", "qurl_go"]`,
		`.frp == $root.repositories.frp`,
		`actual_sha="$(gh api "repos/layervai/${repository}/commits/${expected_sha}" --jq '.sha')"`,
		"website\twebsite",
		`gh api "repos/${GITHUB_REPOSITORY}/pulls/93"`,
		`.head.sha == $sha`,
		`.base.ref == "main"`,
		`.commit.verification.verified == true`,
		"QURL_GO_SANDBOX_CANDIDATE_PR_PATH=${candidate_pr}",
		"QURL_GO_SANDBOX_CANDIDATE_COMMIT_PATH=${candidate_commit}",
		"QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256",
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256",
		"retired_lifecycle_surface.json",
		`type == "number" and isfinite and . == floor and . >= 1 and . <= 9007199254740991`,
		"compute_proof_harness_sha256()",
		"QURL_GO_SANDBOX_INVENTORY_SHA256",
		"QURL_GO_SANDBOX_PROOF_HARNESS_SHA256",
		"pre_removal|post_removal",
		"Verify exact proof inputs",
		"Download authenticated deployment-producer evidence",
		"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
		"artifact-ids: ${{ inputs.deployment_artifact_id }}",
		"repository: layervai/nhp",
		"run-id: ${{ inputs.deployment_producer_run_id }}",
		"github-token: ${{ steps.proof-token.outputs.token }}",
		"path: ${{ runner.temp }}/deployment-producer-artifact",
		"digest-mismatch: error",
		"Materialize authenticated orchestrator evidence",
		`"deployment-manifest.json"`,
		`"deployment-provenance.json"`,
		`"deployment-runtime-inputs.json"`,
		`"orchestrator-evidence.json"`,
		"deployment producer artifact file set drift",
		`cmp -- "${producer_dir}/deployment-manifest.json" "${RUNNER_TEMP}/sandbox-deployment-manifest.json"`,
		`cmp -- "${producer_dir}/deployment-runtime-inputs.json" "${RUNNER_TEMP}/deployment-runtime-inputs.json"`,
		"QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH",
		"QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256",
		`QURL_GO_SANDBOX_NHP_SOURCE_SHA=$(jq -r '.repositories.nhp' "${manifest}")`,
		`[[ "$(jq -r '.repositories.nhp' "${deployment}")" == "${QURL_GO_SANDBOX_NHP_SOURCE_SHA}" ]]`,
		`[[ "${QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH:-}" == "${orchestrator_evidence_path}" ]]`,
		`[[ "$(sha256sum "${orchestrator_evidence_path}" | cut -d' ' -f1)" == "${QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256}" ]]`,
		"base64 --decode",
		"decode_canonical_base64()",
		"validate_runtime_inputs()",
		"deployment_runtime_inputs_sha256",
		`repos/layervai/nhp/actions/runs/${QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ID}`,
		`repos/layervai/nhp/actions/artifacts/${QURL_GO_SANDBOX_DEPLOYMENT_ARTIFACT_ID}`,
		`workflow_path: ".github/workflows/udp-proof-deployment-manifest.yml"`,
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
		"TestSandboxNativeUDPLifecycle|TestSandboxWireEvidence|TestSandboxTopology",
		"Enforce qurl-go scenario evidence",
		"pre_retirement_scenarios.json",
		".all_scenarios_required",
		"select(.status == \"implemented\")",
		".Action == \"pass\"",
		".Action == \"skip\"",
		"select(.status != \"implemented\")",
		"qurl-go-owned native UDP scenarios remain unproven",
		"Build allowlisted evidence manifest",
		"native-udp-sandbox.raw.json",
		"native-udp-sandbox.evidence.json",
		"deployment_manifest_sha256",
		"inventory_sha256",
		"scenario_contract_sha256",
		"proof_harness_sha256",
		"nhp_controller_run_id",
		"nhp_controller_run_attempt",
		"dispatch_correlation_id",
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
		"Require complete qurl-go proof publication",
		"Remove credential state",
	)
	requireContains(t, workflow, "          qurl_typescript\tqurl-typescript\n          website\twebsite\n          REPOSITORIES")
	requireNotContains(t, workflow,
		"schedule:",
		"pull_request:",
		"pull_request_target:",
		"push:",
		"repository_dispatch:",
		"workflow_call:",
		"continue-on-error:",
		"runs-on: ubuntu-latest",
		"labels: self-hosted",
		"QURL_GO_SANDBOX_ATTESTATION_TOKEN",
		"connector_proof_run_id",
		"connector_attestation_sha256",
		"QURL_GO_SANDBOX_CONNECTOR_PROOF_RUN_ID",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_PATH",
		"QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256",
		"Attest exact same-phase Connector proof",
		"${{ vars.QURL_GO_SANDBOX_HUB_HOST }}",
		"${{ vars.QURL_GO_SANDBOX_HUB_PORT }}",
		"${{ vars.QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64 }}",
		" | tee ",
		"test \"${pre_head_sha}\" = \"${GITHUB_SHA}\"",
		"pre_protected=\"$(jq -cS '{repositories: {frp: .repositories.frp, qurl_connector: .repositories.qurl_connector, qurl_go:",
	)
	requireBefore(t, workflow,
		"Mint read-only proof-attestation token",
		"Verify exact proof inputs",
		"Download authenticated deployment-producer evidence",
		"Materialize authenticated orchestrator evidence",
		"Validate exact retirement inventory",
		"Run strict direct UDP proof",
		"Enforce qurl-go scenario evidence",
		"Build allowlisted evidence manifest",
		"Upload non-secret JSON evidence",
		"Require complete qurl-go proof publication",
		"Remove credential state",
	)
	if got := strings.Count(workflow, "def valid_counter:"); got != 2 {
		t.Fatalf("valid_counter definition count = %d, want 2", got)
	}
	if got := strings.Count(workflow, "permissions:"); got != 1 {
		t.Fatalf("permissions boundary count = %d, want one exact read-only workflow boundary", got)
	}
}

func TestNativeUDPOrchestratorEvidenceMaterializationFailsClosed(t *testing.T) {
	script := stepRun(t, readWorkflow(t, "native-udp-sandbox.yml"), "Materialize authenticated orchestrator evidence")
	createArtifact := func(t *testing.T) (string, string) {
		t.Helper()
		runnerTemp := t.TempDir()
		producerDir := filepath.Join(runnerTemp, "deployment-producer-artifact")
		if err := os.Mkdir(producerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{
			"deployment-manifest.json":       []byte("{}"),
			"deployment-provenance.json":     []byte("{}"),
			"deployment-runtime-inputs.json": []byte("{}"),
			"orchestrator-evidence.json":     []byte(`{"schema_version":1}`),
		}
		for name, contents := range files {
			if err := os.WriteFile(filepath.Join(producerDir, name), contents, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(runnerTemp, "sandbox-deployment-manifest.json"), files["deployment-manifest.json"], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runnerTemp, "deployment-runtime-inputs.json"), files["deployment-runtime-inputs.json"], 0o600); err != nil {
			t.Fatal(err)
		}
		return runnerTemp, producerDir
	}

	t.Run("exact artifact", func(t *testing.T) {
		runnerTemp, producerDir := createArtifact(t)
		githubEnv := filepath.Join(runnerTemp, "github.env")
		runScript(t, t.TempDir(), script, map[string]string{
			"RUNNER_TEMP": runnerTemp,
			"GITHUB_ENV":  githubEnv,
		}, true)
		evidencePath := filepath.Join(producerDir, "orchestrator-evidence.json")
		outputs := readStepOutputs(t, githubEnv)
		if outputs["QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH"] != evidencePath {
			t.Fatalf("orchestrator evidence path = %q, want %q",
				outputs["QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH"], evidencePath)
		}
		raw, err := os.ReadFile(evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if got, want := outputs["QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256"], fmt.Sprintf("%x", digest); got != want {
			t.Fatalf("orchestrator evidence digest = %q, want %q", got, want)
		}
		info, err := os.Stat(evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("orchestrator evidence mode = %o, want 444", info.Mode().Perm())
		}
	})

	tests := map[string]func(t *testing.T, producerDir string){
		"missing file": func(t *testing.T, producerDir string) {
			if err := os.Remove(filepath.Join(producerDir, "deployment-provenance.json")); err != nil {
				t.Fatal(err)
			}
		},
		"extra file": func(t *testing.T, producerDir string) {
			if err := os.WriteFile(filepath.Join(producerDir, "unexpected.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"manifest mismatch": func(t *testing.T, producerDir string) {
			if err := os.WriteFile(filepath.Join(producerDir, "deployment-manifest.json"), []byte(`{"drift":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"orchestrator symlink": func(t *testing.T, producerDir string) {
			path := filepath.Join(producerDir, "orchestrator-evidence.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "evidence.json")
			if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"empty orchestrator evidence": func(t *testing.T, producerDir string) {
			if err := os.WriteFile(filepath.Join(producerDir, "orchestrator-evidence.json"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized orchestrator evidence": func(t *testing.T, producerDir string) {
			if err := os.WriteFile(
				filepath.Join(producerDir, "orchestrator-evidence.json"),
				bytes.Repeat([]byte("x"), 64*1024+1),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runnerTemp, producerDir := createArtifact(t)
			mutate(t, producerDir)
			runScript(t, t.TempDir(), script, map[string]string{
				"RUNNER_TEMP": runnerTemp,
				"GITHUB_ENV":  filepath.Join(runnerTemp, "github.env"),
			}, false)
		})
	}
}

func TestNativeUDPSandboxRejectsMalformedNHPControllerRunIdentity(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	tests := []struct {
		name       string
		runID      string
		runAttempt string
	}{
		{name: "missing run id", runID: "", runAttempt: "1"},
		{name: "zero run id", runID: "0", runAttempt: "1"},
		{name: "leading-zero run id", runID: "01", runAttempt: "1"},
		{name: "non-numeric run id", runID: "run-1", runAttempt: "1"},
		{name: "oversized run id", runID: strings.Repeat("1", 21), runAttempt: "1"},
		{name: "missing run attempt", runID: "1234", runAttempt: ""},
		{name: "zero run attempt", runID: "1234", runAttempt: "0"},
		{name: "leading-zero run attempt", runID: "1234", runAttempt: "01"},
		{name: "non-numeric run attempt", runID: "1234", runAttempt: "rerun"},
		{name: "oversized run attempt", runID: "1234", runAttempt: strings.Repeat("1", 11)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyNativeUDPManifest(
				t,
				fixture,
				fixture.postSHA,
				t.TempDir(),
				"pre_removal",
				"",
				manifest,
				map[string]string{
					"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID":      test.runID,
					"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT": test.runAttempt,
				},
				false,
			)
		})
	}
}

func TestNativeUDPSandboxRejectsMalformedDispatchCorrelationID(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	tests := []string{
		"",
		"nhp-123456-1-qurl_go-pre_removal",
		"nhp-123456-1-qurl_go-pre_removal-" + strings.Repeat("a", 31),
		"nhp-123456-1-qurl_go-pre_removal-" + strings.Repeat("a", 33),
		"nhp-123456-1-qurl_go-pre_removal-" + strings.Repeat("A", 32),
		"nhp-123456-2-qurl_go-pre_removal-" + strings.Repeat("a", 32),
		"nhp-123456-1-connector-pre_removal-" + strings.Repeat("a", 32),
		"nhp-123456-1-qurl_go-post_removal-" + strings.Repeat("a", 32),
	}
	for _, correlationID := range tests {
		t.Run(correlationID, func(t *testing.T) {
			verifyNativeUDPManifest(
				t,
				fixture,
				fixture.postSHA,
				t.TempDir(),
				"pre_removal",
				"",
				manifest,
				map[string]string{
					"QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID": correlationID,
				},
				false,
			)
		})
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

	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Enforce qurl-go scenario evidence")
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
				stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Enforce qurl-go scenario evidence"),
				proofHashEnvironment(runnerTemp, inputs), false)

			agentID := "qurl-go-sandbox-nested-1"
			writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID, inputs)
			environment := proofHashEnvironment(runnerTemp, inputs)
			for key, value := range map[string]string{
				"GITHUB_REPOSITORY":                  "layervai/qurl-go",
				"GITHUB_SHA":                         fixture.postSHA,
				"GITHUB_RUN_ID":                      "7654",
				"GITHUB_RUN_ATTEMPT":                 "1",
				"QURL_GO_SANDBOX_AGENT_ID":           agentID,
				"QURL_GO_SANDBOX_PROOF_PHASE":        "pre_removal",
				"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID": "",
				"STRICT_OUTCOME":                     "success",
				"ENFORCEMENT_OUTCOME":                "failure",
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
			Status   string `json:"status"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(inventory.Scenarios))
	for _, scenario := range inventory.Scenarios {
		if scenario.Status == "implemented" {
			names = append(names, scenario.TestName)
		}
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
	runtime := deploymentRuntimeInputsBytes(t, manifest)
	publishedRuntime, err := os.ReadFile(filepath.Join(runnerTemp, "deployment-runtime-inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedRuntime, runtime) {
		t.Fatalf("published runtime sidecar is not the canonical submitted sidecar:\n got %s\nwant %s", publishedRuntime, runtime)
	}
	if outputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"] != sha256Hex(runtime) {
		t.Fatalf("runtime sidecar hash = %q, want %q", outputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"], sha256Hex(runtime))
	}
	if info, err := os.Stat(filepath.Join(runnerTemp, "deployment-runtime-inputs.json")); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o444 {
		t.Fatalf("runtime sidecar mode = %o, want 444", info.Mode().Perm())
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

func TestNativeUDPSandboxRejectsUnboundRuntimeAndProducerInputs(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	validRuntime := deploymentRuntimeInputsBytes(t, manifest)

	mutateRuntime := func(mutate func(map[string]any)) string {
		t.Helper()
		var runtime map[string]any
		if err := json.Unmarshal(validRuntime, &runtime); err != nil {
			t.Fatal(err)
		}
		mutate(runtime)
		encoded, err := json.Marshal(runtime)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(encoded)
	}

	tests := map[string]map[string]string{
		"noncanonical runtime JSON": {
			"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_B64": base64.StdEncoding.EncodeToString(append(validRuntime, '\n')),
		},
		"runtime Hub key does not match manifest": {
			"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_B64": mutateRuntime(func(runtime map[string]any) {
				runtime["hub"].(map[string]any)["server_public_key_b64"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
			}),
		},
		"runtime cell order differs from producer": {
			"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_B64": mutateRuntime(func(runtime map[string]any) {
				cells := runtime["cells"].([]any)
				cells[0], cells[1] = cells[1], cells[0]
			}),
		},
		"producer run metadata does not match dispatch": {
			"MOCK_PRODUCER_HEAD_SHA": strings.Repeat("f", 40),
		},
		"noncanonical runtime base64": {
			"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_B64": base64.StdEncoding.EncodeToString(validRuntime) + "\n",
		},
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			verifyNativeUDPManifest(
				t, fixture, fixture.postSHA, t.TempDir(), "pre_removal", "",
				manifest, extra, false,
			)
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
		map[string]string{"MOCK_MISSING_SHA": fixture.postSHA},
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
		mutateEvidence func(map[string]any)
	}{
		{name: "extra archive file", mutation: "extra_zip_file"},
		{name: "unsafe archive path", mutation: "unsafe_zip_path"},
		{name: "noncanonical evidence", mutation: "noncanonical_evidence"},
		{name: "noncanonical inventory", mutation: "noncanonical_inventory"},
		{name: "noncanonical retired lifecycle surface", mutation: "noncanonical_retired_surface"},
		{name: "changed retired lifecycle surface", mutation: "changed_retired_surface"},
		{name: "pre-removal strict step failed", mutation: "strict_failed"},
		{name: "pre-removal provenance schema is stale", mutateEvidence: func(value map[string]any) {
			value["provenance"].(map[string]any)["schema_version"] = 1
		}},
		{name: "pre-removal provenance deployment digest mismatches", mutateEvidence: func(value map[string]any) {
			value["provenance"].(map[string]any)["deployment_manifest_sha256"] = strings.Repeat("f", 64)
		}},
		{name: "pre-removal provenance typed contract digest mismatches", mutateEvidence: func(value map[string]any) {
			value["provenance"].(map[string]any)["typed_evidence_contract_sha256"] = strings.Repeat("f", 64)
		}},
		{name: "pre-removal dispatch correlation mismatches", mutateEvidence: func(value map[string]any) {
			value["dispatch_correlation_id"] = nativeUDPDispatchCorrelation("wrong_client", "pre_removal")
		}},
		{name: "pre-removal controller identity mismatches correlation", mutateEvidence: func(value map[string]any) {
			value["nhp_controller_run_attempt"] = "2"
		}},
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
			evidence := validPreRemovalEvidence(t, fixture.preSHA, preOutputs)
			if test.mutateEvidence != nil {
				test.mutateEvidence(evidence)
			}
			writeJSONFile(t, preEvidence, evidence)
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
			Status   string `json:"status"`
			TestName string `json:"test_name"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	scenarioResults := make([]any, 0, len(inventory.Scenarios))
	typedEvidence := make([]any, 0, len(inventory.Scenarios))
	implemented := 0
	for _, scenario := range inventory.Scenarios {
		evidence := []any{}
		if scenario.Status == "implemented" {
			implemented++
			scenarioResults = append(scenarioResults, map[string]any{
				"test_name":       scenario.TestName,
				"action":          "pass",
				"elapsed_seconds": 1.0,
			})
			evidence = []any{map[string]any{
				"kind":               "wire_trace",
				"observation":        map[string]any{"verified": true},
				"observation_sha256": "348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9",
			}}
		}
		typedEvidence = append(typedEvidence, map[string]any{
			"scenario_key": scenario.ID,
			"evidence":     evidence,
		})
	}
	return map[string]any{
		"schema_version":                   1,
		"phase":                            "pre_removal",
		"repository":                       "layervai/qurl-go",
		"commit_sha":                       commitSHA,
		"run_id":                           "987",
		"run_attempt":                      "3",
		"dispatch_correlation_id":          nativeUDPDispatchCorrelation("qurl_go", "pre_removal"),
		"nhp_controller_run_id":            "123456",
		"nhp_controller_run_attempt":       "1",
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
		"deployment_runtime_inputs_sha256": outputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"],
		"deployment_producer": map[string]any{
			"repository":      "layervai/nhp",
			"workflow_path":   ".github/workflows/udp-proof-deployment-manifest.yml",
			"run_id":          "987654",
			"run_attempt":     "1",
			"head_sha":        strings.Repeat("c", 40),
			"artifact_id":     "7654321",
			"artifact_digest": "sha256:" + strings.Repeat("d", 64),
		},
		"inventory_sha256":                 outputs["QURL_GO_SANDBOX_INVENTORY_SHA256"],
		"inventory_mapping_sha256":         outputs["QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256"],
		"scenario_contract_sha256":         outputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"],
		"retired_lifecycle_surface_sha256": outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256"],
		"typed_evidence_contract_sha256":   outputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
		"proof_harness_sha256":             outputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
		"strict_outcome":                   "success",
		"counts":                           map[string]int{"implemented": implemented, "blocking": len(inventory.Scenarios) - implemented, "failures": 0, "skips": 0, "exact_passes": implemented},
		"provenance": proofProvenanceValue(
			commitSHA,
			"qurl-go-sandbox-pre-proof",
			outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
			outputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
		),
		"scenario_results": scenarioResults,
	}
}

func TestNativeUDPSandboxEvidenceManifestIsAllowlisted(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	runnerTemp := t.TempDir()
	manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
	inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
	agentID := "qurl-go-sandbox-1234-2"
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID, inputs)

	rawPath := filepath.Join(runnerTemp, "native-udp-sandbox.raw.json")
	const reflectedSecret = "server-minted-enrollment-secret-must-not-upload"
	raw := []byte(`{"Action":"output","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure","Output":"` + reflectedSecret + `\n"}` + "\n" +
		`{"Action":"pass","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure","Elapsed":0.25}` + "\n")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Build allowlisted evidence manifest")
	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                  "layervai/qurl-go",
		"GITHUB_SHA":                         fixture.postSHA,
		"GITHUB_RUN_ID":                      "1234",
		"GITHUB_RUN_ATTEMPT":                 "2",
		"QURL_GO_SANDBOX_AGENT_ID":           agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":        "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID": "",
		"STRICT_OUTCOME":                     "success",
		"ENFORCEMENT_OUTCOME":                "failure",
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
		"phase":                            "pre_removal",
		"repository":                       "layervai/qurl-go",
		"commit_sha":                       fixture.postSHA,
		"deployment_manifest_sha256":       sha256Hex(manifest),
		"deployment_runtime_inputs_sha256": inputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"],
		"proof_harness_sha256":             inputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
		"strict_outcome":                   "success",
		"inputs_unchanged":                 true,
		"gate_passed":                      false,
		"dispatch_correlation_id":          nativeUDPDispatchCorrelation("qurl_go", "pre_removal"),
		"nhp_controller_run_id":            "123456",
		"nhp_controller_run_attempt":       "1",
		"provenance_valid":                 true,
		"two_cell_provenance":              true,
	} {
		if got := decoded[name]; got != want {
			t.Errorf("evidence %s = %v, want %v", name, got, want)
		}
	}
	producer, ok := decoded["deployment_producer"].(map[string]any)
	if !ok ||
		producer["repository"] != "layervai/nhp" ||
		producer["workflow_path"] != ".github/workflows/udp-proof-deployment-manifest.yml" ||
		producer["run_id"] != "987654" ||
		producer["run_attempt"] != "1" ||
		producer["head_sha"] != strings.Repeat("c", 40) ||
		producer["artifact_id"] != "7654321" ||
		producer["artifact_digest"] != "sha256:"+strings.Repeat("d", 64) {
		t.Fatalf("evidence deployment producer = %v", decoded["deployment_producer"])
	}
	counts := decoded["counts"].(map[string]any)
	if counts["blocking"] != float64(36) {
		t.Fatalf("evidence blocking count = %v, want 36", counts["blocking"])
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
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID, inputs)

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
	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                  "layervai/qurl-go",
		"GITHUB_SHA":                         fixture.postSHA,
		"GITHUB_RUN_ID":                      "4321",
		"GITHUB_RUN_ATTEMPT":                 "1",
		"QURL_GO_SANDBOX_AGENT_ID":           agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":        "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID": "",
		"STRICT_OUTCOME":                     "success",
		"ENFORCEMENT_OUTCOME":                "success",
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
	writeProofProvenance(t, runnerTemp, fixture.postSHA, agentID, inputs)
	environment := proofHashEnvironment(runnerTemp, inputs)
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY":                  "layervai/qurl-go",
		"GITHUB_SHA":                         fixture.postSHA,
		"GITHUB_RUN_ID":                      "1111",
		"GITHUB_RUN_ATTEMPT":                 "1",
		"QURL_GO_SANDBOX_AGENT_ID":           agentID,
		"QURL_GO_SANDBOX_PROOF_PHASE":        "pre_removal",
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID": "",
		"STRICT_OUTCOME":                     "failure",
		"ENFORCEMENT_OUTCOME":                "success",
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
		counts["blocking"] != float64(22) || counts["exact_passes"] != counts["implemented"] ||
		evidence["provenance_valid"] != true || evidence["two_cell_provenance"] != true {
		t.Fatalf("strict-step failure was not independently bound fail-closed: %v", evidence)
	}
}

func TestNativeUDPSandboxOperationalProvenanceRequiresExactTransition(t *testing.T) {
	fixture := newNativeUDPProofFixture(t)
	cells := func(provenance map[string]any) []any {
		return provenance["assigned_cells"].([]any)
	}
	tests := map[string]func(map[string]any){
		"wrong phase order": func(provenance map[string]any) {
			observations := cells(provenance)
			observations[0], observations[1] = observations[1], observations[0]
		},
		"warm tuple drift": func(provenance map[string]any) {
			cells := cells(provenance)
			cells[1] = proofCell("warm_open", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 1)
		},
		"stale reassignment generation": func(provenance map[string]any) {
			cells := cells(provenance)
			cells[2] = proofCell("reassignment", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
		},
		"refresh tuple drift": func(provenance map[string]any) {
			cells := cells(provenance)
			cells[3] = proofCell("refresh", "cell0", "cell0.nhp.layerv.ai", strings.Repeat("0", 64), 2, 3)
		},
		"stale refresh generation": func(provenance map[string]any) {
			cells := cells(provenance)
			cells[3] = proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 1, 2)
		},
		"stale refresh revision": func(provenance map[string]any) {
			cells := cells(provenance)
			cells[3] = proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", strings.Repeat("1", 64), 2, 1)
		},
		"regressed refresh lease": func(provenance map[string]any) {
			cells(provenance)[3].(map[string]any)["lease_expires_at"] = "2026-07-22T11:59:59.999999999Z"
		},
		"invalid calendar refresh lease": func(provenance map[string]any) {
			cells(provenance)[3].(map[string]any)["lease_expires_at"] = "2026-02-31T12:30:00Z"
		},
		"wrong deployment digest": func(provenance map[string]any) {
			provenance["deployment_manifest_sha256"] = strings.Repeat("f", 64)
		},
		"wrong typed contract digest": func(provenance map[string]any) {
			provenance["typed_evidence_contract_sha256"] = strings.Repeat("f", 64)
		},
		"legacy provenance schema": func(provenance map[string]any) {
			provenance["schema_version"] = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			manifest := deploymentManifestBytes(t, "pre_removal", fixture.postSHA)
			inputs := verifyNativeUDPManifest(t, fixture, fixture.postSHA, runnerTemp, "pre_removal", "", manifest, nil, true)
			agentID := "qurl-go-sandbox-transition-1"
			provenance := proofProvenanceValue(
				fixture.postSHA,
				agentID,
				inputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
				inputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
			)
			mutate(provenance)
			writeProofProvenanceValue(t, runnerTemp, provenance)
			if err := os.WriteFile(filepath.Join(runnerTemp, "native-udp-sandbox.raw.json"),
				[]byte(`{"Action":"pass","Test":"TestSandboxNativeUDPLifecycle/hub_dns_failure"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			environment := proofHashEnvironment(runnerTemp, inputs)
			for key, value := range map[string]string{
				"GITHUB_REPOSITORY":                  "layervai/qurl-go",
				"GITHUB_SHA":                         fixture.postSHA,
				"GITHUB_RUN_ID":                      "8765",
				"GITHUB_RUN_ATTEMPT":                 "1",
				"QURL_GO_SANDBOX_AGENT_ID":           agentID,
				"QURL_GO_SANDBOX_PROOF_PHASE":        "pre_removal",
				"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID": "",
				"STRICT_OUTCOME":                     "success",
				"ENFORCEMENT_OUTCOME":                "failure",
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
	raw, err := os.ReadFile(filepath.Join(workflowDir(t), "..", "..", "tests", "e2e", "nativeudp", "pre_retirement_scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory map[string]any
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	typedEvidence := make([]any, 0, 68)
	implemented := 0
	for _, value := range inventory["scenarios"].([]any) {
		scenario := value.(map[string]any)
		evidence := []any{}
		if scenario["owner"] == "qurl-go" {
			scenario["status"] = "implemented"
			implemented++
			evidence = []any{map[string]any{
				"kind":               "wire_trace",
				"observation":        map[string]any{"verified": true},
				"observation_sha256": "348f299cf43d57826c76c5ef7c8ccc37668b45161b857d4ef09f7125f3381be9",
			}}
		} else {
			scenario["status"] = "external_dependency"
		}
		typedEvidence = append(typedEvidence, map[string]any{
			"scenario_key": scenario["id"],
			"evidence":     evidence,
		})
	}
	base := map[string]any{
		"schema_version":                   1,
		"repository":                       "layervai/qurl-go",
		"commit_sha":                       strings.Repeat("a", 40),
		"run_id":                           "1234",
		"run_attempt":                      "1",
		"gate_passed":                      true,
		"phase":                            "pre_removal",
		"strict_outcome":                   "success",
		"enforcement_outcome":              "success",
		"inputs_unchanged":                 true,
		"nhp_controller_run_id":            "123456",
		"nhp_controller_run_attempt":       "1",
		"dispatch_correlation_id":          nativeUDPDispatchCorrelation("qurl_go", "pre_removal"),
		"deployment_runtime_inputs_sha256": strings.Repeat("e", 64),
		"deployment_manifest_sha256":       strings.Repeat("f", 64),
		"inventory_sha256":                 strings.Repeat("1", 64),
		"inventory_mapping_sha256":         strings.Repeat("2", 64),
		"scenario_contract_sha256":         strings.Repeat("3", 64),
		"retired_lifecycle_surface_sha256": strings.Repeat("4", 64),
		"proof_harness_sha256":             strings.Repeat("5", 64),
		"pre_removal_run_id":               nil,
		"pre_removal_evidence_sha256":      nil,
		"pre_removal_deployment_sha256":    nil,
		"deployment_producer": map[string]any{
			"repository":      "layervai/nhp",
			"workflow_path":   ".github/workflows/udp-proof-deployment-manifest.yml",
			"run_id":          "987654",
			"run_attempt":     "1",
			"head_sha":        strings.Repeat("c", 40),
			"artifact_id":     "7654321",
			"artifact_digest": "sha256:" + strings.Repeat("d", 64),
		},
		"counts":                         map[string]any{"implemented": implemented, "blocking": 68 - implemented, "failures": 0, "skips": 0, "exact_passes": implemented},
		"provenance_valid":               true,
		"two_cell_provenance":            true,
		"typed_evidence_complete":        true,
		"typed_evidence":                 typedEvidence,
		"typed_evidence_contract_sha256": "e15008760ea838875de9c75561726c86e9d2e7f7f507247e55a588fa3ac65fe5",
		"provenance":                     nil,
		"scenario_results":               []any{},
	}
	tests := []struct {
		name        string
		mutate      func(map[string]any)
		wantSuccess bool
	}{
		{name: "qurl-go complete with visible external dependencies", wantSuccess: true},
		{name: "gate false", mutate: func(value map[string]any) { value["gate_passed"] = false }},
		{name: "global-looking zero blockers", mutate: func(value map[string]any) { value["counts"].(map[string]any)["blocking"] = 0 }},
		{name: "Connector coupling field", mutate: func(value map[string]any) { value["connector_proof_run_id"] = "777" }},
		{name: "missing inventory row", mutate: func(value map[string]any) {
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
			writeJSONFile(t, filepath.Join(runnerTemp, "pre_retirement_scenarios.json"), inventory)
			runScript(t, t.TempDir(), stepRun(t, readWorkflow(t, "native-udp-sandbox.yml"), "Require complete qurl-go proof publication"),
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
			scenario := item.(map[string]any)
			if scenario["owner"] == "qurl-go" {
				scenario["status"] = "implemented"
			} else {
				scenario["status"] = "external_dependency"
			}
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
		"QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID": nativeUDPDispatchCorrelation(
			"qurl_go",
			phase,
		),
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID":      "123456",
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT": "1",
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_B64":    base64.StdEncoding.EncodeToString(manifest),
		"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_B64": base64.StdEncoding.EncodeToString(
			deploymentRuntimeInputsBytes(t, manifest),
		),
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ID":      "987654",
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ATTEMPT": "1",
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_HEAD_SHA":    strings.Repeat("c", 40),
		"QURL_GO_SANDBOX_DEPLOYMENT_ARTIFACT_ID":          "7654321",
		"QURL_GO_SANDBOX_DEPLOYMENT_ARTIFACT_DIGEST":      "sha256:" + strings.Repeat("d", 64),
		"QURL_GO_SANDBOX_PRE_REMOVAL_RUN_ID":              preRemovalRunID,
		"MOCK_PRODUCER_RUN_ID":                            "987654",
		"MOCK_PRODUCER_RUN_ATTEMPT":                       "1",
		"MOCK_PRODUCER_HEAD_SHA":                          strings.Repeat("c", 40),
		"MOCK_PRODUCER_ARTIFACT_ID":                       "7654321",
		"MOCK_PRODUCER_ARTIFACT_DIGEST":                   "sha256:" + strings.Repeat("d", 64),
	}
	for key, value := range extra {
		environment[key] = value
	}
	script := stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Verify exact proof inputs")
	runScript(t, fixture.repository, script, environment, wantSuccess)
	if !wantSuccess {
		return nil
	}
	producerDir := filepath.Join(runnerTemp, "deployment-producer-artifact")
	if err := os.Mkdir(producerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"deployment-manifest.json":       manifest,
		"deployment-provenance.json":     []byte("{}"),
		"deployment-runtime-inputs.json": deploymentRuntimeInputsBytes(t, manifest),
		"orchestrator-evidence.json":     []byte(`{"schema_version":1}`),
	} {
		if err := os.WriteFile(filepath.Join(producerDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runScript(
		t,
		fixture.repository,
		stepRun(t, readNativeUDPFixtureWorkflow(t, fixture), "Materialize authenticated orchestrator evidence"),
		map[string]string{"RUNNER_TEMP": runnerTemp, "GITHUB_ENV": githubEnv},
		true,
	)
	return readStepOutputs(t, githubEnv)
}

func writeManifestCommitGHMock(t *testing.T) string {
	t.Helper()
	mockBin := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
test "$1" = "api"
case "$2" in
  repos/layervai/nhp/actions/runs/*)
    test "${2##*/}" = "${MOCK_PRODUCER_RUN_ID}"
    printf '{"id":%s,"run_attempt":%s,"path":".github/workflows/udp-proof-deployment-manifest.yml","event":"workflow_dispatch","status":"completed","conclusion":"success","head_branch":"main","head_sha":"%s","repository":{"full_name":"layervai/nhp"},"head_repository":{"full_name":"layervai/nhp"}}\n' \
      "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_RUN_ATTEMPT}" "${MOCK_PRODUCER_HEAD_SHA}"
    ;;
  repos/layervai/nhp/actions/artifacts/*)
    test "${2##*/}" = "${MOCK_PRODUCER_ARTIFACT_ID}"
    printf '{"id":%s,"name":"udp-proof-deployment-manifest-%s-%s","digest":"%s","expired":false,"size_in_bytes":4096,"workflow_run":{"id":%s,"head_branch":"main","head_sha":"%s"}}\n' \
      "${MOCK_PRODUCER_ARTIFACT_ID}" "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_RUN_ATTEMPT}" \
      "${MOCK_PRODUCER_ARTIFACT_DIGEST}" "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_HEAD_SHA}"
    ;;
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
		"QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID":          nativeUDPDispatchCorrelation("qurl_go", "pre_removal"),
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID":            "123456",
		"QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT":       "1",
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_PATH":         outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_PATH"],
		"QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256":       outputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
		"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_PATH":   outputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_PATH"],
		"QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256": outputs["QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"],
		"QURL_GO_SANDBOX_NHP_SOURCE_SHA":                   outputs["QURL_GO_SANDBOX_NHP_SOURCE_SHA"],
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ID":       "987654",
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ATTEMPT":  "1",
		"QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_HEAD_SHA":     strings.Repeat("c", 40),
		"QURL_GO_SANDBOX_DEPLOYMENT_ARTIFACT_ID":           "7654321",
		"QURL_GO_SANDBOX_DEPLOYMENT_ARTIFACT_DIGEST":       "sha256:" + strings.Repeat("d", 64),
		"QURL_GO_SANDBOX_INVENTORY_PATH":                   outputs["QURL_GO_SANDBOX_INVENTORY_PATH"],
		"QURL_GO_SANDBOX_INVENTORY_SHA256":                 outputs["QURL_GO_SANDBOX_INVENTORY_SHA256"],
		"QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256":         outputs["QURL_GO_SANDBOX_INVENTORY_MAPPING_SHA256"],
		"QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256":         outputs["QURL_GO_SANDBOX_SCENARIO_CONTRACT_SHA256"],
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_PATH":   outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_PATH"],
		"QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256": outputs["QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256"],
		"QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256":   outputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
		"QURL_GO_SANDBOX_PROOF_HARNESS_SHA256":             outputs["QURL_GO_SANDBOX_PROOF_HARNESS_SHA256"],
		"QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH":       outputs["QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH"],
		"QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256":     outputs["QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256"],
	}
}

func nativeUDPDispatchCorrelation(client, phase string) string {
	return "nhp-123456-1-" + client + "-" + phase + "-" + strings.Repeat("a", 32)
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
			"qurl_go": qurlGoSHA,
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
			map[string]any{"cell_id": "cell0", "host": "cell0.nhp.layerv.ai", "port": 62206, "server_public_key_sha256": sha256Hex(bytes.Repeat([]byte{0x11}, 32))},
			map[string]any{"cell_id": "cell1", "host": "cell1.nhp.layerv.ai", "port": 62206, "server_public_key_sha256": sha256Hex(bytes.Repeat([]byte{0x22}, 32))},
		},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func deploymentRuntimeInputsBytes(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var deployed map[string]any
	if err := json.Unmarshal(manifest, &deployed); err != nil {
		t.Fatal(err)
	}
	hub := deployed["hub"].(map[string]any)
	cells := deployed["cells"].([]any)
	runtime := map[string]any{
		"schema_version": 1,
		"hub": map[string]any{
			"host":                  hub["host"],
			"port":                  hub["port"],
			"server_public_key_b64": base64.StdEncoding.EncodeToString(nativeUDPProofHubKey()),
		},
		"cells": []any{
			map[string]any{
				"cell_id":               "cell0",
				"host":                  cells[0].(map[string]any)["host"],
				"port":                  cells[0].(map[string]any)["port"],
				"server_public_key_b64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
			},
			map[string]any{
				"cell_id":               "cell1",
				"host":                  cells[1].(map[string]any)["host"],
				"port":                  cells[1].(map[string]any)["port"],
				"server_public_key_b64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
			},
		},
	}
	encoded, err := json.Marshal(runtime)
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

func writeProofProvenance(t *testing.T, runnerTemp, buildSHA, agentID string, inputs map[string]string) {
	t.Helper()
	writeProofProvenanceValue(t, runnerTemp, proofProvenanceValue(
		buildSHA,
		agentID,
		inputs["QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"],
		inputs["QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"],
	))
}

func writeProofProvenanceValue(t *testing.T, runnerTemp string, value map[string]any) {
	t.Helper()
	directory := filepath.Join(runnerTemp, "qurl-go-native-udp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(directory, "provenance.json"), value)
}

func proofProvenanceValue(buildSHA, agentID, deploymentManifestSHA, typedEvidenceContractSHA string) map[string]any {
	cell0KeySHA := sha256Hex(bytes.Repeat([]byte{0x11}, 32))
	cell1KeySHA := sha256Hex(bytes.Repeat([]byte{0x22}, 32))
	refresh := proofCell("refresh", "cell1", "cell1.nhp.layerv.ai", cell1KeySHA, 2, 3)
	refresh["lease_expires_at"] = "2026-07-22T12:30:00.123456789Z"
	return map[string]any{
		"schema_version":                 2,
		"build_sha":                      buildSHA,
		"agent_id":                       agentID,
		"deployment_manifest_sha256":     deploymentManifestSHA,
		"typed_evidence_contract_sha256": typedEvidenceContractSHA,
		"hub": map[string]any{
			"host":                     "hub.nhp.layerv.ai",
			"port":                     62206,
			"server_public_key_sha256": sha256Hex(nativeUDPProofHubKey()),
		},
		"assigned_cells": []any{
			proofCell("registration", "cell0", "cell0.nhp.layerv.ai", cell0KeySHA, 1, 1),
			proofCell("warm_open", "cell0", "cell0.nhp.layerv.ai", cell0KeySHA, 1, 1),
			proofCell("reassignment", "cell1", "cell1.nhp.layerv.ai", cell1KeySHA, 2, 2),
			refresh,
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
    repos/layervai/nhp/actions/runs/*)
      test "${2##*/}" = "${MOCK_PRODUCER_RUN_ID}"
      printf '{"id":%s,"run_attempt":%s,"path":".github/workflows/udp-proof-deployment-manifest.yml","event":"workflow_dispatch","status":"completed","conclusion":"success","head_branch":"main","head_sha":"%s","repository":{"full_name":"layervai/nhp"},"head_repository":{"full_name":"layervai/nhp"}}\n' \
        "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_RUN_ATTEMPT}" "${MOCK_PRODUCER_HEAD_SHA}"
      ;;
    repos/layervai/nhp/actions/artifacts/*)
      test "${2##*/}" = "${MOCK_PRODUCER_ARTIFACT_ID}"
      printf '{"id":%s,"name":"udp-proof-deployment-manifest-%s-%s","digest":"%s","expired":false,"size_in_bytes":4096,"workflow_run":{"id":%s,"head_branch":"main","head_sha":"%s"}}\n' \
        "${MOCK_PRODUCER_ARTIFACT_ID}" "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_RUN_ATTEMPT}" \
        "${MOCK_PRODUCER_ARTIFACT_DIGEST}" "${MOCK_PRODUCER_RUN_ID}" "${MOCK_PRODUCER_HEAD_SHA}"
      ;;
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
		{name: "deployment-runtime-inputs.json", path: filepath.Join(filepath.Dir(manifestPath), "deployment-runtime-inputs.json")},
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
