package workflowcontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeUDPSandboxWorkflowIsAttendedStrictAndEvidenceBearing(t *testing.T) {
	workflow := readWorkflow(t, "native-udp-sandbox.yml")

	requireContains(t, workflow,
		"workflow_dispatch:",
		"environment: sandbox",
		"permissions:\n  contents: read",
		"QURL_GO_SANDBOX_STRICT: \"true\"",
		"QURL_GO_SANDBOX_EXPECTED_SHA: ${{ github.sha }}",
		"QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL: ${{ secrets.QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL }}",
		"test \"$(git rev-parse HEAD)\" = \"${QURL_GO_SANDBOX_EXPECTED_SHA}\"",
		"Validate exact pre-retirement inventory",
		"go test -count=1 ./tests/e2e/nativeudp -run '^TestPreRetirementScenarioInventory$'",
		"go test -count=1 -timeout=10m -json ./tests/e2e/nativeudp",
		"-run '^TestSandboxNativeUDPLifecycle$'",
		"Enforce full pre-retirement scenario inventory",
		"pre_retirement_scenarios.json",
		".all_scenarios_required",
		"select(.status == \"implemented\")",
		".Action == \"pass\"",
		".Action == \"skip\"",
		"select(.status != \"implemented\")",
		"required pre-retirement scenarios remain unproven; HTTP lifecycle retirement is blocked",
		"if-no-files-found: error",
		"retention-days: 30",
		"Remove credential state",
	)
	requireNotContains(t, workflow,
		"schedule:",
		"pull_request:",
		"push:",
		"continue-on-error:",
	)
	requireBefore(t, workflow,
		"Verify clean exact checkout",
		"Validate exact pre-retirement inventory",
		"Run strict direct UDP proof",
		"Enforce full pre-retirement scenario inventory",
		"Upload non-secret JSON evidence",
		"Remove credential state",
	)
}

func TestNativeUDPSandboxCurrentSevenCannotOpenRetirementGate(t *testing.T) {
	runnerTemp := t.TempDir()
	artifact := filepath.Join(runnerTemp, "native-udp-sandbox.json")
	testNames := []string{
		"TestSandboxNativeUDPLifecycle/provenance_and_hub_trust",
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

	repository := filepath.Clean(filepath.Join(workflowDir(t), "..", ".."))
	script := stepRun(t, readWorkflow(t, "native-udp-sandbox.yml"), "Enforce full pre-retirement scenario inventory")
	runScript(t, repository, script, map[string]string{"RUNNER_TEMP": runnerTemp}, false)
}
