package workflowcontract

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const otpSchemaV2CanaryWorkflow = "otp-schema-v2-canary.yml"

func readOTPSchemaV2Canary(t *testing.T) string {
	t.Helper()
	return readWorkflow(t, otpSchemaV2CanaryWorkflow)
}

// workflowJobs returns every top-level job body. The canary workflow
// deliberately uses ordinary two-space job keys, so a small scanner gives
// these tests a precise security boundary without adding a YAML dependency to
// the SDK. Enumerating rather than looking up only today's two job names keeps a
// future credential-bearing third job inside the authorization contract.
func workflowJobs(t *testing.T, workflow string) map[string]string {
	t.Helper()
	const jobsMarker = "\njobs:\n"
	start := strings.Index(workflow, jobsMarker)
	if start < 0 {
		t.Fatalf("%s has no jobs block", otpSchemaV2CanaryWorkflow)
	}

	jobs := make(map[string]string)
	current := ""
	for _, line := range strings.SplitAfter(workflow[start+len(jobsMarker):], "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") &&
			strings.HasSuffix(strings.TrimSpace(line), ":") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			if current == "" {
				t.Fatal("canary workflow has an empty job id")
			}
			if _, duplicate := jobs[current]; duplicate {
				t.Fatalf("canary workflow repeats job id %q", current)
			}
			jobs[current] = line
			continue
		}
		if current != "" {
			jobs[current] += line
		}
	}
	if len(jobs) == 0 {
		t.Fatal("canary workflow jobs block is empty")
	}
	return jobs
}

func workflowJob(t *testing.T, workflow, name string) string {
	t.Helper()
	job, ok := workflowJobs(t, workflow)[name]
	if !ok {
		t.Fatalf("%s has no %q job", otpSchemaV2CanaryWorkflow, name)
	}
	return job
}

func TestOTPSchemaV2CanaryIsAttendedMainOnly(t *testing.T) {
	workflow := readOTPSchemaV2Canary(t)
	if !strings.Contains(workflow, "on:\n  workflow_dispatch:\n") {
		t.Fatal("canary must be an attended workflow_dispatch")
	}
	for _, forbidden := range []string{"\n  push:", "\n  pull_request:", "\n  schedule:"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("canary contains forbidden trigger %q", strings.TrimSpace(forbidden))
		}
	}
	for _, input := range []string{
		"expected_qurl_go_main_sha:",
		"authority_image_digest:",
		"nhp_writer_convergence_run_url:",
		"nhp_writer_convergence_main_sha:",
		"reset_inventory_pass_run_url:",
		"reset_manifest_sha256:",
		"receipts_reviewed:",
	} {
		if !strings.Contains(workflow, "      "+input) {
			t.Errorf("canary dispatch contract omits %s", input)
		}
	}
	authority := strings.Index(workflow, "      authority_image_digest:")
	convergence := strings.Index(workflow, "      nhp_writer_convergence_run_url:")
	reset := strings.Index(workflow, "      reset_inventory_pass_run_url:")
	if authority < 0 || convergence <= authority || reset <= convergence {
		t.Fatal("dispatch inputs must present final Authority, then NHP writer convergence, then reset/PASS")
	}
	for _, gate := range []string{
		`[ "${GITHUB_REPOSITORY}" != "layervai/qurl-go" ]`,
		`[ "${GITHUB_REF}" != "refs/heads/main" ]`,
		`[ "${RECEIPTS_REVIEWED}" != "true" ]`,
		`^https://github\.com/layervai/qurl-service/actions/runs/[1-9][0-9]*$`,
		`^https://github\.com/layervai/nhp/actions/runs/[1-9][0-9]*$`,
		`^sha256:[0-9a-f]{64}$`,
	} {
		if !strings.Contains(workflow, gate) {
			t.Errorf("canary authorization omits fail-closed gate %q", gate)
		}
	}
}

func TestOTPSchemaV2CanarySeparatesAuthorizationFromCredentials(t *testing.T) {
	workflow := readOTPSchemaV2Canary(t)
	jobs := workflowJobs(t, workflow)
	authorize := workflowJob(t, workflow, "authorize")
	canary := workflowJob(t, workflow, "canary")

	if count := strings.Count(workflow, "    environment: otp-schema-v2-canary"); count != 1 {
		t.Fatalf("protected Environment bindings = %d, want authorize only", count)
	}
	if !strings.Contains(authorize, "    environment: otp-schema-v2-canary") {
		t.Fatal("credential-free authorize job does not use the protected Environment")
	}
	if strings.Contains(authorize, "id-token: write") || strings.Contains(authorize, "${{ secrets.") {
		t.Fatal("protected authorize job must receive neither OIDC permission nor secrets")
	}
	if !strings.Contains(canary, "    needs: authorize") {
		t.Fatal("credential-bearing canary job is not gated on authorize success")
	}
	if strings.Contains(canary, "environment:") {
		t.Fatal("credential-bearing canary job declares an Environment and would change its OIDC subject")
	}
	if !strings.Contains(canary, "id-token: write") || !strings.Contains(canary, "${{ secrets.") {
		t.Fatal("canary job must carry the existing secret inputs and ephemeral OIDC permission")
	}

	for _, sensitive := range []string{"id-token: write", "${{ secrets."} {
		insideJobs := 0
		for _, job := range jobs {
			insideJobs += strings.Count(job, sensitive)
		}
		if total := strings.Count(workflow, sensitive); total != insideJobs {
			t.Fatalf("%q references outside enumerated top-level jobs = %d", sensitive, total-insideJobs)
		}
	}
	for name, job := range jobs {
		if !strings.Contains(job, "id-token: write") && !strings.Contains(job, "${{ secrets.") {
			continue
		}
		protected := strings.Contains(job, "    environment: otp-schema-v2-canary")
		authorized := strings.Contains(job, "    needs: authorize")
		if !protected && !authorized {
			t.Errorf("credential-bearing job %q has neither the protected Environment nor needs: authorize", name)
		}
	}
}

func TestOTPSchemaV2CanaryRechecksCurrentMainBeforeCredentials(t *testing.T) {
	workflow := readOTPSchemaV2Canary(t)
	authorize := workflowJob(t, workflow, "authorize")
	canary := workflowJob(t, workflow, "canary")

	for name, job := range map[string]string{"authorize": authorize, "canary": canary} {
		for _, required := range []string{
			"git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
			`checked_out_sha="$(git rev-parse HEAD)"`,
			`current_main_sha="$(git rev-parse refs/remotes/origin/main)"`,
			`[ "${GITHUB_SHA}" !=`,
			`[ "${checked_out_sha}" !=`,
			`[ "${current_main_sha}" !=`,
		} {
			if !strings.Contains(job, required) {
				t.Errorf("%s job omits current-main barrier fragment %q", name, required)
			}
		}
	}

	barrier := strings.Index(canary, "- name: Re-fetch and require the authorized current main before credentials")
	if barrier < 0 {
		t.Fatal("canary has no post-authorization current-main barrier")
	}
	for _, live := range []string{
		"- name: Require protected canary configuration",
		"- name: Configure ephemeral mailbox credentials",
		"- name: Register with emailed OTP and assert device credential warm-open",
	} {
		position := strings.Index(canary, live)
		if position < 0 || position <= barrier {
			t.Errorf("live step %q is absent or precedes the current-main barrier", live)
		}
	}
}

func TestOTPSchemaV2CanaryUsesOnlyTheSanctionedOTPHarness(t *testing.T) {
	workflow := readOTPSchemaV2Canary(t)
	for _, forbidden := range []string{
		"UDP_PROOF_FAST_GH_TOKEN",
		"aws dynamodb",
		"qurl-agent-key-inventory",
		"gh api",
		"go test -v",
		"QURL_OTP_E2E_ENROLLMENT: ${{ secrets.OTP_E2E_ENROLLMENT }}",
		"QURL_OTP_E2E_CANARY_RAW_RECEIPT",
		"agent_id_sha256",
		"public_key_sha256",
		"device_api_key_id_sha256",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("canary contains forbidden authority/logging surface %q", forbidden)
		}
	}

	secretReference := regexp.MustCompile(`secrets\.([A-Z0-9_]+)`).FindAllStringSubmatch(workflow, -1)
	seen := make(map[string]bool)
	for _, match := range secretReference {
		seen[match[1]] = true
	}
	want := []string{
		"OTP_E2E_AGENT_ID",
		"OTP_E2E_ENROLLMENT_POOL",
		"OTP_E2E_HUB_HOST",
		"OTP_E2E_HUB_PORT",
		"OTP_E2E_HUB_SERVER_KEY",
		"OTP_E2E_MAILBOX_BUCKET",
		"OTP_E2E_MAILBOX_QUEUE_URL",
		"OTP_E2E_MAILBOX_RECIPIENT",
		"OTP_E2E_MAILBOX_REGION",
		"OTP_E2E_ROLE_ARN",
	}
	got := make([]string, 0, len(seen))
	for name := range seen {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("canary secret references = %v, want existing OTP harness set %v", got, want)
	}

	for _, required := range []string{
		"go test -count=1 ./tests/e2e/nativeudp/",
		"-run '^TestEmailedOTPCompletesIdempotentSDKRegistration$'",
		"QURL_OTP_E2E_STRICT: \"1\"",
		"mask-aws-account-id: true",
		"QURL_OTP_E2E_CANARY_COMMITMENT_PATH: ${{ runner.temp }}/canary-binding-commitment.json",
		"umask 077",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("canary omits exact live-test contract %q", required)
		}
	}
}

func TestOTPSchemaV2CanaryPublishesOnlyTheLinkedCommitment(t *testing.T) {
	workflow := readOTPSchemaV2Canary(t)
	canary := workflowJob(t, workflow, "canary")

	if count := strings.Count(workflow, "actions/upload-artifact@"); count != 1 {
		t.Fatalf("canary upload-artifact steps = %d, want exactly one", count)
	}
	for _, required := range []string{
		"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
		"name: otp-schema-v2-canary-commitment-${{ github.run_id }}-${{ github.run_attempt }}",
		"path: ${{ runner.temp }}/canary-binding-commitment.json",
		"if-no-files-found: error",
		"retention-days: 7",
		"compression-level: 0",
		"overwrite: false",
		"include-hidden-files: false",
		`expected = ["schema_version", "binding_sha256", "github_run_id", "github_run_attempt"]`,
		`re.fullmatch(r"[0-9a-f]{64}"`,
		`stat.S_IMODE(info.st_mode) != 0o600`,
		`raw != canonical`,
		`value[key] != int(os.environ[environment])`,
		`print(f"verified binding commitment {value['binding_sha256']} for run {value['github_run_id']} attempt {value['github_run_attempt']}")`,
		"- name: Remove the runner-local commitment\n        if: always()",
		`rm -f -- "${COMMITMENT_PATH}"`,
		`[ -e "${COMMITMENT_PATH}" ] || [ -L "${COMMITMENT_PATH}" ]`,
	} {
		if !strings.Contains(canary, required) {
			t.Errorf("canary linked-commitment contract omits %q", required)
		}
	}

	upload := strings.Index(canary, "- name: Publish the linked binding commitment")
	cleanup := strings.Index(canary, "- name: Remove the runner-local commitment")
	verify := strings.Index(canary, "- name: Verify the canonical non-secret commitment")
	testStep := strings.Index(canary, "- name: Register with emailed OTP and assert device credential warm-open")
	if testStep < 0 || verify <= testStep || upload <= verify || cleanup <= upload {
		t.Fatal("canary must test, verify, publish, then always remove the commitment in that order")
	}
	for _, forbidden := range []string{
		"agent_id\"", "public_key_b64\"", "device_api_key_id\"",
		"canary-commitments.sha256", "*.json", "${{ runner.temp }}/",
	} {
		if forbidden == "${{ runner.temp }}/" {
			// The exact commitment path is allowed; a directory upload is not.
			if strings.Contains(canary, "path: "+forbidden+"\n") {
				t.Error("canary uploads the runner temp directory instead of the exact commitment file")
			}
			continue
		}
		if strings.Contains(canary, forbidden) {
			t.Errorf("canary exposes or uploads forbidden commitment material %q", forbidden)
		}
	}
	if regexp.MustCompile(`(?m)echo[^\n]*(AGENT_ID|PUBLIC_KEY|DEVICE_API_KEY_ID)`).MatchString(canary) {
		t.Error("canary echoes a raw binding input")
	}
}

func TestOTPSchemaV2CanaryTargetKeepsCredentialAndWarmOpenAssertions(t *testing.T) {
	path := filepath.Join(workflowDir(t), "..", "..", "tests", "e2e", "nativeudp", "otp_registration_idempotency_test.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OTP registration target: %v", err)
	}
	source := string(raw)
	for _, required := range []string{
		"WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAccount)",
		`if binding.DeviceAPIKeyID == ""`,
		"if replayBinding.DeviceAPIKeyID != binding.DeviceAPIKeyID",
		"if replayBinding.AgentID != binding.AgentID",
		"if replayBinding.PublicKeyB64 != binding.PublicKeyB64",
		"if !replayBinding.RegisteredAt.Equal(binding.RegisteredAt)",
		"if calls, fresh := mailbox.snapshot(); calls != 1 || !fresh",
		"t.Cleanup(binding.Destroy)",
		`t.Errorf("close sealed agent state: %v", err)`,
		"writeOTPE2ECanaryCommitment(path, binding",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("live OTP target no longer proves %q", required)
		}
	}
	if strings.Contains(source, "binding.DeviceAPIKeyID, replayBinding.DeviceAPIKeyID") {
		t.Error("live OTP target formats device API key ids into a failure message")
	}
	for _, rawFormat := range []string{
		`binding.AgentID, replayBinding.AgentID`,
		`binding.PublicKeyB64, replayBinding.PublicKeyB64`,
		`binding.DeviceAPIKeyID, replayBinding.DeviceAPIKeyID`,
		`binding.AgentID, binding.CellID`,
	} {
		if strings.Contains(source, rawFormat) {
			t.Errorf("live OTP target formats raw binding material %q", rawFormat)
		}
	}
}

func TestOTPSchemaV2CanaryDocumentsExternalInventoryClosure(t *testing.T) {
	path := filepath.Join(workflowDir(t), "..", "..", "docs", "otp-schema-v2-canary.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canary rollout note: %v", err)
	}
	document := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"Finish the qurl-service producer",
		"same qurl-service source as the final Authority writer image",
		"The Authority scratch image does not contain the inventory binary",
		"same-source immutable API image/run that contains `qurl-agent-key-inventory`",
		"across Control and both cells",
		"This must stop schema-v1 writers before reset",
		"Only after writer convergence, run the governed reset",
		"The Authority digest remains the writer-convergence receipt; it is not the inventory executable",
		"qurl-service reset/inventory workflow maintainers, owned by the Connector rollout coordinator",
		"post-canary verifier from the same immutable API image",
		"Do not dispatch the canary until that companion verifier is available",
		".github/workflows/otp-schema-v2-canary.yml",
		"canary_binding_sha256",
		"reviewer must authenticate that hash against the qurl-go run summary or its retained artifact",
		"qurl-service `github.token` cannot be relied on to list or download a sibling repository's artifacts",
		"locally constructs the canonical receipt",
		"otp-schema-v2-canary-commitment-<run_id>-<run_attempt>",
		"canary-binding-commitment.json",
		"not a hidden machine-readable dependency for the qurl-service workflow",
		"one complete linked triple across the schema-v2 registration, owner claim, active API agent-key row, and active Authority device-credential head",
		"must not report an invented global `0 -> 1`",
		"must not report an invented global `0 -> 1` or mechanically diff every counter against reset evidence",
		"retain the actual post-canary counts and require a full strict inventory `PASS`",
		"every registered agent is schema v2 and claimed",
		"unsupported, malformed, unclaimed, and cross-owner counters are `0`",
		"exact canary binding is unique and active",
		"A strict-inventory or exact-binding failure is a failed rollout receipt",
		"rollout remains blocked",
		"layerv:qurl-go:otp-schema-v2-canary:binding:v1",
		"four-byte unsigned big-endian UTF-8 byte length",
		"Frame the public key's base64 text, not its 32 decoded bytes",
		"88e8071c4c5e1e5222dda436d6f6f93f6654120d68190206bad3fce1a63189bc",
		"mode `0600` and an exclusive create",
		"always()` cleanup step",
		"administrator bypass: disabled",
	} {
		if !strings.Contains(document, required) {
			t.Errorf("canary rollout note omits %q", required)
		}
	}
	for _, conflation := range []string{
		"immutable Authority image",
		"inventory from the final Authority digest",
		"inventory again using the same Authority digest",
		"retain and compare the actual aggregate counts",
		"Orphan legacy claims must remain at the frozen baseline",
		"Any unexplained or unequal aggregate movement",
	} {
		if strings.Contains(document, conflation) {
			t.Errorf("canary rollout note conflates Authority writer and API inventory images: %q", conflation)
		}
	}
	last := -1
	for _, ordered := range []string{
		"Finish the qurl-service producer",
		"Run the exact current-main NHP pre-strict writer-convergence workflow",
		"Only after writer convergence, run the governed reset",
		"Confirm qurl-go `main` at the intended canary commit",
	} {
		position := strings.Index(document, ordered)
		if position <= last {
			t.Fatalf("canary rollout order is missing or out of sequence at %q", ordered)
		}
		last = position
	}
}
