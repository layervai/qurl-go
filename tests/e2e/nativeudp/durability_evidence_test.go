package nativeudp_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	qurlGoRepository       = "layervai/qurl-go"
	maxCandidateJSONBytes  = 1024 * 1024
	maxProductionTestBytes = 4 * 1024 * 1024
)

type nativeDurabilityProofAdapter struct {
	adapterName     string
	scenarioKey     string
	evidenceKind    string
	productionTests []string
}

func nativeDurabilityProofAdapters() []nativeDurabilityProofAdapter {
	return []nativeDurabilityProofAdapter{
		{
			adapterName:  "account_otp_dedupe",
			scenarioKey:  "otp.dedupe",
			evidenceKind: "otp_flow_observation",
			productionTests: []string{
				"TestRegisterAgentRuntime_AccountLostRAKReusesOriginalCodeWithoutSecondOTP",
			},
		},
		{
			adapterName:  "account_otp_error",
			scenarioKey:  "otp.error",
			evidenceKind: "otp_flow_observation",
			productionTests: []string{
				"TestRegisterAgentRuntime_AccountOTPProviderFailuresSendOneOTPNoREGAndPersistNoCode",
			},
		},
		{
			adapterName:  "account_otp_rate_limit",
			scenarioKey:  "otp.rate_limit",
			evidenceKind: "otp_flow_observation",
			productionTests: []string{
				"TestRegisterAgentRuntime_AccountRegistrationRateLimitIsTerminalForCall",
			},
		},
		{
			adapterName:  "ambiguous_rak_recovery",
			scenarioKey:  "recovery.ambiguous_rak",
			evidenceKind: "recovery_transition",
			productionTests: []string{
				"TestRegisterAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry",
			},
		},
		{
			adapterName:  "registration_restart_recovery",
			scenarioKey:  "recovery.registration_restart",
			evidenceKind: "recovery_transition",
			productionTests: []string{
				"TestRegisterAgentRuntime_PreREGCancellationLeavesExactPendingActivation",
				"TestRegisterAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry",
				"TestRegisterAgentRuntime_PostRAKCommitThenErrorReloadsAndResumesExactCandidate",
				"TestRegisterAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply",
				"TestRegisterAgentRuntime_FinalSaveFailureKeepsCandidateRecoverable",
			},
		},
		{
			adapterName:  "ambiguous_completion_lrt_recovery",
			scenarioKey:  "recovery.ambiguous_completion_lrt",
			evidenceKind: "recovery_transition",
			productionTests: []string{
				"TestRegisterAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply",
			},
		},
		{
			adapterName:  "final_state_save_ambiguity",
			scenarioKey:  "recovery.final_state_save_ambiguity",
			evidenceKind: "recovery_transition",
			productionTests: []string{
				"TestRegisterAgentRuntime_FinalSaveFailureKeepsCandidateRecoverable",
				"TestRegisterAgentRuntime_DeadlineDoesNotMaskFinalPromotionPersistenceAmbiguity",
			},
		},
	}
}

type candidatePRProof struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Head   struct {
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string `json:"ref"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}

type candidateCommitProof struct {
	SHA    string `json:"sha"`
	Commit struct {
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	} `json:"commit"`
}

func proveExactQURLGo93Candidate(t *testing.T, cfg sandboxConfig) {
	t.Helper()
	assertBuildProvenance(t, cfg.buildSHA)

	var pull candidatePRProof
	readBoundedCandidateJSON(t, cfg.candidatePRPath, &pull)
	if pull.Number != 93 || pull.State != "open" ||
		pull.Head.SHA != cfg.buildSHA || pull.Head.Repo.FullName != qurlGoRepository ||
		pull.Base.Ref != "main" || pull.Base.Repo.FullName != qurlGoRepository {
		t.Fatalf("authenticated PR candidate does not identify open %s#93 at exact build %s targeting main", qurlGoRepository, cfg.buildSHA)
	}

	var commit candidateCommitProof
	readBoundedCandidateJSON(t, cfg.candidateCommit, &commit)
	if commit.SHA != cfg.buildSHA || !commit.Commit.Verification.Verified {
		t.Fatalf("authenticated candidate commit does not report exact verified build %s", cfg.buildSHA)
	}
	t.Logf("EVIDENCE repository=%s pull_request=93 base=main build_sha=%s github_verified=true", qurlGoRepository, cfg.buildSHA)
}

func readBoundedCandidateJSON(t *testing.T, path string, target any) {
	t.Helper()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("candidate evidence path %q is not canonical absolute", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect candidate evidence: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxCandidateJSONBytes {
		t.Fatalf("candidate evidence path is not a bounded regular non-symlink file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read candidate evidence: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode candidate evidence: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("candidate evidence has trailing JSON")
	}
}

type goTestJSONEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

func runProductionStateMachineProofs(t *testing.T, exactTests []string) {
	t.Helper()
	if len(exactTests) == 0 {
		t.Fatal("production proof adapter has no exact tests")
	}
	seen := make(map[string]struct{}, len(exactTests))
	quoted := make([]string, 0, len(exactTests))
	for _, name := range exactTests {
		if !strings.HasPrefix(name, "Test") {
			t.Fatalf("production proof name %q is not an exact Go test", name)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("production proof repeats exact test %q", name)
		}
		seen[name] = struct{}{}
		quoted = append(quoted, regexp.QuoteMeta(name))
	}

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	command := exec.CommandContext(
		t.Context(),
		"go", "test", "-json", "-count=1",
		"-run", "^(?:"+strings.Join(quoted, "|")+")$",
		"./qurl",
	)
	command.Dir = root
	command.Env = productionProofEnvironment(os.Environ())
	output, runErr := command.CombinedOutput()
	if len(output) > maxProductionTestBytes {
		t.Fatalf("production proof output exceeded %d bytes", maxProductionTestBytes)
	}
	if err := validateProductionProofEvents(output, exactTests); err != nil {
		t.Fatalf("production state-machine evidence failed: %v", err)
	}
	if runErr != nil {
		t.Fatalf("production state-machine tests failed: %v", runErr)
	}
	t.Logf("EVIDENCE exact_production_tests=%s", strings.Join(exactTests, ","))
}

func productionProofEnvironment(source []string) []string {
	out := make([]string, 0, len(source))
	for _, entry := range source {
		name, _, _ := strings.Cut(entry, "=")
		if name == enrollmentEnv || name == typedEvidencePathEnv || name == "GH_TOKEN" || name == "GITHUB_TOKEN" {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func validateProductionProofEvents(raw []byte, exactTests []string) error {
	passes := make(map[string]int, len(exactTests))
	expected := make(map[string]struct{}, len(exactTests))
	for _, name := range exactTests {
		expected[name] = struct{}{}
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), maxProductionTestBytes)
	for scanner.Scan() {
		var event goTestJSONEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("decode go test event: %w", err)
		}
		for name := range expected {
			if event.Test != name && !strings.HasPrefix(event.Test, name+"/") {
				continue
			}
			switch event.Action {
			case "fail":
				return fmt.Errorf("%s failed", event.Test)
			case "skip":
				return fmt.Errorf("%s skipped", event.Test)
			case "pass":
				if event.Test == name {
					passes[name]++
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan go test events: %w", err)
	}
	for _, name := range exactTests {
		if passes[name] != 1 {
			return fmt.Errorf("%s emitted %d exact passing events, want 1", name, passes[name])
		}
	}
	return nil
}

func TestProductionDurabilityProofAdaptersExecuteExactTests(t *testing.T) {
	var exactTests []string
	seen := make(map[string]struct{})
	for _, proof := range nativeDurabilityProofAdapters() {
		for _, name := range proof.productionTests {
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			exactTests = append(exactTests, name)
		}
	}
	runProductionStateMachineProofs(t, exactTests)
}

func TestValidateProductionProofEventsFailsClosed(t *testing.T) {
	const name = "TestExactProductionBoundary"
	event := func(action, test string) []byte {
		raw, err := json.Marshal(goTestJSONEvent{Action: action, Package: "github.com/layervai/qurl-go/qurl", Test: test})
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	if err := validateProductionProofEvents(event("pass", name), []string{name}); err != nil {
		t.Fatalf("exact pass rejected: %v", err)
	}
	for label, raw := range map[string][]byte{
		"missing": nil,
		"skip":    event("skip", name),
		"failure": event("fail", name+"/case"),
		"other":   event("pass", "TestOther"),
		"invalid": []byte("not-json\n"),
	} {
		t.Run(label, func(t *testing.T) {
			if err := validateProductionProofEvents(raw, []string{name}); err == nil {
				t.Fatal("invalid production proof events passed")
			}
		})
	}
}
