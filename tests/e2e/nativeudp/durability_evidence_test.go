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
	qurlGoCandidateBaseRef = "main"
	maxCandidateJSONBytes  = 1024 * 1024
	maxProductionTestBytes = 4 * 1024 * 1024

	// The only two candidate shapes the proof accepts. The workflow resolves
	// exactly one of them through the authenticated API and names it here; the
	// assertions below re-derive the property from the recorded payload, so a
	// mislabelled document fails instead of picking the weaker branch.
	candidateKindOpenPullRequest = "open_pull_request"
	candidateKindMainContained   = "main_contained"
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

// candidateComparisonProof is the authenticated compare payload for
// `main...<build sha>`. Containment in main is not "the commit object exists"
// — a fork tip or an abandoned branch satisfies that. It is "the merge base of
// main and this commit is this commit, and nothing is ahead of it", which holds
// only for main's head or an ancestor of it.
type candidateComparisonProof struct {
	URL             string `json:"url"`
	Status          string `json:"status"`
	AheadBy         int    `json:"ahead_by"`
	MergeBaseCommit struct {
		SHA string `json:"sha"`
	} `json:"merge_base_commit"`
	BaseCommit struct {
		SHA string `json:"sha"`
	} `json:"base_commit"`
}

type candidateCommitProof struct {
	SHA    string `json:"sha"`
	Commit struct {
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	} `json:"commit"`
}

// verifyCandidatePullRequest accepts only an open pull request of this exact
// repository, targeting main, whose CURRENT head is the running build. A
// cross-repository head, a closed or merged pull request, and a head that has
// moved on since dispatch are all rejected. The pull request number itself is
// operator-supplied and carries no integrity weight, so it is only required to
// be a real positive number — the binding that matters is head SHA plus
// repository plus base ref.
func verifyCandidatePullRequest(pull candidatePRProof, buildSHA string) error {
	switch {
	case pull.Number < 1:
		return fmt.Errorf("candidate pull request number %d is not a positive pull request", pull.Number)
	case pull.State != "open":
		return fmt.Errorf("candidate pull request state is %q, want open", pull.State)
	case pull.Head.Repo.FullName != qurlGoRepository:
		return fmt.Errorf("candidate pull request head repository is %q, want %s", pull.Head.Repo.FullName, qurlGoRepository)
	case pull.Base.Repo.FullName != qurlGoRepository:
		return fmt.Errorf("candidate pull request base repository is %q, want %s", pull.Base.Repo.FullName, qurlGoRepository)
	case pull.Base.Ref != qurlGoCandidateBaseRef:
		return fmt.Errorf("candidate pull request base ref is %q, want %s", pull.Base.Ref, qurlGoCandidateBaseRef)
	case pull.Head.SHA != buildSHA:
		return fmt.Errorf("candidate pull request head is %q, want the exact running build %s", pull.Head.SHA, buildSHA)
	}
	return nil
}

// verifyCandidateMainContainment accepts only a compare payload proving the
// running build is contained in this repository's main. The URL is asserted
// verbatim so the payload itself — not merely the request that produced it —
// names the repository, the base ref, and the head SHA.
func verifyCandidateMainContainment(compare candidateComparisonProof, buildSHA string) error {
	wantURL := "https://api.github.com/repos/" + qurlGoRepository +
		"/compare/" + qurlGoCandidateBaseRef + "..." + buildSHA
	switch {
	case compare.URL != wantURL:
		return fmt.Errorf("candidate comparison url is %q, want %q", compare.URL, wantURL)
	case compare.Status != "identical" && compare.Status != "behind":
		return fmt.Errorf("candidate comparison status is %q, want identical or behind", compare.Status)
	case compare.AheadBy != 0:
		return fmt.Errorf("candidate comparison reports %d commits ahead of %s, want 0", compare.AheadBy, qurlGoCandidateBaseRef)
	case compare.MergeBaseCommit.SHA != buildSHA:
		return fmt.Errorf("candidate comparison merge base is %q, want the exact running build %s", compare.MergeBaseCommit.SHA, buildSHA)
	case !canonicalLowerHex(compare.BaseCommit.SHA, 40):
		return fmt.Errorf("candidate comparison base commit %q is not an exact lowercase commit SHA", compare.BaseCommit.SHA)
	}
	return nil
}

func verifyCandidateCommit(commit candidateCommitProof, buildSHA string) error {
	if commit.SHA != buildSHA {
		return fmt.Errorf("candidate commit is %q, want the exact running build %s", commit.SHA, buildSHA)
	}
	if !commit.Commit.Verification.Verified {
		return fmt.Errorf("GitHub does not report candidate commit %s as cryptographically verified", buildSHA)
	}
	return nil
}

// proveExactQURLGoCandidate binds this run to one GitHub-verified commit of
// this repository at the exact running SHA. Every branch is fail-closed: an
// unknown candidate kind, a payload that does not satisfy its declared shape,
// and an unverified commit all abort the proof.
func proveExactQURLGoCandidate(t *testing.T, cfg sandboxConfig) {
	t.Helper()
	assertBuildProvenance(t, cfg.buildSHA)

	switch cfg.candidateKind {
	case candidateKindOpenPullRequest:
		var pull candidatePRProof
		readBoundedCandidateJSON(t, cfg.candidatePath, &pull)
		if err := verifyCandidatePullRequest(pull, cfg.buildSHA); err != nil {
			t.Fatalf("authenticated candidate is not an open %s pull request at exact build %s: %v", qurlGoRepository, cfg.buildSHA, err)
		}
		t.Logf("EVIDENCE repository=%s candidate_kind=%s pull_request=%d base=%s", qurlGoRepository, cfg.candidateKind, pull.Number, qurlGoCandidateBaseRef)
	case candidateKindMainContained:
		var compare candidateComparisonProof
		readBoundedCandidateJSON(t, cfg.candidatePath, &compare)
		if err := verifyCandidateMainContainment(compare, cfg.buildSHA); err != nil {
			t.Fatalf("authenticated candidate is not contained in %s %s at exact build %s: %v", qurlGoRepository, qurlGoCandidateBaseRef, cfg.buildSHA, err)
		}
		t.Logf("EVIDENCE repository=%s candidate_kind=%s base=%s base_head_sha=%s comparison_status=%s", qurlGoRepository, cfg.candidateKind, qurlGoCandidateBaseRef, compare.BaseCommit.SHA, compare.Status)
	default:
		t.Fatalf("candidate kind %q is neither %s nor %s", cfg.candidateKind, candidateKindOpenPullRequest, candidateKindMainContained)
	}

	var commit candidateCommitProof
	readBoundedCandidateJSON(t, cfg.candidateCommit, &commit)
	if err := verifyCandidateCommit(commit, cfg.buildSHA); err != nil {
		t.Fatalf("authenticated candidate commit rejected: %v", err)
	}
	t.Logf("EVIDENCE repository=%s candidate_kind=%s base=%s build_sha=%s github_verified=true", qurlGoRepository, cfg.candidateKind, qurlGoCandidateBaseRef, cfg.buildSHA)
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

// candidateBuildSHAFixture is a stand-in for the running GITHUB_SHA in the
// forged-candidate tests below. It is deliberately not any real commit.
const candidateBuildSHAFixture = "0123456789abcdef0123456789abcdef01234567"

func exactCandidatePullRequestFixture(buildSHA string) candidatePRProof {
	var pull candidatePRProof
	pull.Number = 128
	pull.State = "open"
	pull.Head.SHA = buildSHA
	pull.Head.Repo.FullName = qurlGoRepository
	pull.Base.Ref = qurlGoCandidateBaseRef
	pull.Base.Repo.FullName = qurlGoRepository
	return pull
}

func exactCandidateComparisonFixture(buildSHA string) candidateComparisonProof {
	var compare candidateComparisonProof
	compare.URL = "https://api.github.com/repos/" + qurlGoRepository +
		"/compare/" + qurlGoCandidateBaseRef + "..." + buildSHA
	compare.Status = "behind"
	compare.AheadBy = 0
	compare.MergeBaseCommit.SHA = buildSHA
	compare.BaseCommit.SHA = strings.Repeat("b", 40)
	return compare
}

func TestVerifyCandidatePullRequestFailsClosed(t *testing.T) {
	if err := verifyCandidatePullRequest(exactCandidatePullRequestFixture(candidateBuildSHAFixture), candidateBuildSHAFixture); err != nil {
		t.Fatalf("exact open pull request candidate rejected: %v", err)
	}
	for label, forge := range map[string]func(*candidatePRProof){
		"absent pull request": func(p *candidatePRProof) { p.Number = 0 },
		"negative number":     func(p *candidatePRProof) { p.Number = -1 },
		"closed":              func(p *candidatePRProof) { p.State = "closed" },
		"merged":              func(p *candidatePRProof) { p.State = "merged" },
		"fork head":           func(p *candidatePRProof) { p.Head.Repo.FullName = "someone/qurl-go" },
		"foreign base":        func(p *candidatePRProof) { p.Base.Repo.FullName = "someone/qurl-go" },
		"non-main base":       func(p *candidatePRProof) { p.Base.Ref = "release" },
		"head moved on":       func(p *candidatePRProof) { p.Head.SHA = strings.Repeat("f", 40) },
		"empty head":          func(p *candidatePRProof) { p.Head.SHA = "" },
		"empty document":      func(p *candidatePRProof) { *p = candidatePRProof{} },
	} {
		t.Run(label, func(t *testing.T) {
			pull := exactCandidatePullRequestFixture(candidateBuildSHAFixture)
			forge(&pull)
			if err := verifyCandidatePullRequest(pull, candidateBuildSHAFixture); err == nil {
				t.Fatal("forged pull request candidate accepted")
			}
		})
	}
}

func TestVerifyCandidateMainContainmentFailsClosed(t *testing.T) {
	for _, status := range []string{"identical", "behind"} {
		t.Run("accepts "+status, func(t *testing.T) {
			compare := exactCandidateComparisonFixture(candidateBuildSHAFixture)
			compare.Status = status
			if err := verifyCandidateMainContainment(compare, candidateBuildSHAFixture); err != nil {
				t.Fatalf("exact %s containment candidate rejected: %v", status, err)
			}
		})
	}
	for label, forge := range map[string]func(*candidateComparisonProof){
		// "ahead" and "diverged" are exactly the shapes a commit that only
		// exists — an unmerged branch or a fork tip — produces.
		"unmerged branch":  func(c *candidateComparisonProof) { c.Status = "ahead"; c.AheadBy = 1 },
		"diverged history": func(c *candidateComparisonProof) { c.Status = "diverged"; c.AheadBy = 2 },
		"status without ancestry": func(c *candidateComparisonProof) {
			c.Status = "behind"
			c.MergeBaseCommit.SHA = strings.Repeat("e", 40)
		},
		"commits ahead of main": func(c *candidateComparisonProof) { c.AheadBy = 1 },
		"foreign repository": func(c *candidateComparisonProof) {
			c.URL = "https://api.github.com/repos/someone/qurl-go/compare/main..." + candidateBuildSHAFixture
		},
		"another base ref": func(c *candidateComparisonProof) {
			c.URL = "https://api.github.com/repos/" + qurlGoRepository + "/compare/release..." + candidateBuildSHAFixture
		},
		"another head sha": func(c *candidateComparisonProof) {
			c.URL = "https://api.github.com/repos/" + qurlGoRepository +
				"/compare/" + qurlGoCandidateBaseRef + "..." + strings.Repeat("f", 40)
		},
		"two-dot comparison": func(c *candidateComparisonProof) {
			c.URL = "https://api.github.com/repos/" + qurlGoRepository +
				"/compare/" + qurlGoCandidateBaseRef + ".." + candidateBuildSHAFixture
		},
		"absent base head":       func(c *candidateComparisonProof) { c.BaseCommit.SHA = "" },
		"noncanonical base head": func(c *candidateComparisonProof) { c.BaseCommit.SHA = strings.ToUpper(strings.Repeat("b", 40)) },
		"empty document":         func(c *candidateComparisonProof) { *c = candidateComparisonProof{} },
	} {
		t.Run(label, func(t *testing.T) {
			compare := exactCandidateComparisonFixture(candidateBuildSHAFixture)
			forge(&compare)
			if err := verifyCandidateMainContainment(compare, candidateBuildSHAFixture); err == nil {
				t.Fatal("forged containment candidate accepted")
			}
		})
	}
}

// TestCandidateShapesDoNotSubstituteForEachOther proves the two accepted shapes
// cannot be swapped: a pull request payload decoded as a comparison, and a
// comparison payload decoded as a pull request, both fail. That is what keeps
// the workflow-declared candidate kind from selecting a weaker check.
func TestCandidateShapesDoNotSubstituteForEachOther(t *testing.T) {
	pullBytes, err := json.Marshal(exactCandidatePullRequestFixture(candidateBuildSHAFixture))
	if err != nil {
		t.Fatal(err)
	}
	compareBytes, err := json.Marshal(exactCandidateComparisonFixture(candidateBuildSHAFixture))
	if err != nil {
		t.Fatal(err)
	}

	var comparisonFromPull candidateComparisonProof
	if err := json.Unmarshal(pullBytes, &comparisonFromPull); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateMainContainment(comparisonFromPull, candidateBuildSHAFixture); err == nil {
		t.Fatal("pull request payload accepted as main containment")
	}

	var pullFromComparison candidatePRProof
	if err := json.Unmarshal(compareBytes, &pullFromComparison); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidatePullRequest(pullFromComparison, candidateBuildSHAFixture); err == nil {
		t.Fatal("comparison payload accepted as an open pull request")
	}
}

func TestVerifyCandidateCommitFailsClosed(t *testing.T) {
	exact := func() candidateCommitProof {
		var commit candidateCommitProof
		commit.SHA = candidateBuildSHAFixture
		commit.Commit.Verification.Verified = true
		return commit
	}
	if err := verifyCandidateCommit(exact(), candidateBuildSHAFixture); err != nil {
		t.Fatalf("exact verified candidate commit rejected: %v", err)
	}
	for label, forge := range map[string]func(*candidateCommitProof){
		"another commit":    func(c *candidateCommitProof) { c.SHA = strings.Repeat("f", 40) },
		"absent commit":     func(c *candidateCommitProof) { c.SHA = "" },
		"unverified commit": func(c *candidateCommitProof) { c.Commit.Verification.Verified = false },
	} {
		t.Run(label, func(t *testing.T) {
			commit := exact()
			forge(&commit)
			if err := verifyCandidateCommit(commit, candidateBuildSHAFixture); err == nil {
				t.Fatal("forged candidate commit accepted")
			}
		})
	}
}
