// Package workflowcontract locks the repository's secret-bearing workflow
// boundary. The fixture tests execute the local snapshot origin preparation
// and the terminal verifier; the hosted action itself remains covered by its
// immutable, hand-audited pin and actionlint.
package workflowcontract

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	auditedClaudeActionRef     = "anthropics/claude-code-action@12dd8d74c712f5f3669365b2369b558c495b1104"
	auditedClaudeActionVersion = "v1.0.238"

	claudeModel  = "claude-opus-5-5"
	claudeEffort = "medium"
)

// TestClaudeWorkflowsUseAuditedAction makes the action's Git behavior part of
// the secret-bearing workflow contract. Since upstream v1.0.187 the action
// replaces origin with a token-bearing URL of this repository even when
// use_commit_signing is true, and fetches the base branch through it. The
// terminal verifier tolerates exactly that and nothing wider, so an immutable,
// consistent pin is not sufficient: every new pin must be audited for what it
// does to Git configuration and refs before this constant moves.
func TestClaudeWorkflowsUseAuditedAction(t *testing.T) {
	for _, name := range []string{"claude-code-review.yml", "claude.yml"} {
		t.Run(name, func(t *testing.T) {
			pin, err := solePin(readWorkflow(t, name), claudeAction)
			if err != nil {
				t.Fatalf("resolve Claude action pin: %v", err)
			}
			if pin.reference != auditedClaudeActionRef || pin.version != auditedClaudeActionVersion {
				t.Errorf("Claude action pin %q # %s is not the audited pin %q # %s",
					pin.reference, pin.version, auditedClaudeActionRef, auditedClaudeActionVersion)
			}
		})
	}
}

var claudeArgFlag = regexp.MustCompile(`(?m)^[ \t]*--(model|effort)[ \t]+(\S+)[ \t]*$`)

// TestClaudeWorkflowsBindModelAndEffort holds both lanes to one model and one
// effort. The two are a pair with the action pin: the bundled Claude Code
// release decides which models the API accepts, so a lane left on another
// model or effort is a lane reviewing under settings nobody chose.
func TestClaudeWorkflowsBindModelAndEffort(t *testing.T) {
	for _, name := range []string{"claude-code-review.yml", "claude.yml"} {
		t.Run(name, func(t *testing.T) {
			got := map[string][]string{}
			for _, match := range claudeArgFlag.FindAllStringSubmatch(readWorkflow(t, name), -1) {
				got[match[1]] = append(got[match[1]], match[2])
			}
			for flag, want := range map[string]string{"model": claudeModel, "effort": claudeEffort} {
				if values := got[flag]; len(values) != 1 || values[0] != want {
					t.Errorf("--%s = %v, want exactly one, %q", flag, values, want)
				}
			}
		})
	}
}

func TestAutomaticClaudeWorkflowUsesTrustedReadOnlySnapshots(t *testing.T) {
	workflow := readWorkflow(t, "claude-code-review.yml")

	requireContains(t, workflow,
		"pull_request_target:",
		"types: [opened, synchronize, reopened, ready_for_review]",
		"github.event.pull_request.state == 'open'",
		"github.event.pull_request.draft == false",
		"github.event.pull_request.head.repo.full_name == github.repository",
		"github.event.pull_request.base.repo.full_name == github.repository",
		"github.event.pull_request.base.ref == github.event.repository.default_branch",
		"github.event.pull_request.head.ref != github.event.repository.default_branch",
		"Resolve live review context",
		"ref: ${{ github.sha }}",
		"fetch-depth: 0",
		"persist-credentials: false",
		"Prepare local snapshot review origin",
		"bash .github/scripts/resolve-claude-pr.sh",
		"bash .github/scripts/prepare-claude-origin.sh",
		"bash .github/scripts/verify-claude-review.sh",
		"use_commit_signing: true",
		"classify_inline_comments: false",
		"Read CONTRIBUTING.md at AUTHORIZED BASE SHA",
		"steps.claude_review.outputs.execution_file",
	)
	requireContains(t, readWorkflowScript(t, "resolve-claude-pr.sh"), ".base.repo.default_branch")
	requireContains(t, readWorkflowScript(t, "prepare-claude-origin.sh"),
		"git init --bare --quiet",
		"git config --local fetch.recurseSubmodules false",
	)
	requireContains(t, readWorkflowScript(t, "verify-claude-review.sh"),
		`current_state}" != "open"`,
		`current_draft}" != "false"`,
		`current_default_ref}" != "${TRUSTED_DEFAULT_REF}"`,
		`current_head_ref}" == "${current_default_ref}"`,
		"] | length == 1",
	)
	requireReadOnlyActionContract(t, workflow)
	requireNotContains(t, workflow,
		"\n  pull_request:\n",
		"pull_request_review:",
		"pull_request_review_comment:",
		"Read CLAUDE.md",
		"id-token: write",
	)
	requireBefore(t, workflow,
		requirePin(t, workflow, checkoutAction),
		"Resolve live review context",
		"Prepare local snapshot review origin",
		requirePin(t, workflow, claudeAction),
		"Verify reviewed pull request snapshots",
	)
}

func TestInteractiveClaudeWorkflowUsesDefaultBranchCommentPath(t *testing.T) {
	workflow := readWorkflow(t, "claude.yml")

	requireContains(t, workflow,
		"issue_comment:",
		"types: [created]",
		"github.event.issue.pull_request != null",
		"github.event.comment.body == '@claude'",
		"startsWith(github.event.comment.body, '@claude ')",
		"github.event.comment.author_association == 'OWNER'",
		"collaborators/${TRIGGER_ACTOR}/permission",
		"admin|maintain|write",
		"ref: ${{ github.sha }}",
		"Prepare local snapshot Claude origin",
		"bash .github/scripts/resolve-claude-pr.sh",
		"bash .github/scripts/prepare-claude-origin.sh",
		"bash .github/scripts/verify-claude-review.sh",
		"do not edit or commit files",
		"steps.claude.outputs.execution_file",
	)
	requireContains(t, readWorkflowScript(t, "resolve-claude-pr.sh"),
		".base.repo.default_branch",
		`state}" != "open"`,
		`head_repo}" != "${GITHUB_REPOSITORY}"`,
		`base_repo}" != "${GITHUB_REPOSITORY}"`,
		`default_ref}" != "${TRUSTED_DEFAULT_REF}"`,
		`head_ref}" == "${default_ref}"`,
	)
	requireContains(t, readWorkflowScript(t, "verify-claude-review.sh"),
		"Claude trigger actor lost repository write access",
		"Claude review is stale or the PR trust boundary changed",
		"] | length == 1",
	)
	requireReadOnlyActionContract(t, workflow)
	requireNotContains(t, workflow,
		"\n  pull_request:\n",
		"pull_request_target:",
		"pull_request_review:",
		"pull_request_review_comment:",
		"contains(github.event.comment.body, '@claude')",
		"id-token: write",
	)
	requireBefore(t, workflow,
		"Validate Claude trigger actor permission",
		requirePin(t, workflow, checkoutAction),
		"Resolve Claude pull request context",
		"Prepare local snapshot Claude origin",
		requirePin(t, workflow, claudeAction),
		"Verify reviewed pull request snapshots",
	)
}

func TestLocalSnapshotOriginPreparationExecutes(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		extra map[string]string
	}{
		{
			name: "automatic", mode: "automatic",
			extra: map[string]string{
				"EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
				"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
				"PR_NUMBER": "93", "RUN_ID": "123", "RUN_ATTEMPT": "1",
			},
		},
		{name: "interactive", mode: "interactive"},
	}
	script := readWorkflowScript(t, "prepare-claude-origin.sh")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			runGit(t, fixture.repository, "checkout", "--detach", "--quiet", fixture.baseSHA)
			env := map[string]string{
				"CLAUDE_REVIEW_MODE":   test.mode,
				"GITHUB_REPOSITORY":    "layervai/qurl-go",
				"GITHUB_OUTPUT":        filepath.Join(t.TempDir(), "outputs"),
				"RUNNER_TEMP":          t.TempDir(),
				"EXPECTED_HEAD_SHA":    fixture.headSHA,
				"EXPECTED_HEAD_REF":    fixture.headRef,
				"EXPECTED_BASE_SHA":    fixture.baseSHA,
				"EXPECTED_BASE_REF":    fixture.baseRef,
				"TRUSTED_DEFAULT_REF":  fixture.baseRef,
				"EXPECTED_TRUSTED_SHA": fixture.baseSHA,
			}
			for key, value := range test.extra {
				env[key] = value
			}
			wrongTrustedSHA := cloneEnvironment(env)
			wrongTrustedSHA["EXPECTED_TRUSTED_SHA"] = fixture.headSHA
			runScript(t, fixture.repository, script, wrongTrustedSHA, false)
			runScript(t, fixture.repository, script, env, true)
			outputs, err := os.ReadFile(env["GITHUB_OUTPUT"])
			if err != nil {
				t.Fatalf("read workflow outputs: %v", err)
			}
			if !strings.Contains(string(outputs), "ready=true") {
				t.Fatalf("workflow outputs = %q, want ready=true", outputs)
			}
			// Prepare leaves origin as the local pin, with no credential, and
			// records the snapshots in the lane's workflow-owned namespace.
			if got, want := runGit(t, fixture.repository, "remote", "get-url", "--all", "origin"), readStepOutputs(t, env["GITHUB_OUTPUT"])["path"]; got != want {
				t.Errorf("origin after prepare = %q, want the local snapshot %q", got, want)
			}
			namespace := snapshotNamespace(test.mode)
			if got := runGit(t, fixture.repository, "rev-parse", namespace+"/head"); got != fixture.headSHA {
				t.Errorf("%s/head = %s, want %s", namespace, got, fixture.headSHA)
			}
			if got := runGit(t, fixture.repository, "rev-parse", namespace+"/base"); got != fixture.baseSHA {
				t.Errorf("%s/base = %s, want %s", namespace, got, fixture.baseSHA)
			}
		})
	}
}

func TestAutomaticOriginRejectsClosedOrDefaultHead(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "closed", env: map[string]string{"EXPECTED_STATE": "closed"}},
		{name: "draft", env: map[string]string{"EXPECTED_DRAFT": "true"}},
		{name: "default head", env: map[string]string{"EXPECTED_HEAD_REF": "main"}},
		{name: "fork", env: map[string]string{"EXPECTED_HEAD_REPO": "attacker/qurl-go"}},
	}
	script := readWorkflowScript(t, "prepare-claude-origin.sh")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			runGit(t, fixture.repository, "checkout", "--detach", "--quiet", fixture.baseSHA)
			env := map[string]string{
				"CLAUDE_REVIEW_MODE": "automatic",
				"GITHUB_REPOSITORY":  "layervai/qurl-go", "GITHUB_OUTPUT": filepath.Join(t.TempDir(), "outputs"),
				"RUNNER_TEMP": t.TempDir(), "EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
				"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
				"EXPECTED_HEAD_SHA": fixture.headSHA, "EXPECTED_HEAD_REF": fixture.headRef,
				"EXPECTED_BASE_SHA": fixture.baseSHA, "EXPECTED_BASE_REF": fixture.baseRef,
				"TRUSTED_DEFAULT_REF": fixture.baseRef, "PR_NUMBER": "93", "RUN_ID": "123", "RUN_ATTEMPT": "1",
				"EXPECTED_TRUSTED_SHA": fixture.baseSHA,
			}
			for key, value := range test.env {
				env[key] = value
			}
			runScript(t, fixture.repository, script, env, false)
		})
	}
}

func TestLivePRResolversRejectUnsafeCurrentState(t *testing.T) {
	skipWithoutGNUTimeout(t)
	tests := []struct {
		name  string
		mode  string
		extra func(gitFixture) map[string]string
	}{
		{
			name: "automatic", mode: "automatic",
			extra: func(fixture gitFixture) map[string]string {
				return map[string]string{
					"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
					"EXPECTED_HEAD_SHA": fixture.headSHA, "EXPECTED_HEAD_REF": fixture.headRef,
					"EXPECTED_BASE_SHA": fixture.baseSHA, "EXPECTED_BASE_REF": fixture.baseRef,
					"EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
					"TRUSTED_DEFAULT_REF": fixture.baseRef, "EXPECTED_TRUSTED_SHA": fixture.baseSHA,
				}
			},
		},
		{
			name: "interactive", mode: "interactive",
			extra: func(fixture gitFixture) map[string]string {
				return map[string]string{
					"TRUSTED_DEFAULT_REF":  fixture.baseRef,
					"EXPECTED_TRUSTED_SHA": fixture.baseSHA,
				}
			},
		},
	}
	script := readWorkflowScript(t, "resolve-claude-pr.sh")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			runGit(t, fixture.repository, "checkout", "--detach", "--quiet", fixture.baseSHA)
			mockBin := writeGHMock(t)
			baseEnv := map[string]string{
				"CLAUDE_REVIEW_MODE": test.mode,
				"PATH":               mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GH_TOKEN":           "test-token",
				"GITHUB_REPOSITORY":  "layervai/qurl-go",
				"GITHUB_OUTPUT":      filepath.Join(t.TempDir(), "outputs"),
				"PR_NUMBER":          "100",
			}
			for key, value := range test.extra(fixture) {
				baseEnv[key] = value
			}
			baseEnv["MOCK_PR_JSON"] = mockPullRequestJSON(t, fixture, "open", false, fixture.baseRef)
			runScript(t, fixture.repository, script, baseEnv, true)

			unsafePRs := []struct {
				name       string
				state      string
				defaultRef string
			}{
				{name: "closed", state: "closed", defaultRef: fixture.baseRef},
				{name: "head is default", state: "open", defaultRef: fixture.headRef},
				{name: "default changed", state: "open", defaultRef: "release/stable"},
			}
			for _, unsafe := range unsafePRs {
				t.Run(unsafe.name, func(t *testing.T) {
					env := cloneEnvironment(baseEnv)
					env["MOCK_PR_JSON"] = mockPullRequestJSON(t, fixture, unsafe.state, false, unsafe.defaultRef)
					runScript(t, fixture.repository, script, env, false)
				})
			}
		})
	}
}

// verifierModes are the two lanes that share the prepare and verify scripts.
var verifierModes = []struct {
	name  string
	extra map[string]string
}{
	{
		name: "automatic",
		extra: map[string]string{
			"EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
			"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
			"PR_NUMBER": "100", "RUN_ID": "123", "RUN_ATTEMPT": "1",
		},
	},
	{name: "interactive"},
}

func snapshotNamespace(mode string) string {
	if mode == "automatic" {
		return "refs/automatic-review"
	}
	return "refs/claude-command"
}

// newVerifierFixture runs the real prepare script against a fresh fixture and
// returns it with an environment under which the real verify script passes.
func newVerifierFixture(t *testing.T, mode string, extra map[string]string) (gitFixture, map[string]string) {
	t.Helper()
	fixture := newGitFixture(t)
	outputFile := filepath.Join(t.TempDir(), "outputs")
	prepareEnv := map[string]string{
		"CLAUDE_REVIEW_MODE":   mode,
		"GITHUB_REPOSITORY":    "layervai/qurl-go",
		"GITHUB_OUTPUT":        outputFile,
		"RUNNER_TEMP":          t.TempDir(),
		"EXPECTED_HEAD_SHA":    fixture.headSHA,
		"EXPECTED_HEAD_REF":    fixture.headRef,
		"EXPECTED_BASE_SHA":    fixture.baseSHA,
		"EXPECTED_BASE_REF":    fixture.baseRef,
		"TRUSTED_DEFAULT_REF":  fixture.baseRef,
		"EXPECTED_TRUSTED_SHA": fixture.baseSHA,
	}
	for key, value := range extra {
		prepareEnv[key] = value
	}
	runScript(t, fixture.repository, readWorkflowScript(t, "prepare-claude-origin.sh"), prepareEnv, true)
	outputs := readStepOutputs(t, outputFile)

	executionFile := filepath.Join(t.TempDir(), "execution.json")
	if err := os.WriteFile(executionFile, []byte("{\"subtype\":\"success\"}\n"), 0o600); err != nil {
		t.Fatalf("write execution fixture: %v", err)
	}
	marker := outputs["review_marker"]
	if marker == "" {
		marker = "<!-- claude-command:layervai/qurl-go:pr-100:run-123:attempt-1:head-" + fixture.headSHA + " -->"
	}
	comments, err := json.Marshal([][]map[string]any{{{
		"user": map[string]string{"login": "github-actions[bot]"},
		"body": "No findings.\n" + marker,
	}}})
	if err != nil {
		t.Fatalf("marshal comment fixture: %v", err)
	}

	verifyEnv := map[string]string{
		"CLAUDE_REVIEW_MODE":    mode,
		"PATH":                  writeGHMock(t) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_TOKEN":              "test-token",
		"GITHUB_REPOSITORY":     "layervai/qurl-go",
		"GITHUB_SERVER_URL":     "https://github.com",
		"PR_NUMBER":             "100",
		"EXPECTED_HEAD_SHA":     fixture.headSHA,
		"EXPECTED_HEAD_REF":     fixture.headRef,
		"EXPECTED_BASE_SHA":     fixture.baseSHA,
		"EXPECTED_BASE_REF":     fixture.baseRef,
		"TRUSTED_DEFAULT_REF":   fixture.baseRef,
		"EXPECTED_ORIGIN":       outputs["path"],
		"EXPECTED_LOCAL_SHA":    outputs["trusted_sha"],
		"CLAUDE_EXECUTION_FILE": executionFile,
		"MOCK_PR_JSON":          mockPullRequestJSON(t, fixture, "open", false, fixture.baseRef),
		"MOCK_COMMENTS_JSON":    string(comments),
	}
	if mode == "automatic" {
		verifyEnv["EXPECTED_REVIEW_MARKER"] = marker
	} else {
		verifyEnv["EXPECTED_TRIGGER_ACTOR"] = "maintainer"
		verifyEnv["EXPECTED_RESULT_MARKER"] = marker
	}
	return fixture, verifyEnv
}

func TestTerminalVerifiersRejectUnsafeCurrentState(t *testing.T) {
	skipWithoutGNUTimeout(t)
	verifyScript := readWorkflowScript(t, "verify-claude-review.sh")

	for _, test := range verifierModes {
		t.Run(test.name, func(t *testing.T) {
			fixture, verifyEnv := newVerifierFixture(t, test.name, test.extra)
			runScript(t, fixture.repository, verifyScript, verifyEnv, true)

			unsafePRs := []struct {
				name       string
				state      string
				defaultRef string
			}{
				{name: "closed", state: "closed", defaultRef: fixture.baseRef},
				{name: "head is default", state: "open", defaultRef: fixture.headRef},
				{name: "default changed", state: "open", defaultRef: "release/stable"},
			}
			for _, unsafe := range unsafePRs {
				t.Run(unsafe.name, func(t *testing.T) {
					env := cloneEnvironment(verifyEnv)
					env["MOCK_PR_JSON"] = mockPullRequestJSON(t, fixture, unsafe.state, false, unsafe.defaultRef)
					runScript(t, fixture.repository, verifyScript, env, false)
				})
			}

			t.Run("local HEAD changed", func(t *testing.T) {
				runGit(t, fixture.repository, "checkout", "--detach", "--quiet", fixture.headSHA)
				runScript(t, fixture.repository, verifyScript, verifyEnv, false)
			})
		})
	}
}

// originToken stands in for the installation token the action writes into the
// origin URL, in the real token's shape. No verifier output may ever contain
// it. It is assembled at run time so the source holds nothing token-shaped.
var originToken = "ghs_" + strings.Repeat("t0K", 12)

const (
	errRemoteSet        = "::error::The Claude run added, removed, or reshaped a Git remote."
	errOriginURLCount   = "::error::Origin does not have exactly one fetch and one push URL."
	errOriginShape      = "::error::Origin is neither the local snapshot nor a recognizable URL of this repository."
	errOriginMoved      = "::error::Origin moved off this repository:"
	errSnapshots        = "::error::The Claude run changed the authorized local snapshots."
	errCredentialConfig = "::error::The Claude run left a Git credential header or helper in the workspace."
	errNoOriginTargets  = "::error::Runner-provided origin comparison targets are unavailable."
)

// TestTerminalVerifierAssertsOriginDestination is the contract that replaced
// "origin is still exactly the local pin". The audited action re-points origin
// at this repository with a token in the URL and fetches the base branch
// through it, so the verifier has to accept that and nothing else: any origin
// that could carry the token, or the snapshots, to another destination fails.
func TestTerminalVerifierAssertsOriginDestination(t *testing.T) {
	skipWithoutGNUTimeout(t)
	verifyScript := readWorkflowScript(t, "verify-claude-review.sh")
	credentialed := func(rest string) string { return "https://x-access-token:" + originToken + "@" + rest }
	setOrigin := func(url string) func(*testing.T, gitFixture, string) {
		return func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "origin", url)
		}
	}

	tests := []struct {
		name string
		// mutate stands in for what happened to the workspace between the
		// prepare and verify steps; namespace is the lane's snapshot refs.
		mutate func(t *testing.T, fixture gitFixture, namespace string)
		env    map[string]string
		// wantError is empty when the verifier must pass.
		wantError string
	}{
		{name: "local pin untouched", mutate: func(*testing.T, gitFixture, string) {}},
		{name: "token-bearing URL of this repository", mutate: setOrigin(credentialed("github.com/layervai/qurl-go.git"))},
		{name: "token-bearing URL without .git", mutate: setOrigin(credentialed("github.com/layervai/qurl-go"))},
		{name: "this repository without userinfo", mutate: setOrigin("https://github.com/layervai/qurl-go.git")},
		{name: "this repository in another letter case", mutate: setOrigin(credentialed("GitHub.com/LayerVAI/Qurl-Go.git"))},
		{
			// What the audited action really does: re-point origin, then
			// fetch a base branch that has moved since the snapshot.
			name: "action rewrite with an advanced origin-tracking base",
			mutate: func(t *testing.T, fixture gitFixture, _ string) {
				runGit(t, fixture.repository, "remote", "set-url", "origin", credentialed("github.com/layervai/qurl-go.git"))
				runGit(t, fixture.repository, "update-ref", "refs/remotes/origin/"+fixture.baseRef, fixture.headSHA)
			},
		},

		{name: "another host", mutate: setOrigin(credentialed("evil.example/layervai/qurl-go.git")), wantError: errOriginMoved},
		{name: "host with this host as a prefix", mutate: setOrigin(credentialed("github.com.evil.example/layervai/qurl-go.git")), wantError: errOriginMoved},
		{name: "another port", mutate: setOrigin(credentialed("github.com:8443/layervai/qurl-go.git")), wantError: errOriginMoved},
		{name: "another scheme", mutate: setOrigin("http://x-access-token:" + originToken + "@github.com/layervai/qurl-go.git"), wantError: errOriginMoved},
		{name: "another owner", mutate: setOrigin(credentialed("github.com/attacker/qurl-go.git")), wantError: errOriginMoved},
		{name: "another repository", mutate: setOrigin(credentialed("github.com/layervai/other.git")), wantError: errOriginMoved},
		{name: "longer path", mutate: setOrigin(credentialed("github.com/layervai/qurl-go.git/extra")), wantError: errOriginMoved},
		{name: "allowed destination only in the path", mutate: setOrigin("https://evil.example/@github.com/layervai/qurl-go.git"), wantError: errOriginMoved},
		{name: "token then allowed destination in the path", mutate: setOrigin("https://evil.example/" + originToken + "@github.com/layervai/qurl-go.git"), wantError: errOriginMoved},
		// A URL client ends the host at these characters; a parser that only
		// strips through the last "@" reads the host as github.com.
		{name: "fragment before the at sign", mutate: setOrigin("https://evil.example#" + originToken + "@github.com/layervai/qurl-go.git"), wantError: errOriginShape},
		{name: "query before the at sign", mutate: setOrigin("https://evil.example?" + originToken + "@github.com/layervai/qurl-go.git"), wantError: errOriginShape},
		{name: "backslash before the at sign", mutate: setOrigin(`https://evil.example\` + originToken + "@github.com/layervai/qurl-go.git"), wantError: errOriginShape},
		{name: "second at sign in the authority", mutate: setOrigin("https://" + originToken + "@evil.example@github.com/layervai/qurl-go.git"), wantError: errOriginShape},
		{name: "scp-style remote", mutate: setOrigin("git@github.com:layervai/qurl-go.git"), wantError: errOriginShape},
		{name: "another local path", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "origin", filepath.Join(fixture.repository, ".git"))
		}, wantError: errOriginShape},

		{name: "extra remote", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "add", "exfil", credentialed("evil.example/layervai/qurl-go.git"))
		}, wantError: errRemoteSet},
		{name: "extra remote addressing this repository", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "add", "upstream", "https://github.com/layervai/qurl-go.git")
		}, wantError: errRemoteSet},
		{name: "push URL to another host", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "origin", credentialed("github.com/layervai/qurl-go.git"))
			runGit(t, fixture.repository, "remote", "set-url", "--push", "origin", credentialed("evil.example/layervai/qurl-go.git"))
		}, wantError: errRemoteSet},
		{name: "second fetch URL", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "--add", "origin", credentialed("evil.example/layervai/qurl-go.git"))
		}, wantError: errRemoteSet},
		{name: "fetch redirected by insteadOf", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "origin", credentialed("github.com/layervai/qurl-go.git"))
			runGit(t, fixture.repository, "config", "--local", "url.https://evil.example/.insteadOf", credentialed("github.com/"))
		}, wantError: errOriginMoved},
		{name: "push redirected by pushInsteadOf", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "remote", "set-url", "origin", credentialed("github.com/layervai/qurl-go.git"))
			runGit(t, fixture.repository, "config", "--local", "url.https://evil.example/.pushInsteadOf", credentialed("github.com/"))
		}, wantError: errOriginMoved},
		{name: "credential helper installed", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "config", "--local", "credential.helper", "store")
		}, wantError: errCredentialConfig},
		{name: "authorization header installed", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "config", "--local", "http.https://github.com/.extraheader", "AUTHORIZATION: basic "+originToken)
		}, wantError: errCredentialConfig},

		{name: "workflow-owned head snapshot moved", mutate: func(t *testing.T, fixture gitFixture, namespace string) {
			runGit(t, fixture.repository, "update-ref", namespace+"/head", fixture.baseSHA)
		}, wantError: errSnapshots},
		{name: "workflow-owned base snapshot deleted", mutate: func(t *testing.T, fixture gitFixture, namespace string) {
			runGit(t, fixture.repository, "update-ref", "-d", namespace+"/base")
		}, wantError: errSnapshots},
		{name: "workspace head branch moved", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "update-ref", "refs/heads/"+fixture.headRef, fixture.baseSHA)
		}, wantError: errSnapshots},
		{name: "local snapshot origin branch moved", mutate: func(t *testing.T, fixture gitFixture, _ string) {
			runGit(t, fixture.repository, "push", "--quiet", "--force", "origin", fixture.baseSHA+":refs/heads/"+fixture.headRef)
			runGit(t, fixture.repository, "update-ref", "refs/remotes/origin/"+fixture.headRef, fixture.headSHA)
		}, wantError: errSnapshots},

		{
			name: "no server URL from the runner", mutate: setOrigin(credentialed("github.com/layervai/qurl-go.git")),
			env: map[string]string{"GITHUB_SERVER_URL": ""}, wantError: errNoOriginTargets,
		},
		{
			name: "another server URL from the runner", mutate: setOrigin(credentialed("github.com/layervai/qurl-go.git")),
			env: map[string]string{"GITHUB_SERVER_URL": "https://ghes.example"}, wantError: errOriginMoved,
		},
	}

	for _, mode := range verifierModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					// Every case owns its fixture and temp directories.
					t.Parallel()
					fixture, verifyEnv := newVerifierFixture(t, mode.name, mode.extra)
					test.mutate(t, fixture, snapshotNamespace(mode.name))
					for key, value := range test.env {
						verifyEnv[key] = value
					}
					output := runScriptOutput(t, fixture.repository, verifyScript, verifyEnv, test.wantError == "")
					if test.wantError != "" && !strings.Contains(output, test.wantError) {
						t.Errorf("verifier failed for another reason:\n%s\nwant %q", output, test.wantError)
					}
					if strings.Contains(output, originToken) {
						t.Errorf("verifier printed the origin credential:\n%s", output)
					}
				})
			}
		})
	}
}

// The two lanes must not share a snapshot namespace: a ref written for one
// lane is not evidence for the other.
func TestTerminalVerifierSnapshotNamespaceIsPerLane(t *testing.T) {
	skipWithoutGNUTimeout(t)
	verifyScript := readWorkflowScript(t, "verify-claude-review.sh")
	for _, mode := range verifierModes {
		t.Run(mode.name, func(t *testing.T) {
			fixture, verifyEnv := newVerifierFixture(t, mode.name, mode.extra)
			own := snapshotNamespace(mode.name)
			other := "refs/claude-command"
			if own == other {
				other = "refs/automatic-review"
			}
			for _, side := range []string{"head", "base"} {
				sha := runGit(t, fixture.repository, "rev-parse", own+"/"+side)
				runGit(t, fixture.repository, "update-ref", other+"/"+side, sha)
				runGit(t, fixture.repository, "update-ref", "-d", own+"/"+side)
			}
			output := runScriptOutput(t, fixture.repository, verifyScript, verifyEnv, false)
			if !strings.Contains(output, errSnapshots) {
				t.Errorf("verifier failed for another reason:\n%s\nwant %q", output, errSnapshots)
			}
		})
	}
}

func TestExistingLintContextRunsActionlint(t *testing.T) {
	workflow := readWorkflow(t, "ci.yml")
	requireUniquePin(t, workflow, "reviewdog/action-actionlint")
	requireContains(t, workflow,
		"name: golangci-lint",
		"name: actionlint",
	)
	actionlint := strings.Index(workflow, "name: actionlint")
	golangciAction := strings.Index(workflow, "golangci/golangci-lint-action@")
	if actionlint == -1 || golangciAction == -1 || actionlint >= golangciAction {
		t.Errorf("actionlint step must run before golangci-lint action")
	}
}

func requireReadOnlyActionContract(t *testing.T, workflow string) {
	t.Helper()
	// Resolving each pin is the assertion: an absent, repeated, or mutable
	// reference fails inside requirePin.
	requirePin(t, workflow, claudeAction)
	requirePin(t, workflow, checkoutAction)
	requireContains(t, workflow,
		"github_token: ${{ github.token }}",
		"use_commit_signing: true",
		"contents: read",
		"pull-requests: write",
		"mcp__github__add_issue_comment",
		"Bash,Read,Glob,Grep,LS,Task,Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch",
		"mcp__github_file_ops__commit_files",
		"mcp__github__create_or_update_file",
	)
}

type gitFixture struct {
	repository string
	baseRef    string
	headRef    string
	baseSHA    string
	headSHA    string
}

func newGitFixture(t *testing.T) gitFixture {
	t.Helper()
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet", "--initial-branch=main")
	runGit(t, repository, "config", "user.name", "workflow test")
	runGit(t, repository, "config", "user.email", "workflow@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "base.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}
	runGit(t, repository, "add", "base.txt")
	runGit(t, repository, "commit", "--quiet", "-m", "base")
	baseSHA := runGit(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "switch", "--quiet", "-c", "feature/review")
	if err := os.WriteFile(filepath.Join(repository, "head.txt"), []byte("head\n"), 0o600); err != nil {
		t.Fatalf("write head fixture: %v", err)
	}
	runGit(t, repository, "add", "head.txt")
	runGit(t, repository, "commit", "--quiet", "-m", "head")
	headSHA := runGit(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "switch", "--quiet", "main")
	runGit(t, repository, "remote", "add", "origin", filepath.Join(repository, ".git"))
	return gitFixture{repository: repository, baseRef: "main", headRef: "feature/review", baseSHA: baseSHA, headSHA: headSHA}
}

func mockPullRequestJSON(t *testing.T, fixture gitFixture, state string, draft bool, defaultRef string) string {
	t.Helper()
	payload := map[string]any{
		"state": state,
		"draft": draft,
		"head": map[string]any{
			"sha":  fixture.headSHA,
			"ref":  fixture.headRef,
			"repo": map[string]string{"full_name": "layervai/qurl-go"},
		},
		"base": map[string]any{
			"sha": fixture.baseSHA,
			"ref": fixture.baseRef,
			"repo": map[string]string{
				"full_name":      "layervai/qurl-go",
				"default_branch": defaultRef,
			},
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal pull request fixture: %v", err)
	}
	return string(encoded)
}

func writeGHMock(t *testing.T) string {
	t.Helper()
	mockBin := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'/collaborators/'*)
    printf '%s\n' "${MOCK_PERMISSION:-write}"
    ;;
  *'/comments?'*)
    printf '%s\n' "${MOCK_COMMENTS_JSON:-[[]]}"
    ;;
  *)
    printf '%s\n' "${MOCK_PR_JSON}"
    ;;
esac
`
	path := filepath.Join(mockBin, "gh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write gh mock: %v", err)
	}
	return mockBin
}

func readStepOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read step outputs: %v", err)
	}
	outputs := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			outputs[key] = value
		}
	}
	return outputs
}

func cloneEnvironment(environment map[string]string) map[string]string {
	clone := make(map[string]string, len(environment))
	for key, value := range environment {
		clone[key] = value
	}
	return clone
}

// skipWithoutGNUTimeout guards tests whose extracted workflow scripts wrap gh
// calls in `timeout 30s`. GitHub runners always ship the coreutils binary;
// contributor machines may not (stock macOS has none), so the truthful
// condition is the binary lookup, not the operating system.
func skipWithoutGNUTimeout(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skipf("workflow step scripts need the GNU timeout binary, which is not on PATH; on macOS install it with Homebrew coreutils (brew install coreutils)")
	}
}

func runScript(t *testing.T, directory, script string, environment map[string]string, wantSuccess bool) {
	t.Helper()
	runScriptOutput(t, directory, script, environment, wantSuccess)
}

// runScriptOutput is runScript for callers that assert on what a step SAID, not
// only on whether it failed -- the whole point of a diagnosability gate.
func runScriptOutput(t *testing.T, directory, script string, environment map[string]string, wantSuccess bool) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "bash", "-c", script)
	command.Dir = directory
	controlled := map[string]string{
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"LANG":                "C",
		"LC_ALL":              "C",
		"TZ":                  "UTC",
	}
	for _, key := range []string{"HOME", "PATH", "TMPDIR"} {
		if value := os.Getenv(key); value != "" {
			controlled[key] = value
		}
	}
	for key, value := range environment {
		controlled[key] = value
	}
	keys := make([]string, 0, len(controlled))
	for key := range controlled {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		command.Env = append(command.Env, key+"="+controlled[key])
	}
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("script failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("script succeeded unexpectedly:\n%s", output)
	}
	return string(output)
}

func TestRunScriptDoesNotInheritWorkflowControlVariables(t *testing.T) {
	t.Setenv("MOCK_CANDIDATE_STATE", "closed")
	t.Setenv("QURL_GO_SANDBOX_PROOF_PHASE", "post_removal")
	t.Setenv("GITHUB_SHA", strings.Repeat("f", 40))
	runScript(t, t.TempDir(), `
		set -euo pipefail
		test -z "${MOCK_CANDIDATE_STATE:-}"
		test -z "${QURL_GO_SANDBOX_PROOF_PHASE:-}"
		test -z "${GITHUB_SHA:-}"
	`, nil, true)
}

func runGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = directory
	// Contributor git customization (commit.gpgsign, templates, hooks) must
	// not leak into fixture repositories; the identity the fixtures need is
	// written to repo-local config, which still applies.
	command.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workflowDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func readWorkflowScript(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workflowDir(t), "..", "scripts", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func workflowDir(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow contract path")
	}
	return filepath.Join(filepath.Dir(testFile), "..", "..", ".github", "workflows")
}

func requireContains(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(contents, fragment) {
			t.Errorf("workflow is missing required fragment %q", fragment)
		}
	}
}

func requireNotContains(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if strings.Contains(contents, fragment) {
			t.Errorf("workflow contains forbidden fragment %q", fragment)
		}
	}
}

func requireBefore(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	position := -1
	for _, fragment := range fragments {
		count := strings.Count(contents, fragment)
		if count != 1 {
			t.Errorf("ordered fragment %q appears %d times, want exactly once", fragment, count)
			continue
		}
		next := strings.Index(contents, fragment)
		if next <= position {
			t.Errorf("ordered fragment %q appears out of order", fragment)
		}
		position = next
	}
}
