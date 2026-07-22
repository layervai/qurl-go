// Package workflowcontract locks the repository's secret-bearing workflow
// boundary. The fixture tests execute the credential-free origin preparation;
// the hosted action itself remains covered by its immutable pin and actionlint.
package workflowcontract

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	claudeAction   = "anthropics/claude-code-action@fa7e2f0a29a126f0b81cdcf360561b36e44cf608 # v1.0.180"
	checkoutAction = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
)

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
		".base.repo.default_branch",
		"ref: ${{ steps.review_pr.outputs.default_branch }}",
		"fetch-depth: 0",
		"persist-credentials: false",
		"Prepare credential-free review origin",
		"git init --bare --quiet",
		"git config --local fetch.recurseSubmodules false",
		"use_commit_signing: true",
		"classify_inline_comments: false",
		"Read CONTRIBUTING.md at AUTHORIZED BASE SHA",
		"steps.claude_review.outputs.execution_file",
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
		"Prepare credential-free review origin",
		claudeAction,
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
		`state}" != "open"`,
		`head_repo}" != "${GITHUB_REPOSITORY}"`,
		`base_repo}" != "${GITHUB_REPOSITORY}"`,
		`default_ref}" != "${TRUSTED_DEFAULT_REF}"`,
		`head_ref}" == "${default_ref}"`,
		".base.repo.default_branch",
		"ref: ${{ steps.claude_pr.outputs.default_branch }}",
		"Prepare credential-free Claude origin",
		"do not edit or commit files",
		"steps.claude.outputs.execution_file",
		"Claude trigger actor lost repository write access",
		"Claude command is stale or the PR trust boundary changed",
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
		"Resolve Claude pull request context",
		checkoutAction,
		"Prepare credential-free Claude origin",
		claudeAction,
		"Verify reviewed pull request snapshots",
	)
}

func TestCredentialFreeOriginPreparationExecutes(t *testing.T) {
	tests := []struct {
		name     string
		workflow string
		step     string
		extra    map[string]string
	}{
		{
			name: "automatic", workflow: "claude-code-review.yml", step: "Prepare credential-free review origin",
			extra: map[string]string{
				"EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
				"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
				"PR_NUMBER": "93", "RUN_ID": "123", "RUN_ATTEMPT": "1",
			},
		},
		{name: "interactive", workflow: "claude.yml", step: "Prepare credential-free Claude origin"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			env := map[string]string{
				"GITHUB_REPOSITORY":   "layervai/qurl-go",
				"GITHUB_OUTPUT":       filepath.Join(t.TempDir(), "outputs"),
				"RUNNER_TEMP":         t.TempDir(),
				"EXPECTED_HEAD_SHA":   fixture.headSHA,
				"EXPECTED_HEAD_REF":   fixture.headRef,
				"EXPECTED_BASE_SHA":   fixture.baseSHA,
				"EXPECTED_BASE_REF":   fixture.baseRef,
				"TRUSTED_DEFAULT_REF": fixture.baseRef,
			}
			for key, value := range test.extra {
				env[key] = value
			}
			runScript(t, fixture.repository, stepRun(t, readWorkflow(t, test.workflow), test.step), env, true)
			outputs, err := os.ReadFile(env["GITHUB_OUTPUT"])
			if err != nil {
				t.Fatalf("read workflow outputs: %v", err)
			}
			if !strings.Contains(string(outputs), "ready=true") {
				t.Fatalf("workflow outputs = %q, want ready=true", outputs)
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
	workflow := readWorkflow(t, "claude-code-review.yml")
	script := stepRun(t, workflow, "Prepare credential-free review origin")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			env := map[string]string{
				"GITHUB_REPOSITORY": "layervai/qurl-go", "GITHUB_OUTPUT": filepath.Join(t.TempDir(), "outputs"),
				"RUNNER_TEMP": t.TempDir(), "EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
				"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
				"EXPECTED_HEAD_SHA": fixture.headSHA, "EXPECTED_HEAD_REF": fixture.headRef,
				"EXPECTED_BASE_SHA": fixture.baseSHA, "EXPECTED_BASE_REF": fixture.baseRef,
				"TRUSTED_DEFAULT_REF": fixture.baseRef, "PR_NUMBER": "93", "RUN_ID": "123", "RUN_ATTEMPT": "1",
			}
			for key, value := range test.env {
				env[key] = value
			}
			runScript(t, fixture.repository, script, env, false)
		})
	}
}

func TestLivePRResolversRejectUnsafeCurrentState(t *testing.T) {
	tests := []struct {
		name     string
		workflow string
		step     string
		extra    func(gitFixture) map[string]string
	}{
		{
			name: "automatic", workflow: "claude-code-review.yml", step: "Resolve live review context",
			extra: func(fixture gitFixture) map[string]string {
				return map[string]string{
					"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
					"EXPECTED_HEAD_SHA": fixture.headSHA, "EXPECTED_HEAD_REF": fixture.headRef,
					"EXPECTED_BASE_SHA": fixture.baseSHA, "EXPECTED_BASE_REF": fixture.baseRef,
				}
			},
		},
		{
			name: "interactive", workflow: "claude.yml", step: "Resolve Claude pull request context",
			extra: func(fixture gitFixture) map[string]string {
				return map[string]string{"TRUSTED_DEFAULT_REF": fixture.baseRef}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			mockBin := writeGHMock(t)
			script := stepRun(t, readWorkflow(t, test.workflow), test.step)
			baseEnv := map[string]string{
				"PATH":              mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GH_TOKEN":          "test-token",
				"GITHUB_REPOSITORY": "layervai/qurl-go",
				"GITHUB_OUTPUT":     filepath.Join(t.TempDir(), "outputs"),
				"PR_NUMBER":         "100",
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

func TestTerminalVerifiersRejectUnsafeCurrentState(t *testing.T) {
	tests := []struct {
		name        string
		workflow    string
		prepareStep string
		verifyStep  string
		extra       map[string]string
	}{
		{
			name: "automatic", workflow: "claude-code-review.yml",
			prepareStep: "Prepare credential-free review origin", verifyStep: "Verify reviewed pull request snapshots",
			extra: map[string]string{
				"EXPECTED_STATE": "open", "EXPECTED_DRAFT": "false",
				"EXPECTED_HEAD_REPO": "layervai/qurl-go", "EXPECTED_BASE_REPO": "layervai/qurl-go",
				"PR_NUMBER": "100", "RUN_ID": "123", "RUN_ATTEMPT": "1",
			},
		},
		{
			name: "interactive", workflow: "claude.yml",
			prepareStep: "Prepare credential-free Claude origin", verifyStep: "Verify reviewed pull request snapshots",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitFixture(t)
			outputFile := filepath.Join(t.TempDir(), "outputs")
			prepareEnv := map[string]string{
				"GITHUB_REPOSITORY":   "layervai/qurl-go",
				"GITHUB_OUTPUT":       outputFile,
				"RUNNER_TEMP":         t.TempDir(),
				"EXPECTED_HEAD_SHA":   fixture.headSHA,
				"EXPECTED_HEAD_REF":   fixture.headRef,
				"EXPECTED_BASE_SHA":   fixture.baseSHA,
				"EXPECTED_BASE_REF":   fixture.baseRef,
				"TRUSTED_DEFAULT_REF": fixture.baseRef,
			}
			for key, value := range test.extra {
				prepareEnv[key] = value
			}
			runScript(t, fixture.repository, stepRun(t, readWorkflow(t, test.workflow), test.prepareStep), prepareEnv, true)
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

			mockBin := writeGHMock(t)
			verifyEnv := map[string]string{
				"PATH":                  mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GH_TOKEN":              "test-token",
				"GITHUB_REPOSITORY":     "layervai/qurl-go",
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
			if test.name == "automatic" {
				verifyEnv["EXPECTED_REVIEW_MARKER"] = marker
			} else {
				verifyEnv["EXPECTED_TRIGGER_ACTOR"] = "maintainer"
				verifyEnv["EXPECTED_RESULT_MARKER"] = marker
			}
			verifier := stepRun(t, readWorkflow(t, test.workflow), test.verifyStep)
			runScript(t, fixture.repository, verifier, verifyEnv, true)

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
					runScript(t, fixture.repository, verifier, env, false)
				})
			}
		})
	}
}

func TestEveryWorkflowPinsCheckout(t *testing.T) {
	entries, err := os.ReadDir(workflowDir(t))
	if err != nil {
		t.Fatalf("read workflow directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yml" && filepath.Ext(entry.Name()) != ".yaml") {
			continue
		}
		workflow := readWorkflow(t, entry.Name())
		if got, want := strings.Count(workflow, checkoutAction), strings.Count(workflow, "actions/checkout@"); got != want {
			t.Errorf("%s has %d checkout uses but %d exact pins", entry.Name(), want, got)
		}
	}
}

func TestExistingLintContextRunsActionlint(t *testing.T) {
	workflow := readWorkflow(t, "ci.yml")
	requireContains(t, workflow,
		"name: golangci-lint",
		"name: actionlint",
		"reviewdog/action-actionlint@6fb7acc99f4a1008869fa8a0f09cfca740837d9d # v1.72.0",
	)
	actionlint := strings.Index(workflow, "name: actionlint")
	golangciAction := strings.Index(workflow, "golangci/golangci-lint-action@")
	if actionlint == -1 || golangciAction == -1 || actionlint >= golangciAction {
		t.Errorf("actionlint step must run before golangci-lint action")
	}
}

func requireReadOnlyActionContract(t *testing.T, workflow string) {
	t.Helper()
	requireContains(t, workflow,
		claudeAction,
		checkoutAction,
		"github_token: ${{ github.token }}",
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

func stepRun(t *testing.T, workflow, name string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	stepStart := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == "- name: "+name {
			stepStart = index
			break
		}
	}
	if stepStart == -1 {
		t.Fatalf("workflow is missing step %q", name)
	}
	runStart := -1
	for index := stepStart + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], "      - name:") {
			break
		}
		if strings.TrimSpace(lines[index]) == "run: |" {
			runStart = index + 1
			break
		}
	}
	if runStart == -1 {
		t.Fatalf("step %q has no run block", name)
	}
	var script []string
	for index := runStart; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "      - name:") {
			break
		}
		if line == "" {
			script = append(script, "")
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			break
		}
		script = append(script, strings.TrimPrefix(line, "          "))
	}
	return strings.Join(script, "\n")
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

func runScript(t *testing.T, directory, script string, environment map[string]string, wantSuccess bool) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "bash", "-c", script)
	command.Dir = directory
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("script failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("script succeeded unexpectedly:\n%s", output)
	}
}

func runGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = directory
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
