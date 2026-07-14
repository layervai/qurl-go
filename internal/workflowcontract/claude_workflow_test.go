// Package workflowcontract intentionally locks exact security-sensitive
// workflow text. These tests detect configuration drift; they do not execute
// the pinned third-party action or replace verification of its input semantics.
package workflowcontract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// When bumping claudeAction, re-verify that upstream action.yml still declares
// exclude_comments_by_actor and that actor-filter.ts retains the special
// *[bot] literal-suffix semantics. GitHub ignores unknown action inputs.
// Sources:
// https://github.com/anthropics/claude-code-action/blob/558b1d6cab4085c7753fe402c10bef0fbb92ac7a/action.yml#L51-L54
// https://github.com/anthropics/claude-code-action/blob/558b1d6cab4085c7753fe402c10bef0fbb92ac7a/src/github/utils/actor-filter.ts#L17-L21
const (
	claudeAction   = "anthropics/claude-code-action@558b1d6cab4085c7753fe402c10bef0fbb92ac7a # v1.0.165"
	checkoutAction = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
)

func TestInteractiveClaudeWorkflowAuthorizesBeforeImmutableCheckout(t *testing.T) {
	workflow := readWorkflow(t, "claude.yml")

	requireContains(t, workflow,
		"timeout-minutes: 20",
		"types: [opened]",
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`,
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.review.author_association)`,
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.issue.author_association)`,
		"TRIGGER_ACTOR: ${{ github.actor }}",
		"admin|write",
		".head.sha // \"\"",
		`if [[ "$head_repo" != "$GITHUB_REPOSITORY" ]]`,
		`[[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]`,
		"steps.claude_actor.outputs.authorized == 'true'",
		"steps.claude_pr.outputs.checkout_allowed == 'true'",
		"ref: ${{ steps.claude_pr.outputs.sha != '' && steps.claude_pr.outputs.sha || github.sha }}",
		"fetch-depth: ${{ steps.claude_pr.outputs.sha != '' && '0' || '1' }}",
		"if: steps.checkout.outcome == 'success'",
		"issues: write",
	)
	requireSharedActionContract(t, workflow)
	requireBefore(t, workflow,
		"collaborators/$TRIGGER_ACTOR/permission",
		".head.repo.full_name // \"\"",
		checkoutAction,
		claudeAction,
	)
}

func TestAutomaticClaudeWorkflowPinsBoundedCommentAuthorInput(t *testing.T) {
	workflow := readWorkflow(t, "claude-code-review.yml")

	requireContains(t, workflow,
		"group: claude-review-${{ github.event.pull_request.number }}",
		"cancel-in-progress: true",
		"github.actor != 'dependabot[bot]'",
		"github.event.pull_request.head.repo.full_name == github.repository",
		"issues: read",
	)
	requireSharedActionContract(t, workflow)
	requireNotContains(t, workflow, "issues: write")
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
		checkoutUses := strings.Count(workflow, "actions/checkout@")
		if pinnedUses := strings.Count(workflow, checkoutAction); pinnedUses != checkoutUses {
			t.Errorf("%s has %d actions/checkout uses but %d match the repository pin", entry.Name(), checkoutUses, pinnedUses)
		}
	}
}

// requireSharedActionContract verifies the action and permissions shared by
// both workflows. The action filters GraphQL author.login: historical
// transcripts use `claude` and `github-actions`, while `*[bot]` only matches
// actors whose login literally has that suffix.
func requireSharedActionContract(t *testing.T, workflow string) {
	t.Helper()
	requireContains(t, workflow,
		claudeAction,
		checkoutAction,
		"contents: read",
		"github_token: ${{ github.token }}",
		"persist-credentials: false",
		"exclude_comments_by_actor: 'claude,github-actions,*[bot]'",
		"pull-requests: write",
	)
	requireNotContains(t, workflow, "id-token: write")
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(workflowDir(t), name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func workflowDir(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow contract test path")
	}
	return filepath.Join(filepath.Dir(testFile), "..", "..", ".github", "workflows")
}

func requireContains(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(contents, fragment) {
			t.Errorf("workflow is missing required contract fragment %q", fragment)
		}
	}
}

func requireNotContains(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if strings.Contains(contents, fragment) {
			t.Errorf("workflow contains forbidden contract fragment %q", fragment)
		}
	}
}

func requireBefore(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	positions := make([]int, len(fragments))
	allUnique := true
	for i, fragment := range fragments {
		if count := strings.Count(contents, fragment); count != 1 {
			t.Errorf("ordered workflow contract fragment %q must appear exactly once; got %d", fragment, count)
			allUnique = false
			continue
		}
		positions[i] = strings.Index(contents, fragment)
	}
	if !allUnique {
		// Ordering is undefined until every anchor is unique; the cardinality
		// diagnostics above identify the prerequisite contract failures.
		return
	}
	for i := 1; i < len(fragments); i++ {
		if positions[i] <= positions[i-1] {
			t.Errorf("workflow contract fragment %q appears out of order", fragments[i])
		}
	}
}
