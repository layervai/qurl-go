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
const (
	claudeAction   = "anthropics/claude-code-action@558b1d6cab4085c7753fe402c10bef0fbb92ac7a # v1.0.165"
	checkoutAction = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
)

func TestInteractiveClaudeWorkflowAuthorizesBeforeImmutableCheckout(t *testing.T) {
	workflow := readWorkflow(t, "claude.yml")

	requireContains(t, workflow,
		"timeout-minutes: 20",
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`,
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.review.author_association)`,
		`contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.issue.author_association)`,
		"TRIGGER_ACTOR: ${{ github.actor }}",
		"admin|maintain|write",
		".head.sha // \"\"",
		`if [[ "$head_repo" != "$GITHUB_REPOSITORY" ]]`,
		`[[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]`,
		"steps.claude_actor.outputs.authorized == 'true'",
		"steps.claude_pr.outputs.checkout_allowed == 'true'",
		"ref: ${{ steps.claude_pr.outputs.sha != '' && steps.claude_pr.outputs.sha || github.sha }}",
		"if: steps.checkout.outcome == 'success'",
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

	// The action filters GraphQL author.login. On this repository, historical
	// transcripts are authored by `claude` and `github-actions`; `*[bot]` alone
	// only matches actors whose login literally has that suffix.
	requireContains(t, workflow,
		"github.actor != 'dependabot[bot]'",
		"github.event.pull_request.head.repo.full_name == github.repository",
	)
	requireSharedActionContract(t, workflow)
}

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
		"issues: write",
	)
	requireNotContains(t, workflow, "id-token: write")
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow contract test path")
	}
	path := filepath.Join(filepath.Dir(testFile), "..", "..", ".github", "workflows", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func requireContains(t *testing.T, contents string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(contents, fragment) {
			t.Errorf("workflow is missing required contract fragment %q", fragment)
		}
	}
}

func requireNotContains(t *testing.T, contents string, fragment string) {
	t.Helper()
	if strings.Contains(contents, fragment) {
		t.Errorf("workflow contains forbidden contract fragment %q", fragment)
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
