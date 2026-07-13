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

// When bumping this pin, re-verify that upstream action.yml still declares
// exclude_comments_by_actor and that actor-filter.ts retains the special
// *[bot] literal-suffix semantics. GitHub ignores unknown action inputs.
const claudeAction = "anthropics/claude-code-action@558b1d6cab4085c7753fe402c10bef0fbb92ac7a # v1.0.165"

func TestInteractiveClaudeWorkflowAuthorizesBeforeImmutableCheckout(t *testing.T) {
	workflow := readWorkflow(t, "claude.yml")

	requireContains(t, workflow,
		"timeout-minutes: 20",
		"Review-only by design",
		"github.event.comment.author_association == 'OWNER'",
		"github.event.comment.author_association == 'MEMBER'",
		"github.event.comment.author_association == 'COLLABORATOR'",
		"github.event.review.author_association == 'OWNER'",
		"github.event.review.author_association == 'MEMBER'",
		"github.event.review.author_association == 'COLLABORATOR'",
		"github.event.issue.author_association == 'OWNER'",
		"github.event.issue.author_association == 'MEMBER'",
		"github.event.issue.author_association == 'COLLABORATOR'",
		"TRIGGER_ACTOR: ${{ github.actor }}",
		"collaborators/$TRIGGER_ACTOR/permission",
		"admin|maintain|write",
		".head.repo.full_name // \"\"",
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
		"- name: Validate Claude trigger actor permission",
		"- name: Resolve Claude pull request context",
		"- name: Checkout repository",
		"- name: Run Claude Code",
	)
}

func TestAutomaticClaudeWorkflowPinsBoundedCommentAuthorInput(t *testing.T) {
	workflow := readWorkflow(t, "claude-code-review.yml")

	// The action filters GraphQL author.login. On this repository, historical
	// transcripts are authored by `claude` and `github-actions`; `*[bot]` alone
	// only matches actors whose login literally has that suffix.
	requireContains(t, workflow,
		"documented minimum permissions include both Issues",
		"github.event.pull_request.head.repo.full_name == github.repository",
		"job-level gate skips fork heads before checkout",
		"`pull_request` also withholds repository secrets",
		"Pinned v1.0.165 implements `*[bot]` as a literal [bot]-suffix",
	)
	requireSharedActionContract(t, workflow)
}

func requireSharedActionContract(t *testing.T, workflow string) {
	t.Helper()
	requireContains(t, workflow,
		claudeAction,
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
	previous := -1
	for _, fragment := range fragments {
		if count := strings.Count(contents, fragment); count != 1 {
			t.Errorf("ordered workflow contract fragment %q must appear exactly once; got %d", fragment, count)
			continue
		}
		position := strings.Index(contents, fragment)
		if position <= previous {
			t.Errorf("workflow contract fragment %q appears out of order", fragment)
		}
		previous = position
	}
}
