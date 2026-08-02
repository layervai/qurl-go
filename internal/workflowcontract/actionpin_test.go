package workflowcontract

// Action pins move. Dependabot rewrites the SHA in `.github/workflows` on
// every upstream release, so a second copy of that SHA inside this contract
// turns each bump into a red build that only a hand edit clears (#119). The
// helpers below derive pins from the workflows and assert the properties a
// bump must never change — every `uses:` is an immutable 40-hex commit pin
// carrying the version comment reviewers read, and an action used by more
// than one workflow carries the same pin in all of them — instead of
// restating one blessed SHA that Dependabot exists to replace.
//
// What this deliberately does not assert is that a pin holds a specific
// value. That property belongs to the supply-chain gates that survive a
// bump: dependency review, the pin-age quarantine, CodeQL's actions
// analysis, and required review on the default branch.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	claudeAction   = "anthropics/claude-code-action"
	checkoutAction = "actions/checkout"
)

var (
	// usesReference captures the `uses:` value and its trailing version
	// comment, for both step-level (`- uses:`) and job-level reusable
	// workflow references.
	usesReference = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*(\S+)(?:[ \t]*#[ \t]*(\S+))?[ \t]*$`)
	// commitPin matches `owner/repo[/path]@<40-hex>`. Anything shorter,
	// uppercased, or symbolic is a mutable reference the upstream owner can
	// repoint after review.
	commitPin = regexp.MustCompile(`^[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)
	// usesKey matches the bare `uses:` key. Comparing its hit count against
	// the parsed pins catches a reference whose formatting slipped past
	// usesReference, without counting the word inside prompts or comments.
	usesKey = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?uses:`)
)

// workflowPin is one `uses:` reference as it appears in a workflow.
type workflowPin struct {
	reference string // owner/repo[/path]@ref
	version   string // the `# vX.Y.Z` comment, empty when absent
	text      string // exact source text spanning reference through version
}

// action is the owner/repo[/path] half of the reference, present even when the
// ref itself is mutable so that violations can be reported against a name.
func (p workflowPin) action() string {
	name, _, _ := strings.Cut(p.reference, "@")
	return name
}

// immutable reports whether the reference is a full commit pin carrying the
// version comment. Both halves matter: the SHA is what upstream cannot
// repoint, and the comment is what makes the SHA reviewable.
func (p workflowPin) immutable() bool {
	return commitPin.MatchString(p.reference) && p.version != ""
}

// workflowPins extracts every `uses:` reference from a workflow, mutable ones
// included, so callers can reject rather than silently skip them.
func workflowPins(contents string) []workflowPin {
	var pins []workflowPin
	for _, match := range usesReference.FindAllStringSubmatchIndex(contents, -1) {
		pin := workflowPin{
			reference: contents[match[2]:match[3]],
			text:      contents[match[2]:match[3]],
		}
		if match[4] >= 0 {
			pin.version = contents[match[4]:match[5]]
			pin.text = contents[match[2]:match[5]]
		}
		pins = append(pins, pin)
	}
	return pins
}

// pinsFor selects the `uses:` references naming action. Every count in this
// file goes through it: a raw substring count would also match the action
// named inside a prompt or a comment, and the Claude workflows carry prompts
// long enough for that to eventually happen.
func pinsFor(contents, action string) []workflowPin {
	var found []workflowPin
	for _, pin := range workflowPins(contents) {
		if pin.action() == action {
			found = append(found, pin)
		}
	}
	return found
}

// uniquePin returns the immutable pin that every reference to action in
// contents shares. Two references to the same action at different SHAs is the
// drift a half-applied bump leaves behind, so it fails rather than picking one.
func uniquePin(contents, action string) (workflowPin, error) {
	found := pinsFor(contents, action)
	if len(found) == 0 {
		return workflowPin{}, fmt.Errorf("%s: no uses: reference", action)
	}
	for _, pin := range found {
		if !pin.immutable() {
			return workflowPin{}, fmt.Errorf(
				"%s: %q is not a 40-hex commit pin with a version comment", action, pin.text)
		}
		if pin.reference != found[0].reference {
			return workflowPin{}, fmt.Errorf(
				"%s: pinned to both %q and %q", action, found[0].reference, pin.reference)
		}
	}
	return found[0], nil
}

// solePin is uniquePin plus the requirement that action runs as exactly one
// step. It backs the ordering assertions, which need a unique anchor, and the
// steps where a second invocation would itself deserve review: another
// checkout inside a workflow that deliberately fetches one snapshot with
// persist-credentials disabled, or a second Claude run past the trust gate.
func solePin(contents, action string) (workflowPin, error) {
	pin, err := uniquePin(contents, action)
	if err != nil {
		return workflowPin{}, err
	}
	if count := len(pinsFor(contents, action)); count != 1 {
		return workflowPin{}, fmt.Errorf("%s: used %d times, want exactly once", action, count)
	}
	return pin, nil
}

// requirePin resolves the sole immutable pin for action and returns its source
// text, suitable for the ordering assertions. Resolving is itself the
// assertion: an absent, duplicated, or mutable reference fails here.
func requirePin(t *testing.T, contents, action string) string {
	t.Helper()
	pin, err := solePin(contents, action)
	if err != nil {
		t.Fatalf("resolve pin: %v", err)
	}
	return pin.text
}

// requireUniquePin asserts action is present and immutably pinned without
// constraining how many steps use it, for the pins that replaced a bare
// presence check and carry no ordering or single-step meaning.
func requireUniquePin(t *testing.T, contents, action string) {
	t.Helper()
	if _, err := uniquePin(contents, action); err != nil {
		t.Fatalf("resolve pin: %v", err)
	}
}

// TestEveryWorkflowActionIsImmutablyPinned holds the property the removed
// hardcoded SHAs used to imply for three actions, now across every action in
// every workflow: nothing runs from a tag or branch that upstream can repoint
// after this repository reviewed it.
func TestEveryWorkflowActionIsImmutablyPinned(t *testing.T) {
	for name, contents := range allWorkflows(t) {
		pins := workflowPins(contents)
		if len(pins) == 0 {
			continue
		}
		for _, pin := range pins {
			if !pin.immutable() {
				t.Errorf("%s: %q must be pinned to a 40-hex commit SHA with a version comment",
					name, pin.text)
			}
		}
	}
}

// TestActionsSharedAcrossWorkflowsUseOnePin generalizes the checkout-pin
// contract to every action: a bump that updates one workflow and forgets
// another leaves two SHAs behind, and that split is the failure worth naming.
func TestActionsSharedAcrossWorkflowsUseOnePin(t *testing.T) {
	references := make(map[string]map[string][]string)
	for name, contents := range allWorkflows(t) {
		for _, pin := range workflowPins(contents) {
			if references[pin.action()] == nil {
				references[pin.action()] = make(map[string][]string)
			}
			references[pin.action()][pin.reference] = append(
				references[pin.action()][pin.reference], name)
		}
	}
	for action, byReference := range references {
		if len(byReference) > 1 {
			t.Errorf("%s is pinned to %d different refs across workflows: %v",
				action, len(byReference), byReference)
		}
	}
}

// TestCheckoutIsPinnedEverywhere keeps checkout called out by name. It is the
// step that materializes untrusted pull request content, so a workflow that
// drifts to a different checkout than the rest of the repository is worth
// failing on its own line rather than inside a generic sweep.
func TestCheckoutIsPinnedEverywhere(t *testing.T) {
	pin := ""
	for name, contents := range allWorkflows(t) {
		if !strings.Contains(contents, checkoutAction+"@") {
			continue
		}
		resolved, err := uniquePin(contents, checkoutAction)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if pin == "" {
			pin = resolved.reference
			continue
		}
		if resolved.reference != pin {
			t.Errorf("%s pins checkout to %q, other workflows use %q", name, resolved.reference, pin)
		}
	}
	if pin == "" {
		t.Fatal("no workflow checks out the repository; expected the checkout pin contract to have a subject")
	}
}

// TestPinResolutionFailsClosed proves the helpers reject what the hardcoded
// SHAs used to reject. Without it, a parser that silently matched nothing
// would turn every contract above into a green no-op.
func TestPinResolutionFailsClosed(t *testing.T) {
	const sha = "be7b93b1907a4abad570368f3c74b6fe3807510b"
	const other = "fa7e2f0a29a126f0b81cdcf360561b36e44cf608"

	tests := []struct {
		name     string
		workflow string
		wantErr  string
	}{
		{
			name:     "major version tag",
			workflow: "      - uses: anthropics/claude-code-action@v1 # v1\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "exact version tag",
			workflow: "      - uses: anthropics/claude-code-action@v1.0.183 # v1.0.183\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "branch",
			workflow: "      - uses: anthropics/claude-code-action@main # main\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "abbreviated sha",
			workflow: "      - uses: anthropics/claude-code-action@be7b93b # v1.0.183\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "uppercase sha",
			workflow: "      - uses: anthropics/claude-code-action@" + strings.ToUpper(sha) + " # v1.0.183\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "missing version comment",
			workflow: "      - uses: anthropics/claude-code-action@" + sha + "\n",
			wantErr:  "not a 40-hex commit pin",
		},
		{
			name:     "absent",
			workflow: "      - uses: actions/checkout@" + sha + " # v7.0.0\n",
			wantErr:  "no uses: reference",
		},
		{
			name: "split across two shas",
			workflow: "      - uses: anthropics/claude-code-action@" + sha + " # v1.0.183\n" +
				"      - uses: anthropics/claude-code-action@" + other + " # v1.0.180\n",
			wantErr: "pinned to both",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := uniquePin(test.workflow, claudeAction)
			if err == nil {
				t.Fatalf("uniquePin(%q) succeeded, want error", test.workflow)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("uniquePin error = %v, want it to mention %q", err, test.wantErr)
			}
		})
	}

	t.Run("duplicate identical pins are not sole", func(t *testing.T) {
		workflow := strings.Repeat("      - uses: anthropics/claude-code-action@"+sha+" # v1.0.183\n", 2)
		if _, err := uniquePin(workflow, claudeAction); err != nil {
			t.Fatalf("uniquePin on matching duplicates = %v, want success", err)
		}
		if _, err := solePin(workflow, claudeAction); err == nil {
			t.Fatal("solePin on duplicates succeeded, want error")
		}
	})

	t.Run("action named in a prompt is not a use", func(t *testing.T) {
		// The Claude workflows pass multi-page prompts. Counting raw
		// occurrences instead of parsed uses: lines would let prose about an
		// action fail the workflow that merely describes it.
		workflow := "      - uses: anthropics/claude-code-action@" + sha + " # v1.0.183\n" +
			"        with:\n" +
			"          prompt: |\n" +
			"            Do not add anthropics/claude-code-action@" + other + " to any workflow.\n"
		pin, err := solePin(workflow, claudeAction)
		if err != nil {
			t.Fatalf("solePin = %v, want the prompt mention ignored", err)
		}
		if !strings.Contains(pin.reference, sha) {
			t.Fatalf("pin reference = %q, want the uses: pin %q", pin.reference, sha)
		}
	})

	t.Run("valid pin resolves to its source text", func(t *testing.T) {
		workflow := "      - uses: anthropics/claude-code-action@" + sha + " # v1.0.183\n"
		pin, err := solePin(workflow, claudeAction)
		if err != nil {
			t.Fatalf("solePin = %v, want success", err)
		}
		want := claudeAction + "@" + sha + " # v1.0.183"
		if pin.text != want {
			t.Fatalf("pin text = %q, want %q", pin.text, want)
		}
		if !strings.Contains(workflow, pin.text) {
			t.Fatalf("pin text %q is not a substring of the workflow it came from", pin.text)
		}
	})
}

// TestWorkflowPinsCoverEveryUsesLine guards the regex against silently
// skipping a reference style the repository actually writes: a parser that
// missed job-level `uses:` would exempt reusable workflows from every rule.
func TestWorkflowPinsCoverEveryUsesLine(t *testing.T) {
	for name, contents := range allWorkflows(t) {
		want := len(usesKey.FindAllString(contents, -1))
		if got := len(workflowPins(contents)); got != want {
			t.Errorf("%s: parsed %d uses: references, file has %d", name, got, want)
		}
	}
}

// allWorkflows reads every workflow definition keyed by file name.
func allWorkflows(t *testing.T) map[string]string {
	t.Helper()
	directory := workflowDir(t)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read workflow directory: %v", err)
	}
	workflows := make(map[string]string)
	for _, entry := range entries {
		extension := filepath.Ext(entry.Name())
		if entry.IsDir() || (extension != ".yml" && extension != ".yaml") {
			continue
		}
		workflows[entry.Name()] = readWorkflow(t, entry.Name())
	}
	if len(workflows) == 0 {
		t.Fatalf("no workflows found under %s", directory)
	}
	return workflows
}
