package workflowcontract

// The Claude action is pinned here by audit rather than by version:
// TestClaudeWorkflowsUseAuditedCredentialFreeAction rejects every pin but the
// one whose Git behavior was reviewed, because upstream v1.0.187 began
// rewriting origin to a token-bearing network URL on the use_commit_signing
// path while both Claude workflows deliberately point origin at a local bare
// repo holding an exact pull request snapshot.
//
// That makes each bump Dependabot opens red on arrival, so .github/dependabot.yml
// ignores the dependency instead of reopening one weekly (#182 was the last one
// closed by hand). The ignore entry is the only part of that boundary carried
// by configuration rather than by a test, and deleting it fails nothing on its
// own -- the red pull requests simply come back. Assert it against the same
// claudeAction constant the workflow pins resolve through, so the config and
// the audit cannot drift apart. Deletion is not the only drift that matters:
// an ignore narrowed with `update-types` or `versions` still names the
// dependency while letting the bumps it exists to stop come straight back, so
// the assertion reads each rule's conditions and requires this one to be
// unconditional.
//
// A subpath reference needs no separate assertion here. Dependabot would name
// such a dependency `anthropics/claude-code-action/<path>`, which this
// exact-string ignore would no longer match -- but pinsFor compares the action
// name for equality, so solePin(workflow, claudeAction) stops resolving and
// TestClaudeWorkflowsUseAuditedCredentialFreeAction goes red first.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	dependabotConfig   = ".github/dependabot.yml"
	dependabotWorkflow = "validate-dependabot-config.yml"
)

// GitHub parses the Dependabot config on its own servers and answers a
// malformed one with silence -- updates stop for every ecosystem it declares,
// reported only in this repository's Dependabot logs. validate-dependabot-config.yml
// is what turns that into a red check, which makes the workflow itself the
// boundary this file's other test warns about: a part carried by configuration
// that fails nothing when it is deleted or quietly repointed. The path filter
// is the subtle half. Naming only the workflow and not the config it guards
// would leave it green forever while never running on the edit that matters.
//
// The config's own header advertises this gate, so the claim is load-bearing
// too: a reader who trusts that line after the workflow is gone is back to the
// silence the gate exists to end. Assert it here, where `vet + test -race`
// is a required check and the path-filtered workflow is not.
func TestDependabotConfigIsSchemaChecked(t *testing.T) {
	workflow := readWorkflow(t, dependabotWorkflow)
	requireContains(t, workflow,
		"check-jsonschema --builtin-schema vendor.dependabot "+dependabotConfig,
		"if [[ ! -f "+dependabotConfig+" ]]; then",
	)
	// Once under push, once under pull_request.
	if got := strings.Count(workflow, `      - "`+dependabotConfig+`"`); got != 2 {
		t.Errorf("path filter names %s %d times, want 2 (push and pull_request)",
			dependabotConfig, got)
	}
	// `validate` is already a required context on main, from pr-title.yml. A
	// second job answering to that name is indistinguishable from it in branch
	// protection.
	requireNotContains(t, workflow, "\n  validate:\n")

	if config := readDependabotConfig(t); !strings.Contains(config, dependabotWorkflow) {
		t.Errorf("%s does not name %s; its header claims to be schema-checked by it",
			dependabotConfig, dependabotWorkflow)
	}
}

func TestDependabotIgnoresTheAuditedClaudeAction(t *testing.T) {
	block, err := updateEntry(readDependabotConfig(t), "github-actions")
	if err != nil {
		t.Fatalf("locate update entry: %v", err)
	}
	rules := ignoreRules(block)
	i := slices.IndexFunc(rules, func(r ignoreRule) bool { return r.dependency == claudeAction })
	if i < 0 {
		t.Fatalf("github-actions updates ignore %v, want %s among them",
			ignoredNames(rules), claudeAction)
	}
	if conditions := rules[i].conditions; len(conditions) > 0 {
		t.Errorf("%s is ignored only under %v; the audited pin needs every bump suppressed, not a subset",
			claudeAction, conditions)
	}
}

// readDependabotConfig returns .github/dependabot.yml as text. The contract
// tests carry no YAML dependency -- go.mod is a security floor this repository
// keeps deliberately small -- so the readers below scan the document by
// indentation, which is also what lets them assert placement rather than mere
// presence.
func readDependabotConfig(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workflowDir(t), "..", "dependabot.yml"))
	if err != nil {
		t.Fatalf("read dependabot.yml: %v", err)
	}
	return string(contents)
}

// updateEntry returns the lines of the `updates:` item for ecosystem, ending at
// the next item at the same indent. Bounding the entry is the point: without it
// an assertion about github-actions could be satisfied by configuration that
// belongs to gomod. Dependabot allows one entry per ecosystem per directory, so
// a second declaration is an error here rather than a silent first-match. This
// repository updates only `/`; a second directory would want the reader keyed
// on both fields rather than a choice between two entries.
func updateEntry(config, ecosystem string) ([]string, error) {
	lines := strings.Split(config, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) != "- package-ecosystem: "+ecosystem {
			continue
		}
		if start >= 0 {
			return nil, fmt.Errorf("%s: declared more than once", ecosystem)
		}
		start = i
	}
	if start < 0 {
		return nil, fmt.Errorf("%s: no updates entry", ecosystem)
	}
	for i := start + 1; i < len(lines); i++ {
		if indentOf(lines[i]) == indentOf(lines[start]) && strings.HasPrefix(strings.TrimSpace(lines[i]), "- ") {
			return lines[start:i], nil
		}
	}
	return lines[start:], nil
}

// ignoreRule is one item under an entry's `ignore:` key. conditions holds the
// item's other keys -- `update-types`, `versions` -- which narrow the rule to a
// slice of releases. An unconditional rule has none, and only an unconditional
// rule suppresses every bump.
type ignoreRule struct {
	dependency string
	conditions []string
}

// ignoreRules returns the rules under the entry's own `ignore:` key. The key is
// matched at the entry's key depth exactly, so an `ignore` nested inside
// `groups` is not read, and the run ends at the next key at that depth.
//
// Reading conditions rather than names alone is what closes the narrowing path:
// a rule that keeps the dependency but adds `update-types` reads as present to
// any name-only check while Dependabot resumes opening everything outside that
// slice. A reader that finds nothing returns nil and fails the assertion, so
// the absent and narrowed cases both fail closed.
func ignoreRules(entry []string) []ignoreRule {
	if len(entry) == 0 {
		return nil
	}
	keyDepth := indentOf(entry[0]) + len("- ")
	var rules []ignoreRule
	inIgnore := false
	listDepth := -1
	for _, line := range entry[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		depth := indentOf(line)
		if depth <= keyDepth {
			inIgnore = depth == keyDepth && trimmed == "ignore:"
			listDepth = -1
			continue
		}
		if !inIgnore {
			continue
		}
		if item, ok := strings.CutPrefix(trimmed, "- "); ok {
			if listDepth < 0 {
				listDepth = depth
			}
			// A `- ` line deeper than the list's own indent is a sequence
			// value belonging to the current rule's key, not a new rule.
			if depth != listDepth {
				continue
			}
			key, value, _ := strings.Cut(item, ":")
			if key != "dependency-name" {
				rules = append(rules, ignoreRule{conditions: []string{key}})
				continue
			}
			rules = append(rules, ignoreRule{dependency: unquoted(value)})
			continue
		}
		// A key indented past the list marker is a sibling of the current
		// rule's `dependency-name`, so it narrows that rule.
		if listDepth >= 0 && depth > listDepth && len(rules) > 0 {
			key, _, _ := strings.Cut(trimmed, ":")
			last := &rules[len(rules)-1]
			last.conditions = append(last.conditions, key)
		}
	}
	return rules
}

// ignoredNames reports the dependencies named by rules, for the failure message
// that has to say what the entry ignores instead.
func ignoredNames(rules []ignoreRule) []string {
	var names []string
	for _, rule := range rules {
		if rule.dependency != "" {
			names = append(names, rule.dependency)
		}
	}
	return names
}

// unquoted returns the scalar a value position holds, without the quotes YAML
// allows around it or a trailing comment. The comment matters because the entry
// this reads is heavily commented: `- dependency-name: "x"  # audited pin` is a
// plausible next edit, and a reader that kept the comment would report a
// dependency nothing ignores and red a config that is correct.
func unquoted(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[1 : 1+end]
		}
	}
	// Unquoted, a `#` opens a comment only where whitespace precedes it, so a
	// `#` inside the scalar itself survives.
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	return value
}

// indentOf counts leading spaces. YAML forbids tabs for indentation, so spaces
// are the whole story.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func TestUnquotedReadsTheScalarWithoutItsComment(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: ` "anthropics/claude-code-action"`, want: claudeAction},
		{value: ` anthropics/claude-code-action`, want: claudeAction},
		{value: ` "anthropics/claude-code-action"  # audited pin`, want: claudeAction},
		{value: ` anthropics/claude-code-action # audited pin`, want: claudeAction},
		{value: ` 'anthropics/claude-code-action'`, want: claudeAction},
		{value: ` sharp#inside`, want: "sharp#inside"},
	} {
		t.Run(strings.TrimSpace(test.value), func(t *testing.T) {
			if got := unquoted(test.value); got != test.want {
				t.Errorf("unquoted(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

// twoEcosystems mirrors the shape of the real file: both ecosystems carry an
// ignore, and the github-actions entry is followed by nested mappings deeper
// than its own keys.
const twoEcosystems = `version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    ignore:
      - dependency-name: "example.com/gomod-only"
  - package-ecosystem: github-actions
    directory: /
    ignore:
      - dependency-name: "anthropics/claude-code-action"
    groups:
      codeql-action:
        patterns:
          - "github/codeql-action*"
`

func TestUpdateEntryBoundsOneEcosystem(t *testing.T) {
	for _, test := range []struct {
		name      string
		config    string
		ecosystem string
		want      []string
		wantErr   bool
	}{
		{
			name:      "reads its own ignore, not the neighbor's",
			config:    twoEcosystems,
			ecosystem: "github-actions",
			want:      []string{claudeAction},
		},
		{
			name:      "the neighbor keeps its own",
			config:    twoEcosystems,
			ecosystem: "gomod",
			want:      []string{"example.com/gomod-only"},
		},
		{
			name:      "absent ecosystem is an error, not an empty result",
			config:    twoEcosystems,
			ecosystem: "npm",
			wantErr:   true,
		},
		{
			name: "a duplicated ecosystem is an error rather than a first match",
			config: "version: 2\nupdates:\n" +
				"  - package-ecosystem: github-actions\n" +
				"  - package-ecosystem: github-actions\n",
			ecosystem: "github-actions",
			wantErr:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry, err := updateEntry(test.config, test.ecosystem)
			if test.wantErr {
				if err == nil {
					t.Fatalf("updateEntry(%s) = %q, want error", test.ecosystem, entry)
				}
				return
			}
			if err != nil {
				t.Fatalf("updateEntry(%s): %v", test.ecosystem, err)
			}
			if got := ignoredNames(ignoreRules(entry)); !slices.Equal(got, test.want) {
				t.Errorf("ignoredNames = %v, want %v", got, test.want)
			}
		})
	}
}

func TestIgnoreRulesReadsScopeAndPlacement(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry string
		want  []ignoreRule
	}{
		{
			name: "an ignore nested inside groups is not the entry's ignore",
			entry: "  - package-ecosystem: github-actions\n" +
				"    groups:\n" +
				"      ignore:\n" +
				"        patterns:\n" +
				"          - dependency-name: \"nested\"\n",
			want: nil,
		},
		{
			name: "the run ends at the next key, so later nesting is not ignored",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      - dependency-name: \"first\"\n" +
				"    groups:\n" +
				"      later:\n" +
				"        patterns:\n" +
				"          - dependency-name: \"not-ignored\"\n",
			want: []ignoreRule{{dependency: "first"}},
		},
		{
			name: "comments and blank lines inside the run do not end it",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      # why this one is pinned by audit\n" +
				"\n" +
				"      - dependency-name: anthropics/claude-code-action\n",
			want: []ignoreRule{{dependency: claudeAction}},
		},
		{
			name: "an inline update-types narrows the rule",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      - dependency-name: \"anthropics/claude-code-action\"\n" +
				"        update-types: [\"version-update:semver-patch\"]\n",
			want: []ignoreRule{{dependency: claudeAction, conditions: []string{"update-types"}}},
		},
		{
			name: "a sequence-valued update-types narrows one rule, not two",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      - dependency-name: \"anthropics/claude-code-action\"\n" +
				"        update-types:\n" +
				"          - \"version-update:semver-major\"\n",
			want: []ignoreRule{{dependency: claudeAction, conditions: []string{"update-types"}}},
		},
		{
			name: "conditions attach to their own rule",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      - dependency-name: \"anthropics/claude-code-action\"\n" +
				"      - dependency-name: \"other/action\"\n" +
				"        versions: [\"1.x\"]\n",
			want: []ignoreRule{
				{dependency: claudeAction},
				{dependency: "other/action", conditions: []string{"versions"}},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ignoreRules(strings.Split(test.entry, "\n"))
			if !slices.EqualFunc(got, test.want, func(a, b ignoreRule) bool {
				return a.dependency == b.dependency && slices.Equal(a.conditions, b.conditions)
			}) {
				t.Errorf("ignoreRules = %+v, want %+v", got, test.want)
			}
		})
	}
}
