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
// the audit cannot drift apart.
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

func TestDependabotIgnoresTheAuditedClaudeAction(t *testing.T) {
	block, err := updateEntry(readDependabotConfig(t), "github-actions")
	if err != nil {
		t.Fatalf("locate update entry: %v", err)
	}
	if ignored := ignoredDependencies(block); !slices.Contains(ignored, claudeAction) {
		t.Errorf("github-actions updates ignore %v, want %s among them", ignored, claudeAction)
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
// belongs to gomod. A second declaration of the same ecosystem is an error
// rather than a silent first-match, since the two would disagree.
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

// ignoredDependencies returns the names the entry ignores. Only
// `- dependency-name:` items under the entry's own `ignore:` key count: the key
// is matched at the entry's key depth exactly, so an `ignore` nested inside
// `groups` is not read, and the run ends at the next key at that depth.
//
// Every failure mode here is closed. A reader that finds nothing returns nil
// and the assertion fails; it cannot report an ignore that is not there.
func ignoredDependencies(entry []string) []string {
	if len(entry) == 0 {
		return nil
	}
	keyDepth := indentOf(entry[0]) + len("- ")
	var names []string
	inIgnore := false
	for _, line := range entry[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if depth := indentOf(line); depth <= keyDepth {
			inIgnore = depth == keyDepth && trimmed == "ignore:"
			continue
		}
		if !inIgnore {
			continue
		}
		if name, ok := strings.CutPrefix(trimmed, "- dependency-name:"); ok {
			names = append(names, strings.Trim(strings.TrimSpace(name), `"'`))
		}
	}
	return names
}

// indentOf counts leading spaces. YAML forbids tabs for indentation, so spaces
// are the whole story.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
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
			if got := ignoredDependencies(entry); !slices.Equal(got, test.want) {
				t.Errorf("ignoredDependencies = %v, want %v", got, test.want)
			}
		})
	}
}

func TestIgnoredDependenciesReadsOnlyTheEntrysOwnIgnore(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry string
		want  []string
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
			want: []string{"first"},
		},
		{
			name: "comments and blank lines inside the run do not end it",
			entry: "  - package-ecosystem: github-actions\n" +
				"    ignore:\n" +
				"      # why this one is pinned by audit\n" +
				"\n" +
				"      - dependency-name: anthropics/claude-code-action\n",
			want: []string{claudeAction},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ignoredDependencies(strings.Split(test.entry, "\n")); !slices.Equal(got, test.want) {
				t.Errorf("ignoredDependencies = %v, want %v", got, test.want)
			}
		})
	}
}
