package docscontract

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Word-boundary patterns (\b) so identifier substrings never false-positive:
// ConnectAgentRuntime must not match the banned names, and a banned name
// embedded in a longer identifier is not a match either.
var (
	reConnectAgentRuntime = regexp.MustCompile(`\bConnectAgentRuntime\b`)
	reDeploymentEnv       = regexp.MustCompile(`\bQURL_DEPLOYMENT\b`)
	readmeBannedSymbols   = []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: "RegisterAgentRuntime", re: regexp.MustCompile(`\bRegisterAgentRuntime\b`)},
		{name: "OpenRegisteredAgentRuntime", re: regexp.MustCompile(`\bOpenRegisteredAgentRuntime\b`)},
	}
)

// TestREADMEEnrollmentQuickstartAnchors is tier 4: the minimal anchors of the
// README's honest enrollment story.
//
//   - The enrollment quickstart fence calls ConnectAgentRuntime — the single
//     call that enrolls, resumes, or reopens on every start.
//   - No fence in that story resurrects the deleted RegisterAgentRuntime or
//     OpenRegisteredAgentRuntime entry points (word-boundary matching, so
//     ConnectAgentRuntime itself never false-positives; the live
//     OpenRegisteredAgent / OpenRegisteredAgentWithIdentity names do not
//     contain the banned tokens).
//   - The README mentions QURL_DEPLOYMENT at least once: pre-GA, the trust
//     root enrollment authenticates against comes from that deployment file.
func TestREADMEEnrollmentQuickstartAnchors(t *testing.T) {
	root := repoRoot(t)
	readme := filepath.Join(root, "README.md")
	data, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	fences := extractGoFences(t, root, readme)
	var connect []*goFence
	for i := range fences {
		if reConnectAgentRuntime.MatchString(fences[i].src()) {
			connect = append(connect, &fences[i])
		}
	}
	if len(connect) == 0 {
		t.Errorf("README.md has no go fence calling ConnectAgentRuntime; the enrollment quickstart lost its anchor — the README must keep showing the one-call enrollment story")
	}

	for _, f := range connect {
		for _, banned := range readmeBannedSymbols {
			for i, line := range f.lines {
				if banned.re.MatchString(line) {
					t.Errorf("README.md:%d: enrollment quickstart fence references %s — a deleted entry point; the honest story is ConnectAgentRuntime",
						f.docLine(i+1), banned.name)
				}
			}
		}
	}

	if !reDeploymentEnv.Match(data) {
		t.Errorf("README.md never mentions QURL_DEPLOYMENT; pre-GA, native opens and agent enrollment need the deployment file from LayerV setup, and the README must say so")
	}
}
