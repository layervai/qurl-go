package workflowcontract

// The OTP gate's strict short-pool error tells an operator, in the message
// printed by a REQUIRED check, that setting the single-credential variable
// "does not clear this" because no workflow maps it in. That is a claim about
// EVERY workflow, so it is fenced against every workflow rather than against
// the two that happen to spend the pool today -- a third one wiring the
// variable would otherwise make the message misdirect again, silently, which
// is the exact defect the reword removed.
//
// This lives here rather than beside the message because `allWorkflows` is
// here: the nativeudp test that owns the message can only reach workflows by
// hardcoded relative path, which is how a two-file fence gets written for a
// universal claim.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// otpEnrollmentEnvPattern extracts the single-credential variable's NAME from
// the Go source that defines it, rather than restating it.
//
// Restating would break the fence open on a rename: the constant would move,
// every workflow would keep not wiring the new spelling, and this test would
// keep passing against a name nothing uses. Deriving it means a rename either
// carries through or fails loudly here.
var otpEnrollmentEnvPattern = regexp.MustCompile(
	`otpE2EEnrollmentEnv\s*=\s*"([A-Z0-9_]+)"`)

// otpRegistrationSourcePath is the file that owns the constant, the message
// making the claim, and the job-summary writer fenced below. Reading across
// into tests/e2e is the same move public_estate_identifiers_test.go makes.
const otpRegistrationSourcePath = "tests/e2e/nativeudp/otp_registration_idempotency_test.go"

func TestNoWorkflowWiresTheSingleOTPCredentialVariable(t *testing.T) {
	variable := singleCredentialVariableName(t)
	name := regexp.QuoteMeta(variable)

	// ANCHORED, not a substring scan. claude.yml and claude-code-review.yml
	// embed multi-page prompts as block scalars, and this package already
	// rejects raw substring counting for that reason -- see actionpin_test.go's
	// "action named in a prompt is not a use". A fence that reds a required
	// check because prose mentions the variable is a new instance of the class
	// this change removes, and its fix would be to edit a prompt.
	//
	// Three shapes, because a workflow can wire a variable three ways and only
	// the first begins with the name:
	//   env mapping   NAME: value   /   NAME : value   /   - NAME: value
	//   assignment    NAME=value   /   export NAME=value   (also a heredoc
	//                 line, and an `env NAME=value cmd` prefix)
	//   env-file      echo "NAME=value" >> "$GITHUB_ENV"
	//
	// The bare assignment is flagged UNCONDITIONALLY rather than only when the
	// line also says GITHUB_ENV. Requiring both tokens on one line missed the
	// idiomatic multi-line form, where the heredoc body carries the assignment
	// and the redirect sits on an earlier line:
	//
	//	cat >> "$GITHUB_ENV" <<'EOF'
	//	NAME=value
	//	EOF
	//
	// A line that BEGINS with this variable and an `=` is not prose in any
	// workflow here, so anchoring alone keeps the false-positive property
	// without the co-occurrence rule. The echo form still needs that rule,
	// because there the name is not at the start of the line.
	//
	// That premise is true today rather than structurally: it holds because of
	// what the prompts in claude.yml and claude-code-review.yml happen to say,
	// and prompts get edited. A prompt line documenting local setup as
	// `NAME=...` at the start of a line would red a required check whose fix is
	// to edit a prompt -- the failure actionpin_test.go's "action named in a
	// prompt is not a use" exists to avoid. The trade is still right, because
	// the false NEGATIVE it replaces let the claim go silently false; but the
	// false-positive side is the side that decays, so revisit this before
	// widening the pattern further.
	// `["']?` and the flow-mapping alternative: YAML allows a quoted key, and
	// allows the mapping inline (`env: {NAME: value}`), where the name is not at
	// the start of the line. Every workflow here uses unquoted block mappings,
	// so this is defence in depth -- but the message being fenced makes a claim
	// about EVERY workflow, and these are the shapes where it would quietly
	// stop being universal.
	mapping := regexp.MustCompile(`^(?:-\s+)?["']?` + name + `["']?\s*:`)
	flowMapping := regexp.MustCompile(`[{,]\s*["']?` + name + `["']?\s*:`)
	assignment := regexp.MustCompile(`^(?:export\s+|env\s+)?` + name + `\s*=`)
	inlineEnvFile := regexp.MustCompile(name + `\s*=`)

	for workflow, contents := range allWorkflows(t) {
		for number, line := range strings.Split(contents, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			var wiring string
			switch {
			case mapping.MatchString(trimmed):
				wiring = "an env mapping"
			case flowMapping.MatchString(trimmed):
				wiring = "an inline env mapping"
			case assignment.MatchString(trimmed):
				wiring = "a shell assignment"
			case inlineEnvFile.MatchString(trimmed) && strings.Contains(trimmed, "GITHUB_ENV"):
				wiring = "a $GITHUB_ENV append"
			default:
				continue
			}
			t.Errorf("%s:%d wires %s as %s (%q), but the strict short-pool error in %s "+
				"tells operators that setting it does not clear the failure -- update "+
				"that message, or drop the wiring",
				workflow, number+1, variable, wiring, trimmed, otpRegistrationSourcePath)
		}
	}
}

// nativeUDPGoFiles lists every Go source in the gate's package, slash-separated
// and relative to the repository root -- the same convention as repoGoFiles, so
// a caller joining one with repositoryRoot joins both. Both fences in this file
// read the package rather than a hand-listed subset, so neither can be evaded
// by putting the new code in another file.
func nativeUDPGoFiles(t *testing.T) []string {
	t.Helper()
	directory := filepath.Join(repositoryRoot(t), filepath.FromSlash(nativeUDPTestDir))
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", nativeUDPTestDir, err)
	}
	var found []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		found = append(found, nativeUDPTestDir+"/"+entry.Name())
	}
	if len(found) == 0 {
		t.Fatalf("found no Go sources under %s; this fence would pass vacuously",
			nativeUDPTestDir)
	}
	return found
}

// summaryReadPattern matches a Go site that READS the job-summary path, not one
// that merely names it.
//
// A bare strings.Contains was the method this file rejects a hundred lines
// above, applied to itself: any doc comment saying "deliberately does not write
// to GITHUB_STEP_SUMMARY" joined the site set and broke an exact-set assertion
// that has no slack. The old self-exemption was the tell -- this fence had to
// skip its own file because naming the variable is not using it. Matching the
// lookup closes both, and needs no exemption: the pattern's own source spells
// the parens escaped, so it does not match itself.
var summaryReadPattern = regexp.MustCompile(
	`(?:lookup|os\.Getenv)\("GITHUB_STEP_SUMMARY"\)`)

// advisoryLiteralPattern counts degradationAdvisory composite literals of ANY
// shape; advisoryTitlePattern extracts the title from the one shape that states
// it inline. The pair is the point: the count catches an addition the title
// scan cannot model (a keyed literal, or a named constant), and the titles then
// say which advisories are sanctioned. Package-level, matching the two patterns
// above, rather than recompiled per file inside the loop.
var (
	advisoryLiteralPattern = regexp.MustCompile(`degradationAdvisory\{`)
	advisoryTitlePattern   = regexp.MustCompile(`degradationAdvisory\{"([^"]+)"`)
)

// TestOnlyTheFencedWriterPublishesToTheJobSummary keeps the degradation
// reporter from becoming an unreviewed publication channel.
//
// The canary withholds -v so that a successful run prints no agent identity or
// live topology, and TestOTPSchemaV2CanaryUsesOnlyTheSanctionedOTPHarness
// enforces that. The job summary is deliberately the one channel that
// suppression cannot reach -- which is what makes it useful for a degraded
// pool, and what makes an unfenced writer a hole in the same policy.
//
// Nothing is exposed by the two advisories that exist: they carry pool sizes
// and duplicate counts, the same kind of text the gate already annotates in
// public. The risk is the THIRD one. noteDegradation is a generic emitter whose
// stated purpose is that a new advisory cannot arrive quieter than these two,
// so a new advisory is expected -- and its author currently gets no signal that
// its text lands on a public run summary. Pinning both the writer and the
// advisory set means adding one is a decision somebody makes on purpose.
func TestOnlyTheFencedWriterPublishesToTheJobSummary(t *testing.T) {
	var sites []string
	for _, path := range repoGoFiles(t) {
		contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if summaryReadPattern.Match(contents) {
			sites = append(sites, path)
		}
	}
	slices.Sort(sites)
	// ONE sanctioned site now that the scan matches reads rather than mentions:
	// appendJobSummary. The emitter's tests supply the path through a described
	// lookup instead of reading it, so they are no longer sites -- and the
	// vector they represent (a test handing over the REAL environment) is
	// fenced by TestOnlyTheGateItselfEmitsFromTheProcessEnvironment, which is
	// where that property belongs.
	want := []string{otpRegistrationSourcePath}
	if !slices.Equal(sites, want) {
		t.Errorf("Go sources READING GITHUB_STEP_SUMMARY = %v, want %v.\nThe job summary "+
			"is the channel the canary's no--v policy cannot suppress, so a new site is a "+
			"publication decision: confirm what it writes, then add it here", sites, want)
	}

	// The advisories that reporter may carry. A new one is fine -- it is the
	// point -- but it arrives here first.
	//
	// COUNTED as well as named, and across the whole package rather than one
	// file. Extracting titles alone only models an unkeyed literal whose first
	// element is a string constant, so a third advisory written as
	// `degradationAdvisory{title: …}` or with a named constant would leave the
	// extracted set equal to the two pinned values and pass green -- the exact
	// outcome this fence exists to make deliberate. The count trips on any
	// shape; the titles then say which ones are sanctioned.
	wantTitles := []string{
		"OTP credential pool has duplicates",
		"OTP credential pool size is degraded",
	}
	var titles []string
	literals := 0
	// Over the whole nativeudp package, NOT over `sites`. `sites` is by
	// construction only the files naming GITHUB_STEP_SUMMARY, and a third
	// advisory need not live in one: poolAdvisories can append a helper's
	// result, putting the literal in a file this fence would never open while
	// the count stayed at two. Scanning the directory is what makes the claim
	// above true, and matches how the process-env fence below reads the package.
	for _, path := range nativeUDPGoFiles(t) {
		source, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		literals += len(advisoryLiteralPattern.FindAllString(string(source), -1))
		for _, match := range advisoryTitlePattern.FindAllStringSubmatch(string(source), -1) {
			titles = append(titles, match[1])
		}
	}
	slices.Sort(titles)
	// TWO checks, not one condition, because they have different remedies and a
	// combined message prescribed a step that could not clear it: appending a
	// keyed literal's title to wantTitles makes the count agree and then fails
	// the title comparison instead, with nothing saying the real fix is to
	// write the literal in unkeyed form. A required check whose own message
	// cannot clear it is the defect this change exists to remove.
	if literals != len(wantTitles) {
		t.Errorf("found %d degradationAdvisory literal(s) in %s, want %d.\nThis counts "+
			"literals of the TYPE, not published advisories, so a table-driven test that "+
			"builds them trips it too -- in that case widen this fence rather than "+
			"changing the test. If it IS a new advisory: its text reaches a public run "+
			"summary, so confirm it carries no identity or topology, write it as an "+
			"unkeyed literal with an inline string title (which is what the title check "+
			"below can read), and add that title to wantTitles.",
			literals, nativeUDPTestDir, len(wantTitles))
	}
	if !slices.Equal(titles, wantTitles) {
		t.Errorf("advisory titles = %v, want %v.\nA title the scan cannot read means the "+
			"literal is keyed or uses a named constant; rewrite it as an unkeyed literal "+
			"with the title inline, so the set published to the run summary stays "+
			"readable from source.", titles, wantTitles)
	}

	// And the production emission path stays single. noteDegradation is
	// package-level, so a new advisory could reach the summary without adding a
	// degradationAdvisory literal at all -- by calling the emitter directly.
	// Pinning the one call site inside loadOTPE2EGateConfig forces a new
	// advisory through poolAdvisories, and therefore through the list above.
	// The declaration itself is excluded; the emitter's own tests drive it
	// directly and live in the other fenced file.
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), otpRegistrationSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", otpRegistrationSourcePath, err)
	}
	calls := regexp.MustCompile(`(?m)^\s*noteDegradation\(`).FindAllString(string(source), -1)
	if len(calls) != 1 {
		t.Errorf("%s has %d noteDegradation call site(s), want exactly 1 -- the loop in "+
			"loadOTPE2EGateConfig.\nA second one publishes to the run summary without "+
			"passing through poolAdvisories, so the advisory list above stops being the "+
			"full set", otpRegistrationSourcePath, len(calls))
	}
}

// singleCredentialVariableName reads the constant out of the owning source
// file. It fails rather than defaulting: a fence that cannot find the name it
// guards is not a passing fence, it is an absent one.
func singleCredentialVariableName(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), otpRegistrationSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", otpRegistrationSourcePath, err)
	}
	match := otpEnrollmentEnvPattern.FindSubmatch(source)
	if match == nil {
		t.Fatalf("%s no longer declares otpE2EEnrollmentEnv as a plain string constant, "+
			"so this fence can no longer derive the variable it guards",
			otpRegistrationSourcePath)
	}
	return string(match[1])
}

// repoGoFiles lists every Go source in the repository, slash-separated and
// relative to the root, skipping the trees that hold no first-party code.
//
// The root itself comes from repositoryRoot, this package's existing helper.
// The walk is separate only because TestRepositoryCommitsNoAWSEstateIdentifiers
// performs its equivalent inline and collects different data; extracting that
// one would mean editing an unrelated estate fence to serve this test.
func repoGoFiles(t *testing.T) []string {
	t.Helper()
	root := repositoryRoot(t)
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Dot-directories as a CLASS, not just .git. This fence asserts
			// exact set equality, which has no slack: a git worktree parked
			// under .claude/worktrees/ is inside the repository root and holds
			// a second copy of the whole Go tree, so the walk would report it
			// and red the fence locally while CI's clean checkout stayed green.
			// A local-only false red on a fence whose message says "add it
			// here" is one that gets fixed by editing the want list. Nothing
			// first-party lives in a dot-directory.
			//
			// The limit: a second copy parked at a NON-dot path is still seen.
			// Deriving the list from `git ls-files` would close that too, at
			// the cost of shelling out from a test.
			if strings.HasPrefix(entry.Name(), ".") {
				return fs.SkipDir
			}
			switch entry.Name() {
			case "vendor", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("found no Go sources; this fence would pass vacuously")
	}
	return found
}

// nativeUDPTestDir holds the gate and every test that drives its loader.
const nativeUDPTestDir = "tests/e2e/nativeudp"

// gateEmitterProcessEnvPattern finds a call that hands the REAL process
// environment to the degradation emitter, directly or through the loader.
//
// appendJobSummary is named alongside the other two: it is package-level, so it
// can be called without going through noteDegradation at all.
//
// The window is same-line and bounded rather than `[^)]*`, which stopped at the
// FIRST close paren and so missed `noteDegradation(t, f(), os.Getenv, …)`. A
// nested-group pattern fixes that case and breaks `wrap(os.Getenv)` instead,
// because it cannot stop inside a group. Every call of these three is written
// on one line, so a bounded same-line scan covers all three shapes; a call
// split across lines would evade it, which is the stated limit of this fence.
var gateEmitterProcessEnvPattern = regexp.MustCompile(
	`(?:loadOTPE2EGateConfig|noteDegradation|appendJobSummary)\([^\n]{0,200}os\.Getenv`)

// TestOnlyTheGateItselfEmitsFromTheProcessEnvironment fences the vector the
// fabricated-advisory incident actually used.
//
// TestOnlyTheFencedWriterPublishesToTheJobSummary pins WHO may write and WHAT
// may be written, and neither would have caught that incident: it added no file
// and no advisory. It came from a unit test driving the loader against the
// process environment, so on CI a deliberately degraded fixture emitted a real
// annotation and appended a real block to the run summary.
//
// Threading the lookup made "not on CI" describable, but nothing yet stops the
// next test passing os.Getenv back in -- and the emission now lives INSIDE
// loadOTPE2EGateConfig, which has more callers than the gate. So the rule is
// pinned rather than left to convention: exactly one call site may read the
// real environment, and it is the one that is actually running on the runner.
func TestOnlyTheGateItselfEmitsFromTheProcessEnvironment(t *testing.T) {
	var sites []string
	for _, path := range nativeUDPGoFiles(t) {
		contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Counted per file, then reported as one entry per file. Appending per
		// MATCH named the same file twice for two call sites in it, which read
		// as a set mismatch whose advice ("pass a described lookup") is wrong
		// for a genuine second gate call.
		if matches := len(gateEmitterProcessEnvPattern.FindAll(contents, -1)); matches > 0 {
			sites = append(sites, fmt.Sprintf("%s (%d call site(s))",
				filepath.Base(filepath.FromSlash(path)), matches))
		}
	}
	slices.Sort(sites)

	// One, in the gate test: the only caller that IS the runner.
	want := []string{"otp_registration_idempotency_test.go (1 call site(s))"}
	if !slices.Equal(sites, want) {
		t.Errorf("call sites handing os.Getenv to the gate loader or the degradation "+
			"emitter = %v, want %v.\nA unit test that reads the real environment emits a "+
			"real annotation and appends a real block to the run summary -- describing a "+
			"pool that does not exist. Pass a described lookup (envFrom) instead.",
			sites, want)
	}
}
