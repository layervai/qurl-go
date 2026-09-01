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
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
	//   shell export  export NAME=value
	//   env-file      echo "NAME=value" >> "$GITHUB_ENV"
	// The env-file form cannot be anchored, so it is narrowed by requiring
	// GITHUB_ENV on the same line -- which is what makes it a wiring rather
	// than a mention.
	mapping := regexp.MustCompile(`^(?:-\s+)?` + name + `\s*:`)
	export := regexp.MustCompile(`^export\s+` + name + `\s*=`)
	envFile := regexp.MustCompile(name + `\s*=`)

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
			case export.MatchString(trimmed):
				wiring = "a shell export"
			case envFile.MatchString(trimmed) && strings.Contains(trimmed, "GITHUB_ENV"):
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
	// This fence names the variable in order to guard it, so it would otherwise
	// match itself. Skipped BY PATH rather than by skipping the package, so a
	// different workflowcontract file that started writing summaries is still
	// caught.
	const self = "internal/workflowcontract/otp_enrollment_wiring_test.go"

	var sites []string
	for _, path := range repoGoFiles(t) {
		if path == self {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(repoRootDir(t), path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(contents), "GITHUB_STEP_SUMMARY") {
			sites = append(sites, path)
		}
	}
	slices.Sort(sites)
	// Two sanctioned sites: appendJobSummary, and the test that drives it with a
	// described environment. Naming the test as well as the writer is
	// deliberate -- a test is exactly how a fabricated advisory reached the
	// real summary once already, so it belongs inside the fence, not outside.
	want := []string{
		"tests/e2e/nativeudp/otp_enrollment_pool_test.go",
		otpRegistrationSourcePath,
	}
	slices.Sort(want)
	if !slices.Equal(sites, want) {
		t.Errorf("Go sources naming GITHUB_STEP_SUMMARY = %v, want %v.\nThe job summary "+
			"is the channel the canary's no--v policy cannot suppress, so a new site is a "+
			"publication decision: confirm what it writes, then add it here", sites, want)
	}

	// The advisories that reporter may carry. A new one is fine -- it is the
	// point -- but it arrives here first.
	source, err := os.ReadFile(filepath.Join(repoRootDir(t), otpRegistrationSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", otpRegistrationSourcePath, err)
	}
	var titles []string
	for _, match := range regexp.MustCompile(
		`degradationAdvisory\{"([^"]+)"`).FindAllStringSubmatch(string(source), -1) {
		titles = append(titles, match[1])
	}
	slices.Sort(titles)
	wantTitles := []string{
		"OTP credential pool has duplicates",
		"OTP credential pool size is degraded",
	}
	if !slices.Equal(titles, wantTitles) {
		t.Errorf("advisories published to the job summary = %v, want %v.\nEach one's text "+
			"reaches a public run summary; confirm the new advisory carries no identity "+
			"or topology, then add it here", titles, wantTitles)
	}
}

// singleCredentialVariableName reads the constant out of the owning source
// file. It fails rather than defaulting: a fence that cannot find the name it
// guards is not a passing fence, it is an absent one.
func singleCredentialVariableName(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(repoRootDir(t), otpRegistrationSourcePath))
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

// repoRootDir resolves the repository root from this file's own location, the
// way workflowDir does for .github/workflows.
func repoRootDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow contract path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// repoGoFiles lists every Go source in the repository as a slash-separated
// path relative to the root, skipping directories that hold no first-party
// code.
func repoGoFiles(t *testing.T) []string {
	t.Helper()
	root := repoRootDir(t)
	var found []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
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
