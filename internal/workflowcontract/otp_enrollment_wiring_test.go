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

// otpRegistrationSourcePath is the file that owns both the constant and the
// message making the claim. Reading across into tests/e2e is the same move
// public_estate_identifiers_test.go already makes.
const otpRegistrationSourcePath = "tests/e2e/nativeudp/otp_registration_idempotency_test.go"

func TestNoWorkflowWiresTheSingleOTPCredentialVariable(t *testing.T) {
	variable := singleCredentialVariableName(t)

	// The POOL variable's name extends this one, so anchor on the character
	// that follows: a workflow wires a variable either as a YAML mapping
	// (`NAME: value`) or as a shell export appended to $GITHUB_ENV
	// (`NAME=value`), and the pool spelling has `_` there instead. Checking
	// only the mapping form left the fence green while a run block exported
	// the variable -- the same misdirection with one extra step.
	assignments := []string{variable + ":", variable + "="}

	for name, workflow := range allWorkflows(t) {
		for _, line := range strings.Split(workflow, "\n") {
			// Comments mention variable names legitimately; only a real
			// assignment wires one.
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, assignment := range assignments {
				if strings.Contains(line, assignment) {
					t.Errorf("%s wires %s (%q on line %q), but the strict short-pool "+
						"error in %s tells operators that setting it does not clear the "+
						"failure -- update that message, or drop the wiring",
						name, variable, assignment, strings.TrimSpace(line),
						otpRegistrationSourcePath)
				}
			}
		}
	}
}

// singleCredentialVariableName reads the constant out of the owning source
// file. It fails rather than defaulting: a fence that cannot find the name it
// guards is not a passing fence, it is an absent one.
func singleCredentialVariableName(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow contract path")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..",
		filepath.FromSlash(otpRegistrationSourcePath))
	source, err := os.ReadFile(path)
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
