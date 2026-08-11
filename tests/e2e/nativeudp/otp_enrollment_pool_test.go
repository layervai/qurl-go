package nativeudp_test

// Unit coverage for credential-pool selection.
//
// These run everywhere -- no sandbox, no AWS, no secrets -- which is the point.
// The pool exists to stop the gate failing on an exhausted issuance budget, and
// a defect in the selection logic reappears as exactly the symptom the pool was
// built to remove: a red required check that says nothing about the change under
// test. That is expensive to diagnose from CI and nearly free to catch here.

import (
	"fmt"
	"strings"
	"testing"
)

// envFrom builds a lookup over a fixed map, matching loadOTPE2EConfig's shape.
func envFrom(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

func TestParseEnrollmentPoolSplitsAndCleans(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{"newline separated", "one\ntwo\nthree", []string{"one", "two", "three"}},
		{"comma separated", "one,two,three", []string{"one", "two", "three"}},
		{"crlf line endings", "one\r\ntwo", []string{"one", "two"}},
		{"blank lines dropped", "one\n\n\ntwo\n", []string{"one", "two"}},
		{"surrounding space trimmed", "  one  \n\ttwo\t", []string{"one", "two"}},
		{"empty", "", nil},
		{"only separators", "\n,\n , \n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEnrollmentPool(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("parsed %d entries %q, want %d %q", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("entry %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSelectEnrollmentDegenerateCases(t *testing.T) {
	lookup := envFrom(map[string]string{"GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1"})

	t.Run("empty pool reports no slot", func(t *testing.T) {
		got, slot := selectEnrollment(nil, lookup)
		if got != "" || slot != -1 {
			t.Fatalf("selectEnrollment(nil) = %q, %d; want \"\", -1", got, slot)
		}
	})

	t.Run("single credential is always slot zero", func(t *testing.T) {
		got, slot := selectEnrollment([]string{"only"}, lookup)
		if got != "only" || slot != 0 {
			t.Fatalf("selectEnrollment = %q, %d; want \"only\", 0", got, slot)
		}
	})
}

func TestSelectEnrollmentIsDeterministicForOneAttempt(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}
	lookup := envFrom(map[string]string{"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"})

	first, firstSlot := selectEnrollment(pool, lookup)
	for i := 0; i < 32; i++ {
		got, slot := selectEnrollment(pool, lookup)
		if got != first || slot != firstSlot {
			t.Fatalf("selection %d = %q/%d; want stable %q/%d", i, got, slot, first, firstSlot)
		}
	}
}

// TestSelectEnrollmentSpreadsReruns is the property the pool exists for.
//
// A rerun is the case that exhausted the budget in practice: same run id, a new
// attempt, another issuance. Keying selection on the run alone would send every
// attempt back to the credential whose budget the previous attempt just spent,
// so the pool would be present and useless. Successive attempts must move.
func TestSelectEnrollmentSpreadsReruns(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}

	seen := map[int]bool{}
	for attempt := 1; attempt <= 6; attempt++ {
		_, slot := selectEnrollment(pool, envFrom(map[string]string{
			"GITHUB_RUN_ID":      "999",
			"GITHUB_RUN_ATTEMPT": fmt.Sprint(attempt),
		}))
		seen[slot] = true
	}
	// Six attempts over six slots will collide sometimes; demanding a perfect
	// permutation would be asserting a property of FNV rather than of this
	// code. What must hold is that reruns genuinely move around.
	if len(seen) < 3 {
		t.Fatalf("six reruns used only %d distinct slots (%v); reruns are not spreading", len(seen), seen)
	}
}

// TestSelectEnrollmentSpreadsRuns covers the ordinary case: distinct PRs.
func TestSelectEnrollmentSpreadsRuns(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}

	seen := map[int]bool{}
	for run := 0; run < 40; run++ {
		_, slot := selectEnrollment(pool, envFrom(map[string]string{
			"GITHUB_RUN_ID":      fmt.Sprintf("101%d", run),
			"GITHUB_RUN_ATTEMPT": "1",
		}))
		seen[slot] = true
	}
	if len(seen) != len(pool) {
		t.Fatalf("40 runs reached only %d of %d slots (%v); distribution is skewed",
			len(seen), len(pool), seen)
	}
}

// TestSelectEnrollmentAlwaysReturnsAPoolMember guards the modulo arithmetic.
// An out-of-range slot would panic, and an off-CI path that returned "" would
// send an empty credential to the authority and fail as an auth error.
func TestSelectEnrollmentAlwaysReturnsAPoolMember(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}
	member := map[string]bool{}
	for _, c := range pool {
		member[c] = true
	}

	for _, env := range []map[string]string{
		{"GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"},
		{"GITHUB_RUN_ID": "1"},      // attempt absent
		{"GITHUB_RUN_ATTEMPT": "3"}, // run id absent
		{},                          // off CI entirely
		{"GITHUB_RUN_ID": "  ", "GITHUB_RUN_ATTEMPT": " "}, // whitespace only
	} {
		got, slot := selectEnrollment(pool, envFrom(env))
		if !member[got] {
			t.Fatalf("env %v selected %q, which is not in the pool", env, got)
		}
		if slot < 0 || slot >= len(pool) {
			t.Fatalf("env %v selected slot %d, outside [0,%d)", env, slot, len(pool))
		}
	}
}

// TestLoadOTPE2EConfigAcceptsEitherCredentialSource pins the either-or rule:
// the pool and the single value each satisfy the requirement alone, and the
// skip path must still trip when neither is present.
func TestLoadOTPE2EConfigAcceptsEitherCredentialSource(t *testing.T) {
	base := map[string]string{
		otpE2EHubHostEnv:          "hub.example",
		otpE2EHubPortEnv:          "443",
		otpE2EHubKeyEnv:           "key",
		otpE2EAgentIDEnv:          "agent",
		otpE2EMailboxQueueURLEnv:  "https://queue.example/q",
		otpE2EMailboxBucketEnv:    "bucket",
		otpE2EMailboxRecipientEnv: "otp@example",
		otpE2EMailboxRegionEnv:    "us-east-2",
	}
	with := func(extra map[string]string) map[string]string {
		merged := map[string]string{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		return merged
	}

	t.Run("pool alone suffices", func(t *testing.T) {
		cfg, skip, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo\nthree",
		})))
		if err != nil || skip {
			t.Fatalf("loadOTPE2EConfig = skip %t, err %v; want a usable config", skip, err)
		}
		if cfg.enrollmentPoolSize != 3 {
			t.Fatalf("pool size = %d, want 3", cfg.enrollmentPoolSize)
		}
		if cfg.enrollment == "" {
			t.Fatal("config carries no credential")
		}
	})

	t.Run("single value alone suffices", func(t *testing.T) {
		cfg, skip, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentEnv: "solo",
		})))
		if err != nil || skip {
			t.Fatalf("loadOTPE2EConfig = skip %t, err %v; want a usable config", skip, err)
		}
		if cfg.enrollment != "solo" || cfg.enrollmentPoolSize != 1 {
			t.Fatalf("credential = %q, pool size %d; want \"solo\", 1", cfg.enrollment, cfg.enrollmentPoolSize)
		}
	})

	t.Run("pool wins when both are set", func(t *testing.T) {
		cfg, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo",
			otpE2EEnrollmentEnv:     "solo",
		})))
		if err != nil {
			t.Fatalf("loadOTPE2EConfig: %v", err)
		}
		if cfg.enrollment == "solo" || cfg.enrollmentPoolSize != 2 {
			t.Fatalf("credential = %q, pool size %d; want a pool member and size 2",
				cfg.enrollment, cfg.enrollmentPoolSize)
		}
	})

	t.Run("neither skips, and names both in strict mode", func(t *testing.T) {
		_, skip, err := loadOTPE2EConfig(envFrom(base))
		if !skip || err != nil {
			t.Fatalf("loadOTPE2EConfig = skip %t, err %v; want a clean skip", skip, err)
		}

		strict := with(map[string]string{otpE2EStrictEnv: "1"})
		if _, _, err = loadOTPE2EConfig(envFrom(strict)); err == nil {
			t.Fatal("strict run with no credential succeeded; the gate would rubber-stamp")
		}
		// The message has to name both spellings: a dropped secret is fixed by
		// setting one of them, and the operator needs to know which.
		if !strings.Contains(err.Error(), otpE2EEnrollmentPoolEnv) ||
			!strings.Contains(err.Error(), otpE2EEnrollmentEnv) {
			t.Fatalf("strict error %q names neither credential variable", err)
		}
	})
}
