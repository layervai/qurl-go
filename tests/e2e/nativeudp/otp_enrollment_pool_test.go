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
	lookup := envFrom(map[string]string{"GITHUB_RUN_NUMBER": "100", "GITHUB_RUN_ATTEMPT": "1"})

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
	lookup := envFrom(map[string]string{"GITHUB_RUN_NUMBER": "12345", "GITHUB_RUN_ATTEMPT": "2"})

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
// A rerun is the case that exhausted the budget in practice: same run, a new
// attempt, another issuance. Keying selection on the run alone would send every
// attempt back to the credential whose budget the previous attempt just spent,
// so the pool would be present and useless. Successive attempts must move -- and
// because the attempt rotates rather than rehashes, they must move to a slot
// nobody has used yet, which is the strongest form of "move".
func TestSelectEnrollmentSpreadsReruns(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}

	seen := map[int]bool{}
	for attempt := 1; attempt <= len(pool); attempt++ {
		_, slot := selectEnrollment(pool, envFrom(map[string]string{
			"GITHUB_RUN_NUMBER":  "999",
			"GITHUB_RUN_ATTEMPT": fmt.Sprint(attempt),
		}))
		seen[slot] = true
	}
	if len(seen) != len(pool) {
		t.Fatalf("%d reruns used only %d distinct slots (%v); a rotation must visit every slot before repeating",
			len(pool), len(seen), seen)
	}
}

// TestSelectEnrollmentSpreadsRuns covers the ordinary case: distinct PRs.
//
// GITHUB_RUN_NUMBER increments by one per run of this workflow, so consecutive
// runs must land on consecutive slots and the pool must stay balanced to within
// one. A hash would only manage this on average, and "on average" is what the
// per-credential budget punishes -- see the clustering test below.
func TestSelectEnrollmentSpreadsRuns(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f"}

	const runs = 40
	used := map[int]int{}
	for run := 0; run < runs; run++ {
		_, slot := selectEnrollment(pool, envFrom(map[string]string{
			"GITHUB_RUN_NUMBER":  fmt.Sprint(1000 + run),
			"GITHUB_RUN_ATTEMPT": "1",
		}))
		used[slot]++
	}
	if len(used) != len(pool) {
		t.Fatalf("%d runs reached only %d of %d slots (%v); distribution is skewed",
			runs, len(used), len(pool), used)
	}
	low, high := runs/len(pool), (runs+len(pool)-1)/len(pool)
	for slot, n := range used {
		if n < low || n > high {
			t.Fatalf("slot %d took %d of %d runs; a rotation keeps every slot within [%d,%d] (%v)",
				slot, n, runs, low, high, used)
		}
	}
}

// TestSelectEnrollmentNeverClustersWithinTheIssuanceBudget pins the property
// whose absence turned the gate red on 2026-08-31, and is the whole reason
// selection rotates instead of hashing.
//
// Issuance is capped per CREDENTIAL, so the pool is only worth its advertised
// perCredentialHourlyBudget*len(pool) an hour if runs land EVENLY. A hash
// spreads them independently -- balls-in-bins -- and the gate goes red the
// moment any single bin fills, however much of the pool is still untouched.
// That is not a tail risk: nine real runs hashed into three slots, put five on
// one of them, and refused the tenth with twenty-one of thirty issuances
// unspent. A rotation makes it arithmetically impossible: across any N
// consecutive runs no slot is used more than ceil(N/len(pool)) times, so a full
// hour of perCredentialHourlyBudget*len(pool) runs still fits.
//
// Reverting selectEnrollment to a hash of the run id fails this test.
func TestSelectEnrollmentNeverClustersWithinTheIssuanceBudget(t *testing.T) {
	// qurl-service registrationOTPPerCredentialRate at the time of writing. It
	// only sets how far this test looks ahead, so service-side retuning cannot
	// invalidate the property being asserted.
	const perCredentialHourlyBudget = 5
	pool := []string{"a", "b", "c", "d", "e", "f"}
	fullHour := perCredentialHourlyBudget * len(pool)

	// A rotation has to hold from any offset: GITHUB_RUN_NUMBER is wherever
	// this workflow's own history has reached, not a number this test chooses.
	for _, start := range []int{0, 1, 7, 41, 202, 1000} {
		for window := 1; window <= fullHour; window++ {
			used := map[int]int{}
			for i := 0; i < window; i++ {
				_, slot := selectEnrollment(pool, envFrom(map[string]string{
					"GITHUB_RUN_NUMBER":  fmt.Sprint(start + i),
					"GITHUB_RUN_ATTEMPT": "1",
				}))
				used[slot]++
			}
			ceiling := (window + len(pool) - 1) / len(pool)
			for slot, n := range used {
				if n > ceiling {
					t.Fatalf("%d consecutive runs from %d put %d issuances on slot %d; "+
						"a rotation allows at most %d, and the credential budget is %d",
						window, start, n, slot, ceiling, perCredentialHourlyBudget)
				}
			}
		}
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
		{"GITHUB_RUN_NUMBER": "1", "GITHUB_RUN_ATTEMPT": "1"},
		{"GITHUB_RUN_NUMBER": "1"},  // attempt absent
		{"GITHUB_RUN_ATTEMPT": "3"}, // run number absent -- random fallback
		{},                          // off CI entirely
		{"GITHUB_RUN_NUMBER": "  ", "GITHUB_RUN_ATTEMPT": " "},  // whitespace only
		{"GITHUB_RUN_NUMBER": "not-a-number"},                   // unparseable
		{"GITHUB_RUN_NUMBER": "-4", "GITHUB_RUN_ATTEMPT": "-1"}, // negative
		{"GITHUB_RUN_NUMBER": "0", "GITHUB_RUN_ATTEMPT": "0"},   // zero
		{"GITHUB_RUN_NUMBER": "99999999999999999999"},           // overflows int
		// MaxInt64 in both: the sum must not wrap to a negative slot.
		{"GITHUB_RUN_NUMBER": "9223372036854775807", "GITHUB_RUN_ATTEMPT": "9223372036854775807"},
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
