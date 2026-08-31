package nativeudp_test

// Unit coverage for credential-pool selection.
//
// These run everywhere -- no sandbox, no AWS, no secrets -- which is the point.
// The pool exists to stop the gate failing on an exhausted issuance budget, and
// a defect in the selection logic reappears as exactly the symptom the pool was
// built to remove: a red required check that says nothing about the change under
// test. That is expensive to diagnose from CI and nearly free to catch here.

import (
	"strconv"
	"strings"
	"testing"
)

// envFrom builds a lookup over a fixed map, matching loadOTPE2EConfig's shape.
func envFrom(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

// sixSlotPool is the pool's shape today: six credentials, one per distinct
// owner. Selection only does anything above one slot, so the distribution tests
// share it rather than restating it.
var sixSlotPool = []string{"a", "b", "c", "d", "e", "f"}

// ciEnv builds the two variables selectEnrollment rotates on. Taking ints keeps
// callers from respelling the variable names on every loop iteration.
func ciEnv(runNumber, attempt int) func(string) string {
	return envFrom(map[string]string{
		"GITHUB_RUN_NUMBER":  strconv.Itoa(runNumber),
		"GITHUB_RUN_ATTEMPT": strconv.Itoa(attempt),
	})
}

// slotFor is the tally step every distribution test below repeats.
func slotFor(pool []string, runNumber, attempt int) int {
	_, slot, _ := selectEnrollment(pool, ciEnv(runNumber, attempt))
	return slot
}

// ceilDiv is the per-slot ceiling a rotation guarantees over n runs.
func ceilDiv(n, slots int) int { return (n + slots - 1) / slots }

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
	lookup := ciEnv(100, 1)

	t.Run("empty pool reports no slot", func(t *testing.T) {
		got, slot, _ := selectEnrollment(nil, lookup)
		if got != "" || slot != -1 {
			t.Fatalf("selectEnrollment(nil) = %q, %d; want \"\", -1", got, slot)
		}
	})

	t.Run("single credential is always slot zero", func(t *testing.T) {
		got, slot, _ := selectEnrollment([]string{"only"}, lookup)
		if got != "only" || slot != 0 {
			t.Fatalf("selectEnrollment = %q, %d; want \"only\", 0", got, slot)
		}
	})
}

func TestSelectEnrollmentIsDeterministicForOneAttempt(t *testing.T) {
	pool := sixSlotPool
	lookup := ciEnv(12345, 2)

	first, firstSlot, _ := selectEnrollment(pool, lookup)
	for i := 0; i < 32; i++ {
		got, slot, _ := selectEnrollment(pool, lookup)
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
	pool := sixSlotPool

	seen := map[int]bool{}
	for attempt := 1; attempt <= len(pool); attempt++ {
		seen[slotFor(pool, 999, attempt)] = true
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
	pool := sixSlotPool

	const runs = 40
	used := map[int]int{}
	for run := 0; run < runs; run++ {
		used[slotFor(pool, 1000+run, 1)]++
	}
	// Ranging over the pool rather than over `used` is deliberate: a slot that
	// took ZERO runs has no map entry, so ranging the map would skip exactly
	// the starvation this lower bound exists to catch.
	low, high := runs/len(pool), ceilDiv(runs, len(pool))
	for slot := range pool {
		if n := used[slot]; n < low || n > high {
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
// perCredentialHourlyBudget is qurl-service's registrationOTPPerCredentialRate
// at the time of writing. It only sets how far these tests look ahead, so
// service-side retuning cannot invalidate the properties they assert.
const perCredentialHourlyBudget = 5

func TestSelectEnrollmentNeverClustersWithinTheIssuanceBudget(t *testing.T) {
	pool := sixSlotPool
	fullHour := perCredentialHourlyBudget * len(pool)

	// Prefix windows from several offsets, at several attempts. Prefixes are
	// enough because the rotation is translation-invariant mod len(pool): a
	// window starting mid-sequence is a prefix from a different offset, which
	// is what varying `start` covers. Run numbers are wherever this workflow's
	// history has reached, not values a test may choose, and an hour of reruns
	// is still an hour of issuances.
	for _, start := range []int{0, 1, 7, 41, 202, 1000} {
		for _, attempt := range []int{1, 2, 3} {
			// Counts accumulate: after run i the tallies ARE the window of
			// i+1, so only the slot just incremented can have crossed its
			// ceiling -- every other slot is unchanged from the previous
			// window, where it already met a ceiling no larger than this one.
			used := map[int]int{}
			for i := 0; i < fullHour; i++ {
				slot := slotFor(pool, start+i, attempt)
				used[slot]++
				if ceiling := ceilDiv(i+1, len(pool)); used[slot] > ceiling {
					t.Fatalf("%d consecutive runs from %d (attempt %d) put %d issuances on "+
						"slot %d; a rotation allows at most %d, and the credential budget is %d",
						i+1, start, attempt, used[slot], slot, ceiling, perCredentialHourlyBudget)
				}
			}
		}
	}
}

// TestSmallestFactorFlagsExactlyTheVulnerablePoolSizes covers the runtime half
// of the stride guard: the gate logs a note when the LIVE pool size is
// composite, and stays silent once it is prime. Silence is the signal that the
// seventh-owner residual has been closed, so it has to be exact.
func TestSmallestFactorFlagsExactlyTheVulnerablePoolSizes(t *testing.T) {
	for _, tc := range []struct {
		size int
		want int
	}{
		{0, 0}, {1, 0}, {2, 0}, {3, 0}, // nothing to collapse onto
		{4, 2}, {6, 2}, {8, 2}, {9, 3}, {10, 2}, // composite: flagged
		{5, 0}, {7, 0}, {11, 0}, {13, 0}, // prime: silent
	} {
		if got := smallestFactor(tc.size); got != tc.want {
			t.Fatalf("smallestFactor(%d) = %d, want %d", tc.size, got, tc.want)
		}
	}
	// The two sizes this actually turns on: today's pool is flagged, and the
	// seventh owner is what silences it.
	if smallestFactor(len(sixSlotPool)) == 0 {
		t.Fatal("today's six-slot pool must be flagged; the residual is still open")
	}
	if smallestFactor(len(sixSlotPool)+1) != 0 {
		t.Fatal("a seventh owner must silence the note; that is how the fix is observed")
	}
}

// TestSelectEnrollmentStridedTrafficNeedsACoprimePoolSize pins the residual the
// rotation cannot fix on its own, and shows it is a POOL SIZE decision.
//
// Only scope-relevant runs spend an issuance, so spending runs are a
// subsequence of the run numbers. A subsequence of stride d visits just
// len(pool)/gcd(d, len(pool)) slots, so the guarantee survives a stride only
// when it stays coprime to the pool size. Six is the worst size available: a
// stretch where relevant and irrelevant PRs merely alternate is d=2, which
// collapses six slots onto three and reproduces the outage this file exists to
// document. A prime size is immune to every stride below it.
//
// This asserts the ARITHMETIC, and is the argument for seeding a seventh owner.
// It cannot police the live pool: that size is len(parseEnrollmentPool(secret))
// at runtime, so seeding the secret to eight would collapse under stride 2 with
// this test still green. The run-time half of the guard is the note the gate
// logs beside its slot evidence, where the real size lands.
func TestSelectEnrollmentStridedTrafficNeedsACoprimePoolSize(t *testing.T) {
	worstSlotUnderStride := func(pool []string, stride int) int {
		used := map[int]int{}
		for i := 0; i < perCredentialHourlyBudget*len(pool); i++ {
			used[slotFor(pool, i*stride, 1)]++
		}
		worst := 0
		for _, n := range used {
			if n > worst {
				worst = n
			}
		}
		return worst
	}

	// Strides BELOW the size: for a prime p every d in [1,p) has gcd(d,p)=1.
	// At d == p even a prime collapses onto one slot, which is arithmetic, not
	// a property any pool size can buy off.
	prime := []string{"a", "b", "c", "d", "e", "f", "g"}
	for stride := 1; stride < len(prime); stride++ {
		ideal := perCredentialHourlyBudget
		if got := worstSlotUnderStride(prime, stride); got > ideal {
			t.Fatalf("prime pool of %d under stride %d put %d on one slot; want at most %d",
				len(prime), stride, got, ideal)
		}
	}

	// The other half: a size of six genuinely does degrade, so selectEnrollment's
	// comment is not being alarmist. This pins the arithmetic for six, not the
	// live pool -- seeding a seventh owner does not and should not change it.
	if got := worstSlotUnderStride(sixSlotPool, 2); got <= perCredentialHourlyBudget {
		t.Fatalf("six-slot pool under stride 2 put only %d on one slot; the size dependency "+
			"this test documents no longer holds -- re-derive it before trusting the comment",
			got)
	}
}

// TestSelectEnrollmentAlwaysReturnsAPoolMember guards the modulo arithmetic.
// An out-of-range slot would panic, and an off-CI path that returned "" would
// send an empty credential to the authority and fail as an auth error.
func TestSelectEnrollmentAlwaysReturnsAPoolMember(t *testing.T) {
	pool := sixSlotPool
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
		got, slot, _ := selectEnrollment(pool, envFrom(env))
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

	// The rotation is a prerequisite, and strict mode is where prerequisites
	// stop being silent. Without this, a runner that stopped exporting
	// GITHUB_RUN_NUMBER would quietly go back to random selection and the only
	// symptom would be the gate clustering red again weeks later.
	t.Run("strict run without a run number refuses to fall back to random", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo\nthree",
			otpE2EStrictEnv:         "1",
		})))
		if err == nil {
			t.Fatal("strict run selected a credential at random; the pool would cluster")
		}
		if !strings.Contains(err.Error(), "GITHUB_RUN_NUMBER") {
			t.Fatalf("strict error %q does not name the variable an operator must set", err)
		}
	})

	// A one-entry pool has nothing to rotate, so strict mode must not treat it
	// as a failed rotation -- that would break the single-credential setup the
	// either-or rule above exists to support.
	t.Run("strict run with a single credential is not a rotation failure", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentEnv: "solo",
			otpE2EStrictEnv:     "1",
		})))
		if err != nil {
			t.Fatalf("strict single-credential run failed: %v", err)
		}
	})

	// The attempt half of the same rule. Defaulting a broken attempt to 1 would
	// send every rerun of a run back to that run's own slot -- five reruns, one
	// credential, the original outage.
	t.Run("strict run with an unusable attempt refuses to fall back to random", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo\nthree",
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "not-a-number",
		})))
		if err == nil {
			t.Fatal("strict run accepted an unusable GITHUB_RUN_ATTEMPT; reruns would collide")
		}
		// Must name the counter that actually failed. Reporting the run number
		// here would send an operator to inspect a variable that is correctly
		// set -- the misdirection this whole change exists to stop.
		if !strings.Contains(err.Error(), "GITHUB_RUN_ATTEMPT") {
			t.Fatalf("strict error %q blames the wrong counter; the attempt is at fault", err)
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
