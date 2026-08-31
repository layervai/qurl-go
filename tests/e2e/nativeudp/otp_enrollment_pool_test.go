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

// sweepStarts returns every residue class mod size, plus a few arbitrary large
// offsets. DERIVED from the size rather than listed: a literal list silently
// loses coverage the day the pool changes size, and in the direction this repo
// is heading -- {0, 1, 7, 41, 202, 1000} covers four of six residues today and
// only THREE OF SEVEN at the prime size selectEnrollment argues for, while the
// sweeps that use it would keep passing and still claim to start "from any
// offset".
func sweepStarts(size int) []int {
	starts := make([]int, 0, size+3)
	for i := range size {
		starts = append(starts, i)
	}
	return append(starts, 41, 202, 1000)
}

func TestParseEnrollmentPoolSplitsAndCleans(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		want     []string
		wantDups int
	}{
		{"newline separated", "one\ntwo\nthree", []string{"one", "two", "three"}, 0},
		{"comma separated", "one,two,three", []string{"one", "two", "three"}, 0},
		{"crlf line endings", "one\r\ntwo", []string{"one", "two"}, 0},
		{"blank lines dropped", "one\n\n\ntwo\n", []string{"one", "two"}, 0},
		{"surrounding space trimmed", "  one  \n\ttwo\t", []string{"one", "two"}, 0},
		{"empty", "", nil, 0},
		{"only separators", "\n,\n , \n", nil, 0},
		// A duplicate must not inflate len(pool): it is the denominator of the
		// hourly ceiling and the input to the composite-size warning, so a
		// repeat would overstate capacity AND silence the warning at once.
		{"duplicate dropped and counted", "one\ntwo\none", []string{"one", "two"}, 1},
		{"duplicate after trimming", "one\n  one  \ntwo", []string{"one", "two"}, 1},
		{"every entry repeated", "a\nb\na\nb", []string{"a", "b"}, 2},
		{
			"six owners with one repeat parses as six", "a\nb\nc\nd\ne\nf\nc",
			[]string{"a", "b", "c", "d", "e", "f"},
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, dups := parseEnrollmentPool(tc.raw)
			if dups != tc.wantDups {
				t.Fatalf("dropped %d duplicates, want %d", dups, tc.wantDups)
			}
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
// at the time of writing. It sets how far these tests look ahead, and every
// message a runtime path INTERPOLATES the rate into reads it from here -- the
// truncated-pool error, the pool-size advisory, and otpMailbox.timedOut, which
// is the first thing an operator sees on this failure.
//
// It does NOT cover prose. The rate is also written out longhand in
// selectEnrollment's derivation and in the gate workflow's GATE_PATHS comment,
// where nothing can interpolate it; if the service retunes the rate, those are
// the two places that must be edited by hand. Claiming otherwise would be the
// same kind of overreach this file's history is made of.
const perCredentialHourlyBudget = 5

func TestSelectEnrollmentNeverClustersWithinTheIssuanceBudget(t *testing.T) {
	pool := sixSlotPool
	fullHour := perCredentialHourlyBudget * len(pool)

	// Prefix windows from every offset, at several attempts. Prefixes are enough
	// because the rotation is translation-invariant mod len(pool): a window
	// starting mid-sequence is a prefix from a different offset, and sweepStarts
	// covers every residue class so that claim is actually true. Run numbers are
	// wherever this workflow's history has reached, not values a test may
	// choose, and an hour of reruns is still an hour of issuances.
	for _, start := range sweepStarts(len(pool)) {
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
		// 2 and 3 are prime, so smallestFactor is silent by construction. That
		// is right ARITHMETICALLY but is not a safety claim: size 2 collapses
		// under a stride of 2, which is why poolSizeAdvisory handles it
		// separately. See TestPoolSizeAdvisorySpeaksAtEverySizeThatCosts.
		{0, 0},
		{1, 0},
		{2, 0},
		{3, 0},
		{4, 2},
		{6, 2},
		{8, 2},
		{9, 3},
		{10, 2}, // composite: flagged
		{5, 0},
		{7, 0},
		{11, 0},
		{13, 0}, // prime: silent
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

// TestSelectEnrollmentBoundsInterleavedReruns covers the window shape the sweep
// above cannot reach, despite looking like it does.
//
// slotFor reduces to (runNumber + attempt - 1) mod len(pool), so a window at a
// FIXED attempt is bit-for-bit the same window at a different start: the sweep's
// attempt loop widens which residues the starts cover, but every window in it
// still holds the attempt constant, which is the case the rotation makes
// trivially perfect. The distinct shape is attempts INTERLEAVED inside one
// window -- a flaky stretch where runs retry -- which is where the aliasing
// selectEnrollment documents ((N, attempt 2) onto (N+1, attempt 1)) shows up.
//
// The ideal ceiling does NOT survive interleaving and is not claimed to: three
// runs each retried once put 6 issuances on 4 slots, two of them twice, against
// a ceil(6/6)=1 ideal. The bound that does hold is ceil(runs/len(pool)) per
// attempt level, i.e. reruns cost proportionally rather than collapsing the
// pool -- which is the "bounded at one extra issuance on one slot" claim on
// selectEnrollment, asserted here rather than left as prose.
func TestSelectEnrollmentBoundsInterleavedReruns(t *testing.T) {
	pool := sixSlotPool

	for _, attemptsPerRun := range []int{2, 3} {
		for _, start := range sweepStarts(len(pool)) {
			for runs := 1; runs <= perCredentialHourlyBudget*len(pool); runs++ {
				used := map[int]int{}
				for i := 0; i < runs; i++ {
					for attempt := 1; attempt <= attemptsPerRun; attempt++ {
						used[slotFor(pool, start+i, attempt)]++
					}
				}
				bound := ceilDiv(runs, len(pool)) * attemptsPerRun
				for slot := range pool {
					if n := used[slot]; n > bound {
						t.Fatalf("%d runs from %d each retried to attempt %d put %d issuances "+
							"on slot %d; interleaved reruns must stay within %d",
							runs, start, attemptsPerRun, n, slot, bound)
					}
				}
				// The count bound above is NOT sensitive to the attempt term --
				// an implementation that ignored the attempt entirely, sending
				// every rerun back to its run's own slot, satisfies it exactly
				// (7 runs x 3 attempts puts 6 on one slot against a bound of
				// 6). This is the assertion that pins the aliasing: reruns must
				// REACH further, so the runs spread over runs+attempts-1 slots
				// rather than piling onto the runs alone.
				if want := min(len(pool), runs+attemptsPerRun-1); len(used) != want {
					t.Fatalf("%d runs from %d retried to attempt %d touched %d slots; a "+
						"rotation that moves reruns touches %d (%v)",
						runs, start, attemptsPerRun, len(used), want, used)
				}
			}
		}
	}
}

// TestPoolSizeAdvisorySpeaksAtEverySizeThatCosts pins WHICH sizes get a warning.
// Silence is read as "the guarantee holds", so a size that degrades quietly is
// worse than no advisory at all.
func TestPoolSizeAdvisorySpeaksAtEverySizeThatCosts(t *testing.T) {
	// 0 and 1 are the unpooled state itself; 2 collapses under the likely
	// stride; the rest are composite.
	for _, size := range []int{0, 1, 2, 4, 6, 8, 9, 10, 12} {
		if poolSizeAdvisory(size) == "" {
			t.Fatalf("pool size %d degrades under a plausible stride but says nothing", size)
		}
	}
	// Primes above two: only a stride equal to the size collapses them, which
	// no size can buy off, so silence here is honest.
	for _, size := range []int{3, 5, 7, 11, 13} {
		if got := poolSizeAdvisory(size); got != "" {
			t.Fatalf("prime pool size %d should be silent, said %q", size, got)
		}
	}
	// Two is the case the strict guard accepts and smallestFactor calls prime.
	// Its warning must name the collapse, not merely exist.
	if got := poolSizeAdvisory(2); !strings.Contains(got, "unpooled") {
		t.Fatalf("the size-2 advisory must say it reaches the unpooled state, said %q", got)
	}
	// Size 1 is reachable from BOTH credential sources, and strict judges them
	// oppositely: it refuses a damaged pool and accepts the single-credential
	// setup. An advisory that asserts a refusal would be printing "strict runs
	// refuse this" from inside a strict run that was not refused, so it has to
	// name both variables and attribute the refusal to the right one.
	got := poolSizeAdvisory(1)
	for _, name := range []string{otpE2EEnrollmentPoolEnv, otpE2EEnrollmentEnv} {
		if !strings.Contains(got, name) {
			t.Fatalf("the size-1 advisory %q does not name %s; it cannot say which "+
				"source is damaged and which is supported", got, name)
		}
	}
	// Today's size, and the size the seventh owner buys.
	if poolSizeAdvisory(len(sixSlotPool)) == "" {
		t.Fatal("today's six-slot pool must warn; the residual is still open")
	}
	if poolSizeAdvisory(len(sixSlotPool)+1) != "" {
		t.Fatal("a seventh owner must silence the advisory; that is how the fix is observed")
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
			// A VALID attempt, so this exercises the case it is named for
			// rather than repeating the both-counters-missing case below.
			"GITHUB_RUN_ATTEMPT": "1",
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

	// loadOTPE2EConfig's contract is to collect EVERY missing variable so a
	// misconfiguration is fixed in one pass. The rotation guard has to obey it
	// too, or a runner that dropped both counters costs two full gate cycles.
	t.Run("strict run names both counters when both are unusable", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo\nthree",
			otpE2EStrictEnv:         "1",
		})))
		if err == nil {
			t.Fatal("strict run with neither counter selected at random")
		}
		for _, name := range []string{"GITHUB_RUN_NUMBER", "GITHUB_RUN_ATTEMPT"} {
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("strict error %q omits %s; fixing one would burn a gate cycle "+
					"to discover the other", err, name)
			}
		}
	})

	// THE CONFIGURATION THE GATE ACTUALLY RUNS IN. Every other strict subtest
	// here expects an error, so only the FIRING side of the two new guards was
	// pinned -- nothing proved they stay silent on a real run. Without this,
	// widening the truncation threshold to len(pool) < 3 leaves the whole suite
	// green and hard-fails the next real PR on a REQUIRED check, with a message
	// pointing away from the change under test: the exact failure this file
	// exists to remove.
	t.Run("strict run with a rotating pool is accepted", func(t *testing.T) {
		cfg, skip, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo\nthree",
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err != nil || skip {
			t.Fatalf("the gate's own configuration was rejected: skip %t, err %v", skip, err)
		}
		// Observes end to end, through loadOTPE2EConfig, that the config the
		// gate consumes carries the ROTATED slot rather than a random one.
		if want := 41 % 3; cfg.enrollmentSlot != want {
			t.Fatalf("slot = %d, want the rotation's %d", cfg.enrollmentSlot, want)
		}
		if cfg.enrollmentPoolSize != 3 {
			t.Fatalf("pool size = %d, want 3", cfg.enrollmentPoolSize)
		}
	})

	// The BOUNDARY of the truncation guard. Two credentials is the smallest
	// genuinely-pooled configuration, so it must be accepted -- this is what
	// pins the threshold at "< 2" specifically. A three-entry happy path alone
	// does not: widening the guard to "< 3" would still leave it green.
	t.Run("strict run accepts the smallest real pool", func(t *testing.T) {
		cfg, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one\ntwo",
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err != nil {
			t.Fatalf("a two-credential pool is a real pool and must rotate: %v", err)
		}
		if want := 41 % 2; cfg.enrollmentSlot != want {
			t.Fatalf("slot = %d, want the rotation's %d", cfg.enrollmentSlot, want)
		}
	})

	// The reviewer's scenario end to end: six distinct owners plus one repeated
	// line. Without dedup this reports SEVEN slots -- overstating the ceiling,
	// spending two of seven slots on one credential, and (because 7 is prime)
	// silencing the composite-size warning at the exact moment the pool is
	// degraded. Secrets are write-only, so whoever appends the seventh owner
	// cannot look first; this is the failure that mistake produces.
	t.Run("a duplicated credential does not inflate the pool size", func(t *testing.T) {
		cfg, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "a\nb\nc\nd\ne\nf\nc",
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err != nil {
			t.Fatalf("a pool with a repeated line is usable, just smaller: %v", err)
		}
		if cfg.enrollmentPoolSize != 6 {
			t.Fatalf("pool size = %d, want 6 distinct credentials from 7 lines",
				cfg.enrollmentPoolSize)
		}
		if cfg.enrollmentPoolDuplicates != 1 {
			t.Fatalf("duplicates = %d, want 1; the operator needs to be told",
				cfg.enrollmentPoolDuplicates)
		}
		// Six is composite, so the stride warning must still fire. An inflated
		// size of seven would have suppressed it.
		if smallestFactor(cfg.enrollmentPoolSize) == 0 {
			t.Fatal("a degraded pool reported a prime size; the stride warning is silenced")
		}
	})

	// The crack the parse-result keying left open: a pool variable that yields
	// NOTHING. Whitespace, or " , , ", parses to zero credentials, so keying
	// fromPool on len(pool) would let the single-credential variable be adopted
	// silently -- a worse version of the very mistake the guard catches at one
	// entry, and invisible because no note or error would print.
	t.Run("strict run refuses a pool variable that yielded nothing", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: " , , ",
			otpE2EEnrollmentEnv:     "solo", // present, and must NOT rescue it
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err == nil {
			t.Fatal("strict run silently fell back to the single credential and ran unpooled")
		}
		if !strings.Contains(err.Error(), otpE2EEnrollmentPoolEnv) {
			t.Fatalf("strict error %q does not name the damaged variable", err)
		}
		// The COUNT must be the pool variable's own yield, which is zero. The
		// single credential backfilled `pool` to one, and reporting that would
		// attribute another variable's credential to this one -- sending the
		// operator after a pool truncated to one line when it holds none.
		if !strings.Contains(err.Error(), "parsed 0 credential") {
			t.Fatalf("strict error %q reports the backfilled count; the pool yielded none", err)
		}
	})

	// A secret re-saved as the same credential twice collapses to one entry.
	// That is a duplicate, not a truncation, and the duplicates NOTE lives in
	// the test body -- past the t.Fatal this error causes -- so the message
	// itself has to say which mistake was made.
	t.Run("truncation error names duplicates when that is the cause", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "a\na",
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err == nil {
			t.Fatal("strict run accepted a pool of one repeated credential")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("strict error %q blames truncation; the secret was duplicated", err)
		}
	})

	// A pool secret re-saved truncated -- one line kept, or six credentials
	// pasted space-separated, which parseEnrollmentPool collapses to one entry
	// since it splits only on newline, CR and comma -- silently returns the gate
	// to 5 issuances an hour for everything, which is the pre-pool state this
	// whole change exists to prevent. Strict mode is loud about the counters;
	// it has to be loud about this too.
	t.Run("strict run refuses a pool variable that yielded one credential", func(t *testing.T) {
		_, _, err := loadOTPE2EConfig(envFrom(with(map[string]string{
			otpE2EEnrollmentPoolEnv: "one two three", // spaces are not separators
			otpE2EStrictEnv:         "1",
			"GITHUB_RUN_NUMBER":     "41",
			"GITHUB_RUN_ATTEMPT":    "1",
		})))
		if err == nil {
			t.Fatal("strict run accepted a one-entry pool; the gate would run unpooled")
		}
		if !strings.Contains(err.Error(), otpE2EEnrollmentPoolEnv) {
			t.Fatalf("strict error %q does not name the truncated variable", err)
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
