package nativeudp_test

// End-to-end proof that a code a real person would read out of a real inbox
// completes SDK registration, and that repeating the call is idempotent.
//
// WHY THIS EXISTS SEPARATELY FROM native_udp_sandbox_test.go: that suite is
// the attended UDP proof's client half — it runs under a dispatch workflow
// that requires an NHP controller run id, and it wraps every assertion in
// evidence collection, provenance chains, and signed manifests whose
// infrastructure was removed with the attended proof itself. It also never
// re-registers, so idempotency has never actually been asserted anywhere.
//
// This file is deliberately lean enough to run on a hosted runner inside a
// pull request: real hub, real UDP, real emailed code, no evidence apparatus,
// no in-VPC runner, no environment lock.
//
// PUBLIC REPOSITORY: every environment-specific value is read from the
// environment. Nothing here may carry a hostname, account id, bucket, queue
// URL, or key id as a literal.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

const (
	// otpE2EStrictEnv turns a missing prerequisite from "skip" into "fail".
	//
	// This matters more than it looks. The workflow that runs this test is a
	// REQUIRED status check, and a test that skips reports success — so a
	// dropped secret or a renamed variable would silently convert the gate
	// into a rubber stamp. CI sets this; a developer running locally without
	// sandbox access still gets a clean skip.
	otpE2EStrictEnv = "QURL_OTP_E2E_STRICT"

	otpE2EHubHostEnv    = "QURL_OTP_E2E_HUB_HOST"
	otpE2EHubPortEnv    = "QURL_OTP_E2E_HUB_PORT"
	otpE2EHubKeyEnv     = "QURL_OTP_E2E_HUB_SERVER_KEY"
	otpE2EEnrollmentEnv = "QURL_OTP_E2E_ENROLLMENT"
	// otpE2EEnrollmentPoolEnv holds several credentials, one per line. See
	// selectEnrollment for why the pool exists and why it is keyed on owners.
	otpE2EEnrollmentPoolEnv = "QURL_OTP_E2E_ENROLLMENT_POOL"
	otpE2EAgentIDEnv        = "QURL_OTP_E2E_AGENT_ID"

	otpE2EMailboxQueueURLEnv  = "QURL_OTP_E2E_MAILBOX_QUEUE_URL"
	otpE2EMailboxBucketEnv    = "QURL_OTP_E2E_MAILBOX_BUCKET"
	otpE2EMailboxRecipientEnv = "QURL_OTP_E2E_MAILBOX_RECIPIENT"
	otpE2EMailboxRegionEnv    = "QURL_OTP_E2E_MAILBOX_REGION"

	// otpE2EHostname and otpE2EVersion are the bounded audit fields assigned-cell
	// REG carries. They are required -- omitting them is rejected as 52109
	// "registration input invalid" -- and they surface in the OTP email body, so
	// they name this gate rather than a generic placeholder.
	otpE2EHostname = "otp-gate.ci.qurl-go"
	otpE2EVersion  = "otp-registration-gate"

	// otpE2EMailboxWait is the mailbox's own budget, kept below otpE2EDeadline
	// so a mailbox timeout reports ITS reason rather than being overwritten by
	// the SDK with a bare context deadline.
	otpE2EMailboxWait = 4 * time.Minute

	// otpE2EDeadline bounds the whole exchange. Most of it is waiting for SES
	// to deliver: issuance, delivery, S3 write, and the SQS notification are
	// each fast, but the sum is not instant.
	otpE2EDeadline = 5 * time.Minute
)

type otpE2EConfig struct {
	hub        qurl.HubBootstrap
	enrollment string
	agentID    string

	// enrollmentSlot and enrollmentPoolSize are evidence, not inputs: a run
	// that fails on the issuance rate limit needs to say WHICH credential it
	// spent, and the pool is secret so the value itself can never be logged.
	enrollmentSlot     int
	enrollmentPoolSize int
	// enrollmentPoolDuplicates is how many repeated credentials the secret
	// carried. Non-zero means the pool is smaller than whoever seeded it
	// believes, which is invisible from the secret itself.
	enrollmentPoolDuplicates int

	mailboxQueueURL  string
	mailboxBucket    string
	mailboxRecipient string
	mailboxRegion    string
}

// loadOTPE2EConfig reports (config, skip, error). It collects EVERY missing
// variable before returning so a misconfigured workflow is fixed in one pass
// rather than one variable per CI round-trip.
func loadOTPE2EConfig(lookup func(string) string) (otpE2EConfig, bool, error) {
	required := []string{
		otpE2EHubHostEnv, otpE2EHubPortEnv, otpE2EHubKeyEnv,
		otpE2EAgentIDEnv,
		otpE2EMailboxQueueURLEnv, otpE2EMailboxBucketEnv,
		otpE2EMailboxRecipientEnv, otpE2EMailboxRegionEnv,
	}
	var missing []string
	for _, name := range required {
		if strings.TrimSpace(lookup(name)) == "" {
			missing = append(missing, name)
		}
	}

	// The credential arrives as a pool or as a single value, so neither name
	// belongs in `required` on its own -- either one alone satisfies this.
	pool, poolDuplicates := parseEnrollmentPool(lookup(otpE2EEnrollmentPoolEnv))
	// Whether the POOL variable is the source decides whether a short result is
	// a configuration or an accident: the single-credential setup has its own
	// variable, so a pool that parsed to fewer than two credentials is damage.
	//
	// Keyed on the RAW variable, not on the parse result. The question is "did
	// an operator intend a pool here", and only the raw value answers it: a
	// secret re-saved to whitespace, or to " , , ", parses to nothing, and
	// keying on len(pool) would make that MORE invisible than the single-entry
	// case the guard already catches -- the pool source would go unnoticed, the
	// single-credential variable would be adopted, and a strict run would
	// proceed unpooled at 5/hour with neither an error nor a note.
	// NOT TrimSpace'd. Trimming answers "does this hold credentials", which the
	// parse result already answers; the question here is "did an operator set
	// this variable", and only the untouched value answers that. Trimming got
	// it wrong for exactly one of the two damage shapes named above: " , , "
	// survives a trim and a whitespace-only secret does not, so two values that
	// both parse to zero credentials took opposite branches -- one correctly
	// reported as damaged, the other reported as ABSENT, which is the
	// misdirection the branch below exists to prevent.
	fromPool := lookup(otpE2EEnrollmentPoolEnv) != ""
	// The pool variable's OWN yield, captured before the single-credential
	// backfill below can overwrite it. Reporting len(pool) after the backfill
	// would attribute another variable's credential to this one: a pool of
	// " , , " alongside a valid single credential yields zero here and one
	// there, and the operator would be sent hunting for a pool truncated to one
	// line when the pool in fact contains no credentials at all.
	fromPoolCount := len(pool)
	if len(pool) == 0 {
		if single := strings.TrimSpace(lookup(otpE2EEnrollmentEnv)); single != "" {
			pool = []string{single}
		}
	}
	if len(pool) == 0 {
		// "Missing" is the wrong word when the variable is SET and simply
		// yields nothing, and it is the wrong word on the branch production
		// actually takes: both workflows supply only the pool variable, so a
		// secret damaged to whitespace lands here rather than in the
		// damaged-pool guard further down, which sits after this early return.
		// Reporting it as absent sends the operator to Settings to find the
		// secret sitting right where they left it.
		if fromPool {
			missing = append(missing, otpE2EEnrollmentPoolEnv+
				" (present, but it parsed to 0 credentials -- a damaged or whitespace-only secret)")
		} else {
			missing = append(missing, otpE2EEnrollmentPoolEnv+" (or "+otpE2EEnrollmentEnv+")")
		}
	}

	strict := strings.TrimSpace(lookup(otpE2EStrictEnv)) != ""
	if len(missing) > 0 {
		if strict {
			detail := strings.Join(missing, ", ")
			// The counters are an independent fault, and this return is the one
			// a pool that parsed to ZERO credentials takes -- the shape both
			// workflows can actually produce, since they supply only the pool
			// variable. The aggregated guard further down never runs on this
			// branch, so without this the second fault costs another gate cycle
			// to discover, which is the contract this function opens by stating.
			if fromPool {
				if blocked := blockedRotationCounters(lookup); len(blocked) > 0 {
					detail += "; and " + strings.Join(blocked, " and ") +
						" unusable, so selection could not have rotated either"
				}
			}
			return otpE2EConfig{}, false, fmt.Errorf(
				"strict OTP e2e run is missing %d prerequisite(s): %s", len(missing), detail)
		}
		return otpE2EConfig{}, true, nil
	}

	port, err := strconv.Atoi(strings.TrimSpace(lookup(otpE2EHubPortEnv)))
	if err != nil || port <= 0 || port > 65535 {
		return otpE2EConfig{}, false, fmt.Errorf("%s must be a valid UDP port", otpE2EHubPortEnv)
	}

	enrollment, slot, _ := selectEnrollment(pool, lookup)

	// Every other prerequisite in this gate is loud (see otpE2EStrictEnv), and
	// the rotation has to join them. A missing GITHUB_RUN_NUMBER falls back to
	// random, which quietly reinstates the clustering the pool exists to avoid
	// -- and the only symptom would be this gate going red again weeks later,
	// for the same reason and with the same misleading evidence as last time.

	// ONE report, not one per gate cycle. loadOTPE2EConfig's contract is to
	// collect every misconfiguration before returning, and these two are
	// independent: a damaged pool secret and a runner that stopped exporting a
	// counter can be true at once, and returning on the first would hide the
	// second until the next run. That matters more here than for `missing`,
	// because a damaged pool makes selectEnrollment short-circuit and report
	// nothing blocked at all -- so the counter fault would not merely be
	// deferred, it would be invisible until the secret was fixed.
	if strict {
		var degraded []string

		// A pool that lost its slots degrades exactly as silently as a missing
		// counter, and to the same place: one credential, and the whole gate on
		// that credential's hourly budget, which is the state the pool exists to
		// leave. The only other signal is "slot 0 of 1", in a log the canary
		// does not print.
		if fromPool && fromPoolCount < 2 {
			degraded = append(degraded, fmt.Sprintf(
				"%s parsed %d credential(s)%s: the pool is the multi-credential source "+
					"(single credentials belong in %s), so this is a damaged secret and the "+
					"gate would run unpooled at %d/hour",
				otpE2EEnrollmentPoolEnv, fromPoolCount, duplicateSuffix(poolDuplicates),
				otpE2EEnrollmentEnv, perCredentialHourlyBudget))
		}

		// Asked whenever a pool is INTENDED: the supported single-credential
		// setup has nothing to rotate and must not be failed, but a damaged pool
		// still needs its counters reported alongside it. fromPool is the whole
		// condition -- a pool of more than one entry can only have come from the
		// pool variable, so testing len(pool) as well would suggest a second
		// path into this guard that does not exist.
		if fromPool {
			if blocked := blockedRotationCounters(lookup); len(blocked) > 0 {
				degraded = append(degraded, fmt.Sprintf(
					"%s unusable, so credential selection fell back to random and the pool "+
						"would cluster rather than rotate",
					strings.Join(blocked, " and ")))
			}
		}

		if len(degraded) > 0 {
			return otpE2EConfig{}, false, fmt.Errorf(
				"strict OTP e2e run cannot rotate credentials: %s",
				strings.Join(degraded, "; "))
		}
	}

	return otpE2EConfig{
		hub: qurl.HubBootstrap{
			Host: strings.TrimSpace(lookup(otpE2EHubHostEnv)),
			// Supplied, never defaulted to the package's standardNHPUDPPort:
			// that constant is the INTERNAL bind. The publicly reachable hub
			// listener is a different port, and hardcoding either one here
			// would silently point a hosted runner at an unreachable socket.
			Port:               port,
			ServerPublicKeyB64: strings.TrimSpace(lookup(otpE2EHubKeyEnv)),
		},
		enrollment:               enrollment,
		enrollmentSlot:           slot,
		enrollmentPoolSize:       len(pool),
		enrollmentPoolDuplicates: poolDuplicates,
		agentID:                  runScopedAgentID(strings.TrimSpace(lookup(otpE2EAgentIDEnv)), lookup),
		mailboxQueueURL:          strings.TrimSpace(lookup(otpE2EMailboxQueueURLEnv)),
		mailboxBucket:            strings.TrimSpace(lookup(otpE2EMailboxBucketEnv)),
		mailboxRecipient:         strings.TrimSpace(lookup(otpE2EMailboxRecipientEnv)),
		mailboxRegion:            strings.TrimSpace(lookup(otpE2EMailboxRegionEnv)),
	}, false, nil
}

// parseEnrollmentPool splits the pool secret into credentials, reporting how
// many duplicate entries it dropped.
//
// Newline is the natural separator for a multi-line GitHub secret; comma is
// accepted so the same value can be passed on a command line. Blank entries are
// dropped rather than becoming an empty credential that fails obscurely later.
//
// DEDUPLICATION IS LOAD-BEARING, not tidiness. len(pool) is the denominator of
// the 5*len(pool) hourly ceiling, the pool size in this run's evidence, and the
// input to smallestFactor -- the runtime half of the stride guard. A repeated
// credential breaks all three at once and in the REASSURING direction: six
// distinct owners plus one duplicated line parses to seven, the rotation spends
// two of its seven slots on one credential so that credential takes double
// traffic and hits its 5/hour cap early, and smallestFactor(7) is 0 so the gate
// prints no composite-size warning -- reporting an arithmetic guarantee at the
// exact moment the pool is degraded.
//
// That is reachable, not theoretical: GitHub secrets are write-only, so an
// operator adding an owner cannot read the current value to check whether the
// line is already there. Counting the drops rather than swallowing them tells
// them which mistake they made -- a duplicate paste, or a seeding that never
// landed -- since both otherwise present only as a pool smaller than expected.
func parseEnrollmentPool(raw string) ([]string, int) {
	var pool []string
	seen := map[string]bool{}
	duplicates := 0
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	}) {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			continue
		}
		if seen[trimmed] {
			duplicates++
			continue
		}
		seen[trimmed] = true
		pool = append(pool, trimmed)
	}
	return pool, duplicates
}

// selectEnrollment picks this run's credential and reports which slot it used.
//
// Registration OTP issuance is rate limited on four dimensions, and only two of
// them can bind this gate: 5/hour per credential and 10/hour per owner. (Per
// peer is 5/hour but every run generates a fresh device key, and per source is
// 60/hour across runner IPs that vary.) So a single credential caps the gate at
// five runs an hour -- which a busy afternoon on a REQUIRED check exhausts,
// turning the gate red for reasons that have nothing to do with the change
// under test. That is not hypothetical; it is what happened while building
// this.
//
// The pool is therefore one credential per DISTINCT owner, because owners are
// the dimension that scales without bound: a SECOND credential on an owner
// already in the pool buys five more runs an hour and then stops dead at that
// owner's ten, while each new owner buys another five every time.
//
// THE BINDING LIMIT IS THE CREDENTIAL'S FIVE, NOT THE OWNER'S TEN. With one
// credential per owner the per-owner budget is unreachable -- a slot's own
// credential refuses its sixth issuance while its owner is only halfway to ten
// -- so the POOL is worth 5/hour per slot and 5*len(pool) per hour in total.
// That is the pool's ceiling, not this workflow's: otp-schema-v2-canary.yml
// runs this same test against the same secret on its own run-number sequence,
// so both workflows spend from these totals. Two independently phased rotations
// each stay within one of ideal, so their per-slot sum stays within two (two
// hashes would not), and the canary is attended dispatch, so this composes
// today -- but the number belongs to the pool, not to either caller.
//
// SELECTION MUST ROTATE, NOT HASH. Both spread runs across the pool "evenly" in
// the long run, but a hash spreads them INDEPENDENTLY: it is balls-in-bins, and
// the whole pool goes red as soon as any one bin reaches five, which happens far
// below 5*len(pool). This is not a theoretical worry -- it is the outage that
// prompted this comment. On 2026-08-31 nine issuances in the hour hashed into
// slots {4:5, 0:3, 2:1}: three of six slots touched, slot 4 at its cap, and the
// tenth run refused with twenty-one of the pool's thirty still unspent. Replayed
// over the whole recorded history (135 issuances), hashing peaks at 5 in a
// rolling hour -- exactly the cap -- while rotating peaks at 3.
//
// GITHUB_RUN_NUMBER is the rotation counter: unlike GITHUB_RUN_ID (a global
// GitHub id whose irregular gaps make it hash-like), it increments by exactly
// one per run OF THIS WORKFLOW, so consecutive runs take consecutive slots.
// Adding the attempt rotates a rerun onto the next slot -- reruns are the case
// that actually exhausted a credential, since the previous attempt just spent
// that slot's budget.
//
// KEEP len(pool) PRIME. The rotation runs over ALL gate runs, but only the ones
// the scope step finds relevant spend an issuance, so spending runs are a
// SUBSEQUENCE -- and a subsequence of stride d visits only len(pool)/gcd(d,
// len(pool)) slots. Six is the worst size available for that: 6 = 2*3, so a
// stretch where relevant and irrelevant PRs merely alternate (d=2) collapses
// the pool onto three slots and reproduces the original outage with a different
// traffic shape. At a prime size every stride up to len(pool) stays coprime and
// the ceiling holds arithmetically instead of empirically.
// TestSelectEnrollmentStridedTrafficNeedsACoprimePoolSize pins both halves.
// Today's pool is six, which is a seeding decision rather than a code one: a
// seventh owner would close this, and until then the guarantee is empirical.
// It does hold empirically -- replaying the 135 recorded issuances at their
// real run numbers, real skips included, the worst rolling hour puts 3 on a
// slot against the hash's 5 -- but empirical is weaker than arithmetic, and
// this is the residual to check first if the gate ever clusters again.
//
// The SECOND thing to check is relevance DENSITY, which is the residual a fixed
// stride does not describe. Real skips are irregular rather than strided (there
// is no trigger-level paths: filter, so every PR takes a run number while only
// GATE_PATHS spends), and irregular skips push runNumber mod len(pool) back
// toward the independence a hash has. Rotation still wins for any plausible
// traffic -- over M consecutive numbers at relevance density p, per-slot
// variance is (Mp/n)(1-p) rotating against (Mp/n)((n-1)/n) hashing, so rotation
// is strictly better whenever p > 1/n, and GATE_PATHS covers nearly the repo --
// but a gate that clustered again with a prime pool would be telling you the
// density collapsed.
//
// THE SLOT IS NO LONGER RECOMPUTABLE OFFLINE, which is a real cost of this
// change and the thing to know before auditing the pool again. The previous
// selection was a pure function of GITHUB_RUN_ID and the attempt, and
// runScopedAgentID bakes both into the agent credential's name
// (agent:...-<runid>-<attempt>), so which slot a past run drew could be
// recomputed from the sandbox record alone -- that is how the
// one-credential-per-distinct-owner premise was proven over 136 registrations.
// GITHUB_RUN_NUMBER is not in that name and is not derivable from the run id,
// so the same audit now needs a join: `gh run list --workflow
// otp-registration-gate.yml --json databaseId,number` maps run id to run
// number, and the run history outlives the 30-day log retention that the
// EVIDENCE line depends on. Recoverable, then, but no longer free. Putting the
// run number into the agent id would restore the offline property at the cost
// of changing a live registration input, which is not a trade worth making
// inside a change about selection.
//
// GITHUB_RUN_NUMBER restarts at 1 if this workflow file is ever renamed. That
// only re-phases the rotation -- every property here is modular and holds from
// any offset, which is what sweepStarts pins -- so it costs nothing. Noted
// because a counter that jumps backwards looks like evidence during an
// investigation, and it is not.
//
// A rerun aliases onto its neighbour by construction: (N, attempt 2) and
// (N+1, attempt 1) resolve to the same slot, where the hash collided only one
// time in len(pool). Any additive offset does this, and the cost is bounded at
// one extra issuance on one slot rather than a cluster, so it is a deliberate
// trade rather than an oversight.
//
// Off CI there is no counter to rotate on, so fall back to random: repeated
// local runs are just as capable of exhausting one credential.
// The third return names EVERY counter that prevented the rotation, empty when
// the run rotated (or had nothing to rotate). Callers report them all, matching
// loadOTPE2EConfig's rule for missing variables: naming the wrong one, or only
// the first of two, costs a whole gate cycle per variable to discover.
func selectEnrollment(pool []string, lookup func(string) string) (string, int, []string) {
	switch len(pool) {
	case 0:
		return "", -1, nil
	case 1:
		// One credential is the whole pool, so there is nothing to rotate and
		// nothing for a caller to warn about.
		return pool[0], 0, nil
	}

	// BOTH counters must be usable, and an unreadable attempt is not the softer
	// failure it looks like: defaulting it to 1 would resolve every attempt of
	// run N onto N's slot, spending that one credential five times over the
	// reruns -- which is the exact case that exhausted a credential before the
	// pool existed. Treat it exactly as strictly as the run number.
	runNumber, haveRun := rotationCounter(lookup, "GITHUB_RUN_NUMBER", 1)
	attempt, haveAttempt := rotationCounter(lookup, "GITHUB_RUN_ATTEMPT", 1)
	if haveRun && haveAttempt {
		// Reduce both terms before adding. A real run number never approaches
		// MaxInt, but this reads an environment variable, and the sum of two
		// unreduced values there would overflow to a negative slot and panic
		// the index below rather than fail some assertion. Both counters are
		// >= 1 here, so attempt-1 cannot underflow either.
		slot := (runNumber%len(pool) + (attempt-1)%len(pool)) % len(pool)
		return pool[slot], slot, nil
	}

	// Only now, on the path that failed, is it worth re-reading the variables to
	// name which one did it. The helper is shared with loadOTPE2EConfig, which
	// must be able to ask the same question when the pool is too small to
	// rotate and this function has already short-circuited.
	blocked := blockedRotationCounters(lookup)

	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return pool[0], 0, blocked
	}
	slot := int(binary.BigEndian.Uint32(raw) % uint32(len(pool)))
	return pool[slot], slot, blocked
}

// duplicateSuffix names dropped duplicates inside the truncation error. The
// duplicates NOTE is logged by the test body, which never runs when this error
// aborts the load -- so a secret re-saved as the same credential twice would
// otherwise be reported as a truncation and send the operator hunting for a
// missing line rather than a repeated one.
func duplicateSuffix(duplicates int) string {
	if duplicates == 0 {
		return ""
	}
	return fmt.Sprintf(" (after dropping %d duplicate(s))", duplicates)
}

// poolSizeAdvisory reports what a given LIVE pool size costs, or "" when the
// size carries no warning. Pure and separate from the test body so the wording
// each size produces is itself asserted -- an advisory that goes quiet at the
// wrong size is worse than none, because silence here is read as "the guarantee
// holds".
//
// Two is the case that makes "silent" and "safe" come apart. It is prime, so
// smallestFactor says nothing, and the strict guard deliberately accepts it as
// the smallest real pool -- but the LIKELY spending stride is 2, which equals
// the size, so alternating relevant and irrelevant PRs put every issuance on
// one credential. That is the same unpooled state the truncation guard hard
// fails at one credential to prevent, and it must not arrive quietly.
//
// The line between two and three is plausibility, not arithmetic, and is worth
// stating because it is the only judgement here. EVERY size collapses at a
// stride equal to itself, three included; no size can buy that off. What makes
// two different is that its self-collapsing stride is 2 -- the one shape this
// file names as likely, since relevant and irrelevant PRs alternating is
// ordinary traffic. A stride of exactly three is not, so three stays silent.
func poolSizeAdvisory(size int) string {
	if size < 2 {
		// Deliberately silent about which source this came from, because both
		// reach here and they are judged differently: from the pool variable a
		// strict run has already refused it, while from the single-credential
		// variable it is the supported setup and strict accepts it. Saying
		// "strict runs refuse this" would be false in the second case, printed
		// from inside a strict run that was not refused.
		return fmt.Sprintf("pool size %d is not a pool: every run spends the same "+
			"credential, so the gate is worth %d/hour. From %s that is a damaged secret, "+
			"which a strict run refuses; from %s it is the supported single-credential "+
			"setup and this is just the ceiling. See selectEnrollment",
			size, perCredentialHourlyBudget, otpE2EEnrollmentPoolEnv, otpE2EEnrollmentEnv)
	}
	if size == 2 {
		return fmt.Sprintf("pool size 2 is the smallest the strict guard accepts, and the "+
			"likely spending stride of 2 EQUALS it: alternating relevant and irrelevant "+
			"PRs would put every issuance on one credential, i.e. %d/hour, which is the "+
			"unpooled state. Seed more owners -- a PRIME size above two is what makes the "+
			"rotation's guarantee arithmetic; see selectEnrollment", perCredentialHourlyBudget)
	}
	factor := smallestFactor(size)
	if factor == 0 {
		return ""
	}
	likely, worst := factor, size/factor
	if likely == worst {
		// A prime square (or 4): the two strides coincide, and naming them
		// separately would read as a contradiction.
		return fmt.Sprintf("pool size %d is composite: a spending stride of %d collapses it "+
			"onto %d slot(s). A PRIME size makes the rotation's guarantee arithmetic rather "+
			"than empirical; see selectEnrollment", size, likely, worst)
	}
	return fmt.Sprintf("pool size %d is composite: a spending stride of %d (the likely one) "+
		"collapses it onto %d slot(s), and a stride of %d onto %d -- the worst case. A PRIME "+
		"size makes the rotation's guarantee arithmetic rather than empirical; see "+
		"selectEnrollment", size, likely, worst, worst, likely)
}

// smallestFactor returns the smallest non-trivial divisor of n, or 0 when n is
// prime (or too small to matter). A composite pool size is what lets a strided
// spending pattern collapse the rotation onto a subset of the pool.
func smallestFactor(n int) int {
	if n < 4 {
		return 0
	}
	for d := 2; d*d <= n; d++ {
		if n%d == 0 {
			return d
		}
	}
	return 0
}

// blockedRotationCounters names every counter that cannot carry a rotation.
//
// Separate from selectEnrollment so a caller can ask the question even when the
// pool is too small to rotate: selectEnrollment short-circuits at one credential
// and reports nothing blocked, which is right for selection but would hide a
// broken counter behind a damaged pool and cost a second gate cycle to find.
func blockedRotationCounters(lookup func(string) string) []string {
	var blocked []string
	if _, ok := rotationCounter(lookup, "GITHUB_RUN_NUMBER", 1); !ok {
		blocked = append(blocked, "GITHUB_RUN_NUMBER")
	}
	if _, ok := rotationCounter(lookup, "GITHUB_RUN_ATTEMPT", 1); !ok {
		blocked = append(blocked, "GITHUB_RUN_ATTEMPT")
	}
	return blocked
}

// rotationCounter reads one of the two GitHub counters the rotation turns on,
// reporting whether the value is usable rather than substituting a default.
// Actions always exports both; anything else is a runner regression, and the
// caller's job is to make that loud instead of quietly selecting at random.
//
// Both floors are 1 because both counters are 1-based by GitHub's contract. A
// zero is therefore already a runner regression and is refused rather than
// rotated on -- the floor tracks the variable's semantics, not what happens to
// be convenient for a caller.
//
// The ATTEMPT floor is also load-bearing arithmetic, and must not be relaxed on
// the semantic argument alone. Go's % keeps the sign of its operand, so an
// attempt of 0 makes (attempt-1)%n equal -1, and a run number divisible by the
// pool size then yields slot -1 and panics the index. That is pinned by the
// GITHUB_RUN_NUMBER=6/GITHUB_RUN_ATTEMPT=0 row in
// TestSelectEnrollmentAlwaysReturnsAPoolMember, which exists because the
// obvious zero-zero row cannot reach it: the run-number floor blocks first.
func rotationCounter(lookup func(string) string, name string, lowest int) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(lookup(name)))
	if err != nil || parsed < lowest {
		return 0, false
	}
	return parsed, true
}

// runScopedAgentID appends a per-run suffix to the configured agent id.
//
// An agent that has already COMPLETED enrolment cannot enrol again from a new
// device key: the authority holds a COMPLETION record binding that agent to the
// original device credential, and a fresh registration then fails its OTP check
// with 52100 "one-time code incorrect" even though the delivered code is
// correct. Verified by isolation -- same credential, agent with a completion
// record fails, fresh agent passes.
//
// This test creates a new state directory, and therefore a new device key, on
// every run, so it needs a new agent identity to match. The retired proof
// harness embedded the controller run id in its agent ids for the same reason.
//
// Falls back to random off CI. Agent ids allow only lowercase letters, digits
// and hyphens, must be 2-64 characters, and must start and end alphanumeric.
func runScopedAgentID(base string, lookup func(string) string) string {
	suffix := strings.ToLower(strings.TrimSpace(lookup("GITHUB_RUN_ID")))
	if attempt := strings.TrimSpace(lookup("GITHUB_RUN_ATTEMPT")); suffix != "" && attempt != "" {
		suffix += "-" + strings.ToLower(attempt)
	}
	if suffix == "" {
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err == nil {
			suffix = hex.EncodeToString(raw)
		}
	}
	suffix = strings.Trim(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, suffix), "-")
	if base == "" || suffix == "" {
		return base
	}
	scoped := base + "-" + suffix
	if len(scoped) > 64 {
		scoped = strings.Trim(scoped[:64], "-")
	}
	return scoped
}

// ephemeralStateKeyWrapper is a valid AgentStateKeyWrapper backed by a random
// key held only in this process's memory.
//
// The sealed store requires a wrapper; this test is not about key custody, and
// a KMS-backed one would add an IAM surface and a second AWS dependency for no
// assertion. The binding is authenticated as AAD, so a record wrapped under a
// different agent or provider fails closed exactly as a real provider must.
type ephemeralStateKeyWrapper struct {
	aead cipher.AEAD
}

func newEphemeralStateKeyWrapper() (*ephemeralStateKeyWrapper, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("draw ephemeral state key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("construct ephemeral state cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("construct ephemeral state AEAD")
	}
	return &ephemeralStateKeyWrapper{aead: aead}, nil
}

func (w *ephemeralStateKeyWrapper) aad(binding qurl.AgentStateKeyBinding) ([]byte, error) {
	// Every binding field is authenticated, as the interface requires.
	return json.Marshal([]string{
		binding.Purpose, strconv.Itoa(binding.EnvelopeVersion),
		binding.ProviderID, binding.AgentID,
	})
}

func (w *ephemeralStateKeyWrapper) WrapKey(
	_ context.Context, plaintextKey []byte, binding qurl.AgentStateKeyBinding,
) (qurl.WrappedAgentStateKey, error) {
	aad, err := w.aad(binding)
	if err != nil {
		return qurl.WrappedAgentStateKey{}, errors.New("encode ephemeral key binding")
	}
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return qurl.WrappedAgentStateKey{}, errors.New("draw ephemeral wrap nonce")
	}
	return qurl.WrappedAgentStateKey{
		Version:    1,
		Ciphertext: w.aead.Seal(nonce, nonce, plaintextKey, aad),
	}, nil
}

func (w *ephemeralStateKeyWrapper) UnwrapKey(
	_ context.Context, wrapped qurl.WrappedAgentStateKey, binding qurl.AgentStateKeyBinding,
) ([]byte, error) {
	aad, err := w.aad(binding)
	if err != nil {
		return nil, errors.New("encode ephemeral key binding")
	}
	if wrapped.Version != 1 || len(wrapped.Ciphertext) < w.aead.NonceSize() {
		// Fail closed as ErrInvalidWrappedAgentStateKey, not as an outage:
		// a malformed record is tampering, not a retryable provider blip.
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	nonce := wrapped.Ciphertext[:w.aead.NonceSize()]
	key, err := w.aead.Open(nil, nonce, wrapped.Ciphertext[w.aead.NonceSize():], aad)
	if err != nil {
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	return key, nil
}

// TestEmailedOTPCompletesIdempotentSDKRegistration is the whole point of the
// gate: a code that actually travelled through SES to a real mailbox registers
// a real SDK client, and calling register again does not enroll a second time.
func TestEmailedOTPCompletesIdempotentSDKRegistration(t *testing.T) {
	cfg, skip, err := loadOTPE2EConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if skip {
		t.Skipf("OTP e2e prerequisites absent; set %s to make this fatal", otpE2EStrictEnv)
	}

	// Logged HERE, before anything can fail, not beside the success assertion.
	// The failure this evidence exists for -- a refused issuance, which arrives
	// as a mailbox timeout -- kills the test inside ConnectAgentRuntime below,
	// so a slot logged after that call is absent from precisely the run whose
	// diagnosis needs it. Every other failure in the exchange gets it too.
	t.Logf("EVIDENCE this run drew credential slot %d of %d",
		cfg.enrollmentSlot, cfg.enrollmentPoolSize)

	// The pool's SIZE decides whether the rotation survives a strided spending
	// pattern (see selectEnrollment). That size lives in a secret, so no test
	// can assert it -- say it out loud on the runs that actually load it.
	if advisory := poolSizeAdvisory(cfg.enrollmentPoolSize); advisory != "" {
		t.Logf("NOTE %s", advisory)
	}

	if cfg.enrollmentPoolDuplicates > 0 {
		t.Logf("NOTE the pool secret carried %d duplicate credential(s), so it holds %d "+
			"distinct slots rather than %d: a repeated credential takes double traffic "+
			"and spends its %d/hour early. Secrets are write-only, so check the value you "+
			"appended was not already present",
			cfg.enrollmentPoolDuplicates, cfg.enrollmentPoolSize,
			cfg.enrollmentPoolSize+cfg.enrollmentPoolDuplicates, perCredentialHourlyBudget)
	}

	ctx, cancel := context.WithTimeout(context.Background(), otpE2EDeadline)
	defer cancel()

	wrapper, err := newEphemeralStateKeyWrapper()
	if err != nil {
		t.Fatal(err)
	}
	// Leave the nested state directory absent so the SDK creates it with the
	// native owner-only ACL on every supported operating system.
	stateDir := filepath.Join(t.TempDir(), "qurl-state")
	statePath := filepath.Join(stateDir, "agent-state.sealed")
	store, err := qurl.NewSealedFileAgentState(statePath, "otp-e2e-ephemeral", wrapper)
	if err != nil {
		t.Fatalf("open sealed agent state: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close sealed agent state: %v", err)
		}
	})

	// The mailbox harness binds each delivered message to this agent id (it
	// matches the Connector ID rendered in the email body), so concurrent gate
	// runs cannot consume one another's codes.
	// Only mail delivered after this instant counts. Every run enrols the same
	// agent id, so an OTP email from an earlier run satisfies the same
	// Connector-ID filter and the reader would return a stale code -- rejected
	// as 52100 "one-time code incorrect", which reads like a broken OTP path
	// rather than a dirty mailbox. Draining first is not sufficient on its own:
	// SQS short polling samples a subset of servers, so a stale message can
	// survive a drain and be long-polled afterwards.
	mailbox := newOTPMailbox(cfg, time.Now().UTC(), otpE2EMailboxWait)

	client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
		qurl.WithAgentRuntimeEnrollmentCredential(cfg.enrollment),
		qurl.WithAgentRuntimeHub(cfg.hub),
		qurl.WithAgentRuntimeIdentity(cfg.agentID),
		// Assigned-cell REG carries these audit fields, and the authority
		// rejects the registration input without them (52109). They are also
		// what the OTP email renders as Hostname, so supplying real-looking
		// values keeps the delivered message representative.
		qurl.WithAgentRuntimeMetadata(otpE2EHostname, otpE2EVersion),
		qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAccount),
		qurl.WithAgentRuntimeOTPProvider(mailbox.provide),
	)
	if err != nil {
		t.Fatalf("ConnectAgentRuntime with an emailed OTP: %v", err)
	}
	if client == nil || binding == nil {
		t.Fatal("ConnectAgentRuntime returned a nil client or binding")
	}
	t.Cleanup(binding.Destroy)

	if calls, fresh := mailbox.snapshot(); calls != 1 || !fresh {
		t.Fatalf("OTP provider calls = %d, fresh = %t; want exactly one freshly delivered code", calls, fresh)
	}
	if binding.DeviceAPIKeyID == "" {
		t.Fatal("registration produced no device API key id")
	}
	t.Logf("EVIDENCE emailed OTP completed registration with credential slot %d of %d",
		cfg.enrollmentSlot, cfg.enrollmentPoolSize)

	// ── Idempotency ──
	//
	// After RAK the SDK durably persists ONE pending device-secret candidate
	// before sending completion, so a crash or a lost LRT reuses that
	// candidate and cannot mint a second credential. Re-registering against
	// the same store inside a live lease must therefore be a warm open that
	// returns the same binding — not a second enrollment.
	//
	// This has to stay inside the assignment lease: past expiry the correct
	// call is RefreshAgentRuntime, and asserting warm-open semantics there
	// would be asserting the wrong contract.
	if remaining := time.Until(binding.LeaseExpiresAt); remaining <= 0 {
		t.Fatalf("assignment lease already expired (%s); cannot assert warm-open idempotency", remaining)
	}

	replayClient, replayBinding, err := qurl.ConnectAgentRuntime(ctx, store,
		qurl.WithAgentRuntimeEnrollmentCredential(cfg.enrollment),
		qurl.WithAgentRuntimeHub(cfg.hub),
		qurl.WithAgentRuntimeIdentity(cfg.agentID),
		qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAccount),
		// The same provider deliberately stays installed. It errors on a
		// second FRESH challenge, so if the replay tried to enroll again
		// instead of warm-opening, this fails loudly rather than quietly
		// burning a second real OTP email.
		qurl.WithAgentRuntimeOTPProvider(mailbox.provide),
	)
	if err != nil {
		t.Fatalf("second ConnectAgentRuntime must warm-open, got: %v", err)
	}
	if replayClient == nil || replayBinding == nil {
		t.Fatal("second ConnectAgentRuntime returned a nil client or binding")
	}
	t.Cleanup(replayBinding.Destroy)

	// The credential identity is the sharp edge: a second enrollment would
	// mint a new device API key. Everything else could plausibly match while
	// a duplicate credential was created behind it.
	if replayBinding.DeviceAPIKeyID != binding.DeviceAPIKeyID {
		t.Fatal("device API key id changed across re-registration; a second credential was minted")
	}
	if replayBinding.AgentID != binding.AgentID {
		t.Fatal("agent id changed across re-registration")
	}
	if replayBinding.PublicKeyB64 != binding.PublicKeyB64 {
		t.Fatal("device public key changed across re-registration; the runtime re-keyed instead of warm-opening")
	}
	if !replayBinding.RegisteredAt.Equal(binding.RegisteredAt) {
		t.Fatalf("registered-at moved across re-registration: %s -> %s; this was a second enrollment",
			binding.RegisteredAt, replayBinding.RegisteredAt)
	}

	// No second code was requested. The provider would have errored on a
	// fresh challenge, but assert the count too so a future provider that
	// tolerates repeats cannot quietly weaken this.
	//
	// Note the coupling this creates, deliberately: the reader's
	// PendingActivationRecovery branch replays the original code and is dead in
	// this flow, because a warm open does not re-challenge. If the SDK ever
	// starts re-challenging with PendingActivationRecovery=true on warm open,
	// callCount becomes 2 and this assertion FAILS rather than passing through
	// the replay branch. That is the intended direction -- a silent change in
	// warm-open behaviour should break this test, not be absorbed by it.
	if calls, fresh := mailbox.snapshot(); calls != 1 || !fresh {
		t.Fatalf("OTP provider calls = %d after re-registration; want the original one and no second code", calls)
	}
	if path := os.Getenv(otpE2ECanaryCommitmentPathEnv); path != "" {
		if err := writeOTPE2ECanaryCommitment(path, binding,
			os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT")); err != nil {
			t.Fatalf("write OTP canary binding commitment: %v", err)
		}
	}
	t.Log("EVIDENCE re-registration warm-opened the same credential with no second OTP")
}
