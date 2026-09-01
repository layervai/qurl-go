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
	//
	// Strict now also requires a usable ROTATION, so running this against the
	// real sandbox from a workstation means exporting GITHUB_RUN_NUMBER and
	// GITHUB_RUN_ATTEMPT by hand (any values >= 1). Without strict set, a
	// local run selects at random and needs neither.
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
	//
	// Rendered by credentialEvidence, which loadOTPE2EGateConfig emits as part
	// of loading -- see the note there for why "after a successful
	// registration" is the one place this evidence is useless.
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

// credentialEvidence renders which credential of the pool this run drew.
//
// One phrasing in one place because it is emitted on three different paths --
// after load, inside the registration failure, and after success -- and three
// drifting spellings of one fact is how grepping CI logs for it stops working.
// The "credential slot" stem is therefore the one the success log already used.
//
// "(0-based)" is the one addition. selectEnrollment returns a zero-based slot,
// so the values range over 0..n-1 while "slot 4 of 6" reads as a one-based
// ordinal to almost everyone -- and a reader mapping the slot onto a line of
// the pool secret is then off by one exactly half the time they think about
// it. Documenting that only here would have left the artifact people actually
// read at 4am still ambiguous, which is the same defect this file's other two
// fixes address: technically correct, and misleading anyway.
//
// It sits directly after the slot rather than trailing both numbers, where it
// would read as if the POOL SIZE were zero-based too -- an off-by-one reached
// by a different route.
func (c otpE2EConfig) credentialEvidence() string {
	return fmt.Sprintf("credential slot %d (0-based) of %d", c.enrollmentSlot, c.enrollmentPoolSize)
}

// loadOTPE2EGateConfig loads the gate's config and reports which credential the
// run drew, in ONE call.
//
// Emitting the evidence is part of loading, not a separate statement below it,
// and that is the entire fix for the defect this file was changed for. The slot
// exists to explain a run that FAILED -- "which credential did this spend" is
// only asked when the issuance budget is the suspect -- and it used to be
// rendered once, after a successful ConnectAgentRuntime, past the Fatalf that
// any failure takes. On the single path the field was added for it printed
// nothing, and two red runs of this gate on #181 produced no slot at all.
//
// Written this way rather than as a t.Logf the caller is trusted to keep above
// its first error check: an ordering between two statements is a thing to get
// wrong, and folding them into one call leaves no order to get wrong. `go test`
// prints a failed test's buffered output, so the line lands with or without -v.
// Takes a testing.TB and an explicit lookup rather than closing over *testing.T
// and os.Getenv, so the emission itself is testable: folding load and emit
// together removes the statement ORDER that caused the defect, but not the
// possibility of deleting the t.Logf, and that one line is the whole fix.
// TestGateConfigLoadEmitsTheCredentialEvidence covers it.
func loadOTPE2EGateConfig(t testing.TB, lookup func(string) string) otpE2EConfig {
	t.Helper()
	cfg, skip, err := loadOTPE2EConfig(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if skip {
		t.Skipf("OTP e2e prerequisites absent; set %s to make this fatal", otpE2EStrictEnv)
	}
	t.Logf("EVIDENCE this run drew %s", cfg.credentialEvidence())
	// The pool's non-fatal degradations, emitted from the same call and for the
	// same reason the evidence is. These used to sit as their own statements in
	// the gate test, one error check further down, which is the arrangement the
	// evidence line was just moved OUT of: a degraded pool is most interesting
	// on a run that then fails, and a statement below the first Fatalf is
	// absent from exactly those runs. Folding them in leaves no order to get
	// wrong. TestGateConfigLoadEmitsThePoolAdvisories covers it.
	for _, advisory := range poolAdvisories(cfg) {
		noteDegradation(t, lookup, advisory.title, advisory.text)
	}
	return cfg
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

	// EVERY unmet prerequisite, in one pass. This function opens by promising
	// that, and the three fault classes below are independent: an absent
	// variable, a pool secret too small to rotate, and a runner that stopped
	// exporting a counter can all be true at once. Reporting the first and
	// returning would cost a gate cycle per fault to discover -- and worse for
	// two of them, since a damaged pool makes selectEnrollment short-circuit
	// and report nothing blocked, so the counter fault would not merely be
	// deferred but invisible until the secret was fixed.
	//
	// Everything is appended to the LIST, never to the rendered string, so the
	// count and the contents cannot disagree.
	if strict {
		unmet := append([]string(nil), missing...)

		// Only when the pool variable yielded something: a pool that yielded
		// NOTHING already contributed its own entry to `missing` above, and
		// naming it twice would overstate the number of things to fix.
		//
		// THE remedy explanation; the fences that pin this wording point here
		// rather than restating it.
		//
		// It names the POOL secret because that is the only credential source
		// any workflow wires. An earlier wording sent the operator to the
		// single-credential variable, which is a dead end twice over: no
		// workflow maps it into the environment, and even wired it would not
		// clear this error, because `fromPool` keys on the raw pool variable
		// that CI always sets -- so the backfill above feeds a pool this guard
		// still refuses on fromPoolCount. Both damage shapes (truncated to one
		// line, or whitespace) still hard-fail with it set; setting it only
		// moves the whitespace shape from the absent branch to this one,
		// changing the diagnosis and not the outcome.
		//
		// A required check that prescribes a step which cannot work is the
		// misdirection this file exists to remove, so the text states the fix
		// that IS available from CI and marks the other path as local-only.
		if fromPool && len(pool) > 0 && fromPoolCount < 2 {
			unmet = append(unmet, fmt.Sprintf(
				"%s parsed %d credential(s)%s: the pool is the only credential source CI "+
					"wires, so this is a damaged secret and the gate would run unpooled at "+
					"%d/hour. Re-save the secret behind %s with another owner's credential "+
					"appended, one per line (%s is a LOCAL-run convenience that no workflow "+
					"maps in, so setting it does not clear this)",
				otpE2EEnrollmentPoolEnv, fromPoolCount, duplicateSuffix(poolDuplicates),
				perCredentialHourlyBudget, otpE2EEnrollmentPoolEnv, otpE2EEnrollmentEnv))
		}

		// Skipped ONLY for the single-credential setup, which genuinely has
		// nothing to rotate. That setup is supported for LOCAL runs only -- no
		// workflow wires the single-credential variable, and CI always sets the
		// pool variable, so `fromPool` is true on every CI run and this branch
		// is unreachable there. Everything else asks -- including the case where
		// the pool secret is absent entirely: Actions renders a deleted secret as
		// the empty string, so keying this on fromPool meant a deleted secret AND
		// a stopped counter reported only the secret, and the counter cost
		// another gate cycle. That is the exact charge this block is written to
		// answer, so the condition has to be "is there nothing to rotate", not
		// "was a pool asked for".
		fromSingle := !fromPool && len(pool) == 1
		if !fromSingle {
			if blocked := blockedRotationCounters(lookup); len(blocked) > 0 {
				unmet = append(unmet, strings.Join(blocked, " and ")+
					" unusable, so credential selection could not rotate")
			}
		}

		if len(unmet) > 0 {
			return otpE2EConfig{}, false, fmt.Errorf(
				"strict OTP e2e run has %d unmet prerequisite(s): %s",
				len(unmet), strings.Join(unmet, "; "))
		}
	} else if len(missing) > 0 {
		return otpE2EConfig{}, true, nil
	}

	port, err := strconv.Atoi(strings.TrimSpace(lookup(otpE2EHubPortEnv)))
	if err != nil || port <= 0 || port > 65535 {
		return otpE2EConfig{}, false, fmt.Errorf("%s must be a valid UDP port", otpE2EHubPortEnv)
	}

	// Reached only once the strict block above has accepted the configuration,
	// so on CI this always rotates; off CI, or non-strict, it may fall back to
	// random, which is the documented local behaviour.
	enrollment, slot := selectEnrollment(pool, lookup)

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
// len(pool)) slots. Six -- the size this gate ran at through the outage -- was
// the worst available for that: 6 = 2*3, so a stretch where relevant and
// irrelevant PRs merely alternate (d=2) collapses the pool onto three slots and
// reproduces the original outage with a different traffic shape. At a PRIME
// size every stride below len(pool) stays coprime and the ceiling holds
// arithmetically instead of empirically.
// TestSelectEnrollmentStridedTrafficNeedsACoprimePoolSize pins both halves.
//
// THE SANDBOX POOL WAS PRIME AS OF 2026-08-31, so this residual is closed
// there: a seventh owner was seeded, the gate's own evidence line reports seven
// slots, and the composite-size advisory below has gone silent -- which is
// exactly how that fix is meant to be observed, and why the observation lives
// in the gate's log rather than in this comment. The size is a seeding decision
// rather than a code one, so this stays written as a property of len(pool)
// rather than of any particular number: a pool resized to a composite value
// reopens it, and the advisory says so at runtime.
//
// Before the reseeding the guarantee was only empirical, and it did hold:
// replaying the 135 issuances recorded under the six-slot pool at their real
// run numbers, real skips included, the worst rolling hour put 3 on a slot
// against the hash's 5. Empirical is weaker than arithmetic, which is why the
// size matters; check it first if the gate ever clusters again.
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
// Which counter BLOCKED a rotation is deliberately not returned here. Callers
// that need it ask blockedRotationCounters, because they must be able to ask
// even when the pool is too small to rotate -- the len<2 case below short
// circuits before reading a counter at all, so a value returned from here would
// be silent in exactly the situation that needs reporting.
func selectEnrollment(pool []string, lookup func(string) string) (string, int) {
	switch len(pool) {
	case 0:
		return "", -1
	case 1:
		// One credential is the whole pool, so there is nothing to rotate.
		return pool[0], 0
	}

	// BOTH counters must be usable, and an unreadable attempt is not the softer
	// failure it looks like: defaulting it to 1 would resolve every attempt of
	// run N onto N's slot, spending that one credential five times over the
	// reruns -- which is the exact case that exhausted a credential before the
	// pool existed. Treat it exactly as strictly as the run number.
	runNumber, haveRun := rotationCounter(lookup, "GITHUB_RUN_NUMBER")
	attempt, haveAttempt := rotationCounter(lookup, "GITHUB_RUN_ATTEMPT")
	if haveRun && haveAttempt {
		// Reduce both terms before adding. A real run number never approaches
		// MaxInt, but this reads an environment variable, and the sum of two
		// unreduced values there would overflow to a negative slot and panic
		// the index below rather than fail some assertion. Both counters are
		// >= 1 here, so attempt-1 cannot underflow either.
		slot := (runNumber%len(pool) + (attempt-1)%len(pool)) % len(pool)
		return pool[slot], slot
	}

	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return pool[0], 0
	}
	slot := int(binary.BigEndian.Uint32(raw) % uint32(len(pool)))
	return pool[slot], slot
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
		//
		// "Supported" is scoped to LOCAL runs, matching the strict guard's
		// remedy: no workflow wires the single-credential variable, so on CI
		// this branch is reachable only from a pool that strict already
		// refused. Calling it supported without that scope would read as an
		// offer CI cannot take.
		return fmt.Sprintf("pool size %d is not a pool: every run spends the same "+
			"credential, so the gate is worth %d/hour. From %s that is a damaged secret, "+
			"which a strict run refuses; from %s it is the supported single-credential "+
			"setup for a LOCAL run -- no workflow wires it -- and this is just the "+
			"ceiling. See selectEnrollment",
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
	smallest, worst := factor, size/factor
	// "likely" means a stride of 2 throughout this change -- relevant and
	// irrelevant PRs alternating, which is ordinary traffic. It is earned only
	// by EVEN sizes: at 9, 15 or 25 the smallest factor is 3 or 5 while stride 2
	// is coprime and collapses nothing, so claiming it there would misname the
	// traffic shape and overstate the risk. Built before the branch below, not
	// inside it, because 4 is even AND a prime square -- it took the coincident
	// branch and was the one even size that lost the framing.
	note := ""
	if size%2 == 0 {
		note = ", which is the likely one -- relevant and irrelevant PRs alternating"
	}
	if smallest == worst {
		// A prime square (or 4): the two strides coincide, and naming them
		// separately would read as a contradiction.
		return fmt.Sprintf("pool size %d is composite: a spending stride of %d%s collapses it "+
			"onto %d slot(s). A PRIME size makes the rotation's guarantee arithmetic rather "+
			"than empirical; see selectEnrollment", size, smallest, note, worst)
	}
	return fmt.Sprintf("pool size %d is composite: a spending stride of %d%s collapses it "+
		"onto %d slot(s), and a stride of %d onto %d -- the worst case. A PRIME size makes "+
		"the rotation's guarantee arithmetic rather than empirical; see selectEnrollment",
		size, smallest, note, worst, worst, smallest)
}

// poolDuplicateAdvisory reports a pool secret carrying repeated credentials, or
// "" when it carries none. Pure and separate from the test body so the wording
// is asserted rather than assumed -- see poolSizeAdvisory for the same reason.
func poolDuplicateAdvisory(duplicates, distinct int) string {
	if duplicates <= 0 {
		return ""
	}
	return fmt.Sprintf("the pool secret carried %d duplicate credential(s), so it holds %d "+
		"distinct slots rather than %d: a repeated credential takes double traffic and "+
		"spends its %d/hour early. Secrets are write-only, so check the value you appended "+
		"was not already present", duplicates, distinct, distinct+duplicates,
		perCredentialHourlyBudget)
}

// degradationAdvisory pairs an advisory with the annotation title it carries.
type degradationAdvisory struct {
	title string
	text  string
}

// poolAdvisories returns every degradation advisory a loaded config carries, in
// the order the gate reports them, or nothing when the pool is healthy.
//
// Pure and separate from the test body for the reason poolSizeAdvisory already
// gives about its wording, applied one level up: the sandbox is unreachable
// from a unit test, so while this mapping lived inline in the gate test NOTHING
// outside CI could prove a given advisory was still reported -- see
// noteDegradation for what that cost. Returning the set makes it assertable, so
// dropping an advisory now fails a test rather than going quiet in the one
// place quiet is indistinguishable from healthy.
func poolAdvisories(cfg otpE2EConfig) []degradationAdvisory {
	var out []degradationAdvisory
	// The pool's SIZE decides whether the rotation survives a strided spending
	// pattern (see selectEnrollment). That size lives in a secret, so no test
	// can assert the LIVE one -- say it out loud on the runs that load it.
	if text := poolSizeAdvisory(cfg.enrollmentPoolSize); text != "" {
		out = append(out, degradationAdvisory{"OTP credential pool size is degraded", text})
	}
	if text := poolDuplicateAdvisory(cfg.enrollmentPoolDuplicates, cfg.enrollmentPoolSize); text != "" {
		out = append(out, degradationAdvisory{"OTP credential pool has duplicates", text})
	}
	return out
}

// annotationSink receives the GitHub workflow command. It is a variable so a
// test can observe the command without reassigning the process-wide os.Stdout:
// that swap is global, would race the first time anything in this package calls
// t.Parallel, and leaves every later test writing into a closed pipe if the
// capture ever unwinds through a panic.
var annotationSink io.Writer = os.Stdout

// noteDegradation reports a pool degradation that does NOT fail closed: a
// missing counter and a one-entry pool both stop the run, but a shrunken or
// strided pool merely spends its budget faster and the run still goes green.
//
// Both advisories emit through here rather than each carrying its own copy.
// The duplicate advisory was annotated first, on the claim that it was "the
// one instance left"; poolSizeAdvisory had been sitting beside it at a bare
// t.Logf the whole time, firing for a live pool of 0, 1, 2 or any composite
// size. Sharing the emitter is what stops a third advisory arriving quieter
// than these two.
//
// Takes the LOOKUP its caller was handed, never os.Getenv. That is not
// symmetry with loadOTPE2EConfig, it is the whole reason the parameter exists:
// a test drives this with a deliberately degraded pool, and reading the process
// environment meant every such test appended a FABRICATED degradation to the
// real CI job summary -- on every PR and every push. The channel introduced to
// make a real degraded pool visible would have arrived pre-filled with a fake
// one, and a reader who has ignored that block on thirty green runs does not
// read it on the red one. Threading the lookup makes "not on CI" describable
// rather than global.
//
// THREE channels, because no one of them reaches both workflows:
//
//   - t.Logf, for a developer reading a local run.
//   - a ::warning annotation, which puts it on the check itself. Non-verbose
//     `go test` buffers the test binary's stdout and stderr and discards both
//     when the package PASSES, so this is visible only under -v: the gate runs
//     verbose and gets it, the canary does not and never did.
//   - the job summary, which is a FILE the runner hands us by path, so it is
//     the only channel `go test` cannot swallow. It is what carries the
//     canary, whose non-verbose invocation is fixed by a security fence
//     (internal/workflowcontract forbids "go test -v" there as a logging
//     surface), so the reporting had to come to the canary rather than the
//     canary loosening to admit it.
func noteDegradation(t testing.TB, lookup func(string) string, title, advisory string) {
	t.Helper()
	t.Logf("NOTE %s", advisory)
	if lookup("GITHUB_ACTIONS") != "true" {
		return
	}
	fmt.Fprintf(annotationSink, "::warning title=%s::%s\n",
		encodeCommandProperty(title), encodeCommandData(advisory))
	appendJobSummary(t, lookup, title, advisory)
}

// encodeCommandData escapes a workflow command's MESSAGE. GitHub parses these
// commands line by line, so an unescaped newline truncates the annotation at
// the break and a literal % can be read as the start of an escape -- the one
// outcome an emitter built to be loud must not have. Both advisories are
// single-line and %-free today; this is for the third one.
//
// The % rule runs first and is not re-scanned: strings.Replacer matches in a
// single left-to-right pass, so the % it inserts is not itself re-encoded.
func encodeCommandData(value string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)
}

// encodeCommandProperty escapes a property value such as title=. Properties
// additionally cannot carry the delimiters GitHub splits them on.
func encodeCommandProperty(value string) string {
	return strings.NewReplacer(
		"%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value)
}

// appendJobSummary writes one advisory to the run's job summary.
//
// O_CREATE, deliberately. The runner normally pre-creates this file, but one
// that exports only the PATH -- a self-hosted runner, or `act` -- would
// otherwise ENOENT here, and on the canary that costs the report outright.
//
// A failed write is reported and swallowed rather than fatal: this is a
// REPORTING channel, and failing a required check because a summary file was
// unwritable would manufacture exactly the kind of red-for-no-reason the pool
// exists to prevent. Be clear about what the swallow costs, though. On the
// gate the t.Logf and the annotation both survive, so a failed write is
// cosmetic; on the canary neither does (see noteDegradation), so a failed
// write there IS total silence. O_CREATE is what makes that near-unreachable
// rather than merely unlikely.
func appendJobSummary(t testing.TB, lookup func(string) string, title, advisory string) {
	t.Helper()
	path := lookup("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	// One error path, not two: an unopenable file and an unwritable one cost
	// the operator exactly the same thing, so they read the same way.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err == nil {
		// Every line carries the quote marker. A multi-line advisory would
		// otherwise break out of the blockquote after its first line and the
		// rest would render as body text, detached from the warning it belongs
		// to -- again, for the advisory that has not been written yet.
		quoted := "> " + strings.ReplaceAll(advisory, "\n", "\n> ")
		_, err = fmt.Fprintf(file, "> [!WARNING]\n> **%s**\n%s\n\n", title, quoted)
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		t.Logf("NOTE job summary unavailable (%v), so on a non-verbose run this "+
			"degradation has no surviving report: %s", err, advisory)
	}
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
	if _, ok := rotationCounter(lookup, "GITHUB_RUN_NUMBER"); !ok {
		blocked = append(blocked, "GITHUB_RUN_NUMBER")
	}
	if _, ok := rotationCounter(lookup, "GITHUB_RUN_ATTEMPT"); !ok {
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
func rotationCounter(lookup func(string) string, name string) (int, bool) {
	// Not a parameter. Every caller floors at 1 and the doc above argues it can
	// never be anything else, so exposing it would invite exactly the
	// relaxation that comment warns against.
	const lowest = 1
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
	cfg := loadOTPE2EGateConfig(t, os.Getenv)

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
		// Repeated in the fatal rather than left to the log line above: this
		// is the last line before FAIL, so it is what a reader sees at the
		// tail of the job log without scrolling back, and the slot is the
		// first thing to reach for when the cause turns out to be an
		// exhausted issuance budget rather than the change under test.
		//
		// NOT because it becomes the check's annotation -- it does not. The
		// gate runs a bare `go test`, with no reporter and no ::error::
		// around it, so a failing step gets GitHub's generic "Process
		// completed with exit code 1" and this text lives only in the log.
		t.Fatalf("ConnectAgentRuntime with an emailed OTP (%s): %v",
			cfg.credentialEvidence(), err)
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
	t.Logf("EVIDENCE emailed OTP completed registration with %s", cfg.credentialEvidence())

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
