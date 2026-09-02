package nativeudp_test

// Fences the OTP gate's FAILURE diagnostics.
//
// These run everywhere -- no sandbox, no AWS, no secrets -- which is the point.
// A diagnostic is only exercised for real by a red run against a live sandbox,
// and that is precisely the moment nobody wants to discover it says nothing.
// Both properties were absent while two real runs of the gate went red on #181
// on 2026-08-30, and neither absence failed anything: the run reported a bare
// registration error, no credential slot, and a rate-limit theory that was not
// what had happened.
//
// The diagnostic behavior here is executable. The ordering property -- that
// the evidence is emitted before anything can fail -- is structural:
// loadOTPE2EGateConfig emits it as part of loading, so there is no statement
// order to police. One narrow source-level fence at the end of this file stops
// the gate test from adding a second emission site again.

import (
	"context"
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCredentialEvidenceNamesTheSlotAndNotTheCredential pins what the evidence
// renders.
//
// The credential is secret and can never be logged, so the slot and the pool
// size are the only things identifying which of the pool's owners a run spent
// ("six" until #225 reseeded it to seven; the count belongs in the pool tests,
// not in prose here, where it can only go stale).
// Dropping either leaves a red run saying nothing useful while still looking
// like it reported evidence; rendering the credential instead would publish a
// secret to a public CI log, which is the reason the slot is carried at all.
func TestCredentialEvidenceNamesTheSlotAndNotTheCredential(t *testing.T) {
	// 4 of 11 rather than 4 of 6: neither number is a substring of the other,
	// so a renderer that swapped the two fields cannot still match.
	cfg := otpE2EConfig{
		enrollment:         "POOL-SECRET-VALUE",
		enrollmentSlot:     4,
		enrollmentPoolSize: 11,
	}

	// Byte equality, not Contains. The claim this change rests on is that the
	// WORDING is the one the success log already used and only its
	// reachability changed -- so what has to hold is that the rendering is
	// stable, which a substring check does not express: "slot 11 of 4" and
	// "4/11" both satisfy Contains and both break every existing grep.
	const want = "credential slot 4 (0-based) of 11"
	evidence := cfg.credentialEvidence()
	if evidence != want {
		t.Errorf("credentialEvidence() = %q, want %q.\nCI logs are grepped for this exact "+
			"wording; changing it silently orphans every search for a past run.", evidence, want)
	}
	// Cannot trip against a renderer that formats two ints; it is a forward
	// fence for the day someone adds the credential "for context".
	if strings.Contains(evidence, cfg.enrollment) {
		t.Errorf("credentialEvidence() = %q; it must never render the credential itself", evidence)
	}
}

// TestMailboxTimeoutNamesEveryCauseNotOnlyRateLimiting fences the other half of
// the same diagnosis failure.
//
// A timed-out mailbox used to assert one cause: "The likely cause is that no
// email was ever sent: issuance is rate limited...". That is the quantitative,
// plausible-sounding answer, so it reads as a diagnosis rather than as one
// hypothesis of several -- and in the case that actually occurred it was wrong.
// The NHP sandbox was mid-deploy, load was around two issuances in the prior
// hour, and the message pointed the investigation at the rate limiter anyway.
//
// So: every cause named, the cheapest check leading, with the concrete log
// coordinates and the signatures that separate them. WHICH cause owns which
// signature is TestMailboxTimeoutTriagesOnOutcomeNotInvocation's property; this
// test only asserts that none of the vocabulary a stuck reader greps for has
// gone missing.
//
// Renamed from ...NamesMidDeployNotOnlyRateLimiting when the rule went from two
// causes to three. The old name asserted a two-way split in its own title,
// which is the "technically correct, still misleading" class this file exists
// to remove.
func TestMailboxTimeoutNamesEveryCauseNotOnlyRateLimiting(t *testing.T) {
	message := (&otpMailbox{}).timedOut().Error()
	lower := strings.ToLower(message)

	// Deliberately NOT asserted here: the log group names, the region, the AWS
	// profile, and the two rate-limit NUMBERS. Three different reasons now, and
	// not one of them wants an assertion here. The region is settled and stays
	// unpublished: it remains a secret, so pinning it here is the one thing this
	// fence must never do. The log group names are settled the other way -- ADR
	// 0002's 2026-09-01 amendment PERMITS them without requiring them, and
	// leaving them unasserted is exactly what keeps a later redaction free. That
	// amendment expressly declines to rule on the AWS profile, so it stays
	// unsettled. The numbers are qurl-service's RegistrationOTPRateLimitWindow
	// and are owned outside this repository.
	// Either way the argument is the same -- pinning a value this repo does not
	// own means the day it legitimately changes, the correct edit to timedOut()
	// reds a REQUIRED check until someone also remembers to edit this file.
	//
	// So assert the DIMENSIONS ("per credential", "per owner") and that both
	// are rates, which is what a stuck reader needs, rather than the figures.
	//
	// The authority's own identifiers ARE pinned, which is a line worth stating
	// rather than leaving as an inconsistency: they are strings its log
	// consumers key on, so renaming one is a breaking change made deliberately,
	// whereas the limits are tuning values expected to move. Pinning the first
	// costs nothing; pinning the second would red a REQUIRED check on somebody
	// else's routine retune.
	//
	// What must not rot is the diagnosis: every cause, and the signature that
	// distinguishes it from the others.
	//
	// Collected and reported once. Echoing the whole message per missing
	// fragment buries the answer in nine copies of the question -- which is
	// the failure mode this entire file exists to stop.
	//
	// Split in two because most of these are identifiers and the rest is prose.
	var missing []string

	// CASE-SENSITIVELY, against the raw message. These are not prose: they are
	// strings the reader pastes into grep, or into a CloudWatch Logs Insights
	// `filter @message like`, both case-sensitive by default. The live cell0
	// log group emits them in exactly this casing -- checked against it while
	// diagnosing real red runs of this gate. An editorial pass normalising
	// "START RequestId" to "Start RequestId" would leave this test green while
	// handing a stuck reader a query that returns zero rows, which is this
	// file's own failure class. Same argument as the byte equality in
	// TestCredentialEvidenceNamesTheSlotAndNotTheCredential, and stronger here,
	// because these are somebody else's identifiers.
	for _, want := range []struct{ fragment, why string }{
		{"Outcome", "the field the whole rule triages on"},
		{"START RequestId", "the line that, without an Outcome beside it, is the init-crash branch"},
		{"INIT_REPORT", "the line that corroborates that branch"},
		{"Runtime.ExitError", "what that INIT_REPORT says, and the reader's confirmation"},
		{"IssueRegistrationOTP", "the operation a healthy issuance logs"},
		{"IssueAssignment", "the leg that keeps SUCCEEDING through a never-invoked run"},
		// Quoted as the log writes it. "an Outcome other than success" was the
		// old wording and covers the init-crash branch too, where there is no
		// Outcome at all to be other than anything -- so the value itself is
		// what has to be here.
		{`"Outcome":"rejected"`, "the value that means refused, as distinct from absent"},
	} {
		if !strings.Contains(message, want.fragment) {
			missing = append(missing, fmt.Sprintf("%q (%s) -- exact casing, it is a log query",
				want.fragment, want.why))
		}
	}

	// Prose, so casing is free to change.
	for _, want := range []struct{ fragment, why string }{
		{"mid-deploy", "the cause that actually produced the red runs on #181"},
		{"per credential", "the limit that actually bites"},
		{"per owner", "the other dimension, so the reader knows which one bit"},
	} {
		if !strings.Contains(lower, want.fragment) {
			missing = append(missing, fmt.Sprintf("%q (%s)", want.fragment, want.why))
		}
	}
	if len(missing) > 0 {
		t.Errorf("the mailbox timeout message omits %d thing(s) a stuck reader needs:\n  %s\n"+
			"Message: %s", len(missing), strings.Join(missing, "\n  "), message)
	}

	// CONDITIONAL, and that is the whole design. Naming cell1 is not asserted --
	// it is an estate coordinate, and while ADR 0002's 2026-09-01 amendment
	// permits it, permitted is not required: a later ADR may still want it
	// gone, and requiring it here would mean that correct redaction reds a
	// REQUIRED check. That is the property the rest of this file is careful
	// about and it applies here too.
	//
	// What IS asserted is that the name never appears WITHOUT its disclaimer.
	// Unqualified, "check ca-iro-cell0 and ca-iro-cell1" reproduces the exact
	// error this correction removes -- a reader finds cell1 empty, reads it as
	// the never-invoked branch, and investigates a deploy that never happened.
	// So: redact the name freely, but do not keep it and drop the qualifier.
	// Windowed rather than sentence-parsed: the claim is that the disclaimer
	// travels WITH the name, which is the property that matters.
	if at := strings.Index(message, "ca-iro-cell1"); at >= 0 &&
		!strings.Contains(lower[at:min(len(lower), at+260)], "never been invoked") {
		t.Errorf("the mailbox timeout message names ca-iro-cell1 without saying it has never "+
			"been invoked, so a reader who finds it empty reads that as the never-invoked "+
			"branch and chases a deploy that did not happen.\nMessage: %s", message)
	}

	// Rate-ness has to be bound to the dimension that BITES, not merely present
	// somewhere in the message: a bare "hour" fragment is satisfied by unrelated
	// prose, and would stay green on "5 per credential" -- a limit turned into a
	// total. Looking in the run-up to the dimension accepts "5/hour per
	// credential" and "an hourly cap per credential" alike, while pinning none
	// of qurl-service's figures.
	//
	// Only per-credential. #225 established that the pool carries one credential
	// per DISTINCT owner, so the per-owner limit is higher and unreachable --
	// the slot's own credential refuses first. The message therefore names that
	// dimension without quoting a rate for it, deliberately, and demanding one
	// would force it to state a number that never applies.
	if at := strings.Index(lower, "per credential"); at >= 0 &&
		!strings.Contains(lower[max(0, at-32):at], "hour") {
		t.Errorf("the mailbox timeout message gives the per-credential limit without saying "+
			"it is an hourly RATE, so a reader takes it for a total.\nMessage: %s", message)
	}

	// Order carries as much as content. Whichever cause is stated first is the
	// one that gets investigated, and the rate limit is both the most expensive
	// check and the one that was wrong, so it goes last and the deploy case
	// leads. (The per-branch version of this is asserted properly in
	// TestMailboxTimeoutTriagesOnOutcomeNotInvocation; kept here because it is
	// the specific inversion that cost a diagnosis cycle.)
	deploy, limit := strings.Index(lower, "mid-deploy"), strings.Index(lower, "per credential")
	if deploy >= 0 && limit >= 0 && deploy > limit {
		t.Errorf("the mailbox timeout message states the issuance limit before the mid-deploy "+
			"cause; the limit is the plausible-sounding answer and is read as a diagnosis.\n"+
			"Message: %s", message)
	}
}

// TestMailboxTimeoutTriagesOnOutcomeNotInvocation is the fence for the decision
// RULE, as opposed to the vocabulary.
//
// The message named two causes for most of its life and split them on whether
// the issuer had been invoked: "no invocation at all is (1); an Outcome other
// than success is (2)". Both halves of that are reachable, so nothing about it
// looked wrong -- and it had a hole a real run fell straight into. Gate run 56
// (2026-08-19, 270s, the same signature as every other member of this family)
// logged a START with no Outcome after the authority died in init. Invoked, so
// not (1). Never refused, so not (2). The rule placed it in NEITHER branch and
// the reader was left with a message that confidently offered two answers,
// neither of which was true.
//
// A two-way split is therefore not merely incomplete here, it is the defect.
// This test fences the three-way one, and it is the assertion that goes red if
// the rule is reverted: every other fence in this file stayed GREEN across the
// change from two causes to three, which is how a rule with a hole in it
// survived in the first place.
//
// It asserts the branches STRUCTURALLY -- each enumerated branch owns its
// discriminating signature -- rather than pinning the prose that explains them.
// Wording is expected to be edited; what must not move is which log state sends
// the reader where.
func TestMailboxTimeoutTriagesOnOutcomeNotInvocation(t *testing.T) {
	message := (&otpMailbox{}).timedOut().Error()

	// Where the enumerated branches stop and the shared reference material
	// starts. Prose, and deliberately the only prose this test pins: it is a
	// structural landmark rather than an explanation, and something has to
	// close the last branch.
	const tailParagraph = "Issuer logs:"

	// One row per fault that ends this wait, in the order the message must
	// present them. `signature` is the log evidence that identifies THAT branch
	// and no other -- which is the whole content of the rule, so binding each
	// signature to its own branch is the property, not merely listing them.
	//
	// Verified partition, every historical occurrence of the ~4.5-minute
	// signature: runs 118/119/120 (2026-08-27) are never-invoked, run 56
	// (2026-08-19) is the init crash, runs 9/10/14 (2026-08-11) and run 192
	// (2026-08-31) are refusals. Nothing is unclassified and nothing is double
	// counted, which is what makes three the right number.
	branches := []struct{ marker, signature, state, why string }{
		{
			"(1)", "IssueAssignment", "no log line at all",
			"never invoked; the assignment leg keeps succeeding, so the message has to " +
				"say so or the absence reads as a transport fault",
		},
		{
			"(2)", "START RequestId", "START present, Outcome absent",
			"invoked and died coming up -- the branch the old two-way rule had no room for",
		},
		{
			"(3)", `"Outcome":"rejected"`, "Outcome says rejected",
			"reached and refused; the budget, and the only branch the message used to " +
				"state with any confidence",
		},
	}

	// The markers first, and in order. A message that dropped to two branches
	// fails here before any signature is looked at, which is the revert case.
	at := make([]int, len(branches))
	for i, b := range branches {
		if at[i] = strings.Index(message, b.marker); at[i] < 0 {
			t.Fatalf("the mailbox timeout message has no %s branch (%s -> %s).\n"+
				"Every fault that ends this wait needs its own branch; one that is missing "+
				"is one a reader will try to force into a neighbouring branch that does not "+
				"fit it.\nMessage: %s", b.marker, b.state, b.why, message)
		}
		if i > 0 && at[i] < at[i-1] {
			t.Fatalf("the mailbox timeout message states %s before %s. The order is the "+
				"order the checks should be run in, cheapest first.\nMessage: %s",
				b.marker, branches[i-1].marker, message)
		}
	}
	// A fourth branch is not an error, but it is outside this fence, so say so
	// rather than silently covering two thirds of the rule.
	if strings.Contains(message, "(4)") {
		t.Errorf("the mailbox timeout message has a (4) branch this test does not fence. " +
			"Add it to the table above.")
	}

	// The branches are followed by a paragraph of shared reference material --
	// where the log groups are, which region, what a healthy issuance looks
	// like -- which belongs to no branch. It has to bound the LAST one, or that
	// branch's span runs to the end of the message and is the only one whose
	// signature could drift out of it undetected. That is the weakest place to
	// leave a gap: (3) is the budget branch, the one most often edited.
	tail := strings.Index(message, tailParagraph)
	if tail < at[len(at)-1] {
		t.Fatalf("the mailbox timeout message has no %q paragraph after its last branch. "+
			"The branch table is bounded by it; without it the last branch is unfenced.\n"+
			"Message: %s", tailParagraph, message)
	}

	// Each signature inside its OWN branch. This is the part that could not be
	// expressed while the rule keyed on invocation: "START RequestId" appeared
	// in the message the whole time, as the line whose ABSENCE meant mid-deploy.
	// Same fragment, opposite meaning, and only its position says which.
	for i, b := range branches {
		end := tail
		if i+1 < len(branches) {
			end = at[i+1]
		}
		if !strings.Contains(message[at[i]:end], b.signature) {
			t.Errorf("branch %s (%s) does not carry %q.\n%s\n"+
				"A signature outside the branch it identifies is worse than a missing one: "+
				"the reader matches it against whichever branch it is sitting in.\n"+
				"Branch text: %s", b.marker, b.state, b.signature, b.why, message[at[i]:end])
		}
	}

	// And the negative that names the old rule. "Invoked at all" is no longer a
	// discriminator -- it is true of (2) and (3) alike -- so a message that
	// still resolves the diagnosis on it has regressed however many branches it
	// prints. The two clauses below are the old rule's own words.
	lower := strings.ToLower(message)
	for _, stale := range []string{"no invocation at all", "never invoked and never"} {
		if strings.Contains(lower, stale) {
			t.Errorf("the mailbox timeout message resolves the diagnosis on %q. Invocation "+
				"does not separate the causes: run 56 was invoked and was neither a refusal "+
				"nor a healthy issuance. Triage on Outcome.\nMessage: %s", stale, message)
		}
	}
}

// TestMailboxTimeoutSurvivesTheCallersDeadline is the assertion the rest of
// this file depends on: a diagnosis nobody ever sees is worth nothing.
//
// The SDK discards this reader's error and returns a bare ctx.Err() whenever
// the CALLER's context is already done, so ~1.5kB of carefully ordered causes
// reaches the log only if the mailbox gives up first. That used to rest on
// otpE2EMailboxWait (4m) being under otpE2EDeadline (5m) -- but the two clocks
// start at different times, so the real margin was however much of that one
// minute the knock, LST and REG round-trips had not already spent. A slow
// run-up inverted it, and a slow run-up is the mid-deploy case this whole
// change was written for.
//
// So the property is not "4 is less than 5". It is that whatever the caller's
// deadline is, and however late the provider is first called, this reader
// returns ITS error while the caller's context is still alive.
func TestMailboxTimeoutSurvivesTheCallersDeadline(t *testing.T) {
	// Durations sit around otpMailboxDeadlineMargin so each case takes a
	// different route, and none sleeps for long -- this runs in a REQUIRED
	// check on every PR, so seconds here are seconds everyone pays.
	//
	// The `margin + N` cases: N is the budget, and so both the case's runtime
	// AND how much scheduler stall it takes to misroute into the early return
	// and fail on the wrong fragment. It is NOT the slack on the closing
	// liveness assertion -- that is margin minus otpMailboxTeardownCost, about
	// 1.75s, whatever N is. So N buys robustness against a stalled runner and
	// nothing else, and 2s is the point where it stops being worth more CI time
	// on every pull request in the repository.
	for _, tc := range []struct {
		name      string
		outer     time.Duration
		budget    time.Duration
		runUpCost time.Duration
		// pollsOnce makes the first aws call SUCCEED, which is the only way to
		// reach timedOut(). Without it every case lands in a never-polled arm
		// and the ~1.5kB diagnosis this change is built around is never
		// returned by receive() in any test -- so inverting its guarantee
		// would leave this table green.
		pollsOnce bool
		// wantFragment is unique to one of the three messages. "mid-deploy" is
		// NOT: spentBeforePolling names it too ("a sandbox mid-deploy is the
		// usual reason those crawl"), so a table keyed on it distinguishes
		// nothing.
		wantFragment string
	}{
		{
			"a completed poll then silence", time.Minute, 300 * time.Millisecond, 0, true,
			"most likely none was ever sent",
		},
		// The timedOut path against a deadline it would OUTLIVE unclamped:
		// waitBudget is an hour, the caller has three seconds. Without the
		// clamp this returns long after the caller is done and the SDK throws
		// the diagnosis away. It is the only case that puts the ~1.5kB message
		// itself -- rather than one of the never-polled ones -- under the
		// guarantee this test is named for.
		{
			"a completed poll, then a budget that would outlive the caller",
			otpMailboxDeadlineMargin + 2*time.Second, time.Hour, 0, true,
			"most likely none was ever sent",
		},
		{
			"the caller's deadline clamps the budget",
			otpMailboxDeadlineMargin + 2*time.Second, time.Hour, 0, false,
			"the registration deadline was spent",
		},
		{
			"a slow run-up leaves no room to poll",
			time.Second, time.Hour, 100 * time.Millisecond, false,
			"the registration deadline was spent",
		},
		{"no budget configured at all", time.Second, 0, 0, false, "the registration deadline was spent"},
		{
			"the mailbox's own budget expires first", time.Hour, 150 * time.Millisecond, 0, false,
			"budget expired before the queue",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Parallel: every case owns its context, mailbox and counters, and
			// all of them block on timers rather than burning CPU, so the added
			// contention is near zero while the wall clock collapses from the
			// sum to the longest case. The ~1.75s slack on the closing liveness
			// assertion is margin minus teardown either way, unchanged by this.
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), tc.outer)
			defer cancel()
			if tc.runUpCost > 0 {
				time.Sleep(tc.runUpCost) // the knock, LST and REG round-trips
			}

			polls := 0
			mailbox := &otpMailbox{
				waitBudget: tc.budget,
				runAWS: func(ctx context.Context, _ ...string) ([]byte, error) {
					polls++
					if tc.pollsOnce && polls == 1 {
						return []byte(`{"Messages":[]}`), nil // a real, empty read
					}
					// Then never answers, so only a deadline ends this -- and
					// it takes time to unwind, which is the cost
					// otpMailboxDeadlineMargin was sized for. A stub returning
					// the instant ctx.Done() fires would elide exactly what the
					// constant exists to cover (SIGKILL, Wait, the pipe-copy
					// goroutine, RemoveAll), leaving the margin argued but
					// never measured.
					<-ctx.Done()
					time.Sleep(otpMailboxTeardownCost)
					// runAWSCLI's real shape: no sentinel of its own.
					return nil, errors.New(`mailbox AWS operation "sqs receive-message" failed (exit 255)`)
				},
			}
			_, err := mailbox.receive(ctx, "agent")

			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("receive returned %v; want the diagnosis naming %q", err, tc.wantFragment)
			}
			// The point of the whole exercise: the SDK only propagates this
			// while the caller's context is still alive.
			if ctx.Err() != nil {
				t.Errorf("the mailbox reported only after the caller's context was already "+
					"done (%v), so the SDK would discard this diagnosis and the gate would "+
					"report a bare \"context deadline exceeded\" instead.\n"+
					"The slack here is otpMailboxDeadlineMargin minus otpMailboxTeardownCost, "+
					"about %s, so a runner stalled longer than that trips this too -- rule "+
					"that out before hunting the clamp.",
					ctx.Err(), otpMailboxDeadlineMargin-otpMailboxTeardownCost)
			}
		})
	}
}

// otpMailboxTeardownCost stands in for killing an in-flight aws CLI and
// unwinding back to the caller. Deliberately well above the real cost, so the
// margin is shown to have room rather than assumed to.
const otpMailboxTeardownCost = 250 * time.Millisecond

// TestNeverPolledMailboxDoesNotClaimNoEmailArrived is the narrow version of the
// same point, stated as its own property: a message must not read as a
// diagnosis of something it never looked at.
func TestNeverPolledMailboxDoesNotClaimNoEmailArrived(t *testing.T) {
	polled := false
	mailbox := &otpMailbox{
		waitBudget: time.Hour,
		runAWS: func(context.Context, ...string) ([]byte, error) {
			polled = true
			return nil, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded with no deadline left")
	}
	if polled {
		t.Fatal("the mailbox polled after all; this test no longer covers the never-polled path")
	}
	// Classifiable on THIS path too. It is the early return, taken before the
	// loop, and it once carried the same message as the loop path with a
	// different error identity -- so which one a caller got depended only on
	// whether the run-up crossed the margin before or after entering receive.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the early-return path does not match errors.Is(context.DeadlineExceeded) "+
			"while the loop path does: same cause, same message, two identities.\nError: %v", err)
	}
	for _, forbidden := range []string{
		"no OTP email arrived",
		"none was ever sent",
		"suspect delivery",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("the never-polled error says %q.\n"+
				"Nothing was read, so that asserts a cause this reader did not observe -- and "+
				"sends the reader to the issuer logs, where a healthy issuance will not fit "+
				"any of the offered explanations.\nError: %s", forbidden, err)
		}
	}
}

// TestMailboxThatWasKilledMidPollDoesNotClaimNoEmailArrived covers the band the
// entry-time arithmetic misses.
//
// A budget of a second or two is POSITIVE, so the loop is entered -- and the
// aws CLI's own startup (roughly 0.5-1.5s) is then killed before it ever
// reaches SQS. "Polled at least once" cannot be inferred from the budget at
// entry; it has to be observed. Otherwise the reader claims "no OTP email
// arrived, so most likely none was ever sent" about a queue it never read --
// the defect spentBeforePolling was added to remove, surviving in the band just
// above the margin that removed it.
func TestMailboxThatWasKilledMidPollDoesNotClaimNoEmailArrived(t *testing.T) {
	reached := make(chan struct{}, 1)
	mailbox := &otpMailbox{
		// Positive but tiny: the loop starts, the poll starts, and the derived
		// deadline kills it before it can answer.
		waitBudget: time.Second,
		runAWS: func(ctx context.Context, _ ...string) ([]byte, error) {
			reached <- struct{}{}
			<-ctx.Done() // killed mid-startup, having read nothing
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded despite never reading the queue")
	}
	select {
	case <-reached:
	default:
		t.Fatal("the poll never started; this test no longer covers the killed-mid-poll band")
	}
	for _, forbidden := range []string{
		"no OTP email arrived", "none was ever sent", "suspect delivery",
		// Blaming the CALLER's deadline here would print "59m59s left, under
		// the 2s held in reserve" -- a message its own figures refute.
		"the registration deadline was spent",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("a mailbox killed mid-poll says %q.\n"+
				"It never read the queue, so that asserts a cause it did not observe.\nError: %s",
				forbidden, err)
		}
	}
	// Not merely "not the wrong message" -- the right one. Asserting only
	// absence is what let the previous version pin a self-contradictory
	// diagnostic in place.
	if !strings.Contains(err.Error(), "budget expired before the queue") {
		t.Errorf("a mailbox killed mid-poll does not name its own budget as the cause.\nError: %s", err)
	}
}

// TestCancelledMailboxDoesNotDiagnoseIssuance keeps the essay for the case that
// earned it. A cancelled run asked nobody about issuance, so answering with two
// named causes and a pointer into /aws/lambda/ claims far more than the
// evidence supports.
func TestCancelledMailboxDoesNotDiagnoseIssuance(t *testing.T) {
	mailbox := &otpMailbox{
		waitBudget: time.Hour,
		runAWS: func(ctx context.Context, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancellation returned %v; it should wrap context.Canceled so callers can tell", err)
	}
	// And the negative. This path runs through errors.Join in orExpired, so it
	// is the one where a deadline sentinel could creep in alongside -- and the
	// negative half is the one that rots, which is the whole argument for
	// mailboxDeadlineError existing.
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a CANCELLED wait also matches context.DeadlineExceeded; nothing timed out, "+
			"and the two have to stay distinguishable.\nError: %v", err)
	}
	for _, forbidden := range []string{"mid-deploy", "IssueRegistrationOTP", "/aws/lambda/"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("a CANCELLED mailbox wait returned the issuance diagnosis (%q).\n"+
				"Nothing timed out and nothing was asked of the issuer.\nError: %s", forbidden, err)
		}
	}
}

// TestMailboxDeadlineErrorsAreClassifiable pins the symmetry between the two
// context outcomes.
//
// Cancellation wraps context.Canceled so a caller can tell what happened. The
// deadline paths carry ~1.5kB of prose and used to wrap nothing, so anything
// classifying provider failures with errors.Is could not tell a mailbox timeout
// from a parse error -- and only the wrapping half was pinned by a test, which
// is how an asymmetry like that survives.
//
// Error() must stay the diagnosis alone: the SDK discards a provider error only
// when the CALLER's context is done, not by inspecting the error, so wrapping
// is safe here -- but a reader at 4am should still see the prose first.
func TestMailboxDeadlineErrorsAreClassifiable(t *testing.T) {
	mailbox := &otpMailbox{
		waitBudget: 50 * time.Millisecond,
		runAWS: func(ctx context.Context, _ ...string) ([]byte, error) {
			<-ctx.Done()
			// The shape runAWSCLI actually returns: a plain error carrying no
			// sentinel. Returning ctx.Err() would hand errors.Join the
			// DeadlineExceeded sentinel by identity, and the assertion below
			// would resolve through THAT -- leaving the one test named for the
			// wrapping unable to notice its removal. In production nothing but
			// mailboxDeadlineError carries the sentinel through orExpired.
			return nil, errors.New(`mailbox AWS operation "sqs receive-message" failed (exit 255)`)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded despite an expired budget")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a mailbox deadline error does not match errors.Is(context.DeadlineExceeded), "+
			"so a caller cannot tell it from a parse failure.\nError: %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("a mailbox deadline error also matches context.Canceled; the two must stay "+
			"distinguishable.\nError: %v", err)
	}
	// The prose leads, not the wrapped sentinel.
	if strings.HasPrefix(err.Error(), context.DeadlineExceeded.Error()) {
		t.Errorf("the diagnosis is prefixed by %q; the message a person reads must come first.\n"+
			"Error: %v", context.DeadlineExceeded, err)
	}
}

// TestUnboundedMailboxRefusesRatherThanHanging covers the one configuration
// where nothing bounds the wait: no budget, and a caller context with no
// deadline. The loop would poll forever and never produce a diagnosis -- the
// fail-OPEN the clamp exists to remove.
func TestUnboundedMailboxRefusesRatherThanHanging(t *testing.T) {
	polled := false
	calls := 0
	mailbox := &otpMailbox{
		waitBudget: 0,
		runAWS: func(context.Context, ...string) ([]byte, error) {
			polled = true
			// Bounded so a FAILING run does not abandon a goroutine hot-looping
			// receive for the rest of the package: with nothing to bound it,
			// an empty page every time would spin forever.
			if calls++; calls > 3 {
				return nil, errors.New("stub exhausted")
			}
			return []byte(`{"Messages":[]}`), nil
		},
	}

	done := make(chan error, 1)
	go func() {
		_, err := mailbox.receive(context.Background(), "agent")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("receive succeeded with nothing bounding it")
		}
		if !strings.Contains(err.Error(), "neither a wait budget nor a caller deadline") {
			t.Errorf("unbounded receive returned %v; want it to name the missing bound", err)
		}
		if polled {
			t.Error("it started polling before refusing; the refusal must precede the loop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive is still polling with no budget and no caller deadline; it would hang " +
			"a real run instead of reporting anything")
	}
}

// TestFetchKilledByTheDeadlineIsNotReportedAsAnAWSFailure covers the call site
// the deadline routing originally skipped.
//
// Only `sqs receive-message` used to choose between "the deadline expired" and
// the CLI's exit code; `s3api get-object` returned the exit code raw. When the
// budget expires mid-fetch, exec.CommandContext kills the CLI and that surfaces
// as `mailbox AWS operation "s3api get-object" failed (exit 255)` -- the exact
// shape runAWSCLI's own comment says "sent me hunting through IAM once
// already". And get-object runs LATE in a long wait, so it is likeliest on
// precisely the slow runs this file exists to explain.
func TestFetchKilledByTheDeadlineIsNotReportedAsAnAWSFailure(t *testing.T) {
	const bucket = "mailbox-bucket"
	notification := `{"Records":[{"eventTime":"2099-01-01T00:00:00Z","s3":` +
		`{"bucket":{"name":"` + bucket + `"},"object":{"key":"otp/message"}}}]}`
	received := `{"Messages":[{"ReceiptHandle":"handle","Body":` + strconv.Quote(notification) + `}]}`

	fetched := make(chan struct{}, 1)
	mailbox := &otpMailbox{
		bucket:     bucket,
		waitBudget: time.Second,
		runAWS: func(ctx context.Context, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[0] == "sqs" && args[1] == "receive-message" {
				return []byte(received), nil // a real read: polled becomes true
			}
			if len(args) >= 1 && args[0] == "s3api" {
				fetched <- struct{}{}
				<-ctx.Done() // killed mid-fetch by the budget
				return nil, errors.New(`mailbox AWS operation "s3api get-object" failed (exit 255)`)
			}
			return []byte(`{}`), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded despite the fetch being killed")
	}
	select {
	case <-fetched:
	default:
		t.Fatal("the fetch never ran; this test no longer covers the get-object path")
	}
	// The cause may appear -- orExpired joins it, so a genuine IAM failure
	// racing the deadline is not deleted -- but it must not LEAD. That was the
	// original complaint: a timeout reported as a permissions problem costs a
	// diagnosis cycle in IAM.
	if strings.HasPrefix(err.Error(), "mailbox AWS operation") {
		t.Errorf("a fetch killed by the deadline LEADS with an AWS operation failure.\n"+
			"The diagnosis has to come first; the exit code belongs underneath it.\n"+
			"Error: %s", err)
	}
	// And NOT the no-email diagnosis. A delivery notification was in hand, so
	// both of timedOut's causes are wrong here.
	for _, forbidden := range []string{"most likely none was ever sent", "suspect delivery"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("a fetch killed with a delivery already in hand says %q.\n"+
				"The queue had a notification for an otp/ object, so issuance and delivery "+
				"are not in question.\nError: %s", forbidden, err)
		}
	}
	// It must NOT claim the delivery was ours, and must NOT send the reader
	// away from the issuer logs. Ownership is decided by parsing the body,
	// which is exactly what ran out of time -- and on a shared queue the object
	// routinely belongs to a concurrent run or a rerun. Run A killed fetching
	// run B's object is the mid-deploy case, where the issuer log IS the answer.
	for _, forbidden := range []string{
		"ALREADY arrived for this run",
		"NOT in question",
		"wrong place to look",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("a fetch killed before ownership was established says %q.\n"+
				"It cannot know whose object that was.\nError: %s", forbidden, err)
		}
	}
	if !strings.Contains(err.Error(), "shared mailbox") {
		t.Errorf("a fetch killed before ownership was established does not say so.\n"+
			"Error: %s", err)
	}
}

// matchedOTPCode is the code matchedCodeMailbox plants for "agent".
const matchedOTPCode = "13572468"

// TestExtractedCodeSurvivesAKilledCleanup is the sharpest form of the same
// point, and the one that was a regression rather than merely a bad message.
//
// The queue is read, the object fetched, the code extracted and matched -- and
// then the budget expires during the `sqs delete-message` that consumes it.
// Routing that through the deadline diagnosis announced "no OTP email arrived
// for this run, so most likely none was ever sent" about an email just parsed,
// while holding a valid code: contradicted by a variable in the same frame.
// Discarding a good code because CLEANUP was killed is also simply the wrong
// trade, so the code comes back.
func TestExtractedCodeSurvivesAKilledCleanup(t *testing.T) {
	deleted := make(chan struct{}, 1)
	mailbox := matchedCodeMailbox(t, func(ctx context.Context) ([]byte, error) {
		deleted <- struct{}{}
		<-ctx.Done() // the cleanup is killed by the budget
		return nil, errors.New(`mailbox AWS operation "sqs delete-message" failed (exit 255)`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	code, err := mailbox.receive(ctx, "agent")
	if err != nil {
		t.Fatalf("a killed cleanup discarded a successfully extracted code: %v", err)
	}
	// Guarded like every sibling here. Without it, an argv change that stopped
	// the stub matching would let the cleanup SUCCEED, `return code, nil` would
	// be taken for an entirely different reason, and this test would pass while
	// asserting nothing about a killed cleanup at all.
	select {
	case <-deleted:
	default:
		t.Fatal("the cleanup never ran; this test no longer covers a killed delete-message")
	}
	if code != matchedOTPCode {
		t.Errorf("receive returned %q, want the extracted code %q", code, matchedOTPCode)
	}
}

// TestGenuineCleanupFailureStillSurfaces is the fail-closed half of the same
// branch, and it had no fence.
//
// The swallow is guarded on ctx.Err() precisely so that a real failure -- an
// IAM problem on the mailbox role, a malformed receipt handle -- is still
// reported. Delete that guard and every test stayed green, because nothing
// reached this delete-message with a live context: the stale and s3:TestEvent
// deletes go through orExpired, and the foreign-delivery path goes through
// releaseMessage. A regression there would quietly turn a broken mailbox role
// into a passing gate, which is the shape this whole change exists to remove.
func TestGenuineCleanupFailureStillSurfaces(t *testing.T) {
	deleted := make(chan struct{}, 1)
	mailbox := matchedCodeMailbox(t, func(context.Context) ([]byte, error) {
		deleted <- struct{}{}
		// Fails on its own account, with the budget still running.
		return nil, errors.New(`mailbox AWS operation "sqs delete-message" failed (exit 255)`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	select {
	case <-deleted:
	default:
		t.Fatal("the cleanup never ran; this test no longer covers a live-context failure")
	}
	if err == nil {
		t.Fatal("a genuine delete-message failure was swallowed.\n" +
			"The swallow is for a killed cleanup only: an IAM or receipt-handle problem on " +
			"the mailbox role has to surface, or a broken role reads as a passing gate.")
	}
	if !strings.Contains(err.Error(), "delete-message") {
		t.Errorf("the cleanup failure was replaced by something else: %v", err)
	}
}

// matchedCodeMailbox builds a reader that walks all the way to a matched code
// for "agent", with the delete-message that consumes it under the caller's
// control. Shared so the two halves of that branch cannot drift apart.
func matchedCodeMailbox(t *testing.T, onDelete func(context.Context) ([]byte, error)) *otpMailbox {
	t.Helper()
	const bucket = "mailbox-bucket"
	notification := `{"Records":[{"eventTime":"2099-01-01T00:00:00Z","s3":` +
		`{"bucket":{"name":"` + bucket + `"},"object":{"key":"otp/message"}}}]}`
	received := `{"Messages":[{"ReceiptHandle":"handle","Body":` + strconv.Quote(notification) + `}]}`
	email := "Subject: " + otpEmailSubject + "\r\n" +
		"To: otp@example\r\n\r\n" +
		"Connector ID:  \"agent\"\n" +
		"Your qURL Connector verification code is: " + matchedOTPCode + "\n"

	return &otpMailbox{
		bucket:     bucket,
		recipient:  "otp@example",
		waitBudget: time.Second,
		runAWS: func(ctx context.Context, args ...string) ([]byte, error) {
			switch {
			case len(args) >= 2 && args[0] == "sqs" && args[1] == "receive-message":
				return []byte(received), nil
			case len(args) >= 1 && args[0] == "s3api":
				return nil, os.WriteFile(args[len(args)-3], []byte(email), 0o600)
			case len(args) >= 2 && args[1] == "delete-message":
				return onDelete(ctx)
			}
			return []byte(`{}`), nil
		},
	}
}

// TestForeignDeliveryDoesNotPoisonALaterTimeout covers a delivery that turned
// out to belong to somebody else.
//
// The queue, bucket and recipient come from shared secrets and the workflow's
// concurrency group only serialises the same ref, so a concurrent run's email
// -- or a rerun's, since runScopedAgentID scopes on run id AND attempt -- is
// routinely seen and released. Raising progress before extractOTPCode is right,
// because until the body is parsed the delivery might be ours. Leaving it
// raised afterwards is not: a later timeout then claimed a delivery had
// "ALREADY arrived for this run" and told the reader the issuer logs were the
// wrong place to look, which is precisely where the answer was.
func TestForeignDeliveryDoesNotPoisonALaterTimeout(t *testing.T) {
	const bucket = "mailbox-bucket"
	notification := `{"Records":[{"eventTime":"2099-01-01T00:00:00Z","s3":` +
		`{"bucket":{"name":"` + bucket + `"},"object":{"key":"otp/message"}}}]}`
	received := `{"Messages":[{"ReceiptHandle":"handle","Body":` + strconv.Quote(notification) + `}]}`
	// Well-formed and addressed to the shared recipient, but another run's agent.
	foreign := "Subject: " + otpEmailSubject + "\r\n" +
		"To: otp@example\r\n\r\n" +
		"Connector ID:  \"someone-elses-agent\"\n" +
		"Your qURL Connector verification code is: 99887766\n"

	reads := 0
	mailbox := &otpMailbox{
		bucket:     bucket,
		recipient:  "otp@example",
		waitBudget: time.Second,
		runAWS: func(ctx context.Context, args ...string) ([]byte, error) {
			switch {
			case len(args) >= 2 && args[0] == "sqs" && args[1] == "receive-message":
				reads++
				if reads == 1 {
					return []byte(received), nil // the foreign delivery
				}
				<-ctx.Done() // and then nothing for us, ever
				return nil, ctx.Err()
			case len(args) >= 1 && args[0] == "s3api":
				return nil, os.WriteFile(args[len(args)-3], []byte(foreign), 0o600)
			}
			return []byte(`{}`), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded on somebody else's delivery")
	}
	if reads < 2 {
		t.Fatalf("the reader stopped after %d poll(s); this test no longer covers a release "+
			"followed by a later timeout", reads)
	}
	if strings.Contains(err.Error(), "ALREADY arrived for this run") {
		t.Errorf("a released FOREIGN delivery still answers for this run's timeout.\n"+
			"It was somebody else's, so nothing arrived for us -- and this wording sends the "+
			"reader away from the issuer logs that hold the answer.\nError: %s", err)
	}
	if !strings.Contains(err.Error(), "most likely none was ever sent") {
		t.Errorf("a run that polled repeatedly and saw nothing of its own should get the "+
			"timeout diagnosis.\nError: %s", err)
	}
}

// recordingTB captures what a helper reports, so an emission can be asserted
// rather than assumed. Only Helper and Logf are exercised; the embedded TB
// leaves everything else nil, which is deliberate -- a helper that started
// failing or skipping on a complete config should be loud about it.
type recordingTB struct {
	testing.TB
	logs    []string
	fatal   string
	skipped string
}

func (r *recordingTB) Helper() {}

// Recorded rather than fatal. Embedding a nil TB would turn any future required
// variable in loadOTPE2EConfig into a nil-pointer panic here, aborting the
// whole package run and hiding every other result -- loud in the worst way.
func (r *recordingTB) Fatal(args ...any) { r.fatal = fmt.Sprint(args...) }

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}

func (r *recordingTB) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
}

func (r *recordingTB) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// TestGateConfigLoadEmitsTheCredentialEvidence closes the one hole left under
// this change's headline fix.
//
// Folding the emission into loadOTPE2EGateConfig removes the statement ORDER
// that made the evidence unreachable -- there is no longer a t.Logf anyone can
// slide below the first error check. It does not stop anyone deleting that line
// outright, and deleting it restores the original defect exactly: a red gate
// with no slot, and every other test here still green.
func TestGateConfigLoadEmitsTheCredentialEvidence(t *testing.T) {
	recorder := &recordingTB{}
	cfg := loadOTPE2EGateConfig(recorder, envFrom(map[string]string{
		otpE2EHubHostEnv:          "hub.example",
		otpE2EHubPortEnv:          "443",
		otpE2EHubKeyEnv:           "key",
		otpE2EAgentIDEnv:          "agent",
		otpE2EMailboxQueueURLEnv:  "https://queue.example/q",
		otpE2EMailboxBucketEnv:    "bucket",
		otpE2EMailboxRecipientEnv: "otp@example",
		otpE2EMailboxRegionEnv:    "region-placeholder",
		otpE2EEnrollmentPoolEnv:   "one\ntwo\nthree",
	}))

	if recorder.fatal != "" || recorder.skipped != "" {
		t.Fatalf("loading a complete config failed or skipped: fatal=%q skip=%q",
			recorder.fatal, recorder.skipped)
	}
	// Filtered to EVIDENCE lines rather than counting every log. Requiring
	// exactly one line full stop would red a REQUIRED check the moment someone
	// added a second diagnostic here -- logging the resolved agent id, say --
	// while the evidence was still being emitted perfectly well.
	var evidence []string
	for _, line := range recorder.logs {
		if strings.Contains(line, "EVIDENCE") {
			evidence = append(evidence, line)
		}
	}
	if len(evidence) != 1 {
		t.Fatalf("loading the gate config emitted %d EVIDENCE line(s), want exactly one naming "+
			"the credential slot.\nThat line is this change's entire fix: without it a red gate "+
			"says nothing about which credential it spent.\nLogs: %q", len(evidence), recorder.logs)
	}
	if !strings.Contains(evidence[0], cfg.credentialEvidence()) {
		t.Errorf("the load emitted %q; want it to carry %q", evidence[0], cfg.credentialEvidence())
	}
}

// TestCancelledCallerInsideTheMarginIsNotCalledADeadline covers receive's early
// return, the one exit that does not pass through expired().
//
// When the caller's deadline sits inside otpMailboxDeadlineMargin the reader
// stands down before polling. If the caller was CANCELLED rather than late,
// reporting "the registration deadline was spent" claims a cause that did not
// happen -- and makes errors.Is report DeadlineExceeded for a context that is
// Canceled, the exact inversion TestMailboxDeadlineErrorsAreClassifiable says
// must not occur. Not reachable from the gate today, whose context is a plain
// WithTimeout; reachable the moment the SDK hands the provider a context it can
// cancel, which it already derives (providerCtx).
func TestCancelledCallerInsideTheMarginIsNotCalledADeadline(t *testing.T) {
	polled := false
	mailbox := &otpMailbox{
		waitBudget: time.Hour,
		runAWS: func(context.Context, ...string) ([]byte, error) {
			polled = true
			return []byte(`{"Messages":[]}`), nil
		},
	}
	// Inside the margin, so the early return is taken -- and cancelled, so the
	// deadline is not why.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()

	_, err := mailbox.receive(ctx, "agent")
	if err == nil {
		t.Fatal("receive succeeded on a cancelled caller")
	}
	if polled {
		t.Fatal("the reader polled; this test no longer covers the early return")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled caller inside the margin does not match context.Canceled.\n"+
			"Error: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a CANCELLED caller inside the margin is reported as a deadline.\n"+
			"Nothing ran out of time, and the two must stay distinguishable.\nError: %v", err)
	}
	if strings.Contains(err.Error(), "the registration deadline was spent") {
		t.Errorf("a cancelled caller is told its registration deadline was spent -- a cause "+
			"that did not happen.\nError: %v", err)
	}
}

// TestUnboundedCallerWithABudgetNamesTheMissingDeadline covers the second
// rendering of budgetSpentBeforePolling.
//
// It needs a budget AND a caller with no deadline at all, which no other test
// produces: TestUnboundedMailboxRefusesRatherThanHanging sets waitBudget to
// zero and so lands on the refusal instead. Every sibling message here is
// fenced; this string was the one that was not.
func TestUnboundedCallerWithABudgetNamesTheMissingDeadline(t *testing.T) {
	mailbox := &otpMailbox{
		waitBudget: 100 * time.Millisecond,
		runAWS: func(ctx context.Context, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	// No deadline: the budget is the only thing bounding this.
	_, err := mailbox.receive(context.Background(), "agent")
	if err == nil {
		t.Fatal("receive succeeded despite an expired budget")
	}
	if !strings.Contains(err.Error(), "the caller set no deadline at all") {
		t.Errorf("an unbounded caller is not told its deadline is missing; the message "+
			"reasons about time the caller never gave.\nError: %s", err)
	}
	if strings.Contains(err.Error(), "still left on the caller's") {
		t.Errorf("an unbounded caller is told how much of its deadline remains.\nError: %s", err)
	}
}

// otpRegistrationTestPath is the gate test's own source, read as text. A test
// binary runs with its package directory as the working directory.
const otpRegistrationTestPath = "otp_registration_idempotency_test.go"

// TestCredentialEvidenceHasExactlyOneEmissionSite is the fence for how this
// file's own fix got undone.
//
// #221 moved the emission into loadOTPE2EGateConfig so the slot could not be
// logged after the first thing that can fail. #225 independently added an early
// t.Logf to the gate test body, solving the same problem in the other place.
// Neither touched the other's lines, so git auto-merged BOTH without reporting
// a conflict, and the gate then printed the fact twice, seven lines apart, in
// two spellings:
//
//	EVIDENCE this run drew credential slot 2 (0-based) of 7
//	EVIDENCE this run drew credential slot 2 of 7
//
// The second is the pre-fix wording, so the merge reinstated exactly the
// ambiguity "(0-based)" was added to remove -- and left a reader at the tail of
// a red log with two renderings and no way to know which is authoritative.
//
// TestGateConfigLoadEmitsTheCredentialEvidence could not catch it: it drives
// loadOTPE2EGateConfig through a recordingTB and counts what the LOADER emits,
// so it never observes the test body. Neither vet nor the linters see a
// duplicate log line. This file-local fence counts matching text in Go string
// literals in the gate source; it does not count prose in comments.
func TestCredentialEvidenceHasExactlyOneEmissionSite(t *testing.T) {
	raw, err := os.ReadFile(otpRegistrationTestPath)
	if err != nil {
		t.Fatalf("read %s: %v", otpRegistrationTestPath, err)
	}

	file := token.NewFileSet().AddFile(otpRegistrationTestPath, -1, len(raw))
	var lexer scanner.Scanner
	lexer.Init(file, raw, nil, 0)
	var sourceStrings strings.Builder
	for {
		_, kind, literal := lexer.Scan()
		if kind == token.EOF {
			break
		}
		if kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal)
		if err != nil {
			t.Fatalf("unquote string literal in %s: %v", otpRegistrationTestPath, err)
		}
		sourceStrings.WriteString(value)
		sourceStrings.WriteByte('\n')
	}
	executableText := sourceStrings.String()

	if n := strings.Count(executableText, "EVIDENCE this run drew"); n != 1 {
		t.Errorf("%s contains %d credential-evidence emission prefixes, want exactly 1.\n"+
			"Two emissions means two renderings of one fact in the same job log, which is "+
			"the ambiguity this evidence exists to remove. loadOTPE2EGateConfig is the one "+
			"site; remove duplicated emissions or update this file-local fence if that site "+
			"deliberately moves.", otpRegistrationTestPath, n)
	}
	// And one rendering template. The duplicate used t.Logf while the canonical
	// renderer uses fmt.Sprintf, so count the template text independently of the
	// function that owns its string literal.
	if n := strings.Count(executableText, "credential slot %d"); n != 1 {
		t.Errorf("%s contains %d credential-slot format templates, want exactly 1 "+
			"(credentialEvidence). Remove hand-rolled renderings or update this file-local "+
			"fence if the canonical renderer deliberately moves.", otpRegistrationTestPath, n)
	}
}
