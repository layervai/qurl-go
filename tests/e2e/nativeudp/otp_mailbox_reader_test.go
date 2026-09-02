package nativeudp_test

// Self-contained reader for the CI OTP mailbox.
//
// This deliberately depends on nothing from the attended native-UDP proof,
// which #168 retired: that suite's harness carried evidence collection,
// provenance, and a controller contract this gate has no use for, and taking a
// dependency on it is what made the previous version of this test break the
// moment the proof was deleted.
//
// It shells out to the `aws` CLI rather than importing aws-sdk-go-v2. The root
// module has exactly two direct requires and `awsstore` is a separate module
// precisely to keep AWS out of the public SDK's dependency graph; a test-only
// import would still land in it.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

// otpEmailSubject is the exact subject qurl-service stamps on the agent OTP
// email (internal/email: agentOTPSubject). A message with any other subject is
// not ours and is skipped rather than parsed.
const otpEmailSubject = "qURL Connector verification code"

// otpCodePattern matches the code line in the text/plain part. Anchoring on the
// surrounding copy rather than "any 8 digits" keeps an unrelated number
// elsewhere in the body from being mistaken for the code.
var otpCodePattern = regexp.MustCompile(`Your qURL Connector verification code is:\s*([0-9]{8})\b`)

// otpMailboxDeadlineMargin is how far ahead of the caller's deadline this
// reader gives up, so its error is the one that survives rather than being
// overwritten by a bare context deadline.
//
// Small on purpose. It only has to cover killing an in-flight `aws` call and
// unwinding back to the caller, which is sub-second -- and the slack is NOT
// free: it is time subtracted from POLLING. A 30s reserve would refuse to look
// at a queue that may already hold the code whenever a run arrived with less
// than that left, throwing away two long-polls to protect a sub-second unwind.
const otpMailboxDeadlineMargin = 2 * time.Second

// maxMailBytes bounds a decoded MIME part. A hostile or malformed message must
// not be able to exhaust the runner.
const maxMailBytes = 256 * 1024

type otpMailbox struct {
	queueURL  string
	bucket    string
	recipient string
	region    string
	// notBefore discards notifications for mail that arrived before this run
	// began. S3 stamps each record with an eventTime, so staleness is decided
	// on the delivery itself rather than on queue hygiene.
	notBefore time.Time
	// waitBudget is deliberately SHORTER than the caller's registration
	// deadline. The SDK discards this reader's error and returns the bare
	// ctx.Err() whenever the outer context is already done, so a mailbox
	// timeout that races the outer deadline surfaces as an opaque
	// "context deadline exceeded". Finishing first keeps the diagnosis.
	//
	// A constant alone does not buy that, which is why receive clamps it: the
	// budget starts when the SDK first calls the provider, not when the caller
	// created its context, so "4m < 5m" only holds if reaching the OTP
	// challenge takes under a minute. See receive.
	waitBudget time.Duration
	runAWS     func(context.Context, ...string) ([]byte, error)

	mu        sync.Mutex
	code      string
	fresh     bool
	callCount int
}

func newOTPMailbox(cfg otpE2EConfig, notBefore time.Time, waitBudget time.Duration) *otpMailbox {
	return &otpMailbox{
		queueURL:   cfg.mailboxQueueURL,
		bucket:     cfg.mailboxBucket,
		recipient:  cfg.mailboxRecipient,
		region:     cfg.mailboxRegion,
		notBefore:  notBefore,
		waitBudget: waitBudget,
		runAWS:     runAWSCLI,
	}
}

func runAWSCLI(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "aws", args...).Output()
	if err != nil {
		// Names the operation but not the AWS stderr, which can carry request
		// context and identifiers this public repository's CI logs should not
		// hold. Suppressing everything made a permissions failure read as a
		// generic outage and cost a diagnosis cycle; the verb is the part that
		// actually localises the fault.
		operation := "aws"
		if len(args) >= 2 {
			operation = args[0] + " " + args[1]
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("mailbox AWS operation %q failed (exit %d)", operation, exitErr.ExitCode())
		}
		return nil, fmt.Errorf("mailbox AWS operation %q failed", operation)
	}
	return out, nil
}

type sqsReceiveOutput struct {
	Messages []struct {
		ReceiptHandle string `json:"ReceiptHandle"`
		Body          string `json:"Body"`
	} `json:"Messages"`
}

type s3Notification struct {
	Event   string `json:"Event"`
	Records []struct {
		EventTime string `json:"eventTime"`
		S3        struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
}

// provide is the qurl.WithAgentRuntimeOTPProvider callback.
//
// A PendingActivationRecovery challenge replays the ORIGINAL code: that path
// exists precisely because the same enrollment is being resumed, and minting a
// second code would defeat it. A second FRESH challenge is an error, which is
// what makes the idempotency assertion in the test meaningful -- if a replay
// tried to enroll again it fails loudly here instead of quietly consuming
// another real email.
func (m *otpMailbox) provide(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	if challenge.AgentID == "" || challenge.CellID == "" {
		return "", errors.New("OTP challenge is missing its agent or cell identity")
	}

	m.mu.Lock()
	m.callCount++
	if challenge.PendingActivationRecovery {
		code := m.code
		m.mu.Unlock()
		if code == "" {
			return "", errors.New("activation recovery requested before any code was delivered")
		}
		return code, nil
	}
	if m.fresh {
		m.mu.Unlock()
		return "", errors.New("a second fresh OTP challenge was issued; registration was not idempotent")
	}
	m.mu.Unlock()

	code, err := m.receive(ctx, challenge.AgentID)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.code, m.fresh = code, true
	m.mu.Unlock()
	return code, nil
}

func (m *otpMailbox) snapshot() (calls int, fresh bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount, m.fresh
}

// timedOut explains a mailbox wait that produced nothing.
//
// This reader cannot tell "no email was ever sent" from "the email was slow",
// so it names the ways the authority produces no email at all. There are
// THREE, and the mailbox wait cannot distinguish them: every one of them ends
// this test at otpE2EMailboxWait, so a ~4.5-minute red run is a SYMPTOM and
// this message's only job is to hand the reader the query that splits it.
//
// TRIAGE ON Outcome, NOT ON INVOCATION. The message named two causes for most
// of its life and split them on whether the issuer had been invoked at all --
// "no invocation is (1), an Outcome other than success is (2)". That rule has
// a hole, and a real run fell in it: gate run 56 (2026-08-19, 270s, the same
// signature) logged
//
//	ERROR connector authority initialization failed failure_code=initialization_type_invalid
//	INIT_REPORT Init Duration: ... Phase: init  Status: error  Error Type: Runtime.ExitError
//	START RequestId: ...
//	REPORT ... Status: error  Error Type: Runtime.ExitError
//
// -- invoked, so "cause 1 is out", and never refused, so not cause 2 either.
// It belonged to neither branch. Outcome is the field that separates all
// three, because it is written at the one moment the authority has actually
// decided:
//
//	no log line at all      -> never invoked          (1)
//	START, but no Outcome   -> invoked, died on init  (2)
//	Outcome: rejected       -> reached, and refused   (3)
//
// Every historical occurrence of the signature partitions cleanly: runs 9, 10
// and 14 (2026-08-11) and run 192 (2026-08-31) are (3); run 56 is (2); runs
// 118, 119 and 120 (2026-08-27) are (1). Nothing is left over, which is what
// makes THREE the right number rather than merely a larger one.
//
// (1) has had more than one root cause, so the message stays at the altitude
// that covers them: a layervai/nhp "Build and Deploy NHP" run (33353630466)
// redeploying the issuer at 03:46Z turned this gate red on #181 while Relay
// and the cells were still rolling, whereas 118-120 were a cutover that
// authorised the new lambda slot at the cell endpoint before the server fleet
// had moved to it. Both present identically here: no invocation, no email, and
// no error anywhere this test can see.
//
// (3) IS THE PLAUSIBLE-SOUNDING ONE, hence its position last. It is the
// quantitative answer, so it reads as a diagnosis rather than as one
// hypothesis of three, and it cost a diagnosis cycle on #181 where the sandbox
// was mid-deploy and load was nowhere near any limit. It interpolates
// perCredentialHourlyBudget rather than restating it: this is the first thing
// an operator reads on this failure, so a stale number misdirects at the worst
// possible moment.
//
// (1) CARRIES A TRAP WORTH THE THREE LINES IT COSTS. It is diagnosed by the
// ABSENCE of evidence, which is exactly when a reader reaches for a
// corroborating signal -- and the nearest one lies. This gate's assignment leg
// keeps succeeding all the way through a (1), because ca-ia is not cell-scoped
// and sits outside the cell endpoint policy that a Blue-Green cutover rewrites.
// Two investigations read that asymmetry as a transport fault and re-derived
// the wrong answer; the message pre-empts it rather than leaving it to be
// rediscovered.
//
// On what this message does and does not spell out.
//
// The region is named INDIRECTLY, and that is mechanical rather than editorial.
// It is the value of the OTP_E2E_MAILBOX_REGION secret, and Actions redacts a
// secret's value from log output wherever it appears -- a test's own error
// string included. A committed literal would therefore render as *** in the OTP
// gate's job log, which is the single venue this message exists for. Confirmed
// against a real run: that log contains no occurrence of the region, only ***.
//
// This has been re-opened on review more than once, so the ruling is recorded
// here rather than left to be re-derived: the fix is NOT to stop paying for the
// masking by demoting OTP_E2E_MAILBOX_REGION to a plain value or an Actions
// variable. This repository is public and so are its workflow run logs, and the
// masking is not bought for this message -- it is bought for the AWS CLI and
// SDK errors printed by steps that have no idea the value is an estate
// coordinate. Actions does not mask variables. That is the same trade #166 made
// when it moved every estate identifier out of the tree and into secrets, and
// ADR 0002 is what settles which side of it a region sits on: this repository
// does not publish the sandbox estate's concrete coordinates. So the indirection
// stays, and the region's one committed literal (ADR 0001's, which ADR 0002 had
// already declared historical) is gone rather than joined by a second.
//
// The cost is worth naming honestly: demoting the secret WOULD read better here
// and would unmask `aws-region:` in the AWS step. It is declined because it also
// requires unpicking the value from the schema-v2 canary, whose contract test
// asserts the harness secret set with slices.Equal -- so the cheaper-looking
// edit ends at loosening a green REQUIRED check to publish a coordinate.
//
// The deployment prefix is omitted, so the message says how to LIST the groups
// instead. The cells are now named INDIVIDUALLY rather than by glob, which is
// a deliberate reversal: the glob was chosen so a count could not go stale, but
// it made the message unable to state the one fact a reader most needs about
// them, that cell1 has never been invoked. A glob cannot say which member of
// itself is always empty.
//
// The cell family, the assignment authority and the workstation profile ARE
// named, all by suffix. ADR 0002 was open on whether it wanted the first two
// here; its 2026-09-01 amendment rules that it does, because a suffix names no
// account, deployment prefix or endpoint and so reaches nothing on its own.
// The workstation profile is NOT covered by that ruling: it was committed
// before #235 and is not what #235 put to the ADR, so the amendment records it
// as untouched rather than settled. Do not read this paragraph as blessing it.
//
// The fence in otp_failure_diagnostics_test.go still asserts none of those
// coordinates -- only the three-way rule and the signature owned by each branch
// -- so redacting any of them later reds no REQUIRED check. Probed rather than
// assumed, and over the whole package rather than a -run subset, which is what
// the REQUIRED check actually executes: the three suffixes were removed from
// the message together, then the workstation profile on its own, and
// tests/e2e/nativeudp stayed green both times.
//
// It is no longer the ONE-file edit this comment used to promise. A complete
// redaction spans THREE files: this one, the ADR amendment that quotes the
// names, and otp_failure_diagnostics_test.go. Within them, GREP -- do not
// work from a list. Successive review passes each found one more occurrence a
// hand-written inventory had missed, including ones in the very paragraphs
// doing the enumerating: this comment names ca-ia and ca-iro-cell1 in its own
// prose, not just in the format string below. An inventory of sites is always
// one occurrence behind, and reads as verified when it was merely reasoned,
// which is the failure this paragraph warns about turned on itself. The file
// count is worth stating because it is stable and checkable; the sites are
// not, so the instruction is `grep -rn "ca-iro\|ca-ia" .` rather than a list.
// The fence stays green under redaction either way, which is precisely why
// this matters -- nothing reds to catch a half-finished job.
//
// The AuthorityOperation values are the exception, and are pinned outright:
// they are the authority's log schema rather than a coordinate, so removing
// one DOES red a REQUIRED check. Worth naming here rather than leaving inside
// "the signature owned by each branch", since that phrasing is what let an
// earlier revision believe the whole message was free to redact.
//
// That claim is load-bearing, so it is worth saying how it survives contact
// with the cell1 correction, which is the one piece of prose here that NEEDS a
// coordinate to say anything at all. The fence does not require the name. It
// requires that the name never appear WITHOUT its disclaimer: drop
// "ca-iro-cell1" and the check silently stops applying, keep it and drop
// "has never been invoked" and the check reds. So a redactor may delete this
// sentence wholesale and stay green; what they may not do is leave the reader
// a cell to check and no warning that finding it empty means nothing. An
// earlier revision of this change asserted the name outright, which made the
// correct redaction red a REQUIRED check while this comment claimed the
// opposite -- caught by probing the redaction rather than by reading it.
func (m *otpMailbox) timedOut() error {
	return fmt.Errorf(
		"no OTP email arrived for this run, so most likely none was ever sent. THREE "+
			"distinct faults end this wait identically, so the elapsed time tells you "+
			"nothing about which one it was; the issuer's own logs separate all three. Go "+
			"there before suspecting SES or this reader, and triage on the \"Outcome\" "+
			"field, NOT on whether the authority was invoked:\n"+
			"  (1) NO LOG LINE AT ALL, on any cell: never invoked, and the fault is "+
			"upstream of the authority. A layervai/nhp \"Build and Deploy NHP\" run rolling "+
			"Relay and the cells Blue-Green is the usual reason -- mid-deploy, a "+
			"registration reaches no issuer at all -- so check that repository's recent "+
			"deploy runs against this run's start time. BEWARE THE ASYMMETRY: this gate's "+
			"assignment leg keeps succeeding right through a (1), logging "+
			"{\"AuthorityOperation\":\"IssueAssignment\",...,\"Outcome\":\"success\"} a "+
			"fraction of a second after the test starts, because ca-ia is not cell-scoped "+
			"and sits outside the cell endpoint policy a cutover rewrites. A healthy "+
			"assignment says NOTHING about issuance; reading it as one is how this has "+
			"twice been misdiagnosed as a transport fault.\n"+
			"  (2) \"START RequestId\" PRESENT, NO \"Outcome\": invoked, and died coming "+
			"up. Beside it sits an INIT_REPORT with \"Status: error\" and \"Error Type: "+
			"Runtime.ExitError\", and above that an ERROR line carrying the failure_code "+
			"that names the fault. Not a rate limit: the authority never got as far as "+
			"deciding. Not this repository's bug either.\n"+
			"  (3) \"Outcome\":\"rejected\": reached, and refused. THE ISSUANCE BUDGET WAS "+
			"SPENT: %d/hour per credential, and because the pool carries one credential "+
			"per owner it is that limit which runs out first -- the per owner limit is "+
			"higher and unreachable. Selection rotates across the pool, so exhausting it "+
			"takes roughly that many times the pool size in an hour; but issuances count "+
			"against the SLOT this run drew, which the run logs, not against the pool as a "+
			"whole.\n"+
			"Issuer logs: the ca-iro-cell0 and ca-iro-cell1 lambda log groups under "+
			"/aws/lambda/. Sandbox issuance is cell0-ONLY today: ca-iro-cell1 has never "+
			"been invoked, not once, so an empty cell1 is its normal state and is evidence "+
			"of nothing -- do not read it as a (1). Check any further cells the estate has "+
			"since grown, and list the groups rather than guessing, since the deployment "+
			"prefix is internal configuration and is deliberately not committed here. Count "+
			"invocations from the LOGS: get-metric-statistics on the bare FunctionName "+
			"dimension under-reports these functions, which are invoked through Blue/Green "+
			"aliases. Use the region this gate's own credentials are already configured for "+
			"(the OTP_E2E_MAILBOX_REGION secret; spelling it out here would print as ***, "+
			"because Actions masks it in this very log), or AWS profile \"layerv\" on a "+
			"maintainer workstation. A healthy issuance ends with "+
			"{\"AuthorityOperation\":\"IssueRegistrationOTP\",...,\"Outcome\":\"success\"} "+
			"-- suspect delivery only once you have seen that line for THIS run",
		perCredentialHourlyBudget)
}

// spentBeforePolling explains a run whose deadline was gone before the mailbox
// read anything at all.
//
// Distinct from timedOut, and that distinction is the point: nothing was
// polled, so "no OTP email arrived, so most likely none was ever sent" would be
// a claim this reader never checked. It would send someone to the issuer logs
// to choose between mid-deploy and a spent budget, where they may well find a
// healthy issuance -- and then to the closing advice, "suspect delivery only
// once the issuer shows a successful issuance", which is also wrong here. The
// message may be sitting in the queue, unread.
//
// Asserting a cause you did not observe is the exact defect this file exists to
// remove. It does not get an exception for being our own message.
func (m *otpMailbox) spentBeforePolling(remaining time.Duration) error {
	// "-1.2s left" is the small version of what this whole change is about.
	left := remaining.Round(time.Millisecond).String() + " left"
	if remaining <= 0 {
		left = "already expired by " + (-remaining).Round(time.Millisecond).String()
	}
	return fmt.Errorf(
		"the registration deadline was spent before this mailbox was read even once: %s, "+
			"under the %s held in reserve so a mailbox error outlives the caller's. "+
			"Nothing was polled, so this says NOTHING about whether an OTP was issued or "+
			"delivered -- the message may be in the queue, unread. What was too slow is the "+
			"RUN-UP: the knock, LST and REG round-trips that precede the OTP challenge. A "+
			"sandbox mid-deploy is the usual reason those crawl, and raising the deadline "+
			"only helps if they finish at all",
		left, otpMailboxDeadlineMargin)
}

// mailboxDeadlineError carries a diagnosis while still matching
// errors.Is(err, context.DeadlineExceeded).
//
// The cancel path wraps context.Canceled, so leaving the deadline paths
// unwrappable would make a timeout indistinguishable from a parse failure to
// anything classifying by errors.Is. Error() stays the diagnosis alone, so the
// prose a person reads leads.
//
// Safe because the SDK's discard is keyed on the caller's ctx.Err(), never on
// this error's identity: native_agent_runtime.go reads `if ctx.Err() != nil`
// then `if providerCtx.Err() != nil`, and classifies a provider error with
// errors.Is nowhere. If that ever changes, wrapping this sentinel would cause
// the very discard the clamp prevents -- check there before editing this.
type mailboxDeadlineError struct{ diagnosis error }

func (e mailboxDeadlineError) Error() string { return e.diagnosis.Error() }

func (e mailboxDeadlineError) Unwrap() []error {
	return []error{e.diagnosis, context.DeadlineExceeded}
}

// mailboxProgress records how far the read got. What this reader may honestly
// claim depends entirely on that: a bool marking only "the queue was read"
// makes every later failure say "no OTP email arrived", including one that
// happens while fetching a delivery the queue has already announced.
type mailboxProgress int

const (
	mailboxUnread        mailboxProgress = iota // nothing was read
	mailboxPolled                               // the queue was read; no delivery for this run yet
	mailboxDeliveryFound                        // a notification for an otp/ object is in hand
)

// expired reports the right error for a finished context, or nil.
//
// ONE rule wherever a deadline ends this read: wrap. The deadline this reader
// runs under is its own, caller-minus-margin, and it did expire -- exempting
// the "standing down early" case would leave the identical message classifiable
// on one path and not the other, decided only by whether the run-up crossed the
// margin before or after entering receive.
//
// The arms are ordered by what the reader has actually observed: cancellation
// first (nothing timed out), then a delivery seen, then a queue read, then
// nothing read at all -- and the last splits on whose clock ran out.
func (m *otpMailbox) expired(
	ctx context.Context, progress mailboxProgress, remaining time.Duration, bounded bool,
) error {
	if ctx.Err() == nil {
		return nil
	}
	// Hoisted: the switch cannot bind, so testing m.cancelled(ctx) in a case
	// and returning it in the body built the error twice and returned an
	// object other than the one that was tested -- in the loop's per-iteration
	// check.
	if cancelled := m.cancelled(ctx); cancelled != nil {
		return cancelled
	}
	switch {
	case progress >= mailboxDeliveryFound:
		return mailboxDeadlineError{m.deliveryNotFetched()}
	case progress >= mailboxPolled:
		return mailboxDeadlineError{m.timedOut()}
	case bounded && remaining <= otpMailboxDeadlineMargin:
		// The CALLER's clock is what ran out.
		return mailboxDeadlineError{m.spentBeforePolling(remaining)}
	default:
		// Our own budget ran out while the caller still had time -- a
		// different cause, and blaming the registration deadline here would
		// print "59m59s left, under the 2s held in reserve" in one breath.
		return mailboxDeadlineError{m.budgetSpentBeforePolling(remaining, bounded)}
	}
}

// deliveryNotFetched explains a deadline that arrived while fetching an object
// the queue had already announced.
//
// Careful about WHOSE. Ownership is not known until extractOTPCode has parsed
// the body, and progress rises as soon as the bucket and otp/ prefix match --
// which every concurrent run's and every rerun's delivery does, on a queue and
// bucket that come from shared secrets. So this message must not say the
// delivery was ours, and must not tell the reader the issuer logs are the wrong
// place: run A can be killed fetching run B's object precisely because A's own
// OTP was never issued, which is the mid-deploy case, and the issuer log is
// exactly where A's answer is.
//
// It is the one message here that tells someone to STOP looking somewhere, so
// it is the one that has to be most careful about what it actually knows.
func (m *otpMailbox) deliveryNotFetched() error {
	return errors.New(
		"the deadline expired while fetching a delivery from the shared mailbox: the queue " +
			"carried a notification for an otp/ object and it could not be read in time. " +
			"WHOSE that object is was never established -- ownership is decided by parsing " +
			"the body, which is what ran out of time -- so it may belong to a concurrent run " +
			"or a rerun, and issuance for THIS run is confirmed neither way. What certainly " +
			"ran out is this mailbox's budget against S3, so weigh the run-up cost and S3 " +
			"latency, or give the registration deadline more room; and if no issuance for " +
			"this run shows in the issuer logs, that is still the answer")
}

// cancelled reports a caller that stopped for a reason other than running out
// of time, or nil.
//
// Shared with receive's early return, which is the only exit that does not pass
// through expired(). Without it, a cancelled caller whose deadline happened to
// be inside the margin was told "the registration deadline was spent" -- a
// cause it did not observe, and one that made errors.Is report DeadlineExceeded
// for a context that was Canceled, inverting exactly what
// TestMailboxDeadlineErrorsAreClassifiable requires.
func (m *otpMailbox) cancelled(ctx context.Context) error {
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("the mailbox wait was cancelled before any code arrived: %w", err)
	}
	return nil
}

// orExpired prefers the deadline diagnosis over a killed CLI's exit code.
//
// exec.CommandContext kills the aws CLI when the budget expires, and that
// surfaces as a generic non-zero exit reported as "mailbox AWS operation ...
// failed" -- the shape that, per runAWSCLI's own comment, sent someone hunting
// through IAM once already. Only the receive-message call used to make this
// choice; the get-object and delete/release calls returned the exit code raw,
// and get-object runs LATE in a long wait, which is exactly the slow-run shape
// this file is about. One helper so every site chooses the same way.
func (m *otpMailbox) orExpired(
	ctx context.Context, err error, progress mailboxProgress, remaining time.Duration, bounded bool,
) error {
	if expired := m.expired(ctx, progress, remaining, bounded); expired != nil {
		// Joined, not substituted. The killed-CLI exit code is noise and must
		// not LEAD -- that was the whole complaint -- but deleting it also
		// deletes the genuine failures that can race a deadline here: an IAM
		// error on release, or a local "write mailbox delete request". The
		// diagnosis leads and the cause survives underneath it, which is the
		// same trade every other message in this file makes.
		return errors.Join(expired, err)
	}
	return err
}

// budgetSpentBeforePolling explains a wait whose OWN budget expired before the
// queue could be read once, while the caller still had time to spare.
//
// Separate from spentBeforePolling because the cause is different and the
// numbers give it away: that message reasons about the caller's deadline and
// the reserve held against it, which is nonsense when there is an hour left. A
// diagnostic contradicted by the figures it quotes is worse than a vague one.
//
// What it points at is different too. Nothing here is about issuance: the poll
// itself neither answered nor exited, which is a network or credential problem
// on the path to SQS, not something any issuer log will explain.
func (m *otpMailbox) budgetSpentBeforePolling(remaining time.Duration, bounded bool) error {
	left := "the caller set no deadline at all"
	if bounded {
		left = fmt.Sprintf("%s still left on the caller's", remaining.Round(time.Millisecond))
	}
	return fmt.Errorf(
		"this mailbox's own %s budget expired before the queue could be read even once, with "+
			"%s. Nothing was polled, so this says NOTHING about whether an OTP was issued or "+
			"delivered. What failed to finish is the `aws sqs receive-message` call itself -- "+
			"it neither answered nor exited, which points at the network path to SQS or at "+
			"the gate's credentials, NOT at the issuer. No lambda log will explain this one",
		m.waitBudget, left)
}

// receive long-polls until a message addressed to this agent arrives, or ctx
// expires. A message that is not ours is deleted only when it predates this run
// -- anything newer is released back, because a concurrent run is still waiting
// for it.
func (m *otpMailbox) receive(ctx context.Context, agentID string) (string, error) {
	// Bounded by what is actually LEFT of the caller's deadline, not just set
	// to waitBudget.
	//
	// The two clocks do not start together. The caller's context begins at the
	// top of the test; this budget begins when the SDK first calls the
	// provider -- after the knock, the LST and the REG round-trips. So "4m is
	// under the 5m deadline" only holds while reaching the OTP challenge takes
	// under a minute, and that one minute was the entire margin. Exceed it and
	// the OUTER deadline fires first, the SDK discards everything below and
	// returns a bare "context deadline exceeded" -- deleting the whole
	// diagnosis this file exists to produce, in precisely the situation that
	// motivated it: a mid-deploy sandbox, where Relay rolling Blue-Green is
	// exactly what makes the run-up slow. Lowering otpE2EDeadline or raising
	// otpE2EMailboxWait would have deleted it silently too.
	//
	// Derived OUTSIDE any `waitBudget > 0` guard, so the guarantee is
	// structural rather than conditional: a zero waitBudget would otherwise
	// skip all of this and block on the caller's context, producing the very
	// outcome the clamp prevents. TestMailboxTimeoutSurvivesTheCallersDeadline
	// pins the clamp; TestUnboundedMailboxRefusesRatherThanHanging the refusal.
	callerDeadline, bounded := ctx.Deadline()
	budget := m.waitBudget
	if bounded {
		room := time.Until(callerDeadline) - otpMailboxDeadlineMargin
		if room <= 0 {
			if cancelled := m.cancelled(ctx); cancelled != nil {
				return "", cancelled
			}
			return "", mailboxDeadlineError{m.spentBeforePolling(time.Until(callerDeadline))}
		}
		if budget <= 0 || room < budget {
			budget = room
		}
	}
	// remaining reports the CALLER's deadline, not the derived one below.
	remaining := func() time.Duration {
		if !bounded {
			return 0
		}
		return time.Until(callerDeadline)
	}
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	} else if !bounded {
		// Nothing bounds this at all: no budget, no caller deadline. The loop
		// below would long-poll forever and never produce a diagnosis, which is
		// the fail-OPEN the clamp exists to remove -- unreachable today only
		// because newOTPMailbox always passes otpE2EMailboxWait and the gate
		// always sets otpE2EDeadline. Refuse rather than rely on that.
		return "", errors.New(
			"the mailbox has neither a wait budget nor a caller deadline, so a missing OTP " +
				"would hang instead of being reported; set otpE2EMailboxWait or give the " +
				"caller's context a deadline")
	}
	dir, err := os.MkdirTemp("", "qurl-otp-mailbox-")
	if err != nil {
		return "", errors.New("create mailbox scratch directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", errors.New("secure mailbox scratch directory")
	}
	defer os.RemoveAll(dir)

	// progress records how far this read actually got. Arithmetic
	// at entry is not enough: a budget of a second or two is positive, so the
	// loop starts, and the aws CLI's own 0.5-1.5s startup is then killed before
	// it reaches SQS. Claiming "no OTP email arrived" there would assert a
	// cause this reader never observed -- the same defect spentBeforePolling
	// exists to remove, surviving in the band just above the margin.
	progress := mailboxUnread
	for {
		if err := m.expired(ctx, progress, remaining(), bounded); err != nil {
			return "", err
		}
		raw, err := m.runAWS(ctx,
			"sqs", "receive-message",
			"--queue-url", m.queueURL,
			"--max-number-of-messages", "1",
			"--wait-time-seconds", "10",
			"--visibility-timeout", "60",
			"--region", m.region,
			"--output", "json",
		)
		if err != nil {
			// exec.CommandContext kills the CLI when the budget expires, which
			// surfaces as a generic non-zero exit. That is a timeout, and
			// reporting it as an AWS failure sent me hunting through IAM once
			// already.
			return "", m.orExpired(ctx, err, progress, remaining(), bounded)
		}
		// The queue was read. Anything from here on may honestly say so.
		progress = mailboxPolled
		var received sqsReceiveOutput
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &received); err != nil {
				return "", errors.New("mailbox queue returned malformed JSON")
			}
		}
		if len(received.Messages) == 0 {
			continue
		}
		message := received.Messages[0]
		if message.ReceiptHandle == "" {
			return "", errors.New("mailbox queue returned a message with no receipt handle")
		}

		var notification s3Notification
		if err := json.Unmarshal([]byte(message.Body), &notification); err != nil {
			return "", errors.New("mailbox queue returned a malformed S3 notification")
		}
		// S3 emits one of these when the notification configuration is created.
		if notification.Event == "s3:TestEvent" {
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				return "", m.orExpired(ctx, err, progress, remaining(), bounded)
			}
			continue
		}
		if len(notification.Records) != 1 {
			return "", errors.New("mailbox notification did not describe exactly one object")
		}
		record := notification.Records[0]
		// Deliveries from before this run started are nobody's: every run that
		// wanted them has finished. Delete those.
		//
		// Anything NEWER is potentially a concurrent run's, because the queue,
		// bucket, and recipient come from shared repo secrets and the workflow's
		// concurrency group only serialises the same ref. Releasing rather than
		// deleting is what actually upholds "concurrent runs cannot consume one
		// another's messages" -- the agent-id binding alone only stops a run
		// READING a foreign code, not destroying it.
		//
		// An unparseable eventTime is treated as not-stale and released, so a
		// malformed timestamp can never cause a delete.
		delivered, err := time.Parse(time.RFC3339, record.EventTime)
		if err == nil && delivered.Before(m.notBefore) {
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				return "", m.orExpired(ctx, err, progress, remaining(), bounded)
			}
			continue
		}
		key, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil || record.S3.Bucket.Name != m.bucket || !strings.HasPrefix(key, "otp/") {
			return "", errors.New("mailbox notification escaped its expected bucket or prefix")
		}

		// A delivery for this run exists. From here a deadline is no longer
		// about whether an email was sent.
		progress = mailboxDeliveryFound

		path := dir + "/message"
		if _, err := m.runAWS(ctx, "s3api", "get-object",
			"--bucket", m.bucket, "--key", key, path, "--region", m.region); err != nil {
			return "", m.orExpired(ctx, err, progress, remaining(), bounded)
		}
		body, err := readBoundedFile(path)
		if err != nil {
			return "", err
		}
		_ = os.Remove(path)

		code, matched, err := extractOTPCode(body, m.recipient, agentID)
		if err != nil {
			return "", err
		}
		if matched {
			// Ours: consume it. The S3 object is deliberately left alone -- the
			// gate role is read-only on the bucket and the mailbox expires
			// objects after a day, so asking for s3:DeleteObject would widen the
			// role for no benefit.
			if err := m.deleteMessage(ctx, dir, message.ReceiptHandle); err != nil {
				// The code is in hand. Discarding it because a CLEANUP call was
				// killed is the wrong trade, and reporting a deadline here used
				// to announce "no OTP email arrived" about an email just
				// parsed -- contradicted by a variable in the same frame. An
				// undeleted message becomes visible again and a later run
				// removes it through the notBefore staleness path, so nothing
				// leaks. A genuine failure (permissions, a bad handle) still
				// surfaces: it says something real about the mailbox role.
				if ctx.Err() == nil {
					return "", err
				}
			}
			return code, nil
		}
		// Not ours, and recent enough to belong to a concurrent run. Release it
		// so its owner can still receive it, rather than deleting it and turning
		// their run red. The short delay keeps this loop from immediately
		// re-receiving the same message and spinning on it (that delay is the
		// --visibility-timeout on releaseMessage below, not anything local).
		//
		// Not ours after all, so it says nothing about whether an email was
		// sent for THIS run -- stop letting it answer for one.
		//
		// progress is raised before extractOTPCode, which is right: until the
		// body is parsed the delivery might be ours. It has to come back down
		// here, because a concurrent run's email -- or a rerun's, since
		// runScopedAgentID scopes on run id AND attempt -- would otherwise keep
		// it high for the rest of the wait and let a foreign delivery answer
		// for a later timeout.
		progress = mailboxPolled
		if err := m.releaseMessage(ctx, message.ReceiptHandle); err != nil {
			return "", m.orExpired(ctx, err, progress, remaining(), bounded)
		}
	}
}

// releaseMessage returns a message to the queue for another run to receive.
func (m *otpMailbox) releaseMessage(ctx context.Context, receiptHandle string) error {
	_, err := m.runAWS(ctx,
		"sqs", "change-message-visibility",
		"--queue-url", m.queueURL,
		"--receipt-handle", receiptHandle,
		"--visibility-timeout", "10",
		"--region", m.region,
	)
	return err
}

func (m *otpMailbox) deleteMessage(ctx context.Context, dir, receiptHandle string) error {
	// Passed via --cli-input-json: a receipt handle can contain characters that
	// are awkward on a command line.
	path := dir + "/delete.json"
	payload, err := json.Marshal(map[string]string{"QueueUrl": m.queueURL, "ReceiptHandle": receiptHandle})
	if err != nil {
		return errors.New("encode mailbox delete request")
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return errors.New("write mailbox delete request")
	}
	_, err = m.runAWS(ctx, "sqs", "delete-message", "--cli-input-json", "file://"+path, "--region", m.region)
	_ = os.Remove(path)
	return err
}

// extractOTPCode returns the code if raw is the OTP email for this recipient
// and agent. matched=false means "not our message", which is not an error --
// only a malformed or ambiguous message is.
func extractOTPCode(raw []byte, recipient, agentID string) (code string, matched bool, err error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", false, errors.New("mailbox message is not valid RFC 5322 mail")
	}
	subject, err := (&mime.WordDecoder{}).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		return "", false, errors.New("mailbox message subject is malformed")
	}
	if subject != otpEmailSubject {
		return "", false, nil
	}
	recipients, err := message.Header.AddressList("To")
	if err != nil {
		return "", false, errors.New("mailbox message recipient header is malformed")
	}
	if len(recipients) != 1 || !strings.EqualFold(recipients[0].Address, recipient) {
		return "", false, nil
	}
	body, err := decodeMIMEBody(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return "", false, err
	}
	// Binds the code to THIS agent, so concurrent gate runs cannot consume one
	// another's messages.
	if !strings.Contains(body, `Connector ID:  "`+agentID+`"`) {
		return "", false, nil
	}
	unique := make(map[string]struct{})
	for _, match := range otpCodePattern.FindAllStringSubmatch(body, -1) {
		unique[match[1]] = struct{}{}
	}
	if len(unique) != 1 {
		return "", false, errors.New("mailbox message did not contain exactly one distinct 8-digit code")
	}
	for candidate := range unique {
		return candidate, true, nil
	}
	return "", false, errors.New("mailbox code extraction failed")
}

func decodeMIMEBody(header textproto.MIMEHeader, body io.Reader) (string, error) {
	decoded, err := decodeTransferEncoding(header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return "", err
	}
	contentType := header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		return "", errors.New("mailbox message content type is malformed")
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		raw, err := io.ReadAll(io.LimitReader(decoded, maxMailBytes+1))
		if err != nil || len(raw) > maxMailBytes {
			return "", errors.New("mailbox message body exceeded its bound")
		}
		return string(raw), nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", errors.New("multipart mailbox message has no boundary")
	}
	// Concatenate every part: the code lives in text/plain, and scanning all of
	// them avoids depending on part ordering.
	var combined strings.Builder
	reader := multipart.NewReader(decoded, boundary)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errors.New("mailbox message multipart structure is malformed")
		}
		text, err := decodeMIMEBody(part.Header, part)
		_ = part.Close()
		if err != nil {
			return "", err
		}
		combined.WriteString(text)
		combined.WriteString("\n")
		if combined.Len() > maxMailBytes {
			return "", errors.New("mailbox message body exceeded its bound")
		}
	}
	return combined.String(), nil
}

func decodeTransferEncoding(encoding string, body io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "quoted-printable":
		return quotedprintable.NewReader(body), nil
	case "base64":
		return newBase64Reader(body), nil
	default:
		return nil, errors.New("mailbox message uses an unsupported transfer encoding")
	}
}

// newBase64Reader decodes a base64 MIME part. Line breaks are stripped because
// base64 bodies are wrapped, and the standard decoder rejects them.
func newBase64Reader(body io.Reader) io.Reader {
	stripped := &newlineStrippingReader{inner: body}
	return base64.NewDecoder(base64.StdEncoding, stripped)
}

type newlineStrippingReader struct{ inner io.Reader }

// Read never returns (0, nil), including when the inner reader does. The
// discouraged zero-count/nil-error pair only happens to be safe here because
// base64.NewDecoder reads through io.ReadFull, and depending on a consumer's
// implementation detail is not a property worth keeping. Loop instead.
func (r *newlineStrippingReader) Read(p []byte) (int, error) {
	for {
		n, err := r.inner.Read(p)
		if n > 0 {
			filtered := p[:0]
			for _, b := range p[:n] {
				if b != '\r' && b != '\n' {
					filtered = append(filtered, b)
				}
			}
			if len(filtered) > 0 {
				return len(filtered), err
			}
			if err == nil {
				continue // stripped everything; go back for real bytes
			}
			return 0, err
		}
		if err == nil {
			continue // inner reader returned (0, nil); do not propagate it
		}
		return 0, err
	}
}

// readBoundedFile reads a fetched message under maxMailBytes.
//
// The cap previously bound only the decoded MIME part, so an oversized object
// was buffered whole before decoding ever ran -- the guarantee the maxMailBytes
// comment states was not actually enforced at the fetch. Low impact given the
// source is our own SES pipeline, but the bound should be where the claim is.
func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open fetched mailbox message")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxMailBytes+1))
	if err != nil {
		return nil, errors.New("read fetched mailbox message")
	}
	if len(body) > maxMailBytes {
		return nil, errors.New("fetched mailbox message exceeded its size bound")
	}
	return body, nil
}
