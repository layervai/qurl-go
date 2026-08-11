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
	otpE2EAgentIDEnv    = "QURL_OTP_E2E_AGENT_ID"

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
		otpE2EEnrollmentEnv, otpE2EAgentIDEnv,
		otpE2EMailboxQueueURLEnv, otpE2EMailboxBucketEnv,
		otpE2EMailboxRecipientEnv, otpE2EMailboxRegionEnv,
	}
	var missing []string
	for _, name := range required {
		if strings.TrimSpace(lookup(name)) == "" {
			missing = append(missing, name)
		}
	}
	strict := strings.TrimSpace(lookup(otpE2EStrictEnv)) != ""
	if len(missing) > 0 {
		if strict {
			return otpE2EConfig{}, false, fmt.Errorf(
				"strict OTP e2e run is missing %d prerequisite(s): %s",
				len(missing), strings.Join(missing, ", "))
		}
		return otpE2EConfig{}, true, nil
	}

	port, err := strconv.Atoi(strings.TrimSpace(lookup(otpE2EHubPortEnv)))
	if err != nil || port <= 0 || port > 65535 {
		return otpE2EConfig{}, false, fmt.Errorf("%s must be a valid UDP port", otpE2EHubPortEnv)
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
		enrollment:       strings.TrimSpace(lookup(otpE2EEnrollmentEnv)),
		agentID:          runScopedAgentID(strings.TrimSpace(lookup(otpE2EAgentIDEnv)), lookup),
		mailboxQueueURL:  strings.TrimSpace(lookup(otpE2EMailboxQueueURLEnv)),
		mailboxBucket:    strings.TrimSpace(lookup(otpE2EMailboxBucketEnv)),
		mailboxRecipient: strings.TrimSpace(lookup(otpE2EMailboxRecipientEnv)),
		mailboxRegion:    strings.TrimSpace(lookup(otpE2EMailboxRegionEnv)),
	}, false, nil
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

	ctx, cancel := context.WithTimeout(context.Background(), otpE2EDeadline)
	defer cancel()

	wrapper, err := newEphemeralStateKeyWrapper()
	if err != nil {
		t.Fatal(err)
	}
	// t.TempDir() honours the process umask, which on a hosted runner yields
	// 0755. The SDK refuses to open a state namespace that group/other can
	// traverse -- the credential and the setup lock both live here -- so tighten
	// it before constructing the store rather than letting the store reject it.
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatalf("restrict agent state directory: %v", err)
	}
	statePath := filepath.Join(stateDir, "agent-state.sealed")
	store, err := qurl.NewSealedFileAgentState(statePath, "otp-e2e-ephemeral", wrapper)
	if err != nil {
		t.Fatalf("open sealed agent state: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

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

	//nolint:staticcheck // RegisterAgentRuntime is the exact call this gate must protect.
	client, binding, err := qurl.RegisterAgentRuntime(ctx, cfg.enrollment, store,
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
		t.Fatalf("RegisterAgentRuntime with an emailed OTP: %v", err)
	}
	if client == nil || binding == nil {
		t.Fatal("RegisterAgentRuntime returned a nil client or binding")
	}
	t.Cleanup(binding.Destroy)

	if calls, fresh := mailbox.snapshot(); calls != 1 || !fresh {
		t.Fatalf("OTP provider calls = %d, fresh = %t; want exactly one freshly delivered code", calls, fresh)
	}
	if binding.DeviceAPIKeyID == "" {
		t.Fatal("registration produced no device API key id")
	}
	t.Logf("EVIDENCE emailed OTP completed registration: agent=%s cell=%s generation=%d",
		binding.AgentID, binding.CellID, binding.AssignmentGeneration)

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

	//nolint:staticcheck // second call is the assertion.
	replayClient, replayBinding, err := qurl.RegisterAgentRuntime(ctx, cfg.enrollment, store,
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
		t.Fatalf("second RegisterAgentRuntime must warm-open, got: %v", err)
	}
	if replayClient == nil || replayBinding == nil {
		t.Fatal("second RegisterAgentRuntime returned a nil client or binding")
	}
	t.Cleanup(replayBinding.Destroy)

	// The credential identity is the sharp edge: a second enrollment would
	// mint a new device API key. Everything else could plausibly match while
	// a duplicate credential was created behind it.
	if replayBinding.DeviceAPIKeyID != binding.DeviceAPIKeyID {
		t.Fatalf("device API key id changed across re-registration: %q -> %q; a second credential was minted",
			binding.DeviceAPIKeyID, replayBinding.DeviceAPIKeyID)
	}
	if replayBinding.AgentID != binding.AgentID {
		t.Fatalf("agent id changed across re-registration: %q -> %q", binding.AgentID, replayBinding.AgentID)
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
	t.Log("EVIDENCE re-registration warm-opened the same credential with no second OTP")
}
