package qurl

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Typed errors for RegisterAgent, the NHP-native agent enrollment front door.
//
// These mirror the sentinel + typed-view conventions the rest of the package
// uses (facade.go's error sentinels, reply.go's ServerDenyError view): match a
// broad outcome with errors.Is against a sentinel, and pull structured detail
// with errors.As against the typed error. Every message is written to be
// actionable when read by an operator or an LLM agent driving registration —
// it names the next concrete step, not just the failure.

// ErrInvalidRegisterConfig is returned when RegisterAgent inputs or options are
// invalid before any network call.
var ErrInvalidRegisterConfig = errors.New("qurl: invalid register config")

// ErrOTPPending is returned (wrapped in *OTPPendingError) when account-key
// registration has requested an email one-time code and is waiting for the
// caller to supply it. It is not a failure: it is the pause point of the
// two-phase email-OTP flow. Re-run RegisterAgent with WithOTP once the code
// arrives.
var ErrOTPPending = errors.New("qurl: registration awaiting one-time code")

// ErrOTPIncorrect is returned when a supplied one-time code was rejected as
// wrong. Re-run RegisterAgent with the correct code.
var ErrOTPIncorrect = errors.New("qurl: one-time code incorrect")

// ErrOTPExpired is returned when a supplied one-time code was valid but has
// expired. Re-run RegisterAgent with no code to request a fresh one, then
// supply the new code.
var ErrOTPExpired = errors.New("qurl: one-time code expired")

// ErrRegistrationRateLimited is returned when the enrollment service is rate
// limiting or has locked out further attempts for now. Back off and retry
// later.
var ErrRegistrationRateLimited = errors.New("qurl: registration rate limited")

// ErrKeyRejected is returned when the supplied API key was rejected as invalid.
// Check the key and re-run registration.
var ErrKeyRejected = errors.New("qurl: registration key rejected")

// ErrAgentIdentityConflict is returned when the device identity is already
// enrolled to a different key or agent. Re-run RegisterAgent with WithTakeover
// to re-bind it, or choose a different device id with WithDeviceID.
var ErrAgentIdentityConflict = errors.New("qurl: agent identity conflict")

// ErrNoAccountEmail is returned when account-key email-OTP registration cannot
// proceed because the account has no usable email on file to send the code to.
// Add an email to the account, or register with a pre-issued key instead.
var ErrNoAccountEmail = errors.New("qurl: account has no email for one-time code")

// ErrDeviceCredentialMissing is returned when the saved AgentState shows the
// device is registered but does not hold its device API credential — the
// credential is issued once and this state cannot reproduce it. Recovery depends
// on how it arose: if a completion reported the key was already issued, register
// under a new device id (WithDeviceID) or re-bind with WithTakeover; if a
// locally-registered state simply lacks the credential (for example a legacy
// bootstrap-era state file), clear or replace the persisted state to mint a fresh
// credential.
var ErrDeviceCredentialMissing = errors.New("qurl: device credential missing from agent state")

// ErrRegistrationInvalidInput is returned when the enrollment service rejected a
// registration input as malformed (for example a device id that is not a valid
// identifier). Fix the input and re-run RegisterAgent.
var ErrRegistrationInvalidInput = errors.New("qurl: registration input invalid")

// ErrRegistrationDisabled is returned when agent registration is disabled for
// the account. Contact the account owner to enable it.
var ErrRegistrationDisabled = errors.New("qurl: agent registration disabled")

// ErrRegistrationRetryLater is returned when the registration relay answered with
// an overload cookie-challenge (NHP_COK) instead of a registration reply: the
// enrollment path is under load. Back off briefly and re-run RegisterAgent.
var ErrRegistrationRetryLater = errors.New("qurl: registration relay busy; retry shortly")

// ErrRegisterReplyMalformed is returned when the registration relay returned a
// reply that failed the request→reply correlation contract before the SDK could
// interpret it: the NHP_RAK did not echo the request counter, or its header type
// was not a valid answer to an NHP_REG. It is the enrollment-path peer of the
// portal's ErrMalformedReply, mapping relayknock.ErrMalformedReply into the
// registration taxonomy. Only a misbehaving/byzantine relay produces it — a
// conforming relay routes a reply back by its cleartext counter — so it is a
// defense-in-depth signal, not an expected failure on a healthy relay.
var ErrRegisterReplyMalformed = errors.New("qurl: registration reply malformed")

// OTPPendingError is the typed error the account-key path returns after it has
// asked LayerV to email a one-time code and is waiting for the caller to supply
// it. It unwraps to ErrOTPPending, so callers can match either the sentinel
// (errors.Is) or read RequestedAt / MaskedEmail (errors.As).
//
// A pending result does not by itself guarantee a code was delivered: the SDK
// persists the "requested" state before dispatching (anti-spam ordering), so if
// that send fails transiently, a re-run within the resend cooldown still reports
// pending — no code in the inbox yet — until the cooldown elapses and a fresh
// code is sent.
type OTPPendingError struct {
	// RequestedAt is when the one-time code was requested (emailed).
	RequestedAt time.Time
	// MaskedEmail is the masked destination the code was sent to, for example
	// "j***@x.com". It may be empty if the service did not report one.
	MaskedEmail string
}

func (e *OTPPendingError) Error() string {
	dest := "your account email"
	if strings.TrimSpace(e.MaskedEmail) != "" {
		dest = e.MaskedEmail
	}
	return fmt.Sprintf(
		"qurl: a one-time code was requested for %s — check that inbox and re-run qurl.RegisterAgent with qurl.WithOTP(\"<code>\") to finish enrollment. Codes expire after a short window; if none arrives, re-running without WithOTP re-sends a fresh code after a short cooldown.",
		dest,
	)
}

// Unwrap ties OTPPendingError to the ErrOTPPending sentinel so errors.Is matches.
func (e *OTPPendingError) Unwrap() error { return ErrOTPPending }

// RegistrationDenyError is an authenticated enrollment denial the SDK could not
// map to a known typed sentinel: the NHP registration reply (NHP_RAK) carried an
// error code this SDK version does not recognize. ErrCode and ErrMsg are the
// raw wire fields, surfaced verbatim so an operator can act on a code newer than
// the SDK. Known codes are mapped to the typed sentinels above instead of this
// error; Is() below bridges the ones a RegistrationDenyError can still carry.
type RegistrationDenyError struct {
	// ErrCode is the NHP_RAK error code string ("0"/"" are success and never
	// produce this error).
	ErrCode string
	// ErrMsg is the human-readable message from the enrollment service, if any.
	ErrMsg string
}

func (e *RegistrationDenyError) Error() string {
	if strings.TrimSpace(e.ErrMsg) != "" {
		return fmt.Sprintf("qurl: registration denied (errCode=%q): %s", e.ErrCode, e.ErrMsg)
	}
	return fmt.Sprintf("qurl: registration denied (errCode=%q)", e.ErrCode)
}

// Is lets a RegistrationDenyError match the typed registration sentinels for the
// known error codes, so a caller that only kept the mapped-error path still
// matches even if a construction site handed back the raw deny. mapRAKError is
// the primary mapping; this keeps errors.Is consistent for a RegistrationDenyError
// that carries a known code.
func (e *RegistrationDenyError) Is(target error) bool {
	sentinel := sentinelForRAKCode(e.ErrCode)
	return sentinel != nil && errors.Is(sentinel, target)
}
