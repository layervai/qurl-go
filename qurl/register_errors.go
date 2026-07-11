package qurl

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Typed errors for the NHP-native agent enrollment and lifecycle front doors.
//
// These mirror the sentinel + typed-view conventions the rest of the package
// uses (facade.go's error sentinels, reply.go's ServerDenyError view): match a
// broad outcome with errors.Is against a sentinel, and pull structured detail
// with errors.As against the typed error. Every message is written to be
// actionable when read by an operator or an LLM agent driving registration —
// it names the next concrete step, not just the failure.

// ErrInvalidRegisterConfig is returned when registration/lifecycle inputs or
// options are invalid before any network call.
var ErrInvalidRegisterConfig = errors.New("qurl: invalid register config")

// ErrOTPPending is returned (wrapped in *OTPPendingError) when account-key
// registration has requested an email one-time code and is waiting for the
// caller to supply it. It is not a failure: it is the pause point of the
// two-phase email-OTP flow. Re-run the same operation with WithOTP once the code
// arrives.
var ErrOTPPending = errors.New("qurl: registration awaiting one-time code")

// ErrOTPIncorrect is returned when a supplied one-time code was rejected as
// wrong. Re-run the same operation with the correct WithOTP code.
var ErrOTPIncorrect = errors.New("qurl: one-time code incorrect")

// ErrOTPExpired is returned when a supplied one-time code was valid but has
// expired. Re-run the same operation with no code to request a fresh one, then
// re-run it with the new WithOTP code.
var ErrOTPExpired = errors.New("qurl: one-time code expired")

// ErrRegistrationRateLimited is returned when the enrollment service is rate
// limiting or has locked out further attempts for now. Back off and retry
// later.
var ErrRegistrationRateLimited = errors.New("qurl: registration rate limited")

// ErrDeviceKeyQuotaExceeded is returned when the account has no free active
// device-key slot. Revoke an existing unused device key to free a slot, then
// retry the same registration or recovery operation.
var ErrDeviceKeyQuotaExceeded = errors.New("qurl: device key quota exceeded")

// DeviceKeyQuotaExceededError carries the device id whose credential could not
// be issued and preserves the completion API error. The service reports this
// only when the atomic mint transaction rejected the request without writing,
// so freeing a slot and retrying is safe.
type DeviceKeyQuotaExceededError struct {
	DeviceID string
	Cause    error
}

func (e *DeviceKeyQuotaExceededError) Error() string {
	message := fmt.Sprintf("qurl: cannot issue a device key for %q because the account has reached its active device-key limit; revoke an existing unused device key to free a slot, then retry the same qurl.RegisterAgent or qurl.RecoverAgentCredential operation; only when intentionally re-binding this device id from a different key, revoke that device key and retry with qurl.WithTakeover", e.DeviceID)
	return messageWithCause(message, e.Cause)
}

func (e *DeviceKeyQuotaExceededError) Unwrap() []error {
	return unwrapWithCause(e.Cause, ErrDeviceKeyQuotaExceeded)
}

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

// ErrDeviceCredentialMissing is the broad compatibility class for an AgentState
// that cannot authorize resource calls. Credential issuance/recovery errors also
// match ErrCredentialRecoveryRequired and carry the persisted device id; revoke
// agent:<device_id>, then explicitly call RecoverAgentCredential.
var ErrDeviceCredentialMissing = errors.New("qurl: device credential missing from agent state")

// ErrCredentialRecoveryRequired means the service-side device credential and
// local AgentState are no longer safely reconcilable through ordinary
// RegisterAgent. The owner must revoke agent:<device_id>, then explicitly call
// RecoverAgentCredential with the same persisted identity.
var ErrCredentialRecoveryRequired = errors.New("qurl: agent credential recovery required")

// ErrRegistrationKeyKindDisallowed means registration-info reported a valid key
// kind that the caller's WithAllowedRegistrationKeyKinds policy rejects.
var ErrRegistrationKeyKindDisallowed = errors.New("qurl: registration key kind disallowed")

// RegistrationKeyKindDisallowedError carries the rejected server-reported kind
// and the caller's accepted kinds. It is returned before OTP dispatch or NHP REG.
type RegistrationKeyKindDisallowedError struct {
	Kind    RegistrationKeyKind
	Allowed []RegistrationKeyKind
}

func (e *RegistrationKeyKindDisallowedError) Error() string {
	allowed := make([]string, len(e.Allowed))
	for i, kind := range e.Allowed {
		allowed[i] = string(kind)
	}
	return fmt.Sprintf("qurl: registration key kind %q is disallowed; accepted kinds: %s", e.Kind, strings.Join(allowed, ", "))
}

func (e *RegistrationKeyKindDisallowedError) Unwrap() error {
	return ErrRegistrationKeyKindDisallowed
}

// CredentialRecoveryRequiredError identifies an already-issued device
// credential that cannot be fetched again. Revoke agent:<device_id> through an
// owner credential, then call RecoverAgentCredential with the same state store.
// WithTakeover alone does not clear the issuance record; add it after revocation
// only when re-binding a changed keypair/host.
type CredentialRecoveryRequiredError struct {
	DeviceID string
	Cause    error
}

func (e *CredentialRecoveryRequiredError) Error() string {
	keyID := "agent:" + e.DeviceID
	message := fmt.Sprintf("qurl: device credential for %q was already issued and cannot be fetched again; revoke the active %q key first, then call qurl.RecoverAgentCredential with this state store; qurl.WithTakeover alone does not clear the issuance record—add it after revocation only when re-binding a changed keypair or host; the only no-revoke alternative is enrolling a distinct new device id in a separate state store", e.DeviceID, keyID)
	return messageWithCause(message, e.Cause)
}

func (e *CredentialRecoveryRequiredError) Unwrap() []error {
	return recoveryClassUnwrap(e.Cause)
}

func validatePersistedDeviceCredential(state *AgentState, errKind error) error {
	if state.DeviceAPIKey == "" {
		return &CredentialRecoveryRequiredError{DeviceID: state.AgentID, Cause: ErrDeviceCredentialMissing}
	}
	if err := validateExactBearerToken(state.DeviceAPIKey, "persisted device credential", errKind); err != nil {
		return &CredentialRecoveryRequiredError{DeviceID: state.AgentID, Cause: err}
	}
	return nil
}

func recoveryClassUnwrap(cause error) []error {
	return unwrapWithCause(cause, ErrCredentialRecoveryRequired, ErrDeviceCredentialMissing)
}

// unwrapWithCause builds the multi-error Unwrap chain shared by the typed
// credential errors: the class sentinels followed by the wrapped cause when one
// is present. Each caller passes its own sentinel set, so appending the cause
// cannot alias shared storage.
func unwrapWithCause(cause error, sentinels ...error) []error {
	if cause == nil {
		return sentinels
	}
	return append(sentinels, cause)
}

// messageWithCause appends a wrapped cause to a typed error's operator-facing
// message when one is present. Each credential issuance/recovery type builds a
// distinct message and then surfaces its underlying cause identically.
func messageWithCause(message string, cause error) string {
	if cause != nil {
		return fmt.Sprintf("%s: %v", message, cause)
	}
	return message
}

// CredentialPersistenceError means completion may have minted its one-time
// plaintext device credential, but the SDK could not prove a valid durable
// commit. This includes transport/5xx/response ambiguity as well as a final
// AgentState save failure. Retrying ordinary registration is unsafe. Revoke
// agent:<device_id>, then explicitly recover the same identity.
type CredentialPersistenceError struct {
	DeviceID string
	Cause    error
}

func (e *CredentialPersistenceError) Error() string {
	keyID := "agent:" + e.DeviceID
	message := fmt.Sprintf("qurl: device credential for %q may have been minted but was not safely persisted; revoke %q, then call qurl.RecoverAgentCredential with this state store", e.DeviceID, keyID)
	return messageWithCause(message, e.Cause)
}

func (e *CredentialPersistenceError) Unwrap() []error {
	return recoveryClassUnwrap(e.Cause)
}

// ErrRegistrationInvalidInput is returned when the enrollment service rejected a
// registration input as malformed (for example a device id that is not a valid
// identifier). Fix the input and re-run the same operation.
var ErrRegistrationInvalidInput = errors.New("qurl: registration input invalid")

// ErrRegistrationDisabled is returned when agent registration is disabled for
// the account. Contact the account owner to enable it.
var ErrRegistrationDisabled = errors.New("qurl: agent registration disabled")

// ErrRegistrationRetryLater is returned when the registration relay answers
// with an overload cookie-challenge or completion reports a structured,
// authoritative no-write service_unavailable admission result. Back off briefly
// and re-run the same operation.
var ErrRegistrationRetryLater = errors.New("qurl: registration temporarily unavailable; retry shortly")

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
		"qurl: a one-time code was requested for %s — check that inbox and re-run the same qurl operation with qurl.WithOTP(\"<code>\"). Codes expire after a short window; if none arrives, re-running the same operation without WithOTP re-sends a fresh code after a short cooldown.",
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
