package qurl

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidRegisterConfig is returned when native registration inputs or
// options are invalid before any UDP exchange.
var ErrInvalidRegisterConfig = errors.New("qurl: invalid register config")

// ErrAgentBindingPersistence means an AgentState save reported failure. The
// save may have committed before its acknowledgement failed, so reload first.
// PendingActivation resumes with the same enrollment credential,
// PendingCompletion resumes without one, and completed state may already hold
// the authenticated refreshed or reassigned binding.
var ErrAgentBindingPersistence = errors.New("qurl: agent binding persistence failed")

// ErrAgentCompletionCandidatePersistence means assigned-cell registration was
// accepted, but the SDK could not prove whether the atomic pending-activation
// to pending-completion transition became durable. Reload before deciding
// whether to re-drive the exact pending REG with the same enrollment credential
// or resume the exact pending completion candidate.
var ErrAgentCompletionCandidatePersistence = errors.New("qurl: native completion candidate durability is unknown")

// AgentCompletionCandidatePersistenceError is the typed post-RAK durability
// failure view.
type AgentCompletionCandidatePersistenceError struct {
	AgentID string
	Cause   error
}

func (e *AgentCompletionCandidatePersistenceError) Error() string {
	agentID := ""
	if e != nil {
		agentID = e.AgentID
	}
	message := fmt.Sprintf("qurl: assigned-cell registration for agent %q succeeded, but its post-RAK state-transition durability is unknown; reload state first and resume an exact pending activation with the same enrollment credential or an exact pending completion with an empty enrollment credential; save ambiguity alone never authorizes a replacement ticket, and only an exact pending-activation replay authenticated as 52111 or account 52101 permits the one bounded replacement", agentID)
	if e == nil {
		return message
	}
	return messageWithCause(message, e.Cause)
}

func (e *AgentCompletionCandidatePersistenceError) Unwrap() []error {
	if e == nil || e.Cause == nil {
		return []error{ErrAgentCompletionCandidatePersistence, ErrAgentBindingPersistence}
	}
	return []error{ErrAgentCompletionCandidatePersistence, ErrAgentBindingPersistence, e.Cause}
}

// ErrOTPIncorrect and ErrOTPExpired classify assigned-cell account OTP
// rejection. Invoke RegisterAgentRuntime again explicitly for a fresh attempt.
var (
	ErrOTPIncorrect = errors.New("qurl: one-time code incorrect")
	ErrOTPExpired   = errors.New("qurl: one-time code expired")
)

// ErrRegistrationRateLimited means the authenticated Hub or assigned cell is
// rate limiting registration.
var ErrRegistrationRateLimited = errors.New("qurl: registration rate limited")

// ErrDeviceKeyQuotaExceeded means native completion could not mint another
// active device credential until the owner revokes an unused one.
var ErrDeviceKeyQuotaExceeded = errors.New("qurl: device key quota exceeded")

// ErrKeyRejected means the enrollment credential was rejected.
var ErrKeyRejected = errors.New("qurl: registration key rejected")

// ErrAgentIdentityConflict means the requested native agent identity is bound
// to another key. Use explicit NHP-native reprovisioning; there is no implicit
// takeover option.
var ErrAgentIdentityConflict = errors.New("qurl: agent identity conflict")

// ErrNoAccountEmail means an account credential cannot receive the assigned-
// cell OTP challenge.
var ErrNoAccountEmail = errors.New("qurl: account has no email for one-time code")

// ErrDeviceCredentialMissing classifies completed native state that cannot
// authorize steady-state resource calls.
var ErrDeviceCredentialMissing = errors.New("qurl: device credential missing from agent state")

// ErrCredentialRecoveryRequired means completed native state and its
// authority-side credential are not safely usable without explicit native
// recovery or reprovisioning.
var ErrCredentialRecoveryRequired = errors.New("qurl: agent credential recovery required")

// ErrRegistrationKeyKindDisallowed means an authenticated Hub assignment
// reported a valid key kind rejected by caller policy.
var ErrRegistrationKeyKindDisallowed = errors.New("qurl: registration key kind disallowed")

// RegistrationKeyKindDisallowedError carries the rejected kind and the
// caller's accepted kinds. It is returned before OTP dispatch or REG.
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

func validatePersistedNativeDeviceCredential(state *AgentState, errKind error) error {
	if state == nil {
		return &NativeCredentialRecoveryRequiredError{Cause: fmt.Errorf("%w: native agent state is nil", errKind)}
	}
	if state.DeviceAPIKey == "" {
		return &NativeCredentialRecoveryRequiredError{AgentID: state.AgentID, Cause: ErrDeviceCredentialMissing}
	}
	if err := validateNativeDeviceCredential(state.DeviceAPIKey, "persisted device credential", errKind); err != nil {
		return &NativeCredentialRecoveryRequiredError{AgentID: state.AgentID, Cause: err}
	}
	if err := validateAPIKeyID(state.DeviceAPIKeyID, "persisted device credential id", errKind); err != nil {
		return &NativeCredentialRecoveryRequiredError{AgentID: state.AgentID, Cause: err}
	}
	return nil
}

func validatePersistedCredentialForState(state *AgentState, errKind error) error {
	if !isNativeAgentRuntimeState(state) {
		agentID := ""
		if state != nil {
			agentID = state.AgentID
		}
		return &NativeCredentialRecoveryRequiredError{
			AgentID: agentID,
			Cause:   fmt.Errorf("%w: completed state is not a native UDP runtime state", ErrInvalidAgentState),
		}
	}
	return validatePersistedNativeDeviceCredential(state, errKind)
}

func isNativeAgentRuntimeState(state *AgentState) bool {
	return state != nil && (state.Assignment != nil || state.PendingActivation != nil || state.PendingCompletion != nil || state.DeviceAPIKeyID != "")
}

// NativeCredentialRecoveryRequiredError reports a missing or malformed native
// device id-and-secret pair. No HTTP recovery API exists.
type NativeCredentialRecoveryRequiredError struct {
	AgentID string
	Cause   error
}

func (e *NativeCredentialRecoveryRequiredError) Error() string {
	agentID := ""
	if e != nil {
		agentID = e.AgentID
	}
	message := fmt.Sprintf("qurl: native device credential for agent %q is missing or malformed; explicit NHP-native recovery or reprovisioning is required before reopening this runtime, and this SDK version does not yet provide that operation", agentID)
	if e == nil {
		return message
	}
	return messageWithCause(message, e.Cause)
}

func (e *NativeCredentialRecoveryRequiredError) Unwrap() []error {
	if e == nil {
		return []error{ErrCredentialRecoveryRequired, ErrDeviceCredentialMissing}
	}
	return unwrapWithCause(e.Cause, ErrCredentialRecoveryRequired, ErrDeviceCredentialMissing)
}

const (
	apiKeyIDPrefix       = "key_"
	apiKeyIDRandomLength = 12
	apiKeyIDLength       = len(apiKeyIDPrefix) + apiKeyIDRandomLength
)

func validateAPIKeyID(value, label string, errKind error) error {
	if !validAPIKeyID(value) {
		return fmt.Errorf("%w: %s must match %s plus %d alphanumeric characters", errKind, label, apiKeyIDPrefix, apiKeyIDRandomLength)
	}
	return nil
}

func validAPIKeyID(value string) bool {
	if len(value) != apiKeyIDLength || !strings.HasPrefix(value, apiKeyIDPrefix) {
		return false
	}
	for i := len(apiKeyIDPrefix); i < len(value); i++ {
		ch := value[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

func unwrapWithCause(cause error, sentinels ...error) []error {
	if cause == nil {
		return sentinels
	}
	return append(sentinels, cause)
}

// recoveryBudgetErrorString keeps the three phase-specific public recovery
// types source-compatible while centralizing their identical message shape.
func recoveryBudgetErrorString(scope, guidance string, attempts int, elapsed time.Duration, last error) string {
	return fmt.Sprintf("qurl: %s retry budget exhausted after %d attempts over %s; %s: %v", scope, attempts, elapsed, guidance, last)
}

func messageWithCause(message string, cause error) string {
	if cause != nil {
		return fmt.Sprintf("%s: %v", message, cause)
	}
	return message
}

// ErrRegistrationInvalidInput and ErrRegistrationDisabled classify assigned-
// cell registration denials.
var (
	ErrRegistrationInvalidInput = errors.New("qurl: registration input invalid")
	ErrRegistrationDisabled     = errors.New("qurl: agent registration disabled")
)

// ErrRegisterReplyMalformed means an authenticated native registration reply
// violated the strict request/reply contract.
var ErrRegisterReplyMalformed = errors.New("qurl: registration reply malformed")
