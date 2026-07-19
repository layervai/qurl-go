package qurl

import (
	"errors"
	"fmt"
	"time"
)

// AgentRegistrationRecoveryHorizon is the maximum supported age of one
// persisted native-UDP registration transaction. The horizon is anchored to
// the authenticated Hub assignment-ticket expiry, not to a caller or local
// process timestamp, and is copied unchanged from pending activation into
// pending completion.
//
// A caller may begin an exact recovery only while its persisted deadline is
// live. The authority retains replay evidence beyond this horizon for bounded
// in-flight and cleanup grace; that server-side grace does not extend the SDK
// guarantee.
const AgentRegistrationRecoveryHorizon = 90 * 24 * time.Hour

// AgentRecoveryPhase identifies which durable registration transition requires
// operator recovery. Its closed values are safe to use in low-cardinality
// metrics.
type AgentRecoveryPhase string

const (
	// AgentRecoveryPhaseActivation identifies a persisted assigned-cell REG.
	AgentRecoveryPhaseActivation AgentRecoveryPhase = "activation"
	// AgentRecoveryPhaseCompletion identifies a persisted device-key completion.
	AgentRecoveryPhaseCompletion AgentRecoveryPhase = "completion"
)

var (
	// ErrAgentRecoveryExpired reports that a durable pending transaction is
	// outside the released SDK recovery guarantee. The state is preserved and no
	// recovery packet is sent.
	ErrAgentRecoveryExpired = errors.New("qurl: agent registration recovery horizon expired")
	// ErrAgentRecoveryMigrationRequired reports legacy pending state that cannot
	// be assigned a finite authority-time deadline without inventing history.
	// The state is preserved and no recovery packet is sent.
	ErrAgentRecoveryMigrationRequired = errors.New("qurl: agent registration recovery migration required")
)

// AgentRecoveryExpiredError carries the non-secret phase and absolute recovery
// deadline for an expired pending transaction.
type AgentRecoveryExpiredError struct {
	Phase             AgentRecoveryPhase
	RecoveryExpiresAt time.Time
}

func (e *AgentRecoveryExpiredError) Error() string {
	if e == nil {
		return ErrAgentRecoveryExpired.Error()
	}
	return fmt.Sprintf("%s: %s recovery expired at %s; persisted state was preserved, so use explicit NHP-native credential recovery or reprovisioning",
		ErrAgentRecoveryExpired, e.Phase, e.RecoveryExpiresAt.UTC().Format(time.RFC3339))
}

func (e *AgentRecoveryExpiredError) Unwrap() error {
	return ErrAgentRecoveryExpired
}

// AgentRecoveryMigrationRequiredError reports a legacy pending transition for
// which the finite recovery deadline cannot be reconstructed. SchemaVersion is
// non-secret state metadata and is included to make operator diagnostics
// actionable without exposing agent or credential identity.
type AgentRecoveryMigrationRequiredError struct {
	Phase         AgentRecoveryPhase
	SchemaVersion int
}

func (e *AgentRecoveryMigrationRequiredError) Error() string {
	if e == nil {
		return ErrAgentRecoveryMigrationRequired.Error()
	}
	return fmt.Sprintf("%s: legacy %s state at schema version %d has no authenticated recovery anchor; preserve it and use explicit NHP-native credential recovery or reprovisioning",
		ErrAgentRecoveryMigrationRequired, e.Phase, e.SchemaVersion)
}

func (e *AgentRecoveryMigrationRequiredError) Unwrap() error {
	return ErrAgentRecoveryMigrationRequired
}

func agentRecoveryDeadline(anchor time.Time) (time.Time, error) {
	if anchor.IsZero() {
		return time.Time{}, fmt.Errorf("%w: recovery anchor is missing", ErrInvalidAgentState)
	}
	deadline := anchor.UTC().Add(AgentRegistrationRecoveryHorizon)
	if !deadline.After(anchor) || deadline.Year() > 9999 {
		return time.Time{}, fmt.Errorf("%w: recovery deadline is out of range", ErrInvalidAgentState)
	}
	return deadline, nil
}

func pendingRecoveryDeadline(state *AgentState) (AgentRecoveryPhase, time.Time, bool) {
	if state == nil {
		return "", time.Time{}, false
	}
	if state.PendingActivation != nil {
		return AgentRecoveryPhaseActivation, state.PendingActivation.RecoveryExpiresAt, true
	}
	if state.PendingCompletion != nil {
		return AgentRecoveryPhaseCompletion, state.PendingCompletion.RecoveryExpiresAt, true
	}
	return "", time.Time{}, false
}

func legacyPendingActivationDeadlineAllowed(state *AgentState, deadline time.Time) bool {
	return deadline.IsZero() && state != nil && state.SchemaVersion < agentStateSchemaVersion
}

func validatePendingActivationRecoveryDeadline(pending *PendingAgentActivation, state *AgentState) error {
	if pending == nil {
		return fmt.Errorf("%w: pending activation is nil", ErrInvalidAgentState)
	}
	if legacyPendingActivationDeadlineAllowed(state, pending.RecoveryExpiresAt) {
		return nil
	}
	expected, err := agentRecoveryDeadline(pending.AssignmentTicketExpiresAt)
	if err != nil || pending.RecoveryExpiresAt.IsZero() || pending.RecoveryExpiresAt.Nanosecond() != 0 ||
		!pending.RecoveryExpiresAt.Equal(expected) {
		return fmt.Errorf("%w: pending activation recovery deadline is invalid", ErrInvalidAgentState)
	}
	return nil
}

func validatePendingCompletionRecoveryDeadline(pending *PendingAgentCompletion, state *AgentState) error {
	if pending == nil || state == nil || state.Assignment == nil {
		return fmt.Errorf("%w: pending completion recovery deadline requires an assignment", ErrInvalidAgentState)
	}
	if state.SchemaVersion < agentStateSchemaVersion && pending.AssignmentTicketExpiresAt.IsZero() && pending.RecoveryExpiresAt.IsZero() {
		return nil
	}
	expected, err := agentRecoveryDeadline(pending.AssignmentTicketExpiresAt)
	if err != nil || pending.RecoveryExpiresAt.IsZero() || pending.RecoveryExpiresAt.Nanosecond() != 0 ||
		!pending.RecoveryExpiresAt.Equal(expected) ||
		!state.Assignment.LeaseExpiresAt.After(pending.AssignmentTicketExpiresAt) {
		return fmt.Errorf("%w: pending completion recovery deadline is invalid", ErrInvalidAgentState)
	}
	return nil
}
