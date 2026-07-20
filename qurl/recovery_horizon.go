package qurl

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/layervai/qurl-go/internal/udpfence"
)

// AgentRegistrationRecoveryHorizon is the maximum supported age of one
// persisted native-UDP registration transaction. The horizon is anchored to
// the first authenticated Hub assignment-ticket expiry in the recovery episode,
// not to a caller or local process timestamp, and is copied unchanged through
// replacement activation and pending completion.
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
	// outside the released SDK recovery guarantee. No recovery datagram is sent
	// at or after the deadline. A call that crossed the boundary may already have
	// sent earlier datagrams or committed a state transition, so persistence
	// errors retain their mandatory reload-first classification.
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

// agentRecoveryBoundary binds one loaded pending phase to its immutable
// absolute deadline. Its context timer stops blocked DNS/socket/backoff work,
// while its internal UDP fence rechecks the injected lifecycle clock at the
// closest reliable point before every datagram write.
type agentRecoveryBoundary struct {
	phase    AgentRecoveryPhase
	deadline time.Time
	clock    func() time.Time
	expired  atomic.Bool
}

func newAgentRecoveryBoundary(state *AgentState, clock func() time.Time) (*agentRecoveryBoundary, error) {
	phase, deadline, pending := pendingRecoveryDeadline(state)
	if !pending {
		return nil, fmt.Errorf("%w: recovery boundary requires pending state", ErrInvalidAgentState)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: recovery clock is nil", ErrInvalidRegisterConfig)
	}
	boundary := &agentRecoveryBoundary{phase: phase, deadline: deadline, clock: clock}
	if err := boundary.check(); err != nil {
		return nil, err
	}
	return boundary, nil
}

// boundedRecovery constructs the pending recovery boundary and its bounded,
// UDP-fenced context as one operation. On success the caller must cancel the
// returned context; on error there is nothing to clean up.
func boundedRecovery(ctx context.Context, state *AgentState, clock func() time.Time) (*agentRecoveryBoundary, context.Context, context.CancelFunc, error) {
	boundary, err := newAgentRecoveryBoundary(state, clock)
	if err != nil {
		return nil, nil, nil, err
	}
	recoveryCtx, cancel, err := boundary.context(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return boundary, recoveryCtx, cancel, nil
}

func (b *agentRecoveryBoundary) expiredError() error {
	return &AgentRecoveryExpiredError{Phase: b.phase, RecoveryExpiresAt: b.deadline}
}

func (b *agentRecoveryBoundary) check() error {
	if b == nil || b.deadline.IsZero() {
		return fmt.Errorf("%w: recovery boundary is missing", ErrInvalidAgentState)
	}
	return b.checkAt(b.clock().UTC())
}

func (b *agentRecoveryBoundary) checkAt(now time.Time) error {
	if b.expired.Load() {
		return b.expiredError()
	}
	if now.IsZero() {
		return fmt.Errorf("%w: recovery clock returned zero", ErrInvalidRegisterConfig)
	}
	if !now.Before(b.deadline) {
		b.expired.Store(true)
		return b.expiredError()
	}
	return nil
}

func (b *agentRecoveryBoundary) context(ctx context.Context) (context.Context, context.CancelFunc, error) {
	now := b.clock().UTC()
	if err := b.checkAt(now); err != nil {
		return nil, nil, err
	}
	remaining := b.deadline.Sub(now)
	// remaining uses the injected clock while WithTimeout uses real monotonic
	// time; the UDP fence remains the authoritative per-write deadline check.
	bounded, cancel := context.WithTimeout(ctx, remaining)
	return udpfence.With(bounded, b.check), cancel, nil
}

// mapError requires the non-nil parent and bounded contexts used for the
// attempted operation; callers invoke it only after boundedRecovery succeeds.
func (b *agentRecoveryBoundary) mapError(parent, bounded context.Context, err error) error {
	if err == nil || errors.Is(err, ErrAgentRecoveryExpired) {
		return err
	}
	// A save may commit before returning an acknowledgement failure. Deadline or
	// caller cancellation observed concurrently cannot prove which durable state
	// won, so never replace either reload-first persistence classification with a
	// timing error.
	if errors.Is(err, ErrAgentBindingPersistence) || errors.Is(err, ErrAgentCompletionCandidatePersistence) {
		return err
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	if bounded.Err() != nil {
		return b.expiredError()
	}
	return err
}

func validatePendingActivationRecoveryDeadline(pending *PendingAgentActivation, state *AgentState) error {
	if pending == nil || state == nil {
		return fmt.Errorf("%w: pending activation is nil", ErrInvalidAgentState)
	}
	return validateRecoveryDeadlineFields(
		pending.RecoveryAnchorTicketExpiresAt,
		pending.RecoveryExpiresAt,
		state.SchemaVersion,
		AgentRecoveryPhaseActivation,
	)
}

func validatePendingCompletionRecoveryDeadline(pending *PendingAgentCompletion, state *AgentState) error {
	if pending == nil || state == nil || state.Assignment == nil {
		return fmt.Errorf("%w: pending completion recovery deadline requires an assignment", ErrInvalidAgentState)
	}
	return validateRecoveryDeadlineFields(
		pending.RecoveryAnchorTicketExpiresAt,
		pending.RecoveryExpiresAt,
		state.SchemaVersion,
		AgentRecoveryPhaseCompletion,
	)
}

func validateRecoveryDeadlineFields(anchor, deadline time.Time, schemaVersion int, phase AgentRecoveryPhase) error {
	if schemaVersion < registrationRecoveryStateSchemaVersion {
		if !anchor.IsZero() || !deadline.IsZero() {
			return fmt.Errorf("%w: legacy pending %s contains forward recovery fields", ErrInvalidAgentState, phase)
		}
		return nil
	}
	expected, err := agentRecoveryDeadline(anchor)
	if err != nil || anchor.Nanosecond() != 0 ||
		deadline.IsZero() || deadline.Nanosecond() != 0 ||
		!deadline.Equal(expected) {
		return fmt.Errorf("%w: pending %s recovery deadline is invalid", ErrInvalidAgentState, phase)
	}
	return nil
}
