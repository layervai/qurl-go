package qurl

import (
	"errors"
	"testing"
	"time"
)

type recoveryErrorContract interface {
	error
	Unwrap() []error
}

func TestRecoveryRequiredErrors_NilSafety(t *testing.T) {
	var nilAssignment *AssignmentRecoveryRequiredError
	var nilRegistration *RegistrationRecoveryRequiredError
	var nilCompletion *CompletionRecoveryRequiredError
	tests := []struct {
		name     string
		nilValue recoveryErrorContract
		newValue func(error) recoveryErrorContract
		sentinel error
		want     string
	}{
		{
			name: "assignment", nilValue: nilAssignment,
			newValue: func(last error) recoveryErrorContract {
				return &AssignmentRecoveryRequiredError{Attempts: 1, Elapsed: time.Second, Last: last}
			},
			sentinel: ErrAssignmentRecoveryRequired,
			want:     "qurl: assignment retry budget exhausted after 1 attempts over 1s; surface recovery: last assignment transport failure",
		},
		{
			name: "registration", nilValue: nilRegistration,
			newValue: func(last error) recoveryErrorContract {
				return &RegistrationRecoveryRequiredError{Attempts: 1, Elapsed: time.Second, Last: last}
			},
			sentinel: ErrRegistrationRecoveryRequired,
			want:     "qurl: assigned-cell registration retry budget exhausted after 1 attempts over 1s; resume the exact pending activation with the same enrollment credential: last registration transport failure",
		},
		{
			name: "completion", nilValue: nilCompletion,
			newValue: func(last error) recoveryErrorContract {
				return &CompletionRecoveryRequiredError{Attempts: 1, Elapsed: time.Second, Last: last}
			},
			sentinel: ErrCompletionRecoveryRequired,
			want:     "qurl: completion retry budget exhausted after 1 attempts over 1s; reopen the persisted pending candidate: last completion transport failure",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.nilValue.Error(); got != test.sentinel.Error() || !errors.Is(test.nilValue, test.sentinel) {
				t.Fatalf("nil recovery = %q / %v, want stable sentinel", got, test.nilValue.Unwrap())
			}
			if causes := test.nilValue.Unwrap(); len(causes) != 1 || !errors.Is(causes[0], test.sentinel) {
				t.Fatalf("nil recovery causes = %#v, want sentinel only", causes)
			}
			last := errors.New("last " + test.name + " transport failure")
			recovery := test.newValue(last)
			if got := recovery.Error(); got != test.want {
				t.Fatalf("recovery message = %q, want %q", got, test.want)
			}
			if !errors.Is(recovery, test.sentinel) || !errors.Is(recovery, last) {
				t.Fatalf("recovery lost sentinel or last cause: %v", recovery)
			}
			causes := recovery.Unwrap()
			if len(causes) != 2 || !errors.Is(causes[0], test.sentinel) || !errors.Is(causes[1], last) {
				t.Fatalf("recovery causes = %#v, want sentinel then last cause", causes)
			}
		})
	}
}

// These messages are the operator's instructions: which call to make next, and
// which deadline or placement decided it. A sentinel assertion alone would let
// the text regress to something that names no action at all, so pin the strings.
func TestOperatorGuidanceErrorMessages(t *testing.T) {
	deadline := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	// A non-UTC spelling of the same instant must render as the UTC deadline the
	// authority set, not as whatever zone this process happens to run in.
	localDeadline := deadline.In(time.FixedZone("elsewhere", 3600))
	previous := &AgentAssignment{CellID: "cell0", AssignmentGeneration: 1}
	current := &AgentAssignment{CellID: "cell1", AssignmentGeneration: 2}

	for _, test := range []struct {
		name     string
		err      error
		nilErr   error
		wantNil  string
		sentinel error
		want     string
	}{
		{
			// The only one of these with no fixed sentinel: kind is per-denial, so a
			// nil receiver can only fall back to the generic class name.
			name:     "credential recovery denial",
			err:      &CredentialRecoveryError{Code: "52411", Phase: string(credentialRecoveryCellPhase), kind: ErrCredentialRecoveryGrantRejected},
			nilErr:   (*CredentialRecoveryError)(nil),
			wantNil:  "qurl: credential recovery error",
			sentinel: ErrCredentialRecoveryGrantRejected,
			want:     "qurl: credential recovery assigned_cell_complete_recovery error 52411",
		},
		{
			name:     "credential recovery horizon",
			err:      &CredentialRecoveryExpiredError{RecoveryExpiresAt: localDeadline},
			nilErr:   (*CredentialRecoveryExpiredError)(nil),
			wantNil:  ErrCredentialRecoveryExpired.Error(),
			sentinel: ErrCredentialRecoveryExpired,
			want:     "qurl: credential recovery horizon expired at 2026-10-13T12:00:00Z; persisted candidate was preserved",
		},
		{
			name:     "credential recovered but assignment stale",
			err:      &CredentialRecoveredAssignmentRefreshRequiredError{Cause: errors.New("hub unreachable")},
			sentinel: ErrCredentialRecoveredAssignmentRefreshRequired,
			want:     "qurl: credential recovered; assignment refresh required; call RefreshAgentRuntime before using the runtime",
		},
		{
			name:     "assignment moved under a pin",
			err:      &AgentAssignmentChangedError{Previous: previous, Current: current},
			sentinel: ErrAssignmentReassignmentRequired,
			want:     "qurl: authoritative assignment changed cell or generation; explicit reassignment handling is required",
		},
		{
			name:     "registration recovery horizon",
			err:      &AgentRecoveryExpiredError{Phase: AgentRecoveryPhaseActivation, RecoveryExpiresAt: localDeadline},
			nilErr:   (*AgentRecoveryExpiredError)(nil),
			wantNil:  ErrAgentRecoveryExpired.Error(),
			sentinel: ErrAgentRecoveryExpired,
			want:     "qurl: agent registration recovery horizon expired: activation recovery expired at 2026-10-13T12:00:00Z; persisted state was preserved, so use explicit NHP-native credential recovery or reprovisioning",
		},
		{
			name:     "legacy state has no recovery anchor",
			err:      &AgentRecoveryMigrationRequiredError{Phase: AgentRecoveryPhaseCompletion, SchemaVersion: 5},
			nilErr:   (*AgentRecoveryMigrationRequiredError)(nil),
			wantNil:  ErrAgentRecoveryMigrationRequired.Error(),
			sentinel: ErrAgentRecoveryMigrationRequired,
			want:     "qurl: agent registration recovery migration required: legacy completion state at schema version 5 has no authenticated recovery anchor; preserve it and use explicit NHP-native credential recovery or reprovisioning",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.err.Error(); got != test.want {
				t.Fatalf("message = %q, want %q", got, test.want)
			}
			if !errors.Is(test.err, test.sentinel) {
				t.Fatalf("%v lost its sentinel %v", test.err, test.sentinel)
			}
			if test.nilErr != nil {
				if got := test.nilErr.Error(); got != test.wantNil {
					t.Fatalf("nil receiver message = %q, want %q", got, test.wantNil)
				}
			}
		})
	}
}
