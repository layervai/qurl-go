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
