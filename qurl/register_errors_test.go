package qurl

import (
	"errors"
	"strings"
	"testing"
)

// The message an operator actually sees must name the fix. Both shapes below
// were hit while onboarding against a live deployment: the answer existed only
// in the package doc, which is exactly where an operator staring at a terminal
// will not look.
func TestRegistrationKeyKindDisallowedError_NamesTheRemedy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    RegistrationKeyKind
		allowed []RegistrationKeyKind
		want    []string
	}{
		{
			name:    "pre-issued credential under the default OTP policy",
			kind:    RegistrationKeyKindAgent,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
			want:    []string{"WithAgentRuntimeAllowedRegistrationKeyKinds", "WithAgentRuntimeHeadlessEnrollment", "qurl:agent scope"},
		},
		{
			name:    "bootstrap credential under the default OTP policy",
			kind:    RegistrationKeyKindBootstrap,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
			want:    []string{"WithAgentRuntimeAllowedRegistrationKeyKinds", "WithAgentRuntimeHeadlessEnrollment"},
		},
		{
			name:    "account credential under an explicitly headless policy",
			kind:    RegistrationKeyKindAccount,
			allowed: []RegistrationKeyKind{RegistrationKeyKindBootstrap, RegistrationKeyKindAgent},
			want:    []string{"WithAgentRuntimeOTPProvider"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &RegistrationKeyKindDisallowedError{Kind: tc.kind, Allowed: tc.allowed}
			got := err.Error()
			// The original diagnostic is preserved, not replaced.
			if !strings.Contains(got, string(tc.kind)) {
				t.Fatalf("error dropped the rejected kind: %q", got)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("error does not name %q: %q", want, got)
				}
			}
			if !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
				t.Fatal("sentinel must still match")
			}
		})
	}
}

// No speculative advice when the shape is not one we recognise.
func TestRegistrationKeyKindDisallowedError_SilentWhenUnrecognised(t *testing.T) {
	err := &RegistrationKeyKindDisallowedError{
		Kind:    RegistrationKeyKindAccount,
		Allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
	}
	if strings.Contains(err.Error(), "(") {
		t.Fatalf("unexpected remedy appended: %q", err.Error())
	}
}
