package qurl

import (
	"context"
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
			name:    "one-shot credential under the default OTP policy",
			kind:    RegistrationKeyKindConnectorBootstrap,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount, RegistrationKeyKindAgent},
			want:    []string{"one-shot", "WithAgentRuntimeHeadlessEnrollment"},
		},
		{
			name:    "bootstrap credential under the default OTP policy",
			kind:    RegistrationKeyKindBootstrap,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount, RegistrationKeyKindAgent},
			want:    []string{"one-shot", "WithAgentRuntimeHeadlessEnrollment"},
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

// The enrollment matrix, pinned. Every (credential kind x enrollment path)
// admission decision in one table.
//
// This is the coverage whose absence let a real onboarding trap ship: nothing
// asserted which kinds the DEFAULT policy admits, so narrowing it to account
// alone looked harmless and silently removed the frictionless path from every
// key carrying the qurl:agent scope. A table that fails loudly when a cell
// changes is the fence.
func TestEnrollmentPolicyMatrix(t *testing.T) {
	hub := runtimeTestHub()
	otp := func(context.Context, AgentOTPChallenge) (string, error) { return "12345678", nil }

	paths := []struct {
		name string
		opts []AgentRuntimeRegistrationOption
		// admits reports whether this path accepts the kind.
		admits map[RegistrationKeyKind]bool
	}{
		{
			name: "default (OTP)",
			opts: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeHub(hub), WithAgentRuntimeOTPProvider(otp),
			},
			admits: map[RegistrationKeyKind]bool{
				// Durable credentials owned by an account with an address: both
				// can answer a code, so both enroll frictionlessly.
				RegistrationKeyKindAccount: true,
				RegistrationKeyKindAgent:   true,
				// One-shot kinds: minting IS the authorization.
				RegistrationKeyKindBootstrap:          false,
				RegistrationKeyKindConnectorBootstrap: false,
			},
		},
		{
			name: "headless escape hatch",
			opts: []AgentRuntimeRegistrationOption{
				WithAgentRuntimeHub(hub), WithAgentRuntimeHeadlessEnrollment(),
			},
			admits: map[RegistrationKeyKind]bool{
				// The exact inverse: this runtime just said it cannot answer a
				// code, so a credential that REQUIRES one is refused.
				RegistrationKeyKindAccount:            false,
				RegistrationKeyKindAgent:              true,
				RegistrationKeyKindBootstrap:          true,
				RegistrationKeyKindConnectorBootstrap: true,
			},
		},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			cfg, err := newNativeAgentRuntimeConfig(path.opts)
			if err != nil {
				t.Fatalf("newNativeAgentRuntimeConfig: %v", err)
			}
			for kind, want := range path.admits {
				t.Run(string(kind), func(t *testing.T) {
					err := cfg.requireAllowedRegistrationKeyKind(string(kind))
					if want && err != nil {
						t.Fatalf("%s must admit %q, got %v", path.name, kind, err)
					}
					if !want {
						if err == nil {
							t.Fatalf("%s must refuse %q", path.name, kind)
						}
						if !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
							t.Fatalf("refusal for %q = %v, want the typed sentinel", kind, err)
						}
						// A refusal the operator cannot act on is the bug this
						// whole area kept reproducing.
						if !strings.Contains(err.Error(), "WithAgentRuntime") {
							t.Fatalf("refusal for %q names no remedy: %q", kind, err.Error())
						}
					}
				})
			}
		})
	}
}

// An unknown kind is refused by both paths, and never as "disallowed by policy"
// -- that would imply widening the policy could admit it.
func TestEnrollmentPolicyMatrix_UnknownKindIsNotAPolicyRefusal(t *testing.T) {
	cfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()), WithAgentRuntimeHeadlessEnrollment(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.requireAllowedRegistrationKeyKind("wat")
	if errors.Is(err, ErrRegistrationKeyKindDisallowed) {
		t.Fatalf("unknown kind reported as a policy refusal: %v", err)
	}
	if !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("unknown kind err = %v, want ErrAssignmentInvalidResponse", err)
	}
}
