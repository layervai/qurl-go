package qurl

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The message an operator actually sees must name the fix. Shapes of this
// refusal were hit while onboarding against a live deployment: the answer
// existed only in the package doc, which is exactly where an operator staring
// at a terminal will not look. The retired agent kind gets its own remedy on
// every path, because the fix (mint a one-shot enrollment token) is not
// discoverable from the accepted-kinds list alone.
func TestRegistrationKeyKindDisallowedError_NamesTheRemedy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    RegistrationKeyKind
		allowed []RegistrationKeyKind
		want    []string
	}{
		{
			name:    "one-shot token under the default OTP policy",
			kind:    RegistrationKeyKindConnectorBootstrap,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
			want:    []string{"one-shot", "WithAgentRuntimeHeadlessEnrollment"},
		},
		{
			name:    "bootstrap token under the default OTP policy",
			kind:    RegistrationKeyKindBootstrap,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
			want:    []string{"one-shot", "WithAgentRuntimeHeadlessEnrollment"},
		},
		{
			name:    "account credential under an explicitly headless policy",
			kind:    RegistrationKeyKindAccount,
			allowed: []RegistrationKeyKind{RegistrationKeyKindBootstrap, RegistrationKeyKindConnectorBootstrap},
			want:    []string{"one-time code", "drop WithAgentRuntimeHeadlessEnrollment", "WithAgentRuntimeOTPProvider"},
		},
		{
			name:    "retired agent kind under the default OTP policy",
			kind:    RegistrationKeyKindAgent,
			allowed: []RegistrationKeyKind{RegistrationKeyKindAccount},
			want:    []string{"no longer enroll", "agent_bootstrap", "WithAgentRuntimeHeadlessEnrollment"},
		},
		{
			name:    "retired agent kind under a headless policy",
			kind:    RegistrationKeyKindAgent,
			allowed: []RegistrationKeyKind{RegistrationKeyKindBootstrap, RegistrationKeyKindConnectorBootstrap},
			want:    []string{"no longer enroll", "agent_bootstrap", "WithAgentRuntimeHeadlessEnrollment"},
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
// The model: a durable API key (wire kind account) enrolls with an emailed
// one-time code on the default path; a one-shot enrollment token (bootstrap,
// connector_bootstrap) is its own proof and enrolls headlessly; and the
// durable agent kind is retired — the platform no longer mints keys that
// classify as it, so NO path admits it by default, while its wire token stays
// reserved so retirement is reversible without a protocol change. A table
// that fails loudly when a cell changes is the fence.
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
				// The durable API key: it can answer an emailed code.
				RegistrationKeyKindAccount: true,
				// Retired: no longer minted, admitted by no default path.
				RegistrationKeyKindAgent: false,
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
				// This runtime just said it cannot answer a code, so a
				// credential that REQUIRES one is refused.
				RegistrationKeyKindAccount: false,
				// Retired here too: headless admits only the one-shot kinds.
				RegistrationKeyKindAgent:              false,
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
						// The retired kind must be refused with the retirement
						// remedy on every path, not a generic policy message.
						if kind == RegistrationKeyKindAgent && !strings.Contains(err.Error(), "no longer enroll") {
							t.Fatalf("agent refusal lacks the retirement remedy: %q", err.Error())
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
