// Package agentstatecontract holds wire-neutral AgentState constants shared by
// the root SDK and in-repository storage modules. It is internal so these
// persistence details do not become public SDK API.
package agentstatecontract

// PendingActivationEnrollmentCredentialFingerprintDomain separates the
// durable enrollment-credential equality tag from every other SHA-256 use.
// It is exported only within this internal package's repository boundary.
//
//nolint:gosec // Domain separator, not a credential.
const PendingActivationEnrollmentCredentialFingerprintDomain = "qurl-go/pending-activation-enrollment-credential-v1\x00"

// PendingCredentialRecoveryCredentialFingerprintDomain separates the durable
// equality tag used to replay one IssueCredentialRecovery logical operation.
// The raw recovery credential must never enter AgentState.
const PendingCredentialRecoveryCredentialFingerprintDomain = "qurl-go/pending-credential-recovery-credential-v1\x00" //nolint:gosec // Domain separator, not a credential.
