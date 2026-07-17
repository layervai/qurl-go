// Package agentstatecontract holds wire-neutral AgentState constants shared by
// the root SDK and in-repository storage modules. It is internal so these
// persistence details do not become public SDK API.
package agentstatecontract

// PendingActivationEnrollmentCredentialFingerprintDomain separates the
// durable enrollment-credential equality tag from every other SHA-256 use.
// It is exported only within this internal package's repository boundary.
const PendingActivationEnrollmentCredentialFingerprintDomain = fingerprintDomainV1

const fingerprintDomainV1 = "qurl-go/pending-activation-enrollment-credential-v1\x00"
