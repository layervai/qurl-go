package qurl_test

import (
	"fmt"

	"github.com/layervai/qurl-go/qurl"
)

// Build the claim from the consumer's delivered email and retained admission
// leaf. Replace these placeholders; never send the email code to the publisher.
func ExampleConsumerEnrollmentOperation_emailClaim() {
	claim := qurl.ConsumerEnrollmentOperation{
		Action:              "email_verify",
		EnrollmentReference: "reference-from-the-consumers-email",
		VerificationCode:    "12345678",
		AdmissionPublicKey:  "base64-public-key-of-the-retained-admission-leaf",
	}
	// Send with ConsumerEnrollmentClient.Exchange. It first requires the
	// authenticated email_access_supported capability. The reply is metadata,
	// not access: MintAdmission still checks issuer, CRID, and the same leaf.
	fmt.Println(claim)
	// Output: qurl.ConsumerEnrollmentOperation{[REDACTED]}
}
