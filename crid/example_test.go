// Package-level examples for the crid package. Every value is a frozen
// fixture from the public CRID v1 conformance artifact (qurl-crid-v1-vectors
// in github.com/layervai/qurl-conformance) — the same artifact the package's
// always-run conformance test pins itself against — so the outputs are
// deterministic by contract.
package crid_test

import (
	"encoding/base64"
	"fmt"

	"github.com/layervai/qurl-go/crid"
)

// The held identifier and the two delivered keys are the artifact's key-match
// fixtures: committedKeyB64URL is the DER SubjectPublicKeyInfo the CRID
// commits to, and foreignKeyB64URL is a well-formed resource key that is
// simply not the committed one.
const (
	heldCRID = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"

	committedKeyB64URL = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
	foreignKeyB64URL   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpDu9mdM6E96ncBm5qjKn16Rjv6sWoHRQQz2ElwKSg5YQDLCvofuEb7gmId2YBKv3YXcrdc3tmBaiRzYCH9Hp6Q"
)

// ExampleKeyMatches shows the one rule every CRID consumer MUST apply: a
// delivered resource key is used only if it hashes to the CRID already held,
// and on a mismatch the consumer fails closed — no fallback to the delivered
// key, no partial trust.
func ExampleKeyMatches() {
	committed, err := base64.RawURLEncoding.DecodeString(committedKeyB64URL)
	if err != nil {
		panic(err)
	}
	foreign, err := base64.RawURLEncoding.DecodeString(foreignKeyB64URL)
	if err != nil {
		panic(err)
	}

	// The committed key re-derives the held CRID.
	ok, err := crid.KeyMatches(heldCRID, committed)
	if err != nil {
		panic(err) // the error reports a held CRID that fails the local gate
	}
	fmt.Println("committed key matches:", ok)

	// A well-formed key that is not the committed one is the substitution the
	// identifier exists to detect: (false, nil) — do not use the key.
	ok, err = crid.KeyMatches(heldCRID, foreign)
	if err != nil {
		panic(err)
	}
	fmt.Println("foreign key matches:", ok)

	// Output:
	// committed key matches: true
	// foreign key matches: false
}

// ExampleParse parses three artifact fixtures and reports what a program may
// read off a locally valid CRID. The first character is a human aid —
// production full CRIDs start with 'a', test ones with 'q' — while programs
// use Environment, which reports "unknown" for unregistered version bytes
// instead of guessing from the environment bit.
func ExampleParse() {
	for _, value := range []string{
		"ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha", // version 0x01
		"qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq", // version 0x81
		"p44jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743out3lhq", // version 0x7f, unregistered
	} {
		c, err := crid.Parse(value)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%c: %s (known=%t, %d digest bytes)\n",
			value[0], c.Environment(), c.Known(), c.DigestLength())
	}

	// Output:
	// a: production (known=true, 32 digest bytes)
	// q: test (known=true, 32 digest bytes)
	// p: unknown (known=false, 32 digest bytes)
}
