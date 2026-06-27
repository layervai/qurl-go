package qv2

import (
	"errors"
	"testing"
)

// The qv2 package is a strict parser for attacker-controlled input: the fragment
// of a qURL link is fully under the control of whoever sends the link. These fuzz
// targets assert the two invariants that matter for such a parser:
//
//  1. It never panics, no matter how malformed the input — a panic in a parser
//     reached from untrusted input is a denial-of-service bug.
//  2. Its security-critical canonicalization holds: a base64url string is accepted
//     ONLY if it is the unique canonical encoding of its bytes. This is what keeps
//     a signed part from being silently re-normalized (see decodeB64's doc).
//
// Run locally with e.g. `go test -run=^$ -fuzz=FuzzDecodeB64Canonical -fuzztime=30s ./qv2`.

// fragmentSeeds pulls every fragment-class vector out of the vendored conformance
// artifact so the corpus starts from real accept/reject wire shapes rather than
// only hand-written guesses.
func fragmentSeeds(tb testing.TB) []string {
	tb.Helper()
	cf, err := LoadConformanceFile(conformanceFilePath)
	if err != nil {
		tb.Fatalf("load conformance seeds: %v", err)
	}
	var seeds []string
	for _, v := range cf.Classes["fragment"].Vectors {
		if v.Fragment != "" {
			seeds = append(seeds, v.Fragment)
		}
	}
	return seeds
}

// FuzzParseFragment drives the full fragment entry point. The only invariant a
// fuzzer can assert without a signing oracle is total: ParseFragment must return
// — never panic — for any input, and a successful parse must round-trip its
// verbatim parts back through ParseFragment to the same result (idempotence over
// the wire bytes it chose to preserve).
func FuzzParseFragment(f *testing.F) {
	f.Add("qv2.a.b.c")
	f.Add("#qv2...")
	f.Add("")
	f.Add("not-a-fragment")
	for _, s := range fragmentSeeds(f) {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, fragment string) {
		frag, err := ParseFragment(fragment)
		if err != nil {
			return // any rejection is acceptable; we only care that it returned
		}
		// On success the verbatim parts must be present and re-parse identically:
		// the parser promises ClaimsB64/SecretB64/SigB64 are exactly the received
		// bytes, so reassembling and re-parsing them is a fixed point.
		if frag.Claims == nil || frag.Secret == nil {
			t.Fatalf("ParseFragment returned success with nil Claims/Secret for %q", fragment)
		}
		reassembled := FragmentPrefix + "." + frag.ClaimsB64 + "." + frag.SecretB64 + "." + frag.SigB64
		again, err := ParseFragment(reassembled)
		if err != nil {
			t.Fatalf("re-parse of verbatim parts failed: %v (orig %q)", err, fragment)
		}
		if again.ClaimsB64 != frag.ClaimsB64 || again.SecretB64 != frag.SecretB64 || again.SigB64 != frag.SigB64 {
			t.Fatalf("re-parse not idempotent for %q", fragment)
		}
	})
}

// FuzzParseClaims targets the strict JSON claims walker directly with raw bytes.
// It asserts the parser never panics on hostile JSON, and that any accepted claim
// set satisfies the value invariants the parser is responsible for enforcing.
func FuzzParseClaims(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":2}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"v":2,"v":2}`)) // duplicate key
	f.Add([]byte("{\x00}"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := parseClaims(raw)
		if err != nil {
			return
		}
		// A successful parse must have run validateClaimValues; re-running it must
		// agree. This catches any future path that returns a Claims without
		// enforcing the time/range invariants.
		if err := validateClaimValues(c); err != nil {
			t.Fatalf("parseClaims accepted claims that fail validateClaimValues: %v (raw %q)", err, raw)
		}
	})
}

// FuzzDecodeB64Canonical fuzzes the security-critical property of the strict
// base64url decoder: it accepts a string ONLY if that string is the unique
// canonical encoding of the bytes it decodes to. If decode succeeds, re-encoding
// the bytes must reproduce the exact input — otherwise a non-canonical variant of
// a signed value would be silently normalized.
func FuzzDecodeB64Canonical(f *testing.F) {
	f.Add("")
	f.Add("AAAA")
	f.Add("AQID")
	f.Add("_-_-")
	f.Add("A")    // invalid length for raw base64
	f.Add("AAA=") // padding is rejected by the raw decoder
	f.Add("AAB")  // non-canonical trailing bits
	f.Add("\r")   // bare CR: Go's decoder skips it; must be rejected as non-canonical
	f.Add("\n")   // bare LF: same
	f.Add("A\nA") // embedded LF inside otherwise-valid base64

	f.Fuzz(func(t *testing.T, s string) {
		raw, err := decodeB64(s)
		if err != nil {
			if !errors.Is(err, ErrEncoding) {
				t.Fatalf("decodeB64 rejected %q with non-ErrEncoding error: %v", s, err)
			}
			return
		}
		// Assert through encodeB64 — the exact encoding decodeB64's canonical
		// check uses — so the test mirrors the implementation, not a parallel one.
		if got := encodeB64(raw); got != s {
			t.Fatalf("decodeB64 accepted non-canonical %q (canonical form is %q)", s, got)
		}
	})
}
