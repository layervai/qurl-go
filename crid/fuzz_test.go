package crid

import (
	"errors"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

// A CRID is attacker-controlled input: it arrives in API responses, CLI
// arguments, and pasted identifiers. This fuzz target asserts the two
// invariants that matter for such a parser:
//
//  1. It never panics, and every rejection maps to exactly one of the five
//     public sentinels — the reject vocabulary is closed by contract, so an
//     unmapped error is a bug, not a new class.
//  2. Its canonicality holds: a value is accepted ONLY if it is the unique
//     canonical encoding of its bytes, so re-encoding the parsed fields
//     reproduces the exact input and a re-parse is a fixed point.
//
// Live fuzzing runs as the nightly soak (fuzz.yml); the seeds below replay
// deterministically in the normal test job. Run locally with e.g.
// `go test -run=^$ -fuzz=FuzzParse -fuzztime=30s ./crid`.

// cridSeeds pulls every value out of the conformance artifact so the corpus
// starts from real accept/reject wire shapes rather than only hand-written
// guesses.
func cridSeeds(tb testing.TB) []string {
	tb.Helper()
	cf, err := conformance.CRIDV1()
	if err != nil {
		tb.Fatalf("load conformance seeds: %v", err)
	}
	var seeds []string
	for _, c := range cf.ProducerCases {
		seeds = append(seeds, c.ExpectedCRID)
	}
	for _, c := range cf.ConsumerValueCases {
		seeds = append(seeds, c.Value)
	}
	for _, c := range cf.VersionCases {
		seeds = append(seeds, c.Value)
	}
	for _, c := range cf.KeyMatchCases {
		seeds = append(seeds, c.CRID)
	}
	return seeds
}

func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add(strings.Repeat("a", truncatedLength))
	f.Add(strings.Repeat("a", fullLength))
	f.Add(strings.Repeat("7", fullLength))
	f.Add("A" + strings.Repeat("a", fullLength-1)) // uppercase: charset, never folded
	f.Add(" " + strings.Repeat("a", fullLength-1)) // whitespace: charset, never trimmed
	f.Add(strings.Repeat("a", fullLength-1) + "\n")
	for _, s := range cridSeeds(f) {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse(s)
		if verr := Validate(s); (err == nil) != (verr == nil) {
			t.Fatalf("Parse (%v) and Validate (%v) disagree for %q", err, verr, s)
		}
		if err != nil {
			if !errors.Is(err, ErrCharset) && !errors.Is(err, ErrLength) &&
				!errors.Is(err, ErrChecksum) && !errors.Is(err, ErrNonCanonical) &&
				!errors.Is(err, ErrForbiddenVersion) {
				t.Fatalf("Parse rejected %q with an error outside the closed vocabulary: %v", s, err)
			}
			return
		}
		// Accepted ⇒ shape holds: the cheap predicate must never be narrower
		// than the full gate.
		if !MatchesShape(s) {
			t.Fatalf("accepted value fails MatchesShape: %q", s)
		}
		// Accepted ⇒ canonical re-encode equality, proven independently: the
		// input must be exactly the encoding of the parsed version and digest
		// with a freshly recomputed checksum. This is what keeps a
		// non-canonical spelling of a committed identifier from being
		// silently normalized into the canonical one.
		if got := reencode(c.Version(), c.digest); got != s {
			t.Fatalf("accepted non-canonical %q (canonical form is %q)", s, got)
		}
		if c.String() != s {
			t.Fatalf("String() = %q, want the verbatim input %q", c.String(), s)
		}
		// Re-parse is a fixed point over every reported field.
		again, err := Parse(c.String())
		if err != nil {
			t.Fatalf("re-parse of accepted value failed: %v", err)
		}
		if again.Version() != c.Version() || again.Known() != c.Known() ||
			again.Environment() != c.Environment() || again.DigestLength() != c.DigestLength() {
			t.Fatalf("re-parse not a fixed point for %q", s)
		}
	})
}
