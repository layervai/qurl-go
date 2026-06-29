package qv2

import (
	"strings"
	"testing"
)

// TestFragmentEncodingMalleability is the end-to-end regression for a bug found
// by FuzzDecodeB64Canonical: Go's base64 decoder silently skips embedded '\r'/'\n'
// even in Strict mode, so whitespace injected into a base64url part used to decode
// to the same bytes. Because the issuer signature is over the EXACT received
// claims string, tampering the claims part was already caught — but the signature
// and secret parts decode through the same path, so a newline injected there
// produced a DISTINCT fragment string that still verified. That breaks the
// documented "exactly one string per byte slice" guarantee and makes the fragment
// malleable for any consumer that keys/dedupes/revokes on the link string.
//
// Every part must now reject embedded whitespace; no tampered variant may verify.
func TestFragmentEncodingMalleability(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	ts := signer.trustStore(t)

	if _, err := ParseAndVerify(body, ts); err != nil {
		t.Fatalf("clean minted fragment must verify: %v", err)
	}

	parts := strings.SplitN(body, ".", 4)
	if len(parts) != fragmentParts {
		t.Fatalf("minted fragment has %d parts, want %d", len(parts), fragmentParts)
	}

	// Whitespace the Go base64 decoder silently skips: LF, CR, and the CRLF pair.
	whitespace := map[string]string{"LF": "\n", "CR": "\r", "CRLF": "\r\n"}
	// Inject at the front, middle, and end of the part to cover offset-dependent
	// decoder behaviour, not just a single fixed position.
	positions := []string{"front", "middle", "end"}

	// parts[0] is the literal "qv2" prefix; tamper each base64url part in turn.
	for i := 1; i < fragmentParts; i++ {
		p := parts[i]
		for wsName, ws := range whitespace {
			for _, pos := range positions {
				var injected string
				switch pos {
				case "front":
					injected = ws + p
				case "middle":
					injected = p[:len(p)/2] + ws + p[len(p)/2:]
				case "end":
					injected = p + ws
				}
				tampered := make([]string, len(parts))
				copy(tampered, parts)
				tampered[i] = injected

				if _, err := ParseAndVerify(strings.Join(tampered, "."), ts); err == nil {
					t.Errorf("part %d: %s-injected (%s) fragment verified; encoding is malleable", i, wsName, pos)
				}
			}
		}
	}
}
