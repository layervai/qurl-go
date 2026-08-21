package qv2

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestTransportFragment_VerifiedRoundTripPreservesSignedBytes(t *testing.T) {
	signer := newTestSigner(t)
	claimsB64, rawSig := signer.signClaims(t, baselineClaims(t))
	canonical, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}

	transport, err := EncodeTransportFragment(canonical)
	if err != nil {
		t.Fatalf("EncodeTransportFragment: %v", err)
	}
	if !strings.HasPrefix(transport, TransportPrefix+".") {
		t.Fatalf("transport prefix = %q, want %q", transport[:len(TransportPrefix)], TransportPrefix)
	}
	for _, part := range strings.Split(transport, ".")[4:] {
		if len(part) == 0 || len(part) > transportChunkLength {
			t.Fatalf("emitted chunk length = %d, want 1..%d", len(part), transportChunkLength)
		}
	}

	decoded, err := DecodeTransportFragment(transport)
	if err != nil {
		t.Fatalf("DecodeTransportFragment: %v", err)
	}
	if decoded != canonical {
		t.Fatal("transport round trip changed canonical qv2 bytes")
	}

	frag, err := FragmentFromLinkAndVerify("https://qurl.link/portal?source=test#"+transport, signer.trustStore(t))
	if err != nil {
		t.Fatalf("FragmentFromLinkAndVerify: %v", err)
	}
	if frag.ClaimsB64 != claimsB64 {
		t.Fatal("verified fragment did not preserve the exact signed claims bytes")
	}

	reencoded, err := EncodeTransportFragment(decoded)
	if err != nil {
		t.Fatalf("re-encode decoded fragment: %v", err)
	}
	if reencoded != transport {
		t.Fatal("transport encoding is not canonical and deterministic")
	}
}

func TestDecodeTransportFragment_AcceptsProtocolLimits(t *testing.T) {
	claims := strings.Repeat("A", transportMaxClaimsLength)
	secret := strings.Repeat("A", transportMaxSecretLength)
	sig := strings.Repeat("A", transportMaxSigLength)
	transport := makeTransportFixture(claims, secret, sig)

	decoded, err := DecodeTransportFragment(transport)
	if err != nil {
		t.Fatalf("DecodeTransportFragment(maximum fields): %v", err)
	}
	want := strings.Join([]string{FragmentPrefix, claims, secret, sig}, ".")
	if decoded != want {
		t.Fatal("maximum-size fields were not reconstructed exactly")
	}
}

func TestDecodeTransportFragment_IsFramingOnly(t *testing.T) {
	decoded, err := DecodeTransportFragment("qv2t1.1.1.1.A.B.C")
	if err != nil {
		t.Fatalf("minimum transport frame: %v", err)
	}
	if decoded != "qv2.A.B.C" {
		t.Fatalf("decoded = %q, want exact presented bytes", decoded)
	}
	if _, err := ParseFragment(decoded); err == nil {
		t.Fatal("invalid inner base64 unexpectedly passed the downstream qv2 parser")
	}
}

func TestDecodeTransportFragment_RejectsMalformedEnvelope(t *testing.T) {
	chunk := strings.Repeat("A", transportChunkLength)
	shortChunk := strings.Repeat("A", transportChunkLength-4)
	valid := "qv2t1.1.1.1.AQ.AQ.AQ"

	tests := map[string]string{
		"unknown prefix":             "qv2t2.1.1.1.AQ.AQ.AQ",
		"legacy qv2":                 "qv2.AQ.AQ.AQ",
		"leading hash":               "#qv2t1.1.1.1.AQ.AQ.AQ",
		"zero count":                 "qv2t1.0.1.1.AQ.AQ.AQ",
		"leading-zero count":         "qv2t1.01.1.1.AQ.AQ.AQ",
		"signed count":               "qv2t1.+1.1.1.AQ.AQ.AQ",
		"non-decimal count":          "qv2t1.1x.1.1.AQ.AQ.AQ",
		"claims count above cap":     "qv2t1.27.1.1.AQ.AQ.AQ",
		"secret count above cap":     "qv2t1.1.4.1.AQ.AQ.AQ",
		"signature count above cap":  "qv2t1.1.1.2.AQ.AQ.AQ",
		"missing declared part":      "qv2t1.1.1.1.AQ.AQ",
		"extra undeclared part":      valid + ".AQ",
		"empty chunk":                "qv2t1.1.1.1..AQ.AQ",
		"non-final chunk too short":  "qv2t1.2.1.1." + shortChunk + ".AAAA.AQ.AQ",
		"chunk above 240 characters": "qv2t1.1.1.1." + chunk + "A.AQ.AQ",
		"non-base64url character":    "qv2t1.1.1.1.A=.AQ.AQ",
		"claims field above cap":     "qv2t1.26.1.1." + strings.Join(repeatedChunks(chunk, 26), ".") + ".AQ.AQ",
		"secret field above cap":     "qv2t1.1.3.1.AQ." + strings.Join(repeatedChunks(chunk, 3), ".") + ".AQ",
		"signature field above cap":  "qv2t1.1.1.1.AQ.AQ." + strings.Repeat("A", transportMaxSigLength+4),
		"total length above cap":     strings.Repeat(".", transportFragmentMaxLength+1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeTransportFragment(input)
			if !errors.Is(err, ErrFragment) {
				t.Fatalf("DecodeTransportFragment: want ErrFragment, got %v", err)
			}
		})
	}
}

func TestDecodeTransportFragment_ErrorsDoNotExposeCredentialParts(t *testing.T) {
	const secretMarker = "SUPERSECRETMARKER"
	_, err := DecodeTransportFragment("qv2t1.1.1.1.AQ." + secretMarker + ".AQ.extra")
	if !errors.Is(err, ErrFragment) {
		t.Fatalf("want ErrFragment, got %v", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("transport error exposed a credential part: %v", err)
	}
}

func TestEncodeTransportFragment_RejectsNonCanonicalOrOversizedInput(t *testing.T) {
	tests := map[string]string{
		"leading hash":        "#qv2.AQ.AQ.AQ",
		"wrong prefix":        "qv3.AQ.AQ.AQ",
		"extra part":          "qv2.AQ.AQ.AQ.AQ",
		"non-canonical field": "qv2.A.AQ.AQ",
		"claims above cap":    "qv2." + strings.Repeat("A", transportMaxClaimsLength+4) + ".AQ.AQ",
		"secret above cap":    "qv2.AQ." + strings.Repeat("A", transportMaxSecretLength+4) + ".AQ",
		"signature above cap": "qv2.AQ.AQ." + strings.Repeat("A", transportMaxSigLength+4),
		"total above cap":     strings.Repeat("A", canonicalFragmentMaxLength+1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeTransportFragment(input); !errors.Is(err, ErrFragment) {
				t.Fatalf("EncodeTransportFragment: want ErrFragment, got %v", err)
			}
		})
	}
}

func TestIsCredentialLink_ClassifiesWithoutTreatingShapeAsVerification(t *testing.T) {
	tests := map[string]struct {
		link string
		want bool
	}{
		"valid-looking":              {"https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ", true},
		"malformed but declared":     {"https://qurl.link/portal#qv2t1.not-valid", true},
		"oversized but declared":     {"https://qurl.link/#qv2t1." + strings.Repeat("A", transportFragmentMaxLength+1), true},
		"custom scheme fails closed": {"custom://open#qv2t1.not-valid", true},
		"legacy transport":           {"https://qurl.link/#qv2.AQ.AQ.AQ", false},
		"bare prefix":                {"https://qurl.link/#qv2t1", false},
		"prefix in query":            {"https://qurl.link/?fragment=qv2t1.1.1.1", false},
		"encoded separator":          {"https://qurl.link/#qv2t1%2E1%2E1%2E1", false},
		"ordinary anchor":            {"https://example.com/docs#qv2-transport", false},
		"invalid URL":                {"\x00https://qurl.link/#qv2t1.x", false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsCredentialLink(test.link); got != test.want {
				t.Fatalf("IsCredentialLink(%q) = %v, want %v", test.link, got, test.want)
			}
		})
	}
}

func FuzzDecodeTransportFragment(f *testing.F) {
	f.Add("qv2t1.1.1.1.AQ.AQ.AQ")
	f.Add("qv2t1.2.1.1." + strings.Repeat("A", transportChunkLength) + ".AQ.AQ.AQ")
	f.Add("qv2.legacy.secret.signature")
	f.Add(strings.Repeat(".", transportFragmentMaxLength+1))
	for _, seed := range transportSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		canonical, err := DecodeTransportFragment(input)
		if err != nil {
			return
		}
		reencoded, err := EncodeTransportFragment(canonical)
		if err != nil {
			// Decode is intentionally framing-only. The unchanged inner parser
			// rejects alphabet-only fields that are not canonical base64url.
			return
		}
		if reencoded != input {
			t.Fatal("accepted a non-canonical transport representation")
		}
	})
}

func makeTransportFixture(claims, secret, sig string) string {
	fields := []string{claims, secret, sig}
	parts := []string{TransportPrefix}
	for _, field := range fields {
		parts = append(parts, decimalChunkCount(field))
	}
	for _, field := range fields {
		for start := 0; start < len(field); start += transportChunkLength {
			end := min(start+transportChunkLength, len(field))
			parts = append(parts, field[start:end])
		}
	}
	return strings.Join(parts, ".")
}

func decimalChunkCount(field string) string {
	return strconv.Itoa(chunkCount(len(field)))
}

func repeatedChunks(chunk string, count int) []string {
	chunks := make([]string, count)
	for i := range chunks {
		chunks[i] = chunk
	}
	return chunks
}
