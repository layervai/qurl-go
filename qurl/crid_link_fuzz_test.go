package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/layervai/qurl-go/relayknock"
)

// The answer to a CRID link request is input from the network. It is
// authenticated, so only the cell can send it, but the client checks exist
// precisely so that a link is not trusted on the cell's word alone. These fuzz
// targets hold the two places that decide what is trusted to properties that
// must be true of ANY input, not only of the inputs somebody thought to write
// down.
//
// Live fuzzing runs in the nightly soak; the seeds below replay in the normal
// test job. Run locally with e.g.
// `go test -run=^$ -fuzz=FuzzInterpretCRIDLinkReply -fuzztime=30s ./qurl`.

// FuzzSplitIssuedCRIDLink checks the textual origin test against an
// independent reader. Whatever the function accepts must be, character for
// character, the origin, an optional "/", "#", and the fragment it returned —
// so there is nowhere in an accepted link for another host, a path, or a query
// to be. And when Go's URL parser can read an accepted link at all, it must
// read the same origin out of it.
func FuzzSplitIssuedCRIDLink(f *testing.F) {
	const origin = "https://qurl.link"
	for _, seed := range []string{
		"https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ",
		"https://qurl.link#qv2t1.1.1.1.AQ.AQ.AQ",
		"https://qurl.link/",
		"https://qurl.link",
		"https://qurl.link.example.com/#f",
		"https://qurl.link:8443/#f",
		"https://qurl.link:443/#f",
		"https://user@qurl.link/#f",
		"https://qurl.link@example.com/#f",
		`https://qurl.link\@example.com/#f`,
		"https://qurl.link%2f@example.com/#f",
		"https://qurl.link/open#f",
		"https://qurl.link/?next=open#f",
		"https://qurl.link?#f",
		"https://qurl.link/#a#b",
		"https://qurl.link/#%zz",
		"http://qurl.link/#f",
		"HTTPS://QURL.LINK/#f",
		"https://qurl.link\t/#f",
		"https://qurl.link。example.com/#f",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, link string) {
		fragment, class := splitIssuedCRIDLink(link, origin)
		switch class {
		case "":
		case CRIDLinkRejectOrigin, CRIDLinkRejectPathOrQuery, CRIDLinkRejectTransport:
			if fragment != "" {
				t.Fatalf("a rejected link returned the fragment %q", fragment)
			}
			return
		default:
			t.Fatalf("splitIssuedCRIDLink returned the class %q, which is not one of its own", class)
		}

		// Accepted: the link is exactly these parts and nothing else.
		if link != origin+"#"+fragment && link != origin+"/#"+fragment {
			t.Fatalf("accepted %q, which is not the origin, an optional slash, and the fragment %q", link, fragment)
		}
		// An independent parse, where one is possible, agrees on every part.
		parsed, err := url.Parse(link)
		if err != nil {
			return // e.g. a fragment with a malformed escape; the transport decoder refuses it next
		}
		if parsed.Scheme+"://"+parsed.Host != origin || parsed.User != nil || parsed.Opaque != "" {
			t.Fatalf("accepted %q, which a URL parser reads as origin %q with userinfo %v", link, parsed.Scheme+"://"+parsed.Host, parsed.User)
		}
		if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery {
			t.Fatalf("accepted %q, which a URL parser reads with path %q and query %q", link, parsed.Path, parsed.RawQuery)
		}
	})
}

// FuzzBuildCRIDLinkKnockBody holds the request body to its contract for any
// user agent a caller might pass: the body is JSON that reads back as the
// request; what is sent for the user agent is valid UTF-8 within the limit;
// it is a prefix of the (repaired) input; it is the LONGEST such prefix — the
// next character would not have fit; and the bytes are the canonical ones,
// compared with a serializer that does not share the builder's encoder.
func FuzzBuildCRIDLinkKnockBody(f *testing.F) {
	const value = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	for _, seed := range []string{
		"", "example-tool/1.2", `"quoted" back\slash <tag> a&b`, "Zürich 😀",
		strings.Repeat("a", 256), strings.Repeat("a", 257), strings.Repeat("c", 253) + "😀c",
		strings.Repeat("c", 255) + "ü", "ab\xffcd", "a\u2028b\u2029c", "a\x00b\x1fc\x7f",
		strings.Repeat("\xff", 300), `a\u2028b`, `a\` + "\u2028", `\\` + "\u2029" + `\`, "\b\f\n\r\t",
		strings.Repeat("d", 253) + "\u2028" + "tail", strings.Repeat("d", 254) + "\u2028",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, userAgent string) {
		body, err := buildCRIDLinkKnockBody(value, userAgent)
		if err != nil {
			t.Fatalf("buildCRIDLinkKnockBody: %v", err)
		}
		var decoded cridLinkKnockMsg
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("the body is not JSON: %v\n%s", err, body)
		}
		if decoded.HeaderType != relayknock.TypeKnock || decoded.AspID != qurlAspID ||
			decoded.ResID != cridLinkResourceID || decoded.UsrData.CRID != value {
			t.Fatalf("decoded body = %+v", decoded)
		}
		sent := decoded.UsrData.UserAgent
		// The bytes are the canonical ones, for whatever was sent. An empty
		// user agent is omitted, not sent as an empty member.
		if want := canonicalCRIDLinkKnockBody(value, sent); string(body) != want {
			t.Fatalf("the body is not in canonical form\n got %s\nwant %s", body, want)
		}

		repaired := strings.ToValidUTF8(userAgent, string(utf8.RuneError))
		if !utf8.ValidString(sent) || len(sent) > cridLinkUserAgentMaxBytes {
			t.Fatalf("sent a %d-byte user agent, valid UTF-8 = %t", len(sent), utf8.ValidString(sent))
		}
		if !strings.HasPrefix(repaired, sent) {
			t.Fatalf("the sent user agent %q is not a prefix of the input %q", sent, repaired)
		}
		if rest := repaired[len(sent):]; rest != "" {
			// Something was cut, so the next character must not have fit.
			_, size := utf8.DecodeRuneInString(rest)
			if len(sent)+size <= cridLinkUserAgentMaxBytes {
				t.Fatalf("cut at %d bytes although the next %d-byte character fits", len(sent), size)
			}
		}
	})
}

// FuzzInterpretCRIDLinkReply feeds arbitrary ACK bodies to the reply
// interpreter. The seeds are real answers; the fuzzer mutates them. For every
// body:
//
//   - exactly one of a link and an error comes back;
//   - a link that comes back is one the opener independently accepts for the
//     requested CRID, is on the link origin, and came from a body whose outcome
//     code a second decoder also reads as the link-issued string;
//   - every display string in the result is within the cap;
//   - an error is one of the documented kinds, and its text contains nothing
//     of the link that was in play.
func FuzzInterpretCRIDLinkReply(f *testing.F) {
	const origin = cridLinkTestOrigin
	// Fixed keys, not keys minted per process. The inputs the fuzzer saves
	// contain links signed by this issuer for this resource. Under keys that
	// changed with every run a saved input would stop verifying as soon as the
	// process exited, and a failure that needs a valid link could not be
	// replayed from the corpus.
	signer, err := NewLocalSigner(cridLinkFuzzKey(f, "issuer"), "crid-link-fuzz-issuer")
	if err != nil {
		f.Fatal(err)
	}
	issuerDER, err := signer.PublicKeyDER()
	if err != nil {
		f.Fatal(err)
	}
	trust, err := NewTrustStoreFromDER(map[string][]byte{signer.KID(): issuerDER})
	if err != nil {
		f.Fatal(err)
	}
	resourceKey := cridLinkFuzzSPKI(f, "resource")
	requested := testCRIDForKey(0x01, 32, resourceKey)
	cellSeed := sha256.Sum256([]byte("qurl-go CRID link fuzz key: cell"))
	cell, err := ecdh.X25519().NewPrivateKey(cellSeed[:])
	if err != nil {
		f.Fatal(err)
	}
	mint := func(key []byte) string {
		link, mintErr := CreatePortalWithParams(context.Background(), signer, CreateParams{
			CellPublicKey: cell.PublicKey().Bytes(), RelayURL: "https://relay.example.com",
			ResourcePublicKey: key, JTI: "qurl_01JCRIDLINKFUZZ",
			IssuedAt: 1781910000, NotBefore: 1781910000, Expiry: 1781910300,
		})
		if mintErr != nil {
			f.Fatal(mintErr)
		}
		return link
	}
	link, foreign := mint(resourceKey), mint(cridLinkFuzzSPKI(f, "another resource"))
	fragment := link[strings.IndexByte(link, '#')+1:]
	parsed, err := VerifyLink(link, trust)
	if err != nil {
		f.Fatal(err)
	}
	secrets := []string{link, fragment, parsed.SecretB64, parsed.Secret.QurlUserPrivateKeyB64, parsed.SigB64, foreign}

	quoted := func(s string) string {
		encoded, marshalErr := json.Marshal(s)
		if marshalErr != nil {
			f.Fatal(marshalErr)
		}
		return string(encoded)
	}
	info := `{"crid":` + quoted(requested) + `,"qurl_id":"q_1","expires_at":"2026-06-19T23:05:00Z",` +
		`"resource_created_at":"2026-06-18T09:30:00Z","publisher":{"name":"Example Publisher","verified":false}}`
	for _, seed := range []string{
		`{"errCode":"52600","opnTime":0,"redirectUrl":` + quoted(link) + `,"redirectInfo":` + info + `}`,
		`{"errCode":"52600","redirectUrl":` + quoted(link) + `}`,
		`{"errCode":"52600","redirectUrl":` + quoted(foreign) + `}`,
		`{"errCode":"52600","redirectUrl":` + quoted("https://example.com/#"+fragment) + `}`,
		`{"errCode":"52600","redirectUrl":` + quoted(origin+"/x?y#"+fragment) + `}`,
		`{"errCode":"52600","redirectUrl":[` + quoted(link) + `]}`,
		`{"errCode":"52600","redirectUrl":` + quoted(link) + `,"redirectInfo":{"crid":null}}`,
		`{"errCode":"52600","redirectUrl":` + quoted(link) + `,"redirectInfo":{"publisher":{"verified":true,"name":"n"}}}`,
		`{"errCode":"52602","redirectUrl":` + quoted(link) + `}`,
		`{"errCode":"0","redirectUrl":` + quoted(link) + `}`,
		`{"errCode":52600,"redirectUrl":` + quoted(link) + `}`,
		`{"errCode":"52607"}`,
		`{"errCode":` + quoted(link) + `}`,
		`{"errCode":"52601","errCode":"52600","redirectUrl":` + quoted(link) + `}`,
		`{}`, `null`, `[]`, ``, `{"errCode":"52600"`,
	} {
		f.Add([]byte(seed))
	}

	documented := []error{
		ErrCRIDLinkUnavailable, ErrCRIDLinkNotFound, ErrCRIDLinkRateLimited, ErrCRIDResourceOffline,
		ErrCRIDResourceClosed, ErrInvalidCRIDLinkRequest, ErrCRIDLinkProtocol, ErrCRIDLinkRejected,
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		issued, err := interpretCRIDLinkReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: body}, requested, origin, trust)
		if (issued == nil) == (err == nil) {
			t.Fatalf("interpretCRIDLinkReply = %v, %v; want exactly one of a link and an error", issued, err)
		}

		if issued != nil {
			// The opener, from the link alone, reaches the same verdict.
			if _, verifyErr := VerifyLinkForCRID(issued.Link, requested, trust); verifyErr != nil {
				t.Fatalf("returned a link the opener does not accept for the requested CRID: %v", verifyErr)
			}
			if !strings.HasPrefix(issued.Link, origin+"#") && !strings.HasPrefix(issued.Link, origin+"/#") {
				t.Fatal("returned a link that is not on the link origin")
			}
			// A second, plain decoder agrees that the outcome code is the
			// link-issued code and that it is a string. It decodes into a map
			// because member names are case-sensitive: a struct decode would
			// also accept "ERRCODE", which is some other member.
			var plain map[string]any
			if decodeErr := json.Unmarshal(body, &plain); decodeErr != nil {
				t.Fatalf("returned a link from a body a plain decoder cannot read: %v", decodeErr)
			}
			if code, isString := plain["errCode"].(string); !isString || code != cridLinkCodeIssued {
				t.Fatalf("returned a link from a body whose outcome code is %#v", plain["errCode"])
			}
			for name, text := range map[string]string{"QURLID": issued.QURLID, "Publisher.Name": issued.Publisher.Name} {
				if utf8.RuneCountInString(text) > cridLinkInfoTextMaxCodePoints {
					t.Fatalf("%s is %d code points, over the cap", name, utf8.RuneCountInString(text))
				}
			}
			// An absent creation time is nil, never a pointer to the zero time.
			if issued.ResourceCreatedAt != nil && issued.ResourceCreatedAt.IsZero() {
				t.Fatal("ResourceCreatedAt points at the zero time")
			}
			return
		}

		// An error is one of the documented kinds...
		var deny *ServerDenyError
		known := errors.As(err, &deny)
		for _, sentinel := range documented {
			known = known || errors.Is(err, sentinel)
		}
		if !known {
			t.Fatalf("error %v is none of the documented outcomes", err)
		}
		if deny != nil && !isCanonicalKnockDenyCode(deny.ErrCode) {
			t.Fatalf("a deny carries the code %q, which is not a decimal code", deny.ErrCode)
		}
		// ...and says nothing of the links that were in play. The named
		// secrets belong to the links this run minted. An input replayed from
		// the corpus can carry a link an earlier run minted, with a signature
		// and a key of its own; for that one the transport prefix, which every
		// link carries, is the check.
		walkErrorChain(err, func(inner error) {
			for _, secret := range secrets {
				if strings.Contains(inner.Error(), secret) {
					t.Fatalf("error text carries link material: %v", inner)
				}
			}
			if strings.Contains(inner.Error(), "qv2t1.") {
				t.Fatalf("error text carries link transport text: %v", inner)
			}
		})
	})
}

// cridLinkFuzzKey is a fixed P-256 private key for a fuzz target, derived from
// a label so that every run of the target, on every machine, uses the same one.
func cridLinkFuzzKey(f *testing.F, label string) *ecdsa.PrivateKey {
	f.Helper()
	scalar := sha256.Sum256([]byte("qurl-go CRID link fuzz key: " + label))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		f.Fatalf("the fixed %s key is not a usable P-256 scalar; choose another label: %v", label, err)
	}
	return key
}

// cridLinkFuzzSPKI is the DER SPKI of the fixed key for label: the shape of a
// resource key.
func cridLinkFuzzSPKI(f *testing.F, label string) []byte {
	f.Helper()
	der, err := x509.MarshalPKIXPublicKey(&cridLinkFuzzKey(f, label).PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	return der
}
