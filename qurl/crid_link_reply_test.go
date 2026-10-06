package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/layervai/qurl-go/relayknock"
)

// The reply interpreter, at its own seam. The request tests prove these rules
// hold over the wire; here they are pinned one input at a time, including the
// inputs no transport would hand back.

func TestInterpretCRIDLinkReply_ReadsTheHeaderTypeFirst(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	issued := cridLinkIssued(t, fixture.link, fixture.info()).body
	interpret := func(reply *relayknock.Reply) (*CRIDLink, error) {
		return interpretCRIDLinkReply(reply, fixture.crid, cridLinkTestOrigin, fixture.cfg.TrustStore)
	}

	// The same body under three header types is three different things.
	link, err := interpret(&relayknock.Reply{Type: relayknock.TypeACK, Body: issued})
	if err != nil || link == nil || link.Link != fixture.link {
		t.Fatalf("ACK = %v, %v; want the link", link, err)
	}
	link, err = interpret(&relayknock.Reply{Type: relayknock.TypeCookieChallenge, Body: issued})
	if link != nil || !errors.Is(err, ErrServerOverloaded) {
		t.Fatalf("cookie reply = %v, %v; want ErrServerOverloaded", link, err)
	}
	for _, other := range []int{
		relayknock.TypeListResult, relayknock.TypeRegisterAck, relayknock.TypeKnock, relayknock.TypeExit, 0, 99,
	} {
		link, err = interpret(&relayknock.Reply{Type: other, Body: issued})
		if link != nil || !errors.Is(err, ErrMalformedReply) {
			t.Fatalf("reply type %d = %v, %v; want ErrMalformedReply", other, link, err)
		}
		// Not a client result: it says nothing the server decided.
		if errors.Is(err, ErrCRIDLinkProtocol) || errors.Is(err, ErrServerOverloaded) {
			t.Fatalf("reply type %d was given a client result: %v", other, err)
		}
	}
	if link, err = interpret(nil); link != nil || !errors.Is(err, ErrMalformedReply) {
		t.Fatalf("nil reply = %v, %v; want ErrMalformedReply", link, err)
	}
}

func TestInterpretCRIDLinkReply_DecidesOnTheCodeAlone(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	interpret := func(body string) (*CRIDLink, error) {
		return interpretCRIDLinkReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)},
			fixture.crid, cridLinkTestOrigin, fixture.cfg.TrustStore)
	}

	// A refusal needs nothing but its code. The other members an ordinary deny
	// is held to — an open time, no session id — are not this reply's
	// contract, and their absence or their content changes nothing.
	for _, body := range []string{
		`{"errCode":"52602"}`,
		`{"errCode":"52602","opnTime":0}`,
		`{"errCode":"52602","opnTime":900,"sessId":7,"aspToken":"x.y"}`,
		`{"errCode":"52602","errMsg":"anything at all","future":{"nested":[1,2,3]}}`,
		` { "errCode" : "52602" } `,
	} {
		if link, err := interpret(body); link != nil || !errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("%s = %v, %v; want ErrCRIDLinkNotFound", body, link, err)
		}
	}

	// The diagnostic message never decides: a refusal whose message says a
	// link was issued is still the refusal.
	if _, err := interpret(`{"errCode":"52605","errMsg":"crid link issued"}`); !errors.Is(err, ErrCRIDResourceClosed) {
		t.Fatalf("error = %v, want ErrCRIDResourceClosed", err)
	}

	// Codes outside the decimal grammar are never echoed and never a deny.
	for _, code := range []string{" 52602", "52602 ", "052602", "+52602", "5260２", "52602\n", "0x1", "-1"} {
		encoded, err := json.Marshal(code)
		if err != nil {
			t.Fatal(err)
		}
		_, err = interpret(`{"errCode":` + string(encoded) + `}`)
		if !errors.Is(err, ErrCRIDLinkProtocol) {
			t.Fatalf("code %q: error = %v, want ErrCRIDLinkProtocol", code, err)
		}
		var deny *ServerDenyError
		if errors.As(err, &deny) {
			t.Fatalf("code %q was carried in a *ServerDenyError", code)
		}
		if trimmed := strings.TrimSpace(code); len(trimmed) > 2 && strings.Contains(err.Error(), trimmed) {
			t.Fatalf("code %q was echoed in the error: %v", code, err)
		}
	}
}

// JSON member names are case-sensitive, and the interpreter reads them that
// way. Go's struct decoding does not: it would match "ERRCODE" to errCode and
// let the later of two differently-cased members win, which no duplicate check
// catches. Read that way, a refusal followed by "ErrCode":"52600" would turn
// into a link. These cases pin the exact-name reading.
func TestInterpretCRIDLinkReply_MemberNamesAreExact(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	link := string(mustJSON(t, fixture.link))
	interpret := func(body string) (*CRIDLink, error) {
		return interpretCRIDLinkReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)},
			fixture.crid, cridLinkTestOrigin, fixture.cfg.TrustStore)
	}

	// A differently-cased code is some other member: the reply has no code.
	for _, body := range []string{
		`{"ERRCODE":"52600","redirectUrl":` + link + `}`,
		`{"errcode":"52600","redirectUrl":` + link + `}`,
		`{"ErrCode":"52600","redirectUrl":` + link + `}`,
	} {
		if issued, err := interpret(body); issued != nil || !errors.Is(err, ErrCRIDLinkProtocol) {
			t.Fatalf("%s = %v, %v; want ErrCRIDLinkProtocol", body, issued, err)
		}
	}

	// A refusal stays the refusal whatever differently-cased members follow or
	// precede it.
	for _, body := range []string{
		`{"errCode":"52602","ErrCode":"52600","redirectUrl":` + link + `}`,
		`{"ERRCODE":"52600","errCode":"52602","redirectUrl":` + link + `}`,
		`{"errCode":"52602","errcode":"0","redirectUrl":` + link + `}`,
	} {
		if issued, err := interpret(body); issued != nil || !errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("%s = %v, %v; want ErrCRIDLinkNotFound", body, issued, err)
		}
	}

	// A differently-cased link member is not the link.
	for _, body := range []string{
		`{"errCode":"52600","REDIRECTURL":` + link + `}`,
		`{"errCode":"52600","redirecturl":` + link + `}`,
		`{"errCode":"52600","RedirectUrl":` + link + `}`,
	} {
		_, err := interpret(body)
		var rejected *CRIDLinkRejectedError
		if !errors.As(err, &rejected) || rejected.Class != CRIDLinkRejectMissingRedirect {
			t.Fatalf("%s: error = %v, want a missing_redirect rejection", body, err)
		}
	}

	// In the metadata, a differently-cased member is an unknown member: it is
	// not the echoed CRID, not the publisher, and not a display string.
	issued, err := interpret(`{"errCode":"52600","redirectUrl":` + link + `,"redirectInfo":{` +
		`"CRID":"some other value","Qurl_Id":"q_wrong","EXPIRES_AT":"2026-06-19T23:05:00Z",` +
		`"Resource_Created_At":"2026-06-18T09:30:00Z",` +
		`"Publisher":{"name":"Wrong","verified":true},"publisher":{"Name":"Wrong","VERIFIED":true}}}`)
	if err != nil {
		t.Fatalf("differently-cased metadata failed the request: %v", err)
	}
	if issued.QURLID != "" || !issued.ExpiresAt.IsZero() || issued.ResourceCreatedAt != nil || issued.Publisher != (Publisher{}) {
		t.Fatalf("differently-cased metadata was read: %v", issued)
	}
	// And a differently-cased redirectInfo is not the metadata at all, so its
	// crid is not an echo.
	if _, err := interpret(`{"errCode":"52600","redirectUrl":` + link + `,"RedirectInfo":{"crid":"other"}}`); err != nil {
		t.Fatalf("a member that is not redirectInfo was checked as the echo: %v", err)
	}
}

// The duplicate check every reply body goes through has bounds of its own, and
// a body outside them is refused whole: a protocol violation, with no outcome
// read from it, although it repeats nothing. No server sends such a body. The
// cases pin that the refusal is the safe one, and that inside the bounds an
// unknown member is ignored whatever its shape.
func TestInterpretCRIDLinkReply_RefusesABodyOutsideTheReadersBounds(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	link := string(mustJSON(t, fixture.link))
	interpret := func(body string) (*CRIDLink, error) {
		return interpretCRIDLinkReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)},
			fixture.crid, cridLinkTestOrigin, fixture.cfg.TrustStore)
	}
	nested := func(depth int) string {
		return strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)
	}

	for name, body := range map[string]string{
		"a number no float64 holds":       `{"errCode":"52602","opnTime":1e999}`,
		"an integer of 400 digits":        `{"errCode":"52602","count":` + strings.Repeat("9", 400) + `}`,
		"a refusal with a member 40 deep": `{"errCode":"52602","future":` + nested(40) + `}`,
		"a link with a member 40 deep":    `{"errCode":"52600","redirectUrl":` + link + `,"future":` + nested(40) + `}`,
	} {
		issued, err := interpret(body)
		if issued != nil || !errors.Is(err, ErrCRIDLinkProtocol) {
			t.Errorf("%s = %v, %v; want ErrCRIDLinkProtocol and no link", name, issued, err)
		}
	}

	if _, err := interpret(`{"errCode":"52602","future":` + nested(20) + `,"count":1e300}`); !errors.Is(err, ErrCRIDLinkNotFound) {
		t.Errorf("a refusal with unknown members inside the bounds = %v, want ErrCRIDLinkNotFound", err)
	}
	issued, err := interpret(`{"errCode":"52600","redirectUrl":` + link + `,"future":` + nested(20) + `}`)
	if err != nil || issued == nil || issued.Link != fixture.link {
		t.Errorf("a link with an unknown member inside the bounds = %v, %v; want the link", issued, err)
	}
}

// The two JSON readers every rule above is built on. Each accepts exactly one
// JSON type; in particular null is neither a string nor an object, which is
// what lets a caller tell "present but not a string" from "absent".
func TestCRIDLinkJSONReaders(t *testing.T) {
	for raw, want := range map[string]struct {
		value string
		ok    bool
	}{
		`"text"`:        {"text", true},
		`""`:            {"", true},
		` "padded" `:    {"padded", true},
		`"a\u00e9\n"`:   {"a\u00e9\n", true},
		`null`:          {"", false},
		`0`:             {"", false},
		`52600`:         {"", false},
		`true`:          {"", false},
		`["text"]`:      {"", false},
		`{"v":"text"}`:  {"", false},
		``:              {"", false},
		`"unterminated`: {"", false},
		`text`:          {"", false},
	} {
		value, ok := cridLinkJSONString(json.RawMessage(raw))
		if value != want.value || ok != want.ok {
			t.Errorf("cridLinkJSONString(%s) = %q, %t; want %q, %t", raw, value, ok, want.value, want.ok)
		}
	}

	for raw, want := range map[string]bool{
		`{}`: true, `{"a":1}`: true, ` {"a":{"b":[1]}} `: true,
		`null`: false, `[]`: false, `[{"a":1}]`: false, `"{}"`: false, `7`: false, `true`: false, ``: false, `{`: false,
	} {
		fields, ok := cridLinkJSONObject(json.RawMessage(raw))
		if ok != want || (ok && fields == nil) || (!ok && fields != nil) {
			t.Errorf("cridLinkJSONObject(%s) = %v, %t; want ok = %t", raw, fields, ok, want)
		}
	}
}

func TestSplitIssuedCRIDLink(t *testing.T) {
	const origin = "https://qurl.link"
	for _, tc := range []struct {
		link         string
		wantFragment string
		wantClass    CRIDLinkRejectClass
	}{
		// The two forms an issued link takes.
		{"https://qurl.link/#qv2t1.x", "qv2t1.x", ""},
		{"https://qurl.link#qv2t1.x", "qv2t1.x", ""},
		// The fragment is everything after the first '#', verbatim.
		{"https://qurl.link/#a#b", "a#b", ""},
		{"https://qurl.link/#%41", "%41", ""},
		{"https://qurl.link/#", "", ""},

		// Not on the origin at all.
		{"http://qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"HTTPS://qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"https://QURL.LINK/#f", "", CRIDLinkRejectOrigin},
		{"https://example.com/#f", "", CRIDLinkRejectOrigin},
		{"https://user@qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"https://user:pass@qurl.link/#f", "", CRIDLinkRejectOrigin},
		{" https://qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"//qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"qurl.link/#f", "", CRIDLinkRejectOrigin},
		{"", "", CRIDLinkRejectOrigin},
		{"#f", "", CRIDLinkRejectOrigin},

		// The origin is a prefix, but the authority goes on past it.
		{"https://qurl.link.example.com/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.linkx/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link:8443/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link:443/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link:/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link@example.com/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link.@example.com/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link./#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link.#f", "", CRIDLinkRejectOrigin},
		{`https://qurl.link\@example.com/#f`, "", CRIDLinkRejectOrigin},
		{"https://qurl.link%2f@example.com/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link\t/#f", "", CRIDLinkRejectOrigin},
		{"https://qurl.link /#f", "", CRIDLinkRejectOrigin},

		// On the origin, with something other than the bare fragment link.
		{"https://qurl.link/open#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link//#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/./#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/.#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/..#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/%2e#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/@example.com/#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/?next=open#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link?next=open#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/?#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link?#f", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/open", "", CRIDLinkRejectPathOrQuery},
		{"https://qurl.link/?q=1", "", CRIDLinkRejectPathOrQuery},

		// On the origin and bare, with no fragment to open.
		{"https://qurl.link/", "", CRIDLinkRejectTransport},
		{"https://qurl.link", "", CRIDLinkRejectTransport},
	} {
		fragment, class := splitIssuedCRIDLink(tc.link, origin)
		if fragment != tc.wantFragment || class != tc.wantClass {
			t.Errorf("splitIssuedCRIDLink(%q) = %q, %q; want %q, %q", tc.link, fragment, class, tc.wantFragment, tc.wantClass)
		}
	}

	// A configured origin with a port is matched as text as well.
	for link, want := range map[string]CRIDLinkRejectClass{
		"https://links.example.org:8443/#f":  "",
		"https://links.example.org:84430/#f": CRIDLinkRejectOrigin,
		"https://links.example.org/#f":       CRIDLinkRejectOrigin,
		"https://links.example.org:8443#f":   "",
	} {
		if _, class := splitIssuedCRIDLink(link, "https://links.example.org:8443"); class != want {
			t.Errorf("splitIssuedCRIDLink(%q) class = %q, want %q", link, class, want)
		}
	}
}

func TestSanitizeCRIDLinkInfo(t *testing.T) {
	// 128 code points whose last one lies outside the BMP: at the cap in code
	// points, over it in bytes and in UTF-16 code units. A cap counted in
	// either of those would wrongly drop it.
	atLimit := strings.Repeat("a", cridLinkInfoTextMaxCodePoints-1) + "\U00020000"
	overLimit := strings.Repeat("a", cridLinkInfoTextMaxCodePoints+1)
	if utf8.RuneCountInString(atLimit) != 128 || len(atLimit) != 131 || len(utf16.Encode([]rune(atLimit))) != 129 {
		t.Fatal("fixture drift: the at-limit string no longer straddles the three ways of counting")
	}
	quote := func(s string) string {
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	full := cridLinkInfo{
		qurlID: "q_1", expiresAt: "2026-06-19T23:05:00Z", resourceCreatedAt: "2026-06-18T09:30:00Z",
		publisher: Publisher{Name: "Example Publisher"},
	}
	const fullJSON = `"qurl_id":"q_1","expires_at":"2026-06-19T23:05:00Z","resource_created_at":"2026-06-18T09:30:00Z"`

	for _, tc := range []struct {
		name string
		raw  string
		want cridLinkInfo
	}{
		{"full", `{"crid":"x",` + fullJSON + `,"publisher":{"name":"Example Publisher","verified":false}}`, full},

		// Not an object: nothing is kept, and the publisher is unverified.
		{"absent", ``, cridLinkInfo{}},
		{"null", `null`, cridLinkInfo{}},
		{"a string", `"Example Publisher"`, cridLinkInfo{}},
		{"a number", `7`, cridLinkInfo{}},
		{"true", `true`, cridLinkInfo{}},
		{"an array holding the object", `[{` + fullJSON + `}]`, cridLinkInfo{}},
		{"empty object", `{}`, cridLinkInfo{}},

		// The publisher is always present in the view, if only as unverified.
		{"publisher missing", `{` + fullJSON + `}`, cridLinkInfo{qurlID: "q_1", expiresAt: full.expiresAt, resourceCreatedAt: full.resourceCreatedAt}},
		{"publisher is a string", `{"publisher":"Example Publisher"}`, cridLinkInfo{}},
		{"publisher is null", `{"publisher":null}`, cridLinkInfo{}},
		{"publisher is an array", `{"publisher":[{"name":"x","verified":true}]}`, cridLinkInfo{}},

		// Only the JSON boolean true is verified.
		{"verified true", `{"publisher":{"name":"n","verified":true}}`, cridLinkInfo{publisher: Publisher{Name: "n", Verified: true}}},
		{"verified true, padded", `{"publisher":{"verified": true }}`, cridLinkInfo{publisher: Publisher{Verified: true}}},
		{"verified false", `{"publisher":{"name":"n","verified":false}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified the string true", `{"publisher":{"name":"n","verified":"true"}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified one", `{"publisher":{"name":"n","verified":1}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified null", `{"publisher":{"name":"n","verified":null}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified missing", `{"publisher":{"name":"n"}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified an object", `{"publisher":{"name":"n","verified":{"value":true}}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},
		{"verified an array", `{"publisher":{"name":"n","verified":[true]}}`, cridLinkInfo{publisher: Publisher{Name: "n"}}},

		// A display string is kept only if it is a non-empty string within the cap.
		{"name is a number", `{"publisher":{"name":42,"verified":false}}`, cridLinkInfo{}},
		{"name is null", `{"publisher":{"name":null}}`, cridLinkInfo{}},
		{"name is empty", `{"publisher":{"name":""}}`, cridLinkInfo{}},
		{"name at the cap", `{"publisher":{"name":` + quote(atLimit) + `}}`, cridLinkInfo{publisher: Publisher{Name: atLimit}}},
		{"name over the cap", `{"publisher":{"name":` + quote(overLimit) + `}}`, cridLinkInfo{}},
		{"qurl id at the cap", `{"qurl_id":` + quote(atLimit) + `}`, cridLinkInfo{qurlID: atLimit}},
		{"qurl id over the cap", `{"qurl_id":` + quote(overLimit) + `}`, cridLinkInfo{}},
		{"qurl id is a number", `{"qurl_id":12345}`, cridLinkInfo{}},
		{"expiry at the cap", `{"expires_at":` + quote(atLimit) + `}`, cridLinkInfo{expiresAt: atLimit}},
		// Over the cap and beginning with a genuine value: dropped, not cut
		// down to the part that would have looked real.
		{"expiry over the cap", `{"expires_at":` + quote(full.expiresAt+strings.Repeat("a", 109)) + `}`, cridLinkInfo{}},
		{"created over the cap", `{"resource_created_at":` + quote(full.resourceCreatedAt+strings.Repeat("a", 109)) + `}`, cridLinkInfo{}},
		{"timestamps are not strings", `{"qurl_id":"q_1","expires_at":1781910300,"resource_created_at":{"seconds":1781775000}}`, cridLinkInfo{qurlID: "q_1"}},
		{"empty strings are absent", `{"qurl_id":"","expires_at":"","resource_created_at":""}`, cridLinkInfo{}},

		// One over-long member removes only itself.
		{
			"an over-long member leaves the others",
			`{"qurl_id":` + quote(overLimit) + `,"expires_at":"2026-06-19T23:05:00Z","publisher":{"name":"n"}}`,
			cridLinkInfo{expiresAt: "2026-06-19T23:05:00Z", publisher: Publisher{Name: "n"}},
		},
		// Unknown members are ignored and never surfaced.
		{
			"unknown members",
			`{` + fullJSON + `,"future_field":{"enabled":true},"publisher":{"name":"Example Publisher","verified":false,"badge":"gold"}}`,
			full,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeCRIDLinkInfo(json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("sanitized = %+v\nwant        %+v", got, tc.want)
			}
		})
	}
	if utf8.RuneCountInString(full.expiresAt+strings.Repeat("a", 109)) != cridLinkInfoTextMaxCodePoints+1 {
		t.Fatal("fixture drift: the over-cap timestamp is not exactly one code point over")
	}
}

// Malformed metadata never fails the request: the link is still returned, and
// what cannot be used is simply absent from the result.
func TestInterpretCRIDLinkReply_MalformedMetadataStillYieldsTheLink(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	createdAt := func(year int, month time.Month, day, hour, minute, second, nanosecond int) *time.Time {
		value := time.Date(year, month, day, hour, minute, second, nanosecond, time.UTC)
		return &value
	}
	for name, tc := range map[string]struct {
		info string
		want CRIDLink
	}{
		"no metadata":   {``, CRIDLink{}},
		"null":          {`null`, CRIDLink{}},
		"a string":      {`"text"`, CRIDLink{}},
		"an array":      {`[{"crid":"not checked: an array has no members"}]`, CRIDLink{}},
		"all malformed": {`{"qurl_id":7,"expires_at":false,"resource_created_at":[],"publisher":"x"}`, CRIDLink{}},
		"unverified":    {`{"publisher":{"name":"Acme","verified":"true"}}`, CRIDLink{Publisher: Publisher{Name: "Acme"}}},
		"verified":      {`{"publisher":{"name":"Acme","verified":true}}`, CRIDLink{Publisher: Publisher{Name: "Acme", Verified: true}}},
		"qurl id only":  {`{"qurl_id":"q_9"}`, CRIDLink{QURLID: "q_9"}},
		"offset time":   {`{"expires_at":"2026-06-20T01:05:00+02:00"}`, CRIDLink{ExpiresAt: time.Date(2026, 6, 19, 23, 5, 0, 0, time.UTC)}},
		"fraction":      {`{"resource_created_at":"2026-06-18T09:30:00.5Z"}`, CRIDLink{ResourceCreatedAt: createdAt(2026, 6, 18, 9, 30, 0, 500_000_000)}},
		"created only":  {`{"resource_created_at":"2026-06-18T11:30:00+02:00"}`, CRIDLink{ResourceCreatedAt: createdAt(2026, 6, 18, 9, 30, 0, 0)}},
		// Kept as text, but not a time this SDK can read: absent where it is used.
		// Absent is the zero time for the expiry and nil for the creation time.
		"not RFC 3339":  {`{"expires_at":"19 June 2026","resource_created_at":"1781775000"}`, CRIDLink{}},
		"date only":     {`{"expires_at":"2026-06-19","resource_created_at":"2026-06-18"}`, CRIDLink{}},
		"trailing text": {`{"expires_at":"2026-06-19T23:05:00Zextra","resource_created_at":"2026-06-18T09:30:00Zextra"}`, CRIDLink{}},
		// The zero time is an unset value, not a creation date: nil, not year 1.
		"zero times": {`{"expires_at":"0001-01-01T00:00:00Z","resource_created_at":"0001-01-01T00:00:00Z"}`, CRIDLink{}},
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"errCode":"52600","redirectUrl":` + string(mustJSON(t, fixture.link))
			if tc.info != "" {
				body += `,"redirectInfo":` + tc.info
			}
			body += `}`
			got, err := interpretCRIDLinkReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)},
				fixture.crid, cridLinkTestOrigin, fixture.cfg.TrustStore)
			if err != nil {
				t.Fatalf("malformed metadata failed the request: %v", err)
			}
			if got.Link != fixture.link {
				t.Fatal("the link was not returned")
			}
			if got.QURLID != tc.want.QURLID || got.Publisher != tc.want.Publisher || !got.ExpiresAt.Equal(tc.want.ExpiresAt) {
				t.Fatalf("result = %v\nwant     %v", got, tc.want)
			}
			if got.ExpiresAt.IsZero() != tc.want.ExpiresAt.IsZero() {
				t.Fatalf("an absent expiry must be the zero time: %v", got)
			}
			// The creation time is absent as nil, never as a pointer to the
			// zero time, and present as the instant the server wrote.
			switch {
			case tc.want.ResourceCreatedAt == nil:
				if got.ResourceCreatedAt != nil {
					t.Fatalf("ResourceCreatedAt = %v, want nil", *got.ResourceCreatedAt)
				}
			case got.ResourceCreatedAt == nil || !got.ResourceCreatedAt.Equal(*tc.want.ResourceCreatedAt):
				t.Fatalf("ResourceCreatedAt = %v, want %v", got.ResourceCreatedAt, *tc.want.ResourceCreatedAt)
			}
		})
	}
}

func TestCRIDLinkInfoCRIDMatches(t *testing.T) {
	const requested = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		// Only an absent member passes without being equal.
		{"no metadata", ``, true},
		{"metadata is null", `null`, true},
		{"metadata is not an object", `"` + requested + `"`, true},
		{"metadata is an array", `[{"crid":"other"}]`, true},
		{"no crid member", `{"qurl_id":"q_1"}`, true},
		{"the requested CRID", `{"crid":"` + requested + `"}`, true},

		{"another CRID", `{"crid":"qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq"}`, false},
		{"upper case", `{"crid":"` + strings.ToUpper(requested) + `"}`, false},
		{"padded", `{"crid":" ` + requested + `"}`, false},
		{"a prefix", `{"crid":"` + requested[:59] + `"}`, false},
		{"empty string", `{"crid":""}`, false},
		// Present but not a string is present and unequal, falsy or not.
		{"zero", `{"crid":0}`, false},
		{"null", `{"crid":null}`, false},
		{"false", `{"crid":false}`, false},
		{"an object holding it", `{"crid":{"value":"` + requested + `"}}`, false},
		{"an array holding it", `{"crid":["` + requested + `"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cridLinkInfoCRIDMatches(requested, json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("cridLinkInfoCRIDMatches = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCRIDLinkRejectedError(t *testing.T) {
	classes := []CRIDLinkRejectClass{
		CRIDLinkRejectMissingRedirect, CRIDLinkRejectOrigin, CRIDLinkRejectPathOrQuery, CRIDLinkRejectTransport,
		CRIDLinkRejectIssuerSignature, CRIDLinkRejectCRIDMismatch, CRIDLinkRejectInfoCRIDMismatch,
	}
	seen := map[CRIDLinkRejectClass]bool{}
	for _, class := range classes {
		if seen[class] || class == "" {
			t.Fatalf("reject class %q is empty or repeated", class)
		}
		seen[class] = true

		err := rejectCRIDLink(class)
		if !errors.Is(err, ErrCRIDLinkRejected) {
			t.Fatalf("%q does not match ErrCRIDLinkRejected", class)
		}
		var rejected *CRIDLinkRejectedError
		if !errors.As(err, &rejected) || rejected.Class != class {
			t.Fatalf("%q: errors.As = %v", class, rejected)
		}
		// Still readable through a caller's own wrapping.
		wrapped := errors.Join(errors.New("context"), err)
		rejected = nil
		if !errors.As(wrapped, &rejected) || rejected.Class != class || !errors.Is(wrapped, ErrCRIDLinkRejected) {
			t.Fatalf("%q: the class is lost when the error is wrapped", class)
		}
		// With no sentinel attached, it matches nothing else.
		for _, other := range []error{ErrCRIDMismatch, ErrSignature, ErrUnknownKID, ErrFragment, ErrMalformedReply, ErrCRIDLinkProtocol} {
			if errors.Is(err, other) {
				t.Fatalf("%q with no sentinel matches %v", class, other)
			}
		}
	}

	// Sentinels are matchable and never part of the text.
	err := rejectCRIDLink(CRIDLinkRejectIssuerSignature, ErrUnknownKID, ErrStrictParse)
	if !errors.Is(err, ErrUnknownKID) || !errors.Is(err, ErrStrictParse) || errors.Is(err, ErrSignature) {
		t.Fatalf("attached sentinels do not match as attached: %v", err)
	}
	if got, want := err.Error(), "qurl: issued CRID link rejected: issuer_signature check failed"; got != want {
		t.Fatalf("error text = %q, want %q", got, want)
	}
}

// cridLinkVerifySentinels keeps the identity of a verification failure and
// drops its text, because the text can quote the link it was given.
func TestCRIDLinkVerifySentinelsDropTheMessage(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	other := freshTrustStore(t)

	// An unknown issuer: the real error names the key id from the link.
	_, verifyErr := VerifyLink(fixture.link, other)
	if !errors.Is(verifyErr, ErrUnknownKID) || !strings.Contains(verifyErr.Error(), fixture.signer.KID()) {
		t.Fatalf("fixture drift: the verify error no longer quotes the key id: %v", verifyErr)
	}
	sentinels := cridLinkVerifySentinels(verifyErr)
	if len(sentinels) != 1 || sentinels[0] != ErrUnknownKID { //nolint:errorlint // identity is the assertion
		t.Fatalf("sentinels = %v, want exactly ErrUnknownKID", sentinels)
	}
	rejected := rejectCRIDLink(CRIDLinkRejectIssuerSignature, sentinels...)
	walkErrorChain(rejected, func(inner error) {
		if strings.Contains(inner.Error(), fixture.signer.KID()) {
			t.Fatalf("the rejection carries text from the link: %v", inner)
		}
	})

	// An error with no sentinel of this package yields none, not a wrapped copy.
	if got := cridLinkVerifySentinels(errors.New("some other failure quoting " + fixture.link)); len(got) != 0 {
		t.Fatalf("sentinels for a foreign error = %v, want none", got)
	}
}

// The outcomes of a request are separate errors. A caller's switch over them
// must never match two, apart from the documented containments.
func TestCRIDLinkErrorsAreDistinct(t *testing.T) {
	outcomes := map[string]error{
		"ErrCRIDLinkUnavailable":    ErrCRIDLinkUnavailable,
		"ErrCRIDLinkNotFound":       ErrCRIDLinkNotFound,
		"ErrCRIDLinkRateLimited":    ErrCRIDLinkRateLimited,
		"ErrCRIDResourceOffline":    ErrCRIDResourceOffline,
		"ErrCRIDResourceClosed":     ErrCRIDResourceClosed,
		"ErrInvalidCRIDLinkRequest": ErrInvalidCRIDLinkRequest,
		"ErrCRIDLinkProtocol":       ErrCRIDLinkProtocol,
		"ErrCRIDLinkRejected":       ErrCRIDLinkRejected,
		"ErrCRIDLinkNotConfigured":  ErrCRIDLinkNotConfigured,
		"ErrServerOverloaded":       ErrServerOverloaded,
		"ErrUnsupportedCRIDVersion": ErrUnsupportedCRIDVersion,
		"ErrInvalidResourceRequest": ErrInvalidResourceRequest,
	}
	for name, err := range outcomes {
		for otherName, other := range outcomes {
			if name != otherName && errors.Is(err, other) {
				t.Errorf("%s matches %s", name, otherName)
			}
		}
		if !strings.HasPrefix(err.Error(), "qurl: ") {
			t.Errorf("%s text %q does not carry the package prefix", name, err.Error())
		}
	}
	// The containments a caller can rely on.
	if !errors.Is(ErrCRIDLinkProtocol, ErrMalformedReply) {
		t.Error("ErrCRIDLinkProtocol must match ErrMalformedReply")
	}
	if !errors.Is(ErrCRIDLinkNotConfigured, ErrNotConfigured) {
		t.Error("ErrCRIDLinkNotConfigured must match ErrNotConfigured")
	}
	// An endpoint that cannot be used is one kind of "not configured", so code
	// written before the narrower error existed keeps matching it.
	if !errors.Is(ErrCRIDLinkMisconfigured, ErrCRIDLinkNotConfigured) || !errors.Is(ErrCRIDLinkMisconfigured, ErrNotConfigured) {
		t.Error("ErrCRIDLinkMisconfigured must match ErrCRIDLinkNotConfigured and ErrNotConfigured")
	}
	// And they are containments, not equalities.
	if errors.Is(ErrMalformedReply, ErrCRIDLinkProtocol) || errors.Is(ErrNotConfigured, ErrCRIDLinkNotConfigured) ||
		errors.Is(ErrCRIDLinkNotConfigured, ErrCRIDLinkMisconfigured) {
		t.Error("a broader sentinel matches its narrower one")
	}
	// The narrower error matches no other outcome.
	for name, other := range outcomes {
		if name != "ErrCRIDLinkNotConfigured" && (errors.Is(ErrCRIDLinkMisconfigured, other) || errors.Is(other, ErrCRIDLinkMisconfigured)) {
			t.Errorf("ErrCRIDLinkMisconfigured and %s match", name)
		}
	}
	if !strings.HasPrefix(ErrCRIDLinkMisconfigured.Error(), "qurl: ") {
		t.Errorf("ErrCRIDLinkMisconfigured text %q does not carry the package prefix", ErrCRIDLinkMisconfigured.Error())
	}
}

// The two timestamps report absence differently, as the same two fields on
// ShareLink do: the expiry as the zero time, the creation time as nil.
func TestCRIDLinkResourceCreatedAt(t *testing.T) {
	for _, absent := range []string{"", "not a time", "2026-06-18", "1781775000", "2026-06-18T09:30:00", "0001-01-01T00:00:00Z"} {
		if got := cridLinkResourceCreatedAt(absent); got != nil {
			t.Errorf("cridLinkResourceCreatedAt(%q) = %v, want nil", absent, *got)
		}
	}
	want := time.Date(2026, 6, 18, 9, 30, 0, 0, time.UTC)
	for _, present := range []string{"2026-06-18T09:30:00Z", "2026-06-18T11:30:00+02:00", "2026-06-18T09:30:00.000Z"} {
		got := cridLinkResourceCreatedAt(present)
		if got == nil || !got.Equal(want) {
			t.Errorf("cridLinkResourceCreatedAt(%q) = %v, want %v", present, got, want)
		}
	}
	// Each call returns its own value: a caller that changes one result does
	// not change another.
	first, second := cridLinkResourceCreatedAt("2026-06-18T09:30:00Z"), cridLinkResourceCreatedAt("2026-06-18T09:30:00Z")
	if first == second {
		t.Fatal("two results share one time value")
	}
}

// The redacted rendering names every field as the struct does and prints the
// creation time as a time or as <nil>, never as a pointer address.
func TestCRIDLinkString(t *testing.T) {
	createdAt := time.Date(2026, 6, 18, 9, 30, 0, 0, time.UTC)
	full := CRIDLink{
		Link: "https://qurl.link/#qv2t1.example", QURLID: "q_1",
		ExpiresAt: time.Date(2026, 6, 19, 23, 5, 0, 0, time.UTC), ResourceCreatedAt: &createdAt,
		Publisher: Publisher{Name: "Example \"Publisher\"\n"},
	}
	const want = `qurl.CRIDLink{Link:[REDACTED], QURLID:"q_1", ExpiresAt:2026-06-19T23:05:00Z, ` +
		`ResourceCreatedAt:2026-06-18T09:30:00Z, Publisher:{Name:"Example \"Publisher\"\n", Verified:false}}`
	for _, got := range []string{full.String(), full.GoString(), fmt.Sprint(full), fmt.Sprintf("%+v", &full), fmt.Sprintf("%#v", full)} {
		if got != want {
			t.Errorf("rendered  %s\nwant      %s", got, want)
		}
	}
	absent := CRIDLink{Link: "https://qurl.link/#qv2t1.example"}
	const wantAbsent = `qurl.CRIDLink{Link:[REDACTED], QURLID:"", ExpiresAt:0001-01-01T00:00:00Z, ` +
		`ResourceCreatedAt:<nil>, Publisher:{Name:"", Verified:false}}`
	if got := absent.String(); got != wantAbsent {
		t.Errorf("rendered  %s\nwant      %s", got, wantAbsent)
	}
}

func TestParseCRIDLinkTime(t *testing.T) {
	for text, want := range map[string]time.Time{
		"":                               {},
		"2026-06-19T23:05:00Z":           time.Date(2026, 6, 19, 23, 5, 0, 0, time.UTC),
		"2026-06-19T23:05:00.123456789Z": time.Date(2026, 6, 19, 23, 5, 0, 123456789, time.UTC),
		"2026-06-19T16:05:00-07:00":      time.Date(2026, 6, 19, 23, 5, 0, 0, time.UTC),
		"2026-06-19 23:05:00Z":           {},
		"2026-06-19T23:05:00":            {},
		"1781910300":                     {},
		"not a time":                     {},
	} {
		got := parseCRIDLinkTime(text)
		if !got.Equal(want) || got.IsZero() != want.IsZero() {
			t.Errorf("parseCRIDLinkTime(%q) = %v, want %v", text, got, want)
		}
	}
}
