package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// These tests drive a CRID link request the way a caller does: through
// RequestCRIDLinkWith and OpenCRIDWith, against a peer that opens the real
// packet and seals a real reply. The pure pieces — the request gate, the body,
// the reply interpreter — have their own tests; these prove the pieces are
// actually wired together, which a unit test of each cannot show.

// TestCRIDLinkTestDerivationMatchesTheArtifact anchors the test-only CRID
// producer to the released CRID v1 fixtures. Tests below use it to build CRIDs
// the registry has no fixture for; if it drifted, they would be testing a
// derivation nobody else uses.
func TestCRIDLinkTestDerivationMatchesTheArtifact(t *testing.T) {
	held, matching, foreign := cridKeyMatchFixture(t)
	if got := testCRIDForKey(0x01, 32, matching); got != held {
		t.Fatalf("test derivation = %q, artifact pins %q", got, held)
	}
	if got := testCRIDForKey(0x01, 32, foreign); got == held {
		t.Fatal("test derivation gave the held CRID for a foreign key")
	}
	if err := crid.Validate(testCRIDForKey(0x81, 32, matching)); err != nil {
		t.Fatalf("derived test-environment CRID fails the local gate: %v", err)
	}
}

func TestRequestCRIDLinkWith_ReturnsAVerifiedLink(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("RequestCRIDLinkWith: %v", err)
	}
	if issued.Link != fixture.link {
		t.Fatal("the returned link is not the link the server issued")
	}
	if issued.QURLID != "q_a1b2c3d4e5f" {
		t.Fatalf("QURLID = %q", issued.QURLID)
	}
	if want := time.Date(2026, 6, 19, 23, 5, 0, 0, time.UTC); !issued.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", issued.ExpiresAt, want)
	}
	if want := time.Date(2026, 6, 18, 9, 30, 0, 0, time.UTC); issued.ResourceCreatedAt == nil || !issued.ResourceCreatedAt.Equal(want) {
		t.Fatalf("ResourceCreatedAt = %v, want %v", issued.ResourceCreatedAt, want)
	}
	if issued.Publisher != (Publisher{Name: "Example Publisher"}) {
		t.Fatalf("Publisher = %+v, want the self-declared name, unverified", issued.Publisher)
	}

	// The returned link is one the opener accepts for this CRID: requesting it
	// and verifying it are the same trust decision.
	if _, err := VerifyLinkForCRID(issued.Link, fixture.crid, fixture.cfg.TrustStore); err != nil {
		t.Fatalf("the returned link does not verify for the requested CRID: %v", err)
	}

	// What reached the cell is exactly one ordinary knock whose body names the
	// CRID and nothing else.
	knocks := fixture.peer.seen()
	if len(knocks) != 1 {
		t.Fatalf("the cell saw %d requests, want 1", len(knocks))
	}
	if knocks[0].headerType != relayknock.TypeKnock {
		t.Fatalf("request header type = %d, want NHP_KNK", knocks[0].headerType)
	}
	wantBody := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + fixture.crid + `"}}`
	if string(knocks[0].body) != wantBody {
		t.Fatalf("request body = %s\nwant           %s", knocks[0].body, wantBody)
	}
}

// An issued link has two forms: the link origin with a slash in front of the
// fragment, and without one. Both are accepted, and each comes back exactly as
// the server wrote it. Returning one form rewritten as the other would hand
// the caller a link the server never issued.
func TestRequestCRIDLinkWith_ReturnsEitherLinkFormAsIssued(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fragment := fixture.link[strings.IndexByte(fixture.link, '#')+1:]
	if fixture.link != cridLinkTestOrigin+"/#"+fragment {
		t.Fatal("fixture drift: the minted link is not the origin, a slash and the fragment")
	}
	for name, link := range map[string]string{
		"with the slash":    cridLinkTestOrigin + "/#" + fragment,
		"without the slash": cridLinkTestOrigin + "#" + fragment,
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(cridLinkIssued(t, link, fixture.info()))
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if err != nil {
				t.Fatalf("RequestCRIDLinkWith: %v", err)
			}
			if issued.Link != link {
				t.Fatal("the returned link is not the link the server issued, byte for byte")
			}
			// The opener accepts the same text for the same CRID.
			if _, err := VerifyLinkForCRID(issued.Link, fixture.crid, fixture.cfg.TrustStore); err != nil {
				t.Fatalf("the returned link does not verify for the requested CRID: %v", err)
			}
		})
	}
}

// TestRequestCRIDLinkWith_UsesAFreshKeyForEveryRequest pins the anonymity
// property of the request. The server decides on the CRID in the body, so the
// initiator key is a throwaway: two requests, even for the same CRID from the
// same process, must not be linkable by it.
func TestRequestCRIDLinkWith_UsesAFreshKeyForEveryRequest(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, nil))

	const requests = 4
	for range requests {
		if _, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg); err != nil {
			t.Fatal(err)
		}
	}
	knocks := fixture.peer.seen()
	if len(knocks) != requests {
		t.Fatalf("the cell saw %d requests, want %d", len(knocks), requests)
	}
	// The link's own key is the one identity that must NOT be used here: it
	// belongs to the second step, and the client does not hold it yet.
	fragment, err := VerifyLink(fixture.link, fixture.cfg.TrustStore)
	if err != nil {
		t.Fatal(err)
	}
	linkKey := mustDecode(t, fragment.Claims.QurlUserPublicKeyB64)
	for i, knock := range knocks {
		if len(knock.devicePub) != 32 || bytes.Equal(knock.devicePub, make([]byte, 32)) {
			t.Fatalf("request %d presented an unusable initiator key %x", i, knock.devicePub)
		}
		if bytes.Equal(knock.devicePub, linkKey) {
			t.Fatalf("request %d was sent under a link key", i)
		}
		for j := range i {
			if bytes.Equal(knock.devicePub, knocks[j].devicePub) {
				t.Fatalf("requests %d and %d were sent under the same initiator key", j, i)
			}
		}
	}
}

func TestRequestCRIDLinkWith_SendsTheConfiguredUserAgent(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, nil))
	fixture.cfg.CRIDLink.UserAgent = `example-tool/1.2 (a&b <c>)`

	if _, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg); err != nil {
		t.Fatal(err)
	}
	want := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + fixture.crid +
		`","qurl_user_agent":"example-tool/1.2 (a&b <c>)"}}`
	if got := string(fixture.peer.seen()[0].body); got != want {
		t.Fatalf("request body = %s\nwant           %s", got, want)
	}
}

// TestOpenCRIDWith_OpensTheResource is the whole feature end to end. A client
// that holds only a CRID asks for a link through the relay, checks it, and
// opens it over native UDP; the handle it gets is the handle EnterPortalWith
// returns for the same link, and it fetches the protected content.
func TestOpenCRIDWith_OpensTheResource(t *testing.T) {
	// The protected content admits only a request carrying the application
	// session the open returned.
	var admitted, refused atomic.Int32
	content := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie(qurlVsessionCookieName)
		if err != nil || cookie.Value != testAuthProviderToken {
			refused.Add(1)
			http.Error(w, "admission required", http.StatusForbidden)
			return
		}
		admitted.Add(1)
		_, _ = w.Write([]byte("protected content"))
	}))
	t.Cleanup(content.Close)
	resourceURL := content.URL + "/report"

	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, resourceURL)
	fixture.cfg.nativeUDPOptions = udp

	handle, err := OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("OpenCRIDWith: %v", err)
	}
	if handle.ResourceURL != resourceURL || handle.SessionID != 123 || handle.OpenSeconds != 900 {
		t.Fatalf("handle = %v", handle)
	}

	// Step 1 went through the relay under a throwaway key; step 2 went to the
	// cell under the issued link's own key. One of each, and not the same key.
	requests, opens := fixture.peer.seen(), admittedKeys()
	if len(requests) != 1 || len(opens) != 1 {
		t.Fatalf("link requests = %d, opens = %d, want 1 and 1", len(requests), len(opens))
	}
	if bytes.Equal(requests[0].devicePub, opens[0]) {
		t.Fatal("the link request and the open used the same initiator key")
	}

	// The end state is the one an ordinary open of that link reaches.
	direct := fixture.cfg
	direct.ExpectedCRID = fixture.crid
	viaLink, err := EnterPortalWith(t.Context(), fixture.link, direct)
	if err != nil {
		t.Fatalf("EnterPortalWith on the same link: %v", err)
	}
	if *viaLink != *handle {
		t.Fatalf("OpenCRIDWith handle = %v, EnterPortalWith handle = %v", handle, viaLink)
	}

	// And it is usable: the handle authorizes a request the content admits.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, handle.ResourceURL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.AuthorizeContentRequest(req); err != nil {
		t.Fatal(err)
	}
	client := content.Client()
	client.CheckRedirect = handle.CheckContentRedirect
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || admitted.Load() != 1 || refused.Load() != 0 {
		t.Fatalf("content status = %d, admitted = %d, refused = %d", resp.StatusCode, admitted.Load(), refused.Load())
	}
}

// TestOpenCRIDWith_DoesNotOpenWhenTheRequestFails pins that the second step is
// reached only through a verified link: a refusal, a rejected link, and a
// transport fault each stop before any open knock is sent.
func TestOpenCRIDWith_DoesNotOpenWhenTheRequestFails(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp

	for name, tc := range map[string]struct {
		answer cridLinkAnswer
		want   error
	}{
		"refused":       {cridLinkDenied(t, "52602"), ErrCRIDLinkNotFound},
		"rejected link": {cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil), ErrCRIDLinkRejected},
		"relay fault":   {cridLinkAnswer{status: http.StatusBadGateway, text: "upstream unavailable"}, nil},
		"busy":          {cridLinkAnswer{replyType: relayknock.TypeCookieChallenge}, ErrServerOverloaded},
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(tc.answer)
			handle, err := OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg)
			if handle != nil || err == nil {
				t.Fatalf("OpenCRIDWith = %v, %v; want no handle and an error", handle, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if got := len(admittedKeys()); got != 0 {
				t.Fatalf("%d open knocks were sent although no link was accepted", got)
			}
		})
	}
}

// TestOpenIssuedCRIDLink_BindsTheOpenToTheCRID pins the second half of an open
// by CRID on its own. The open is bound to the CRID independently of the
// request that fetched the link: handed a genuine link for another resource,
// it refuses before any knock, exactly as EnterPortalForCRID does.
func TestOpenIssuedCRIDLink_BindsTheOpenToTheCRID(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	relay := &refusingDoer{t: t}
	fixture.cfg.HTTPClient = relay
	resolver, dialer := new(portalNoIOResolver), new(portalNoIODialer)
	fixture.cfg.nativeUDPOptions = &nativeudp.Options{Resolver: resolver, Dialer: dialer}

	foreign := fixture.mint(t, fixture.foreignKey)
	handle, err := openIssuedCRIDLink(t.Context(), foreign, fixture.crid, fixture.cfg)
	if handle != nil || !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("openIssuedCRIDLink(link for another resource) = %v, %v; want ErrCRIDMismatch", handle, err)
	}
	if relay.called || resolver.calls.Load() != 0 || dialer.calls.Load() != 0 {
		t.Fatal("an open bound to the wrong CRID reached the network")
	}

	// A pin the caller put in the config does not survive: the CRID of the
	// call is the binding.
	fixture.cfg.ExpectedCRID = testCRIDForKey(0x01, 32, fixture.foreignKey)
	if _, err := openIssuedCRIDLink(t.Context(), foreign, fixture.crid, fixture.cfg); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("a config pin overrode the CRID of the call: %v", err)
	}
}

func TestRequestCRIDLinkWith_EachRefusalIsItsOwnError(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	refusals := map[string]error{
		"52601": ErrCRIDLinkUnavailable,
		"52602": ErrCRIDLinkNotFound,
		"52603": ErrCRIDLinkRateLimited,
		"52604": ErrCRIDResourceOffline,
		"52605": ErrCRIDResourceClosed,
		"52606": ErrInvalidCRIDLinkRequest,
	}
	for code, want := range refusals {
		t.Run(code, func(t *testing.T) {
			fixture.peer.respond(cridLinkDenied(t, code))
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if issued != nil {
				t.Fatal("a refusal returned a link")
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			// Exactly one of the six: a caller's switch must not match two.
			for otherCode, other := range refusals {
				if otherCode != code && errors.Is(err, other) {
					t.Fatalf("code %s also matches the error for %s", code, otherCode)
				}
			}
			// Every refusal is also the generic authenticated deny, with its code.
			var deny *ServerDenyError
			if !errors.As(err, &deny) || deny.ErrCode != code {
				t.Fatalf("refusal %s is not a *ServerDenyError carrying its code: %v", code, err)
			}
			for _, notThis := range []error{ErrCRIDLinkProtocol, ErrCRIDLinkRejected, ErrServerOverloaded, ErrMalformedReply} {
				if errors.Is(err, notThis) {
					t.Fatalf("refusal %s also matches %v", code, notThis)
				}
			}
		})
	}
}

// A refusal that carries a link is still the refusal. The link is perfectly
// valid here, which is the point: only the link-issued code makes it usable.
func TestRequestCRIDLinkWith_ARefusalThatCarriesALinkIsTheRefusal(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, "52602", map[string]any{
		"redirectUrl": fixture.link, "redirectInfo": fixture.info(),
	})})
	issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
	if issued != nil || !errors.Is(err, ErrCRIDLinkNotFound) {
		t.Fatalf("RequestCRIDLinkWith = %v, %v; want ErrCRIDLinkNotFound and no link", issued, err)
	}
}

func TestRequestCRIDLinkWith_UnknownCodesAreAGenericDeny(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	for _, code := range []string{"52607", "52004", "52599", "1"} {
		t.Run(code, func(t *testing.T) {
			// With a valid link attached: an unknown code never yields one.
			fixture.peer.respond(cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, code, map[string]any{
				"redirectUrl": fixture.link,
			})})
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			var deny *ServerDenyError
			if issued != nil || !errors.As(err, &deny) || deny.ErrCode != code {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want a *ServerDenyError carrying %q", issued, err, code)
			}
			for _, sentinel := range []error{
				ErrCRIDLinkUnavailable, ErrCRIDLinkNotFound, ErrCRIDLinkRateLimited, ErrCRIDResourceOffline,
				ErrCRIDResourceClosed, ErrInvalidCRIDLinkRequest, ErrCRIDLinkProtocol, ErrCRIDLinkRejected,
			} {
				if errors.Is(err, sentinel) {
					t.Fatalf("unknown code %s matches %v", code, sentinel)
				}
			}
		})
	}
}

func TestRequestCRIDLinkWith_CookieReplyIsBusy(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	// The cookie reply's body is not read, whatever it holds. Here it holds a
	// complete link-issued answer, and the request counter is not echoed.
	issuedBody := cridLinkIssued(t, fixture.link, fixture.info()).body
	for name, answer := range map[string]cridLinkAnswer{
		"empty body":             {replyType: relayknock.TypeCookieChallenge},
		"body that issues":       {replyType: relayknock.TypeCookieChallenge, body: issuedBody},
		"counter does not match": {replyType: relayknock.TypeCookieChallenge, body: issuedBody, counterSkew: 7},
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(answer)
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if issued != nil || !errors.Is(err, ErrServerOverloaded) {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want ErrServerOverloaded and no link", issued, err)
			}
			if errors.Is(err, ErrCRIDLinkProtocol) || errors.Is(err, ErrMalformedReply) {
				t.Fatalf("a busy server was reported as a malformed reply: %v", err)
			}
		})
	}
}

func TestRequestCRIDLinkWith_ProtocolViolations(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	issued := cridLinkIssued(t, fixture.link, fixture.info()).body

	withCode := func(code string) []byte {
		t.Helper()
		var ack map[string]json.RawMessage
		if err := json.Unmarshal(issued, &ack); err != nil {
			t.Fatal(err)
		}
		if code == "" {
			delete(ack, "errCode")
		} else {
			ack["errCode"] = json.RawMessage(code)
		}
		body, err := json.Marshal(ack)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	// Each body is the link-issued answer with nothing wrong but its code, so a
	// client that trusted any of them would hand out a valid link.
	for name, body := range map[string][]byte{
		"success code":              withCode(`"0"`),
		"empty code":                withCode(`""`),
		"missing code":              withCode(""),
		"numeric code":              withCode(`52600`),
		"null code":                 withCode(`null`),
		"boolean code":              withCode(`true`),
		"array code":                withCode(`["52600"]`),
		"padded code":               withCode(`" 52600"`),
		"code that is not a number": withCode(`"link issued"`),
		"body is an array":          []byte(`[` + string(issued) + `]`),
		"body is a string":          []byte(`"52600"`),
		"body is null":              []byte(`null`),
		"body is not JSON":          []byte(`{"errCode":"52600"`),
		"body repeats a member":     []byte(`{"errCode":"52602","errCode":"52600","redirectUrl":"` + fixture.link + `"}`),
		"trailing data":             append(bytes.Clone(issued), []byte(`{"errCode":"52600"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(cridLinkAnswer{replyType: relayknock.TypeACK, body: body})
			link, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if link != nil || !errors.Is(err, ErrCRIDLinkProtocol) {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want ErrCRIDLinkProtocol and no link", link, err)
			}
			if !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("a protocol violation must also match ErrMalformedReply: %v", err)
			}
			var deny *ServerDenyError
			if errors.As(err, &deny) || errors.Is(err, ErrCRIDLinkRejected) {
				t.Fatalf("a protocol violation was reported as a deny or a rejected link: %v", err)
			}
		})
	}

	// An ACK with no body at all has no code either.
	t.Run("empty body", func(t *testing.T) {
		fixture.peer.respond(cridLinkAnswer{replyType: relayknock.TypeACK})
		link, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
		if link != nil || !errors.Is(err, ErrCRIDLinkProtocol) {
			t.Fatalf("RequestCRIDLinkWith = %v, %v; want ErrCRIDLinkProtocol", link, err)
		}
	})
}

// A reply that is authentic but is not an answer to this request is a
// transport fault: not a link, not a refusal, and not a protocol violation.
func TestRequestCRIDLinkWith_OtherRepliesAreTransportFaults(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	issuedBody := cridLinkIssued(t, fixture.link, fixture.info()).body
	for name, answer := range map[string]cridLinkAnswer{
		"list result":             {replyType: relayknock.TypeListResult, body: issuedBody},
		"register ack":            {replyType: relayknock.TypeRegisterAck, body: issuedBody},
		"unknown type":            {unknownType: 99, body: issuedBody},
		"ack for another request": {replyType: relayknock.TypeACK, body: issuedBody, counterSkew: 1},
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(answer)
			link, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if link != nil || !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want ErrMalformedReply and no link", link, err)
			}
			if errors.Is(err, ErrCRIDLinkProtocol) || errors.Is(err, ErrServerOverloaded) || errors.Is(err, ErrCRIDLinkRejected) {
				t.Fatalf("a foreign reply was given a client result: %v", err)
			}
			var deny *ServerDenyError
			if errors.As(err, &deny) {
				t.Fatalf("a foreign reply was reported as a deny: %v", err)
			}
		})
	}
}

func TestRequestCRIDLinkWith_RejectsALinkThatFailsACheck(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fragment := fixture.link[strings.IndexByte(fixture.link, '#')+1:]
	canonical, err := decodeTransportFragment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	// The same link with one character of its signature changed: still a
	// well-formed signature, no longer this issuer's.
	cut := strings.LastIndexByte(fragment, '.') + 1
	swap := "A"
	if fragment[cut] == 'A' {
		swap = "B"
	}
	tampered := fragment[:cut] + swap + fragment[cut+1:]

	otherSigner, _ := mintSigner(t)
	untrusted, err := CreatePortalWithParams(t.Context(), otherSigner, CreateParams{
		CellPublicKey: fixture.peer.serverKey.PublicKey().Bytes(), RelayURL: fixture.peer.server.URL,
		ResourcePublicKey: fixture.resourceKey, JTI: "qurl_01JUNTRUSTEDISSUER",
		IssuedAt: 1781910000, NotBefore: 1781910000, Expiry: 1781910300,
	})
	if err != nil {
		t.Fatal(err)
	}
	siblingCRID := testCRIDForKey(0x81, 32, fixture.resourceKey)
	info := func(echo any) map[string]any {
		m := fixture.info()
		m["crid"] = echo
		return m
	}

	for _, tc := range []struct {
		name  string
		link  any
		info  any
		class CRIDLinkRejectClass
		also  error // an existing sentinel the rejection must match too
	}{
		{"link absent", nil, fixture.info(), CRIDLinkRejectMissingRedirect, nil},
		{"link empty", "", fixture.info(), CRIDLinkRejectMissingRedirect, nil},
		{"link is an array", []any{fixture.link}, fixture.info(), CRIDLinkRejectMissingRedirect, nil},
		{"link is a number", 7, fixture.info(), CRIDLinkRejectMissingRedirect, nil},

		{"lookalike host", "https://qurl.link.example.com/#" + fragment, fixture.info(), CRIDLinkRejectOrigin, nil},
		{"http scheme", "http://qurl.link/#" + fragment, fixture.info(), CRIDLinkRejectOrigin, nil},
		{"another port", "https://qurl.link:8443/#" + fragment, fixture.info(), CRIDLinkRejectOrigin, nil},
		{"userinfo", "https://user@qurl.link/#" + fragment, fixture.info(), CRIDLinkRejectOrigin, nil},
		{"origin as userinfo", "https://qurl.link@example.com/#" + fragment, fixture.info(), CRIDLinkRejectOrigin, nil},

		{"path", "https://qurl.link/open#" + fragment, fixture.info(), CRIDLinkRejectPathOrQuery, nil},
		{"query", "https://qurl.link/?next=open#" + fragment, fixture.info(), CRIDLinkRejectPathOrQuery, nil},

		{"canonical body as fragment", "https://qurl.link/#" + canonical, fixture.info(), CRIDLinkRejectTransport, ErrFragment},
		{"no fragment", "https://qurl.link/", fixture.info(), CRIDLinkRejectTransport, ErrFragment},
		{"empty fragment", "https://qurl.link/#", fixture.info(), CRIDLinkRejectTransport, ErrFragment},

		{"tampered signature", "https://qurl.link/#" + tampered, fixture.info(), CRIDLinkRejectIssuerSignature, ErrSignature},
		{"issuer the trust store does not know", untrusted, fixture.info(), CRIDLinkRejectIssuerSignature, ErrUnknownKID},

		{"link for another resource", fixture.mint(t, fixture.foreignKey), fixture.info(), CRIDLinkRejectCRIDMismatch, ErrCRIDMismatch},

		{"echo of another CRID", fixture.link, info(siblingCRID), CRIDLinkRejectInfoCRIDMismatch, ErrCRIDMismatch},
		{"echo is a number", fixture.link, info(0), CRIDLinkRejectInfoCRIDMismatch, ErrCRIDMismatch},
		{"echo is null", fixture.link, info(nil), CRIDLinkRejectInfoCRIDMismatch, ErrCRIDMismatch},
		{"echo is an object", fixture.link, info(map[string]any{"value": fixture.crid}), CRIDLinkRejectInfoCRIDMismatch, ErrCRIDMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := cridLinkIssued(t, tc.link, tc.info)
			if tc.link == nil {
				// Absent, not null: the member is left out of the body.
				answer = cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, cridLinkCodeIssued, map[string]any{
					"redirectInfo": tc.info,
				})}
			}
			fixture.peer.respond(answer)

			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if issued != nil {
				t.Fatal("a link that failed a check was returned")
			}
			if !errors.Is(err, ErrCRIDLinkRejected) {
				t.Fatalf("error = %v, want ErrCRIDLinkRejected", err)
			}
			var rejected *CRIDLinkRejectedError
			if !errors.As(err, &rejected) || rejected.Class != tc.class {
				t.Fatalf("reject class = %v, want %q (error %v)", rejected, tc.class, err)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Fatalf("a %q rejection must also match %v: %v", tc.class, tc.also, err)
			}
			// The sentinel is the opener's own verdict on the same link, which is
			// what lets code written for VerifyLinkForCRID keep working. The
			// echo cases are left out: their fault is in the reply, not the link.
			if link, isString := tc.link.(string); isString && tc.also != nil && tc.class != CRIDLinkRejectInfoCRIDMismatch {
				if _, verifyErr := VerifyLinkForCRID(link, fixture.crid, fixture.cfg.TrustStore); !errors.Is(verifyErr, tc.also) {
					t.Fatalf("VerifyLinkForCRID reports %v for this link, not %v", verifyErr, tc.also)
				}
			}
			// The message is the class and nothing from the reply.
			if want := "qurl: issued CRID link rejected: " + string(tc.class) + " check failed"; err.Error() != want {
				t.Fatalf("error text = %q, want %q", err.Error(), want)
			}
			var deny *ServerDenyError
			if errors.As(err, &deny) || errors.Is(err, ErrCRIDLinkProtocol) {
				t.Fatalf("a rejected link was reported as a deny or a protocol violation: %v", err)
			}
		})
	}

	// null is not absent: a null link is a missing redirect, like any non-string.
	t.Run("link is null", func(t *testing.T) {
		fixture.peer.respond(cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, cridLinkCodeIssued, map[string]any{
			"redirectUrl": nil, "redirectInfo": fixture.info(),
		})})
		_, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
		var rejected *CRIDLinkRejectedError
		if !errors.As(err, &rejected) || rejected.Class != CRIDLinkRejectMissingRedirect {
			t.Fatalf("error = %v, want a missing_redirect rejection", err)
		}
	})
}

// TestRequestCRIDLinkWith_AcceptsTheTestEnvironmentCRID pins that check 6 uses
// the requested CRID's own version: the same resource key has a CRID under
// every active version, and each of them accepts the link — when it is the one
// that was asked for.
func TestRequestCRIDLinkWith_AcceptsTheTestEnvironmentCRID(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	sibling := testCRIDForKey(0x81, 32, fixture.resourceKey)
	info := fixture.info()
	info["crid"] = sibling
	fixture.peer.respond(cridLinkIssued(t, fixture.link, info))

	issued, err := RequestCRIDLinkWith(t.Context(), sibling, fixture.cfg)
	if err != nil || issued == nil || issued.Link != fixture.link {
		t.Fatalf("RequestCRIDLinkWith(test-environment CRID) = %v, %v", issued, err)
	}
	if got := string(fixture.peer.seen()[0].body); !strings.Contains(got, `"qurl_crid":"`+sibling+`"`) {
		t.Fatalf("the request did not name the CRID that was asked for: %s", got)
	}
}

// TestCRIDLinkRequest_NeverPutsTheLinkInAnErrorOrALog is the confidentiality
// fence. Every reply here carries a real link — sometimes a valid one — and
// ends in an error. No error text, at any depth of the chain, and nothing the
// standard loggers received, may contain the link or the secret inside it.
func TestCRIDLinkRequest_NeverPutsTheLinkInAnErrorOrALog(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fragment := fixture.link[strings.IndexByte(fixture.link, '#')+1:]
	parsed, err := VerifyLink(fixture.link, fixture.cfg.TrustStore)
	if err != nil {
		t.Fatal(err)
	}
	foreign := fixture.mint(t, fixture.foreignKey)
	foreignFragment := foreign[strings.IndexByte(foreign, '#')+1:]

	// Every sink the standard library offers a careless Printf. The buffer is
	// locked because the test servers may log from their own goroutines.
	logged := new(lockedBuffer)
	priorWriter, priorFlags, priorSlog := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(logged)
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		// Installing a slog handler also redirects the log package and clears
		// its flags; putting the default logger back restores neither.
		slog.SetDefault(priorSlog)
		log.SetOutput(priorWriter)
		log.SetFlags(priorFlags)
	})

	secrets := map[string]string{
		"link":                  fixture.link,
		"fragment":              fragment,
		"secret block":          parsed.SecretB64,
		"private key":           parsed.Secret.QurlUserPrivateKeyB64,
		"signature":             parsed.SigB64,
		"claims":                parsed.ClaimsB64,
		"foreign link":          foreign,
		"foreign link fragment": foreignFragment,
	}
	assertClean := func(t *testing.T, what, text string) {
		t.Helper()
		for name, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains the %s", what, name)
			}
		}
		// A long run of the link's transport is as good as the link.
		if strings.Contains(text, "qv2t1.") || strings.Contains(text, "#qv2") {
			t.Fatalf("%s contains link transport text: %s", what, text)
		}
	}

	udp, _ := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp

	answers := map[string]cridLinkAnswer{
		"refusal with a link":      {replyType: relayknock.TypeACK, body: cridLinkACK(t, "52602", map[string]any{"redirectUrl": fixture.link})},
		"unknown code with a link": {replyType: relayknock.TypeACK, body: cridLinkACK(t, "52607", map[string]any{"redirectUrl": fixture.link})},
		"success code with a link": {replyType: relayknock.TypeACK, body: cridLinkACK(t, "0", map[string]any{"redirectUrl": fixture.link})},
		// The code position is where a careless error would echo it.
		"link in the code":       {replyType: relayknock.TypeACK, body: cridLinkACK(t, fixture.link, nil)},
		"link in the message":    {replyType: relayknock.TypeACK, body: cridLinkACK(t, "52601", map[string]any{"errMsg": fixture.link})},
		"link for another CRID":  cridLinkIssued(t, foreign, nil),
		"link on another origin": cridLinkIssued(t, "https://example.com/#"+fragment, nil),
		"link with a path":       cridLinkIssued(t, "https://qurl.link/x#"+fragment, nil),
		"link as an array":       cridLinkIssued(t, []any{fixture.link}, nil),
		"echo names another":     cridLinkIssued(t, fixture.link, map[string]any{"crid": fixture.link}),
		"busy with a link":       {replyType: relayknock.TypeCookieChallenge, body: cridLinkIssued(t, fixture.link, nil).body},
		"foreign reply type":     {replyType: relayknock.TypeListResult, body: cridLinkIssued(t, fixture.link, nil).body},
		"relay fault":            {status: http.StatusBadGateway, text: "upstream failed"},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(answer)
			for _, call := range []struct {
				name string
				run  func() error
			}{
				{"RequestCRIDLinkWith", func() error {
					issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
					if issued != nil {
						t.Fatal("a failing reply returned a link")
					}
					return err
				}},
				{"OpenCRIDWith", func() error {
					handle, err := OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg)
					if handle != nil {
						t.Fatal("a failing reply opened the resource")
					}
					return err
				}},
			} {
				err := call.run()
				if err == nil {
					t.Fatalf("%s succeeded on a reply that must fail", call.name)
				}
				// The message, the Go-syntax and verbose forms, and every error
				// in the chain, however it is reached.
				assertClean(t, call.name+" error", err.Error())
				assertClean(t, call.name+" %+v", fmt.Sprintf("%+v", err))
				assertClean(t, call.name+" %#v", fmt.Sprintf("%#v", err))
				walkErrorChain(err, func(inner error) {
					assertClean(t, call.name+" wrapped error", inner.Error())
					assertClean(t, call.name+" wrapped %#v", fmt.Sprintf("%#v", inner))
				})
			}
		})
	}

	// A success must not log the link either, and the result must not print it.
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
	issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The verbs the documentation names, on the pointer the calls return and on
	// the value a caller may have copied out of it.
	for _, rendered := range []string{
		fmt.Sprint(issued), fmt.Sprintf("%v", issued), fmt.Sprintf("%+v", issued), fmt.Sprintf("%#v", issued),
		fmt.Sprintf("issued=%s", issued),
		fmt.Sprint(*issued), fmt.Sprintf("%v", *issued), fmt.Sprintf("%+v", *issued), fmt.Sprintf("%#v", *issued),
		fmt.Sprintf("issued=%s", *issued), issued.String(), issued.GoString(),
		// As an exported field of a caller's own type, where fmt still finds
		// the methods.
		fmt.Sprintf("%+v", struct{ Issued *CRIDLink }{issued}), fmt.Sprintf("%v", struct{ Issued CRIDLink }{*issued}),
	} {
		assertClean(t, "a formatted CRIDLink", rendered)
		if !strings.Contains(rendered, "[REDACTED]") || !strings.Contains(rendered, `"Example Publisher"`) {
			t.Fatalf("formatted CRIDLink = %s", rendered)
		}
	}
	if handle, err := OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg); err != nil {
		t.Fatal(err)
	} else {
		assertClean(t, "a formatted ResourceHandle", fmt.Sprintf("%v %+v %#v", handle, handle, handle))
	}

	assertClean(t, "the log output", logged.String())
}

// lockedBuffer is a bytes.Buffer that is safe to write from one goroutine and
// read from another.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// walkErrorChain visits every error reachable from err through Unwrap, in
// both its single and its multiple form.
func walkErrorChain(err error, visit func(error)) {
	if err == nil {
		return
	}
	visit(err)
	switch unwrapped := err.(type) { //nolint:errorlint // walking the chain by hand is the point
	case interface{ Unwrap() error }:
		walkErrorChain(unwrapped.Unwrap(), visit)
	case interface{ Unwrap() []error }:
		for _, inner := range unwrapped.Unwrap() {
			walkErrorChain(inner, visit)
		}
	}
}

func TestRequestCRIDLinkWith_RelayHTTPErrors(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	for _, status := range []int{
		http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge,
		http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture.peer.respond(cridLinkAnswer{status: status, text: "relay could not forward"})
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			var relayErr *RelayError
			if issued != nil || !errors.As(err, &relayErr) || relayErr.Status != status {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want a *RelayError with status %d", issued, err, status)
			}
			// A relay fault is not an answer from the server: none of the
			// outcomes of a request may match it.
			var deny *ServerDenyError
			if errors.As(err, &deny) {
				t.Fatalf("a relay fault was reported as a server deny: %v", err)
			}
			for _, outcome := range []error{
				ErrCRIDLinkUnavailable, ErrCRIDLinkNotFound, ErrCRIDLinkRateLimited, ErrCRIDResourceOffline,
				ErrCRIDResourceClosed, ErrInvalidCRIDLinkRequest, ErrCRIDLinkProtocol, ErrCRIDLinkRejected,
				ErrServerOverloaded, ErrMalformedReply, ErrCRIDLinkNotConfigured,
			} {
				if errors.Is(err, outcome) {
					t.Fatalf("relay status %d matches %v", status, outcome)
				}
			}
		})
	}
}

// TestRequestCRIDLinkWith_AnAnswerThatDoesNotAuthenticateIsNotRead pins what
// makes the relay untrusted. Whatever a relay sends back with a 200, it is an
// answer only if it authenticates as the reply of the cell the request was
// sealed to. Anything else is an error that is none of the request's outcomes,
// and its content is never read: not even a complete, valid link.
func TestRequestCRIDLinkWith_AnAnswerThatDoesNotAuthenticateIsNotRead(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp
	fragment := fixture.link[strings.IndexByte(fixture.link, '#')+1:]

	impostor, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// What a relay that makes up an answer can do at best: a well-formed
	// link-issued reply for the requested CRID, carrying a link that would pass
	// every check, sealed to the right initiator and echoing the right counter,
	// under a key that is not the cell's.
	forged := cridLinkIssued(t, fixture.link, fixture.info())
	forged.sealedBy = impostor.Bytes()

	body := func(content []byte) HTTPDoer {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(bytes.NewReader(content)),
			}, nil
		})
	}
	for name, client := range map[string]HTTPDoer{
		"empty body":                          body(nil),
		"bytes that are not a packet":         body(bytes.Repeat([]byte{0x41}, 400)),
		"the link itself as the body":         body([]byte(fixture.link)),
		"a link-issued answer by another key": fixture.peer.server.Client(),
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respond(forged)
			cfg := fixture.cfg
			cfg.HTTPClient = client

			issued, requestErr := RequestCRIDLinkWith(t.Context(), fixture.crid, cfg)
			handle, openErr := OpenCRIDWith(t.Context(), fixture.crid, cfg)
			if issued != nil || handle != nil {
				t.Fatal("an answer that does not authenticate was used")
			}
			for call, err := range map[string]error{"RequestCRIDLinkWith": requestErr, "OpenCRIDWith": openErr} {
				if err == nil {
					t.Fatalf("%s succeeded on an answer that does not authenticate", call)
				}
				// None of the request's outcomes, and not a relay fault either:
				// the relay did answer.
				var deny *ServerDenyError
				var relayErr *RelayError
				if errors.As(err, &deny) || errors.As(err, &relayErr) {
					t.Fatalf("%s: an unauthenticated answer was reported as %v", call, err)
				}
				for _, outcome := range []error{
					ErrCRIDLinkUnavailable, ErrCRIDLinkNotFound, ErrCRIDLinkRateLimited, ErrCRIDResourceOffline,
					ErrCRIDResourceClosed, ErrInvalidCRIDLinkRequest, ErrCRIDLinkProtocol, ErrCRIDLinkRejected,
					ErrServerOverloaded, ErrMalformedReply, ErrCRIDLinkNotConfigured,
				} {
					if errors.Is(err, outcome) {
						t.Fatalf("%s: an unauthenticated answer matches %v: %v", call, outcome, err)
					}
				}
				if text := fmt.Sprintf("%v %+v %#v", err, err, err); strings.Contains(text, fragment) || strings.Contains(text, "qv2t1.") {
					t.Fatalf("%s: the error carries the link from an answer that was never authenticated", call)
				}
			}
		})
	}
	if got := len(admittedKeys()); got != 0 {
		t.Fatalf("%d open knocks were sent on the strength of an unauthenticated answer", got)
	}
}

// roundTripFunc is an HTTPDoer from a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestRequestCRIDLinkWith_ContextCancellationAndTimeout(t *testing.T) {
	fixture := newCRIDLinkFixture(t)

	t.Run("already canceled", func(t *testing.T) {
		fixture.peer.respond(cridLinkIssued(t, fixture.link, nil))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkWith(ctx, fixture.crid, fixture.cfg)
		if issued != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestCRIDLinkWith = %v, %v; want context.Canceled", issued, err)
		}
		if got := len(fixture.peer.seen()); got != before {
			t.Fatalf("a canceled request still reached the cell (%d new requests)", got-before)
		}
	})

	t.Run("canceled while the relay is silent", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		arrived := make(chan struct{}, 1)
		fixture.peer.respondWith(func(cridLinkKnock) cridLinkAnswer {
			arrived <- struct{}{}
			return cridLinkAnswer{hold: release}
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			<-arrived
			cancel()
		}()
		issued, err := RequestCRIDLinkWith(ctx, fixture.crid, fixture.cfg)
		if issued != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestCRIDLinkWith = %v, %v; want context.Canceled", issued, err)
		}
		// The transport fault it surfaced as is still there for a caller that
		// wants it, and it is not mistaken for anything the server said.
		var relayErr *RelayError
		if !errors.As(err, &relayErr) || relayErr.Status != 0 {
			t.Fatalf("a canceled request lost its transport fault: %v", err)
		}
		if errors.Is(err, ErrServerOverloaded) || errors.Is(err, ErrMalformedReply) {
			t.Fatalf("a cancellation was reported as a server outcome: %v", err)
		}
	})

	t.Run("deadline while the relay is silent", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		fixture.peer.respond(cridLinkAnswer{hold: release})
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer cancel()
		started := time.Now()
		issued, err := RequestCRIDLinkWith(ctx, fixture.crid, fixture.cfg)
		if issued != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RequestCRIDLinkWith = %v, %v; want context.DeadlineExceeded", issued, err)
		}
		if waited := time.Since(started); waited > 5*time.Second {
			t.Fatalf("the request outlived its deadline by far: %v", waited)
		}
	})

	// The response has begun — status 200 and part of a body — and the reply
	// never arrives. The request still ended with the caller's context, and the
	// error still says so. The context is canceled from inside the client, once
	// the status line is in hand, so the test does not depend on timing.
	t.Run("canceled while the reply body is being read", func(t *testing.T) {
		release := make(chan struct{})
		stalled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "400")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, 100))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(func() {
			close(release)
			stalled.Close()
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cfg := fixture.cfg
		endpoint := *fixture.cfg.CRIDLink
		endpoint.RelayURL = stalled.URL
		cfg.CRIDLink = &endpoint
		cfg.RelayAllowlist = NewRelayAllowlist([]string{strings.TrimPrefix(stalled.URL, "https://")})
		cfg.HTTPClient = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := stalled.Client().Do(req)
			cancel() // after the status line, before the body
			return resp, err
		})

		issued, err := RequestCRIDLinkWith(ctx, fixture.crid, cfg)
		if issued != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestCRIDLinkWith = %v, %v; want context.Canceled", issued, err)
		}
		var relayErr *RelayError
		if !errors.As(err, &relayErr) || relayErr.Status != http.StatusOK {
			t.Fatalf("error = %v, want the transport fault of a 200 whose body could not be read", err)
		}
		if errors.Is(err, ErrServerOverloaded) || errors.Is(err, ErrMalformedReply) {
			t.Fatalf("a cancellation was reported as a server outcome: %v", err)
		}
	})

	// A relay that did answer keeps its own status even when the context has
	// ended by the time the answer is read: the caller is told what happened.
	t.Run("an answered request is not rewritten as a cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fixture.cfg.HTTPClient = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := fixture.peer.server.Client().Do(req)
			cancel() // the context ends after the response has arrived
			return resp, err
		})
		fixture.peer.respond(cridLinkAnswer{status: http.StatusBadGateway, text: "upstream unavailable"})
		_, err := RequestCRIDLinkWith(ctx, fixture.crid, fixture.cfg)
		var relayErr *RelayError
		if !errors.As(err, &relayErr) || relayErr.Status != http.StatusBadGateway {
			t.Fatalf("error = %v, want the relay's 502", err)
		}
		if errors.Is(err, context.Canceled) {
			t.Fatalf("a relay answer was reported as the caller's cancellation: %v", err)
		}
	})
}

func TestCRIDLinkRequest_RefusesAnUnusableCRIDBeforeAnyIO(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	doer := &refusingDoer{t: t}
	fixture.cfg.HTTPClient = doer

	// A provider that fails the test if it is consulted: the one-argument
	// calls must refuse before they resolve configuration, because resolving
	// may itself be network I/O.
	resolved := 0
	installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
		resolved++
		return nil, nil, errors.New("configuration must not be resolved for an unusable CRID")
	}))

	oneChanged := []byte(fixture.crid)
	if oneChanged[20] == 'b' {
		oneChanged[20] = 'c'
	} else {
		oneChanged[20] = 'b'
	}
	// The last character carries pad bits that must be zero.
	nonCanonical := fixture.crid[:len(fixture.crid)-1] + "b"

	for _, tc := range []struct {
		name string
		crid string
		want error
	}{
		{"empty", "", crid.ErrLength},
		{"one character short", fixture.crid[:59], crid.ErrLength},
		{"one character long", fixture.crid + "a", crid.ErrLength},
		{"upper case", strings.ToUpper(fixture.crid), crid.ErrCharset},
		{"surrounding space", " " + fixture.crid[1:], crid.ErrCharset},
		{"checksum", string(oneChanged), crid.ErrChecksum},
		{"nonzero pad bits", nonCanonical, crid.ErrNonCanonical},
		{"forbidden version", testCRIDForKey(0x00, 32, fixture.resourceKey), crid.ErrForbiddenVersion},
		{"unregistered version", testCRIDForKey(0x7f, 32, fixture.resourceKey), ErrUnsupportedCRIDVersion},
		{"reserved version 02", testCRIDForKey(0x02, 24, fixture.resourceKey), ErrUnsupportedCRIDVersion},
		{"reserved version 82", testCRIDForKey(0x82, 24, fixture.resourceKey), ErrUnsupportedCRIDVersion},
		{"active version at the short length", testCRIDForKey(0x01, 24, fixture.resourceKey), ErrUnsupportedCRIDVersion},
		{"a link instead of a CRID", fixture.link, crid.ErrCharset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, call := range map[string]func() error{
				"RequestCRIDLinkWith": func() error { _, err := RequestCRIDLinkWith(t.Context(), tc.crid, fixture.cfg); return err },
				"OpenCRIDWith":        func() error { _, err := OpenCRIDWith(t.Context(), tc.crid, fixture.cfg); return err },
				"RequestCRIDLink":     func() error { _, err := RequestCRIDLink(t.Context(), tc.crid); return err },
				"OpenCRID":            func() error { _, err := OpenCRID(t.Context(), tc.crid); return err },
			} {
				err := call()
				if !errors.Is(err, tc.want) {
					t.Fatalf("%s error = %v, want %v", name, err, tc.want)
				}
				if !errors.Is(err, ErrInvalidResourceRequest) {
					t.Fatalf("%s: a locally refused CRID must match ErrInvalidResourceRequest: %v", name, err)
				}
				// A local refusal is not the server's "invalid request".
				if errors.Is(err, ErrInvalidCRIDLinkRequest) || errors.Is(err, ErrCRIDLinkNotConfigured) {
					t.Fatalf("%s: a local refusal was reported as a server or configuration outcome: %v", name, err)
				}
			}
		})
	}
	if doer.called || len(fixture.peer.seen()) != 0 {
		t.Fatal("an unusable CRID caused network I/O")
	}
	if resolved != 0 {
		t.Fatalf("an unusable CRID caused configuration to be resolved %d times", resolved)
	}
}

// The versions the gate accepts are exactly the ones a link can be verified
// against, so the gate and check 6 can never disagree about a CRID.
func TestValidateCRIDForLinkRequest_AcceptsOnlyActiveVersions(t *testing.T) {
	_, key, _ := cridKeyMatchFixture(t)
	for _, tc := range []struct {
		version      byte
		digestLength int
		accept       bool
	}{
		{0x01, 32, true},
		{0x81, 32, true},
		{0x02, 24, false},
		{0x82, 24, false},
		{0x01, 24, false},
		{0x81, 24, false},
		{0x02, 32, false},
		{0x82, 32, false},
		{0x03, 32, false},
		{0x7f, 32, false},
		{0xff, 32, false},
		{0x7f, 24, false},
	} {
		value := testCRIDForKey(tc.version, tc.digestLength, key)
		if err := crid.Validate(value); err != nil {
			t.Fatalf("version %#02x/%d: fixture fails the local gate: %v", tc.version, tc.digestLength, err)
		}
		err := validateCRIDForLinkRequest(value)
		if tc.accept {
			if err != nil {
				t.Fatalf("version %#02x/%d refused: %v", tc.version, tc.digestLength, err)
			}
			// What the gate accepts, the link check can decide.
			if matched, matchErr := crid.KeyMatches(value, key); matchErr != nil || !matched {
				t.Fatalf("version %#02x/%d: the gate accepted a CRID its own key does not match", tc.version, tc.digestLength)
			}
			continue
		}
		if !errors.Is(err, ErrUnsupportedCRIDVersion) || !errors.Is(err, ErrInvalidResourceRequest) {
			t.Fatalf("version %#02x/%d: error = %v, want ErrUnsupportedCRIDVersion", tc.version, tc.digestLength, err)
		}
	}
}

func TestRequestCRIDLinkWith_RefusesAContradictingExpectedCRID(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	doer := &refusingDoer{t: t}
	fixture.cfg.HTTPClient = doer
	fixture.cfg.ExpectedCRID = testCRIDForKey(0x01, 32, fixture.foreignKey)

	if _, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("error = %v, want ErrCRIDMismatch", err)
	}
	if doer.called {
		t.Fatal("a contradicting pin still sent a request")
	}

	// The same CRID as the pin is not a contradiction.
	fixture.cfg.ExpectedCRID = fixture.crid
	fixture.cfg.HTTPClient = fixture.peer.server.Client()
	fixture.peer.respond(cridLinkIssued(t, fixture.link, nil))
	if _, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg); err != nil {
		t.Fatalf("a matching pin was refused: %v", err)
	}
}

func TestBuildCRIDLinkKnockBody_CanonicalForm(t *testing.T) {
	const value = "ae4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743ivbeyha"
	prefix := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + value + `"`

	for _, tc := range []struct {
		name      string
		userAgent string
		// sent is the user agent the body carries. It is empty when the member
		// is left out.
		sent string
		want string
	}{
		{"no user agent", "", "", prefix + `}}`},
		{"plain", "example-tool/1.2", "example-tool/1.2", prefix + `,"qurl_user_agent":"example-tool/1.2"}}`},
		// Only the quote and the backslash are escaped. The solidus and the
		// HTML characters are written as they are.
		{
			"escaping", `tool/1.0 "quoted" back\slash <tag> a&b /path`, `tool/1.0 "quoted" back\slash <tag> a&b /path`,
			prefix + `,"qurl_user_agent":"tool/1.0 \"quoted\" back\\slash <tag> a&b /path"}}`,
		},
		// Non-ASCII text is emitted as UTF-8, never as \u escapes.
		{"non-ASCII", "tool/1.0 (Zürich) 😀", "tool/1.0 (Zürich) 😀", prefix + `,"qurl_user_agent":"tool/1.0 (Zürich) 😀"}}`},
		// A user agent that holds a control character, U+2028 or U+2029 is
		// left out whole. Encoders write those characters in different ways,
		// so the body would not have one canonical form.
		{"control characters", "a\tb\nc", "", prefix + `}}`},
		{"every kind of control character", "\b\f\r\x00\x01\x1f\x7f", "", prefix + `}}`},
		{"line separators", "a\u2028b\u2029c", "", prefix + `}}`},
		{"a backslash in front of a line separator", `a\` + "\u2028" + `\\` + "\u2029", "", prefix + `}}`},
		// The six characters of a line separator escape, as text, are a
		// backslash and five letters. The value is sent, with the backslash
		// escaped, and nothing turns into a separator.
		{"a line separator escape as text", `a\u2028b\u2029c`, `a\u2028b\u2029c`, prefix + `,"qurl_user_agent":"a\\u2028b\\u2029c"}}`},
		// Their neighbours in the same block are ordinary characters.
		{"neighbours of the line separators", "\u2027\u202a", "\u2027\u202a", prefix + `,"qurl_user_agent":"` + "\u2027\u202a" + `"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := buildCRIDLinkKnockBody(value, tc.userAgent)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != tc.want {
				t.Fatalf("body = %s\nwant   %s", body, tc.want)
			}
			// The expectation above was written by hand. The independent
			// serializer agrees with it, which is what lets the fuzz target
			// use that serializer as its oracle.
			if reference := canonicalCRIDLinkKnockBody(value, tc.sent); reference != tc.want {
				t.Fatalf("the reference serializer disagrees with the pinned bytes\n got %s\nwant %s", reference, tc.want)
			}
			// And it is JSON that reads back as what was sent.
			var decoded cridLinkKnockMsg
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("the body is not JSON: %v", err)
			}
			if decoded.UsrData.CRID != value || decoded.UsrData.UserAgent != tc.sent ||
				decoded.HeaderType != relayknock.TypeKnock || decoded.AspID != "qurl" || decoded.ResID != "qurl-crid" {
				t.Fatalf("decoded body = %+v", decoded)
			}
		})
	}

	// The body names the CRID and nothing that belongs to a link-opening
	// knock, with or without a user agent.
	for _, userAgent := range []string{"", "example-tool/1.2"} {
		body, err := buildCRIDLinkKnockBody(value, userAgent)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			UsrData map[string]json.RawMessage `json:"usrData"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"qurl_access_token", claimsUserDataKey, sigUserDataKey, "qurl_passkey", visitorCapabilityUserDataKey,
		} {
			if _, present := decoded.UsrData[forbidden]; present {
				t.Fatalf("the request carries %s", forbidden)
			}
		}
		wantMembers := 1
		if userAgent != "" {
			wantMembers = 2
		}
		if len(decoded.UsrData) != wantMembers {
			t.Fatalf("the request carries %d user-data members, want %d", len(decoded.UsrData), wantMembers)
		}
	}
}

// canonicalCRIDLinkKnockBody is the canonical request body for a CRID and the
// user agent that is sent, written out from the definition of the canonical
// form and not through encoding/json. The request builder is compared with it
// so that the comparison does not share the builder's encoder.
func canonicalCRIDLinkKnockBody(resourceCRID, sentUserAgent string) string {
	body := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":` + canonicalJSONString(resourceCRID)
	if sentUserAgent != "" {
		body += `,"qurl_user_agent":` + canonicalJSONString(sentUserAgent)
	}
	return body + `}}`
}

// canonicalJSONString writes valid UTF-8 text as the JSON string the canonical
// form calls for, which is what JavaScript's JSON.stringify produces: the quote
// and the backslash are escaped, a control character is one of the five short
// escapes or \u00xx in lower-case hex, and everything else — DEL, the line
// separators, every non-ASCII character — is written as it is. A request never
// carries a control character, DEL or a line separator, so for a body the
// builder made only the first rule and the last are used.
func canonicalJSONString(text string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

// TestSentCRIDLinkUserAgent holds the user agent rule of the public vectors,
// which no vector case pins yet. A user agent that holds a control character
// (U+0000 to U+001F, or U+007F), U+2028 or U+2029 is left out whole. The whole
// value is looked at first, and only a value that may be sent is cut to the
// limit.
func TestSentCRIDLinkUserAgent(t *testing.T) {
	const limit = 256

	// Every character of the closed set, wherever it stands in the value.
	notSent := []rune{0x7f, 0x2028, 0x2029}
	for r := rune(0); r <= 0x1f; r++ {
		notSent = append(notSent, r)
	}
	if len(notSent) != 35 {
		t.Fatalf("the closed set has %d characters, want 35", len(notSent))
	}
	for _, r := range notSent {
		for position, userAgent := range map[string]string{
			"alone":  string(r),
			"first":  string(r) + "example-tool/1.2",
			"inside": "example-tool" + string(r) + "/1.2",
			"last":   "example-tool/1.2" + string(r),
		} {
			if got := sentCRIDLinkUserAgent(userAgent); got != "" {
				t.Errorf("U+%04X %s: sent %q, want the member left out", r, position, got)
			}
		}
	}

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "example-tool/1.2", "example-tool/1.2"},
		// The characters on each side of the closed set are sent as they are.
		// The set is the contract's: it has no other control character in it.
		{"space, the first character after the controls", "a b", "a b"},
		{"tilde, the character before DEL", "a~b", "a~b"},
		{"U+0080, the character after DEL", "a\u0080b", "a\u0080b"},
		{"U+009F, the last C1 control", "a\u009fb", "a\u009fb"},
		{"no-break space", "a\u00a0b", "a\u00a0b"},
		{"U+2027 and U+202A, around the separators", "\u2027\u202a", "\u2027\u202a"},
		// Text that only spells an escape holds none of the characters.
		{"escapes as text", `a\u2028b\tc\u0000`, `a\u2028b\tc\u0000`},

		// The order of the two rules. The whole value is looked at before it
		// is cut, so a character past the limit leaves the member out. Cutting
		// first would send the first 256 bytes of each of these.
		{"a tab just past the limit", strings.Repeat("a", limit) + "\t", ""},
		{"a line separator far past the limit", strings.Repeat("a", 280) + "\u2028" + strings.Repeat("a", 20), ""},
		{"DEL as the last of 300 bytes", strings.Repeat("a", 299) + "\x7f", ""},
		// The cut would fall inside this character and drop it whole. It is
		// still seen first.
		{"a paragraph separator across the limit", strings.Repeat("a", limit-1) + "\u2029", ""},
		// And a long value with none of the characters is cut, as before.
		{"long and clean", strings.Repeat("b", 300), strings.Repeat("b", limit)},
		{"long and clean, cut at a character boundary", strings.Repeat("c", 253) + "😀c", strings.Repeat("c", 253)},

		// Bytes that are not UTF-8 are replaced, as before, and are not one of
		// the characters. A control character next to them still is.
		{"invalid bytes", "ab\xffcd", "ab\ufffdcd"},
		{"invalid bytes and a control character", "ab\xff\x1fcd", ""},
		{"a control byte where a continuation byte belongs", "ab\xc3\x1fcd", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sentCRIDLinkUserAgent(tc.in)
			if got != tc.want {
				t.Fatalf("sent %d bytes %q\nwant %d bytes %q", len(got), got, len(tc.want), tc.want)
			}
			if len(got) > limit || !utf8.ValidString(got) || strings.ContainsFunc(got, cridLinkUserAgentRuneNotSent) {
				t.Fatalf("the sent user agent %q breaks the rules for what is sent", got)
			}
		})
	}
}

// TestRequestCRIDLinkWith_LeavesOutAUserAgentItMustNotSend is the user agent
// rule through the exported call. The user agent comes from the caller, in
// CRIDLinkConfig.UserAgent, so that is where the rule has to hold. A value that
// must not be sent costs the member, not the request: the request is still
// made, and it is byte for byte the request of a caller that set no user agent.
func TestRequestCRIDLinkWith_LeavesOutAUserAgentItMustNotSend(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, nil))
	without := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + fixture.crid + `"}}`
	with := func(sent string) string {
		return `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + fixture.crid +
			`","qurl_user_agent":"` + sent + `"}}`
	}

	for _, tc := range []struct {
		name      string
		userAgent string
		want      string
	}{
		{"a tab", "example-tool/1.2\t(linux)", without},
		{"a line feed", "example-tool/1.2\n", without},
		{"NUL", "example-tool\x00", without},
		{"DEL", "example-tool\x7f", without},
		{"U+2028", "example\u2028tool", without},
		{"U+2029", "example\u2029tool", without},
		// Past the limit: the value is not cut and sent, it is left out.
		{"a tab past the limit", strings.Repeat("a", 280) + "\t", without},
		// The neighbouring cases are still sent, so the rule is not "send none".
		{"clean", "example-tool/1.2", with("example-tool/1.2")},
		{"clean and long", strings.Repeat("b", 300), with(strings.Repeat("b", 256))},
		{"U+0080 is not in the set", "a\u0080b", with("a\u0080b")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.cfg.CRIDLink.UserAgent = tc.userAgent
			before := len(fixture.peer.seen())
			if _, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg); err != nil {
				t.Fatalf("RequestCRIDLinkWith: %v", err)
			}
			knocks := fixture.peer.seen()
			if len(knocks) != before+1 {
				t.Fatalf("the cell saw %d requests for one call", len(knocks)-before)
			}
			if got := string(knocks[len(knocks)-1].body); got != tc.want {
				t.Fatalf("request body = %s\nwant           %s", got, tc.want)
			}
		})
	}
}

func TestTruncateCRIDLinkUserAgent(t *testing.T) {
	const limit = 256
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short", "example-tool/1.2", "example-tool/1.2"},
		// Exactly at the limit, with a two-byte character inside: unchanged,
		// although it is fewer than 256 characters.
		{"at the limit", "tool (Zürich) " + strings.Repeat("a", limit-15), "tool (Zürich) " + strings.Repeat("a", limit-15)},
		{"one byte over", strings.Repeat("b", limit+1), strings.Repeat("b", limit)},
		{"far over", strings.Repeat("b", 4096), strings.Repeat("b", limit)},
		// A four-byte character occupies bytes 254 to 257. Cutting the bytes
		// at 256 would split it; counting UTF-16 code units would find nothing
		// to cut. The whole character goes.
		{"straddles the limit", strings.Repeat("c", 253) + "😀c", strings.Repeat("c", 253)},
		{"ends exactly at the limit", strings.Repeat("c", 252) + "😀" + "tail", strings.Repeat("c", 252) + "😀"},
		{"two-byte character straddles", strings.Repeat("c", 255) + "üx", strings.Repeat("c", 255)},
		{"three-byte character straddles", strings.Repeat("c", 254) + "€x", strings.Repeat("c", 254)},
		// Invalid input is replaced before the cut, so the replacement cannot
		// push the result back over the limit.
		{"invalid bytes", "ab\xffcd", "ab�cd"},
		{"invalid bytes near the limit", strings.Repeat("d", 254) + "\xff\xfe" + "tail", strings.Repeat("d", 254)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateCRIDLinkUserAgent(tc.in)
			if got != tc.want {
				t.Fatalf("truncated to %d bytes %q\nwant %d bytes %q", len(got), got, len(tc.want), tc.want)
			}
			if len(got) > limit || !utf8.ValidString(got) {
				t.Fatalf("the sent user agent is %d bytes, valid UTF-8 = %t", len(got), utf8.ValidString(got))
			}
		})
	}
	if len("tool (Zürich) "+strings.Repeat("a", limit-15)) != limit {
		t.Fatal("fixture drift: the at-limit value is not exactly at the limit")
	}
}
