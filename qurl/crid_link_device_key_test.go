package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
)

// Opening a private resource by CRID as a registered device:
// RequestCRIDLinkAsDeviceWith and OpenCRIDAsDeviceWith, which take an explicit
// Config, and RequestCRIDLinkAsDevice and OpenCRIDAsDevice, which resolve the
// default configuration and then call the With forms. Most tests here drive
// the With forms, where the code is. The tests at the end of the file drive
// the forms that take no configuration.
//
// The rule these tests hold is: a random key first, the device key only after
// "not found".
//
//  1. The first request is the request RequestCRIDLinkWith sends, under a
//     random key.
//  2. Only a "not found" answer to it leads to one second request, under the
//     device key.
//  3. The answer to the second request is the result. There is no third.
//  4. Any other outcome of the first request is returned as it is.
//  5. The calls that take no device key send exactly one request, as before.
//
// Like the tests in crid_link_request_test.go, they go through the exported
// calls against a peer that opens the real packet. The peer reads the static
// key of each knock from the packet, so "which key was this request sent
// under" is observed on the wire and not taken from the client's word.

// cridLinkDevice is a registered device in these tests: one X25519 key pair.
type cridLinkDevice struct {
	// private is what a caller passes as deviceStaticPrivateKey.
	private []byte
	// public is what the cell reads as the static key of the device's knock.
	public []byte
}

func newCRIDLinkDevice(t *testing.T) cridLinkDevice {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return cridLinkDevice{private: key.Bytes(), public: key.PublicKey().Bytes()}
}

// servePrivateResource makes the peer answer as a server that holds one
// private resource. A knock under the allowed device key gets forDevice. A
// knock under any other key gets "not found", the answer a server gives to a
// client that may not open the resource.
func (f *cridLinkFixture) servePrivateResource(t *testing.T, allowed cridLinkDevice, forDevice cridLinkAnswer) {
	t.Helper()
	notFound := cridLinkDenied(t, "52602")
	f.peer.respondWith(func(knock cridLinkKnock) cridLinkAnswer {
		if bytes.Equal(knock.devicePub, allowed.public) {
			return forDevice
		}
		return notFound
	})
}

// requestsSince returns the requests the peer has opened after the first
// before of them.
func (p *cridLinkPeer) requestsSince(before int) []cridLinkKnock {
	return p.seen()[before:]
}

// cridLinkRequestBody is the one canonical body of a request for a CRID with
// no user agent. Every request of a call carries exactly this, whichever key
// it is sent under.
func cridLinkRequestBody(resourceCRID string) string {
	return `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + resourceCRID + `"}}`
}

// assertRandomKeyRequest fails unless knock is an ordinary link request sent
// under a usable key that is not the device key.
func assertRandomKeyRequest(t *testing.T, what string, knock cridLinkKnock, device cridLinkDevice, resourceCRID string) {
	t.Helper()
	if len(knock.devicePub) != 32 || bytes.Equal(knock.devicePub, make([]byte, 32)) {
		t.Fatalf("%s was sent under an unusable key %x", what, knock.devicePub)
	}
	if bytes.Equal(knock.devicePub, device.public) {
		t.Fatalf("%s was sent under the device key", what)
	}
	if knock.headerType != relayknock.TypeKnock || string(knock.body) != cridLinkRequestBody(resourceCRID) {
		t.Fatalf("%s is not the ordinary link request: type %d, body %s", what, knock.headerType, knock.body)
	}
}

// assertDeviceKeyRequest fails unless knock is the same link request sent
// under the device key.
func assertDeviceKeyRequest(t *testing.T, what string, knock cridLinkKnock, device cridLinkDevice, resourceCRID string) {
	t.Helper()
	if !bytes.Equal(knock.devicePub, device.public) {
		t.Fatalf("%s was not sent under the device key", what)
	}
	if knock.headerType != relayknock.TypeKnock || string(knock.body) != cridLinkRequestBody(resourceCRID) {
		t.Fatalf("%s is not the ordinary link request: type %d, body %s", what, knock.headerType, knock.body)
	}
}

// cridLinkErrorShape describes an error by everything a caller can match on
// it, so that two errors can be compared for "the same error". It is empty for
// nil.
func cridLinkErrorShape(err error) string {
	if err == nil {
		return ""
	}
	var shape []string
	for _, sentinel := range []struct {
		name string
		err  error
	}{
		{"not found", ErrCRIDLinkNotFound},
		{"unavailable", ErrCRIDLinkUnavailable},
		{"rate limited", ErrCRIDLinkRateLimited},
		{"offline", ErrCRIDResourceOffline},
		{"closed", ErrCRIDResourceClosed},
		{"invalid request", ErrInvalidCRIDLinkRequest},
		{"protocol", ErrCRIDLinkProtocol},
		{"malformed", ErrMalformedReply},
		{"rejected", ErrCRIDLinkRejected},
		{"overloaded", ErrServerOverloaded},
		{"not configured", ErrCRIDLinkNotConfigured},
		{"invalid input", ErrInvalidResourceRequest},
		{"CRID mismatch", ErrCRIDMismatch},
		{"signature", ErrSignature},
		{"canceled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
	} {
		if errors.Is(err, sentinel.err) {
			shape = append(shape, sentinel.name)
		}
	}
	var deny *ServerDenyError
	if errors.As(err, &deny) {
		shape = append(shape, "deny "+deny.ErrCode)
	}
	var relayErr *RelayError
	if errors.As(err, &relayErr) {
		shape = append(shape, "relay "+strconv.Itoa(relayErr.Status))
	}
	var rejected *CRIDLinkRejectedError
	if errors.As(err, &rejected) {
		shape = append(shape, "class "+string(rejected.Class))
	}
	if len(shape) == 0 {
		return "an error that matches nothing"
	}
	return strings.Join(shape, ", ")
}

// Rule 1 for a public resource. A device asks for a public CRID: the answer
// comes from the first request, which is the only one, and the device key is
// never on the wire. That is what keeps a device unlinkable across the public
// resources it opens.
func TestRequestCRIDLinkAsDeviceWith_PublicResourceIsOneRequestUnderARandomKey(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	const calls = 4
	for call := range calls {
		issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
		if err != nil {
			t.Fatalf("call %d: RequestCRIDLinkAsDeviceWith: %v", call, err)
		}
		if issued.Link != fixture.link {
			t.Fatalf("call %d: the returned link is not the link the server issued", call)
		}
	}

	knocks := fixture.peer.seen()
	if len(knocks) != calls {
		t.Fatalf("the cell saw %d requests for %d calls, want one request per call", len(knocks), calls)
	}
	for i, knock := range knocks {
		assertRandomKeyRequest(t, fmt.Sprintf("request %d", i), knock, device, fixture.crid)
		// Holding a device key must not make the random key any less random:
		// still a fresh one for every request.
		for j := range i {
			if bytes.Equal(knock.devicePub, knocks[j].devicePub) {
				t.Fatalf("requests %d and %d were sent under the same key", j, i)
			}
		}
	}
}

// Rules 1, 2 and 3 for a private resource the device may open. The first
// request is under a random key and is answered "not found". The second is the
// same request under the device key, and its link is checked and returned.
func TestRequestCRIDLinkAsDeviceWith_OpensAPrivateResourceWithTheSecondRequest(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	keyBefore := bytes.Clone(device.private)

	issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("RequestCRIDLinkAsDeviceWith: %v", err)
	}
	if issued.Link != fixture.link {
		t.Fatal("the returned link is not the link the server issued")
	}
	// The link went through the checks of every issued link, and the metadata
	// beside it was read the same way.
	if _, err := VerifyLinkForCRID(issued.Link, fixture.crid, fixture.cfg.TrustStore); err != nil {
		t.Fatalf("the returned link does not verify for the requested CRID: %v", err)
	}
	if issued.QURLID != "q_a1b2c3d4e5f" || issued.Publisher != (Publisher{Name: "Example Publisher"}) {
		t.Fatalf("issued = %v", issued)
	}

	knocks := fixture.peer.seen()
	if len(knocks) != 2 {
		t.Fatalf("the cell saw %d requests, want 2", len(knocks))
	}
	assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
	assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)

	// The key is the caller's. The call did not wipe it or change it, so the
	// same key works again. The next call starts with a new random key: nothing
	// of the first call's first request is kept.
	if !bytes.Equal(device.private, keyBefore) {
		t.Fatal("the call changed the caller's device key")
	}
	if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg); err != nil {
		t.Fatalf("a second call with the same key: %v", err)
	}
	knocks = fixture.peer.seen()
	if len(knocks) != 4 {
		t.Fatalf("the cell saw %d requests after two calls, want 4", len(knocks))
	}
	assertRandomKeyRequest(t, "the third request", knocks[2], device, fixture.crid)
	assertDeviceKeyRequest(t, "the fourth request", knocks[3], device, fixture.crid)
	if bytes.Equal(knocks[0].devicePub, knocks[2].devicePub) {
		t.Fatal("two calls sent their first request under the same key")
	}
}

// The user agent is part of the request, so both requests of a call carry it.
func TestRequestCRIDLinkAsDeviceWith_BothRequestsCarryTheSameBody(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, nil))
	fixture.cfg.CRIDLink.UserAgent = "example-tool/1.2"

	if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg); err != nil {
		t.Fatal(err)
	}
	knocks := fixture.peer.seen()
	if len(knocks) != 2 {
		t.Fatalf("the cell saw %d requests, want 2", len(knocks))
	}
	want := `{"headerType":1,"aspId":"qurl","resId":"qurl-crid","usrData":{"qurl_crid":"` + fixture.crid +
		`","qurl_user_agent":"example-tool/1.2"}}`
	for i, knock := range knocks {
		if string(knock.body) != want {
			t.Fatalf("request %d body = %s\nwant             %s", i, knock.body, want)
		}
	}
}

// Rule 3. A device that may not open the resource is answered "not found"
// twice. The result is the not-found error RequestCRIDLinkWith returns, and
// there is no third request.
func TestRequestCRIDLinkAsDeviceWith_NotFoundTwiceIsNotFound(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.peer.respond(cridLinkDenied(t, "52602"))

	// What a caller that is not a device gets for the same answer.
	_, plainErr := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
	if !errors.Is(plainErr, ErrCRIDLinkNotFound) {
		t.Fatalf("RequestCRIDLinkWith: error = %v, want ErrCRIDLinkNotFound", plainErr)
	}
	before := len(fixture.peer.seen())

	issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if issued != nil || !errors.Is(err, ErrCRIDLinkNotFound) {
		t.Fatalf("RequestCRIDLinkAsDeviceWith = %v, %v; want ErrCRIDLinkNotFound and no link", issued, err)
	}
	var deny *ServerDenyError
	if !errors.As(err, &deny) || deny.ErrCode != "52602" {
		t.Fatalf("the error is not a *ServerDenyError carrying 52602: %v", err)
	}
	if err.Error() != plainErr.Error() || cridLinkErrorShape(err) != cridLinkErrorShape(plainErr) {
		t.Fatalf("RequestCRIDLinkAsDeviceWith error = %q (%s)\nRequestCRIDLinkWith error     = %q (%s)\nwant the same error",
			err, cridLinkErrorShape(err), plainErr, cridLinkErrorShape(plainErr))
	}

	knocks := fixture.peer.requestsSince(before)
	if len(knocks) != 2 {
		t.Fatalf("the cell saw %d requests, want exactly 2", len(knocks))
	}
	assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
	assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
}

// Rule 5. RequestCRIDLinkWith and OpenCRIDWith take no device key. For them
// "not found" is final after one request, as it was before the device calls
// existed. The server here holds a private resource, so a second request under
// some key is exactly what must not happen.
func TestRequestCRIDLinkWith_NotFoundIsOneRequest(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp

	for name, call := range map[string]func() (returned bool, err error){
		"RequestCRIDLinkWith": func() (bool, error) {
			issued, err := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			return issued != nil, err
		},
		"OpenCRIDWith": func() (bool, error) {
			handle, err := OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg)
			return handle != nil, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(fixture.peer.seen())
			returned, err := call()
			if returned || !errors.Is(err, ErrCRIDLinkNotFound) {
				t.Fatalf("returned a result = %t, error = %v; want ErrCRIDLinkNotFound and no result", returned, err)
			}
			// The text of the error is the text it has always had.
			if want := `qurl: CRID not found, or this client may not open it: qurl: platform denied access (errCode="52602")`; err.Error() != want {
				t.Fatalf("error text = %q, want %q", err.Error(), want)
			}
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 1 {
				t.Fatalf("the cell saw %d requests, want exactly 1", len(knocks))
			}
			assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
		})
	}
	if got := len(admittedKeys()); got != 0 {
		t.Fatalf("%d open knocks were sent although no link was issued", got)
	}
}

// Rule 4. Only the server's own, authenticated "not found" leads to a second
// request. Every other outcome of the first request is returned as it is,
// after exactly one request under a random key: the device must not identify
// itself because of a fault.
//
// Several cases are built to look like "not found" without being it: an HTTP
// 404 from the relay, a "not found" body under a key that is not the cell's, a
// body that names the code and is not a usable answer, and a reply of another
// type that carries the code.
func TestRequestCRIDLinkAsDeviceWith_OtherFirstOutcomesTakeOneRequest(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)

	impostor, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forgedNotFound := cridLinkDenied(t, "52602")
	forgedNotFound.sealedBy = impostor.Bytes()
	notFoundBody := cridLinkDenied(t, "52602").body

	for _, tc := range []struct {
		name   string
		answer cridLinkAnswer
		// want is the shape of the error. It is the shape RequestCRIDLinkWith
		// gives too, which the test checks.
		want string
		// textVaries is set where the error text holds a value that is new for
		// every request, so two calls cannot have the same text.
		textVaries bool
	}{
		{"rate limited", cridLinkDenied(t, "52603"), "rate limited, deny 52603", false},
		{"unavailable", cridLinkDenied(t, "52601"), "unavailable, deny 52601", false},
		{"publisher offline", cridLinkDenied(t, "52604"), "offline, deny 52604", false},
		{"resource closed", cridLinkDenied(t, "52605"), "closed, deny 52605", false},
		{"invalid request", cridLinkDenied(t, "52606"), "invalid request, deny 52606", false},
		{"a code outside the set", cridLinkDenied(t, "52607"), "deny 52607", false},
		{"a general platform code", cridLinkDenied(t, "51002"), "deny 51002", false},
		{"busy", cridLinkAnswer{replyType: relayknock.TypeCookieChallenge}, "overloaded", false},
		{"busy, with a not-found body", cridLinkAnswer{replyType: relayknock.TypeCookieChallenge, body: notFoundBody}, "overloaded", false},

		{
			"malformed: a success code",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, "0", nil)},
			"protocol, malformed", false,
		},
		{
			"malformed: the not-found code as a number",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: []byte(`{"errCode":52602}`)},
			"protocol, malformed", false,
		},
		{
			"malformed: a cut-off body that names the not-found code",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: []byte(`{"errCode":"52602"`)},
			"protocol, malformed", false,
		},
		{
			"malformed: the not-found code twice",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: []byte(`{"errCode":"52602","errCode":"52602"}`)},
			"protocol, malformed", false,
		},
		{"malformed: an empty body", cridLinkAnswer{replyType: relayknock.TypeACK}, "protocol, malformed", false},
		{
			"malformed: not found in a reply of another type",
			cridLinkAnswer{replyType: relayknock.TypeListResult, body: notFoundBody},
			"malformed", false,
		},
		{
			"malformed: not found for another request",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: notFoundBody, counterSkew: 1},
			"malformed", true,
		},

		{"relay fault", cridLinkAnswer{status: http.StatusBadGateway, text: "upstream unavailable"}, "relay 502", false},
		{"relay answers 404", cridLinkAnswer{status: http.StatusNotFound, text: "not found"}, "relay 404", false},
		{"relay answers 429", cridLinkAnswer{status: http.StatusTooManyRequests, text: "slow down"}, "relay 429", false},
		{"not found under a key that is not the cell's", forgedNotFound, "an error that matches nothing", false},

		{
			"a link that fails a check",
			cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil),
			"rejected, CRID mismatch, class crid_mismatch", false,
		},
		{
			"a link on another origin",
			cridLinkIssued(t, "https://example.com/#"+fixture.link[strings.IndexByte(fixture.link, '#')+1:], nil),
			"rejected, class origin", false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.peer.respond(tc.answer)

			// The call that takes no device key is the reference.
			_, plainErr := RequestCRIDLinkWith(t.Context(), fixture.crid, fixture.cfg)
			if got := cridLinkErrorShape(plainErr); got != tc.want {
				t.Fatalf("RequestCRIDLinkWith: error = %v (%s), want %s", plainErr, got, tc.want)
			}

			before := len(fixture.peer.seen())
			issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
			if issued != nil {
				t.Fatal("a failing first request returned a link")
			}
			if got := cridLinkErrorShape(err); got != tc.want {
				t.Fatalf("RequestCRIDLinkAsDeviceWith: error = %v (%s), want %s", err, got, tc.want)
			}
			if !tc.textVaries && err.Error() != plainErr.Error() {
				t.Fatalf("RequestCRIDLinkAsDeviceWith error = %q\nRequestCRIDLinkWith error     = %q\nwant the same error", err, plainErr)
			}
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 1 {
				t.Fatalf("the cell saw %d requests, want exactly 1", len(knocks))
			}
			assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
		})
	}

	// No reply at all. The relay is silent, and the caller's context ends
	// while the first request waits. The context ends only after the request
	// has reached the peer, so the count below does not depend on timing.
	for name, end := range map[string]error{
		"no reply, and the caller cancels":   context.Canceled,
		"no reply, and the deadline goes by": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			ctx := newEndableContext(t, end)
			fixture.peer.respondWith(func(cridLinkKnock) cridLinkAnswer {
				ctx.end()
				return cridLinkAnswer{hold: release}
			})

			before := len(fixture.peer.seen())
			issued, err := RequestCRIDLinkAsDeviceWith(ctx, device.private, fixture.crid, fixture.cfg)
			if issued != nil || !errors.Is(err, end) {
				t.Fatalf("RequestCRIDLinkAsDeviceWith = %v, %v; want %v and no link", issued, err, end)
			}
			var relayErr *RelayError
			if !errors.As(err, &relayErr) || relayErr.Status != 0 || errors.Is(err, ErrCRIDLinkNotFound) {
				t.Fatalf("error = %v, want the transport fault of a request that got no answer", err)
			}
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 1 {
				t.Fatalf("the cell saw %d requests, want exactly 1", len(knocks))
			}
			assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
		})
	}
}

// The second request is a request like any other: whatever it is answered
// with is the result of the call. A link that fails a check there is refused
// exactly as on the first request, and nothing of the reply is returned.
func TestRequestCRIDLinkAsDeviceWith_TheSecondAnswerIsTheResult(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp

	fragment := fixture.link[strings.IndexByte(fixture.link, '#')+1:]
	cut := strings.LastIndexByte(fragment, '.') + 1
	swap := "A"
	if fragment[cut] == 'A' {
		swap = "B"
	}
	tampered := cridLinkTestOrigin + "/#" + fragment[:cut] + swap + fragment[cut+1:]
	otherCRID := fixture.info()
	otherCRID["crid"] = testCRIDForKey(0x81, 32, fixture.resourceKey)

	for _, tc := range []struct {
		name      string
		forDevice cridLinkAnswer
		want      string
	}{
		{
			"a link for another resource",
			cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), fixture.info()),
			"rejected, CRID mismatch, class crid_mismatch",
		},
		{
			"a link on another origin",
			cridLinkIssued(t, "https://qurl.link.example.com/#"+fragment, fixture.info()),
			"rejected, class origin",
		},
		{
			"a link with a changed signature",
			cridLinkIssued(t, tampered, fixture.info()),
			"rejected, signature, class issuer_signature",
		},
		{
			"metadata that names another CRID",
			cridLinkIssued(t, fixture.link, otherCRID),
			"rejected, CRID mismatch, class info_crid_mismatch",
		},
		{"no link at all", cridLinkIssued(t, "", nil), "rejected, class missing_redirect"},

		{"rate limited", cridLinkDenied(t, "52603"), "rate limited, deny 52603"},
		{"unavailable", cridLinkDenied(t, "52601"), "unavailable, deny 52601"},
		{"publisher offline", cridLinkDenied(t, "52604"), "offline, deny 52604"},
		{"busy", cridLinkAnswer{replyType: relayknock.TypeCookieChallenge}, "overloaded"},
		{
			"malformed",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, "0", map[string]any{"redirectUrl": fixture.link})},
			"protocol, malformed",
		},
		{"relay fault", cridLinkAnswer{status: http.StatusBadGateway, text: "upstream unavailable"}, "relay 502"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.servePrivateResource(t, device, tc.forDevice)
			for _, call := range []struct {
				name string
				run  func() (returned bool, err error)
			}{
				{"RequestCRIDLinkAsDeviceWith", func() (bool, error) {
					issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
					return issued != nil, err
				}},
				{"OpenCRIDAsDeviceWith", func() (bool, error) {
					handle, err := OpenCRIDAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
					return handle != nil, err
				}},
			} {
				before := len(fixture.peer.seen())
				returned, err := call.run()
				if returned {
					t.Fatalf("%s returned a result although the second request failed", call.name)
				}
				if got := cridLinkErrorShape(err); got != tc.want {
					t.Fatalf("%s error = %v (%s), want %s", call.name, err, got, tc.want)
				}
				knocks := fixture.peer.requestsSince(before)
				if len(knocks) != 2 {
					t.Fatalf("%s: the cell saw %d requests, want exactly 2", call.name, len(knocks))
				}
				assertRandomKeyRequest(t, call.name+": the first request", knocks[0], device, fixture.crid)
				assertDeviceKeyRequest(t, call.name+": the second request", knocks[1], device, fixture.crid)
			}
		})
	}
	if got := len(admittedKeys()); got != 0 {
		t.Fatalf("%d open knocks were sent although no link was accepted", got)
	}
}

// One caller context covers both requests.
//
// When the context has ended by the time the first request is answered
// "not found", a second request could not finish, so none is started and the
// device key is never used.
//
// The error is then the context's error, and it is NOT "not found". For a
// device, "not found" is known only when the device's own request has been
// answered. A caller that reads ErrCRIDLinkNotFound tells its user that the
// resource does not exist, and here nobody has asked as the device.
func TestRequestCRIDLinkAsDeviceWith_OneContextCoversBothRequests(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	// The device may open the resource. A second request would get a link, so
	// "no link" below can only mean that no second request was made.
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))

	for _, tc := range []struct {
		name string
		// newContext returns the caller's context, and a function that
		// returns once that context has ended.
		newContext func(t *testing.T) (ctx context.Context, end func())
		is         error
		want       string
	}{
		{
			"the caller cancels after the first answer",
			func(t *testing.T) (context.Context, func()) {
				return context.WithCancel(t.Context())
			},
			context.Canceled, "canceled",
		},
		{
			// A real deadline. The first answer is complete before it and is
			// handed to the SDK only after it has gone by.
			"the deadline goes by after the first answer",
			func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				t.Cleanup(cancel)
				return ctx, func() { <-ctx.Done() }
			},
			context.DeadlineExceeded, "deadline",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, end := tc.newContext(t)
			cfg := fixture.cfg
			// The context ends when the first answer is complete and before
			// the SDK reads it. The exchange itself is not bound to the
			// context, so the outcome does not depend on how fast the machine
			// is.
			client := &countingDoer{next: fixture.peer.clientThatRunsAfterEachAnswer(end)}
			cfg.HTTPClient = client

			before := len(fixture.peer.seen())
			issued, err := RequestCRIDLinkAsDeviceWith(ctx, device.private, fixture.crid, cfg)

			// The second request is not even handed to the HTTP client. This
			// client sends whatever it is handed, also after the context has
			// ended, as a caller's own client may. So what keeps the device
			// key off the wire here is the SDK, not a client that refuses.
			if got := client.handed.Load(); got != 1 {
				t.Errorf("the HTTP client was handed %d requests, want only the first", got)
			}
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 1 {
				t.Fatalf("the cell saw %d requests, want exactly 1", len(knocks))
			}
			assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
			if issued != nil {
				t.Fatal("a link was returned although the context had ended before the second request")
			}

			// The error is the context's error.
			if !errors.Is(err, tc.is) {
				t.Fatalf("error = %v, want it to match %v", err, tc.is)
			}
			// It is not "not found", in any form a caller can match: not the
			// sentinel, and not the server's deny with the not-found code. The
			// first answer said "not found" to a random key. That says nothing
			// about this device.
			if errors.Is(err, ErrCRIDLinkNotFound) {
				t.Fatalf("error = %v: it matches ErrCRIDLinkNotFound although the request with the device key was never sent", err)
			}
			var deny *ServerDenyError
			if errors.As(err, &deny) {
				t.Fatalf("error = %v: it carries the server's deny %s although the request with the device key was never sent", err, deny.ErrCode)
			}
			if got := cridLinkErrorShape(err); got != tc.want {
				t.Fatalf("error = %v (%s), want only %s", err, got, tc.want)
			}
			// And it says in plain words what happened.
			if want := "qurl: the CRID link request with the device key was not sent because the context ended first: " + tc.is.Error(); err.Error() != want {
				t.Fatalf("error text = %q\nwant         %q", err.Error(), want)
			}
		})
	}

	// For the call that takes no device key the same moment changes nothing:
	// an answered request keeps its answer, as it did before. There "not
	// found" is the whole answer.
	t.Run("RequestCRIDLinkWith keeps its answer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cfg := fixture.cfg
		cfg.HTTPClient = fixture.peer.clientThatRunsAfterEachAnswer(cancel)
		_, err := RequestCRIDLinkWith(ctx, fixture.crid, cfg)
		if got := cridLinkErrorShape(err); got != "not found, deny 52602" {
			t.Fatalf("error = %v (%s), want the plain not-found error", err, got)
		}
	})

	// A context that is still open after the first answer lets the second
	// request run. If it ends while that request waits, the result is the
	// second request's own error: it did not complete.
	t.Run("the caller cancels while the second request waits", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		notFound := cridLinkDenied(t, "52602")
		fixture.peer.respondWith(func(knock cridLinkKnock) cridLinkAnswer {
			if !bytes.Equal(knock.devicePub, device.public) {
				return notFound
			}
			// The second request has reached the cell. Now the caller leaves.
			cancel()
			return cridLinkAnswer{hold: release}
		})

		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDeviceWith(ctx, device.private, fixture.crid, fixture.cfg)
		if issued != nil {
			t.Fatal("a link was returned by a request that was canceled")
		}
		if got := cridLinkErrorShape(err); got != "canceled, relay 0" {
			t.Fatalf("error = %v (%s), want the canceled second request", err, got)
		}
		knocks := fixture.peer.requestsSince(before)
		if len(knocks) != 2 {
			t.Fatalf("the cell saw %d requests, want exactly 2", len(knocks))
		}
		assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
		assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
	})

	t.Run("a context that has ended before the call sends nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDeviceWith(ctx, device.private, fixture.crid, fixture.cfg)
		if issued != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("RequestCRIDLinkAsDeviceWith = %v, %v; want context.Canceled", issued, err)
		}
		if got := len(fixture.peer.requestsSince(before)); got != 0 {
			t.Fatalf("a canceled call still sent %d requests", got)
		}
	})
}

// endableContext is a context the test ends by hand, with the error it would
// have after a cancel or after its deadline. It is for the tests that must end
// the context at the moment a request reaches the peer: a real deadline cannot
// be made to go by at a point the test chooses.
type endableContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	err  error
}

func newEndableContext(t *testing.T, err error) *endableContext {
	t.Helper()
	ctx := &endableContext{Context: t.Context(), done: make(chan struct{}), err: err}
	// A request that is still waiting at the end of the test is let go.
	t.Cleanup(ctx.end)
	return ctx
}

func (c *endableContext) end() { c.once.Do(func() { close(c.done) }) }

func (c *endableContext) Done() <-chan struct{} { return c.done }

func (c *endableContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// countingDoer counts the requests it is handed, whether or not they are sent.
type countingDoer struct {
	next   HTTPDoer
	handed atomic.Int32
}

func (d *countingDoer) Do(req *http.Request) (*http.Response, error) {
	d.handed.Add(1)
	return d.next.Do(req)
}

// clientThatRunsAfterEachAnswer is an HTTP client that sends a request to the
// peer, reads the whole answer into memory, and then calls then before it
// hands the answer on.
//
// The exchange with the peer is not bound to the caller's context, and the
// answer is complete before then runs. So then may end the caller's context,
// or wait for its deadline, and the answer still arrives whole.
func (p *cridLinkPeer) clientThatRunsAfterEachAnswer(then func()) HTTPDoer {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := p.server.Client().Do(req.Clone(context.WithoutCancel(req.Context())))
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		then()
		return resp, nil
	})
}

// TestOpenCRIDAsDeviceWith_OpensAPrivateResource is the feature end to end. A
// registered device that holds only a CRID asks for a link, is answered
// "not found" under a random key, asks again under its device key, checks the
// link it gets, and opens it. The open uses the link's own key: the device key
// is the static key of one knock and of nothing else.
func TestOpenCRIDAsDeviceWith_OpensAPrivateResource(t *testing.T) {
	const resourceURL = "https://resource.example.com/report"
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, resourceURL)
	fixture.cfg.nativeUDPOptions = udp

	handle, err := OpenCRIDAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("OpenCRIDAsDeviceWith: %v", err)
	}
	if handle.ResourceURL != resourceURL || handle.SessionID != 123 || handle.OpenSeconds != 900 {
		t.Fatalf("handle = %v", handle)
	}

	requests, opens := fixture.peer.seen(), admittedKeys()
	if len(requests) != 2 || len(opens) != 1 {
		t.Fatalf("link requests = %d, opens = %d, want 2 and 1", len(requests), len(opens))
	}
	assertRandomKeyRequest(t, "the first request", requests[0], device, fixture.crid)
	assertDeviceKeyRequest(t, "the second request", requests[1], device, fixture.crid)
	if bytes.Equal(opens[0], device.public) || bytes.Equal(opens[0], requests[0].devicePub) {
		t.Fatal("the open was not sent under the link's own key")
	}

	// The handle is the one an ordinary open of the issued link reaches.
	direct := fixture.cfg
	direct.ExpectedCRID = fixture.crid
	viaLink, err := EnterPortalWith(t.Context(), fixture.link, direct)
	if err != nil {
		t.Fatalf("EnterPortalWith on the same link: %v", err)
	}
	if *viaLink != *handle {
		t.Fatalf("OpenCRIDAsDeviceWith handle = %v, EnterPortalWith handle = %v", handle, viaLink)
	}
	opensBefore := len(admittedKeys())

	// A client that is not a device, and a device the owner did not allow, get
	// "not found" for the same CRID from the same server, and open nothing.
	stranger := newCRIDLinkDevice(t)
	for name, open := range map[string]func() (*ResourceHandle, error){
		"OpenCRIDWith": func() (*ResourceHandle, error) {
			return OpenCRIDWith(t.Context(), fixture.crid, fixture.cfg)
		},
		"OpenCRIDAsDeviceWith, as another device": func() (*ResourceHandle, error) {
			return OpenCRIDAsDeviceWith(t.Context(), stranger.private, fixture.crid, fixture.cfg)
		},
	} {
		if handle, err := open(); handle != nil || !errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("%s = %v, %v; want ErrCRIDLinkNotFound and no handle", name, handle, err)
		}
	}
	if got := len(admittedKeys()); got != opensBefore {
		t.Fatalf("%d more open knocks were sent by clients that got no link", got-opensBefore)
	}
}

// A device key that cannot be a key is refused first: before the CRID or the
// configuration is looked at, and before anything is sent. So the error does
// not depend on the CRID, on the configuration, or on what the server would
// have answered.
//
// A missing key is refused too. A call made "as a device" with no key must
// not quietly turn into the call that takes no key.
func TestRequestCRIDLinkAsDeviceWith_RefusesAnUnusableDeviceKey(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	// Configurations and CRIDs that would each fail on their own. The key is
	// refused before any of them is looked at.
	noEndpoint := fixture.cfg
	noEndpoint.CRIDLink = nil
	noTrust := fixture.cfg
	noTrust.TrustStore = nil
	contradicting := fixture.cfg
	contradicting.ExpectedCRID = testCRIDForKey(0x01, 32, fixture.foreignKey)

	for _, tc := range []struct {
		name string
		key  []byte
		says string
	}{
		{"no key", nil, "must be 32 bytes"},
		{"an empty key", []byte{}, "must be 32 bytes"},
		{"one byte", device.private[:1], "must be 32 bytes"},
		{"one byte short", device.private[:31], "must be 32 bytes"},
		{"one byte long", append(bytes.Clone(device.private), 0x01), "must be 32 bytes"},
		{"two keys", append(bytes.Clone(device.private), device.private...), "must be 32 bytes"},
		{"a wiped key", make([]byte, 32), "holds only zero bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, with := range []struct {
				name string
				crid string
				cfg  Config
			}{
				{"a usable CRID and configuration", fixture.crid, fixture.cfg},
				{"an unusable CRID", "not a CRID", fixture.cfg},
				{"no endpoint", fixture.crid, noEndpoint},
				{"no trust store", fixture.crid, noTrust},
				{"a contradicting pin", fixture.crid, contradicting},
			} {
				doer := &refusingDoer{t: t}
				cfg := with.cfg
				cfg.HTTPClient = doer

				issued, requestErr := RequestCRIDLinkAsDeviceWith(t.Context(), tc.key, with.crid, cfg)
				handle, openErr := OpenCRIDAsDeviceWith(t.Context(), tc.key, with.crid, cfg)
				if issued != nil || handle != nil {
					t.Fatalf("%s: a call with an unusable device key returned a result", with.name)
				}
				for call, err := range map[string]error{"RequestCRIDLinkAsDeviceWith": requestErr, "OpenCRIDAsDeviceWith": openErr} {
					// Only the invalid-input error: the same sentinel as for a
					// CRID that fails the local gate, and none of the errors
					// the CRID or the configuration would have caused.
					if got := cridLinkErrorShape(err); got != "invalid input" {
						t.Fatalf("%s, %s: error = %v (%s), want only ErrInvalidResourceRequest", with.name, call, err, got)
					}
					if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrUnsupportedCRIDVersion) {
						t.Fatalf("%s, %s: error = %v, want the device key refused first", with.name, call, err)
					}
					if want := "qurl: invalid resource request: the device static private key " + tc.says; err.Error() != want {
						t.Fatalf("%s, %s: error text = %q, want %q", with.name, call, err.Error(), want)
					}
					assertNoDeviceKey(t, call+" error", fmt.Sprintf("%v %+v %#v", err, err, err), device)
				}
				if doer.called {
					t.Fatalf("%s: a request was handed to the HTTP client although the device key cannot be used", with.name)
				}
			}
		})
	}
	if got := len(fixture.peer.seen()); got != 0 {
		t.Fatalf("%d requests were sent although every device key was unusable", got)
	}
}

// With a usable key the device calls pass the same gates, in the same order,
// as the calls that take no key, and report them with the same errors. Nothing
// is sent, and nothing is sent under the device key in particular.
func TestRequestCRIDLinkAsDeviceWith_SharesTheGatesOfRequestCRIDLinkWith(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	noEndpoint := fixture.cfg
	noEndpoint.CRIDLink = nil
	badOrigin := fixture.cfg
	endpoint := *fixture.cfg.CRIDLink
	endpoint.LinkOrigin = "https://qurl.link/"
	badOrigin.CRIDLink = &endpoint
	contradicting := fixture.cfg
	contradicting.ExpectedCRID = testCRIDForKey(0x01, 32, fixture.foreignKey)
	// The CRID is refused before the configuration is looked at.
	unusableCRIDAndNoEndpoint := noEndpoint

	for _, tc := range []struct {
		name string
		crid string
		cfg  Config
	}{
		{"a value that is not a CRID", "not a CRID", fixture.cfg},
		{"a CRID of a version that is not active", testCRIDForKey(0x02, 24, fixture.resourceKey), fixture.cfg},
		{"an unusable CRID and no endpoint", "not a CRID", unusableCRIDAndNoEndpoint},
		{"a contradicting pin", fixture.crid, contradicting},
		{"no endpoint", fixture.crid, noEndpoint},
		{"an endpoint that cannot be used", fixture.crid, badOrigin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doer := &refusingDoer{t: t}
			cfg := tc.cfg
			cfg.HTTPClient = doer

			_, withErr := RequestCRIDLinkWith(t.Context(), tc.crid, cfg)
			_, openWithErr := OpenCRIDWith(t.Context(), tc.crid, cfg)
			issued, requestErr := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, tc.crid, cfg)
			handle, openErr := OpenCRIDAsDeviceWith(t.Context(), device.private, tc.crid, cfg)
			if issued != nil || handle != nil {
				t.Fatal("a call that must be refused returned a result")
			}
			if withErr == nil || openWithErr == nil {
				t.Fatal("fixture drift: the calls that take no key accept this input")
			}
			for call, pair := range map[string][2]error{
				"RequestCRIDLinkAsDeviceWith": {requestErr, withErr}, "OpenCRIDAsDeviceWith": {openErr, openWithErr},
			} {
				got, want := pair[0], pair[1]
				if got == nil || got.Error() != want.Error() || cridLinkErrorShape(got) != cridLinkErrorShape(want) {
					t.Fatalf("%s error = %v (%s)\nthe call with no key = %v (%s)\nwant the same error",
						call, got, cridLinkErrorShape(got), want, cridLinkErrorShape(want))
				}
			}
			if doer.called {
				t.Fatal("a request was handed to the HTTP client although the call must be refused first")
			}
		})
	}
	if got := len(fixture.peer.seen()); got != 0 {
		t.Fatalf("%d requests were sent although every call must be refused first", got)
	}
}

// deviceKeyForms returns the ways a key shows up in text when it is printed or
// encoded, whole and in part. An error or a log line that holds one of them
// holds the key.
func deviceKeyForms(key []byte) map[string]string {
	forms := map[string]string{}
	add := func(name string, part []byte) {
		if len(part) == 0 {
			return
		}
		forms[name+" as raw bytes"] = string(part)
		forms[name+" in hex"] = hex.EncodeToString(part)
		forms[name+" in upper-case hex"] = strings.ToUpper(hex.EncodeToString(part))
		forms[name+" in base64"] = strings.TrimRight(base64.StdEncoding.EncodeToString(part), "=")
		forms[name+" in URL base64"] = strings.TrimRight(base64.URLEncoding.EncodeToString(part), "=")
		// What %v and %d print for a byte slice, and what %#v prints.
		forms[name+" as decimal bytes"] = strings.Trim(fmt.Sprintf("%d", part), "[]")
		forms[name+" in Go syntax"] = strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", part), "[]byte{"), "}")
	}
	add("the key", key)
	if len(key) >= 9 {
		// A part of the key is a leak as well. Nine bytes are twelve base64
		// characters with no padding, so the start in base64 is a true prefix.
		add("the start of the key", key[:9])
		add("the end of the key", key[len(key)-9:])
	}
	return forms
}

// assertNoDeviceKey fails if text holds the device's private key, in any of
// the forms above, or its public key. The public key is not a secret, but it
// names the device, and nothing the package prints has a reason to hold it.
func assertNoDeviceKey(t *testing.T, what, text string, device cridLinkDevice) {
	t.Helper()
	for form, needle := range deviceKeyForms(device.private) {
		if strings.Contains(text, needle) {
			t.Fatalf("%s contains %s of the device private key", what, form)
		}
	}
	for form, needle := range deviceKeyForms(device.public) {
		if strings.Contains(text, needle) {
			t.Fatalf("%s contains %s of the device public key", what, form)
		}
	}
}

// holdsDeviceKey reports whether text holds the device's key in a form
// assertNoDeviceKey looks for.
func holdsDeviceKey(text string, device cridLinkDevice) bool {
	for _, key := range [][]byte{device.private, device.public} {
		for _, needle := range deviceKeyForms(key) {
			if strings.Contains(text, needle) {
				return true
			}
		}
	}
	return false
}

// TestCRIDLinkAsDevice_NeverPutsTheDeviceKeyInAnErrorOrALog is the fence around
// the device key. Every call here is made as the device and ends in an error,
// on the first request or on the second. No error text, at any depth of the
// chain, and nothing the standard loggers received, may hold the key.
func TestCRIDLinkAsDevice_NeverPutsTheDeviceKeyInAnErrorOrALog(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	udp, _ := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp

	// The fence has to be able to see a key. These are the ways a careless
	// line of code would print one, and each must be caught.
	for name, leak := range map[string]string{
		"%v of the key":             fmt.Sprintf("%v", device.private),
		"%x of the key":             fmt.Sprintf("device key %x", device.private),
		"%X of the key":             fmt.Sprintf("%X", device.private),
		"%#v of the key":            fmt.Sprintf("%#v", device.private),
		"%s of the key":             fmt.Sprintf("device key %s", device.private),
		"base64 of the key":         base64.StdEncoding.EncodeToString(device.private),
		"raw URL base64 of the key": base64.RawURLEncoding.EncodeToString(device.private),
		"half of the key in hex":    hex.EncodeToString(device.private[:16]),
		"the key in a struct":       fmt.Sprintf("%+v", struct{ Key []byte }{device.private}),
		"the public key in hex":     hex.EncodeToString(device.public),
	} {
		if !holdsDeviceKey(leak, device) {
			t.Fatalf("the fence does not see %s", name)
		}
	}

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

	impostor, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notFound := cridLinkDenied(t, "52602")
	forged := cridLinkIssued(t, fixture.link, fixture.info())
	forged.sealedBy = impostor.Bytes()

	// first is the answer to the request under a random key, second the answer
	// to the request under the device key. A nil second is never reached.
	type answers struct{ first, second *cridLinkAnswer }
	answer := func(a cridLinkAnswer) *cridLinkAnswer { return &a }
	for name, tc := range map[string]answers{
		"first: rate limited":       {first: answer(cridLinkDenied(t, "52603"))},
		"first: relay fault":        {first: answer(cridLinkAnswer{status: http.StatusBadGateway, text: "upstream failed"})},
		"first: busy":               {first: answer(cridLinkAnswer{replyType: relayknock.TypeCookieChallenge})},
		"first: rejected link":      {first: answer(cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil))},
		"first: does not verify":    {first: answer(forged)},
		"second: not found":         {first: &notFound, second: &notFound},
		"second: rate limited":      {first: &notFound, second: answer(cridLinkDenied(t, "52603"))},
		"second: unknown code":      {first: &notFound, second: answer(cridLinkDenied(t, "52607"))},
		"second: busy":              {first: &notFound, second: answer(cridLinkAnswer{replyType: relayknock.TypeCookieChallenge})},
		"second: malformed":         {first: &notFound, second: answer(cridLinkAnswer{replyType: relayknock.TypeACK, body: []byte(`[]`)})},
		"second: another type":      {first: &notFound, second: answer(cridLinkAnswer{replyType: relayknock.TypeListResult})},
		"second: another request":   {first: &notFound, second: answer(cridLinkAnswer{replyType: relayknock.TypeACK, body: notFound.body, counterSkew: 3})},
		"second: relay fault":       {first: &notFound, second: answer(cridLinkAnswer{status: http.StatusBadGateway, text: "upstream failed"})},
		"second: relay answers 400": {first: &notFound, second: answer(cridLinkAnswer{status: http.StatusBadRequest, text: "invalid packet"})},
		"second: does not verify":   {first: &notFound, second: answer(forged)},
		"second: rejected link":     {first: &notFound, second: answer(cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil))},
		"second: link elsewhere":    {first: &notFound, second: answer(cridLinkIssued(t, "https://example.com/#x", nil))},
	} {
		t.Run(name, func(t *testing.T) {
			fixture.peer.respondWith(func(knock cridLinkKnock) cridLinkAnswer {
				if bytes.Equal(knock.devicePub, device.public) {
					if tc.second == nil {
						t.Error("a request under the device key was sent in a case that must stop after the first request")
						return notFound
					}
					return *tc.second
				}
				return *tc.first
			})
			for _, call := range []struct {
				name string
				run  func() error
			}{
				{"RequestCRIDLinkAsDeviceWith", func() error {
					issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
					if issued != nil {
						t.Fatal("a failing reply returned a link")
					}
					return err
				}},
				{"OpenCRIDAsDeviceWith", func() error {
					handle, err := OpenCRIDAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
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
				assertNoDeviceKey(t, call.name+" error", err.Error(), device)
				assertNoDeviceKey(t, call.name+" %+v", fmt.Sprintf("%+v", err), device)
				assertNoDeviceKey(t, call.name+" %#v", fmt.Sprintf("%#v", err), device)
				walkErrorChain(err, func(inner error) {
					assertNoDeviceKey(t, call.name+" wrapped error", inner.Error(), device)
					assertNoDeviceKey(t, call.name+" wrapped %#v", fmt.Sprintf("%#v", inner), device)
				})
			}
		})
	}

	// The second request that is not sent because the context has ended.
	t.Run("second: not sent", func(t *testing.T) {
		fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, nil))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cfg := fixture.cfg
		cfg.HTTPClient = fixture.peer.clientThatRunsAfterEachAnswer(cancel)
		_, err := RequestCRIDLinkAsDeviceWith(ctx, device.private, fixture.crid, cfg)
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("error = %v, want the context's error and not ErrCRIDLinkNotFound", err)
		}
		assertNoDeviceKey(t, "the error", fmt.Sprintf("%v %+v %#v", err, err, err), device)
	})

	// A success must not log the key either, and neither result prints it.
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertNoDeviceKey(t, "a formatted CRIDLink", fmt.Sprintf("%v %+v %#v", issued, issued, *issued), device)
	handle, err := OpenCRIDAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertNoDeviceKey(t, "a formatted ResourceHandle", fmt.Sprintf("%v %+v %#v", handle, handle, *handle), device)

	assertNoDeviceKey(t, "the log output", logged.String(), device)
}

// The forms that take no configuration.
//
// RequestCRIDLinkAsDevice and OpenCRIDAsDevice resolve the default
// configuration, as RequestCRIDLink and OpenCRID do, and then call the With
// forms. The tests below hold the two things that are their own: they reach
// the With forms with the device key, and they refuse a key or a CRID they
// cannot use before any configuration is resolved.

// TestCRIDLinkAsDevice_ZeroSetupFromADeploymentFile is the path of a caller
// that passes no configuration. The deployment file is the only configuration,
// and the calls are the ones a customer writes. It is
// TestCRIDLink_ZeroSetupFromADeploymentFile for the device calls.
//
// RequestCRIDLinkAsDevice goes all the way: the requests, the authenticated
// replies, and the verified link. OpenCRIDAsDevice is followed to the point
// where it hands the verified link to the native opener, as OpenCRID is in
// that test: a call that takes no configuration cannot be pointed at a test
// cell.
func TestCRIDLinkAsDevice_ZeroSetupFromADeploymentFile(t *testing.T) {
	noDefaultProvider(t)
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)

	relayHost := strings.TrimPrefix(fixture.peer.server.URL, "https://")
	// The cell is named at loopback. The native transport refuses to send
	// there, which ends an open without any network I/O and says which
	// transport took it.
	t.Setenv(EnvDeploymentPath, cridLinkDeploymentFileFor(t, fixture.signer,
		fixture.peer.serverKey.PublicKey().Bytes(), "127.0.0.1", relayHost,
		`{"relay_url":"`+fixture.peer.server.URL+`","link_origin":"`+cridLinkTestOrigin+`"}`))

	// The calls that take no configuration use the default HTTP client. For
	// this test it has to trust the peer's certificate, and nothing else
	// changes.
	prior := http.DefaultTransport
	http.DefaultTransport = fixture.peer.server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prior })

	// openAsDevice runs OpenCRIDAsDevice and requires that it got a verified
	// link and handed it to the native opener. The request succeeded and the
	// link verified, or the open would have failed earlier and for another
	// reason.
	openAsDevice := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		handle, err := OpenCRIDAsDevice(ctx, device.private, fixture.crid)
		if handle != nil || err == nil {
			t.Fatalf("OpenCRIDAsDevice = %v, %v; want the native transport to refuse the loopback cell", handle, err)
		}
		if !strings.Contains(err.Error(), "nativeudp:") {
			t.Fatalf("OpenCRIDAsDevice did not reach the native opener: %v", err)
		}
		if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrCRIDLinkRejected) || errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("OpenCRIDAsDevice failed before the open: %v", err)
		}
		if strings.Contains(err.Error(), fixture.link) || strings.Contains(err.Error(), "qv2t1.") {
			t.Fatalf("the open error carries the link: %v", err)
		}
		assertNoDeviceKey(t, "the open error", fmt.Sprintf("%v %+v %#v", err, err, err), device)
	}

	t.Run("a private resource takes the second request, under the device key", func(t *testing.T) {
		fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))

		// The same configuration and the same CRID with no device key: one
		// request and "not found". So what opens the resource below is the
		// device key and nothing else.
		before := len(fixture.peer.seen())
		if _, err := RequestCRIDLink(t.Context(), fixture.crid); !errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("RequestCRIDLink error = %v, want ErrCRIDLinkNotFound for a private resource", err)
		}
		if got := len(fixture.peer.requestsSince(before)); got != 1 {
			t.Fatalf("RequestCRIDLink: the cell saw %d requests, want exactly 1", got)
		}

		before = len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDevice(t.Context(), device.private, fixture.crid)
		if err != nil {
			t.Fatalf("RequestCRIDLinkAsDevice: %v", err)
		}
		if issued.Link != fixture.link || issued.Publisher.Name != "Example Publisher" || issued.Publisher.Verified {
			t.Fatalf("RequestCRIDLinkAsDevice = %v", issued)
		}
		knocks := fixture.peer.requestsSince(before)
		if len(knocks) != 2 {
			t.Fatalf("RequestCRIDLinkAsDevice: the cell saw %d requests, want exactly 2", len(knocks))
		}
		assertRandomKeyRequest(t, "RequestCRIDLinkAsDevice: the first request", knocks[0], device, fixture.crid)
		assertDeviceKeyRequest(t, "RequestCRIDLinkAsDevice: the second request", knocks[1], device, fixture.crid)

		before = len(fixture.peer.seen())
		openAsDevice(t)
		knocks = fixture.peer.requestsSince(before)
		if len(knocks) != 2 {
			t.Fatalf("OpenCRIDAsDevice: the cell saw %d link requests, want exactly 2", len(knocks))
		}
		assertRandomKeyRequest(t, "OpenCRIDAsDevice: the first request", knocks[0], device, fixture.crid)
		assertDeviceKeyRequest(t, "OpenCRIDAsDevice: the second request", knocks[1], device, fixture.crid)
	})

	t.Run("a public resource takes one request, under a random key", func(t *testing.T) {
		fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDevice(t.Context(), device.private, fixture.crid)
		if err != nil {
			t.Fatalf("RequestCRIDLinkAsDevice: %v", err)
		}
		if issued.Link != fixture.link {
			t.Fatal("the returned link is not the link the server issued")
		}
		knocks := fixture.peer.requestsSince(before)
		if len(knocks) != 1 {
			t.Fatalf("RequestCRIDLinkAsDevice: the cell saw %d requests, want exactly 1", len(knocks))
		}
		assertRandomKeyRequest(t, "RequestCRIDLinkAsDevice: the request", knocks[0], device, fixture.crid)

		before = len(fixture.peer.seen())
		openAsDevice(t)
		knocks = fixture.peer.requestsSince(before)
		if len(knocks) != 1 {
			t.Fatalf("OpenCRIDAsDevice: the cell saw %d link requests, want exactly 1", len(knocks))
		}
		assertRandomKeyRequest(t, "OpenCRIDAsDevice: the request", knocks[0], device, fixture.crid)
	})
}

// A device key that cannot be used, and a CRID that cannot be requested, are
// refused before the default configuration is resolved. Resolving can be
// network I/O: a Provider may fetch its trust. A call that can never be made
// must not cost that, and its error must not depend on what the configuration
// holds.
//
// The key is refused first, the CRID second, as in the With forms.
func TestCRIDLinkAsDevice_RefusesBeforeTheDefaultConfigurationIsResolved(t *testing.T) {
	held, resourceKey, _ := cridKeyMatchFixture(t)
	device := newCRIDLinkDevice(t)
	transport := installCapturingTransport(t)

	// Each source of the default configuration fails when it is asked, with
	// an error the test can tell from every other. So a call that gets as far
	// as the configuration says so in its error. The Provider also counts.
	providerErr := errors.New("the default configuration was resolved")
	for _, source := range []struct {
		name string
		// install puts the source in place. It returns how often the source
		// has been asked, or nil for a source that cannot count, and the
		// error of a call that asks it.
		install func(t *testing.T) (asked func() int, whenAsked error)
	}{
		{"a Provider", func(t *testing.T) (func() int, error) {
			asked := 0
			installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
				asked++
				return nil, nil, providerErr
			}))
			return func() int { return asked }, providerErr
		}},
		{"a deployment file", func(t *testing.T) (func() int, error) {
			noDefaultProvider(t)
			// The file is not there, so reading the deployment fails.
			t.Setenv(EnvDeploymentPath, filepath.Join(t.TempDir(), "no-such-deployment.json"))
			return nil, fs.ErrNotExist
		}},
	} {
		t.Run(source.name, func(t *testing.T) {
			asked, whenAsked := source.install(t)
			// call makes both calls and returns their errors. Neither may
			// return a result in this test.
			call := func(t *testing.T, key []byte, resourceCRID string) map[string]error {
				t.Helper()
				issued, requestErr := RequestCRIDLinkAsDevice(t.Context(), key, resourceCRID)
				handle, openErr := OpenCRIDAsDevice(t.Context(), key, resourceCRID)
				if issued != nil || handle != nil {
					t.Fatal("a call that must fail returned a result")
				}
				return map[string]error{"RequestCRIDLinkAsDevice": requestErr, "OpenCRIDAsDevice": openErr}
			}
			notAsked := func(t *testing.T, what string) {
				t.Helper()
				if asked != nil && asked() != 0 {
					t.Fatalf("%s: the default configuration was resolved %d times, want none", what, asked())
				}
			}

			// A key that cannot be used. The CRID does not matter: the key is
			// refused first.
			for _, bad := range []struct {
				name string
				key  []byte
				says string
			}{
				{"no key", nil, "must be 32 bytes"},
				{"one byte short", device.private[:31], "must be 32 bytes"},
				{"one byte long", append(bytes.Clone(device.private), 0x01), "must be 32 bytes"},
				{"a wiped key", make([]byte, 32), "holds only zero bytes"},
			} {
				// The usable CRID comes first. With it, a call that did not
				// refuse the key first would go on to the configuration.
				for _, with := range []struct{ name, crid string }{{"a usable CRID", held}, {"an unusable CRID", "not a CRID"}} {
					cridName, resourceCRID := with.name, with.crid
					for name, err := range call(t, bad.key, resourceCRID) {
						what := bad.name + ", " + cridName + ", " + name
						if errors.Is(err, whenAsked) {
							t.Fatalf("%s: error = %v: the call got as far as the default configuration", what, err)
						}
						if want := "qurl: invalid resource request: the device static private key " + bad.says; err == nil || err.Error() != want {
							t.Fatalf("%s: error = %v, want %q", what, err, want)
						}
						if got := cridLinkErrorShape(err); got != "invalid input" {
							t.Fatalf("%s: error = %v (%s), want only ErrInvalidResourceRequest", what, err, got)
						}
						assertNoDeviceKey(t, what, fmt.Sprintf("%v %+v %#v", err, err, err), device)
					}
					notAsked(t, bad.name+", "+cridName)
				}
			}

			// A usable key and a CRID that cannot be requested. The error is
			// the one RequestCRIDLink and OpenCRID give for the same CRID.
			for cridName, resourceCRID := range map[string]string{
				"empty":                        "",
				"a value that is not a CRID":   "not a CRID",
				"a version that is not active": testCRIDForKey(0x02, 24, resourceKey),
			} {
				_, wantRequestErr := RequestCRIDLink(t.Context(), resourceCRID)
				_, wantOpenErr := OpenCRID(t.Context(), resourceCRID)
				want := map[string]error{"RequestCRIDLinkAsDevice": wantRequestErr, "OpenCRIDAsDevice": wantOpenErr}
				for name, err := range call(t, device.private, resourceCRID) {
					what := cridName + ", " + name
					if errors.Is(err, whenAsked) {
						t.Fatalf("%s: error = %v: the call got as far as the default configuration", what, err)
					}
					if !errors.Is(err, ErrInvalidResourceRequest) || errors.Is(err, ErrNotConfigured) {
						t.Fatalf("%s: error = %v, want the CRID refused with ErrInvalidResourceRequest", what, err)
					}
					if err.Error() != want[name].Error() || cridLinkErrorShape(err) != cridLinkErrorShape(want[name]) {
						t.Fatalf("%s: error = %v\nthe call with no key = %v\nwant the same error", what, err, want[name])
					}
				}
				notAsked(t, cridName)
			}

			// The control. A usable key and a usable CRID do reach the
			// default configuration, once per call, and get its error. So the
			// zeros above are not the zeros of a source that is never asked.
			for name, err := range call(t, device.private, held) {
				if !errors.Is(err, whenAsked) {
					t.Fatalf("%s with a usable key and CRID: error = %v, want the error of the default configuration", name, err)
				}
			}
			if asked != nil && asked() != 2 {
				t.Fatalf("two usable calls resolved the default configuration %d times, want 2", asked())
			}
		})
	}
	if transport.gotURL != "" {
		t.Fatalf("a call that must be refused first contacted %q", transport.gotURL)
	}
}
