package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
)

// The calls made as a device that take a DeviceKeySource in place of the key:
// RequestCRIDLinkAsDeviceFromKeySourceWith and
// OpenCRIDAsDeviceFromKeySourceWith, which take an explicit Config, and
// RequestCRIDLinkAsDeviceFromKeySource and OpenCRIDAsDeviceFromKeySource,
// which resolve the default configuration.
//
// They send the requests that the calls with a key send, through the same code
// path. The tests in crid_link_device_key_test.go hold the rule for those
// requests. The tests here hold what is new: when the key is read.
//
//  1. The source is not called for the first request. A call that the first
//     request answers never calls it: a public resource, another refusal, a
//     fault, no answer. A call that is refused before it sends anything never
//     calls it either.
//  2. Only a "not found" answer to the first request leads to one call of the
//     source. There is never a second call.
//  3. The key the source returns is the static key of the second request, and
//     holds only zeros when the call has returned.
//  4. A source that gives no usable key ends the call with a
//     *DeviceKeySourceError, and no request is sent under the device key.
//  5. The context of the call ends the wait for a source.
//  6. The calls that take the key itself are unchanged. Their own tests hold
//     that, and they are not edited for this change.

// keySourceProbe is a DeviceKeySource for one device. It counts its calls and
// keeps every slice it returned, so that a test can see what the SDK did with
// it.
type keySourceProbe struct {
	device cridLinkDevice

	mu       sync.Mutex
	returned [][]byte
	contexts []context.Context
}

func newKeySourceProbe(device cridLinkDevice) *keySourceProbe {
	return &keySourceProbe{device: device}
}

// source returns a new copy of the device key on every call, as a source that
// unseals the key does.
func (p *keySourceProbe) source(ctx context.Context) ([]byte, error) {
	key := bytes.Clone(p.device.private)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.returned = append(p.returned, key)
	p.contexts = append(p.contexts, ctx)
	return key, nil
}

func (p *keySourceProbe) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.returned)
}

// mustHaveWipedEveryKey fails unless every slice the source returned holds
// only zeros now. Call it when the SDK call has returned.
func (p *keySourceProbe) mustHaveWipedEveryKey(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, key := range p.returned {
		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Fatalf("the key of call %d of the source was not wiped when the SDK call returned", i+1)
		}
	}
}

// keySourceForm is one of the two calls that take a key source and an explicit
// Config, next to the call of the same kind that takes no device key.
type keySourceForm struct {
	name string
	// call reports whether the call returned a result.
	call func(ctx context.Context, source DeviceKeySource, resourceCRID string, cfg Config) (bool, error)
	// plain is the call of the same kind that takes no device key.
	plain func(ctx context.Context, resourceCRID string, cfg Config) error
}

func keySourceForms() []keySourceForm {
	return []keySourceForm{
		{
			name: "RequestCRIDLinkAsDeviceFromKeySourceWith",
			call: func(ctx context.Context, source DeviceKeySource, resourceCRID string, cfg Config) (bool, error) {
				issued, err := RequestCRIDLinkAsDeviceFromKeySourceWith(ctx, source, resourceCRID, cfg)
				return issued != nil, err
			},
			plain: func(ctx context.Context, resourceCRID string, cfg Config) error {
				_, err := RequestCRIDLinkWith(ctx, resourceCRID, cfg)
				return err
			},
		},
		{
			name: "OpenCRIDAsDeviceFromKeySourceWith",
			call: func(ctx context.Context, source DeviceKeySource, resourceCRID string, cfg Config) (bool, error) {
				handle, err := OpenCRIDAsDeviceFromKeySourceWith(ctx, source, resourceCRID, cfg)
				return handle != nil, err
			},
			plain: func(ctx context.Context, resourceCRID string, cfg Config) error {
				_, err := OpenCRIDWith(ctx, resourceCRID, cfg)
				return err
			},
		},
	}
}

// newKeySourceFixture is a link fixture whose cell also answers the open that
// follows an issued link, so both forms can run to their end, and one device.
func newKeySourceFixture(t *testing.T) (*cridLinkFixture, cridLinkDevice) {
	t.Helper()
	fixture := newCRIDLinkFixture(t)
	udp, _ := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, "https://resource.example.com/")
	fixture.cfg.nativeUDPOptions = udp
	return fixture, newCRIDLinkDevice(t)
}

// errDeviceRequestNotSentText is the text of the error for a context that
// ended after "not found" and before the request under the device key.
func errDeviceRequestNotSentText(ctxErr error) string {
	return "qurl: the CRID link request with the device key was not sent because the context ended first: " + ctxErr.Error()
}

// deviceKeySourceErrorText is the fixed text of a *DeviceKeySourceError.
const deviceKeySourceErrorText = "qurl: the CRID link request with the device key was not sent because the device key source gave no usable key"

// TestCRIDLinkAsDeviceFromKeySource_CountsTheCallsOfTheSource is the point of
// the key source: the key is read only when it is sent.
//
//   - A public resource is answered by the first request. The source is never
//     called, however often the call is made.
//   - A private resource takes the second request. The source is called once
//     in each call, and the key it returned is the static key of that request.
//   - A device that may not open the resource gets "not found" twice. The
//     source is called once, for the second request.
func TestCRIDLinkAsDeviceFromKeySource_CountsTheCallsOfTheSource(t *testing.T) {
	for _, form := range keySourceForms() {
		t.Run(form.name, func(t *testing.T) {
			t.Run("a public resource never calls the source", func(t *testing.T) {
				fixture, device := newKeySourceFixture(t)
				fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
				probe := newKeySourceProbe(device)

				const calls = 3
				for call := range calls {
					ok, err := form.call(t.Context(), probe.source, fixture.crid, fixture.cfg)
					if err != nil || !ok {
						t.Fatalf("call %d = %t, %v; want a result", call, ok, err)
					}
				}
				if got := probe.calls(); got != 0 {
					t.Fatalf("the source was called %d times for a public resource, want never", got)
				}
				knocks := fixture.peer.seen()
				if len(knocks) != calls {
					t.Fatalf("the cell saw %d link requests for %d calls, want one request per call", len(knocks), calls)
				}
				for i, knock := range knocks {
					assertRandomKeyRequest(t, fmt.Sprintf("request %d", i), knock, device, fixture.crid)
				}
			})

			t.Run("a private resource calls the source once in each call", func(t *testing.T) {
				fixture, device := newKeySourceFixture(t)
				fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
				probe := newKeySourceProbe(device)

				// The same CRID with no device key is "not found". So what
				// opens the resource below is the key from the source.
				if err := form.plain(t.Context(), fixture.crid, fixture.cfg); !errors.Is(err, ErrCRIDLinkNotFound) {
					t.Fatalf("the call with no device key: error = %v, want ErrCRIDLinkNotFound", err)
				}

				type callMark struct{}
				for call := 1; call <= 2; call++ {
					before := len(fixture.peer.seen())
					ctx := context.WithValue(t.Context(), callMark{}, call)
					ok, err := form.call(ctx, probe.source, fixture.crid, fixture.cfg)
					if err != nil || !ok {
						t.Fatalf("call %d = %t, %v; want a result", call, ok, err)
					}
					if got := probe.calls(); got != call {
						t.Fatalf("after %d call(s) the source was called %d times, want once in each call", call, got)
					}
					knocks := fixture.peer.requestsSince(before)
					if len(knocks) != 2 {
						t.Fatalf("call %d: the cell saw %d link requests, want 2", call, len(knocks))
					}
					assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
					// The cell reads the static key from the packet. It is the
					// public half of what the source returned.
					assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
					probe.mustHaveWipedEveryKey(t)
					// The source got the context of the call.
					if got := probe.contexts[call-1].Value(callMark{}); got != call {
						t.Fatalf("call %d: the source got a context that is not the context of the call", call)
					}
				}
			})

			t.Run("not found twice calls the source once", func(t *testing.T) {
				fixture, device := newKeySourceFixture(t)
				// The resource opens for another device only.
				fixture.servePrivateResource(t, newCRIDLinkDevice(t), cridLinkIssued(t, fixture.link, fixture.info()))
				probe := newKeySourceProbe(device)

				ok, err := form.call(t.Context(), probe.source, fixture.crid, fixture.cfg)
				if ok {
					t.Fatal("a device that may not open the resource got a result")
				}
				if got := cridLinkErrorShape(err); got != "not found, deny 52602" {
					t.Fatalf("error = %v (%s), want the not-found answer of the second request", err, got)
				}
				if got := probe.calls(); got != 1 {
					t.Fatalf("the source was called %d times, want once", got)
				}
				knocks := fixture.peer.seen()
				if len(knocks) != 2 {
					t.Fatalf("the cell saw %d link requests, want 2", len(knocks))
				}
				assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
				assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
				probe.mustHaveWipedEveryKey(t)
			})
		})
	}
}

// Only the server's own "not found" leads to the source. Every other outcome
// of the first request is returned as the call with no device key returns it,
// after one request under a random key, and the source is never called. So a
// fault never makes the device read its key.
func TestCRIDLinkAsDeviceFromKeySource_OtherFirstOutcomesNeverCallTheSource(t *testing.T) {
	fixture, device := newKeySourceFixture(t)
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
		want   string
	}{
		{"rate limited", cridLinkDenied(t, "52603"), "rate limited, deny 52603"},
		{"unavailable", cridLinkDenied(t, "52601"), "unavailable, deny 52601"},
		{"publisher offline", cridLinkDenied(t, "52604"), "offline, deny 52604"},
		{"resource closed", cridLinkDenied(t, "52605"), "closed, deny 52605"},
		{"invalid request", cridLinkDenied(t, "52606"), "invalid request, deny 52606"},
		{"a code outside the set", cridLinkDenied(t, "52607"), "deny 52607"},
		{"busy", cridLinkAnswer{replyType: relayknock.TypeCookieChallenge}, "overloaded"},
		{"busy, with a not-found body", cridLinkAnswer{replyType: relayknock.TypeCookieChallenge, body: notFoundBody}, "overloaded"},
		{
			"malformed: the not-found code as a number",
			cridLinkAnswer{replyType: relayknock.TypeACK, body: []byte(`{"errCode":52602}`)},
			"protocol, malformed",
		},
		{
			"malformed: not found in a reply of another type",
			cridLinkAnswer{replyType: relayknock.TypeListResult, body: notFoundBody},
			"malformed",
		},
		{"relay fault", cridLinkAnswer{status: http.StatusBadGateway, text: "upstream unavailable"}, "relay 502"},
		{"relay answers 404", cridLinkAnswer{status: http.StatusNotFound, text: "not found"}, "relay 404"},
		{"not found under a key that is not the cell's", forgedNotFound, "an error that matches nothing"},
		{
			"a link that fails a check",
			cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil),
			"rejected, CRID mismatch, class crid_mismatch",
		},
	} {
		for _, form := range keySourceForms() {
			t.Run(tc.name+"/"+form.name, func(t *testing.T) {
				fixture.peer.respond(tc.answer)
				plainErr := form.plain(t.Context(), fixture.crid, fixture.cfg)
				if got := cridLinkErrorShape(plainErr); got != tc.want {
					t.Fatalf("the call with no device key: error = %v (%s), want %s", plainErr, got, tc.want)
				}

				probe := newKeySourceProbe(device)
				before := len(fixture.peer.seen())
				ok, err := form.call(t.Context(), probe.source, fixture.crid, fixture.cfg)
				if ok {
					t.Fatal("a failing first request returned a result")
				}
				if got := cridLinkErrorShape(err); got != tc.want {
					t.Fatalf("error = %v (%s), want %s", err, got, tc.want)
				}
				if got := probe.calls(); got != 0 {
					t.Fatalf("the source was called %d times, want never: the first answer was not \"not found\"", got)
				}
				knocks := fixture.peer.requestsSince(before)
				if len(knocks) != 1 {
					t.Fatalf("the cell saw %d link requests, want exactly 1", len(knocks))
				}
				assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
			})
		}
	}

	// No reply at all: the caller's context ends while the first request
	// waits. The source is not called for a request that got no answer.
	for name, end := range map[string]error{
		"no reply, and the caller cancels":   context.Canceled,
		"no reply, and the deadline goes by": context.DeadlineExceeded,
	} {
		for _, form := range keySourceForms() {
			t.Run(name+"/"+form.name, func(t *testing.T) {
				release := make(chan struct{})
				t.Cleanup(func() { close(release) })
				ctx := newEndableContext(t, end)
				fixture.peer.respondWith(func(cridLinkKnock) cridLinkAnswer {
					ctx.end()
					return cridLinkAnswer{hold: release}
				})
				probe := newKeySourceProbe(device)
				ok, err := form.call(ctx, probe.source, fixture.crid, fixture.cfg)
				if ok || !errors.Is(err, end) {
					t.Fatalf("call = %t, %v; want %v and no result", ok, err, end)
				}
				if got := probe.calls(); got != 0 {
					t.Fatalf("the source was called %d times for a request that got no answer, want never", got)
				}
			})
		}
	}
}

// A call that is refused before it sends anything never calls the source, and
// reports the refusal with the error of the call that takes no device key.
func TestCRIDLinkAsDeviceFromKeySource_RefusedBeforeAnythingIsSentNeverCallsTheSource(t *testing.T) {
	fixture, device := newKeySourceFixture(t)
	// A device that would get a link, so "no result" is the refusal.
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))

	noEndpoint := fixture.cfg
	noEndpoint.CRIDLink = nil
	badOrigin := fixture.cfg
	endpoint := *fixture.cfg.CRIDLink
	endpoint.LinkOrigin = "https://qurl.link/"
	badOrigin.CRIDLink = &endpoint
	contradicting := fixture.cfg
	contradicting.ExpectedCRID = testCRIDForKey(0x01, 32, fixture.foreignKey)
	ended, cancel := context.WithCancel(t.Context())
	cancel()

	for _, tc := range []struct {
		name string
		ctx  context.Context
		crid string
		cfg  Config
	}{
		{"a value that is not a CRID", t.Context(), "not a CRID", fixture.cfg},
		{"a CRID of a version that is not active", t.Context(), testCRIDForKey(0x02, 24, fixture.resourceKey), fixture.cfg},
		{"a contradicting pin", t.Context(), fixture.crid, contradicting},
		{"no endpoint", t.Context(), fixture.crid, noEndpoint},
		{"an endpoint that cannot be used", t.Context(), fixture.crid, badOrigin},
		{"a context that has ended before the call", ended, fixture.crid, fixture.cfg},
	} {
		for _, form := range keySourceForms() {
			t.Run(tc.name+"/"+form.name, func(t *testing.T) {
				want := form.plain(tc.ctx, tc.crid, tc.cfg)
				if want == nil {
					t.Fatal("fixture drift: the call with no device key accepts this input")
				}
				probe := newKeySourceProbe(device)
				before := len(fixture.peer.seen())
				ok, err := form.call(tc.ctx, probe.source, tc.crid, tc.cfg)
				if ok {
					t.Fatal("a call that must be refused returned a result")
				}
				if err == nil || cridLinkErrorShape(err) != cridLinkErrorShape(want) {
					t.Fatalf("error = %v (%s)\nthe call with no device key = %v (%s)\nwant the same error",
						err, cridLinkErrorShape(err), want, cridLinkErrorShape(want))
				}
				if got := probe.calls(); got != 0 {
					t.Fatalf("the source was called %d times by a call that was refused first, want never", got)
				}
				if got := len(fixture.peer.requestsSince(before)); got != 0 {
					t.Fatalf("a call that must be refused first sent %d request(s)", got)
				}
			})
		}
	}
}

// A source that returns an error ends the call. The error is a
// *DeviceKeySourceError that holds the source's error and the answer to the
// first request. No request is sent under the device key, and the error is
// not "not found": nobody asked as the device.
func TestCRIDLinkAsDeviceFromKeySource_ASourceThatFails(t *testing.T) {
	// The text of a careless source: it names its key. The SDK's own text
	// must not repeat it.
	const sourceSecret = "sealed state says 6b65792d6d6174657269616c"
	errSealed := errors.New(sourceSecret)

	for _, form := range keySourceForms() {
		for _, tc := range []struct {
			name string
			// leftover is what the failing source returns beside its error.
			leftover []byte
		}{
			{"an error and no key", nil},
			{"an error and a key beside it", bytes.Repeat([]byte{0x5a}, 32)},
		} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				fixture, device := newKeySourceFixture(t)
				// The device may open the resource. A second request would
				// get a link, so "no result" means it was not sent.
				fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
				calls := 0
				source := func(context.Context) ([]byte, error) {
					calls++
					return tc.leftover, errSealed
				}

				ok, err := form.call(t.Context(), source, fixture.crid, fixture.cfg)
				if ok {
					t.Fatal("a call whose source failed returned a result")
				}
				var sourceErr *DeviceKeySourceError
				if !errors.As(err, &sourceErr) {
					t.Fatalf("error = %v (%T), want a *DeviceKeySourceError", err, err)
				}
				// The source's error is the cause: in the field, and for
				// errors.Is on the error the call returned.
				if !errors.Is(sourceErr.Err, errSealed) || !errors.Is(err, errSealed) {
					t.Fatalf("error = %v with cause %v, want the source's own error as the cause", err, sourceErr.Err)
				}
				// The answer to the first request is kept beside it, as the
				// call with no device key returns it.
				plainErr := form.plain(t.Context(), fixture.crid, fixture.cfg)
				if got := cridLinkErrorShape(sourceErr.FirstAnswer); got != "not found, deny 52602" || got != cridLinkErrorShape(plainErr) {
					t.Fatalf("FirstAnswer = %v (%s), want the not-found answer of the first request", sourceErr.FirstAnswer, got)
				}
				// The error itself is not "not found", in any form a caller
				// can match, and it is none of the other outcomes.
				if got := cridLinkErrorShape(err); got != "an error that matches nothing" {
					t.Fatalf("error = %v (%s), want an error that matches no outcome of a request", err, got)
				}
				// The text is fixed. It does not hold the source's text.
				if err.Error() != deviceKeySourceErrorText {
					t.Fatalf("error text = %q\nwant         %q", err.Error(), deviceKeySourceErrorText)
				}
				for verb, text := range map[string]string{"%v": fmt.Sprintf("%v", err), "%+v": fmt.Sprintf("%+v", err), "%s": fmt.Sprintf("%s", err)} {
					if strings.Contains(text, sourceSecret) || strings.Contains(text, "6b6579") {
						t.Fatalf("the error printed with %s holds the text of the source's error: %q", verb, text)
					}
				}

				if calls != 1 {
					t.Fatalf("the source was called %d times, want once", calls)
				}
				// One request, under a random key. Nothing under the device
				// key: the cell would have recorded it.
				knocks := fixture.peer.seen()
				if len(knocks) != 2 { // the call under test, and the plain call above
					t.Fatalf("the cell saw %d link requests, want 2: one of the call and one of the reference call", len(knocks))
				}
				for i, knock := range knocks {
					assertRandomKeyRequest(t, fmt.Sprintf("request %d", i), knock, device, fixture.crid)
				}
				// Bytes a failing source returned are not used and are wiped.
				if tc.leftover != nil && !bytes.Equal(tc.leftover, make([]byte, len(tc.leftover))) {
					t.Fatal("the bytes a failing source returned were not wiped")
				}
			})
		}
	}
}

// A key the source returns is checked when the source returns it, with the
// gate of the calls that take the key. A key that fails it is not used: the
// error is a *DeviceKeySourceError that matches ErrInvalidDeviceKey, and no
// request is sent under any key derived from those bytes.
func TestCRIDLinkAsDeviceFromKeySource_AKeyTheSourceReturnsMustBeUsable(t *testing.T) {
	for _, form := range keySourceForms() {
		for _, tc := range []struct {
			name string
			key  func(device cridLinkDevice) []byte
			says string
		}{
			{"no key and no error", func(cridLinkDevice) []byte { return nil }, "must be 32 bytes"},
			{"an empty key", func(cridLinkDevice) []byte { return []byte{} }, "must be 32 bytes"},
			{"one byte short", func(d cridLinkDevice) []byte { return bytes.Clone(d.private[:31]) }, "must be 32 bytes"},
			{"one byte long", func(d cridLinkDevice) []byte { return append(bytes.Clone(d.private), 0x01) }, "must be 32 bytes"},
			{"a wiped key", func(cridLinkDevice) []byte { return make([]byte, 32) }, "holds only zero bytes"},
		} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				fixture, device := newKeySourceFixture(t)
				fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
				returned := tc.key(device)
				calls := 0
				source := func(context.Context) ([]byte, error) {
					calls++
					return returned, nil
				}

				ok, err := form.call(t.Context(), source, fixture.crid, fixture.cfg)
				if ok {
					t.Fatal("a call whose source returned an unusable key returned a result")
				}
				var sourceErr *DeviceKeySourceError
				if !errors.As(err, &sourceErr) {
					t.Fatalf("error = %v (%T), want a *DeviceKeySourceError", err, err)
				}
				if !errors.Is(err, ErrInvalidDeviceKey) || errors.Is(err, ErrInvalidResourceRequest) {
					t.Fatalf("error = %v, want it to match ErrInvalidDeviceKey and not ErrInvalidResourceRequest", err)
				}
				if got := cridLinkErrorShape(err); got != "invalid device key" {
					t.Fatalf("error = %v (%s), want only ErrInvalidDeviceKey", err, got)
				}
				// The cause says what is wrong with the key, in the words of
				// the calls that take the key.
				if want := "qurl: invalid device static private key: it " + tc.says; sourceErr.Err == nil || sourceErr.Err.Error() != want {
					t.Fatalf("cause = %v, want %q", sourceErr.Err, want)
				}
				if err.Error() != deviceKeySourceErrorText {
					t.Fatalf("error text = %q\nwant         %q", err.Error(), deviceKeySourceErrorText)
				}
				if got := cridLinkErrorShape(sourceErr.FirstAnswer); got != "not found, deny 52602" {
					t.Fatalf("FirstAnswer = %v (%s), want the not-found answer of the first request", sourceErr.FirstAnswer, got)
				}
				assertNoDeviceKey(t, "the error", fmt.Sprintf("%v %+v", err, err), device)
				assertNoDeviceKey(t, "the cause", sourceErr.Err.Error(), device)

				if calls != 1 {
					t.Fatalf("the source was called %d times, want once", calls)
				}
				knocks := fixture.peer.seen()
				if len(knocks) != 1 {
					t.Fatalf("the cell saw %d link requests, want exactly 1", len(knocks))
				}
				assertRandomKeyRequest(t, "the request", knocks[0], device, fixture.crid)
				if !bytes.Equal(returned, make([]byte, len(returned))) {
					t.Fatal("the unusable key the source returned was not wiped")
				}
			})
		}
	}
}

// A nil source is refused first: before the CRID or the configuration is
// looked at, and before anything is sent. A call made "as a device" with no
// source must not turn into the call that takes no key.
func TestCRIDLinkAsDeviceFromKeySource_ANilSourceIsRefusedFirst(t *testing.T) {
	const wantText = "qurl: invalid device static private key: no device key source was given"
	mustBeTheRefusal := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil || err.Error() != wantText {
			t.Fatalf("%s: error = %v, want %q", what, err, wantText)
		}
		if got := cridLinkErrorShape(err); got != "invalid device key" {
			t.Fatalf("%s: error = %v (%s), want only ErrInvalidDeviceKey", what, err, got)
		}
		var sourceErr *DeviceKeySourceError
		if errors.As(err, &sourceErr) {
			t.Fatalf("%s: error = %v is a *DeviceKeySourceError, which says that a request was sent", what, err)
		}
	}

	t.Run("with an explicit configuration", func(t *testing.T) {
		fixture, _ := newKeySourceFixture(t)
		fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
		noEndpoint := fixture.cfg
		noEndpoint.CRIDLink = nil
		noTrust := fixture.cfg
		noTrust.TrustStore = nil

		for _, form := range keySourceForms() {
			for _, with := range []struct {
				name string
				crid string
				cfg  Config
			}{
				{"a usable CRID and configuration", fixture.crid, fixture.cfg},
				{"an unusable CRID", "not a CRID", fixture.cfg},
				{"no endpoint", fixture.crid, noEndpoint},
				{"no trust store", fixture.crid, noTrust},
			} {
				doer := &refusingDoer{t: t}
				cfg := with.cfg
				cfg.HTTPClient = doer
				ok, err := form.call(t.Context(), nil, with.crid, cfg)
				if ok {
					t.Fatalf("%s, %s: a call with no source returned a result", form.name, with.name)
				}
				mustBeTheRefusal(t, form.name+", "+with.name, err)
				if doer.called {
					t.Fatalf("%s, %s: a request was handed to the HTTP client although there is no source", form.name, with.name)
				}
			}
		}
		if got := len(fixture.peer.seen()); got != 0 {
			t.Fatalf("%d requests were sent although no call had a source", got)
		}
	})

	// The forms that resolve the default configuration refuse a nil source,
	// and then a CRID that cannot be requested, before they resolve anything.
	t.Run("before the default configuration is resolved", func(t *testing.T) {
		held, resourceKey, _ := cridKeyMatchFixture(t)
		device := newCRIDLinkDevice(t)
		transport := installCapturingTransport(t)
		providerErr := errors.New("the default configuration was resolved")
		asked := 0
		installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
			asked++
			return nil, nil, providerErr
		}))
		call := func(source DeviceKeySource, resourceCRID string) map[string]error {
			issued, requestErr := RequestCRIDLinkAsDeviceFromKeySource(t.Context(), source, resourceCRID)
			handle, openErr := OpenCRIDAsDeviceFromKeySource(t.Context(), source, resourceCRID)
			if issued != nil || handle != nil {
				t.Fatal("a call that must fail returned a result")
			}
			return map[string]error{"RequestCRIDLinkAsDeviceFromKeySource": requestErr, "OpenCRIDAsDeviceFromKeySource": openErr}
		}

		for _, resourceCRID := range []string{held, "not a CRID"} {
			for name, err := range call(nil, resourceCRID) {
				mustBeTheRefusal(t, name, err)
			}
		}
		probe := newKeySourceProbe(device)
		for cridName, resourceCRID := range map[string]string{
			"empty":                        "",
			"a value that is not a CRID":   "not a CRID",
			"a version that is not active": testCRIDForKey(0x02, 24, resourceKey),
		} {
			_, wantRequestErr := RequestCRIDLink(t.Context(), resourceCRID)
			_, wantOpenErr := OpenCRID(t.Context(), resourceCRID)
			want := map[string]error{"RequestCRIDLinkAsDeviceFromKeySource": wantRequestErr, "OpenCRIDAsDeviceFromKeySource": wantOpenErr}
			for name, err := range call(probe.source, resourceCRID) {
				if err == nil || err.Error() != want[name].Error() || !errors.Is(err, ErrInvalidResourceRequest) || errors.Is(err, providerErr) {
					t.Fatalf("%s, %s: error = %v\nthe call with no key = %v\nwant the same refusal of the CRID", cridName, name, err, want[name])
				}
			}
		}
		if asked != 0 {
			t.Fatalf("the default configuration was resolved %d times by calls that must be refused first, want none", asked)
		}

		// The control. A source and a usable CRID do reach the default
		// configuration, once in each call, and get its error. So the zero
		// above is not the zero of a configuration that is never asked.
		for name, err := range call(probe.source, held) {
			if !errors.Is(err, providerErr) {
				t.Fatalf("%s with a source and a usable CRID: error = %v, want the error of the default configuration", name, err)
			}
		}
		if asked != 2 {
			t.Fatalf("two usable calls resolved the default configuration %d times, want 2", asked)
		}
		if got := probe.calls(); got != 0 {
			t.Fatalf("the source was called %d times although no call sent a request, want never", got)
		}
		if transport.gotURL != "" {
			t.Fatalf("a call that must be refused first contacted %q", transport.gotURL)
		}
	})
}

// neverDoneContext is a context that reports that it has ended through Err
// while its Done channel is not closed. A real context closes Done at the
// same moment. So this is the instant in which the SDK has taken the source's
// answer and has not seen Done yet, held still for a test.
type neverDoneContext struct {
	context.Context
	ended atomic.Bool
}

func (c *neverDoneContext) Done() <-chan struct{} { return nil }

func (c *neverDoneContext) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

// The context of the call covers the source.
//
// When it has ended by the time the first request is answered "not found",
// the source is not called at all. When it ends while the source is running,
// the call returns without waiting for the source. In both cases the error is
// the one for a context that ended between the two requests, and no request
// is sent under the device key.
func TestCRIDLinkAsDeviceFromKeySource_TheContextCoversTheSource(t *testing.T) {
	for _, form := range keySourceForms() {
		t.Run(form.name+"/the context ends after the first answer: the source is not called", func(t *testing.T) {
			fixture, device := newKeySourceFixture(t)
			fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := fixture.cfg
			client := &countingDoer{next: fixture.peer.clientThatRunsAfterEachAnswer(cancel)}
			cfg.HTTPClient = client
			probe := newKeySourceProbe(device)

			ok, err := form.call(ctx, probe.source, fixture.crid, cfg)
			if ok || err == nil || err.Error() != errDeviceRequestNotSentText(context.Canceled) {
				t.Fatalf("call = %t, %v; want the error of a request that was not sent because the context ended", ok, err)
			}
			if got := cridLinkErrorShape(err); got != "canceled" {
				t.Fatalf("error = %v (%s), want only the context's error", err, got)
			}
			if got := probe.calls(); got != 0 {
				t.Fatalf("the source was called %d times after the context had ended, want never", got)
			}
			if got := client.handed.Load(); got != 1 {
				t.Fatalf("the HTTP client was handed %d requests, want only the first", got)
			}
		})

		// The same moment with a context whose Done channel stays open. With
		// a real context a call that did ask the source would return before
		// the source ran, and the count above would not show it. Here such a
		// call has to wait for the source, so the count is certain.
		t.Run(form.name+"/the context has ended after the first answer: the source is never asked", func(t *testing.T) {
			fixture, device := newKeySourceFixture(t)
			fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
			ctx := &neverDoneContext{Context: t.Context()}
			cfg := fixture.cfg
			client := &countingDoer{next: fixture.peer.clientThatRunsAfterEachAnswer(func() { ctx.ended.Store(true) })}
			cfg.HTTPClient = client
			probe := newKeySourceProbe(device)

			ok, err := form.call(ctx, probe.source, fixture.crid, cfg)
			if ok || err == nil || err.Error() != errDeviceRequestNotSentText(context.Canceled) {
				t.Fatalf("call = %t, %v; want the error of a request that was not sent because the context ended", ok, err)
			}
			if got := probe.calls(); got != 0 {
				t.Fatalf("the source was called %d times after the context had ended, want never", got)
			}
			if got := client.handed.Load(); got != 1 {
				t.Fatalf("the HTTP client was handed %d requests, want only the first", got)
			}
		})

		t.Run(form.name+"/the context ends while the source runs: the call does not wait", func(t *testing.T) {
			fixture, device := newKeySourceFixture(t)
			fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := fixture.cfg
			client := &countingDoer{next: fixture.peer.server.Client()}
			cfg.HTTPClient = client

			// A source that does not look at its context. It returns only
			// when the test lets it, which is after the call has returned.
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			source := func(context.Context) ([]byte, error) {
				calls.Add(1)
				close(started)
				<-release
				return bytes.Clone(device.private), nil
			}
			t.Cleanup(func() { close(release) })

			type outcome struct {
				ok  bool
				err error
			}
			returned := make(chan outcome, 1)
			go func() {
				ok, err := form.call(ctx, source, fixture.crid, cfg)
				returned <- outcome{ok, err}
			}()
			select {
			case <-started:
			case <-time.After(30 * time.Second):
				t.Fatal("the source was not called after \"not found\"")
			}
			cancel()
			var got outcome
			select {
			case got = <-returned:
			case <-time.After(30 * time.Second):
				t.Fatal("the call did not return when its context ended: it waits for the source")
			}

			if got.ok || got.err == nil || got.err.Error() != errDeviceRequestNotSentText(context.Canceled) {
				t.Fatalf("call = %t, %v; want the error of a request that was not sent because the context ended", got.ok, got.err)
			}
			// It is the context's error and nothing else: not "not found",
			// and not the error of a source that failed.
			if shape := cridLinkErrorShape(got.err); shape != "canceled" {
				t.Fatalf("error = %v (%s), want only the context's error", got.err, shape)
			}
			var sourceErr *DeviceKeySourceError
			if errors.As(got.err, &sourceErr) {
				t.Fatalf("error = %v is a *DeviceKeySourceError although the source did not fail", got.err)
			}
			if n := calls.Load(); n != 1 {
				t.Fatalf("the source was called %d times, want once", n)
			}
			if n := client.handed.Load(); n != 1 {
				t.Fatalf("the HTTP client was handed %d requests, want only the first", n)
			}
		})

		// The source returns a key in the moment the context ends, and the
		// SDK takes the key before it sees that the context has ended. The
		// key must not be used all the same.
		t.Run(form.name+"/a key that arrives as the context ends is not used", func(t *testing.T) {
			fixture, device := newKeySourceFixture(t)
			fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
			ctx := &neverDoneContext{Context: t.Context()}
			cfg := fixture.cfg
			client := &countingDoer{next: fixture.peer.clientThatRunsAfterEachAnswer(func() {})}
			cfg.HTTPClient = client
			returnedKey := bytes.Clone(device.private)
			source := func(context.Context) ([]byte, error) {
				ctx.ended.Store(true)
				return returnedKey, nil
			}

			ok, err := form.call(ctx, source, fixture.crid, cfg)
			if ok || err == nil || err.Error() != errDeviceRequestNotSentText(context.Canceled) {
				t.Fatalf("call = %t, %v; want the error of a request that was not sent because the context ended", ok, err)
			}
			if got := client.handed.Load(); got != 1 {
				t.Fatalf("the HTTP client was handed %d requests, want only the first: the key arrived after the context had ended", got)
			}
			if !bytes.Equal(returnedKey, make([]byte, len(returnedKey))) {
				t.Fatal("the key that arrived as the context ended was not wiped")
			}
		})
	}
}

// A source that returns after the call gave up hands its key to nobody. The
// goroutine that ran the source wipes it.
//
// This test is on the unexported type, because it needs to know when that
// goroutine has ended. Nothing a caller can see tells that.
func TestDeviceKeyAsk_WipesAKeyThatArrivesAfterTheWaitGaveUp(t *testing.T) {
	device := newCRIDLinkDevice(t)
	firstAnswer := fmt.Errorf("%w: %w", ErrCRIDLinkNotFound, &ServerDenyError{ErrCode: "52602"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	started, release := make(chan struct{}), make(chan struct{})
	lateKey := bytes.Clone(device.private)
	ask := askDeviceKeySource(ctx, func(context.Context) ([]byte, error) {
		close(started)
		<-release
		return lateKey, nil
	})
	<-started
	cancel()
	key, err := ask.wait(ctx, firstAnswer)
	if key != nil || err == nil || err.Error() != errDeviceRequestNotSentText(context.Canceled) {
		t.Fatalf("wait = %d bytes, %v; want no key and the context's error", len(key), err)
	}
	select {
	case <-ask.finished:
		t.Fatal("the goroutine of the source ended before the source returned")
	default:
	}

	// Now the source returns. Nobody waits for the key.
	close(release)
	select {
	case <-ask.finished:
	case <-time.After(30 * time.Second):
		t.Fatal("the goroutine of the source did not end after the source returned: it still waits to hand over the key")
	}
	if !bytes.Equal(lateKey, make([]byte, len(lateKey))) {
		t.Fatal("a key that arrived after the call gave up was not wiped")
	}
}

// The SDK's own text never holds a key from a source: not in an error of the
// second request, and not in a log line. It is the fence of
// TestCRIDLinkAsDevice_NeverPutsTheDeviceKeyInAnErrorOrALog for a key that
// came from a source.
func TestCRIDLinkAsDeviceFromKeySource_NeverPutsTheKeyInAnErrorOrALog(t *testing.T) {
	fixture, device := newKeySourceFixture(t)

	logged := new(lockedBuffer)
	priorWriter, priorFlags, priorSlog := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(logged)
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(priorSlog)
		log.SetOutput(priorWriter)
		log.SetFlags(priorFlags)
	})

	notFound := cridLinkDenied(t, "52602")
	for name, second := range map[string]cridLinkAnswer{
		"not found":     notFound,
		"rate limited":  cridLinkDenied(t, "52603"),
		"busy":          {replyType: relayknock.TypeCookieChallenge},
		"malformed":     {replyType: relayknock.TypeACK, body: []byte(`[]`)},
		"relay fault":   {status: http.StatusBadGateway, text: "upstream failed"},
		"rejected link": cridLinkIssued(t, fixture.mint(t, fixture.foreignKey), nil),
	} {
		for _, form := range keySourceForms() {
			t.Run(name+"/"+form.name, func(t *testing.T) {
				fixture.peer.respondWith(func(knock cridLinkKnock) cridLinkAnswer {
					if bytes.Equal(knock.devicePub, device.public) {
						return second
					}
					return notFound
				})
				probe := newKeySourceProbe(device)
				ok, err := form.call(t.Context(), probe.source, fixture.crid, fixture.cfg)
				if ok || err == nil {
					t.Fatalf("call = %t, %v; want an error", ok, err)
				}
				if got := probe.calls(); got != 1 {
					t.Fatalf("the source was called %d times, want once", got)
				}
				assertNoDeviceKey(t, "the error", fmt.Sprintf("%v %+v %#v", err, err, err), device)
				walkErrorChain(err, func(inner error) {
					assertNoDeviceKey(t, "a wrapped error", fmt.Sprintf("%v %#v", inner, inner), device)
				})
				probe.mustHaveWipedEveryKey(t)
			})
		}
	}

	// A success logs nothing of the key either.
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	probe := newKeySourceProbe(device)
	issued, err := RequestCRIDLinkAsDeviceFromKeySourceWith(t.Context(), probe.source, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertNoDeviceKey(t, "a formatted CRIDLink", fmt.Sprintf("%v %+v %#v", issued, issued, *issued), device)
	assertNoDeviceKey(t, "the log output", logged.String(), device)
	// The fence can see a key: the hex of the private key is caught.
	if !holdsDeviceKey(hex.EncodeToString(device.private), device) {
		t.Fatal("the fence does not see the device key in hex")
	}
}

// OpenCRIDAsDeviceFromKeySourceWith end to end, for a private resource: the
// source is called once, its key is the static key of the second link request
// only, and the key is already wiped when the open starts. The open uses the
// link's own key.
func TestOpenCRIDAsDeviceFromKeySourceWith_OpensAPrivateResource(t *testing.T) {
	const resourceURL = "https://resource.example.com/report"
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
	udp, admittedKeys := startCRIDLinkCellUDP(t, fixture.peer, fixture.cfg.TrustStore, fixture.link, resourceURL)
	probe := newKeySourceProbe(device)

	// The open resolves the name of the cell first. That runs after the link
	// request has ended, so it is where the test looks at the key.
	resolver := udp.Resolver
	wipedBeforeTheOpen := false
	udp.Resolver = assignmentTestResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		probe.mu.Lock()
		wipedBeforeTheOpen = len(probe.returned) == 1 && bytes.Equal(probe.returned[0], make([]byte, 32))
		probe.mu.Unlock()
		return resolver.LookupNetIP(ctx, network, host)
	})
	fixture.cfg.nativeUDPOptions = udp

	handle, err := OpenCRIDAsDeviceFromKeySourceWith(t.Context(), probe.source, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("OpenCRIDAsDeviceFromKeySourceWith: %v", err)
	}
	if handle.ResourceURL != resourceURL || handle.SessionID != 123 || handle.OpenSeconds != 900 {
		t.Fatalf("handle = %v", handle)
	}
	if got := probe.calls(); got != 1 {
		t.Fatalf("the source was called %d times, want once: the open does not use the device key", got)
	}
	if !wipedBeforeTheOpen {
		t.Fatal("the key from the source was not wiped before the open started")
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

	// The handle is the one the call that takes the key reaches.
	withKey, err := OpenCRIDAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.cfg)
	if err != nil {
		t.Fatalf("OpenCRIDAsDeviceWith: %v", err)
	}
	if *withKey != *handle {
		t.Fatalf("OpenCRIDAsDeviceFromKeySourceWith handle = %v, OpenCRIDAsDeviceWith handle = %v", handle, withKey)
	}
}

// The two forms that take no configuration reach the With forms with the
// source. It is TestCRIDLinkAsDevice_ZeroSetupFromADeploymentFile for the
// calls that take a key source: the deployment file is the only
// configuration.
func TestCRIDLinkAsDeviceFromKeySource_ZeroSetupFromADeploymentFile(t *testing.T) {
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
	prior := http.DefaultTransport
	http.DefaultTransport = fixture.peer.server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prior })

	// open runs OpenCRIDAsDeviceFromKeySource and requires that it got a
	// verified link and handed it to the native opener.
	open := func(t *testing.T, source DeviceKeySource) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		handle, err := OpenCRIDAsDeviceFromKeySource(ctx, source, fixture.crid)
		if handle != nil || err == nil || !strings.Contains(err.Error(), "nativeudp:") {
			t.Fatalf("OpenCRIDAsDeviceFromKeySource = %v, %v; want the native transport to refuse the loopback cell", handle, err)
		}
		if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrCRIDLinkRejected) || errors.Is(err, ErrCRIDLinkNotFound) {
			t.Fatalf("OpenCRIDAsDeviceFromKeySource failed before the open: %v", err)
		}
		assertNoDeviceKey(t, "the open error", fmt.Sprintf("%v %+v %#v", err, err, err), device)
	}

	t.Run("a private resource calls the source once in each call", func(t *testing.T) {
		fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
		probe := newKeySourceProbe(device)

		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDeviceFromKeySource(t.Context(), probe.source, fixture.crid)
		if err != nil || issued.Link != fixture.link {
			t.Fatalf("RequestCRIDLinkAsDeviceFromKeySource = %v, %v; want the link the server issued", issued, err)
		}
		knocks := fixture.peer.requestsSince(before)
		if len(knocks) != 2 || probe.calls() != 1 {
			t.Fatalf("RequestCRIDLinkAsDeviceFromKeySource: %d link requests and %d calls of the source, want 2 and 1", len(knocks), probe.calls())
		}
		assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
		assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)

		before = len(fixture.peer.seen())
		open(t, probe.source)
		knocks = fixture.peer.requestsSince(before)
		if len(knocks) != 2 || probe.calls() != 2 {
			t.Fatalf("OpenCRIDAsDeviceFromKeySource: %d link requests and %d calls of the source in all, want 2 and 2", len(knocks), probe.calls())
		}
		assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
		assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
		probe.mustHaveWipedEveryKey(t)
	})

	t.Run("a public resource never calls the source", func(t *testing.T) {
		fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
		probe := newKeySourceProbe(device)

		before := len(fixture.peer.seen())
		issued, err := RequestCRIDLinkAsDeviceFromKeySource(t.Context(), probe.source, fixture.crid)
		if err != nil || issued.Link != fixture.link {
			t.Fatalf("RequestCRIDLinkAsDeviceFromKeySource = %v, %v; want the link the server issued", issued, err)
		}
		open(t, probe.source)
		knocks := fixture.peer.requestsSince(before)
		if len(knocks) != 2 {
			t.Fatalf("two calls for a public resource sent %d link requests, want one each", len(knocks))
		}
		for i, knock := range knocks {
			assertRandomKeyRequest(t, fmt.Sprintf("request %d", i), knock, device, fixture.crid)
		}
		if got := probe.calls(); got != 0 {
			t.Fatalf("the source was called %d times for a public resource, want never", got)
		}
	})
}
