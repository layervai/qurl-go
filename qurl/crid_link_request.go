package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
)

// Opening a resource by CRID.
//
// EnterPortal opens a link. A client that holds only a CRID has no link, and a
// link is what turns the identifier into access, so opening by CRID is two
// steps:
//
//  1. Ask the server for a link. The request is an ordinary knock whose body
//     names the CRID, sent through the deployment's relay under a key minted
//     for that one request. The reply either carries a short-lived qURL link
//     or says why there is none. This step opens nothing.
//  2. Open the link with the existing opener, bound to the CRID.
//
// The link in step 1 comes from the network, so it is used only after it has
// been checked against things the client already holds: the deployment's link
// origin, the trust store, and the CRID that was asked for. The checks, their
// order, and the outcome of every reply are pinned by the public
// qurl-crid-link-knock-v1-vectors conformance artifact.
//
// The calls made as a device go beyond the text of that artifact in one way,
// and in this one way only. The artifact says that a v1 client uses a fresh
// random key for every request, and that a client does not retry after the
// outcome code 52602, "not found". After 52602 the device calls send one new
// request under the device key. That request and its reply have the shapes the
// artifact pins, and the outcome of the reply is read as the artifact says.
//
// Step 1 always goes through the relay, also when the configuration opens
// links over native UDP. That is the v1 contract: direct UDP is not a
// transport for this request.
//
// Step 1 is one request. Only the calls made as a device can make it two:
// RequestCRIDLinkAsDevice, OpenCRIDAsDevice, and their With forms. They do so
// only when the server answers the first request with "not found": the second
// request is the same request, sent under the caller's device key. See
// RequestCRIDLinkAsDeviceWith.

// CRIDLink is a qURL link the server issued for a CRID, returned only after
// every client check on it has passed: it is on the deployment's link origin,
// its issuer signature verifies under the trust store, and its signed resource
// key derives the CRID that was requested.
//
// Link is a credential. Whoever holds it can open the resource until it
// expires, so do not log it. String and GoString redact it, which covers
// printing a CRIDLink with %v, %+v, %#v, or %s. Reading the field and
// serializing the value remain the caller's responsibility: encoding/json
// writes the link, and so does a structured logger that encodes its values as
// JSON.
//
// Every other field is display-only. It is reported by the server next to the
// link and is NOT covered by the link's signature or by the CRID: a link that
// verifies says nothing about the publisher, the timestamps, or the qURL id
// reported beside it. The fields carry the names and the absence rules of the
// same fields on ShareLink.
type CRIDLink struct {
	// Link is the access link. Open it with EnterPortalForCRID and the same
	// CRID, or let OpenCRID do both steps.
	Link string
	// QURLID identifies this one issued link, or is empty when the server
	// reported none. Server-supplied text: escape it before display.
	QURLID string
	// ExpiresAt is when the server says the link stops working; zero when the
	// server reported no time or one that does not parse. The authoritative
	// expiry is the one inside the signed link, which the server enforces when
	// the link is opened.
	ExpiresAt time.Time
	// ResourceCreatedAt is when the resource behind the CRID was created, as
	// the server reports it. It is the resource's age, not the link's. Unlike
	// ExpiresAt, absence is nil rather than the zero time: nil when the server
	// reported no time, the zero time, or one that does not parse.
	ResourceCreatedAt *time.Time
	// Publisher describes who published the resource. The name is self-declared
	// and every publisher is unverified today: read the Publisher type before
	// showing it to anyone.
	Publisher Publisher
}

// String returns a representation with the link redacted. Server-supplied text
// is quoted, so it cannot inject control characters into a log line.
func (l CRIDLink) String() string {
	// Printed as a time, not as the pointer: an address says nothing, and it
	// would differ between two equal values.
	createdAt := "<nil>"
	if l.ResourceCreatedAt != nil {
		createdAt = l.ResourceCreatedAt.Format(time.RFC3339)
	}
	return fmt.Sprintf(
		"qurl.CRIDLink{Link:[REDACTED], QURLID:%q, ExpiresAt:%s, ResourceCreatedAt:%s, Publisher:{Name:%q, Verified:%t}}",
		l.QURLID, l.ExpiresAt.Format(time.RFC3339), createdAt, l.Publisher.Name, l.Publisher.Verified)
}

// GoString returns the same redacted representation as String.
func (l CRIDLink) GoString() string { return l.String() }

// The outcomes of a CRID link request. Each denial is also a *ServerDenyError
// carrying the server's code, so code that already handles an authenticated
// deny from EnterPortal handles these without change.
var (
	// ErrCRIDLinkUnavailable reports that a link cannot be issued right now.
	// The condition is temporary: try again later.
	ErrCRIDLinkUnavailable = errors.New("qurl: a link for this CRID cannot be issued right now; try again later")
	// ErrCRIDLinkNotFound reports that the CRID is unknown, retired, or
	// malformed, or that this client may not open it. The server gives one
	// answer for all of these and does not say which. Do not retry; check the
	// CRID and your access.
	ErrCRIDLinkNotFound = errors.New("qurl: CRID not found, or this client may not open it")
	// ErrCRIDLinkRateLimited reports too many requests from this client or for
	// this CRID. Try again later.
	ErrCRIDLinkRateLimited = errors.New("qurl: too many CRID link requests; try again later")
	// ErrCRIDResourceOffline reports that the resource exists and this client
	// may open it, but its publisher is offline. It may come back.
	ErrCRIDResourceOffline = errors.New("qurl: the publisher of this CRID is offline")
	// ErrCRIDResourceClosed reports that the resource exists and this client
	// may open it, but it has been closed. Do not retry.
	ErrCRIDResourceClosed = errors.New("qurl: the resource behind this CRID is closed")
	// ErrInvalidCRIDLinkRequest reports that the server refused the request
	// itself: it was malformed, did not arrive through the relay, or carried a
	// member the server does not support. Do not retry. A CRID that fails the
	// local gate never reaches the server and reports ErrInvalidResourceRequest
	// instead.
	ErrInvalidCRIDLinkRequest = errors.New("qurl: the server refused the CRID link request as invalid")

	// ErrCRIDLinkProtocol reports an authenticated reply that is not a usable
	// answer to a CRID link request: its outcome code is missing, is not a
	// string, is empty, is a success code, or is not a decimal code, or its
	// body is not one JSON object with unique member names. A body that the
	// reader refuses whole for its bounds (nested too deep, or a number outside
	// the range of a float64) is reported the same way. A CRID link request
	// opens nothing, so it never succeeds the way an ordinary knock does, and
	// a reply that says it did is not trusted with a link. It wraps
	// ErrMalformedReply.
	ErrCRIDLinkProtocol = fmt.Errorf("%w: not a usable answer to a CRID link request", ErrMalformedReply)

	// ErrCRIDLinkRejected reports that the server issued a link and the link
	// failed a client check. The link is not returned and nothing else from
	// that reply is either. Use errors.As with *CRIDLinkRejectedError to read
	// which check failed.
	ErrCRIDLinkRejected = errors.New("qurl: issued CRID link rejected")

	// ErrInvalidDeviceKey reports that the device static private key given to
	// a call made as a device cannot be used: it is not 32 bytes, or it holds
	// only zero bytes, as a wiped key does. The message says which. The call
	// was refused before it looked at the CRID or the configuration, and
	// nothing was sent.
	//
	// It does not match ErrInvalidResourceRequest. That error says that the
	// CRID cannot be requested, and here the CRID was not looked at.
	ErrInvalidDeviceKey = errors.New("qurl: invalid device static private key")
)

// CRIDLinkRejectClass names the client check an issued link failed. The set is
// closed and matches the reject_classes of the public CRID link knock vectors.
type CRIDLinkRejectClass string

const (
	// CRIDLinkRejectMissingRedirect means the reply carried no link, or carried
	// something that is not a non-empty string where the link belongs.
	CRIDLinkRejectMissingRedirect CRIDLinkRejectClass = "missing_redirect"
	// CRIDLinkRejectOrigin means the link is not on the deployment's link
	// origin: another scheme, host, or port, or any userinfo.
	CRIDLinkRejectOrigin CRIDLinkRejectClass = "origin"
	// CRIDLinkRejectPathOrQuery means the link is on the right origin but
	// carries a path other than "/" or any query. An issued link is the origin
	// and a fragment, nothing more.
	CRIDLinkRejectPathOrQuery CRIDLinkRejectClass = "path_or_query"
	// CRIDLinkRejectTransport means the link has no fragment, or its fragment
	// is not the qv2t1 transport.
	CRIDLinkRejectTransport CRIDLinkRejectClass = "transport"
	// CRIDLinkRejectIssuerSignature means the link's signed content does not
	// parse, or does not verify under the trust store.
	CRIDLinkRejectIssuerSignature CRIDLinkRejectClass = "issuer_signature"
	// CRIDLinkRejectCRIDMismatch means the link is genuine but is for another
	// resource: its signed resource key does not derive the requested CRID.
	CRIDLinkRejectCRIDMismatch CRIDLinkRejectClass = "crid_mismatch"
	// CRIDLinkRejectInfoCRIDMismatch means the reply's own metadata names a
	// CRID other than the one requested.
	CRIDLinkRejectInfoCRIDMismatch CRIDLinkRejectClass = "info_crid_mismatch"
)

// CRIDLinkRejectedError is returned when the server issued a link and the link
// failed a client check. It matches ErrCRIDLinkRejected.
//
// Where the failed check corresponds to an existing sentinel, that sentinel
// matches too, so code written for VerifyLinkForCRID keeps working:
// ErrCRIDMismatch for either CRID class, ErrFragment for the transport class,
// and for the issuer-signature class whichever of ErrSignature, ErrUnknownKID,
// ErrStrictParse, ErrKeyLength, ErrEncoding, or ErrFragment describes the
// fault. ErrUnknownKID in particular means the trust store does not know the
// link's issuer, which is usually a deployment mismatch rather than a forged
// link. The missing-redirect, origin, and path-or-query classes have no
// sentinel of their own.
//
// The message names the failed check and nothing else. It never contains the
// link or any text taken from the reply.
type CRIDLinkRejectedError struct {
	// Class is the check that failed.
	Class CRIDLinkRejectClass

	// sentinels holds only this package's bare sentinels, never a wrapped
	// error with a message: the underlying parse and verify errors can quote
	// parts of what they were given.
	sentinels []error
}

func (e *CRIDLinkRejectedError) Error() string {
	return fmt.Sprintf("%s: %s check failed", ErrCRIDLinkRejected.Error(), string(e.Class))
}

// Unwrap exposes ErrCRIDLinkRejected and the existing sentinels, if any, that
// describe the failed check.
func (e *CRIDLinkRejectedError) Unwrap() []error {
	return append([]error{ErrCRIDLinkRejected}, e.sentinels...)
}

// RequestCRIDLink asks the server for a qURL link to the resource behind
// resourceCRID and returns it once every client check on it has passed. It
// needs no LayerV credentials: the CRID is the only input. The request goes
// through the deployment's relay under a key minted for this one call.
//
// It resolves configuration as EnterPortal does — an installed Provider, then
// the file named by QURL_DEPLOYMENT, then the deployment embedded in the
// build — with one difference: the CRID link endpoint comes only from a
// deployment's "crid_link" object. A Provider supplies trust, not that
// endpoint, so with one installed, and with a deployment that names none, this
// returns ErrCRIDLinkNotConfigured. A deployment that names one that cannot be
// used is ErrCRIDLinkMisconfigured. Use RequestCRIDLinkWith to pass the
// endpoint explicitly.
//
// A CRID that fails the local validation gate, or whose version this SDK
// cannot verify a link against, is refused before any configuration is
// resolved or request sent: the error matches ErrInvalidResourceRequest and
// the crid package's sentinel, or ErrUnsupportedCRIDVersion. That refusal
// says nothing about the configuration. CheckCRIDLinkConfig reports whether a
// request can be sent at all, without a CRID.
//
// The reply decides the rest. A link is returned as *CRIDLink. Each refusal is
// a typed error: ErrCRIDLinkNotFound, ErrCRIDLinkUnavailable,
// ErrCRIDLinkRateLimited, ErrCRIDResourceOffline, ErrCRIDResourceClosed, or
// ErrInvalidCRIDLinkRequest; any other decimal code is a *ServerDenyError. A
// busy server is ErrServerOverloaded. A reply that is not a usable answer is
// ErrCRIDLinkProtocol. An issued link that fails a check is
// *CRIDLinkRejectedError.
//
// A *ServerDenyError that matches none of the six refusals is a server error.
// Its ErrCode carries the code. It is not ErrCRIDLinkUnavailable, and it says
// nothing about this client or its version: a server that does not know this
// request cannot answer with one of the six codes, so it answers with a
// general one.
//
// A relay that cannot be reached, that answers with an HTTP error, or whose
// reply could not be read to the end is a *RelayError; in the last case its
// Status is 200. A relay answer that does not authenticate as the cell's
// reply is an error that matches none of these, as it is for EnterPortal. The
// caller's context bounds the call: when it ends the request before a reply
// has been read, the error also matches the context's error.
//
// Requesting a link opens nothing. Open the returned link with
// EnterPortalForCRID and the same CRID, or call OpenCRID to do both.
func RequestCRIDLink(ctx context.Context, resourceCRID string) (*CRIDLink, error) {
	// Before resolveDefaultConfig: a Provider may do network I/O, and a CRID
	// that can never be requested must not cost a round trip to find that out.
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return RequestCRIDLinkWith(ctx, resourceCRID, cfg)
}

// RequestCRIDLinkWith is RequestCRIDLink with explicit configuration. cfg
// needs a TrustStore, a CRIDLink endpoint, a RelayAllowlist that admits the
// endpoint's relay, and Cells naming exactly one cell, whose key the request
// is sealed to. HTTPClient is optional.
//
// Config.ExpectedCRID, when set, must be the CRID being requested. The
// requested CRID is what an issued link is bound to, so a different pin is a
// contradiction and fails with ErrCRIDMismatch rather than being overridden.
//
// It sends one request, under a key minted for that request. To request a
// link as a registered device, which can open a private resource too, use
// RequestCRIDLinkAsDeviceWith.
func RequestCRIDLinkWith(ctx context.Context, resourceCRID string, cfg Config) (*CRIDLink, error) {
	return requestCRIDLink(ctx, resourceCRID, cfg, nil)
}

// RequestCRIDLinkAsDevice is RequestCRIDLink for a registered device. It can
// return a link for a private resource too, when the owner of the resource
// allowed the device or the device is the owner's own.
// deviceStaticPrivateKey is the device's 32-byte X25519 static private key,
// the key KnockRegisteredAgent takes.
//
// It resolves configuration as RequestCRIDLink does, and what RequestCRIDLink
// says about that holds here: the CRID link endpoint comes only from a
// deployment's "crid_link" object, and a configuration without one is
// ErrCRIDLinkNotConfigured. Then it calls RequestCRIDLinkAsDeviceWith. Read
// RequestCRIDLinkAsDeviceWith for the rule the call follows: a random key
// first, the device key only after "not found". It also says what the second
// request costs, what the relay can and cannot do with it, how the context
// covers both requests, and who owns the key.
//
// A key that cannot be used is refused first, with ErrInvalidDeviceKey, and a
// CRID that cannot be requested second, with ErrInvalidResourceRequest. Both
// are refused before any configuration is resolved, so neither costs any I/O.
func RequestCRIDLinkAsDevice(ctx context.Context, deviceStaticPrivateKey []byte, resourceCRID string) (*CRIDLink, error) {
	// The key gate comes before everything else, as in the With form: a bad
	// key gets the same error whatever the CRID and the configuration are.
	if err := validateCRIDLinkDeviceKey(deviceStaticPrivateKey); err != nil {
		return nil, err
	}
	// Before resolveDefaultConfig: a Provider may do network I/O, and a CRID
	// that can never be requested must not cost a round trip to find that out.
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return RequestCRIDLinkAsDeviceWith(ctx, deviceStaticPrivateKey, resourceCRID, cfg)
}

// RequestCRIDLinkAsDeviceWith is RequestCRIDLinkAsDevice with explicit
// configuration: RequestCRIDLinkWith for a registered device. It can return a
// link for a private resource too. deviceStaticPrivateKey is the device's
// 32-byte X25519 static private key, the key KnockRegisteredAgent takes. cfg
// is what RequestCRIDLinkWith needs.
//
// A private resource can be opened by CRID only by a registered device that
// the owner of the resource allowed, or by the owner's own device. Every other
// client gets ErrCRIDLinkNotFound, the same answer as for a CRID that does not
// exist.
//
// The call follows one rule: a random key first, the device key only after
// "not found".
//
//  1. The first request is the request RequestCRIDLinkWith sends. It is sent
//     under a random key. It is not sent under the device key, and it carries
//     nothing that is derived from the device key. A public resource is
//     answered here.
//  2. Only when the server answers the first request with "not found" does the
//     call send one second request, with the device key as the static key of
//     the knock. The answer to the second request is the result of the call: a
//     link, checked exactly as any issued link, or an error. "Not found" there
//     is ErrCRIDLinkNotFound. There is no third request.
//  3. Any other outcome of the first request is returned as it is: a link,
//     another refusal, a busy server, a reply that is not usable, a link that
//     fails a check, a relay fault, or a request that got no answer. None of
//     these leads to a second request, so a temporary fault never makes the
//     device identify itself.
//
// The rule keeps the device key out of every request that does not need it.
// It does not make the first request anonymous. The server learns the source
// address of every request, and a request carries the user agent when one is
// configured. The server sees the same source address when the device uses its
// key, in the second request or in any other knock. So the source address can
// still connect a request under a random key to the device.
//
// The second request is a real request to the server. It counts against the
// server's per-source request limit like the first one, and it can itself be
// answered with ErrCRIDLinkRateLimited. It presents the device's identity to
// the cell that cfg names. The call does not check that this is the cell the
// device is registered with.
//
// What the relay can and cannot do with a request under the device key. The
// relay carries both requests and is not trusted. With the first request,
// under a random key, it can drop or delay the request, or hand back
// something that does not authenticate. It cannot change what the server
// said. With the second request it can do more, for one reason: a part of
// what protects a reply depends on the public key the reply is sealed to.
// Nobody but the client knows a random key. A device's public key is
// long-lived and is known outside the device: an owner needs it to allow the
// device.
//
// The relay cannot do any of the following, also when it holds the device's
// public key:
//
//   - Forge a link or a refusal, "not found" included, or change one.
//   - Read the request or the reply. It learns neither the CRID nor the link.
//   - Cause the second request. Only the server's own "not found" to the
//     first request does.
//
// A relay that holds the device's public key can:
//
//   - Recognise the reply to the second request, and so that request, as
//     this device's.
//   - See from the size of that reply whether a link was issued. It sees the
//     size of every reply, and a reply with a link is larger than a refusal.
//   - Hand back the server's reply with its content removed. The call then
//     fails with ErrServerOverloaded, ErrCRIDLinkProtocol, or
//     ErrMalformedReply, whatever the server answered.
//
// A relay that does not hold the public key can still hand back, at any later
// time, a reply that the server once sent to the same device. An old "busy"
// reply gives ErrServerOverloaded. Any other old reply gives
// ErrMalformedReply.
//
// So on a call made as a device, read ErrServerOverloaded, ErrCRIDLinkProtocol
// and ErrMalformedReply as "no usable answer". They are not proof that the
// server is busy, or of anything else the server said. A link and a refusal
// are proof: the relay cannot make either.
//
// The caller's context covers both requests. When it has ended by the time
// the first request is answered "not found", the second request is not sent.
// The error then matches the context's error and does not match
// ErrCRIDLinkNotFound: the device never asked, so it is not known whether the
// device may open the CRID. When the context ends while a request is waiting
// for its answer, the error has the same form for the first request and for
// the second. So a context error does not say whether the device key was
// sent.
//
// The key stays owned by the caller. The SDK does not keep it and does not
// wipe it. It uses the key only as the static key of that one knock, never
// logs it, and never puts it in an error. Do not change or wipe the key while
// the call is running. A key that is not 32 bytes, or that holds only zero
// bytes as a wiped key does, is refused before the CRID or the configuration
// is looked at and before anything is sent. That error is ErrInvalidDeviceKey.
// It does not match ErrInvalidResourceRequest, which says that the CRID
// cannot be requested.
func RequestCRIDLinkAsDeviceWith(ctx context.Context, deviceStaticPrivateKey []byte, resourceCRID string, cfg Config) (*CRIDLink, error) {
	if err := validateCRIDLinkDeviceKey(deviceStaticPrivateKey); err != nil {
		return nil, err
	}
	return requestCRIDLink(ctx, resourceCRID, cfg, deviceStaticPrivateKey)
}

// validateCRIDLinkDeviceKey is the gate a device key passes before a link is
// requested as that device. It needs no I/O.
//
// The gate is here, in front of everything, and not where the key is first
// used. The key is used only after the server has answered "not found", so a
// bad key found at that point would be an error that depends on the server's
// answer. A caller with a bad key gets the same error for every CRID.
//
// A key of only zero bytes is refused. It is what a wiped buffer holds, and it
// is not a secret, so it cannot be the key of a registered device.
//
// The error is ErrInvalidDeviceKey. It is an error of its own, and not the
// error for a CRID that cannot be requested: a caller that reads that one
// tells its user that something is wrong with the CRID. The messages say what
// is wrong with the key and never hold any byte of it.
func validateCRIDLinkDeviceKey(deviceStaticPrivateKey []byte) error {
	if len(deviceStaticPrivateKey) != x25519key.Size {
		return fmt.Errorf("%w: it must be %d bytes", ErrInvalidDeviceKey, x25519key.Size)
	}
	var seen byte
	for _, b := range deviceStaticPrivateKey {
		seen |= b
	}
	if seen == 0 {
		return fmt.Errorf("%w: it holds only zero bytes", ErrInvalidDeviceKey)
	}
	return nil
}

// requestCRIDLink is the one code path behind RequestCRIDLinkWith and
// RequestCRIDLinkAsDeviceWith.
//
// With an empty deviceStaticPrivateKey it sends one request and returns its
// answer, whatever the answer is. With a key, which the caller has passed
// through validateCRIDLinkDeviceKey, it follows the rule documented on
// RequestCRIDLinkAsDeviceWith.
func requestCRIDLink(ctx context.Context, resourceCRID string, cfg Config, deviceStaticPrivateKey []byte) (*CRIDLink, error) {
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	if cfg.ExpectedCRID != "" && cfg.ExpectedCRID != resourceCRID {
		return nil, fmt.Errorf("%w: Config.ExpectedCRID names a different CRID than the one requested", ErrCRIDMismatch)
	}
	endpoint, err := resolveCRIDLinkEndpoint(cfg)
	if err != nil {
		return nil, err
	}
	body, err := buildCRIDLinkKnockBody(resourceCRID, endpoint.userAgent)
	if err != nil {
		return nil, err
	}

	// The first request never carries a device key, also when the caller has
	// one: relayknock mints a random identity for this one request and wipes it
	// afterwards. The server decides a public resource on the CRID in the body,
	// so a key that outlived the call would only make two requests linkable.
	issued, err := requestCRIDLinkOnce(ctx, resourceCRID, endpoint, body, cfg, nil)
	if len(deviceStaticPrivateKey) == 0 || !errors.Is(err, ErrCRIDLinkNotFound) {
		return issued, err
	}

	// The caller is a device and the server said "not found". That answer is
	// authenticated to the cell, so a relay cannot forge it to make the device
	// identify itself. It is also the only answer that leads here: every other
	// outcome was returned above, and the device key was not used.
	//
	// One context covers both requests. If it has already ended, a second
	// request could not finish, so none is started and the device key is never
	// used. The first answer is not returned in that case. For a device,
	// "not found" is established only by the answer to the device's own
	// request, and that request was never sent. So the error is the context's
	// error, and it does not match ErrCRIDLinkNotFound.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("qurl: the CRID link request with the device key was not sent because the context ended first: %w", ctxErr)
	}
	// The same body, under the device key. The key is the static key of this
	// one knock and goes nowhere else. Whatever comes back is the result.
	return requestCRIDLinkOnce(ctx, resourceCRID, endpoint, body, cfg, deviceStaticPrivateKey)
}

// requestCRIDLinkOnce sends one CRID link request and reads its answer. With
// an empty deviceStaticPrivateKey the request is sent under a random key that
// relayknock mints for it and wipes afterwards. A key that is passed in stays
// the caller's: it is not kept and not wiped.
//
// The reply is authenticated to the cell key from configuration. That is what
// makes the relay untrusted here, as on a link open: it can drop or delay the
// request, but it cannot forge a link or a refusal, and it cannot substitute
// a link.
//
// For a request under a random key that is all the relay can do. For a
// request under the device key it can also hand back the server's reply with
// its content removed, which reads as "busy" or as a reply that is not usable.
// RequestCRIDLinkAsDeviceWith says exactly what holds.
func requestCRIDLinkOnce(
	ctx context.Context, resourceCRID string, endpoint *cridLinkEndpoint, body []byte, cfg Config, deviceStaticPrivateKey []byte,
) (*CRIDLink, error) {
	reply, err := relayknock.Knock(ctx, endpoint.relayURL, endpoint.serverPublicKey, body, relayknock.KnockOptions{
		HTTPClient:       cfg.HTTPClient,
		DeviceStaticPriv: deviceStaticPrivateKey,
	})
	if err != nil {
		return nil, cridLinkTransportError(ctx, err)
	}
	// A link-issued reply carries a credential. The decoded link is returned to
	// the caller as a string this function cannot erase, but the reply buffer
	// is ours to clear.
	defer wipeBytes(reply.Body)
	return interpretCRIDLinkReply(reply, resourceCRID, endpoint.linkOrigin, cfg.TrustStore)
}

// OpenCRID opens the resource behind resourceCRID: it requests a link with
// RequestCRIDLink, then opens that link bound to the same CRID, as
// EnterPortalForCRID does. It needs no LayerV credentials.
//
// The result is the ResourceHandle an EnterPortal call returns, and every
// error either step can return comes back unchanged. The link never leaves
// this call: it is not returned, logged, or included in any error.
//
// OpenCRID does not report who published the resource. To show the publisher
// before opening — always as unverified — call RequestCRIDLink, then
// EnterPortalForCRID with the link and the same CRID.
//
// Each call requests a fresh link and starts an independent visit.
func OpenCRID(ctx context.Context, resourceCRID string) (*ResourceHandle, error) {
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return OpenCRIDWith(ctx, resourceCRID, cfg)
}

// OpenCRIDWith is OpenCRID with explicit configuration: RequestCRIDLinkWith,
// then EnterPortalWith with Config.ExpectedCRID set to resourceCRID.
//
// The two steps can use different transports. The request always goes through
// the relay; the open uses native UDP, because cfg must name a cell for the
// request to be sealed to and a configured cell catalog selects native UDP.
//
// Every call requests a fresh link, and a PortalSession is bound to one link,
// so a Config.PortalSession cannot carry a visit from one OpenCRIDWith call to
// the next. To retry a visit, request the link once with RequestCRIDLinkWith
// and retry EnterPortalWith with that link and the retained session.
func OpenCRIDWith(ctx context.Context, resourceCRID string, cfg Config) (*ResourceHandle, error) {
	issued, err := RequestCRIDLinkWith(ctx, resourceCRID, cfg)
	if err != nil {
		return nil, err
	}
	return openIssuedCRIDLink(ctx, issued.Link, resourceCRID, cfg)
}

// OpenCRIDAsDevice is OpenCRID for a registered device: it requests a link
// with RequestCRIDLinkAsDevice, then opens that link bound to the same CRID.
// It can open a private resource too, when the owner of the resource allowed
// the device or the device is the owner's own. deviceStaticPrivateKey is the
// device's 32-byte X25519 static private key, the key KnockRegisteredAgent
// takes.
//
// It resolves configuration as OpenCRID does, and what RequestCRIDLink says
// about that holds here. Then it calls OpenCRIDAsDeviceWith. Read
// RequestCRIDLinkAsDeviceWith for the rule the link request follows: a random
// key first, the device key only after "not found". It also says what the
// second request costs, what the relay can and cannot do with it, how the
// context covers both requests, and who owns the key.
//
// A key that cannot be used is refused first, with ErrInvalidDeviceKey, and a
// CRID that cannot be requested second, with ErrInvalidResourceRequest. Both
// are refused before any configuration is resolved, so neither costs any I/O.
func OpenCRIDAsDevice(ctx context.Context, deviceStaticPrivateKey []byte, resourceCRID string) (*ResourceHandle, error) {
	// The key gate comes before everything else, as in the With form: a bad
	// key gets the same error whatever the CRID and the configuration are.
	if err := validateCRIDLinkDeviceKey(deviceStaticPrivateKey); err != nil {
		return nil, err
	}
	// Before resolveDefaultConfig, for the reason RequestCRIDLinkAsDevice
	// gives: a Provider may do network I/O.
	if err := validateCRIDForLinkRequest(resourceCRID); err != nil {
		return nil, err
	}
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return OpenCRIDAsDeviceWith(ctx, deviceStaticPrivateKey, resourceCRID, cfg)
}

// OpenCRIDAsDeviceWith is OpenCRIDAsDevice with explicit configuration:
// RequestCRIDLinkAsDeviceWith, then EnterPortalWith with Config.ExpectedCRID
// set to resourceCRID. cfg is what OpenCRIDWith needs.
//
// The device key is used for the link request only, under the rule of
// RequestCRIDLinkAsDeviceWith: a random key first, the device key only after
// "not found". So this call can send two link requests where OpenCRIDWith
// sends one. Read RequestCRIDLinkAsDeviceWith for the rule, the cost of the
// second request, what the relay can and cannot do with it, the context rule,
// and who owns the key. The context covers the open as well: when it ends
// between the link and the open, the error is the context's error, as it is
// when it ends between the two link requests. The open uses the issued link's
// own key, never the device key.
//
// Every error either step can return comes back unchanged, and the link never
// leaves this call. What OpenCRIDWith says about transports and about
// Config.PortalSession holds here too.
func OpenCRIDAsDeviceWith(ctx context.Context, deviceStaticPrivateKey []byte, resourceCRID string, cfg Config) (*ResourceHandle, error) {
	issued, err := RequestCRIDLinkAsDeviceWith(ctx, deviceStaticPrivateKey, resourceCRID, cfg)
	if err != nil {
		return nil, err
	}
	return openIssuedCRIDLink(ctx, issued.Link, resourceCRID, cfg)
}

// openIssuedCRIDLink opens a link that was issued for resourceCRID, bound to
// that CRID. The request has already checked the link against the CRID; the
// opener checks it again from the link alone, so the binding of an open by
// CRID does not rest on a single call site having run.
func openIssuedCRIDLink(ctx context.Context, link, resourceCRID string, cfg Config) (*ResourceHandle, error) {
	cfg.ExpectedCRID = resourceCRID
	return EnterPortalWith(ctx, link, cfg)
}

// validateCRIDForLinkRequest is the gate a CRID passes before a link is
// requested for it. It refuses, without any I/O, a value that fails the CRID
// local validation gate and a well-formed CRID whose version is not active.
//
// The second rule is narrower than the local gate on purpose. The gate forwards
// an unregistered or reserved version, because the server is authoritative on
// which versions exist. Here that is not enough: an issued link is used only if
// its signed key derives the requested CRID under that CRID's own version, and
// this SDK can make that check only for a version it knows resources carry.
// Requesting a link it would then have to reject helps nobody.
func validateCRIDForLinkRequest(resourceCRID string) error {
	parsed, err := crid.Parse(resourceCRID)
	if err != nil {
		return fmt.Errorf("%w: a CRID link request requires a valid CRID: %w", ErrInvalidResourceRequest, err)
	}
	if !parsed.Active() {
		return fmt.Errorf("%w: %w: a link cannot be verified against CRID version 0x%02x",
			ErrInvalidResourceRequest, ErrUnsupportedCRIDVersion, parsed.Version())
	}
	return nil
}

// The request body. The auth service id and this fixed resource id, together
// with a string CRID in the user data, are what make a knock a link request.
// The resource id is a sentinel, not a resource key: the resource is named by
// the CRID.
const (
	cridLinkResourceID = "qurl-crid"
	// cridLinkUserAgentMaxBytes bounds the user agent a request carries, in
	// bytes of UTF-8.
	cridLinkUserAgentMaxBytes = 256
)

// cridLinkKnockMsg is the knock body of a link request. Its members are
// declared in their canonical wire order, and the user data is a struct rather
// than the map an ordinary knock uses so that order is the declared one and
// not an accident of key sorting.
//
// It carries the CRID and, optionally, a user agent, and nothing else. In
// particular it never carries a member of the link-opening knock, such as the
// signed claims or their signature: the server refuses a request that does.
type cridLinkKnockMsg struct {
	HeaderType int                   `json:"headerType"`
	AspID      string                `json:"aspId"`
	ResID      string                `json:"resId"`
	UsrData    cridLinkKnockUserData `json:"usrData"`
}

type cridLinkKnockUserData struct {
	CRID      string `json:"qurl_crid"`
	UserAgent string `json:"qurl_user_agent,omitempty"`
}

// buildCRIDLinkKnockBody serializes the request for a CRID that has passed
// validateCRIDForLinkRequest. The result is the body's canonical form: compact
// JSON, members in declared order, strings escaped only where JSON requires it
// and every non-ASCII character written as UTF-8.
//
// One encoder default stands between encoding/json and that form. HTML
// escaping is switched off, because the canonical form writes '<', '>' and '&'
// as they are. The encoder differs from other encoders in two more places: it
// has its own way to write a control character, and it always escapes U+2028
// and U+2029. Neither is reached here. A user agent that holds one of those
// characters is not sent at all (see sentCRIDLinkUserAgent), and a CRID never
// holds one.
func buildCRIDLinkKnockBody(resourceCRID, userAgent string) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(cridLinkKnockMsg{
		HeaderType: nhpKNKHeaderType,
		AspID:      qurlAspID,
		ResID:      cridLinkResourceID,
		UsrData: cridLinkKnockUserData{
			CRID:      resourceCRID,
			UserAgent: sentCRIDLinkUserAgent(userAgent),
		},
	}); err != nil {
		return nil, fmt.Errorf("qurl: build CRID link request: %w", err)
	}
	// Encode appends a newline, which is not part of the body.
	return bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), nil
}

// sentCRIDLinkUserAgent returns the user agent a request carries, or "" when
// the request carries none.
//
// A user agent that holds a control character (U+0000 to U+001F, or U+007F),
// U+2028 or U+2029 is left out whole. JSON encoders do not agree on how to
// write those characters, so two correct clients would send different bytes
// for the same value. The member is optional and only for display, so a
// request without it loses nothing.
//
// The whole value is looked at, and only then is a long one cut. A character
// past the limit leaves the member out too. Cutting first would send the start
// of a value that must not be sent.
func sentCRIDLinkUserAgent(userAgent string) string {
	if strings.ContainsFunc(userAgent, cridLinkUserAgentRuneNotSent) {
		return ""
	}
	return truncateCRIDLinkUserAgent(userAgent)
}

// cridLinkUserAgentRuneNotSent reports whether r is one of the characters a
// user agent must not hold if it is to be sent. The set is the contract's and
// is closed. Other control characters, such as U+0080 to U+009F, are not in it.
func cridLinkUserAgentRuneNotSent(r rune) bool {
	return r <= 0x1f || r == 0x7f || r == '\u2028' || r == '\u2029'
}

// truncateCRIDLinkUserAgent cuts a user agent that may be sent to the length a
// request carries: the longest prefix of at most cridLinkUserAgentMaxBytes
// bytes that ends on a character boundary. A long value is cut, never refused,
// and what is sent is always valid UTF-8.
//
// Invalid input is replaced first, not after: a replacement character is three
// bytes, so replacing after the cut could push the value back over the limit.
func truncateCRIDLinkUserAgent(userAgent string) string {
	userAgent = strings.ToValidUTF8(userAgent, string(utf8.RuneError))
	if len(userAgent) <= cridLinkUserAgentMaxBytes {
		return userAgent
	}
	cut := cridLinkUserAgentMaxBytes
	for cut > 0 && !utf8.RuneStart(userAgent[cut]) {
		cut--
	}
	return userAgent[:cut]
}

// cridLinkTransportError maps a failed relay exchange into the qURL taxonomy,
// as the link opener does, and keeps a caller's cancellation matchable.
//
// The relay transport reports a request that died with its context as a
// transport fault with the cause flattened into text, so
// errors.Is(err, context.Canceled) would be false for exactly the failure the
// caller caused. When the context has ended and the exchange stopped before a
// reply was read, the context's error is the honest cause and is added back.
//
// "Before a reply was read" is a fault with no HTTP status, where no response
// arrived, or with status 200, which the transport reports for one thing only:
// the response began and its body could not be read to the end. A relay that
// answered with an HTTP error keeps its own status, even if the context
// expired a moment later.
func cridLinkTransportError(ctx context.Context, err error) error {
	err = normalizeRelayError(err, ErrMalformedReply)
	ctxErr := ctx.Err()
	if ctxErr == nil || errors.Is(err, ctxErr) {
		return err
	}
	var relayErr *RelayError
	if errors.As(err, &relayErr) && (relayErr.Status == 0 || relayErr.Status == http.StatusOK) {
		return fmt.Errorf("qurl: CRID link request did not complete: %w: %w", ctxErr, err)
	}
	return err
}
