package qurl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/relayknock"
)

// Reading the answer to a CRID link request.
//
// The reply is authenticated: the transport has already established that it
// came from the cell the request was sealed to. What is left is deciding what
// it says, and that is decided on the outcome code alone. The diagnostic
// message beside it is never read.
//
// Exactly one code carries a link, and that code is deliberately not a success
// code: the request opens nothing. So a reply that claims success, or that has
// no string code at all, is not a link either — it is a protocol violation,
// whatever else its body carries. And a refusal that happens to carry a link is
// still the refusal.

// cridLinkCodeIssued is the one outcome code that carries a link.
const cridLinkCodeIssued = "52600"

// cridLinkDenials is the closed set of refusals a CRID link request defines.
// Any other decimal code the server may answer with is a generic
// *ServerDenyError.
//
// The set is the contract's, and it is not widened here. A general platform
// code is one of the "other" codes, also when its cause is temporary. The
// contract gives every code outside the set one outcome, a server error, which
// is not the outcome of any refusal in the set. So such a code is not mapped to
// ErrCRIDLinkUnavailable or to any other sentinel below.
var cridLinkDenials = map[string]error{
	"52601": ErrCRIDLinkUnavailable,
	"52602": ErrCRIDLinkNotFound,
	"52603": ErrCRIDLinkRateLimited,
	"52604": ErrCRIDResourceOffline,
	"52605": ErrCRIDResourceClosed,
	"52606": ErrInvalidCRIDLinkRequest,
}

// cridLinkInfoTextMaxCodePoints bounds every display string taken from the
// reply's metadata. It counts code points, not bytes.
const cridLinkInfoTextMaxCodePoints = 128

// interpretCRIDLinkReply maps an authenticated reply to a verified link or a
// typed error. It is the whole decision: nothing about a reply is trusted
// before it, and nothing from a reply it refuses is returned.
func interpretCRIDLinkReply(reply *relayknock.Reply, requestedCRID, linkOrigin string, trust *TrustStore) (*CRIDLink, error) {
	if reply == nil {
		return nil, fmt.Errorf("%w: empty qURL platform reply", ErrMalformedReply)
	}
	// The header type is read before any body. A cookie reply is what a busy
	// server sends instead of an answer. It is not an ACK and has no outcome
	// code, so its body is not read, whatever it holds.
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, fmt.Errorf("%w: unexpected qURL platform reply type %d", ErrMalformedReply, reply.Type)
	}

	ack, ok := decodeCRIDLinkACK(reply.Body)
	if !ok {
		return nil, fmt.Errorf("%w: the reply body is not one JSON object", ErrCRIDLinkProtocol)
	}
	// Only a JSON string is a code. A number is never coerced into one: a reply
	// with the numeric form of the link-issued code is not a link-issued reply.
	code, isString := cridLinkJSONString(ack["errCode"])
	if !isString {
		return nil, fmt.Errorf("%w: the reply carries no outcome code", ErrCRIDLinkProtocol)
	}
	if isSuccessErrCode(code) {
		return nil, fmt.Errorf("%w: the reply carries a success code, and a CRID link request opens nothing", ErrCRIDLinkProtocol)
	}

	if code == cridLinkCodeIssued {
		return issuedCRIDLink(ack, requestedCRID, linkOrigin, trust)
	}
	// From here on the reply is a refusal, and any link or metadata it carries
	// is ignored.
	if denial, known := cridLinkDenials[code]; known {
		return nil, fmt.Errorf("%w: %w", denial, &ServerDenyError{ErrCode: code})
	}
	// An unassigned code, the denial code of another kind of knock, or a
	// general platform code is a generic deny that carries the code. Only a
	// decimal code is carried: the code is echoed in the error text, and a
	// string outside the code grammar could be anything, including a link.
	if !isCanonicalKnockDenyCode(code) {
		return nil, fmt.Errorf("%w: the reply's outcome code is not a decimal code", ErrCRIDLinkProtocol)
	}
	return nil, &ServerDenyError{ErrCode: code}
}

// decodeCRIDLinkACK reads an ACK body as one JSON object whose member names
// are unique at every depth, which is what every reply body this SDK reads
// must be. A body that repeats a member is refused rather than resolved by
// guessing which occurrence counts.
//
// The check is the one every reply body goes through, and it has that check's
// bounds: a body nested deeper than the scanner follows, or holding a number
// outside the range of a float64, is refused whole although it repeats nothing.
func decodeCRIDLinkACK(body []byte) (map[string]json.RawMessage, bool) {
	if rejectDuplicateJSONFields(body) != nil {
		return nil, false
	}
	return cridLinkJSONObject(body)
}

// cridLinkJSONObject accepts only a JSON object. null and an absent value are
// not objects.
func cridLinkJSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// cridLinkJSONString accepts only a JSON string. json.Unmarshal alone would
// also accept null and leave the destination empty, which would make a null
// read like an absent or empty member.
func cridLinkJSONString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	return value, true
}

// issuedCRIDLink runs the client checks on a link-issued reply, in the
// reference order, and builds the result only when all of them pass. A failed
// check is a hard error: the link is not returned, and neither is anything
// else from the reply.
func issuedCRIDLink(ack map[string]json.RawMessage, requestedCRID, linkOrigin string, trust *TrustStore) (*CRIDLink, error) {
	// 1. The link is present and is a non-empty string. A one-element array
	// holding a valid link is not a link.
	link, ok := cridLinkJSONString(ack["redirectUrl"])
	if !ok || link == "" {
		return nil, rejectCRIDLink(CRIDLinkRejectMissingRedirect)
	}
	// 2-6. The link itself.
	if err := verifyIssuedCRIDLink(link, requestedCRID, linkOrigin, trust); err != nil {
		return nil, err
	}
	// 7. If the metadata echoes a CRID, it is the requested one. Only an absent
	// member passes: a null, a number, or an object is present and unequal.
	redirectInfo := ack["redirectInfo"]
	if !cridLinkInfoCRIDMatches(requestedCRID, redirectInfo) {
		return nil, rejectCRIDLink(CRIDLinkRejectInfoCRIDMismatch, ErrCRIDMismatch)
	}

	info := sanitizeCRIDLinkInfo(redirectInfo)
	return &CRIDLink{
		Link:              link,
		QURLID:            info.qurlID,
		ExpiresAt:         parseCRIDLinkTime(info.expiresAt),
		ResourceCreatedAt: cridLinkResourceCreatedAt(info.resourceCreatedAt),
		Publisher:         info.publisher,
	}, nil
}

// verifyIssuedCRIDLink checks an issued link against what the client already
// holds: the deployment's link origin, the trust store, and the requested
// CRID. It returns nil or a *CRIDLinkRejectedError.
func verifyIssuedCRIDLink(link, requestedCRID, linkOrigin string, trust *TrustStore) error {
	// 2-3. On the link origin, with no path and no query.
	fragment, class := splitIssuedCRIDLink(link, linkOrigin)
	switch class {
	case "":
	case CRIDLinkRejectTransport:
		// No fragment at all is the same fault as a fragment that is not the
		// transport, and it matches the same sentinel.
		return rejectCRIDLink(class, ErrFragment)
	default:
		return rejectCRIDLink(class)
	}
	// 4. The fragment is the qv2t1 transport. The canonical qv2 body is not a
	// transport, so a link that carries it as its fragment stops here.
	canonical, err := decodeTransportFragment(fragment)
	if err != nil {
		return rejectCRIDLink(CRIDLinkRejectTransport, ErrFragment)
	}
	// 5. The signed content the transport reconstructs parses and verifies
	// under the trust store. Every failure of that content is one class,
	// whichever step caught it.
	parsed, err := parseFragment(canonical)
	if err == nil {
		err = parsed.verify(trust)
	}
	if err != nil {
		return rejectCRIDLink(CRIDLinkRejectIssuerSignature, cridLinkVerifySentinels(err)...)
	}
	resourceKey, err := decodeResourcePublicKey(parsed.Claims.ResourcePublicKeyB64)
	if err != nil {
		// Unreachable in practice: the parser already decoded this key.
		return rejectCRIDLink(CRIDLinkRejectIssuerSignature, cridLinkVerifySentinels(err)...)
	}
	// 6. The signed resource key derives the requested CRID. This is what ties
	// a genuine link to the resource that was asked for, and it is checked
	// against the caller's CRID, never against anything in the reply.
	matched, err := crid.KeyMatches(requestedCRID, resourceKey)
	if err != nil || !matched {
		return rejectCRIDLink(CRIDLinkRejectCRIDMismatch, ErrCRIDMismatch)
	}
	return nil
}

// splitIssuedCRIDLink checks everything in front of an issued link's fragment
// and returns the fragment, or the class of the check that failed.
//
// The comparison is on text, not on a parsed URL. An issued link is exactly
// the origin, an optional "/", and a fragment, so the origin must be the
// link's literal prefix and what follows it must say that the authority really
// ended there. Parsing first and comparing components is how a link on
// another host passes: userinfo in front of the right host, the right host as
// a prefix of a longer one, and a port appended to it all parse into
// something that looks close. Here each of them is simply text that does not
// continue with "/", "#", or the end of the string.
//
// The fragment is everything after the first '#', verbatim. It is never
// percent-decoded: the transport decoder must see the bytes that were
// presented.
func splitIssuedCRIDLink(link, linkOrigin string) (fragment string, failed CRIDLinkRejectClass) {
	rest, ok := strings.CutPrefix(link, linkOrigin)
	if !ok {
		return "", CRIDLinkRejectOrigin
	}
	location, fragment, hasFragment := strings.Cut(rest, "#")
	switch {
	case location == "" || location == "/":
	case location[0] == '/' || location[0] == '?':
		// The authority ended at the origin, and a path or a query follows.
		return "", CRIDLinkRejectPathOrQuery
	default:
		// The authority goes on past the origin: a longer host, a port, or the
		// origin standing in the userinfo position of some other host.
		return "", CRIDLinkRejectOrigin
	}
	if !hasFragment {
		return "", CRIDLinkRejectTransport
	}
	return fragment, ""
}

// cridLinkVerifySentinels names, as bare sentinels, what a link's signed
// content failed on. Only the sentinels are kept. The errors themselves quote
// parts of what they were given — a key id, a field value — and nothing taken
// from a rejected reply may reach an error message.
func cridLinkVerifySentinels(err error) []error {
	var found []error
	for _, sentinel := range []error{
		ErrUnknownKID, ErrSignature, ErrStrictParse, ErrKeyLength, ErrEncoding, ErrFragment,
	} {
		if errors.Is(err, sentinel) {
			found = append(found, sentinel)
		}
	}
	return found
}

func rejectCRIDLink(class CRIDLinkRejectClass, sentinels ...error) error {
	return &CRIDLinkRejectedError{Class: class, sentinels: sentinels}
}

// cridLinkInfoCRIDMatches is the one hard check on the reply's metadata. When
// the metadata is an object with a crid member, that member must be exactly
// the requested CRID string. The comparison is with what was requested, not
// with what the link's key could derive: the same key has a CRID under every
// version, and an echo of a sibling is still an echo of something else.
func cridLinkInfoCRIDMatches(requestedCRID string, redirectInfo json.RawMessage) bool {
	info, ok := cridLinkJSONObject(redirectInfo)
	if !ok {
		return true
	}
	raw, present := info["crid"]
	if !present {
		return true
	}
	echoed, isString := cridLinkJSONString(raw)
	return isString && echoed == requestedCRID
}

// cridLinkInfo is the sanitized, display-only view of the reply's metadata. It
// keeps the two timestamps as the text the server wrote; the caller-facing
// result parses them. It has no CRID: the echoed CRID is checked, not shown.
type cridLinkInfo struct {
	qurlID            string
	expiresAt         string
	resourceCreatedAt string
	publisher         Publisher
}

// sanitizeCRIDLinkInfo reduces the reply's metadata to what may be displayed.
// It never fails. The metadata is optional and unsigned, so a malformed part
// of it is simply absent and the link is still usable: anything that is not an
// object leaves every member absent and the publisher unverified, a publisher
// that is not an object leaves the publisher unnamed and unverified, and a
// member this SDK does not know is ignored.
func sanitizeCRIDLinkInfo(raw json.RawMessage) cridLinkInfo {
	var info cridLinkInfo
	fields, ok := cridLinkJSONObject(raw)
	if !ok {
		return info
	}
	info.qurlID = cridLinkInfoText(fields["qurl_id"])
	info.expiresAt = cridLinkInfoText(fields["expires_at"])
	info.resourceCreatedAt = cridLinkInfoText(fields["resource_created_at"])

	publisher, ok := cridLinkJSONObject(fields["publisher"])
	if !ok {
		return info
	}
	info.publisher.Name = cridLinkInfoText(publisher["name"])
	// Only the JSON boolean true is verified. The string "true" is not.
	info.publisher.Verified = bytes.Equal(bytes.TrimSpace(publisher["verified"]), []byte("true"))
	return info
}

// cridLinkInfoText is the one rule for every display string in the metadata:
// kept only when it is a non-empty JSON string of at most
// cridLinkInfoTextMaxCodePoints code points. A longer string is dropped whole,
// never shortened, because a shortened value is a different value that looks
// like a real one. The empty result means absent.
func cridLinkInfoText(raw json.RawMessage) string {
	text, isString := cridLinkJSONString(raw)
	if !isString || utf8.RuneCountInString(text) > cridLinkInfoTextMaxCodePoints {
		return ""
	}
	return text
}

// parseCRIDLinkTime reads a kept timestamp. One that is absent, or is not
// RFC 3339, is the zero time: it is display metadata, and a value that cannot
// be read is treated exactly like one that was not sent.
func parseCRIDLinkTime(text string) time.Time {
	if text == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// cridLinkResourceCreatedAt reads the kept creation time the way ShareLink
// reports the same fact: nil when the server sent none or one that does not
// parse. The zero time is nil as well. It is an unset value on the wire, not a
// creation date, and is reported as absent rather than as year 1.
func cridLinkResourceCreatedAt(text string) *time.Time {
	createdAt := parseCRIDLinkTime(text)
	if createdAt.IsZero() {
		return nil
	}
	return &createdAt
}
