package relayknock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Relay transport + the generic message orchestrators (Knock/Exchange/Send).
//
// The relay HTTP contract (the reference NHP relay's handleRelay endpoint): POST
// the raw packet as application/octet-stream to {relayBaseURL}/relay/{serverId}.
// For a round-trip message (NHP_KNK, NHP_REG), 200 → the server's reply packet
// bytes. For the one-way NHP_OTP the server never replies; a conforming relay
// acknowledges dispatch at the HTTP layer with 202 Accepted and an empty body.
// Anything else → a transport fault (RelayError), distinct from an authenticated
// server *deny* (which comes back inside a decryptable reply packet).

// HTTPDoer is the subset of *http.Client the relay transport needs. Narrowing to
// an interface lets a caller inject a fixed-egress client (to honor the
// same-egress-IP invariant), an instrumented client, or a test double. The zero
// value of a KnockOptions / RelayPost call (nil) falls back to http.DefaultClient.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// RelayError is a relay POST that failed at the HTTP layer: a transport fault
// (unknown server, malformed/oversize packet, forward failure, shutdown,
// timeout), or a relay response outside the calling contract — RelayPost
// expects 200 with the reply packet bytes, Send expects 202 Accepted with an
// empty body. Status is the HTTP status, or 0 for a transport-level failure
// with no HTTP response.
type RelayError struct {
	Status int
	Msg    string
}

func (e *RelayError) Error() string {
	if e == nil || strings.TrimSpace(e.Msg) == "" {
		return "relay error"
	}
	return e.Msg
}

// ErrMalformedReply marks an authenticated reply that opened correctly but
// violates the request→reply correlation contract Exchange enforces above the
// crypto: the reply header's counter did not echo the request, or its type is
// not one the request could elicit (see replyTypeAllowed). It is distinct from a
// *RelayError (an HTTP-transport fault, before any authenticated reply) and from
// the decrypt/authentication failures DecryptReply returns. Note an overload
// NHP_COK is handled BEFORE these checks (see Exchange), so a "server busy"
// reply never lands here. Only a misbehaving or byzantine relay produces it — a
// conforming relay routes a reply back by its cleartext counter, so a
// mis-correlated reply could never have reached this caller.
//
// Exposed as a sentinel so a consumer can map it into its own error taxonomy
// with errors.Is rather than matching the message string. The qurl SDK's
// consumer-side mapping (qurl/portal.go normalizeRelayError, translating this to
// the portal ErrMalformedReply / enrollment ErrRegisterReplyMalformed taxonomy)
// lands with the stacked RegisterAgent PR, not this one.
var ErrMalformedReply = errors.New("relayknock: malformed reply")

// RelayPost delivers a round-trip NHP packet (knock or register) to the relay
// and returns the server's reply packet bytes. 200 → reply bytes; any other
// status → *RelayError.
func RelayPost(ctx context.Context, httpClient HTTPDoer, relayBaseURL, serverID string, packet []byte) ([]byte, error) {
	status, body, url, err := relayDo(ctx, httpClient, relayBaseURL, serverID, packet)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		detail := strings.TrimSpace(string(body))
		m := fmt.Sprintf("relay POST %s -> %d", url, status)
		if detail != "" {
			m += ": " + detail
		}
		return nil, &RelayError{Status: status, Msg: m}
	}
	return body, nil
}

// relayDo delivers one packet to {relayBaseURL}/relay/{serverID} and returns
// the HTTP status and the (bounded) response body, leaving status interpretation
// to the caller — RelayPost requires 200 + reply bytes, Send requires 202 +
// empty. Transport-level failures (request build, connection, body read) come
// back as *RelayError; url is returned so callers compose errors around the one
// URL actually posted.
func relayDo(ctx context.Context, httpClient HTTPDoer, relayBaseURL, serverID string, packet []byte) (status int, body []byte, url string, err error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	base := strings.TrimRight(relayBaseURL, "/")
	url = base + "/relay/" + serverID

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(packet))
	if err != nil {
		return 0, nil, url, &RelayError{Status: 0, Msg: fmt.Sprintf("relay POST %s: build request: %v", url, err)}
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, url, &RelayError{Status: 0, Msg: fmt.Sprintf("relay POST %s failed: %v", url, err)}
	}
	defer func() { _ = resp.Body.Close() }() // read path; Close error is not actionable (over-limit body not drained — see #21)

	body, err = io.ReadAll(io.LimitReader(resp.Body, packetBufferSize))
	if err != nil {
		return resp.StatusCode, nil, url, &RelayError{Status: resp.StatusCode, Msg: fmt.Sprintf("relay POST %s: read reply: %v", url, err)}
	}
	return resp.StatusCode, body, url, nil
}

// KnockOptions tunes a Knock, Exchange, or Send. The zero value is the production
// default: a fresh random throwaway device identity and random handshake nonces,
// suitable for a message where the server authenticates by the body rather than a
// pre-registered device key.
//
// The qURL path sets DeviceStaticPriv to the per-link private key from the link's
// secret block, so the server can match the authenticated Noise initiator key to the
// signed public key. The remaining fields stay zero (random) there.
type KnockOptions struct {
	// HTTPClient is the client used for the relay POST. nil ⇒ http.DefaultClient.
	HTTPClient HTTPDoer

	// DeviceStaticPriv is the agent static private key (the Noise initiator
	// identity). nil/empty ⇒ a fresh random 32-byte key is minted for this knock.
	DeviceStaticPriv []byte
}

// Knock performs one NHP relay knock — Exchange fixed to TypeKnock: it builds
// an NHP_KNK for body, POSTs it to the relay, then decrypts and authenticates
// the reply (NHP_ACK / NHP_COK) against serverStaticPub.
//
// The caller's egress IP is the address the NHP server opens access for, so
// a subsequent resource request must share that egress IP (see the package doc).
func Knock(ctx context.Context, relayBaseURL string, serverStaticPub, body []byte, opts KnockOptions) (*Reply, error) {
	return Exchange(ctx, relayBaseURL, serverStaticPub, TypeKnock, body, opts)
}

// Exchange performs one NHP request/reply round trip: it builds a packet of the
// given initiator header type for body, derives
// serverId = PubKeyFingerprint(serverStaticPub), POSTs it to
// relayBaseURL + "/relay/" + serverId, then decrypts and authenticates the reply
// against serverStaticPub. headerType must be a round-trip type — TypeKnock
// (answered with NHP_ACK, or NHP_COK under overload) or TypeRegister (answered
// with NHP_RAK, or NHP_COK under overload); TypeOTP is rejected because the
// server never replies to an OTP message, so
// there is no reply to exchange (use Send). body is an already-serialized
// application body (relayknock does not know any body shape). The returned
// Reply.Body is the decrypted application reply for the caller to interpret.
//
// The reply header's type and counter ride outside the AEAD (the transcript
// authenticates the server, not those fields), so Exchange enforces what the
// crypto cannot: the reply must echo this request's counter and carry a type
// the request can elicit — TypeKnock → NHP_ACK/NHP_COK, TypeRegister →
// NHP_RAK/NHP_COK. Anything else fails closed. The caller branches the success
// and overload outcomes with IsACK / IsRegisterAck versus IsCookieChallenge.
func Exchange(ctx context.Context, relayBaseURL string, serverStaticPub []byte, headerType int, body []byte, opts KnockOptions) (*Reply, error) {
	switch headerType {
	case TypeKnock, TypeRegister:
	case TypeOTP:
		return nil, errors.New("NHP_OTP is one-way (the server never replies to it); use Send, not Exchange")
	default:
		return nil, fmt.Errorf("unsupported round-trip header type %d (want TypeKnock or TypeRegister)", headerType)
	}

	packet, devicePriv, counter, err := buildOutbound(headerType, serverStaticPub, body, opts)
	if err != nil {
		return nil, err
	}

	serverID := PubKeyFingerprint(serverStaticPub)
	reply, err := RelayPost(ctx, opts.HTTPClient, relayBaseURL, serverID, packet)
	if err != nil {
		return nil, err // *RelayError or transport error
	}

	dr, err := DecryptReply(devicePriv, serverStaticPub, reply)
	if err != nil {
		return nil, fmt.Errorf("decrypt reply: %w", err)
	}

	// Overload cookie-challenge FIRST, before the counter-echo check. An NHP_COK
	// is a valid overload reply to BOTH a knock and a register: both are
	// Noise-handshake initiations the server can cookie-challenge under load, so
	// either request can come back as the authenticated "server busy, retry later"
	// signal a caller branches with IsCookieChallenge. It is returned straight to
	// the caller as that retryable overload signal. Unlike an ACK/RAK, a COK is NOT
	// a protocol transaction — the reference server documents it as "not handled as
	// a transaction" and only stamps it with the request counter as a relay-routing
	// concession so the HTTP bridge can deliver it. Gating the retryable overload
	// outcome behind the counter-echo check would let a COK whose counter does not
	// correlate (an older/clustered server, a window boundary, a non-conforming
	// relay) be misclassified as ErrMalformedReply — turning a retryable "busy"
	// into a hard failure on the hot path. So a COK the request can legitimately
	// elicit returns straight to the caller; the caller reads it as overload.
	//
	// The replyTypeAllowed conjunct is always true for today's round-trip types
	// (both TypeKnock and TypeRegister admit NHP_COK) — intentional future-proofing,
	// load-bearing only if a non-cookie-challengeable round-trip type is ever added.
	if dr.IsCookieChallenge() && replyTypeAllowed(headerType, dr.Type) {
		return dr, nil
	}

	// The counter echo enforces the relay profile's OWN correlation contract, not
	// a new assumption this package invents: the relay (an async HTTP↔UDP bridge,
	// not a same-connection proxy) correlates replies to requests by the inner
	// cleartext header counter, routing each reply back to the waiting HTTP POST
	// over a single shared UDP socket. So any non-COK reply delivered to this
	// caller echoes the request counter BY CONSTRUCTION — a reply that did not echo
	// it could not have been routed here at all — and the reference server stamps
	// every transaction reply header (ACK, RAK) with the request's transaction id
	// precisely so that routing works. Enforcing the echo here just refuses a
	// reply a misbehaving relay swapped in from a different exchange; it restates
	// the relay's routing invariant, it is not an unproven premise. The matched
	// REG↔RAK pair is independently pinned by the qurl-conformance
	// agent-registration golden (counter 0xb, conformance#19); this in-package
	// fence consumes it once that vector lands (the current knock/ack goldens are
	// not a matched pair).
	//
	// These two post-decrypt checks wrap ErrMalformedReply, not *RelayError, on
	// purpose: they are semantic/correlation failures of an already-authenticated
	// reply, in the same class as the "decrypt reply" failure just above — only
	// HTTP-transport faults surface as *RelayError (see RelayPost). The sentinel
	// lets a consumer map both into its own taxonomy without a string match.
	if dr.Counter != counter {
		return nil, fmt.Errorf("%w: reply counter %d does not echo request counter %d", ErrMalformedReply, dr.Counter, counter)
	}
	if !replyTypeAllowed(headerType, dr.Type) {
		return nil, fmt.Errorf("%w: reply type %d is not a valid reply to a type-%d request", ErrMalformedReply, dr.Type, headerType)
	}
	return dr, nil
}

// replyTypeAllowed reports whether an authenticated reply's header type is one
// the given request type can legitimately elicit. The type field itself is not
// AEAD-covered, so this pairing — not the decrypt — is what stops a
// misbehaving relay from presenting one reply kind as another.
func replyTypeAllowed(requestType, replyType int) bool {
	switch requestType {
	case TypeKnock:
		return replyType == nhpACK || replyType == nhpCOK
	case TypeRegister:
		return replyType == nhpRAK || replyType == nhpCOK
	default:
		return false
	}
}

// Send performs one one-way NHP dispatch: it builds an NHP_OTP packet for body,
// derives serverId = PubKeyFingerprint(serverStaticPub), and POSTs it to
// relayBaseURL + "/relay/" + serverId. The server does not reply to OTP
// messages, so there are no reply bytes to decrypt; a conforming relay
// acknowledges the dispatch at the HTTP layer with 202 Accepted and an empty
// body, and that acknowledgement is exactly what Send verifies — for a one-way
// message the relay's HTTP acknowledgement, not the server, is the trust
// anchor for dispatch. Anything else — a non-202 status, or a 202 carrying a
// body — comes back as a *RelayError. Every Send mints fresh randomness
// (ephemeral key, counter, preamble), so a retried Send is a new, independent
// dispatch — at-least-once delivery, never a wire-level replay. It also mints a
// fresh random Noise initiator identity unless opts.DeviceStaticPriv is set, so
// a caller that needs a stable device identity across retries (e.g. to present
// the same key on each attempt of a registration bootstrap) must set it.
func Send(ctx context.Context, relayBaseURL string, serverStaticPub, body []byte, opts KnockOptions) error {
	// Send drops buildOutbound's devicePriv and counter: NHP_OTP is one-way, so
	// there is no reply to decrypt or counter to correlate.
	packet, _, _, err := buildOutbound(nhpOTP, serverStaticPub, body, opts)
	if err != nil {
		return err
	}

	serverID := PubKeyFingerprint(serverStaticPub)
	status, respBody, url, err := relayDo(ctx, opts.HTTPClient, relayBaseURL, serverID, packet)
	if err != nil {
		return err // *RelayError transport fault
	}
	if status != http.StatusAccepted {
		// The len>0 guard is deliberate: a bare 200 (empty body) is no evidence the
		// one-way OTP was processed, so it falls through to sendError ("safe to
		// retry"); sendAcceptedError ("may deliver a duplicate") is reserved for a
		// 200 that returned bytes (evidence something may have been delivered).
		if status == http.StatusOK && len(respBody) > 0 {
			// Reply packet bytes to a one-way message: something evidently
			// received and processed the dispatch (a reply exists), the relay
			// just broke the one-way contract. Don't quote the binary body.
			return sendAcceptedError(status, fmt.Sprintf(
				"relay POST %s -> 200 with a %d-byte reply to a one-way NHP_OTP (a conforming relay acknowledges dispatch with 202 Accepted); the server likely processed the dispatch",
				url, len(respBody)))
		}
		// Quoting the body is safe here, unlike the 200/202 branches: a non-2xx
		// body is relay-authored plaintext error detail (the same contract
		// RelayPost quotes), never packet bytes.
		m := fmt.Sprintf("relay POST %s -> %d, want 202 Accepted for a one-way NHP_OTP dispatch", url, status)
		if detail := strings.TrimSpace(string(respBody)); detail != "" {
			m += ": " + detail
		}
		return sendError(status, m)
	}
	if len(respBody) > 0 {
		// 202 but with a body: the relay accepted, just broke the empty-body ack
		// contract. sendAcceptedError carries the retry framing.
		return sendAcceptedError(status, fmt.Sprintf(
			"relay POST %s -> 202 Accepted with an unexpected %d-byte body (a conforming relay acknowledges a one-way dispatch with an empty body)",
			url, len(respBody)))
	}
	return nil
}

// sendError wraps a Send contract violation where nothing acknowledged the
// dispatch, so the send is safe to repeat.
func sendError(status int, msg string) *RelayError {
	return &RelayError{Status: status, Msg: msg + "; dispatch unconfirmed — safe to retry the send"}
}

// sendAcceptedError wraps a Send contract violation where the relay evidently
// DID take the dispatch (a 200 reply, or a 202 with a body) — so a retry may
// deliver a duplicate. One-way NHP_OTP delivery is at-least-once by design, so
// a retry is still safe; the framing just doesn't overclaim that nothing
// happened.
func sendAcceptedError(status int, msg string) *RelayError {
	return &RelayError{Status: status, Msg: msg + "; a retry may deliver a duplicate — one-way NHP_OTP delivery is at-least-once"}
}

// buildOutbound resolves the device identity from opts, mints the per-message
// random values (ephemeral key, counter, preamble), and builds a headerType
// packet for body. It returns the packet, the device static private key
// actually used (a round-trip caller decrypts the reply with it), and the
// minted counter (which a round-trip caller requires the reply to echo).
func buildOutbound(headerType int, serverStaticPub, body []byte, opts KnockOptions) (packet, devicePriv []byte, counter uint64, err error) {
	if len(serverStaticPub) != publicKeySize {
		return nil, nil, 0, fmt.Errorf("server static pub must be %d bytes, got %d", publicKeySize, len(serverStaticPub))
	}

	devicePriv = opts.DeviceStaticPriv
	if len(devicePriv) == 0 {
		devicePriv, err = randBytes(32)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("device key: %w", err)
		}
	} else if len(devicePriv) != 32 {
		return nil, nil, 0, fmt.Errorf("device static priv must be 32 bytes, got %d", len(devicePriv))
	}

	ephemeralPriv, err := randBytes(32)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ephemeral key: %w", err)
	}
	counter, err = randUint64()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("counter: %w", err)
	}
	preamble, err := randUint32()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("preamble: %w", err)
	}

	packet, err = buildMessage(headerType, &KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverStaticPub,
		EphemeralPriv:    ephemeralPriv,
		TimestampNanos:   nowUnixNano(),
		Counter:          counter,
		Preamble:         preamble,
		Body:             body,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("build message: %w", err)
	}
	return packet, devicePriv, counter, nil
}

// randBytes returns n cryptographically random bytes (device/ephemeral keys).
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func randUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
