package relayknock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// Relay transport + the browser-knock orchestrator (Knock).
//
// The relay HTTP contract (the reference NHP relay's handleRelay endpoint): POST
// the raw packet as application/octet-stream to {relayBaseURL}/relay/{serverId}.
// Browser knock-family requests return 200 with the server's reply packet bytes.
// Anything else is a transport fault (RelayError), distinct from an authenticated
// server deny carried inside a decryptable reply packet. Agent lifecycle messages
// (NHP_OTP, NHP_REG, NHP_LST) use native UDP, never this HTTP transport.

// HTTPDoer is the subset of *http.Client the relay transport needs. Narrowing to
// an interface lets a caller inject a fixed-egress client (to honor the
// same-egress-IP invariant), an instrumented client, or a test double. The zero
// value of a KnockOptions / RelayPost call (nil) falls back to http.DefaultClient.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// RelayError is a relay POST that failed at the HTTP layer: a transport fault
// (unknown server, malformed/oversize packet, forward failure, shutdown,
// timeout), or a relay response outside the calling contract. RelayPost expects
// 200 with reply packet bytes. Status is the HTTP status, or 0 for a
// transport-level failure with no HTTP response.
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
// violates the request→reply correlation contract Knock enforces above the
// crypto: the reply header's counter did not echo the request, or its type is
// not one the request could elicit (see knockReplyTypeAllowed). It is distinct from a
// *RelayError (an HTTP-transport fault, before any authenticated reply) and from
// the decrypt/authentication failures DecryptReply returns. Note an overload
// NHP_COK is handled BEFORE these checks (see Knock), so a "server busy"
// reply never lands here. Only a misbehaving or byzantine relay produces it — a
// conforming relay routes a reply back by its cleartext counter, so a
// mis-correlated reply could never have reached this caller.
//
// Exposed as a sentinel so a consumer can map it into its own error taxonomy
// with errors.Is rather than matching the message string. The qurl SDK's
// consumer-side mapping (qurl/portal.go normalizeRelayError, translating this to
// the portal ErrMalformedReply taxonomy) lives in this module's qurl package.
var ErrMalformedReply = nhpwire.ErrMalformedReply

// RelayPost delivers a caller-built browser knock-family packet to the relay and
// returns the server's reply packet bytes. Callers must use NHP_KNK, NHP_RKN, or
// NHP_EXT. It validates the cleartext packet type before any HTTP request; the
// relay independently enforces the same allowlist. 200 returns reply bytes; any
// other status returns *RelayError.
func RelayPost(ctx context.Context, httpClient HTTPDoer, relayBaseURL, serverID string, packet []byte) ([]byte, error) {
	headerType, err := nhpwire.PacketType(packet)
	if err != nil {
		return nil, fmt.Errorf("relay POST rejected malformed NHP packet: %w", err)
	}
	if !browserRelayTypeAllowed(headerType) {
		return nil, fmt.Errorf("relay POST rejected NHP header type %d: browser relay accepts only NHP_KNK, NHP_RKN, or NHP_EXT", headerType)
	}

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

func browserRelayTypeAllowed(headerType int) bool {
	switch headerType {
	case nhpwire.TypeKNK, nhpwire.TypeRKN, nhpwire.TypeEXT:
		return true
	default:
		return false
	}
}

// relayDo delivers one packet to {relayBaseURL}/relay/{serverID} and returns
// the HTTP status and the bounded response body. RelayPost interprets that
// response as 200 + reply bytes. Transport-level failures (request build,
// connection, body read) come back as *RelayError; url is returned so callers
// compose errors around the one URL actually posted.
//
// Security boundary: this transport is only for browser/qv2 portal traffic.
// Registered-agent control traffic must use native UDP and must not reach it.
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

	body, err = io.ReadAll(io.LimitReader(resp.Body, nhpwire.PacketBufferSize))
	if err != nil {
		return resp.StatusCode, nil, url, &RelayError{Status: resp.StatusCode, Msg: fmt.Sprintf("relay POST %s: read reply: %v", url, err)}
	}
	return resp.StatusCode, body, url, nil
}

// KnockOptions tunes a Knock. The zero value is the production
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
	// identity). nil/empty ⇒ a fresh random X25519 key is minted and wiped after
	// the operation. A caller-provided key remains caller-owned and is never wiped.
	DeviceStaticPriv []byte
}

// Knock performs one NHP relay knock: it builds an NHP_KNK for body, derives
// serverId = PubKeyFingerprint(serverStaticPub), POSTs it to
// relayBaseURL + "/relay/" + serverId, then decrypts and authenticates the reply
// (NHP_ACK / NHP_COK) against serverStaticPub. body is an already-serialized
// application body; relayknock does not know its shape. The returned Reply.Body
// is the decrypted application reply for the caller to interpret.
//
// The caller's egress IP is the address the NHP server opens access for, so
// a subsequent resource request must share that egress IP (see the package doc).
//
// The reply header's type and counter ride outside the AEAD (the transcript
// authenticates the server, not those fields), so Knock enforces what the crypto
// cannot: the reply must echo this request's counter and carry NHP_ACK or NHP_COK.
// Anything else fails closed. The caller branches the success and overload
// outcomes with IsACK versus IsCookieChallenge.
func Knock(ctx context.Context, relayBaseURL string, serverStaticPub, body []byte, opts KnockOptions) (*Reply, error) {
	packet, devicePriv, counter, err := buildKnockOutbound(serverStaticPub, body, opts)
	if err != nil {
		return nil, err
	}
	if len(opts.DeviceStaticPriv) == 0 {
		defer cryptoutil.Wipe(devicePriv)
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
	// is a valid overload reply to a knock, which the server can cookie-challenge
	// under load, so a request can come back as the authenticated "server busy,
	// retry later" signal a caller branches with IsCookieChallenge. It is returned
	// straight to the caller as that retryable overload signal. Unlike an ACK, a
	// COK is NOT a protocol transaction — the reference server documents it as
	// "not handled as a transaction" and only stamps it with the request counter
	// as a relay-routing concession so the HTTP bridge can deliver it. Gating the
	// retryable overload outcome behind the counter-echo check would let a COK
	// whose counter does not correlate (an older/clustered server, a window
	// boundary, a non-conforming relay) be misclassified as ErrMalformedReply —
	// turning a retryable "busy"
	// into a hard failure on the hot path. So a COK the request can legitimately
	// elicit returns straight to the caller; the caller reads it as overload.
	//
	if dr.IsCookieChallenge() && knockReplyTypeAllowed(dr.Type) {
		return dr, nil
	}

	// The counter echo enforces the relay profile's OWN correlation contract, not
	// a new assumption this package invents: the relay (an async HTTP↔UDP bridge,
	// not a same-connection proxy) correlates replies to requests by the inner
	// cleartext header counter, routing each reply back to the waiting HTTP POST
	// over a single shared UDP socket. So any non-COK reply delivered to this
	// caller echoes the request counter BY CONSTRUCTION — a reply that did not echo
	// it could not have been routed here at all — and the reference server stamps
	// every transaction ACK header with the request's transaction id
	// precisely so that routing works. Enforcing the echo here just refuses a
	// reply a misbehaving relay swapped in from a different exchange; it restates
	// the relay's routing invariant; it is not an unproven premise.
	//
	// These two post-decrypt checks wrap ErrMalformedReply, not *RelayError, on
	// purpose: they are semantic/correlation failures of an already-authenticated
	// reply, in the same class as the "decrypt reply" failure just above — only
	// HTTP-transport faults surface as *RelayError (see RelayPost). The sentinel
	// lets a consumer map both into its own taxonomy without a string match.
	if dr.Counter != counter {
		return nil, fmt.Errorf("%w: reply counter %d does not echo request counter %d", ErrMalformedReply, dr.Counter, counter)
	}
	if !knockReplyTypeAllowed(dr.Type) {
		return nil, fmt.Errorf("%w: reply type %d is not a valid reply to an NHP_KNK request", ErrMalformedReply, dr.Type)
	}
	return dr, nil
}

// knockReplyTypeAllowed reports whether an authenticated reply's header type is
// one an HTTP NHP_KNK can legitimately elicit. The type field itself is not
// AEAD-covered, so this pairing — not the decrypt — stops a misbehaving relay
// from presenting another reply kind as a knock result.
func knockReplyTypeAllowed(replyType int) bool {
	return replyType == nhpwire.TypeACK || replyType == nhpwire.TypeCOK
}

// buildKnockOutbound resolves the device identity from opts, mints the
// per-message random values (ephemeral key, counter, preamble), and builds an
// NHP_KNK packet for body. It returns the packet, the device static private key
// actually used (a round-trip caller decrypts the reply with it), and the
// minted counter (which a round-trip caller requires the reply to echo).
func buildKnockOutbound(serverStaticPub, body []byte, opts KnockOptions) (packet, devicePriv []byte, counter uint64, err error) {
	if err := x25519key.ValidatePublic(serverStaticPub); err != nil {
		return nil, nil, 0, fmt.Errorf("server static pub is unusable: %w", err)
	}

	var mintedDevicePriv []byte
	devicePriv = opts.DeviceStaticPriv
	if len(devicePriv) == 0 {
		devicePriv, err = cryptoutil.RandomBytes(x25519key.Size)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("device key: %w", err)
		}
		mintedDevicePriv = devicePriv
		// On success the caller owns the throwaway key until Knock has decrypted
		// the reply. Scrub here only when a later build step fails before ownership
		// can transfer.
		defer func() {
			if err != nil {
				cryptoutil.Wipe(mintedDevicePriv)
			}
		}()
	} else if len(devicePriv) != x25519key.Size {
		return nil, nil, 0, fmt.Errorf("device static priv must be %d bytes, got %d", x25519key.Size, len(devicePriv))
	}

	ephemeralPriv, err := cryptoutil.RandomBytes(x25519key.Size)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ephemeral key: %w", err)
	}
	defer cryptoutil.Wipe(ephemeralPriv)
	counter, err = cryptoutil.RandomUint64()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("counter: %w", err)
	}
	preamble, err := cryptoutil.RandomUint32()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("preamble: %w", err)
	}

	packet, err = nhpwire.BuildMessage(nhpwire.TypeKNK, &nhpwire.Inputs{
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
