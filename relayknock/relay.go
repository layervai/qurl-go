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

// RelayPost delivers a knock packet to the relay and returns the server's reply
// packet bytes. 200 → reply bytes; any other status → *RelayError.
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
// (answered with NHP_ACK / NHP_COK) or TypeRegister (answered with NHP_RAK);
// TypeOTP is rejected because the server never replies to an OTP message, so
// there is no reply to exchange (use Send). body is an already-serialized
// application body (relayknock does not know any body shape). The returned
// Reply.Body is the decrypted application reply for the caller to interpret.
func Exchange(ctx context.Context, relayBaseURL string, serverStaticPub []byte, headerType int, body []byte, opts KnockOptions) (*Reply, error) {
	switch headerType {
	case TypeKnock, TypeRegister:
	case TypeOTP:
		return nil, errors.New("NHP_OTP is one-way (the server never replies to it); use Send, not Exchange")
	default:
		return nil, fmt.Errorf("unsupported round-trip header type %d (want TypeKnock or TypeRegister)", headerType)
	}

	packet, devicePriv, err := buildOutbound(headerType, serverStaticPub, body, opts)
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
	return dr, nil
}

// Send performs one one-way NHP dispatch: it builds an NHP_OTP packet for body,
// derives serverId = PubKeyFingerprint(serverStaticPub), and POSTs it to
// relayBaseURL + "/relay/" + serverId. The server does not reply to OTP
// messages, so there are no reply bytes to decrypt; a conforming relay
// acknowledges the dispatch at the HTTP layer with 202 Accepted and an empty
// body, and that acknowledgement is exactly what Send verifies. Anything else —
// a non-202 status, or a 202 carrying a body — leaves the dispatch unconfirmed
// and comes back as a *RelayError; an NHP_OTP send is safe to retry.
func Send(ctx context.Context, relayBaseURL string, serverStaticPub, body []byte, opts KnockOptions) error {
	packet, _, err := buildOutbound(nhpOTP, serverStaticPub, body, opts)
	if err != nil {
		return err
	}

	serverID := PubKeyFingerprint(serverStaticPub)
	status, respBody, url, err := relayDo(ctx, opts.HTTPClient, relayBaseURL, serverID, packet)
	if err != nil {
		return err // *RelayError transport fault
	}
	if status != http.StatusAccepted {
		if status == http.StatusOK && len(respBody) > 0 {
			// Reply packet bytes to a one-way message: don't quote the binary body.
			return sendError(status, fmt.Sprintf(
				"relay POST %s -> 200 with a %d-byte reply to a one-way NHP_OTP (the server never replies to OTP; a conforming relay acknowledges dispatch with 202 Accepted)",
				url, len(respBody)))
		}
		m := fmt.Sprintf("relay POST %s -> %d, want 202 Accepted for a one-way NHP_OTP dispatch", url, status)
		if detail := strings.TrimSpace(string(respBody)); detail != "" {
			m += ": " + detail
		}
		return sendError(status, m)
	}
	if len(respBody) > 0 {
		return sendError(status, fmt.Sprintf(
			"relay POST %s -> 202 Accepted with an unexpected %d-byte body (a conforming relay acknowledges a one-way dispatch with an empty body)",
			url, len(respBody)))
	}
	return nil
}

// sendError wraps a Send contract violation as a *RelayError, appending the
// retry guidance every Send failure shares: the dispatch was not acknowledged,
// and an NHP_OTP send is safe to repeat.
func sendError(status int, msg string) *RelayError {
	return &RelayError{Status: status, Msg: msg + "; dispatch unconfirmed — safe to retry the send"}
}

// buildOutbound resolves the device identity from opts, mints the per-message
// random values (ephemeral key, counter, preamble), and builds a headerType
// packet for body. It returns the packet plus the device static private key
// actually used, which a round-trip caller needs to decrypt the reply.
func buildOutbound(headerType int, serverStaticPub, body []byte, opts KnockOptions) (packet, devicePriv []byte, err error) {
	if len(serverStaticPub) != publicKeySize {
		return nil, nil, fmt.Errorf("server static pub must be %d bytes, got %d", publicKeySize, len(serverStaticPub))
	}

	devicePriv = opts.DeviceStaticPriv
	if len(devicePriv) == 0 {
		devicePriv = make([]byte, 32)
		if _, err := rand.Read(devicePriv); err != nil {
			return nil, nil, fmt.Errorf("device key: %w", err)
		}
	} else if len(devicePriv) != 32 {
		return nil, nil, fmt.Errorf("device static priv must be 32 bytes, got %d", len(devicePriv))
	}

	ephemeralPriv := make([]byte, 32)
	if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, nil, fmt.Errorf("ephemeral key: %w", err)
	}
	counter, err := randUint64()
	if err != nil {
		return nil, nil, fmt.Errorf("counter: %w", err)
	}
	preamble, err := randUint32()
	if err != nil {
		return nil, nil, fmt.Errorf("preamble: %w", err)
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
		return nil, nil, fmt.Errorf("build message: %w", err)
	}
	return packet, devicePriv, nil
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
