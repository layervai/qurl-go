package relayknock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Relay transport + the generic Knock orchestrator.
//
// The relay HTTP contract (nhp endpoints/relay/relay.go::handleRelay): POST the
// raw knock packet as application/octet-stream to {relayBaseURL}/relay/{serverId};
// 200 → the server's reply packet bytes; any other status → a transport fault
// (RelayError), distinct from an authenticated server *deny* (which comes back
// inside a decryptable NHP_ACK).

// HTTPDoer is the subset of *http.Client the relay transport needs. Narrowing to
// an interface lets a caller inject a fixed-egress client (to honor the
// same-egress-IP invariant), an instrumented client, or a test double. The zero
// value of a KnockOptions / RelayPost call (nil) falls back to http.DefaultClient.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// RelayError is a relay reply that was not a 200 application/octet-stream — a
// transport fault (unknown server, malformed/oversize packet, forward failure,
// shutdown, timeout). Status is the HTTP status, or 0 for a transport-level
// failure with no HTTP response.
type RelayError struct {
	Status int
	Msg    string
}

func (e *RelayError) Error() string { return e.Msg }

// RelayPost delivers a knock packet to the relay and returns the server's reply
// packet bytes. 200 → reply bytes; any other status → *RelayError.
func RelayPost(ctx context.Context, httpClient HTTPDoer, relayBaseURL, serverID string, packet []byte) ([]byte, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	base := strings.TrimRight(relayBaseURL, "/")
	url := base + "/relay/" + serverID

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(packet))
	if err != nil {
		return nil, &RelayError{Status: 0, Msg: fmt.Sprintf("relay POST %s: build request: %v", url, err)}
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &RelayError{Status: 0, Msg: fmt.Sprintf("relay POST %s failed: %v", url, err)}
	}
	defer func() { _ = resp.Body.Close() }() // read path; Close error is not actionable (over-limit body not drained — see #21)

	body, err := io.ReadAll(io.LimitReader(resp.Body, packetBufferSize))
	if err != nil {
		return nil, &RelayError{Status: resp.StatusCode, Msg: fmt.Sprintf("relay POST %s: read reply: %v", url, err)}
	}
	if resp.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(body))
		m := fmt.Sprintf("relay POST %s -> %d", url, resp.StatusCode)
		if detail != "" {
			m += ": " + detail
		}
		return nil, &RelayError{Status: resp.StatusCode, Msg: m}
	}
	return body, nil
}

// KnockOptions tunes a Knock. The zero value is the production default: a fresh
// random throwaway device identity and random handshake nonces, suitable for an
// access-token knock where the server authenticates by the body, not a
// pre-registered device key.
//
// The enterPortal/qv2 path sets DeviceStaticPriv to the per-qURL private key from
// the link's secret block, so the server can match the authenticated Noise
// initiator key to the signed qurl_user_public_key. The remaining fields stay
// zero (random) there.
type KnockOptions struct {
	// HTTPClient is the client used for the relay POST. nil ⇒ http.DefaultClient.
	HTTPClient HTTPDoer

	// DeviceStaticPriv is the agent static private key (the Noise initiator
	// identity). nil/empty ⇒ a fresh random 32-byte key is minted for this knock.
	DeviceStaticPriv []byte
}

// Knock performs one NHP relay knock: it builds an NHP_KNK for body, derives
// serverId = PubKeyFingerprint(serverStaticPub), POSTs it to
// relayBaseURL + "/relay/" + serverId, then decrypts and authenticates the reply
// against serverStaticPub. body is an already-serialized application knock body
// (relayknock does not know any body shape). The returned Reply.Body is the
// decrypted application reply for the caller to interpret.
//
// The caller's egress IP is the address the NHP server opens access for, so
// a subsequent resource request must share that egress IP (see the package doc).
func Knock(ctx context.Context, relayBaseURL string, serverStaticPub, body []byte, opts KnockOptions) (*Reply, error) {
	if len(serverStaticPub) != publicKeySize {
		return nil, fmt.Errorf("server static pub must be %d bytes, got %d", publicKeySize, len(serverStaticPub))
	}

	devicePriv := opts.DeviceStaticPriv
	if len(devicePriv) == 0 {
		devicePriv = make([]byte, 32)
		if _, err := rand.Read(devicePriv); err != nil {
			return nil, fmt.Errorf("device key: %w", err)
		}
	} else if len(devicePriv) != 32 {
		return nil, fmt.Errorf("device static priv must be 32 bytes, got %d", len(devicePriv))
	}

	ephemeralPriv := make([]byte, 32)
	if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	counter, err := randUint64()
	if err != nil {
		return nil, fmt.Errorf("counter: %w", err)
	}
	preamble, err := randUint32()
	if err != nil {
		return nil, fmt.Errorf("preamble: %w", err)
	}

	packet, err := BuildKnock(&KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverStaticPub,
		EphemeralPriv:    ephemeralPriv,
		TimestampNanos:   nowUnixNano(),
		Counter:          counter,
		Preamble:         preamble,
		Body:             body,
	})
	if err != nil {
		return nil, fmt.Errorf("build knock: %w", err)
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
