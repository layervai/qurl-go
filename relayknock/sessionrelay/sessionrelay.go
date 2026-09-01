// Package sessionrelay carries registered-agent NHP_KNK and the one possible
// NHP_RKN through one trusted HTTPS relay. Agent assignment, enrollment, and
// registration remain native UDP operations.
package sessionrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
	"github.com/layervai/qurl-go/relayknock/internal/sessioncookie"
)

var (
	// ErrInvalidConfig marks an unusable relay origin or HTTP client.
	ErrInvalidConfig = errors.New("sessionrelay: invalid configuration")
	// ErrInvalidRequest marks a packet that is unusable before HTTP I/O.
	ErrInvalidRequest = errors.New("sessionrelay: invalid request")
	// ErrTransport marks one failed HTTPS POST. It never includes the relay URL,
	// server fingerprint, response body, or an underlying network error.
	ErrTransport = errors.New("sessionrelay: HTTPS exchange failed")
	// ErrServerUnauthenticated marks a response that is oversized or does not
	// authenticate against the caller-pinned server static key.
	ErrServerUnauthenticated = errors.New("sessionrelay: reply failed server authentication")
)

// DefaultTimeout bounds one HTTPS NHP flight when the caller's HTTP client
// does not set a shorter or longer explicit bound. A caller context with an
// earlier deadline still wins.
const DefaultTimeout = 3 * time.Second

// Transport is one immutable trusted HTTPS relay origin and a redirect-refusing
// client. It issues one POST per NHP flight and performs no retry or UDP fallback.
type Transport struct {
	baseURL string
	client  *http.Client
}

// New validates an HTTPS origin and clones client with redirects disabled. A
// nil client clones http.DefaultClient. The origin must not contain credentials,
// a path, query, or fragment.
func New(baseURL string, client *http.Client) (*Transport, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, ErrInvalidConfig
	}
	if client == nil {
		client = http.DefaultClient
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clientCopy.Jar = nil
	if clientCopy.Timeout <= 0 {
		clientCopy.Timeout = DefaultTimeout
	}
	return &Transport{baseURL: strings.TrimRight(baseURL, "/"), client: &clientCopy}, nil
}

// KnockWithReknock sends one KNK. An authenticated COK causes exactly one RKN
// with the strict correlated cookie. Any other failure is terminal for this
// call; the transport does not retry, use UDP, or select another cell.
func (t *Transport) KnockWithReknock(ctx context.Context, serverStaticPub, deviceStaticPriv, knockBody, reknockBody []byte) (*relayknock.Reply, error) {
	if err := validate(ctx, t, serverStaticPub, deviceStaticPriv, knockBody); err != nil {
		return nil, err
	}
	if len(reknockBody) > nhpcontract.MaxApplicationBodySize {
		return nil, ErrInvalidRequest
	}
	reply, counter, err := t.exchange(ctx, relayknock.TypeKnock, serverStaticPub, deviceStaticPriv, knockBody, nil)
	if err != nil {
		return nil, err
	}
	if !reply.IsCookieChallenge() {
		return reply, nil
	}
	cookie, err := sessioncookie.Parse(reply.Body, counter)
	cryptoutil.Wipe(reply.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: cookie challenge rejected", relayknock.ErrMalformedReply)
	}
	defer cryptoutil.Wipe(cookie)
	reply, _, err = t.exchange(ctx, relayknock.TypeReknock, serverStaticPub, deviceStaticPriv, reknockBody, cookie)
	return reply, err
}

func validate(ctx context.Context, transport *Transport, serverStaticPub, deviceStaticPriv, body []byte) error {
	if ctx == nil || transport == nil || transport.client == nil || transport.baseURL == "" {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if x25519key.ValidatePublic(serverStaticPub) != nil || len(deviceStaticPriv) != x25519key.Size ||
		len(body) > nhpcontract.MaxApplicationBodySize {
		return ErrInvalidRequest
	}
	return nil
}

func (t *Transport) exchange(ctx context.Context, requestType int, serverStaticPub, deviceStaticPriv, body, cookie []byte) (*relayknock.Reply, uint64, error) {
	packet, counter, err := buildPacket(requestType, serverStaticPub, deviceStaticPriv, body, cookie)
	if err != nil {
		return nil, 0, err
	}
	replyPacket, err := t.post(ctx, relayknock.PubKeyFingerprint(serverStaticPub), packet)
	if err != nil {
		return nil, 0, err
	}
	reply, err := relayknock.DecryptReply(deviceStaticPriv, serverStaticPub, replyPacket)
	cryptoutil.Wipe(replyPacket)
	if err != nil {
		return nil, 0, ErrServerUnauthenticated
	}
	if reply.IsCookieChallenge() && requestType == relayknock.TypeKnock {
		return reply, counter, nil
	}
	if reply.Counter != counter || !replyTypeAllowed(requestType, reply.Type) {
		cryptoutil.Wipe(reply.Body)
		return nil, 0, fmt.Errorf("%w: reply correlation failed", relayknock.ErrMalformedReply)
	}
	return reply, counter, nil
}

func replyTypeAllowed(requestType, replyType int) bool {
	switch requestType {
	case relayknock.TypeKnock:
		return replyType == relayknock.TypeACK || replyType == relayknock.TypeCookieChallenge
	case relayknock.TypeReknock:
		return replyType == relayknock.TypeACK
	default:
		return false
	}
}

func buildPacket(headerType int, serverStaticPub, deviceStaticPriv, body, cookie []byte) ([]byte, uint64, error) {
	random, err := cryptoutil.RandomBytes(x25519key.Size + 8 + 4)
	if err != nil {
		return nil, 0, ErrTransport
	}
	defer cryptoutil.Wipe(random)
	counter := binary.BigEndian.Uint64(random[x25519key.Size : x25519key.Size+8])
	packet, err := relayknock.BuildMessage(headerType, &relayknock.KnockInputs{
		DeviceStaticPriv: deviceStaticPriv,
		ServerStaticPub:  serverStaticPub,
		EphemeralPriv:    random[:x25519key.Size],
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(random[x25519key.Size+8:]),
		Body:             body,
		Cookie:           cookie,
	})
	if err != nil || len(packet) > nhpwire.PacketBufferSize {
		return nil, 0, ErrInvalidRequest
	}
	return packet, counter, nil
}

func (t *Transport) post(ctx context.Context, serverID string, packet []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/relay/"+serverID, bytes.NewReader(packet))
	if err != nil {
		return nil, ErrTransport
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrTransport
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrTransport
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, nhpwire.PacketBufferSize+1))
	if err != nil {
		return nil, ErrTransport
	}
	if len(body) > nhpwire.PacketBufferSize {
		cryptoutil.Wipe(body)
		return nil, ErrServerUnauthenticated
	}
	return body, nil
}
