package nativeudp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// Tunable defaults. All are overridable per call through Options.
const (
	// DefaultTimeout bounds one send+receive attempt against a single resolved
	// address via the socket deadline. It is a per-attempt socket bound, not a
	// retry budget; the assignment-refresh retry budget lives in the qurl package.
	DefaultTimeout = 3 * time.Second

	// DefaultMaxAddresses caps how many resolved addresses one exchange tries on
	// transport failure before giving up. It bounds the fan-out over a
	// multi-address DNS name without turning a dead endpoint into an unbounded
	// loop.
	DefaultMaxAddresses = 3
)

// Typed transport errors. They follow the qurl-go sentinel convention: match a
// broad outcome with errors.Is against the sentinel. Reply-correlation failures
// deliberately reuse relayknock.ErrMalformedReply so a consumer catches the whole
// malformed-reply class (relay and native UDP alike) with one errors.Is.
var (
	// ErrInvalidEndpoint marks an endpoint that is unusable before any DNS lookup
	// or socket creation: a blank host, an out-of-range port, or a server public
	// key that is not a valid 32-byte X25519 key.
	ErrInvalidEndpoint = errors.New("nativeudp: invalid endpoint")

	// ErrInvalidRequest marks a request that is unusable before any I/O: a
	// non-round-trip header type, a device static private key that is not 32
	// bytes, or an application body larger than the NHP plaintext ceiling.
	ErrInvalidRequest = errors.New("nativeudp: invalid request")

	// ErrResolve marks a failure to resolve the endpoint host to any IP address.
	// The host is treated as opaque LayerV-owned DNS data; a resolved IP is never
	// persisted, so every exchange re-resolves.
	ErrResolve = errors.New("nativeudp: endpoint DNS resolution failed")

	// ErrTransport marks a runtime exchange failure that is safe to re-drive with
	// fresh randomness under a bounded retry policy: unavailable entropy while
	// constructing the packet, dial/write/read failure, or a socket deadline with
	// no reply. A retried exchange re-resolves the host first.
	ErrTransport = errors.New("nativeudp: udp exchange failed")

	// ErrServerUnauthenticated marks a datagram that was received but is not an
	// authenticated reply from the pinned server public key: a wrong server key,
	// a failed handshake authentication, a malformed/oversize datagram, or a
	// non-reply header type. Source-address or DNS agreement never overrides this.
	// It is NOT retried against other addresses — a received-but-unauthenticated
	// datagram is a definitive rejection, not a transport miss. A bounded outer
	// lifecycle may refresh assignment/DNS and start a wholly new exchange with
	// fresh message randomness; it must not reinterpret the rejected datagram as
	// authenticated or fall through within this exchange. The underlying decrypt
	// cause is intentionally opaque (not unwrapped) so callers cannot bypass this
	// single fail-closed authentication class.
	ErrServerUnauthenticated = errors.New("nativeudp: reply failed server authentication")
)

// Resolver resolves an endpoint host to IP addresses. *net.Resolver satisfies it,
// so net.DefaultResolver is the production default; tests inject a deterministic
// resolver (for example one that returns a loopback address, an unreachable
// address first, or an empty set).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer dials a connected UDP socket. *net.Dialer satisfies it, so an empty
// &net.Dialer{} is the production default; tests inject a dialer to drive a
// loopback UDP server or to force dial failures.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Endpoint is a validated native NHP UDP endpoint supplied by trusted bootstrap
// configuration or an authenticated cell assignment. Host is opaque LayerV-owned
// DNS data resolved on every exchange; ServerStaticPub is the raw 32-byte X25519
// NHP server public key the reply is authenticated against. The caller must not
// mutate ServerStaticPub while an Exchange using this Endpoint is in progress.
type Endpoint struct {
	Host            string
	Port            int
	ServerStaticPub []byte
}

// Options carries the per-exchange knobs. The zero value is invalid because
// DeviceStaticPriv is required; Resolver, Dialer, Timeout, and MaxAddresses all
// fall back to production defaults when unset.
type Options struct {
	// DeviceStaticPriv is the agent's persisted X25519 static private key (32
	// bytes) — the Noise initiator identity the assigned server matches. Required.
	// The caller must not mutate it until Exchange returns.
	DeviceStaticPriv []byte

	// Resolver resolves Endpoint.Host. nil ⇒ net.DefaultResolver.
	Resolver Resolver

	// Dialer dials the UDP socket. nil ⇒ &net.Dialer{}.
	Dialer Dialer

	// Timeout bounds one attempt against a single address. <=0 ⇒ DefaultTimeout.
	Timeout time.Duration

	// MaxAddresses caps addresses tried per exchange. <=0 ⇒ DefaultMaxAddresses.
	// Without a caller context deadline, the worst-case silent-endpoint latency
	// is MaxAddresses × Timeout because address fallback is intentionally serial.
	MaxAddresses int
}

// Knock sends an NHP_KNK to the assigned endpoint over native UDP and returns the
// authenticated reply. See Exchange for the full contract.
func Knock(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	return Exchange(ctx, ep, relayknock.TypeKnock, body, opts)
}

// KnockWithReknock performs the native registered-agent admission sequence. A
// direct NHP_ACK completes the initial KNK. An authenticated NHP_COK is strictly
// decoded and correlated through body.trxId to the KNK request counter, then its
// exact decoded 32-byte cookie is mixed into a fresh NHP_RKN whose only accepted
// reply is an echoed-counter NHP_ACK. COK's outer wire counter is deliberately
// unconstrained; no other transition permits COK.
//
// knockBody and reknockBody are already-serialized application bodies. The
// transport does not rewrite headerType inside those authenticated bodies; the
// qurl registered-agent layer constructs the immutable identity/resource/RunID
// pair with outer types KNK and RKN respectively.
func KnockWithReknock(ctx context.Context, ep Endpoint, knockBody, reknockBody []byte, opts Options) (*relayknock.Reply, error) {
	reply, knockCounter, err := exchange(ctx, ep, relayknock.TypeKnock, knockBody, nil, opts)
	if err != nil {
		return nil, err
	}
	if !reply.IsCookieChallenge() {
		return reply, nil
	}
	cookie, err := parseCookieChallenge(reply.Body, knockCounter)
	cryptoutil.Wipe(reply.Body)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Wipe(cookie)
	reply, _, err = exchange(ctx, ep, relayknock.TypeReknock, reknockBody, cookie, opts)
	return reply, err
}

// List sends an NHP_LST to the configured endpoint over native UDP and returns
// the authenticated NHP_LRT. NHP_LST never accepts NHP_COK; a handler-budget or
// pre-handler overload miss is observed as a timeout and belongs to the caller's
// bounded transaction retry.
func List(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	return Exchange(ctx, ep, relayknock.TypeListRequest, body, opts)
}

// Register sends an NHP_REG to the assigned endpoint over native UDP and returns
// the authenticated reply. See Exchange for the full contract.
func Register(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	return Exchange(ctx, ep, relayknock.TypeRegister, body, opts)
}

// Exit sends one NHP_EXT clean-exit transaction to the assigned endpoint. It
// accepts only an authenticated NHP_ACK whose counter echoes EXT; NHP_COK is not
// valid for this transition.
func Exit(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	reply, _, err := exchange(ctx, ep, relayknock.TypeExit, body, nil, opts)
	return reply, err
}

// SendOTP sends exactly one fire-and-forget NHP_OTP datagram to the first
// public address returned for ep.Host. NHP_OTP has no application reply, so a
// successful UDP write proves only local dispatch, not server receipt or email
// delivery. The function deliberately does not fall through to another DNS
// address or retry the packet: duplicating a possibly delivered OTP request can
// invalidate the first emailed code. A caller that wants another attempt must
// start a new enrollment transaction and obtain a fresh assignment ticket.
func SendOTP(ctx context.Context, ep Endpoint, body []byte, opts Options) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if err := validateEndpoint(ep); err != nil {
		return err
	}
	if len(opts.DeviceStaticPriv) != x25519key.Size {
		return fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidRequest, x25519key.Size)
	}
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return fmt.Errorf("%w: application body of %d bytes exceeds the %d-byte NHP maximum", ErrInvalidRequest, len(body), nhpcontract.MaxApplicationBodySize)
	}

	packet, _, err := buildPacket(relayknock.TypeOTP, ep.ServerStaticPub, opts.DeviceStaticPriv, body, nil)
	if err != nil {
		return err
	}
	if len(packet) > nhpwire.PacketBufferSize {
		return fmt.Errorf("%w: packet of %d bytes exceeds the %d-byte NHP buffer", ErrInvalidRequest, len(packet), nhpwire.PacketBufferSize)
	}
	addrs, err := resolveAddresses(ctx, ep.Host, opts)
	if err != nil {
		return err
	}
	// resolveAddresses returns ErrResolve rather than an empty successful slice.
	// OTP intentionally uses exactly that first public address and never fans out.
	return sendDatagram(ctx, addrs[0], ep.Port, packet, opts)
}

// Exchange performs one native-UDP NHP request/reply round trip: it builds a
// packet of the given round-trip initiator header type (relayknock.TypeKnock,
// relayknock.TypeListRequest, or relayknock.TypeRegister) for body with fresh
// per-message randomness, resolves the endpoint host, sends the datagram to the
// assigned host/port, and decrypts and authenticates the reply against
// ep.ServerStaticPub.
//
// The reply is accepted only when the NHP handshake authenticates the pinned
// server public key. On top of that authentication Exchange enforces the native
// profile's type/correlation contract — the header's type and counter ride
// outside the AEAD, so every authenticated reply must carry a type the request
// can elicit, and every completed transaction reply must additionally echo this
// request's counter:
//
//   - NHP_LST accepts exactly NHP_LRT and NHP_REG accepts exactly NHP_RAK.
//     Neither request uses NHP_COK in the native profile.
//   - NHP_KNK accepts NHP_ACK or NHP_COK. An authenticated NHP_COK is the
//     retry-later overload signal and is returned before the ordinary counter
//     gate because it is not a completed transaction; its request and reply
//     counters are intentionally unconstrained relative to one another.
//   - Any transaction reply whose counter does not echo the request, or any
//     reply whose type is not a valid answer, fails closed with
//     relayknock.ErrMalformedReply.
//   - A datagram that does not open as an authenticated reply from the pinned key
//     (wrong key, failed authentication, malformed/oversize body, non-reply type)
//     fails closed with ErrServerUnauthenticated and is NOT retried against other
//     addresses.
//
// Transport faults (dial/write/read/timeout) against a resolved address fall
// through to the next address up to opts.MaxAddresses; if none yields a datagram,
// Exchange returns ErrTransport. DNS is resolved fresh here on every call and a
// resolved IP is never persisted. A caller may later start a bounded wholly new
// exchange after refreshing assignment/DNS; that outer retry is distinct from
// address fallback and always uses fresh ephemeral key, counter, preamble, and
// timestamp. Address fallback deliberately resends the same packet: if a reply
// is lost after the server accepts the first copy and a replay defense rejects a
// later copy, this exchange remains unsuccessful and only that fresh outer
// exchange can recover. Every fallback address came from the same LayerV-owned
// assigned name and the packet is sealed to the pinned server key, so an extra
// poisoned A/AAAA record cannot decrypt it.
func Exchange(ctx context.Context, ep Endpoint, headerType int, body []byte, opts Options) (*relayknock.Reply, error) {
	reply, _, err := exchange(ctx, ep, headerType, body, nil, opts)
	return reply, err
}

func exchange(ctx context.Context, ep Endpoint, headerType int, body, cookie []byte, opts Options) (*relayknock.Reply, uint64, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, 0, err
	}
	if err := validateHeaderType(headerType, cookie); err != nil {
		return nil, 0, err
	}
	if err := validateEndpoint(ep); err != nil {
		return nil, 0, err
	}
	if len(opts.DeviceStaticPriv) != x25519key.Size {
		return nil, 0, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidRequest, x25519key.Size)
	}
	// Explicit pre-I/O packet-size bound: the aggregate encoded body must fit the
	// NHP plaintext ceiling. BuildMessage re-checks the sealed size, but bounding
	// here keeps the size contract explicit before any socket work.
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return nil, 0, fmt.Errorf("%w: application body of %d bytes exceeds the %d-byte NHP maximum", ErrInvalidRequest, len(body), nhpcontract.MaxApplicationBodySize)
	}

	packet, counter, err := buildPacket(headerType, ep.ServerStaticPub, opts.DeviceStaticPriv, body, cookie)
	if err != nil {
		return nil, 0, err
	}
	// The built packet must fit the fixed receive buffer of the reference server.
	if len(packet) > nhpwire.PacketBufferSize {
		return nil, 0, fmt.Errorf("%w: packet of %d bytes exceeds the %d-byte NHP buffer", ErrInvalidRequest, len(packet), nhpwire.PacketBufferSize)
	}

	addrs, err := resolveAddresses(ctx, ep.Host, opts)
	if err != nil {
		return nil, 0, err
	}

	reply, err := sendToAddresses(ctx, addrs, ep.Port, packet, opts)
	if err != nil {
		return nil, 0, err
	}
	opened, err := decryptAndCorrelate(opts.DeviceStaticPriv, ep.ServerStaticPub, headerType, counter, reply)
	return opened, counter, err
}

type cookieChallengeBody struct {
	transactionID uint64
	cookie        string
}

const (
	cookieRejectBodyParse = "body_parse"
	cookieRejectEncoding  = "cookie_encoding"
	cookieRejectLength    = "cookie_length"
	cookieRejectCanonical = "cookie_canonical"
	cookieRejectCounter   = "counter"
)

type cookieChallengeError struct {
	rejectClass string
	detail      string
}

func (e *cookieChallengeError) Error() string {
	return "nativeudp: malformed cookie challenge (" + e.rejectClass + "): " + e.detail
}

func (e *cookieChallengeError) Unwrap() error { return relayknock.ErrMalformedReply }

func rejectCookieChallenge(class, detail string) error {
	return &cookieChallengeError{rejectClass: class, detail: detail}
}

// parseCookieChallenge is a dedicated closed parser rather than an ordinary
// json.Unmarshal: COK is authenticated server input and the v0.6 contract
// rejects duplicate/unknown keys, nulls, trailing values, non-canonical base64,
// and transaction mismatch before RKN can be emitted.
func parseCookieChallenge(body []byte, requestCounter uint64) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, rejectCookieChallenge(cookieRejectBodyParse, "body must be one JSON object")
	}
	var parsed cookieChallengeBody
	seen := make(map[string]struct{}, 2)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, rejectCookieChallenge(cookieRejectBodyParse, "invalid object key")
		}
		key, ok := token.(string)
		if !ok {
			return nil, rejectCookieChallenge(cookieRejectBodyParse, "object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, rejectCookieChallenge(cookieRejectBodyParse, "duplicate field")
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, rejectCookieChallenge(cookieRejectBodyParse, "field has an invalid value")
		}
		switch key {
		case "trxId":
			if err := json.Unmarshal(raw, &parsed.transactionID); err != nil {
				return nil, rejectCookieChallenge(cookieRejectBodyParse, "trxId has an invalid type")
			}
		case "cookie":
			if err := json.Unmarshal(raw, &parsed.cookie); err != nil || parsed.cookie == "" {
				return nil, rejectCookieChallenge(cookieRejectBodyParse, "cookie has an invalid type")
			}
		default:
			return nil, rejectCookieChallenge(cookieRejectBodyParse, "unknown field")
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, rejectCookieChallenge(cookieRejectBodyParse, "object is incomplete")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, rejectCookieChallenge(cookieRejectBodyParse, "trailing JSON")
	}
	if len(seen) != 2 {
		return nil, rejectCookieChallenge(cookieRejectBodyParse, "missing required field")
	}
	if parsed.transactionID != requestCounter {
		return nil, rejectCookieChallenge(cookieRejectCounter, "transaction does not match the knock")
	}
	if bytes.IndexFunc([]byte(parsed.cookie), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) >= 0 {
		return nil, rejectCookieChallenge(cookieRejectEncoding, "cookie is not strict base64")
	}
	cookie, err := base64.StdEncoding.Strict().DecodeString(parsed.cookie)
	if err != nil {
		if raw, rawErr := base64.RawStdEncoding.Strict().DecodeString(parsed.cookie); rawErr == nil && len(raw) == nhpwire.CookieSize {
			cryptoutil.Wipe(raw)
			return nil, rejectCookieChallenge(cookieRejectCanonical, "cookie is not canonical padded base64")
		}
		return nil, rejectCookieChallenge(cookieRejectEncoding, "cookie is not strict base64")
	}
	if len(cookie) != nhpwire.CookieSize {
		cryptoutil.Wipe(cookie)
		return nil, rejectCookieChallenge(cookieRejectLength, "cookie has the wrong decoded length")
	}
	return cookie, nil
}

// sendToAddresses tries each resolved address in turn until one yields a datagram,
// then returns those raw reply bytes. A transport fault against one address falls
// through to the next; a received datagram is returned immediately (its
// authentication/correlation is the caller's next step). Cancellation is mapped to
// the context error rather than a transport error so a caller can distinguish it.
func sendToAddresses(ctx context.Context, addrs []netip.Addr, port int, packet []byte, opts Options) ([]byte, error) {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	portStr := strconv.Itoa(port)
	// Reuse the receive buffer across serial address fallbacks. A failed
	// attempt never exposes its bytes, and a successful attempt returns
	// immediately, so there is no aliasing across live replies. Any future
	// concurrent/pipelined fallback must instead allocate one buffer per attempt.
	replyBuffer := make([]byte, nhpwire.PacketBufferSize+1)
	var lastErr error
	for _, addr := range addrs {
		if err := ctxErr(ctx); err != nil {
			return nil, err
		}
		// net.JoinHostPort brackets IPv6 and avoids a bounds-unchecked uint16(port)
		// conversion; port is already validated to 1..65535 by validateEndpoint.
		reply, err := sendOne(ctx, dialer, net.JoinHostPort(addr.String(), portStr), packet, timeout, replyBuffer)
		if err == nil {
			return reply, nil
		}
		if cerr := ctxErr(ctx); cerr != nil {
			// A cancelled/expired context aborts the whole exchange; do not keep
			// trying addresses under a dead deadline.
			return nil, cerr
		}
		lastErr = err
	}
	if lastErr == nil {
		// resolveAddresses guarantees at least one address, so this is unreachable;
		// keep it explicit so a future change cannot silently return (nil, nil).
		lastErr = errors.New("no address produced a reply")
	}
	return nil, fmt.Errorf("%w: %w", ErrTransport, lastErr)
}

// sendOne dials one address, writes the packet, and reads a single reply datagram
// under a socket deadline. It reads into a buffer one byte larger than the NHP
// buffer so an oversize datagram is detected rather than silently truncated.
func sendOne(ctx context.Context, dialer Dialer, address string, packet []byte, timeout time.Duration, replyBuffer []byte) (reply []byte, err error) {
	conn, stopCancellation, err := dialWithDeadline(ctx, dialer, address, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	defer stopCancellation()

	n, err := conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("write to %s: %w", address, err)
	}
	if n != len(packet) {
		return nil, fmt.Errorf("write to %s: short datagram write: wrote %d of %d bytes", address, n, len(packet))
	}

	// Read one byte past the NHP buffer so an oversize datagram is detectable
	// rather than silently accepted at exactly the cap; the explicit size gate
	// lives on the receive path in decryptAndCorrelate. A returned datagram (even
	// a zero-length or oversize one) stops the address loop — it is a received
	// reply to authenticate/reject, not a transport miss to retry against another
	// address.
	n, err = conn.Read(replyBuffer)
	// Some datagram implementations return both the truncated prefix and an
	// error such as WSAEMSGSIZE. Preserve the bytes-first oversize signal so
	// the caller classifies the received datagram as unauthenticated instead
	// of treating it as a transport miss and falling through to another IP.
	if n <= nhpwire.PacketBufferSize && err != nil {
		return nil, fmt.Errorf("read from %s: %w", address, err)
	}
	return replyBuffer[:n], nil
}

func sendDatagram(ctx context.Context, addr netip.Addr, port int, packet []byte, opts Options) error {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	conn, stopCancellation, err := dialWithDeadline(ctx, dialer, address, timeout)
	if err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return cerr
		}
		return fmt.Errorf("%w: %w", ErrTransport, err)
	}
	defer func() { _ = conn.Close() }()
	defer stopCancellation()
	if cerr := ctxErr(ctx); cerr != nil {
		return cerr
	}
	n, err := conn.Write(packet)
	if err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return cerr
		}
		return fmt.Errorf("%w: write to %s: %w", ErrTransport, address, err)
	}
	if n != len(packet) {
		if cerr := ctxErr(ctx); cerr != nil {
			return cerr
		}
		return fmt.Errorf("%w: write to %s: short datagram write: wrote %d of %d bytes", ErrTransport, address, n, len(packet))
	}
	return nil
}

// dialWithDeadline centralizes the ordering required to make cancellation
// unblock connected-UDP I/O safely: install the ordinary clamped deadline
// first, then arm the context callback that can only pull it earlier.
func dialWithDeadline(ctx context.Context, dialer Dialer, address string, timeout time.Duration) (net.Conn, func() bool, error) {
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", address, err)
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("set deadline for %s: %w", address, err)
	}
	// If ctx is already done, AfterFunc immediately pulls the deadline to now;
	// the future deadline above can never race afterward and overwrite it.
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	return conn, stopCancellation, nil
}

// decryptAndCorrelate authenticates the reply against the pinned server key and
// enforces the native request→reply correlation contract. An authenticated COK
// that the request type may receive is classified first because it is an
// overload signal rather than a completed transaction. All transaction replies
// require an exact counter echo and an allowed reply type.
func decryptAndCorrelate(devicePriv, serverStaticPub []byte, requestType int, counter uint64, reply []byte) (*relayknock.Reply, error) {
	// Explicit receive-side packet-size bound: a conforming server never exceeds
	// the fixed NHP buffer, so an oversize datagram is a rejection, not something
	// to open. (DecryptReply also rejects it; gating here keeps the size contract
	// explicit and the error class stable.)
	if len(reply) > nhpwire.PacketBufferSize {
		return nil, fmt.Errorf("%w: reply of %d bytes exceeds the %d-byte NHP buffer", ErrServerUnauthenticated, len(reply), nhpwire.PacketBufferSize)
	}
	dr, err := relayknock.DecryptReply(devicePriv, serverStaticPub, reply)
	if err != nil {
		// Any datagram that does not open as an authenticated reply from the pinned
		// key is unauthenticated. The underlying relayknock error (e.g. static-key
		// mismatch, timestamp auth failure, malformed reply type, too short/long) is
		// rendered for context but deliberately not wrapped: do not change %s to
		// %w, because decrypt-stage failures must not also match ErrMalformedReply.
		return nil, fmt.Errorf("%w: %s", ErrServerUnauthenticated, err.Error())
	}
	return correlateDecryptedReply(dr, requestType, counter)
}

func correlateDecryptedReply(dr *relayknock.Reply, requestType int, counter uint64) (*relayknock.Reply, error) {
	if dr == nil {
		return nil, fmt.Errorf("%w: decrypted reply is nil", relayknock.ErrMalformedReply)
	}
	// NHP_COK is not a completed transaction. The producer and shared
	// conformance contract require a KNK cookie challenge to surface as the
	// authenticated retry-later signal before the ordinary counter-echo gate;
	// its valid request/reply counters are intentionally unconstrained. Keep the
	// request-type predicate here so LST/REG cannot acquire COK support merely
	// because DecryptReply recognizes the generic reply header.
	if dr.IsCookieChallenge() && replyTypeAllowed(requestType, dr.Type) {
		return dr, nil
	}
	if dr.Counter != counter {
		cryptoutil.Wipe(dr.Body)
		return nil, fmt.Errorf("%w: reply counter %d does not echo request counter %d", relayknock.ErrMalformedReply, dr.Counter, counter)
	}
	if !replyTypeAllowed(requestType, dr.Type) {
		cryptoutil.Wipe(dr.Body)
		return nil, fmt.Errorf("%w: reply type %d is not a valid reply to a type-%d request", relayknock.ErrMalformedReply, dr.Type, requestType)
	}
	return dr, nil
}

// replyTypeAllowed reports whether an authenticated reply's header type is one the
// given round-trip request type can legitimately elicit. It restates
// native request→reply pairing (a list is answered only with NHP_LRT, a knock
// with NHP_ACK/NHP_COK, and a registration only with NHP_RAK) so the type
// field — which rides outside the AEAD — cannot be presented as a different
// reply kind.
func replyTypeAllowed(requestType, replyType int) bool {
	switch requestType {
	case relayknock.TypeKnock:
		return replyType == relayknock.TypeACK || replyType == relayknock.TypeCookieChallenge
	case relayknock.TypeReknock, relayknock.TypeExit:
		return replyType == relayknock.TypeACK
	case relayknock.TypeListRequest:
		return replyType == relayknock.TypeListResult
	case relayknock.TypeRegister:
		return replyType == relayknock.TypeRegisterAck
	default:
		return false
	}
}

// buildPacket mints the per-message randomness (ephemeral key, counter, preamble,
// timestamp) and builds a native-UDP NHP packet of headerType for body. It returns
// the packet and the counter a round-trip caller requires the reply to echo. The
// ephemeral private key is wiped before returning; the device static private key
// belongs to the caller and is not wiped here.
func buildPacket(headerType int, serverStaticPub, devicePriv, body, cookie []byte) (packet []byte, counter uint64, err error) {
	random, err := cryptoutil.RandomBytes(x25519key.Size + 8 + 4)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: generate packet randomness: %w", ErrTransport, err)
	}
	defer cryptoutil.Wipe(random)

	ephemeralPriv := random[:x25519key.Size]
	counter = binary.BigEndian.Uint64(random[x25519key.Size : x25519key.Size+8])
	preamble := binary.BigEndian.Uint32(random[x25519key.Size+8:])

	packet, err = relayknock.BuildMessage(headerType, &relayknock.KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverStaticPub,
		EphemeralPriv:    ephemeralPriv,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         preamble,
		Body:             body,
		Cookie:           cookie,
	})
	if err != nil {
		// BuildMessage errors never quote key or body plaintext (they report only
		// sizes and the header type), so wrapping is safe.
		return nil, 0, fmt.Errorf("%w: build packet: %w", ErrInvalidRequest, err)
	}
	return packet, counter, nil
}

// resolveAddresses resolves host to at most opts.MaxAddresses IP addresses. It
// re-resolves on every exchange (a resolved IP is never persisted) so DNS/NLB
// replacement and multi-address behavior are preserved.
func resolveAddresses(ctx context.Context, host string, opts Options) ([]netip.Addr, error) {
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	maxAddrs := opts.MaxAddresses
	if maxAddrs <= 0 {
		maxAddrs = DefaultMaxAddresses
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return nil, cerr
		}
		// Do not echo the host into the error beyond naming it: it is opaque
		// control-plane data, but it is not a secret, so naming it aids operators.
		return nil, fmt.Errorf("%w: %q: %w", ErrResolve, host, err)
	}
	public := make([]netip.Addr, 0, min(len(addrs), maxAddrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !publicRoutableAddress(addr) {
			continue
		}
		public = append(public, addr)
		if len(public) == maxAddrs {
			break
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("%w: %q resolved to no public addresses", ErrResolve, host)
	}
	return public, nil
}

// netip.Addr.IsGlobalUnicast follows the protocol definition and therefore
// includes reserved space such as 200::/7 and unallocated space inside
// 2000::/3. This release-gated allowlist mirrors the IANA IPv6 Global Unicast
// Address Space allocations. Operators must update this list and ship an SDK
// release before provisioning a cell endpoint exclusively in a newly allocated
// prefix; until then resolution deliberately fails closed with ErrResolve.
var allocatedIPv6GlobalUnicastPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("2001:200::/23"),
	netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"),
	netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"),
	netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"),
	netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"),
	netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"),
	netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"),
	netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"),
	netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"),
	netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"),
	netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"),
	netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"),
	netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"),
	netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"),
	netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"),
	netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"),
	netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"),
	netip.MustParsePrefix("2c00::/12"),
}

var nonRoutablePrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122 this network
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 shared address space
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737 TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737 TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737 TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112 reserved / Class E
	netip.MustParsePrefix("100::/64"),        // RFC 6666 discard-only
	netip.MustParsePrefix("64:ff9b::/96"),    // RFC 6052 well-known NAT64 prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // RFC 8215 local-use NAT64 prefix
	// The whole IANA protocol-assignment block is ineligible for LayerV server
	// endpoints, including its more-specific anycast/protocol allocations.
	netip.MustParsePrefix("2001::/23"),     // RFC 2928 IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"), // RFC 3849 documentation
	netip.MustParsePrefix("2002::/16"),     // deprecated 6to4
	netip.MustParsePrefix("3fff::/20"),     // RFC 9637 documentation
	netip.MustParsePrefix("5f00::/16"),     // RFC 9602 segment routing SIDs
	netip.MustParsePrefix("fec0::/10"),     // RFC 3879 deprecated site-local
}

func publicRoutableAddress(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() ||
		addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is6() {
		allocated := false
		for _, prefix := range allocatedIPv6GlobalUnicastPrefixes {
			if prefix.Contains(addr) {
				allocated = true
				break
			}
		}
		if !allocated {
			return false
		}
	}
	for _, prefix := range nonRoutablePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func validateHeaderType(headerType int, cookie []byte) error {
	switch headerType {
	case relayknock.TypeKnock, relayknock.TypeListRequest, relayknock.TypeRegister, relayknock.TypeExit:
		if len(cookie) == 0 {
			return nil
		}
	case relayknock.TypeReknock:
		if len(cookie) == nhpwire.CookieSize {
			return nil
		}
	default:
		return fmt.Errorf("%w: header type %d is not a native-UDP round-trip type", ErrInvalidRequest, headerType)
	}
	return fmt.Errorf("%w: header type %d has an invalid cookie", ErrInvalidRequest, headerType)
}

func validateEndpoint(ep Endpoint) error {
	if ep.Host == "" {
		return fmt.Errorf("%w: host must not be empty", ErrInvalidEndpoint)
	}
	if ep.Port <= 0 || ep.Port > 65535 {
		return fmt.Errorf("%w: port %d out of range", ErrInvalidEndpoint, ep.Port)
	}
	if err := x25519key.ValidatePublic(ep.ServerStaticPub); err != nil {
		return fmt.Errorf("%w: unusable server public key: %w", ErrInvalidEndpoint, err)
	}
	return nil
}

// ctxErr reports a nil-or-cancelled context as a usable error so every entry point
// fails closed on a dead context before doing work.
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidRequest)
	}
	return ctx.Err()
}
