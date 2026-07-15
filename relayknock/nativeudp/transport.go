package nativeudp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"time"

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

	// ErrTransport marks a datagram exchange that never produced a reply from any
	// resolved address: dial, write, or read failure, or a socket deadline
	// (timeout) with no reply. It is the class the caller may re-drive under a
	// bounded retry policy, re-resolving the host first.
	ErrTransport = errors.New("nativeudp: udp exchange failed")

	// ErrServerUnauthenticated marks a datagram that was received but is not an
	// authenticated reply from the pinned server public key: a wrong server key,
	// a failed handshake authentication, a malformed/oversize datagram, or a
	// non-reply header type. Source-address or DNS agreement never overrides this.
	// It is NOT retried against other addresses — a received-but-unauthenticated
	// datagram is a definitive rejection, not a transport miss.
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

// Endpoint is a validated native NHP UDP endpoint taken from a qurl-service cell
// assignment. Host is opaque LayerV-owned DNS data resolved on every exchange;
// ServerStaticPub is the raw 32-byte X25519 NHP server public key the reply is
// authenticated against.
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
	DeviceStaticPriv []byte

	// Resolver resolves Endpoint.Host. nil ⇒ net.DefaultResolver.
	Resolver Resolver

	// Dialer dials the UDP socket. nil ⇒ &net.Dialer{}.
	Dialer Dialer

	// Timeout bounds one attempt against a single address. <=0 ⇒ DefaultTimeout.
	Timeout time.Duration

	// MaxAddresses caps addresses tried per exchange. <=0 ⇒ DefaultMaxAddresses.
	MaxAddresses int
}

// Knock sends an NHP_KNK to the assigned endpoint over native UDP and returns the
// authenticated reply. See Exchange for the full contract.
func Knock(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	return Exchange(ctx, ep, relayknock.TypeKnock, body, opts)
}

// Register sends an NHP_REG to the assigned endpoint over native UDP and returns
// the authenticated reply. See Exchange for the full contract.
func Register(ctx context.Context, ep Endpoint, body []byte, opts Options) (*relayknock.Reply, error) {
	return Exchange(ctx, ep, relayknock.TypeRegister, body, opts)
}

// Exchange performs one native-UDP NHP request/reply round trip: it builds a
// packet of the given round-trip initiator header type (relayknock.TypeKnock or
// relayknock.TypeRegister) for body with fresh per-message randomness, resolves
// the endpoint host, sends the datagram to the assigned host/port, and decrypts
// and authenticates the reply against ep.ServerStaticPub.
//
// The reply is accepted only when the NHP handshake authenticates the pinned
// server public key. On top of that authentication Exchange enforces the same
// correlation contract relayknock.Exchange does over HTTP — the header's type and
// counter ride outside the AEAD, so an authenticated reply must additionally echo
// this request's counter and carry a type the request can elicit:
//
//   - An NHP_COK overload cookie-challenge is returned straight to the caller
//     (Reply.IsCookieChallenge) as the retryable "server busy" signal, BEFORE the
//     counter-echo check, exactly as the relay path does.
//   - A non-cookie reply whose counter does not echo the request, or whose type
//     is not a valid answer to the request, fails closed with
//     relayknock.ErrMalformedReply.
//   - A datagram that does not open as an authenticated reply from the pinned key
//     (wrong key, failed authentication, malformed/oversize body, non-reply type)
//     fails closed with ErrServerUnauthenticated and is NOT retried against other
//     addresses.
//
// Transport faults (dial/write/read/timeout) against a resolved address fall
// through to the next address up to opts.MaxAddresses; if none yields a datagram,
// Exchange returns ErrTransport. DNS is resolved fresh here on every call and a
// resolved IP is never persisted.
func Exchange(ctx context.Context, ep Endpoint, headerType int, body []byte, opts Options) (*relayknock.Reply, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := validateHeaderType(headerType); err != nil {
		return nil, err
	}
	if err := validateEndpoint(ep); err != nil {
		return nil, err
	}
	if len(opts.DeviceStaticPriv) != nhpwire.PublicKeySize {
		return nil, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidRequest, nhpwire.PublicKeySize)
	}
	// Explicit pre-I/O packet-size bound: the aggregate encoded body must fit the
	// NHP plaintext ceiling. BuildMessage re-checks the sealed size, but bounding
	// here keeps the size contract explicit before any socket work.
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return nil, fmt.Errorf("%w: application body of %d bytes exceeds the %d-byte NHP maximum", ErrInvalidRequest, len(body), nhpcontract.MaxApplicationBodySize)
	}

	packet, counter, err := buildPacket(headerType, ep.ServerStaticPub, opts.DeviceStaticPriv, body)
	if err != nil {
		return nil, err
	}
	// The built packet must fit the fixed receive buffer of the reference server.
	if len(packet) > nhpwire.PacketBufferSize {
		return nil, fmt.Errorf("%w: packet of %d bytes exceeds the %d-byte NHP buffer", ErrInvalidRequest, len(packet), nhpwire.PacketBufferSize)
	}

	addrs, err := resolveAddresses(ctx, ep.Host, opts)
	if err != nil {
		return nil, err
	}

	reply, err := sendToAddresses(ctx, addrs, ep.Port, packet, opts)
	if err != nil {
		return nil, err
	}
	return decryptAndCorrelate(opts.DeviceStaticPriv, ep.ServerStaticPub, headerType, counter, reply)
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
	var lastErr error
	for _, addr := range addrs {
		if err := ctxErr(ctx); err != nil {
			return nil, err
		}
		// net.JoinHostPort brackets IPv6 and avoids a bounds-unchecked uint16(port)
		// conversion; port is already validated to 1..65535 by validateEndpoint.
		reply, err := sendOne(ctx, dialer, net.JoinHostPort(addr.String(), portStr), packet, timeout)
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
func sendOne(ctx context.Context, dialer Dialer, address string, packet []byte, timeout time.Duration) (reply []byte, err error) {
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	defer func() { _ = conn.Close() }()

	// Force an immediate deadline on cancellation so a blocked read/write unblocks
	// promptly; the caller maps the resulting error to the context error.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline for %s: %w", address, err)
	}

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
	// an oversize one) stops the address loop — it is a received reply to
	// authenticate/reject, not a transport miss to retry against another address.
	buf := make([]byte, nhpwire.PacketBufferSize+1)
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", address, err)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// decryptAndCorrelate authenticates the reply against the pinned server key and
// enforces the request→reply correlation contract. It mirrors relayknock.Exchange:
// cookie-challenge first (returned as a retryable overload), then counter echo,
// then reply-type pairing.
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
		// wrapped for context but never carries key or body plaintext.
		return nil, fmt.Errorf("%w: %s", ErrServerUnauthenticated, err.Error())
	}

	// Overload cookie-challenge first, before the counter-echo check — an NHP_COK
	// is a valid retryable reply to both a knock and a register, and the reference
	// server only stamps it with the request counter as a routing concession, so
	// gating it behind the echo check could misclassify a retryable "busy" as a
	// hard failure.
	if dr.IsCookieChallenge() && replyTypeAllowed(requestType, dr.Type) {
		return dr, nil
	}

	if dr.Counter != counter {
		return nil, fmt.Errorf("%w: reply counter %d does not echo request counter %d", relayknock.ErrMalformedReply, dr.Counter, counter)
	}
	if !replyTypeAllowed(requestType, dr.Type) {
		return nil, fmt.Errorf("%w: reply type %d is not a valid reply to a type-%d request", relayknock.ErrMalformedReply, dr.Type, requestType)
	}
	return dr, nil
}

// replyTypeAllowed reports whether an authenticated reply's header type is one the
// given round-trip request type can legitimately elicit. It restates
// relayknock's unexported request→reply pairing (a knock is answered with
// NHP_ACK, a registration with NHP_RAK, and either can be cookie-challenged with
// NHP_COK) so the type field — which rides outside the AEAD — cannot be presented
// as a different reply kind.
func replyTypeAllowed(requestType, replyType int) bool {
	switch requestType {
	case relayknock.TypeKnock:
		return replyType == relayknock.TypeACK || replyType == relayknock.TypeCookieChallenge
	case relayknock.TypeRegister:
		return replyType == relayknock.TypeRegisterAck || replyType == relayknock.TypeCookieChallenge
	default:
		return false
	}
}

// buildPacket mints the per-message randomness (ephemeral key, counter, preamble,
// timestamp) and builds a native-UDP NHP packet of headerType for body. It returns
// the packet and the counter a round-trip caller requires the reply to echo. The
// ephemeral private key is wiped before returning; the device static private key
// belongs to the caller and is not wiped here.
func buildPacket(headerType int, serverStaticPub, devicePriv, body []byte) (packet []byte, counter uint64, err error) {
	ephemeralPriv, err := randBytes(nhpwire.PublicKeySize)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: ephemeral key: %w", ErrInvalidRequest, err)
	}
	defer wipeBytes(ephemeralPriv)

	counter, err = randUint64()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: counter: %w", ErrInvalidRequest, err)
	}
	preamble, err := randUint32()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: preamble: %w", ErrInvalidRequest, err)
	}

	packet, err = relayknock.BuildMessage(headerType, &relayknock.KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverStaticPub,
		EphemeralPriv:    ephemeralPriv,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         preamble,
		Body:             body,
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
		if !publicAssignmentAddress(addr) {
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

func publicAssignmentAddress(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() &&
		!addr.IsLoopback() && !addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func validateHeaderType(headerType int) error {
	switch headerType {
	case relayknock.TypeKnock, relayknock.TypeRegister:
		return nil
	default:
		return fmt.Errorf("%w: header type %d is not a native-UDP round-trip type (want TypeKnock or TypeRegister)", ErrInvalidRequest, headerType)
	}
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

// wipeBytes zeroes a sensitive buffer. runtime.KeepAlive prevents the clear from
// being optimized away as dead before the bytes become unreachable.
func wipeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}
