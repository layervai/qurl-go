package nativeudp_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// This file adds self-contained native-UDP conformance proofs that require no
// live two-cell substrate. Each proof drives the real exported qurl-go transport
// over loopback sockets against a responder built with relayknocktest (the
// server-role mirror of relayknock) and asserts the SDK's centralized fail-closed
// classification. They mirror the always-on fault proofs in
// native_udp_sandbox_test.go (hub_dns_failure, packet_timeout): the same helpers
// back both a strict TestSandboxNativeUDPLifecycle subtest and an always-on
// TestNativeUDPClientFaultPaths subtest, so the proof executes in ordinary CI.

// nhpResponder is how the loopback NHP responder answers one initiator datagram.
type nhpResponder int

const (
	respondCorrectly       nhpResponder = iota // authenticated reply of the correct type
	respondWrongKey                            // authenticated reply built with a different server static key
	respondOversize                            // a datagram larger than the 4096-byte NHP buffer
	respondMalformed                           // garbage bytes that cannot open as an authenticated reply
	respondWrongCounter                        // authenticated reply of the correct type that does not echo the request counter
	respondMalformedCookie                     // authenticated NHP_COK whose application body is not a cookie challenge
	respondDuplicate                           // the correct authenticated reply, written twice
	respondSilently                            // no reply at all
)

// The respondMalformed garbage-datagram sizes straddle the fixed 240-byte NHP
// header: below one header, exactly one header, and one header plus a body.
// None can open as an authenticated reply from the pinned server key.
const (
	malformedShortReplyBytes      = 100
	malformedHeaderReplyBytes     = 240
	malformedHeaderBodyReplyBytes = 400
)

// loopbackNHPServer is a loopback NHP responder. It opens the agent's initiator
// packet with the responder-role helpers and answers according to its configured
// behavior, recording how many initiator datagrams it received.
type loopbackNHPServer struct {
	t              *testing.T
	conn           *net.UDPConn
	serverPriv     []byte
	altPriv        []byte // used by respondWrongKey to sign under an unpinned key
	agentPub       []byte
	behavior       nhpResponder
	malformedBytes int // garbage-datagram size written by respondMalformed
	done           chan struct{}

	mu       sync.Mutex
	received int
	replies  int
}

func newLoopbackNHPServer(t *testing.T, serverPriv, agentPub []byte, behavior nhpResponder, malformedBytes int) *loopbackNHPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &loopbackNHPServer{
		t:              t,
		conn:           conn,
		serverPriv:     serverPriv,
		altPriv:        mustNHPPriv(t),
		agentPub:       agentPub,
		behavior:       behavior,
		malformedBytes: malformedBytes,
		done:           make(chan struct{}),
	}
	go func() {
		defer close(s.done)
		s.serve()
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
			t.Error("loopback NHP server did not stop after socket close")
		}
	})
	return s
}

func (s *loopbackNHPServer) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *loopbackNHPServer) receivedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received
}

// replyCount is how many reply datagrams the responder has finished writing. It
// is incremented only after the write returns, so a caller that observes the
// expected count knows every reply is already on the wire.
func (s *loopbackNHPServer) replyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replies
}

// awaitReplies waits until the responder has finished writing want reply
// datagrams. A client returns as soon as it reads the first copy, so a duplicate
// must be observed on the responder rather than assumed.
func (s *loopbackNHPServer) awaitReplies(want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := s.replyCount(); got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

// awaitReceived waits until the responder has counted want initiator datagrams.
// Fire-and-forget sends (NHP_OTP) return before the datagram is read, so a count
// assertion has to settle first; it deliberately does not wait past want so an
// extra datagram still fails the caller's exact-count check.
func (s *loopbackNHPServer) awaitReceived(want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := s.receivedCount(); got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *loopbackNHPServer) serve() {
	buf := make([]byte, 1<<16)
	for {
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.mu.Lock()
		s.received++
		s.mu.Unlock()

		msg, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, pkt)
		if err != nil {
			s.t.Logf("loopback server: open initiator: %v", err)
			continue
		}
		resp := s.buildResponse(msg)
		if resp == nil {
			continue
		}
		copies := 1
		if s.behavior == respondDuplicate {
			copies = 2
		}
		for range copies {
			if _, err := s.conn.WriteToUDP(resp, raddr); err != nil {
				s.t.Logf("loopback server: write reply: %v", err)
			}
			s.mu.Lock()
			s.replies++
			s.mu.Unlock()
		}
	}
}

func (s *loopbackNHPServer) buildResponse(msg *relayknock.Reply) []byte {
	switch s.behavior {
	case respondSilently:
		return nil
	case respondOversize:
		// A datagram one full NHP buffer over the 4096-byte ceiling; the client
		// reads PacketBufferSize+1 bytes and rejects it before any decrypt.
		return mustNHPRand(s.t, 5000)
	case respondMalformed:
		// Random bytes of the configured size: a received datagram that cannot
		// open as an authenticated reply from the pinned key at all.
		return mustNHPRand(s.t, s.malformedBytes)
	case respondWrongKey:
		return s.buildReply(nhpReplyTypeFor(msg.Type), s.altPriv, msg.Counter)
	case respondWrongCounter:
		// A fully authenticated envelope of the right reply type whose counter
		// does not echo the request: correlation, not authentication, must reject it.
		return s.buildReply(nhpReplyTypeFor(msg.Type), s.serverPriv, msg.Counter+1)
	case respondMalformedCookie:
		// An authenticated flag-zero NHP_COK whose application body is not a
		// cookie challenge at all. Only the Hub assignment profile accepts a COK
		// for an LST, so this exercises the authenticated-body parse boundary.
		return s.buildReply(relayknock.TypeCookieChallenge, s.serverPriv, msg.Counter)
	default:
		return s.buildReply(nhpReplyTypeFor(msg.Type), s.serverPriv, msg.Counter)
	}
}

// buildReply builds a server-originated reply of replyType signed by serverPriv,
// echoing counter. Roles are swapped relative to an initiator packet:
// DeviceStaticPriv is the server static private key and ServerStaticPub is the
// agent static public key.
func (s *loopbackNHPServer) buildReply(replyType int, serverPriv []byte, counter uint64) []byte {
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustNHPRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(mustNHPRand(s.t, 4)),
		Body:             []byte(`{"ok":true}`),
	})
	if err != nil {
		s.t.Errorf("build reply: %v", err)
		return nil
	}
	return packet
}

func nhpReplyTypeFor(initiatorType int) int {
	switch initiatorType {
	case relayknock.TypeListRequest:
		return relayknock.TypeListResult
	case relayknock.TypeRegister:
		return relayknock.TypeRegisterAck
	default:
		return relayknock.TypeACK
	}
}

// loopbackNHPResolver returns a globally routable address so the transport's
// non-public-address rejection stays active; loopbackNHPDialer maps that
// synthetic destination to the local responder on 127.0.0.1. Exactly-once
// delivery is proven by the responder's received-datagram count rather than
// dialer bookkeeping.
type loopbackNHPResolver struct{}

func (loopbackNHPResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type loopbackNHPDialer struct{ port int }

func (d loopbackNHPDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)))
}

// newLoopbackNHPExchange wires a fresh loopback responder with the given behavior
// to a pinned endpoint and matching transport options. The endpoint's
// ServerStaticPub is the responder's correct public key and the options carry the
// agent device key, so only a deliberately-wrong reply key (respondWrongKey) or an
// oversize datagram (respondOversize) can break authentication.
//
// malformedReplyBytes optionally overrides the respondMalformed garbage-datagram
// size; every other behavior ignores it.
func newLoopbackNHPExchange(t *testing.T, behavior nhpResponder, malformedReplyBytes ...int) (*loopbackNHPServer, nativeudp.Endpoint, nativeudp.Options) {
	t.Helper()
	malformedBytes := malformedHeaderReplyBytes
	switch len(malformedReplyBytes) {
	case 0:
	case 1:
		malformedBytes = malformedReplyBytes[0]
	default:
		t.Fatalf("newLoopbackNHPExchange accepts at most one malformed reply size, got %d", len(malformedReplyBytes))
	}
	serverPriv, serverPub := mustNHPKeypair(t)
	devicePriv := mustNHPPriv(t)
	srv := newLoopbackNHPServer(t, serverPriv, nhpPubOf(t, devicePriv), behavior, malformedBytes)
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: srv.port(), ServerStaticPub: serverPub}
	opts := nativeudp.Options{
		DeviceStaticPriv: devicePriv,
		Resolver:         loopbackNHPResolver{},
		Dialer:           loopbackNHPDialer{port: srv.port()},
		Timeout:          2 * time.Second,
		MaxAddresses:     1,
	}
	return srv, ep, opts
}

// nhpExchange fixes one exported transport round-trip for a named lifecycle phase.
type nhpExchange struct {
	name string
	call func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) (*relayknock.Reply, error)
	// singleReplyCompletes reports whether one authenticated, in-profile reply
	// completes the exchange. Every assigned-cell transaction does. The Hub
	// assignment LST deliberately does not: it is a two-leg return-routability
	// profile whose first flight accepts only NHP_COK, so a direct NHP_LRT before
	// source proof is terminal by design.
	singleReplyCompletes bool
}

func hubAndCellExchanges() []nhpExchange {
	return []nhpExchange{
		{name: "hub_assignment_lst", call: nativeudp.AssignmentList},
		{name: "assigned_cell_knock", call: nativeudp.Knock, singleReplyCompletes: true},
		{name: "assigned_cell_register", call: nativeudp.Register, singleReplyCompletes: true},
		{name: "assigned_cell_exit", call: nativeudp.Exit, singleReplyCompletes: true},
	}
}

// proveWrongHubKey proves the SDK rejects a Hub assignment reply that cannot
// authenticate to the configured Hub public key: it is a definitive
// ErrServerUnauthenticated rejection, never a retried transport miss, never a
// malformed-reply correlation error, and it triggers no HTTP.
func proveWrongHubKey(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	server, ep, opts := newLoopbackNHPExchange(t, respondWrongKey)
	reply, err := nativeudp.AssignmentList(ctx, ep, nil, opts)
	assertUnauthenticatedRejection(t, "wrong_hub_key", reply, err, server.receivedCount())
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE wrong_hub_key rejection=ErrServerUnauthenticated received_datagrams=1 fallback=0 lifecycle_http_calls=0")
}

// proveWrongCellKey proves the same fail-closed authentication class for an
// assigned-cell KNK reply signed under the wrong cell public key.
func proveWrongCellKey(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	server, ep, opts := newLoopbackNHPExchange(t, respondWrongKey)
	reply, err := nativeudp.Knock(ctx, ep, nil, opts)
	assertUnauthenticatedRejection(t, "wrong_cell_key", reply, err, server.receivedCount())
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE wrong_cell_key rejection=ErrServerUnauthenticated received_datagrams=1 fallback=0 lifecycle_http_calls=0")
}

// provePacketOversize proves the 4096-byte NHP packet boundary fails closed on
// both the receive and the send path, across every exported Hub and assigned-cell
// exchange. An over-limit reply is a definitive ErrServerUnauthenticated
// rejection; an over-limit request is rejected as ErrInvalidRequest before any
// datagram leaves the client.
func provePacketOversize(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPExchange(t, respondOversize)
		reply, err := exchange.call(ctx, ep, nil, opts)
		assertUnauthenticatedRejection(t, "oversize_reply/"+exchange.name, reply, err, server.receivedCount())
	}

	// Send side: a body past the NHP plaintext ceiling is rejected before I/O, so
	// the responder never receives a datagram.
	server, ep, opts := newLoopbackNHPExchange(t, respondCorrectly)
	oversizeBody := make([]byte, 8192)
	reply, err := nativeudp.AssignmentList(ctx, ep, oversizeBody, opts)
	if reply != nil {
		t.Fatal("oversize request returned a reply")
	}
	if !errors.Is(err, nativeudp.ErrInvalidRequest) {
		t.Fatalf("oversize request error = %v, want errors.Is ErrInvalidRequest", err)
	}
	if got := server.receivedCount(); got != 0 {
		t.Fatalf("oversize request emitted %d datagrams, want 0 (rejected before I/O)", got)
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE oversize_packet reply_boundary=ErrServerUnauthenticated request_boundary=ErrInvalidRequest request_datagrams=0 lifecycle_http_calls=0")
}

// proveCellDNSFailure proves an assigned-cell UDP exchange fails closed on DNS
// resolution failure: a typed ErrResolve with no datagram dialed, no
// cross-endpoint fallback, and no HTTP. It is the assigned-cell mirror of the
// implemented hub_dns_failure proof.
func proveCellDNSFailure(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const cellHost = "cell1.nhp.test"
	_, serverPub := mustNHPKeypair(t)
	resolver := &failureResolver{}
	dialer := &redirectingDialer{}
	ep := nativeudp.Endpoint{Host: cellHost, Port: standardNHPUDPPort, ServerStaticPub: serverPub}
	opts := nativeudp.Options{
		DeviceStaticPriv: mustNHPPriv(t),
		Resolver:         resolver,
		Dialer:           dialer,
		Timeout:          faultUDPAttemptTimeout,
		MaxAddresses:     1,
	}
	reply, err := nativeudp.Knock(ctx, ep, nil, opts)
	if reply != nil {
		t.Fatal("cell DNS failure returned a reply")
	}
	classified := errors.Is(err, nativeudp.ErrResolve) && !errors.Is(err, nativeudp.ErrTransport) &&
		!errors.Is(err, nativeudp.ErrServerUnauthenticated)
	if !classified {
		t.Fatalf("cell DNS failure classification mismatch: error_type=%T resolve=%t transport=%t unauthenticated=%t",
			err, errors.Is(err, nativeudp.ErrResolve), errors.Is(err, nativeudp.ErrTransport),
			errors.Is(err, nativeudp.ErrServerUnauthenticated))
	}
	if calls, network, host := resolver.snapshot(); calls != 1 || network != "ip" || host != cellHost {
		t.Fatalf("cell DNS lookup = calls=%d network=%q host=%q; want 1, ip, %q", calls, network, host, cellHost)
	}
	if calls, network, address := dialer.snapshot(); calls != 0 {
		t.Fatalf("cell DNS failure dialed a fallback: calls=%d network=%q address=%q", calls, network, address)
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE cell_dns_failure rejection=ErrResolve resolver_calls=1 dial_calls=0 lifecycle_http_calls=0")
}

// provePacketRemainingPhaseTimeouts generalizes the implemented Hub first-LST
// timeout across every remaining exported Hub and assigned-cell round-trip. Each
// phase drives a real connected UDP socket at a blackhole that never answers and
// must land in the same bounded taxonomy: a retryable ErrTransport that is also a
// net.Error timeout, never the definitive resolve/authentication/correlation
// classes, exactly one DNS lookup and one dial for one bounded address attempt,
// exactly one emitted datagram, and no HTTP.
func provePacketRemainingPhaseTimeouts(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const attemptTimeout = 250 * time.Millisecond
	_, serverPub := mustNHPKeypair(t)
	totalDatagrams := 0
	for _, exchange := range hubAndCellExchanges() {
		listener := startUDPBlackhole(t)
		host := strings.ReplaceAll(exchange.name, "_", "-") + ".timeout-proof.nhp.test"
		resolver := &fixedResolver{address: netip.MustParseAddr("8.8.8.8")}
		dialer := &redirectingDialer{target: listener.LocalAddr().String()}
		ep := nativeudp.Endpoint{Host: host, Port: standardNHPUDPPort, ServerStaticPub: serverPub}
		opts := nativeudp.Options{
			DeviceStaticPriv: mustNHPPriv(t),
			Resolver:         resolver,
			Dialer:           dialer,
			Timeout:          attemptTimeout,
			MaxAddresses:     1,
		}

		started := time.Now()
		reply, err := exchange.call(ctx, ep, nil, opts)
		elapsed := time.Since(started)

		var netErr net.Error
		classified := reply == nil && errors.Is(err, nativeudp.ErrTransport) &&
			!errors.Is(err, nativeudp.ErrResolve) && !errors.Is(err, nativeudp.ErrServerUnauthenticated) &&
			!errors.Is(err, relayknock.ErrMalformedReply) &&
			errors.As(err, &netErr) && netErr.Timeout() && elapsed >= attemptTimeout/2
		if !classified {
			t.Fatalf("%s timeout classification mismatch: error_type=%T reply_non_nil=%t transport=%t resolve=%t unauthenticated=%t malformed=%t net_timeout=%t elapsed_at_least_half_timeout=%t",
				exchange.name, err, reply != nil,
				errors.Is(err, nativeudp.ErrTransport), errors.Is(err, nativeudp.ErrResolve),
				errors.Is(err, nativeudp.ErrServerUnauthenticated), errors.Is(err, relayknock.ErrMalformedReply),
				errors.As(err, &netErr) && netErr.Timeout(), elapsed >= attemptTimeout/2)
		}
		if calls, network, resolved := resolver.snapshot(); calls != 1 || network != "ip" || resolved != host {
			t.Fatalf("%s timeout DNS lookup = calls=%d network=%q host=%q; want 1, ip, %q", exchange.name, calls, network, resolved, host)
		}
		wantAddress := net.JoinHostPort(resolver.address.String(), fmt.Sprint(standardNHPUDPPort))
		if calls, network, address := dialer.snapshot(); calls != 1 || network != "udp" || address != wantAddress {
			t.Fatalf("%s timeout logical dial = calls=%d network=%q address=%q; want 1, udp, %q", exchange.name, calls, network, address, wantAddress)
		}
		datagrams, _ := drainUDPBlackhole(t, listener)
		if datagrams != 1 {
			t.Fatalf("%s timeout emitted %d datagrams, want exactly 1 for one bounded address attempt", exchange.name, datagrams)
		}
		totalDatagrams += datagrams
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE remaining_phase_timeouts phases=%d rejection=ErrTransport+net.Error.Timeout resolver_calls_per_phase=1 dial_calls_per_phase=1 udp_datagrams=%d lifecycle_http_calls=0",
		len(hubAndCellExchanges()), totalDatagrams)
}

// provePacketMalformed proves every response-accepting exported phase fails
// closed on malformed reply material, and that the SDK keeps the two rejection
// classes distinct. A datagram that cannot open against the pinned key at all is
// the opaque ErrServerUnauthenticated class (never ErrMalformedReply). A fully
// authenticated envelope that does not correlate — or an authenticated Hub
// NHP_COK whose application body is not a cookie challenge — is the generic
// ErrMalformedReply class (never ErrServerUnauthenticated). Neither is ever
// recast as a retryable transport miss, and neither triggers a second datagram.
func provePacketMalformed(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	// Unauthenticated garbage at every exported Hub and assigned-cell phase.
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPExchange(t, respondMalformed)
		reply, err := exchange.call(ctx, ep, nil, opts)
		assertUnauthenticatedRejection(t, "malformed_datagram/"+exchange.name, reply, err, server.receivedCount())
	}

	// The ported garbage-size matrix: below the NHP header, exactly one header,
	// and one header plus a body all fail closed identically.
	for _, size := range []int{malformedShortReplyBytes, malformedHeaderReplyBytes, malformedHeaderBodyReplyBytes} {
		server, ep, opts := newLoopbackNHPExchange(t, respondMalformed, size)
		reply, err := nativeudp.Knock(ctx, ep, nil, opts)
		assertUnauthenticatedRejection(t, fmt.Sprintf("malformed_datagram/%d_bytes", size), reply, err, server.receivedCount())
	}

	// Authenticated envelopes that do not echo the request counter.
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPExchange(t, respondWrongCounter)
		reply, err := exchange.call(ctx, ep, nil, opts)
		assertMalformedReplyRejection(t, "authenticated_wrong_counter/"+exchange.name, reply, err, server.receivedCount())
	}

	// An authenticated Hub NHP_COK carrying a body that is not a cookie challenge.
	server, ep, opts := newLoopbackNHPExchange(t, respondMalformedCookie)
	reply, err := nativeudp.AssignmentList(ctx, ep, nil, opts)
	assertMalformedReplyRejection(t, "authenticated_malformed_cookie_body/hub_assignment_lst", reply, err, server.receivedCount())

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE malformed_packet unauthenticated_phases=%d garbage_sizes=%v authenticated_correlation_phases=%d authenticated_body_phases=1 unauthenticated_class=ErrServerUnauthenticated correlation_class=ErrMalformedReply datagrams_per_case=1 lifecycle_http_calls=0",
		len(hubAndCellExchanges()),
		[]int{malformedShortReplyBytes, malformedHeaderReplyBytes, malformedHeaderBodyReplyBytes},
		len(hubAndCellExchanges()))
}

// provePacketDuplicate proves a duplicated reply datagram cannot produce a second
// logical operation at any exported phase, and that the client itself never
// duplicates a request. The responder writes the same authenticated reply twice —
// proven delivered by its own reply count — while the client still emits exactly
// one initiator datagram and resolves the exchange exactly once. The fire-and-
// forget NHP_OTP path is included because duplicating a possibly delivered OTP is
// the one duplicate the SDK must never emit, even when DNS offers more addresses
// than the exchange may use.
func provePacketDuplicate(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPExchange(t, respondDuplicate)
		reply, err := exchange.call(ctx, ep, nil, opts)
		if exchange.singleReplyCompletes {
			if reply == nil || err != nil {
				t.Fatalf("duplicate_reply/%s = reply %v, err %v; want one completed transaction", exchange.name, reply, err)
			}
		} else if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) {
			t.Fatalf("duplicate_reply/%s = reply %v, err %v; want the terminal pre-proof ErrMalformedReply", exchange.name, reply, err)
		}
		if got := server.awaitReplies(2); got != 2 {
			t.Fatalf("duplicate_reply/%s responder wrote %d replies, want 2 (the duplicate must actually reach the client)", exchange.name, got)
		}
		if got := server.receivedCount(); got != 1 {
			t.Fatalf("duplicate_reply/%s emitted %d initiator datagrams, want exactly 1 (a duplicate reply must not re-drive the request)", exchange.name, got)
		}
	}

	// NHP_OTP: exactly one datagram, no reply wait, and no address fallback. The
	// responder is silent and the dialer maps every resolved address to it, so a
	// second address attempt would show up as a second received datagram.
	server, ep, opts := newLoopbackNHPExchange(t, respondSilently)
	opts.Resolver = fixedAddressesResolver{addresses: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
	}}
	opts.MaxAddresses = 2
	started := time.Now()
	if err := nativeudp.SendOTP(ctx, ep, []byte(`{"otp":true}`), opts); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SendOTP waited for a reply: %s", elapsed)
	}
	if got := server.awaitReceived(1); got != 1 {
		t.Fatalf("SendOTP emitted %d datagrams, want exactly 1 (no duplicate and no address fallback)", got)
	}
	if got := server.replyCount(); got != 0 {
		t.Fatalf("silent responder wrote %d replies, want 0", got)
	}

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_duplicate phases=%d replies_delivered_per_phase=2 initiator_datagrams_per_phase=1 otp_datagrams=1 otp_address_fallback=0 lifecycle_http_calls=0",
		len(hubAndCellExchanges()))
}

// proveMultiAddressBounds proves the mixed IPv4/IPv6 resolution contract through
// the exported transport: non-public answers of either family are filtered before
// any dial, a transport fault against a public IPv6 answer falls through to the
// next public IPv4 answer, MaxAddresses caps how many addresses one exchange may
// try, an answer with no public address is a definitive ErrResolve with zero
// dials, and every exchange re-resolves — a changed DNS answer is used
// immediately, so no resolved IP is carried over.
func proveMultiAddressBounds(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	nonPublic := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),   // loopback
		netip.MustParseAddr("10.1.2.3"),    // RFC 1918 private
		netip.MustParseAddr("192.0.2.1"),   // RFC 5737 TEST-NET-1
		netip.MustParseAddr("2001:db8::1"), // RFC 3849 documentation
		netip.MustParseAddr("fc00::1"),     // unique local
		netip.MustParseAddr("fe80::1"),     // link-local
	}
	publicIPv6 := netip.MustParseAddr("2606:4700:4700::1111")
	altPublicIPv6 := netip.MustParseAddr("2001:4860:4860::8888")
	publicIPv4 := netip.MustParseAddr("8.8.8.8")
	beyondCapIPv4 := netip.MustParseAddr("8.8.4.4")

	// Mixed answer: filtered non-public addresses, a failing public IPv6, a
	// working public IPv4, and one public IPv4 past the MaxAddresses cap.
	server, ep, opts := newLoopbackNHPExchange(t, respondCorrectly)
	mixed := append(append([]netip.Addr(nil), nonPublic...), publicIPv6, publicIPv4, beyondCapIPv4)
	resolver := &scriptedResolver{answers: [][]netip.Addr{mixed}}
	dialer := &addressRecordingDialer{port: ep.Port, fail: map[string]bool{
		netip.AddrPortFrom(publicIPv6, uint16(ep.Port)).String(): true,
	}}
	opts.Resolver, opts.Dialer, opts.MaxAddresses = resolver, dialer, 2
	reply, err := nativeudp.Knock(ctx, ep, nil, opts)
	if reply == nil || err != nil {
		t.Fatalf("mixed-family fallback = reply %v, err %v; want the IPv4 answer to complete the exchange", reply, err)
	}
	wantDialed := []string{
		netip.AddrPortFrom(publicIPv6, uint16(ep.Port)).String(),
		netip.AddrPortFrom(publicIPv4, uint16(ep.Port)).String(),
	}
	if got := dialer.snapshot(); !slices.Equal(got, wantDialed) {
		t.Fatalf("mixed-family dial sequence = %q, want exactly %q (non-public filtered, cap enforced)", got, wantDialed)
	}
	if calls, network, host := resolver.snapshot(); calls != 1 || network != "ip" || host != ep.Host {
		t.Fatalf("mixed-family lookup = calls=%d network=%q host=%q; want 1, ip, %q", calls, network, host, ep.Host)
	}
	if got := server.receivedCount(); got != 1 {
		t.Fatalf("mixed-family fallback delivered %d datagrams, want exactly 1 (only the surviving address)", got)
	}

	// Address-count budget: four public answers, a cap of three, every address
	// failing. The exchange stops at the cap and returns the retryable class.
	_, capEP, capOpts := newLoopbackNHPExchange(t, respondCorrectly)
	allPublic := []netip.Addr{publicIPv4, beyondCapIPv4, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	capDialer := &addressRecordingDialer{port: capEP.Port, failAll: true}
	capOpts.Resolver = &scriptedResolver{answers: [][]netip.Addr{allPublic}}
	capOpts.Dialer, capOpts.MaxAddresses = capDialer, 3
	reply, err = nativeudp.Knock(ctx, capEP, nil, capOpts)
	if reply != nil || !errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) {
		t.Fatalf("exhausted address budget = reply %v, err %v; want ErrTransport only", reply, err)
	}
	if got := len(capDialer.snapshot()); got != 3 {
		t.Fatalf("exhausted address budget dialed %d addresses, want the MaxAddresses cap of 3 out of %d answers", got, len(allPublic))
	}

	// An answer with no public address is a definitive resolve failure: no dial,
	// no datagram, and not a retryable transport miss.
	privateServer, privateEP, privateOpts := newLoopbackNHPExchange(t, respondCorrectly)
	privateDialer := &addressRecordingDialer{port: privateEP.Port}
	privateOpts.Resolver = &scriptedResolver{answers: [][]netip.Addr{nonPublic}}
	privateOpts.Dialer = privateDialer
	reply, err = nativeudp.Knock(ctx, privateEP, nil, privateOpts)
	if reply != nil || !errors.Is(err, nativeudp.ErrResolve) || errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("non-public-only answer = reply %v, err %v; want ErrResolve only", reply, err)
	}
	if got := len(privateDialer.snapshot()); got != 0 {
		t.Fatalf("non-public-only answer dialed %d addresses, want 0", got)
	}
	if got := privateServer.receivedCount(); got != 0 {
		t.Fatalf("non-public-only answer emitted %d datagrams, want 0", got)
	}

	// Re-resolution: the second exchange must use the new DNS answer, which is
	// only possible if no resolved IP was carried over from the first.
	refreshServer, refreshEP, refreshOpts := newLoopbackNHPExchange(t, respondCorrectly)
	refreshResolver := &scriptedResolver{answers: [][]netip.Addr{{altPublicIPv6}, {publicIPv4}}}
	refreshDialer := &addressRecordingDialer{port: refreshEP.Port}
	refreshOpts.Resolver, refreshOpts.Dialer, refreshOpts.MaxAddresses = refreshResolver, refreshDialer, 2
	for attempt := 1; attempt <= 2; attempt++ {
		if reply, err = nativeudp.Knock(ctx, refreshEP, nil, refreshOpts); reply == nil || err != nil {
			t.Fatalf("re-resolution exchange %d = reply %v, err %v; want success", attempt, reply, err)
		}
	}
	wantRefreshed := []string{
		netip.AddrPortFrom(altPublicIPv6, uint16(refreshEP.Port)).String(),
		netip.AddrPortFrom(publicIPv4, uint16(refreshEP.Port)).String(),
	}
	if got := refreshDialer.snapshot(); !slices.Equal(got, wantRefreshed) {
		t.Fatalf("re-resolution dial sequence = %q, want %q (the second exchange must use the new answer)", got, wantRefreshed)
	}
	if calls, _, host := refreshResolver.snapshot(); calls != 2 || host != refreshEP.Host {
		t.Fatalf("re-resolution lookups = calls=%d host=%q; want 2, %q (one per exchange)", calls, host, refreshEP.Host)
	}
	if got := refreshServer.receivedCount(); got != 2 {
		t.Fatalf("re-resolution delivered %d datagrams, want exactly 2 (one per exchange)", got)
	}

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE multi_address_bounds non_public_filtered=%d ipv6_to_ipv4_fallback=1 max_addresses_cap=3/%d resolve_only_rejection=ErrResolve resolve_only_dials=0 re_resolutions=2 persisted_addresses=0 lifecycle_http_calls=0",
		len(nonPublic), len(allPublic))
}

// provePacketCancellation proves the context boundary is honored at every
// exported Hub and assigned-cell phase. A cancellation after the datagram is in
// flight unblocks the socket read promptly and surfaces as context.Canceled —
// never recast as a retryable transport miss — with no datagram emitted after the
// boundary. A context already cancelled at the boundary performs no DNS lookup,
// no dial, and no I/O at all. The public registration driver is included so the
// same boundary is proven not to mutate durable state.
func provePacketCancellation(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const (
		attemptTimeout = 10 * time.Second
		promptUnblock  = 3 * time.Second
		// Long enough that a loaded runner has certainly emitted the datagram
		// before the boundary fires, and far short of attemptTimeout so a prompt
		// unblock stays distinguishable from the ordinary socket deadline.
		cancelAfterFirst = 250 * time.Millisecond
	)
	_, serverPub := mustNHPKeypair(t)

	// In-flight cancellation: exactly one datagram, then a prompt unblock.
	for _, exchange := range hubAndCellExchanges() {
		listener := startUDPBlackhole(t)
		opts := nativeudp.Options{
			DeviceStaticPriv: mustNHPPriv(t),
			Resolver:         &fixedResolver{address: netip.MustParseAddr("8.8.8.8")},
			Dialer:           &redirectingDialer{target: listener.LocalAddr().String()},
			Timeout:          attemptTimeout,
			MaxAddresses:     1,
		}
		ep := nativeudp.Endpoint{Host: "cancellation-proof.nhp.test", Port: standardNHPUDPPort, ServerStaticPub: serverPub}
		exchangeCtx, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(cancelAfterFirst, cancel)

		started := time.Now()
		reply, err := exchange.call(exchangeCtx, ep, nil, opts)
		elapsed := time.Since(started)
		timer.Stop()
		cancel()

		classified := reply == nil && errors.Is(err, context.Canceled) &&
			!errors.Is(err, nativeudp.ErrTransport) && !errors.Is(err, nativeudp.ErrResolve) &&
			!errors.Is(err, nativeudp.ErrServerUnauthenticated) && elapsed < promptUnblock
		if !classified {
			t.Fatalf("%s in-flight cancellation mismatch: error_type=%T reply_non_nil=%t canceled=%t transport=%t resolve=%t unauthenticated=%t elapsed=%s (want < %s of a %s attempt timeout)",
				exchange.name, err, reply != nil, errors.Is(err, context.Canceled),
				errors.Is(err, nativeudp.ErrTransport), errors.Is(err, nativeudp.ErrResolve),
				errors.Is(err, nativeudp.ErrServerUnauthenticated), elapsed, promptUnblock, attemptTimeout)
		}
		if datagrams, _ := drainUDPBlackhole(t, listener); datagrams != 1 {
			t.Fatalf("%s in-flight cancellation emitted %d datagrams, want exactly 1 and none after the boundary", exchange.name, datagrams)
		}
	}

	// Cancellation at the boundary: nothing is resolved, dialed, or emitted.
	for _, exchange := range hubAndCellExchanges() {
		listener := startUDPBlackhole(t)
		resolver := &fixedResolver{address: netip.MustParseAddr("8.8.8.8")}
		dialer := &redirectingDialer{target: listener.LocalAddr().String()}
		ep := nativeudp.Endpoint{Host: "cancellation-proof.nhp.test", Port: standardNHPUDPPort, ServerStaticPub: serverPub}
		opts := nativeudp.Options{
			DeviceStaticPriv: mustNHPPriv(t),
			Resolver:         resolver,
			Dialer:           dialer,
			Timeout:          attemptTimeout,
			MaxAddresses:     1,
		}
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()
		reply, err := exchange.call(cancelledCtx, ep, nil, opts)
		if reply != nil || !errors.Is(err, context.Canceled) || errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("%s pre-boundary cancellation = reply %v, err %v; want context.Canceled only", exchange.name, reply, err)
		}
		if calls, _, _ := resolver.snapshot(); calls != 0 {
			t.Fatalf("%s pre-boundary cancellation performed %d DNS lookups, want 0", exchange.name, calls)
		}
		if calls, _, _ := dialer.snapshot(); calls != 0 {
			t.Fatalf("%s pre-boundary cancellation dialed %d times, want 0", exchange.name, calls)
		}
		assertNoUDPDatagram(t, listener, exchange.name+" pre-boundary cancellation")
	}

	// The public registration driver must observe the same boundary and leave the
	// durable state at initial identity only: no assignment, no device credential,
	// no pending activation or completion episode.
	const agentID = "qurl-go-fault-proof-cancellation"
	store := faultStateStore(t)
	listener := startUDPBlackhole(t)
	hub := qurl.HubBootstrap{
		Host:               "cancellation-proof.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(serverPub),
	}
	registerCtx, cancelRegister := context.WithCancel(ctx)
	registerTimer := time.AfterFunc(cancelAfterFirst, cancelRegister)
	started := time.Now()
	client, binding, err := qurl.RegisterAgentRuntime(registerCtx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "packet-cancellation"),
		qurl.WithAgentRuntimeUDPResolver(&fixedResolver{address: netip.MustParseAddr("8.8.8.8")}),
		qurl.WithAgentRuntimeUDPDialer(&redirectingDialer{target: listener.LocalAddr().String()}),
		qurl.WithAgentRuntimeUDPBounds(attemptTimeout, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(1, time.Minute),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	elapsed := time.Since(started)
	registerTimer.Stop()
	cancelRegister()
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || bindingNonNil || !errors.Is(err, context.Canceled) || elapsed >= promptUnblock {
		t.Fatalf("registration cancellation mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t canceled=%t elapsed=%s (want < %s)",
			err, client != nil, bindingNonNil, errors.Is(err, context.Canceled), elapsed, promptUnblock)
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("registration cancellation reflected the enrollment credential")
	}
	if datagrams, _ := drainUDPBlackhole(t, listener); datagrams != 1 {
		t.Fatalf("registration cancellation emitted %d datagrams, want exactly 1 and none after the boundary", datagrams)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "packet_cancellation")

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_cancellation in_flight_phases=%d pre_boundary_phases=%d rejection=context.Canceled transport_recast=0 pre_boundary_dns_lookups=0 pre_boundary_dials=0 pre_boundary_datagrams=0 registration_state_mutation=0 lifecycle_http_calls=0",
		len(hubAndCellExchanges()), len(hubAndCellExchanges()))
}

// assertMalformedReplyRejection is the shared fail-closed check for an
// authenticated datagram whose envelope or application body cannot be accepted:
// exactly one datagram reached the responder, no reply is returned, the error is
// the generic relayknock.ErrMalformedReply correlation class, and it deliberately
// matches neither the opaque unauthenticated class nor the retryable
// transport/resolve classes.
func assertMalformedReplyRejection(t *testing.T, phase string, reply *relayknock.Reply, err error, received int) {
	t.Helper()
	if reply != nil {
		t.Fatalf("%s returned a reply for a malformed authenticated datagram", phase)
	}
	if !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("%s error = %v, want errors.Is relayknock.ErrMalformedReply", phase, err)
	}
	if errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Fatalf("%s conflated an authenticated correlation failure with the unauthenticated class: %v", phase, err)
	}
	if errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) {
		t.Fatalf("%s recast a definitive rejection as a retryable transport miss: %v", phase, err)
	}
	if received != 1 {
		t.Fatalf("%s responder received %d datagrams, want exactly 1 (no fallback or retry)", phase, received)
	}
}

// assertNoUDPDatagram proves nothing reached listener within a short settling
// window: the boundary under proof must be observed before any socket I/O.
func assertNoUDPDatagram(t *testing.T, listener *net.UDPConn, phase string) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set %s no-datagram deadline: %v", phase, err)
	}
	buffer := make([]byte, 2048)
	n, _, err := listener.ReadFromUDP(buffer)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}
	t.Fatalf("%s emitted a datagram it must not have: bytes=%d err=%v", phase, n, err)
}

// fixedAddressesResolver answers every lookup with the same address list. It is
// the multi-address companion to fixedResolver, which answers with exactly one.
type fixedAddressesResolver struct{ addresses []netip.Addr }

func (r fixedAddressesResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return slices.Clone(r.addresses), nil
}

// scriptedResolver answers each successive lookup with the next scripted answer
// and repeats the last one, so a re-resolution is directly observable: only a
// client that re-resolves can ever see the second answer.
type scriptedResolver struct {
	answers [][]netip.Addr

	mu    sync.Mutex
	calls int
	net   string
	host  string
}

func (r *scriptedResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	answer := r.answers[min(r.calls, len(r.answers)-1)]
	r.calls++
	r.net, r.host = network, host
	return slices.Clone(answer), nil
}

func (r *scriptedResolver) snapshot() (int, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.net, r.host
}

// addressRecordingDialer records every address an exchange dials in order. It
// returns a synthetic transport fault for the addresses in fail (or for all of
// them when failAll is set) and otherwise maps the synthetic public destination
// to the loopback responder on 127.0.0.1.
type addressRecordingDialer struct {
	port    int
	fail    map[string]bool
	failAll bool

	mu     sync.Mutex
	dialed []string
}

func (d *addressRecordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	refuse := d.failAll || d.fail[address]
	d.mu.Unlock()
	if refuse {
		return nil, fmt.Errorf("synthetic transport fault dialing %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)))
}

func (d *addressRecordingDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

// assertUnauthenticatedRejection is the shared fail-closed check for a received
// datagram that must be rejected as unauthenticated: exactly one datagram
// reached the responder (no address fallback or retry), no reply is returned, the
// error is ErrServerUnauthenticated, and it deliberately does not also match the
// malformed-reply correlation class or the retryable transport/resolve classes.
func assertUnauthenticatedRejection(t *testing.T, phase string, reply *relayknock.Reply, err error, received int) {
	t.Helper()
	if reply != nil {
		t.Fatalf("%s returned a reply for an unauthenticated datagram", phase)
	}
	if !errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Fatalf("%s error = %v, want errors.Is ErrServerUnauthenticated", phase, err)
	}
	if errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("%s exposed ErrMalformedReply instead of the opaque ErrServerUnauthenticated class: %v", phase, err)
	}
	if errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) {
		t.Fatalf("%s recast a definitive rejection as a retryable transport miss: %v", phase, err)
	}
	if received != 1 {
		t.Fatalf("%s responder received %d datagrams, want exactly 1 (no fallback or retry)", phase, received)
	}
}

func mustNHPKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func mustNHPPriv(t *testing.T) []byte {
	t.Helper()
	priv, _ := mustNHPKeypair(t)
	return priv
}

func nhpPubOf(t *testing.T, priv []byte) []byte {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("import x25519 priv: %v", err)
	}
	return key.PublicKey().Bytes()
}

func mustNHPRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return b
}
