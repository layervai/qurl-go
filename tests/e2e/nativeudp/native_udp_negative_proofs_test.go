package nativeudp_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	respondUnknownMessage                      // authenticated reply with an unknown NHP header type
	respondPhaseInvalid                        // authenticated known reply that is invalid for the request phase
)

// The respondMalformed garbage-datagram sizes straddle the fixed 240-byte NHP
// header: below one header, exactly one header, and one header plus a body.
// None can open as an authenticated reply from the pinned server key.
const (
	malformedShortReplyBytes      = 100
	malformedHeaderReplyBytes     = 240
	malformedHeaderBodyReplyBytes = 400
	unknownReplyHeaderType        = 0x7ffe
)

// loopbackFaultConfig carries the wire-fault knobs the loss, delay, and replay
// proofs layer on top of an otherwise correct responder. They are deliberately
// orthogonal to nhpResponder: each one models something that happens to a
// well-formed authenticated reply in transit rather than a differently-built
// reply.
type loopbackFaultConfig struct {
	// dropReplies withholds the reply to the first N received flights. The
	// request itself is still received and counted, so a dropped flight is
	// observable as a request the client sent and got no answer to.
	dropReplies int

	// replyDelay sleeps before writing each reply, modelling a slow path. A
	// delay past the attempt timeout makes the reply arrive after the client
	// has already given up on that address.
	replyDelay time.Duration

	// replayFirstReply answers every flight after the first with the exact
	// captured bytes of the first authenticated reply, modelling an on-path
	// replay of genuinely server-signed material.
	replayFirstReply bool

	// reflectRequest writes the agent's own initiator datagram straight back at
	// it, modelling the reflection replay an on-path attacker can mount without
	// holding any key at all.
	reflectRequest bool

	// staleReplyFirst writes one authenticated reply with a non-echoing counter
	// immediately before the correct reply. The client reads exactly one
	// datagram, so accepting the later reply would require incorrectly skipping
	// the stale first packet.
	staleReplyFirst bool

	// replyBody replaces the default {"ok":true} body for the one identity
	// binding proof that drives the public registered-agent admission parser.
	replyBody []byte
}

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
	fault          loopbackFaultConfig
	done           chan struct{}

	mu         sync.Mutex
	received   int
	replies    int
	packets    [][]byte // every initiator datagram, in arrival order
	firstReply []byte   // captured by replayFirstReply
}

// newLoopbackNHPServer builds and starts a responder. Every knob is supplied
// here rather than assigned afterwards: the serve goroutine starts before this
// returns, so a post-construction field write would race it.
func newLoopbackNHPServer(t *testing.T, serverPriv, agentPub []byte, behavior nhpResponder, malformedBytes int, fault loopbackFaultConfig) *loopbackNHPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	fault.replyBody = bytes.Clone(fault.replyBody)
	s := &loopbackNHPServer{
		t:              t,
		conn:           conn,
		serverPriv:     serverPriv,
		altPriv:        mustNHPPriv(t),
		agentPub:       agentPub,
		behavior:       behavior,
		malformedBytes: malformedBytes,
		fault:          fault,
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

// receivedPackets returns a copy of every initiator datagram in arrival order.
// Byte identity across entries is how the loss proof distinguishes an in-exchange
// address fallback — which deliberately resends the same packet — from a wholly
// fresh outer retry, which must mint new randomness.
func (s *loopbackNHPServer) receivedPackets() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	packets := make([][]byte, len(s.packets))
	for i := range s.packets {
		packets[i] = bytes.Clone(s.packets[i])
	}
	return packets
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
		flight := s.received
		s.packets = append(s.packets, pkt)
		s.mu.Unlock()

		// packet.replay: a reflection replay needs no key, so it is applied before
		// the responder even tries to open the datagram.
		if s.fault.reflectRequest {
			if _, err := s.conn.WriteToUDP(pkt, raddr); err != nil {
				s.t.Logf("loopback server: reflect request: %v", err)
			}
			s.mu.Lock()
			s.replies++
			s.mu.Unlock()
			continue
		}

		msg, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, pkt)
		if err != nil {
			s.t.Logf("loopback server: open initiator: %v", err)
			continue
		}
		resp := s.buildResponse(msg)
		if resp == nil {
			continue
		}
		// packet.loss: the request was received but its reply never leaves.
		if flight <= s.fault.dropReplies {
			continue
		}
		// packet.replay: capture the first authenticated reply, then answer every
		// later flight with those exact bytes.
		if s.fault.replayFirstReply {
			s.mu.Lock()
			if s.firstReply == nil {
				s.firstReply = bytes.Clone(resp)
			} else {
				resp = bytes.Clone(s.firstReply)
			}
			s.mu.Unlock()
		}
		// packet.delay: the reply is well-formed but late.
		if s.fault.replyDelay > 0 {
			time.Sleep(s.fault.replyDelay)
		}
		if s.fault.staleReplyFirst {
			stale := s.buildReply(nhpReplyTypeFor(msg.Type), s.serverPriv, msg.Counter+1)
			if _, err := s.conn.WriteToUDP(stale, raddr); err != nil {
				s.t.Logf("loopback server: write stale reply: %v", err)
			}
			s.mu.Lock()
			s.replies++
			s.mu.Unlock()
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
	case respondUnknownMessage:
		return s.buildUnknownReply(msg.Counter)
	case respondPhaseInvalid:
		return s.buildReply(nhpPhaseInvalidReplyTypeFor(msg.Type), s.serverPriv, msg.Counter)
	default:
		return s.buildReply(nhpReplyTypeFor(msg.Type), s.serverPriv, msg.Counter)
	}
}

// buildReply builds a server-originated reply of replyType signed by serverPriv,
// echoing counter. Roles are swapped relative to an initiator packet:
// DeviceStaticPriv is the server static private key and ServerStaticPub is the
// agent static public key.
func (s *loopbackNHPServer) buildReply(replyType int, serverPriv []byte, counter uint64) []byte {
	body := s.fault.replyBody
	if len(body) == 0 {
		body = []byte(`{"ok":true}`)
	}
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustNHPRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(mustNHPRand(s.t, 4)),
		Body:             body,
	})
	if err != nil {
		s.t.Errorf("build reply: %v", err)
		return nil
	}
	return packet
}

func (s *loopbackNHPServer) buildUnknownReply(counter uint64) []byte {
	packet, err := relayknocktest.BuildUnknownReplyForTest(unknownReplyHeaderType, &relayknock.KnockInputs{
		DeviceStaticPriv: s.serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustNHPRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(mustNHPRand(s.t, 4)),
		Body:             []byte(`{"authenticated":"unknown"}`),
	})
	if err != nil {
		s.t.Errorf("build unknown reply: %v", err)
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

func nhpPhaseInvalidReplyTypeFor(initiatorType int) int {
	switch initiatorType {
	case relayknock.TypeRegister:
		return relayknock.TypeACK
	default:
		return relayknock.TypeRegisterAck
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
	return newConfiguredLoopbackNHPExchange(t, behavior, malformedBytes, loopbackFaultConfig{})
}

// newLoopbackNHPFaultExchange wires an otherwise correct responder that applies
// the given in-transit wire faults. It is the loss/delay/replay companion to
// newLoopbackNHPExchange, which varies how the reply is built rather than what
// happens to it.
func newLoopbackNHPFaultExchange(t *testing.T, fault loopbackFaultConfig) (*loopbackNHPServer, nativeudp.Endpoint, nativeudp.Options) {
	t.Helper()
	return newConfiguredLoopbackNHPExchange(t, respondCorrectly, malformedHeaderReplyBytes, fault)
}

func newConfiguredLoopbackNHPExchange(t *testing.T, behavior nhpResponder, malformedBytes int, fault loopbackFaultConfig) (*loopbackNHPServer, nativeudp.Endpoint, nativeudp.Options) {
	t.Helper()
	serverPriv, serverPub := mustNHPKeypair(t)
	devicePriv := mustNHPPriv(t)
	srv := newLoopbackNHPServer(t, serverPriv, nhpPubOf(t, devicePriv), behavior, malformedBytes, fault)
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
		{name: "assigned_cell_completion_lst", call: nativeudp.List, singleReplyCompletes: true},
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

// proveHubDNSAddressRefresh drives two complete assignment return-routability
// exchanges through the same authoritative Hub name while its scripted DNS
// answer changes. Both the first and proof LST of each exchange resolve the
// hostname; no address survives into the next exchange.
func proveHubDNSAddressRefresh(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	firstAddress := netip.MustParseAddr("8.8.8.8")
	secondAddress := netip.MustParseAddr("9.9.9.9")
	exchange := newCookieRoutabilityExchange(t, hubAssignmentRoutability, cookieRoutabilityConfig{})
	resolver := &scriptedResolver{answers: [][]netip.Addr{
		{firstAddress},
		{firstAddress},
		{secondAddress},
		{secondAddress},
	}}
	dialer := &addressRecordingDialer{port: exchange.endpoint.Port}
	exchange.options.Resolver, exchange.options.Dialer = resolver, dialer

	for attempt := 1; attempt <= 2; attempt++ {
		body := []byte(fmt.Sprintf(`{"query":"cell_assignment","request_nonce":"hub-dns-refresh-%d"}`, attempt))
		reply, err := nativeudp.AssignmentList(ctx, exchange.endpoint, body, exchange.options)
		if reply == nil || err != nil {
			t.Fatalf("Hub DNS refresh exchange %d = reply %v, err %v; want success", attempt, reply, err)
		}
	}
	wantDialed := []string{
		netip.AddrPortFrom(firstAddress, uint16(exchange.endpoint.Port)).String(),
		netip.AddrPortFrom(firstAddress, uint16(exchange.endpoint.Port)).String(),
		netip.AddrPortFrom(secondAddress, uint16(exchange.endpoint.Port)).String(),
		netip.AddrPortFrom(secondAddress, uint16(exchange.endpoint.Port)).String(),
	}
	if got := dialer.snapshot(); !slices.Equal(got, wantDialed) {
		t.Fatalf("Hub DNS refresh dial sequence = %q, want %q", got, wantDialed)
	}
	if calls, network, host := resolver.snapshot(); calls != 4 || network != "ip" || host != exchange.endpoint.Host {
		t.Fatalf("Hub DNS refresh lookups = calls=%d network=%q host=%q; want 4, ip, %q",
			calls, network, host, exchange.endpoint.Host)
	}
	first, proof, packets, _, _ := exchange.server.snapshot()
	if len(first) != 2 || len(proof) != 2 || len(packets) != 4 {
		t.Fatalf("Hub DNS refresh flights = first:%d proof:%d packets:%d; want 2/2/4", len(first), len(proof), len(packets))
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE hub_dns_address_refresh authoritative_host=%s logical_exchanges=2 resolutions=4 first_address_legs=2 second_address_legs=2 persisted_addresses=0 lifecycle_http_calls=0",
		exchange.endpoint.Host)
}

// proveCellDNSAddressRefresh is the assigned-cell mirror: two KNK exchanges
// retain the authenticated endpoint name and pinned key while independently
// resolving two successive authoritative addresses.
func proveCellDNSAddressRefresh(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	firstAddress := netip.MustParseAddr("8.8.8.8")
	secondAddress := netip.MustParseAddr("9.9.9.9")
	server, endpoint, opts := newLoopbackNHPExchange(t, respondCorrectly)
	resolver := &scriptedResolver{answers: [][]netip.Addr{{firstAddress}, {secondAddress}}}
	dialer := &addressRecordingDialer{port: endpoint.Port}
	opts.Resolver, opts.Dialer = resolver, dialer

	for attempt := 1; attempt <= 2; attempt++ {
		reply, err := nativeudp.Knock(ctx, endpoint, []byte(fmt.Sprintf(`{"attempt":%d}`, attempt)), opts)
		if reply == nil || err != nil {
			t.Fatalf("cell DNS refresh exchange %d = reply %v, err %v; want success", attempt, reply, err)
		}
	}
	wantDialed := []string{
		netip.AddrPortFrom(firstAddress, uint16(endpoint.Port)).String(),
		netip.AddrPortFrom(secondAddress, uint16(endpoint.Port)).String(),
	}
	if got := dialer.snapshot(); !slices.Equal(got, wantDialed) {
		t.Fatalf("cell DNS refresh dial sequence = %q, want %q", got, wantDialed)
	}
	if calls, network, host := resolver.snapshot(); calls != 2 || network != "ip" || host != endpoint.Host {
		t.Fatalf("cell DNS refresh lookups = calls=%d network=%q host=%q; want 2, ip, %q",
			calls, network, host, endpoint.Host)
	}
	if got := server.receivedCount(); got != 2 {
		t.Fatalf("cell DNS refresh responder received %d datagrams, want 2", got)
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE cell_dns_address_refresh authoritative_host=%s logical_exchanges=2 resolutions=2 first_address_exchanges=1 second_address_exchanges=1 persisted_addresses=0 lifecycle_http_calls=0",
		endpoint.Host)
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
		qurl.WithAgentRuntimeHeadlessEnrollment(),
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

// cookieRoutabilityProfile selects which two-leg return-routability profile the
// loopback responder speaks. Both share a shape — an ordinary first flight, an
// authenticated NHP_COK carrying a 32-byte cookie bound to the first flight's
// counter through body.trxId, then a cookie-bound second flight — but they admit
// different header types and are opened by different responder-role helpers.
type cookieRoutabilityProfile int

const (
	// hubAssignmentRoutability is NHP_LST -> NHP_COK -> cookie-bound proof
	// NHP_LST -> NHP_LRT, driven by nativeudp.AssignmentList and opened with
	// relayknocktest.OpenHubLSTCookieProofMessage.
	hubAssignmentRoutability cookieRoutabilityProfile = iota
	// cellReknockRoutability is NHP_KNK -> NHP_COK -> cookie-bound NHP_RKN ->
	// NHP_ACK, driven by nativeudp.KnockWithReknock and opened with
	// relayknocktest.OpenReknockMessage.
	cellReknockRoutability
)

func (p cookieRoutabilityProfile) String() string {
	if p == hubAssignmentRoutability {
		return "hub_assignment_lst"
	}
	return "assigned_cell_reknock"
}

// firstFlightType is the initiator header type this profile's unproven first
// flight must carry, and resultType is the reply type that completes it.
func (p cookieRoutabilityProfile) firstFlightType() int {
	if p == hubAssignmentRoutability {
		return relayknock.TypeListRequest
	}
	return relayknock.TypeKnock
}

func (p cookieRoutabilityProfile) resultType() int {
	if p == hubAssignmentRoutability {
		return relayknock.TypeListResult
	}
	return relayknock.TypeACK
}

// cookieRoutabilityServer is a loopback responder that speaks a full two-leg
// cookie return-routability profile. It dispatches on what each datagram
// actually opens as rather than on arrival index: the second flight is
// admissible only under the cookie-bound opener, so a correct dispatch is itself
// evidence that a proof packet is not an ordinary initiator message. Every
// proof flight is additionally probed with a deliberately wrong cookie, so the
// digest binding is observed to fail closed rather than assumed.
// cookieRoutabilityConfig carries every responder knob. Like the loopback
// responder's fault config it is supplied at construction, because the serve
// goroutine is already running by the time the constructor returns.
type cookieRoutabilityConfig struct {
	// resultBody is the application body of the completing reply. Empty means
	// the default {"ok":true}.
	resultBody []byte
	// directResult answers the first flight with the completing reply instead of
	// a challenge, so the no-challenge path can be driven from the same harness.
	directResult bool
	// replayFirstChallenge answers every later first flight with the exact
	// captured bytes of the first NHP_COK, modelling an on-path replay of
	// genuinely server-signed challenge material bound to a spent transaction.
	replayFirstChallenge bool
	// staleResultFirst writes a correlated-profile result carrying the wrong
	// counter immediately before the correct result on the proof/RKN leg.
	staleResultFirst bool
	// unknownResult replaces the completing proof/RKN reply with an
	// authenticated packet whose header type is unknown to NHP.
	unknownResult bool
	// phaseInvalidResult replaces the completing reply with a known server reply
	// type that is invalid for this phase.
	phaseInvalidResult bool
}

type cookieRoutabilityServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	agentPub   []byte
	cookie     []byte
	profile    cookieRoutabilityProfile
	config     cookieRoutabilityConfig
	done       chan struct{}

	mu             sync.Mutex
	firstFlights   []*relayknock.Reply
	proofFlights   []*relayknock.Reply
	packets        [][]byte
	replies        int
	firstChallenge []byte
	wrongCookieErr error
	initiatorErr   error
}

func newCookieRoutabilityServer(t *testing.T, serverPriv, agentPub []byte, profile cookieRoutabilityProfile, config cookieRoutabilityConfig) *cookieRoutabilityServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	if len(config.resultBody) == 0 {
		config.resultBody = []byte(`{"ok":true}`)
	}
	s := &cookieRoutabilityServer{
		t:          t,
		conn:       conn,
		serverPriv: serverPriv,
		agentPub:   agentPub,
		cookie:     mustNHPRand(t, 32),
		profile:    profile,
		config:     config,
		done:       make(chan struct{}),
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
			t.Error("cookie routability server did not stop after socket close")
		}
	})
	return s
}

func (s *cookieRoutabilityServer) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *cookieRoutabilityServer) serve() {
	buf := make([]byte, 1<<16)
	for {
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed
		}
		packet := bytes.Clone(buf[:n])
		s.mu.Lock()
		s.packets = append(s.packets, packet)
		s.mu.Unlock()

		request, initiatorErr := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, packet)
		if initiatorErr == nil {
			s.serveFirstFlight(raddr, request)
			continue
		}
		s.mu.Lock()
		s.initiatorErr = initiatorErr
		s.mu.Unlock()
		s.serveProofFlight(raddr, packet)
	}
}

func (s *cookieRoutabilityServer) serveFirstFlight(raddr *net.UDPAddr, request *relayknock.Reply) {
	if request.Type != s.profile.firstFlightType() {
		s.t.Errorf("%s first flight header type = %d, want %d", s.profile, request.Type, s.profile.firstFlightType())
		return
	}
	s.mu.Lock()
	s.firstFlights = append(s.firstFlights, request)
	replay := s.config.replayFirstChallenge && s.firstChallenge != nil
	captured := bytes.Clone(s.firstChallenge)
	s.mu.Unlock()

	if s.config.directResult {
		s.write(raddr, s.buildReply(s.profile.resultType(), request.Counter, s.config.resultBody))
		return
	}
	if replay {
		// A spent, still perfectly authenticated challenge: only its body.trxId
		// binding to the retired first flight can reject it.
		s.write(raddr, captured)
		return
	}
	// The challenge's own wire counter is deliberately unconstrained; body.trxId
	// carries the binding to the flight being challenged.
	challenge := s.buildReply(relayknock.TypeCookieChallenge, request.Counter+99,
		[]byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, request.Counter, base64.StdEncoding.EncodeToString(s.cookie))))
	s.mu.Lock()
	if s.firstChallenge == nil {
		s.firstChallenge = bytes.Clone(challenge)
	}
	s.mu.Unlock()
	s.write(raddr, challenge)
}

func (s *cookieRoutabilityServer) serveProofFlight(raddr *net.UDPAddr, packet []byte) {
	// Fail-closed probe: the same packet under a one-bit-different cookie must
	// not open, so the accepted open below is a real digest binding.
	wrongCookie := bytes.Clone(s.cookie)
	wrongCookie[0] ^= 0xff
	_, wrongCookieErr := s.openProof(wrongCookie, packet)
	s.mu.Lock()
	s.wrongCookieErr = wrongCookieErr
	s.mu.Unlock()

	request, err := s.openProof(s.cookie, packet)
	if err != nil {
		s.t.Errorf("%s open cookie-bound proof flight: %v", s.profile, err)
		return
	}
	s.mu.Lock()
	s.proofFlights = append(s.proofFlights, request)
	s.mu.Unlock()
	if s.config.unknownResult {
		s.write(raddr, s.buildUnknownReply(request.Counter))
		return
	}
	if s.config.phaseInvalidResult {
		replyType := relayknock.TypeRegisterAck
		if s.profile == hubAssignmentRoutability {
			replyType = relayknock.TypeACK
		}
		s.write(raddr, s.buildReply(replyType, request.Counter, s.config.resultBody))
		return
	}
	if s.config.staleResultFirst {
		s.write(raddr, s.buildReply(s.profile.resultType(), request.Counter+1, s.config.resultBody))
	}
	s.write(raddr, s.buildReply(s.profile.resultType(), request.Counter, s.config.resultBody))
}

func (s *cookieRoutabilityServer) openProof(cookie, packet []byte) (*relayknock.Reply, error) {
	if s.profile == hubAssignmentRoutability {
		return relayknocktest.OpenHubLSTCookieProofMessage(s.serverPriv, s.agentPub, cookie, packet)
	}
	return relayknocktest.OpenReknockMessage(s.serverPriv, s.agentPub, cookie, packet)
}

func (s *cookieRoutabilityServer) buildReply(replyType int, counter uint64, body []byte) []byte {
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: s.serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustNHPRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(mustNHPRand(s.t, 4)),
		Body:             body,
	})
	if err != nil {
		s.t.Errorf("%s build reply type %d: %v", s.profile, replyType, err)
		return nil
	}
	return packet
}

func (s *cookieRoutabilityServer) buildUnknownReply(counter uint64) []byte {
	packet, err := relayknocktest.BuildUnknownReplyForTest(unknownReplyHeaderType, &relayknock.KnockInputs{
		DeviceStaticPriv: s.serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustNHPRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         binary.BigEndian.Uint32(mustNHPRand(s.t, 4)),
		Body:             []byte(`{"authenticated":"unknown"}`),
	})
	if err != nil {
		s.t.Errorf("%s build unknown reply: %v", s.profile, err)
		return nil
	}
	return packet
}

func (s *cookieRoutabilityServer) write(raddr *net.UDPAddr, packet []byte) {
	if packet == nil {
		return
	}
	if _, err := s.conn.WriteToUDP(packet, raddr); err != nil {
		s.t.Logf("%s write reply: %v", s.profile, err)
		return
	}
	s.mu.Lock()
	s.replies++
	s.mu.Unlock()
}

func (s *cookieRoutabilityServer) awaitReplies(want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		got := s.replies
		s.mu.Unlock()
		if got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

// snapshot returns the flights the responder admitted plus the two fail-closed
// probes: initiatorErr is why a proof flight is not an ordinary initiator
// message, and wrongCookieErr is why it does not open under a different cookie.
func (s *cookieRoutabilityServer) snapshot() (first, proof []*relayknock.Reply, packets [][]byte, initiatorErr, wrongCookieErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first = slices.Clone(s.firstFlights)
	proof = slices.Clone(s.proofFlights)
	packets = make([][]byte, len(s.packets))
	for i := range s.packets {
		packets[i] = bytes.Clone(s.packets[i])
	}
	return first, proof, packets, s.initiatorErr, s.wrongCookieErr
}

// cookieRoutabilityExchange bundles a two-leg responder with the transport
// wiring that drives it, so a proof can assert the protocol outcome and the
// per-leg resolve/dial bookkeeping together.
type cookieRoutabilityExchange struct {
	server   *cookieRoutabilityServer
	endpoint nativeudp.Endpoint
	options  nativeudp.Options
	resolver *scriptedResolver
	dialer   *addressRecordingDialer
}

// newCookieRoutabilityExchange wires a two-leg responder behind a globally
// routable synthetic address, so the transport's non-public-address rejection
// stays active and every leg is observed to dial the public endpoint.
func newCookieRoutabilityExchange(t *testing.T, profile cookieRoutabilityProfile, config cookieRoutabilityConfig) *cookieRoutabilityExchange {
	t.Helper()
	devicePriv := mustNHPPriv(t)
	return newCookieRoutabilityExchangeForAgent(t, profile, devicePriv, nhpPubOf(t, devicePriv), config)
}

// newCookieRoutabilityExchangeForAgent pins the responder to an agent public key
// the caller already holds. The public registration driver mints and persists
// its own device identity, so a responder that has to open its packets must be
// keyed from that persisted state rather than from a key the test picked;
// devicePriv only populates Options.DeviceStaticPriv, so such a caller passes nil.
func newCookieRoutabilityExchangeForAgent(t *testing.T, profile cookieRoutabilityProfile, devicePriv, agentPub []byte, config cookieRoutabilityConfig) *cookieRoutabilityExchange {
	t.Helper()
	serverPriv, serverPub := mustNHPKeypair(t)
	server := newCookieRoutabilityServer(t, serverPriv, agentPub, profile, config)
	host := "hub.nhp.layerv.ai"
	if profile == cellReknockRoutability {
		host = "cell0.nhp.layerv.ai"
	}
	resolver := &scriptedResolver{answers: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8")}}}
	dialer := &addressRecordingDialer{port: server.port()}
	return &cookieRoutabilityExchange{
		server:   server,
		endpoint: nativeudp.Endpoint{Host: host, Port: server.port(), ServerStaticPub: serverPub},
		options: nativeudp.Options{
			DeviceStaticPriv: devicePriv,
			Resolver:         resolver,
			Dialer:           dialer,
			Timeout:          2 * time.Second,
			MaxAddresses:     1,
		},
		resolver: resolver,
		dialer:   dialer,
	}
}

// assignedCellExchanges is the subset of exported phases that a single
// authenticated in-profile reply completes. The Hub assignment LST is excluded
// because its first flight accepts only NHP_COK, so it cannot succeed against a
// single-reply responder.
func assignedCellExchanges() []nhpExchange {
	all := hubAndCellExchanges()
	cell := make([]nhpExchange, 0, len(all))
	for _, exchange := range all {
		if exchange.singleReplyCompletes {
			cell = append(cell, exchange)
		}
	}
	return cell
}

// twoPublicAddresses is a two-answer DNS result used by the loss and delay
// proofs to exercise the bounded serial address budget.
func twoPublicAddresses() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}
}

// routingDialer maps each logical resolved address to its own concrete loopback
// target, so one address can be a blackhole that swallows the request datagram
// while another reaches the responder. It is how request-flight loss is modelled
// without turning the loss into a dial failure.
type routingDialer struct {
	routes map[string]string

	mu     sync.Mutex
	dialed []string
}

func (d *routingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	target, ok := d.routes[address]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("routingDialer has no route for %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (d *routingDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

// recordingUDPBlackhole accepts datagrams and never answers, keeping every
// datagram's bytes. startUDPBlackhole only counts; the loss proof additionally
// needs the bytes, because whether two outer attempts are the same logical
// operation or two fresh ones is exactly a question about those bytes.
type recordingUDPBlackhole struct {
	conn *net.UDPConn
	done chan struct{}

	mu      sync.Mutex
	packets [][]byte
}

func startRecordingUDPBlackhole(t *testing.T) *recordingUDPBlackhole {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind recording UDP blackhole: %v", err)
	}
	b := &recordingUDPBlackhole{conn: conn, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		buf := make([]byte, 1<<16)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			b.mu.Lock()
			b.packets = append(b.packets, bytes.Clone(buf[:n]))
			b.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-b.done:
		case <-time.After(2 * time.Second):
			t.Error("recording UDP blackhole did not stop after socket close")
		}
	})
	return b
}

func (b *recordingUDPBlackhole) address() string { return b.conn.LocalAddr().String() }

// awaitPackets waits until want datagrams have been recorded, then returns
// everything recorded. It deliberately does not wait past want, so an extra
// datagram still fails a caller's exact-count check.
func (b *recordingUDPBlackhole) awaitPackets(want int) [][]byte {
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		got := len(b.packets)
		b.mu.Unlock()
		if got >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	packets := make([][]byte, len(b.packets))
	for i := range b.packets {
		packets[i] = bytes.Clone(b.packets[i])
	}
	return packets
}

// provePacketLoss proves the SDK's response to a dropped flight is bounded
// recovery that never invents a second logical operation. A lost reply is
// recovered by the serial address budget, and the retried flight is the very
// same packet — address fallback deliberately resends, so a server that already
// accepted the first copy sees no new transaction. When every flight is lost the
// exchange ends as a retryable ErrTransport timeout after exactly the budgeted
// number of datagrams, never as a definitive resolve/authentication/correlation
// rejection. A lost request behaves identically. Above that, the bounded outer
// retry in the public registration driver mints a genuinely fresh packet per
// attempt and still advances no durable state.
func provePacketLoss(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const attemptTimeout = 250 * time.Millisecond

	// A lost reply is recovered inside the address budget with the same packet.
	for _, exchange := range assignedCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{dropReplies: 1})
		dialer := &addressRecordingDialer{port: ep.Port}
		opts.Resolver = fixedAddressesResolver{addresses: twoPublicAddresses()}
		opts.Dialer, opts.MaxAddresses, opts.Timeout = dialer, 2, attemptTimeout
		reply, err := exchange.call(ctx, ep, nil, opts)
		if reply == nil || err != nil {
			t.Fatalf("reply_loss/%s = reply %v, err %v; want the next address to complete the exchange", exchange.name, reply, err)
		}
		packets := server.receivedPackets()
		if len(packets) != 2 {
			t.Fatalf("reply_loss/%s delivered %d datagrams, want exactly 2 (the lost flight and one bounded retry)", exchange.name, len(packets))
		}
		if !bytes.Equal(packets[0], packets[1]) {
			t.Fatalf("reply_loss/%s minted new request material for the address fallback; a resend must not be a second logical operation", exchange.name)
		}
		if got := len(dialer.snapshot()); got != 2 {
			t.Fatalf("reply_loss/%s dialed %d addresses, want exactly 2", exchange.name, got)
		}
	}

	// Total reply loss is a bounded retryable miss at every exported phase.
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{dropReplies: 1 << 20})
		opts.Resolver = fixedAddressesResolver{addresses: twoPublicAddresses()}
		opts.Dialer, opts.MaxAddresses, opts.Timeout = &addressRecordingDialer{port: ep.Port}, 2, attemptTimeout
		reply, err := exchange.call(ctx, ep, nil, opts)
		var netErr net.Error
		classified := reply == nil && errors.Is(err, nativeudp.ErrTransport) &&
			!errors.Is(err, nativeudp.ErrResolve) && !errors.Is(err, nativeudp.ErrServerUnauthenticated) &&
			!errors.Is(err, relayknock.ErrMalformedReply) && errors.As(err, &netErr) && netErr.Timeout()
		if !classified {
			t.Fatalf("total_loss/%s classification mismatch: error_type=%T reply_non_nil=%t transport=%t resolve=%t unauthenticated=%t malformed=%t net_timeout=%t",
				exchange.name, err, reply != nil,
				errors.Is(err, nativeudp.ErrTransport), errors.Is(err, nativeudp.ErrResolve),
				errors.Is(err, nativeudp.ErrServerUnauthenticated), errors.Is(err, relayknock.ErrMalformedReply),
				errors.As(err, &netErr) && netErr.Timeout())
		}
		packets := server.receivedPackets()
		if len(packets) != 2 {
			t.Fatalf("total_loss/%s delivered %d datagrams, want exactly the 2-address budget and no unbounded retry", exchange.name, len(packets))
		}
		if !bytes.Equal(packets[0], packets[1]) {
			t.Fatalf("total_loss/%s minted new request material inside one exchange", exchange.name)
		}
	}

	// A lost request flight recovers the same way: the first address swallows the
	// datagram outright, so the responder sees only the surviving address.
	for _, exchange := range assignedCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{})
		lost := startUDPBlackhole(t)
		addresses := twoPublicAddresses()
		dialer := &routingDialer{routes: map[string]string{
			netip.AddrPortFrom(addresses[0], uint16(ep.Port)).String(): lost.LocalAddr().String(),
			netip.AddrPortFrom(addresses[1], uint16(ep.Port)).String(): net.JoinHostPort("127.0.0.1", strconv.Itoa(ep.Port)),
		}}
		opts.Resolver = fixedAddressesResolver{addresses: addresses}
		opts.Dialer, opts.MaxAddresses, opts.Timeout = dialer, 2, attemptTimeout
		reply, err := exchange.call(ctx, ep, nil, opts)
		if reply == nil || err != nil {
			t.Fatalf("request_loss/%s = reply %v, err %v; want the surviving address to complete the exchange", exchange.name, reply, err)
		}
		if got := server.receivedCount(); got != 1 {
			t.Fatalf("request_loss/%s responder received %d datagrams, want exactly 1 (the lost flight never arrived)", exchange.name, got)
		}
		if dropped, _ := drainUDPBlackhole(t, lost); dropped != 1 {
			t.Fatalf("request_loss/%s lost-address blackhole absorbed %d datagrams, want exactly 1", exchange.name, dropped)
		}
		wantDialed := []string{
			netip.AddrPortFrom(addresses[0], uint16(ep.Port)).String(),
			netip.AddrPortFrom(addresses[1], uint16(ep.Port)).String(),
		}
		if got := dialer.snapshot(); !slices.Equal(got, wantDialed) {
			t.Fatalf("request_loss/%s dial sequence = %q, want the lost address first then the surviving one %q", exchange.name, got, wantDialed)
		}
	}

	// Durable recovery: the public registration driver's bounded outer retry
	// mints genuinely fresh material per attempt and advances no durable state.
	const (
		agentID       = "qurl-go-fault-proof-loss"
		outerAttempts = 2
	)
	store := faultStateStore(t)
	lostHub := startRecordingUDPBlackhole(t)
	_, serverPub := mustNHPKeypair(t)
	hub := qurl.HubBootstrap{
		Host:               "loss-proof.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(serverPub),
	}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "packet-loss"),
		qurl.WithAgentRuntimeUDPResolver(&fixedResolver{address: netip.MustParseAddr("8.8.8.8")}),
		qurl.WithAgentRuntimeUDPDialer(&redirectingDialer{target: lostHub.address()}),
		qurl.WithAgentRuntimeUDPBounds(attemptTimeout, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(outerAttempts, 30*time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	var recovery *qurl.AssignmentRecoveryRequiredError
	if client != nil || bindingNonNil || !errors.As(err, &recovery) || !errors.Is(err, nativeudp.ErrTransport) ||
		recoveryAttempts(recovery) != outerAttempts {
		t.Fatalf("registration loss recovery mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t recovery=%t transport=%t attempts=%d (want %d)",
			err, client != nil, bindingNonNil, errors.As(err, &recovery), errors.Is(err, nativeudp.ErrTransport),
			recoveryAttempts(recovery), outerAttempts)
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("registration loss recovery reflected the enrollment credential")
	}
	outer := lostHub.awaitPackets(outerAttempts)
	if len(outer) != outerAttempts {
		t.Fatalf("registration loss emitted %d datagrams, want exactly one per bounded outer attempt (%d)", len(outer), outerAttempts)
	}
	if bytes.Equal(outer[0], outer[1]) {
		t.Fatal("registration loss re-drove the same packet across outer attempts; a fresh exchange must mint fresh randomness")
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "packet_loss")

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_loss reply_loss_phases=%d total_loss_phases=%d request_loss_phases=%d in_exchange_resend=identical_packet address_budget=2 rejection=ErrTransport+net.Error.Timeout outer_attempts=%d outer_packets_distinct=true registration_state_mutation=0 lifecycle_http_calls=0",
		len(assignedCellExchanges()), len(hubAndCellExchanges()), len(assignedCellExchanges()), outerAttempts)
}

// provePacketDelay proves the SDK's latency contract is a deadline rather than a
// wait. A reply later than the attempt bound is a bounded retryable miss at every
// exported phase and the client returns at its own deadline instead of waiting
// for the slow path; the identical responder inside the bound completes the
// exchange normally, so the rejection is genuinely about lateness. Across the
// serial address budget the worst case stays at MaxAddresses × Timeout, and a
// reply that lands after the client gave up can never be adopted by the next
// exchange.
func provePacketDelay(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const (
		attemptTimeout = 200 * time.Millisecond
		// Comfortably past attemptTimeout, and short enough that the responder
		// finishes well inside its own shutdown tolerance.
		lateReply = 700 * time.Millisecond
		// Comfortably inside the generous bound used by the in-budget case.
		promptReply   = 25 * time.Millisecond
		generousBound = 2 * time.Second
	)

	// A late reply is a bounded retryable miss, and the client does not wait for it.
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{replyDelay: lateReply})
		opts.MaxAddresses, opts.Timeout = 1, attemptTimeout
		started := time.Now()
		reply, err := exchange.call(ctx, ep, nil, opts)
		elapsed := time.Since(started)
		var netErr net.Error
		classified := reply == nil && errors.Is(err, nativeudp.ErrTransport) &&
			!errors.Is(err, nativeudp.ErrResolve) && !errors.Is(err, nativeudp.ErrServerUnauthenticated) &&
			!errors.Is(err, relayknock.ErrMalformedReply) && errors.As(err, &netErr) && netErr.Timeout() &&
			elapsed >= attemptTimeout/2 && elapsed < lateReply
		if !classified {
			t.Fatalf("late_reply/%s classification mismatch: error_type=%T reply_non_nil=%t transport=%t resolve=%t unauthenticated=%t malformed=%t net_timeout=%t elapsed=%s (want >= %s and < the %s reply delay)",
				exchange.name, err, reply != nil,
				errors.Is(err, nativeudp.ErrTransport), errors.Is(err, nativeudp.ErrResolve),
				errors.Is(err, nativeudp.ErrServerUnauthenticated), errors.Is(err, relayknock.ErrMalformedReply),
				errors.As(err, &netErr) && netErr.Timeout(), elapsed, attemptTimeout/2, lateReply)
		}
		if got := server.awaitReceived(1); got != 1 {
			t.Fatalf("late_reply/%s emitted %d datagrams, want exactly 1 for one bounded address attempt", exchange.name, got)
		}
		// The reply genuinely exists and is merely late: this is a delay fault,
		// not the loss fault proven separately.
		if got := server.awaitReplies(1); got != 1 {
			t.Fatalf("late_reply/%s responder wrote %d replies, want 1 (the reply must be late, not absent)", exchange.name, got)
		}
	}

	// The same responder inside the bound completes: the contract is a deadline,
	// not a fixed wait, so the rejection above is about lateness alone.
	for _, exchange := range assignedCellExchanges() {
		_, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{replyDelay: promptReply})
		opts.MaxAddresses, opts.Timeout = 1, generousBound
		reply, err := exchange.call(ctx, ep, nil, opts)
		if reply == nil || err != nil {
			t.Fatalf("in_budget_delay/%s = reply %v, err %v; want a delayed but in-budget reply to complete the exchange", exchange.name, reply, err)
		}
	}

	// Worst-case serial fan-out stays at MaxAddresses × Timeout.
	server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{replyDelay: lateReply})
	opts.Resolver = fixedAddressesResolver{addresses: twoPublicAddresses()}
	opts.Dialer, opts.MaxAddresses, opts.Timeout = &addressRecordingDialer{port: ep.Port}, 2, attemptTimeout
	started := time.Now()
	reply, err := nativeudp.Knock(ctx, ep, nil, opts)
	elapsed := time.Since(started)
	fanoutCeiling := 2*attemptTimeout + 500*time.Millisecond
	if reply != nil || !errors.Is(err, nativeudp.ErrTransport) || elapsed < attemptTimeout || elapsed > fanoutCeiling {
		t.Fatalf("delayed address fan-out = reply %v, err %v, elapsed %s; want ErrTransport bounded within [%s, %s]",
			reply, err, elapsed, attemptTimeout, fanoutCeiling)
	}
	if got := server.awaitReceived(2); got != 2 {
		t.Fatalf("delayed address fan-out emitted %d datagrams, want exactly the 2-address budget", got)
	}

	// A reply the client already gave up on cannot be adopted by a later
	// exchange: each exchange owns a fresh socket and requires its own counter
	// echo, so the next exchange completes on its own reply.
	lateServer, lateEP, lateOpts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{replyDelay: lateReply})
	lateOpts.MaxAddresses, lateOpts.Timeout = 1, attemptTimeout
	if reply, err := nativeudp.Knock(ctx, lateEP, nil, lateOpts); reply != nil || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("abandoned late reply setup = reply %v, err %v; want ErrTransport", reply, err)
	}
	lateOpts.Timeout = generousBound
	if reply, err := nativeudp.Knock(ctx, lateEP, nil, lateOpts); reply == nil || err != nil {
		t.Fatalf("exchange after an abandoned late reply = reply %v, err %v; want its own correlated reply", reply, err)
	}
	if got := lateServer.awaitReceived(2); got != 2 {
		t.Fatalf("abandoned-late-reply sequence emitted %d datagrams, want exactly 2 (one per exchange)", got)
	}

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_delay late_reply_phases=%d in_budget_phases=%d attempt_timeout=%s reply_delay=%s rejection=ErrTransport+net.Error.Timeout client_never_awaits_late_reply=true fanout_bound=max_addresses_times_timeout stale_reply_adopted=0 lifecycle_http_calls=0",
		len(hubAndCellExchanges()), len(assignedCellExchanges()), attemptTimeout, lateReply)
}

// provePacketReplay proves captured, genuinely server-signed material cannot be
// re-used to advance the client. A replayed authenticated reply is rejected by
// the correlation gate at every assigned-cell phase — it is never conflated with
// the unauthenticated class and never recast as a retryable miss. A spent Hub
// NHP_COK replayed into a fresh assignment exchange cannot drive a proof flight,
// because body.trxId still binds it to the retired first LST. A reflection replay
// of the agent's own initiator datagram — the replay an on-path attacker can
// mount holding no key at all — is rejected as unauthenticated and leaves durable
// state at initial identity only.
func provePacketReplay(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const attemptTimeout = 250 * time.Millisecond

	// A captured authenticated reply replayed into a later exchange is rejected.
	for _, exchange := range assignedCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{replayFirstReply: true})
		if reply, err := exchange.call(ctx, ep, nil, opts); reply == nil || err != nil {
			t.Fatalf("replayed_reply/%s setup exchange = reply %v, err %v; want success so a genuine reply is captured", exchange.name, reply, err)
		}
		captured := server.receivedCount()
		reply, err := exchange.call(ctx, ep, nil, opts)
		assertMalformedReplyRejection(t, "replayed_reply/"+exchange.name, reply, err, server.receivedCount()-captured)
	}

	// A spent Hub NHP_COK cannot drive a second proof flight.
	replayHub := newCookieRoutabilityExchange(t, hubAssignmentRoutability, cookieRoutabilityConfig{replayFirstChallenge: true})
	assignmentBody := []byte(`{"query":"cell_assignment","request_nonce":"hub-cookie-replay"}`)
	if reply, err := nativeudp.AssignmentList(ctx, replayHub.endpoint, assignmentBody, replayHub.options); reply == nil || err != nil {
		t.Fatalf("hub cookie replay setup = reply %v, err %v; want the first assignment to complete", reply, err)
	}
	_, _, before, _, _ := replayHub.server.snapshot()
	reply, err := nativeudp.AssignmentList(ctx, replayHub.endpoint, assignmentBody, replayHub.options)
	if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("replayed hub cookie challenge = reply %v, err %v; want the terminal ErrMalformedReply transaction-binding rejection", reply, err)
	}
	if errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Fatalf("replayed hub cookie challenge was classified as unauthenticated; the replayed challenge is authentic and only its binding is spent: %v", err)
	}
	if errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) {
		t.Fatalf("replayed hub cookie challenge was recast as a retryable transport miss: %v", err)
	}
	_, proof, after, _, _ := replayHub.server.snapshot()
	if len(after)-len(before) != 1 {
		t.Fatalf("replayed hub cookie challenge emitted %d datagrams, want exactly 1 (no proof flight on a spent challenge)", len(after)-len(before))
	}
	if len(proof) != 1 {
		t.Fatalf("replayed hub cookie challenge produced %d proof flights in total, want the 1 from the legitimate exchange only", len(proof))
	}

	// A reflection replay is unauthenticated at every exported phase.
	for _, exchange := range hubAndCellExchanges() {
		server, ep, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{reflectRequest: true})
		opts.Timeout = attemptTimeout
		reply, err := exchange.call(ctx, ep, nil, opts)
		assertUnauthenticatedRejection(t, "reflected_request/"+exchange.name, reply, err, server.receivedCount())
	}

	// A reflecting Hub advances no durable state through the public registration
	// driver: an unauthenticated datagram is a definitive rejection, not a
	// retryable miss, so the bounded outer retry never runs.
	const agentID = "qurl-go-fault-proof-replay"
	store := faultStateStore(t)
	reflectServer, reflectEP, _ := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{reflectRequest: true})
	hub := qurl.HubBootstrap{
		Host:               "replay-proof.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(reflectEP.ServerStaticPub),
	}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "packet-replay"),
		qurl.WithAgentRuntimeUDPResolver(&fixedResolver{address: netip.MustParseAddr("8.8.8.8")}),
		qurl.WithAgentRuntimeUDPDialer(&redirectingDialer{target: net.JoinHostPort("127.0.0.1", strconv.Itoa(reflectEP.Port))}),
		qurl.WithAgentRuntimeUDPBounds(attemptTimeout, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(2, 30*time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || bindingNonNil || !errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Fatalf("reflecting-hub registration mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t unauthenticated=%t err=%v",
			err, client != nil, bindingNonNil, errors.Is(err, nativeudp.ErrServerUnauthenticated), err)
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("reflecting-hub registration reflected the enrollment credential")
	}
	if got := reflectServer.awaitReceived(1); got != 1 {
		t.Fatalf("reflecting-hub registration emitted %d datagrams, want exactly 1 (a definitive rejection is not retried)", got)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "packet_replay")

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_replay replayed_reply_phases=%d replayed_hub_cookie_challenge=1 reflected_request_phases=%d correlation_class=ErrMalformedReply reflection_class=ErrServerUnauthenticated spent_challenge_proof_flights=0 registration_state_mutation=0 lifecycle_http_calls=0",
		len(assignedCellExchanges()), len(hubAndCellExchanges()))
}

// provePacketReorder puts a stale authenticated reply immediately before the
// correct reply at every distinct transport boundary. The SDK reads and
// evaluates the first datagram, returns a terminal correlation rejection, and
// never skips ahead to the later packet. Tagged assignment requests repeat the
// same Hub proof-LST behavior at initial, refresh, and recovery call sites.
func provePacketReorder(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	rejected := 0

	for _, exchange := range hubAndCellExchanges() {
		server, endpoint, opts := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{staleReplyFirst: true})
		reply, err := exchange.call(ctx, endpoint, []byte(`{"reorder":"first-leg"}`), opts)
		if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) ||
			errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrServerUnauthenticated) {
			t.Fatalf("reordered first reply/%s = reply %v, err %v; want terminal ErrMalformedReply only",
				exchange.name, reply, err)
		}
		if got := server.awaitReplies(2); got != 2 {
			t.Fatalf("reordered first reply/%s wrote %d datagrams, want stale then correct", exchange.name, got)
		}
		if got := server.receivedCount(); got != 1 {
			t.Fatalf("reordered first reply/%s received %d requests, want 1", exchange.name, got)
		}
		rejected++
	}

	for _, boundary := range []string{"initial", "refresh", "recovery"} {
		exchange := newCookieRoutabilityExchange(t, hubAssignmentRoutability, cookieRoutabilityConfig{staleResultFirst: true})
		body := []byte(fmt.Sprintf(`{"query":"cell_assignment","request_nonce":"reorder-%s"}`, boundary))
		reply, err := nativeudp.AssignmentList(ctx, exchange.endpoint, body, exchange.options)
		if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) ||
			errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrServerUnauthenticated) {
			t.Fatalf("reordered Hub proof LST/%s = reply %v, err %v; want terminal ErrMalformedReply only",
				boundary, reply, err)
		}
		first, proof, packets, _, _ := exchange.server.snapshot()
		if len(first) != 1 || len(proof) != 1 || len(packets) != 2 {
			t.Fatalf("reordered Hub proof LST/%s flights = first:%d proof:%d packets:%d; want 1/1/2",
				boundary, len(first), len(proof), len(packets))
		}
		if got := exchange.server.awaitReplies(3); got != 3 {
			t.Fatalf("reordered Hub proof LST/%s wrote %d replies, want challenge, stale result, correct result",
				boundary, got)
		}
		rejected++
	}

	reknock := newCookieRoutabilityExchange(t, cellReknockRoutability, cookieRoutabilityConfig{staleResultFirst: true})
	reply, err := nativeudp.KnockWithReknock(ctx, reknock.endpoint,
		[]byte(`{"headerType":1,"runId":"reorder-proof"}`),
		[]byte(`{"headerType":8,"runId":"reorder-proof"}`),
		reknock.options)
	if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) ||
		errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Fatalf("reordered RKN result = reply %v, err %v; want terminal ErrMalformedReply only", reply, err)
	}
	first, proof, packets, _, _ := reknock.server.snapshot()
	if len(first) != 1 || len(proof) != 1 || len(packets) != 2 {
		t.Fatalf("reordered RKN flights = first:%d proof:%d packets:%d; want 1/1/2",
			len(first), len(proof), len(packets))
	}
	if got := reknock.server.awaitReplies(3); got != 3 {
		t.Fatalf("reordered RKN wrote %d replies, want challenge, stale result, correct result", got)
	}
	rejected++

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_reorder stale_first_rejections=%d assigned_cell_boundaries=%d hub_first_lst=1 hub_proof_boundaries=3 reknock=1 later_correct_reply_adopted=0 rejection=ErrMalformedReply lifecycle_http_calls=0",
		rejected, len(assignedCellExchanges()))
}

// provePacketUnknownMessage sends authenticated packets with a genuinely
// unknown header type and known-but-phase-invalid reply types. Unknown types
// deliberately collapse into the opaque server-authentication class at the
// public boundary; phase-invalid known replies reach correlation and return the
// terminal malformed-reply class. Neither class falls through to another
// address or advances a two-leg profile.
func provePacketUnknownMessage(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	unknownRejected := 0
	phaseInvalidRejected := 0

	for _, exchange := range hubAndCellExchanges() {
		server, endpoint, opts := newLoopbackNHPExchange(t, respondUnknownMessage)
		reply, err := exchange.call(ctx, endpoint, []byte(`{"unknown":"first-leg"}`), opts)
		assertUnauthenticatedRejection(t, "authenticated_unknown/"+exchange.name, reply, err, server.receivedCount())
		unknownRejected++

		server, endpoint, opts = newLoopbackNHPExchange(t, respondPhaseInvalid)
		reply, err = exchange.call(ctx, endpoint, []byte(`{"phase_invalid":"first-leg"}`), opts)
		assertMalformedReplyRejection(t, "phase_invalid/"+exchange.name, reply, err, server.receivedCount())
		phaseInvalidRejected++
	}

	type invalidResultCase struct {
		name   string
		config cookieRoutabilityConfig
		assert func(*testing.T, string, *relayknock.Reply, error, int)
	}
	invalidResults := []invalidResultCase{
		{name: "unknown", config: cookieRoutabilityConfig{unknownResult: true}, assert: assertUnauthenticatedRejection},
		{name: "phase_invalid", config: cookieRoutabilityConfig{phaseInvalidResult: true}, assert: assertMalformedReplyRejection},
	}
	for _, boundary := range []string{"initial", "refresh", "recovery"} {
		for _, tc := range invalidResults {
			exchange := newCookieRoutabilityExchange(t, hubAssignmentRoutability, tc.config)
			body := []byte(fmt.Sprintf(`{"query":"cell_assignment","request_nonce":"%s-%s"}`, tc.name, boundary))
			reply, err := nativeudp.AssignmentList(ctx, exchange.endpoint, body, exchange.options)
			_, proof, packets, _, _ := exchange.server.snapshot()
			tc.assert(t, tc.name+"/hub_proof_"+boundary, reply, err, len(proof))
			if len(packets) != 2 {
				t.Fatalf("%s Hub proof/%s emitted %d initiator packets, want first LST and proof LST", tc.name, boundary, len(packets))
			}
			if tc.name == "unknown" {
				unknownRejected++
			} else {
				phaseInvalidRejected++
			}
		}
	}

	for _, tc := range invalidResults {
		exchange := newCookieRoutabilityExchange(t, cellReknockRoutability, tc.config)
		reply, err := nativeudp.KnockWithReknock(ctx, exchange.endpoint,
			[]byte(`{"headerType":1,"runId":"unknown-proof"}`),
			[]byte(`{"headerType":8,"runId":"unknown-proof"}`),
			exchange.options)
		_, proof, packets, _, _ := exchange.server.snapshot()
		tc.assert(t, tc.name+"/assigned_cell_reknock", reply, err, len(proof))
		if len(packets) != 2 {
			t.Fatalf("%s RKN emitted %d initiator packets, want KNK and RKN", tc.name, len(packets))
		}
		if tc.name == "unknown" {
			unknownRejected++
		} else {
			phaseInvalidRejected++
		}
	}

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE unknown_message authenticated_unknown_rejections=%d unknown_public_class=ErrServerUnauthenticated phase_invalid_rejections=%d phase_invalid_class=ErrMalformedReply address_fallback=0 accepted_results=0 lifecycle_http_calls=0",
		unknownRejected, phaseInvalidRejected)
}

// provePublicResourceAndKnockResourceIDWireDistinction binds a producer-shaped
// canonical P-256 public resource ID through EnsureConnectorResource, then uses
// that returned resource's separate placement-only KnockResourceID in the public
// registered-agent UDP API. The management call is completed and counted before
// the zero-HTTP lifecycle interval begins; the decrypted NHP_KNK body proves the
// public identity was not substituted into resId or copied elsewhere on wire.
func provePublicResourceAndKnockResourceIDWireDistinction(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const (
		publicResourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2cTVv5_3eeYCcLLq5ROYCqcmY50HiKZ9ATglIkPnCji1E_S63UMtXba1moR8-Q6EV7oM6zwwh9_j2CDujzXvLA"
		routingID        = "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		knockResourceID  = "connector-cell-placement-proof"
		resourceSlug     = "udp-identity-proof"
		deviceCredential = "lv_live_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	)

	der, err := base64.RawURLEncoding.Strict().DecodeString(publicResourceID)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != publicResourceID {
		t.Fatalf("public resource id is not canonical unpadded base64url: %v", err)
	}
	if _, err := qurl.ParseP256PublicKeyDER(der); err != nil {
		t.Fatalf("public resource id is not a canonical P-256 DER SPKI key: %v", err)
	}
	if publicResourceID == knockResourceID {
		t.Fatal("public resource id and knock resource id fixtures must be distinct")
	}

	agentPriv, agentPub := mustNHPKeypair(t)
	cellPriv, cellPub := mustNHPKeypair(t)
	registeredAt := time.Now().UTC()
	store := faultStateStore(t)
	if err := store.SaveAgentState(ctx, &qurl.AgentState{
		AgentID:        "qurl-go-identity-wire-proof",
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(agentPriv),
		PublicKeyB64:   base64.StdEncoding.EncodeToString(agentPub),
		RegisteredAt:   &registeredAt,
		SchemaVersion:  currentAgentStateSchemaVersion,
		DeviceAPIKey:   deviceCredential,
		DeviceAPIKeyID: "key_AbCdEf123456",
		Assignment: &qurl.AgentAssignment{
			CellID:               "cell0",
			AssignmentGeneration: 1,
			EndpointRevision:     1,
			LeaseExpiresAt:       registeredAt.Add(time.Hour),
			Endpoint: qurl.NHPUDPEndpoint{
				Host:               "cell0.nhp.layerv.ai",
				Port:               standardNHPUDPPort,
				ServerPublicKeyB64: base64.StdEncoding.EncodeToString(cellPub),
			},
		},
	}); err != nil {
		t.Fatalf("seed completed registered-agent state: %v", err)
	}

	var managementCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managementCalls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources" || r.URL.RawQuery != "" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+deviceCredential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request struct {
			Type         string `json:"type"`
			Slug         string `json:"slug"`
			FindOrCreate bool   `json:"find_or_create"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
			request.Type != "tunnel" || request.Slug != resourceSlug || !request.FindOrCreate {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":false}}`,
			publicResourceID, routingID, knockResourceID, resourceSlug)
	}))
	defer api.Close()

	client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
		qurl.WithAgentClientBaseURL(api.URL),
		qurl.WithAgentClientHTTPClient(api.Client()),
	)
	if err != nil {
		t.Fatalf("open completed registered-agent runtime: %v", err)
	}
	defer binding.Destroy()
	resourceResult, err := client.EnsureConnectorResource(ctx, resourceSlug)
	if err != nil {
		t.Fatalf("EnsureConnectorResource: %v", err)
	}
	if resourceResult == nil || resourceResult.Resource == nil ||
		resourceResult.Resource.ResourceID != publicResourceID ||
		resourceResult.Resource.KnockResourceID != knockResourceID ||
		resourceResult.Resource.ResourceID == resourceResult.Resource.KnockResourceID {
		t.Fatalf("producer resource identity/admission binding = %#v", resourceResult)
	}
	if got := managementCalls.Load(); got != 1 {
		t.Fatalf("management-plane resource calls = %d, want exactly 1 before native lifecycle proof", got)
	}
	assertNoLifecycleHTTP(t, httpTrap)

	ackBody := []byte(fmt.Sprintf(
		`{"errCode":"0","resHost":{%q:"frps.cell0.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{%q:"proof-token"},"preActions":{%q:null}}`,
		knockResourceID, knockResourceID, knockResourceID))
	server := newLoopbackNHPServer(t, cellPriv, agentPub, respondCorrectly, malformedHeaderReplyBytes,
		loopbackFaultConfig{replyBody: ackBody})
	resolver := &scriptedResolver{answers: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8")}}}
	dialer := &addressRecordingDialer{port: server.port()}
	privateKey := binding.TakeDeviceStaticPrivateKey()
	defer wipe(privateKey)
	result, err := qurl.KnockRegisteredAgent(ctx, binding, privateKey, resourceResult.Resource.KnockResourceID,
		qurl.NativeKnockOptions{RunID: "0123456789abcdef"},
		qurl.WithAgentRuntimeUDPResolver(resolver),
		qurl.WithAgentRuntimeUDPDialer(dialer),
		qurl.WithAgentRuntimeUDPBounds(2*time.Second, 1),
	)
	if err != nil {
		t.Fatalf("KnockRegisteredAgent: %v", err)
	}
	if result == nil || result.ResourceHost != "frps.cell0.example:7000" || result.ACToken != "proof-token" {
		t.Fatalf("native admission result = %v, want exact knock-resource admission", result)
	}
	packets := server.receivedPackets()
	if len(packets) != 1 {
		t.Fatalf("identity distinction emitted %d KNK packets, want exactly 1", len(packets))
	}
	opened, err := relayknocktest.OpenInitiatorMessage(cellPriv, agentPub, packets[0])
	if err != nil {
		t.Fatalf("open identity-distinction KNK: %v", err)
	}
	var wireBody struct {
		HeaderType      int    `json:"headerType"`
		UserID          string `json:"usrId"`
		DeviceID        string `json:"devId"`
		AuthServiceID   string `json:"aspId"`
		KnockResourceID string `json:"resId"`
		RunID           string `json:"runId"`
	}
	var wireFields map[string]json.RawMessage
	if err := json.Unmarshal(opened.Body, &wireBody); err != nil {
		t.Fatalf("decode identity-distinction KNK body: %v", err)
	}
	if err := json.Unmarshal(opened.Body, &wireFields); err != nil {
		t.Fatalf("decode identity-distinction KNK fields: %v", err)
	}
	if len(wireFields) != 6 || wireBody.HeaderType != relayknock.TypeKnock ||
		wireBody.KnockResourceID != knockResourceID ||
		wireBody.KnockResourceID == publicResourceID ||
		bytes.Contains(opened.Body, []byte(publicResourceID)) {
		t.Fatalf("identity-distinction KNK body cross-wired public identity: fields=%d body=%s", len(wireFields), opened.Body)
	}
	if got := managementCalls.Load(); got != 1 {
		t.Fatalf("native lifecycle made a management-plane HTTP call: total=%d", got)
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE public_resource_and_knock_resource_id_wire_distinction public_resource_id_shape=canonical_P256_DER_SPKI producer_binding=accepted distinct_values=true nhp_resId=knock_resource_id public_resource_id_on_nhp_wire=0 management_http_calls_before_lifecycle=1 lifecycle_http_calls=0")
}

// proveHubCookieProofRoutability proves the Hub assignment return-routability
// profile end to end through the exported transport: an ordinary first NHP_LST
// is answered only with an authenticated NHP_COK, and the SDK then sends exactly
// one cookie-bound proof NHP_LST to the same public Hub address that receives the
// final NHP_LRT. The proof flight is observed to be a distinct wire object — it
// does not open as an ordinary initiator message and does not open under a
// different cookie — while carrying a byte-identical application body under fresh
// per-message randomness. There is no third flight and no HTTP.
func proveHubCookieProofRoutability(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	exchange := newCookieRoutabilityExchange(t, hubAssignmentRoutability, cookieRoutabilityConfig{})
	body := []byte(`{"query":"cell_assignment","request_nonce":"hub-cookie-proof-routability"}`)
	reply, err := nativeudp.AssignmentList(ctx, exchange.endpoint, body, exchange.options)
	if err != nil {
		t.Fatalf("hub cookie-proof assignment: %v", err)
	}
	if reply == nil || !reply.IsListResult() || string(reply.Body) != `{"ok":true}` {
		t.Fatalf("hub cookie-proof assignment reply = %#v, want the final authenticated NHP_LRT", reply)
	}

	first, proof, packets, initiatorErr, wrongCookieErr := exchange.server.snapshot()
	if len(first) != 1 || len(proof) != 1 || len(packets) != 2 {
		t.Fatalf("hub cookie-proof flights = first=%d proof=%d datagrams=%d; want exactly one unproven LST and one proof LST",
			len(first), len(proof), len(packets))
	}
	if first[0].Type != relayknock.TypeListRequest || proof[0].Type != relayknock.TypeListRequest {
		t.Fatalf("hub cookie-proof flight types = %d/%d, want both NHP_LST", first[0].Type, proof[0].Type)
	}
	// The proof flight is a distinct wire object, not a resend: it is inadmissible
	// as an ordinary initiator message and inadmissible under any other cookie.
	if initiatorErr == nil {
		t.Fatal("hub cookie-proof flight opened as an ordinary initiator LST; the cookie-bound profile is not exclusive")
	}
	if wrongCookieErr == nil {
		t.Fatal("hub cookie-proof flight opened under a different cookie; the header digest is not cookie-bound")
	}
	if !bytes.Equal(first[0].Body, body) || !bytes.Equal(proof[0].Body, body) {
		t.Fatalf("hub cookie-proof bodies = %q / %q, want the caller's body byte-identical on both flights", first[0].Body, proof[0].Body)
	}
	if proof[0].Counter == first[0].Counter || proof[0].TimestampNanos <= first[0].TimestampNanos || bytes.Equal(packets[0], packets[1]) {
		t.Fatalf("hub cookie-proof flight reused first-flight material: counters %d/%d timestamps %d/%d identical_packets=%t",
			first[0].Counter, proof[0].Counter, first[0].TimestampNanos, proof[0].TimestampNanos, bytes.Equal(packets[0], packets[1]))
	}
	// Both legs reach the same public Hub address, each after its own resolution.
	wantAddress := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(exchange.endpoint.Port)).String()
	if dialed := exchange.dialer.snapshot(); !slices.Equal(dialed, []string{wantAddress, wantAddress}) {
		t.Fatalf("hub cookie-proof dial sequence = %q, want both legs at the public Hub address %q", dialed, wantAddress)
	}
	if calls, network, host := exchange.resolver.snapshot(); calls != 2 || network != "ip" || host != exchange.endpoint.Host {
		t.Fatalf("hub cookie-proof lookups = calls=%d network=%q host=%q; want 2, ip, %q (one per leg)", calls, network, host, exchange.endpoint.Host)
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE hub_cookie_proof_lst_return_routability flights=2 challenge=NHP_COK proof_flight=cookie_bound_NHP_LST result=NHP_LRT ordinary_initiator_open=rejected wrong_cookie_open=rejected body_identical=true fresh_proof_randomness=true resolver_calls=2 dial_calls=2 lifecycle_http_calls=0")
}

// proveCellCookieReknockRoutability proves the assigned-cell registered-agent
// admission sequence end to end: an authenticated NHP_COK for the initial
// NHP_KNK is strictly decoded and its exact cookie mixed into one fresh NHP_RKN,
// whose only accepted reply is an echoed-counter NHP_ACK. The re-knock flight is
// observed to be cookie-bound rather than a re-sent knock, each leg carries its
// own caller-supplied application body unrewritten by the transport, and the
// direct-ACK path is proven to complete in a single flight with no re-knock.
func proveCellCookieReknockRoutability(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	exchange := newCookieRoutabilityExchange(t, cellReknockRoutability, cookieRoutabilityConfig{})
	knockBody := []byte(`{"phase":"knock","resource":"cell-cookie-reknock"}`)
	reknockBody := []byte(`{"phase":"reknock","resource":"cell-cookie-reknock"}`)
	reply, err := nativeudp.KnockWithReknock(ctx, exchange.endpoint, knockBody, reknockBody, exchange.options)
	if err != nil {
		t.Fatalf("assigned-cell cookie re-knock: %v", err)
	}
	if reply == nil || !reply.IsACK() || string(reply.Body) != `{"ok":true}` {
		t.Fatalf("assigned-cell re-knock reply = %#v, want the authenticated NHP_ACK", reply)
	}

	first, proof, packets, initiatorErr, wrongCookieErr := exchange.server.snapshot()
	if len(first) != 1 || len(proof) != 1 || len(packets) != 2 {
		t.Fatalf("re-knock flights = knock=%d reknock=%d datagrams=%d; want exactly one KNK and one RKN",
			len(first), len(proof), len(packets))
	}
	if first[0].Type != relayknock.TypeKnock || proof[0].Type != relayknock.TypeReknock {
		t.Fatalf("re-knock flight types = %d/%d, want NHP_KNK then NHP_RKN", first[0].Type, proof[0].Type)
	}
	if initiatorErr == nil {
		t.Fatal("re-knock flight opened as an ordinary initiator message; NHP_RKN is not cookie-bound")
	}
	if wrongCookieErr == nil {
		t.Fatal("re-knock flight opened under a different cookie; the header digest is not cookie-bound")
	}
	// Each leg carries its own caller-supplied body: the transport does not
	// rewrite an authenticated application body across the transition.
	if !bytes.Equal(first[0].Body, knockBody) || !bytes.Equal(proof[0].Body, reknockBody) {
		t.Fatalf("re-knock bodies = %q / %q, want %q / %q unrewritten", first[0].Body, proof[0].Body, knockBody, reknockBody)
	}
	if proof[0].Counter == first[0].Counter || bytes.Equal(packets[0], packets[1]) {
		t.Fatalf("re-knock flight reused knock material: counters %d/%d identical_packets=%t",
			first[0].Counter, proof[0].Counter, bytes.Equal(packets[0], packets[1]))
	}
	// KNK and RKN are separate exchanges, so the assigned name is resolved again
	// before RKN: a replica change between legs is admissible by construction.
	wantAddress := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(exchange.endpoint.Port)).String()
	if dialed := exchange.dialer.snapshot(); !slices.Equal(dialed, []string{wantAddress, wantAddress}) {
		t.Fatalf("re-knock dial sequence = %q, want both legs at the public cell address %q", dialed, wantAddress)
	}
	if calls, _, host := exchange.resolver.snapshot(); calls != 2 || host != exchange.endpoint.Host {
		t.Fatalf("re-knock lookups = calls=%d host=%q; want 2, %q (KNK and RKN re-resolve independently)", calls, host, exchange.endpoint.Host)
	}

	// The direct-ACK path: a cell that does not challenge completes the knock in
	// one flight and must not emit a re-knock.
	direct := newCookieRoutabilityExchange(t, cellReknockRoutability, cookieRoutabilityConfig{directResult: true})
	reply, err = nativeudp.KnockWithReknock(ctx, direct.endpoint, knockBody, reknockBody, direct.options)
	if err != nil || reply == nil || !reply.IsACK() {
		t.Fatalf("direct-ACK knock = reply %#v, err %v; want a completed single-flight admission", reply, err)
	}
	directFirst, directProof, directPackets, _, _ := direct.server.snapshot()
	if len(directFirst) != 1 || len(directProof) != 0 || len(directPackets) != 1 {
		t.Fatalf("direct-ACK knock flights = knock=%d reknock=%d datagrams=%d; want exactly one KNK and no re-knock",
			len(directFirst), len(directProof), len(directPackets))
	}
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE cell_cookie_reknock_return_routability challenged_flights=2 challenge=NHP_COK proof_flight=cookie_bound_NHP_RKN result=NHP_ACK ordinary_initiator_open=rejected wrong_cookie_open=rejected bodies_unrewritten=true resolver_calls=2 dial_calls=2 direct_ack_flights=1 direct_ack_reknocks=0 lifecycle_http_calls=0")
}

// hubAssignmentWireBody renders an authenticated Hub NHP_LRT initial-assignment
// application body. Every field is rendered from a variable so a case can make
// exactly one thing wrong and leave the rest conforming; the numeric fields are
// rendered raw so a wrong JSON type can be injected too.
type hubAssignmentWireBody struct {
	query, version, mode, agentID string
	keyID, keyKind                string
	cellID, generation, revision  string
	leaseExpiresAt                string
	host, port, serverKeyB64      string
	ticket, ticketExpiresAt       string
}

func (b hubAssignmentWireBody) render() string {
	return fmt.Sprintf(`{"errCode":"0","list":{"query":%q,"version":%s,"mode":%q,"agent_id":%q,`+
		`"registration":{"key_id":%q,"key_kind":%q},`+
		`"assignment":{"cell_id":%q,"assignment_generation":%s,"endpoint_revision":%s,"lease_expires_at":%q,`+
		`"nhp_udp_endpoint":{"host":%q,"port":%s,"server_public_key_b64":%q}},`+
		`"assignment_ticket":%q,"assignment_ticket_expires_at":%q}}`,
		b.query, b.version, b.mode, b.agentID, b.keyID, b.keyKind,
		b.cellID, b.generation, b.revision, b.leaseExpiresAt,
		b.host, b.port, b.serverKeyB64, b.ticket, b.ticketExpiresAt)
}

// with returns a copy mutated by fn, so a case reads as "the conforming body,
// except this one field".
func (b hubAssignmentWireBody) with(fn func(*hubAssignmentWireBody)) string {
	fn(&b)
	return b.render()
}

// invalidAssignmentCase is one row of the authenticated-but-invalid assignment
// matrix: a name and the exact application body a fully authenticated Hub
// returns in its final NHP_LRT.
type invalidAssignmentCase struct {
	name string
	body string
}

// hubAssignmentMatrix builds the conforming baseline plus every invalid
// variation. The baseline is returned separately because it is the control: the
// matrix only means something if the very same harness accepts a conforming body.
func hubAssignmentMatrix(t *testing.T, agentID, cellHost string, cellPort int) (hubAssignmentWireBody, []invalidAssignmentCase) {
	t.Helper()
	_, cellKey := mustNHPKeypair(t)
	now := time.Now().UTC().Truncate(time.Second)
	baseline := hubAssignmentWireBody{
		query:           "cell_assignment",
		version:         "1",
		mode:            "enroll",
		agentID:         agentID,
		keyID:           "key_BsT4rP8wXn6Q",
		keyKind:         "bootstrap",
		cellID:          "cell0",
		generation:      "1",
		revision:        "1",
		leaseExpiresAt:  now.Add(time.Hour).Format(time.RFC3339),
		host:            cellHost,
		port:            strconv.Itoa(cellPort),
		serverKeyB64:    base64.StdEncoding.EncodeToString(cellKey),
		ticket:          "native-udp-proof-assignment-ticket-0001",
		ticketExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
	}
	// An all-zero X25519 public key is a low-order point: canonical base64 that
	// must still be refused as a usable server key.
	lowOrderKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	unpaddedKey := strings.TrimRight(baseline.serverKeyB64, "=")
	rendered := baseline.render()

	drop := func(fragment string) string {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("assignment matrix cannot drop %q: not present in the baseline body", fragment)
		}
		return strings.Replace(rendered, fragment, "", 1)
	}

	return baseline, []invalidAssignmentCase{
		// Endpoint host trust: only a LayerV-owned apex is admissible.
		{"non_layerv_host", baseline.with(func(b *hubAssignmentWireBody) { b.host = "assignment-proof.attacker.example.com" })},
		{"raw_aws_host", baseline.with(func(b *hubAssignmentWireBody) { b.host = "internal-a1b2c3.us-east-1.elb.amazonaws.com" })},
		{"raw_ip_host", baseline.with(func(b *hubAssignmentWireBody) { b.host = "203.0.113.10" })},
		// Endpoint port bounds.
		{"port_zero", baseline.with(func(b *hubAssignmentWireBody) { b.port = "0" })},
		{"port_above_range", baseline.with(func(b *hubAssignmentWireBody) { b.port = "65536" })},
		// Lease liveness.
		{"expired_lease", baseline.with(func(b *hubAssignmentWireBody) {
			b.leaseExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
			b.ticketExpiresAt = now.Add(-2 * time.Minute).Format(time.RFC3339)
		})},
		// Identity binding.
		{"wrong_agent_id", baseline.with(func(b *hubAssignmentWireBody) { b.agentID = agentID + "-substituted" })},
		{"missing_agent_id", drop(fmt.Sprintf(`"agent_id":%q,`, agentID))},
		// Cell identity.
		{"wrong_cell_id", baseline.with(func(b *hubAssignmentWireBody) { b.cellID = "CELL0" })},
		{"missing_cell_id", drop(`"cell_id":"cell0",`)},
		// Assignment ordering counters must be positive and present.
		{"generation_zero", baseline.with(func(b *hubAssignmentWireBody) { b.generation = "0" })},
		{"revision_zero", baseline.with(func(b *hubAssignmentWireBody) { b.revision = "0" })},
		{"missing_generation", drop(`"assignment_generation":1,`)},
		{"missing_revision", drop(`"endpoint_revision":1,`)},
		// Server key trust.
		{"low_order_server_key", baseline.with(func(b *hubAssignmentWireBody) { b.serverKeyB64 = lowOrderKey })},
		{"non_canonical_server_key", baseline.with(func(b *hubAssignmentWireBody) { b.serverKeyB64 = unpaddedKey })},
		{"missing_server_key", drop(fmt.Sprintf(`,"server_public_key_b64":%q`, baseline.serverKeyB64))},
		// Strict-object boundaries.
		{"duplicate_field", strings.Replace(rendered, `"cell_id":"cell0",`, `"cell_id":"cell0","cell_id":"cell9",`, 1)},
		{"unknown_field", strings.Replace(rendered, `"cell_id":"cell0",`, `"cell_id":"cell0","unexpected_field":true,`, 1)},
		{"trailing_input", rendered + `{"trailing":true}`},
	}
}

// seedFaultAgentIdentity drives one deliberately unanswered registration so the
// store holds the driver's own persisted device identity, and returns that
// agent's X25519 public key. It is how a loopback Hub can be keyed to open
// packets the public registration driver signs with a key it minted itself. The
// attempt must leave durable state at initial identity only.
func seedFaultAgentIdentity(ctx context.Context, t *testing.T, store qurl.AgentStateStore, agentID string, httpTrap *lifecycleHTTPTrap) []byte {
	t.Helper()
	_, serverPub := mustNHPKeypair(t)
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(qurl.HubBootstrap{
			Host:               "identity-seed-proof.nhp.layerv.ai",
			Port:               standardNHPUDPPort,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(serverPub),
		}),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "identity-seed"),
		qurl.WithAgentRuntimeUDPResolver(&fixedResolver{address: netip.MustParseAddr("8.8.8.8")}),
		qurl.WithAgentRuntimeUDPDialer(&redirectingDialer{target: startUDPBlackhole(t).LocalAddr().String()}),
		qurl.WithAgentRuntimeUDPBounds(150*time.Millisecond, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(1, 10*time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || err == nil {
		t.Fatalf("identity seed attempt = client_non_nil=%t err=%v; want an unanswered Hub to fail", client != nil, err)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "identity_seed")
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		t.Fatalf("load seeded identity: %v", err)
	}
	agentPub, err := base64.StdEncoding.Strict().DecodeString(state.PublicKeyB64)
	if err != nil || len(agentPub) != x25519PublicKeyLength {
		t.Fatalf("seeded agent public key = %q (%d bytes decoded), want a canonical %d-byte X25519 key: %v",
			state.PublicKeyB64, len(agentPub), x25519PublicKeyLength, err)
	}
	return agentPub
}

// hostRoutedResolver answers each host with its own public address, so the Hub
// and the assigned cell are separately routable and a datagram sent to either is
// unambiguously attributable.
type hostRoutedResolver struct {
	answers map[string]netip.Addr

	mu    sync.Mutex
	calls int
}

func (r *hostRoutedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	addr, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []netip.Addr{addr}, nil
}

// proveAuthenticatedInvalidAssignmentMatrix proves the SDK refuses every
// authenticated-but-invalid Hub assignment. Each case is delivered by a Hub that
// completes the full two-leg return-routability profile and signs the final
// NHP_LRT with the pinned key, so nothing about the transport or the
// authentication is at fault — only the assignment content is. Every case is a
// definitive ErrAssignmentInvalidResponse and never a retryable
// transport/resolve miss. A conforming baseline through the identical harness is
// the control, so the matrix cannot pass vacuously. Finally the public
// registration driver is driven with an invalid assignment and must persist
// nothing and send no assigned-cell datagram.
func proveAuthenticatedInvalidAssignmentMatrix(ctx context.Context, t *testing.T, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const (
		agentID  = "qurl-go-fault-proof-assignment-matrix"
		hubHost  = "assignment-matrix-proof.nhp.layerv.ai"
		cellHost = "cell0.nhp.layerv.ai"
	)
	baseline, cases := hubAssignmentMatrix(t, agentID, cellHost, standardNHPUDPPort)

	// runAssignment drives one authenticated Hub answer through the exported
	// assignment fetch and reports what the SDK made of it.
	runAssignment := func(t *testing.T, body string) (*qurl.InitialAgentAssignment, int, error) {
		t.Helper()
		exchange := newCookieRoutabilityExchange(t, hubAssignmentRoutability, cookieRoutabilityConfig{resultBody: []byte(body)})
		hub := qurl.HubBootstrap{
			Host:               hubHost,
			Port:               standardNHPUDPPort,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(exchange.endpoint.ServerStaticPub),
		}
		assignment, err := qurl.FetchInitialAgentAssignment(ctx, hub, agentID, nonSecretFaultCredential, nativeudp.Options{
			DeviceStaticPriv: exchange.options.DeviceStaticPriv,
			Resolver:         &fixedResolver{address: netip.MustParseAddr("8.8.8.8")},
			Dialer:           &redirectingDialer{target: net.JoinHostPort("127.0.0.1", strconv.Itoa(exchange.endpoint.Port))},
			Timeout:          2 * time.Second,
			MaxAddresses:     1,
		})
		_, _, packets, _, _ := exchange.server.snapshot()
		return assignment, len(packets), err
	}

	// Control: the identical harness must accept a conforming assignment, so a
	// rejection below is attributable to the injected defect alone.
	assignment, flights, err := runAssignment(t, baseline.render())
	if err != nil || assignment == nil {
		t.Fatalf("conforming assignment control = assignment %v, err %v; want the baseline body accepted (the matrix would otherwise pass vacuously)", assignment, err)
	}
	if assignment.Assignment.CellID != "cell0" || assignment.Assignment.Endpoint.Host != cellHost {
		t.Fatalf("conforming assignment control returned %#v, want the baseline cell binding", assignment.Assignment)
	}
	if flights != 2 {
		t.Fatalf("conforming assignment control used %d flights, want the 2-flight return-routability profile", flights)
	}

	for _, invalid := range cases {
		t.Run(invalid.name, func(t *testing.T) {
			assignment, flights, err := runAssignment(t, invalid.body)
			if assignment != nil {
				t.Fatalf("%s returned an assignment: %#v", invalid.name, assignment)
			}
			if !errors.Is(err, qurl.ErrAssignmentInvalidResponse) {
				t.Fatalf("%s error = %v, want errors.Is qurl.ErrAssignmentInvalidResponse", invalid.name, err)
			}
			if errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve) {
				t.Fatalf("%s recast an authenticated invalid assignment as a retryable transport miss: %v", invalid.name, err)
			}
			if errors.Is(err, nativeudp.ErrServerUnauthenticated) {
				t.Fatalf("%s conflated an authenticated invalid assignment with the unauthenticated class: %v", invalid.name, err)
			}
			// An invalid assignment is terminal, so the bounded outer retry must
			// not re-drive the Hub: exactly the two flights of one profile run.
			if flights != 2 {
				t.Fatalf("%s used %d Hub flights, want exactly 2 (an invalid assignment is terminal, not retried)", invalid.name, flights)
			}
		})
	}
	// An expired lease is additionally distinguishable by its own sentinel.
	if _, _, err := runAssignment(t, baseline.with(func(b *hubAssignmentWireBody) {
		b.leaseExpiresAt = time.Now().UTC().Truncate(time.Second).Add(-time.Minute).Format(time.RFC3339)
		b.ticketExpiresAt = time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute).Format(time.RFC3339)
	})); !errors.Is(err, qurl.ErrAssignmentLeaseExpired) {
		t.Fatalf("expired lease error = %v, want errors.Is qurl.ErrAssignmentLeaseExpired alongside the invalid-response class", err)
	}

	// The public registration driver persists nothing and never reaches the cell.
	// It mints its own device identity, so the Hub responder is keyed from the
	// identity a first, deliberately unanswered attempt leaves in the store.
	store := faultStateStore(t)
	agentPub := seedFaultAgentIdentity(ctx, t, store, agentID, httpTrap)
	hubExchange := newCookieRoutabilityExchangeForAgent(t, hubAssignmentRoutability, nil, agentPub, cookieRoutabilityConfig{
		resultBody: []byte(baseline.with(func(b *hubAssignmentWireBody) {
			b.host = "assignment-proof.attacker.example.com"
		})),
	})
	cell, cellEP, _ := newLoopbackNHPFaultExchange(t, loopbackFaultConfig{})
	hubAddress := netip.MustParseAddr("8.8.8.8")
	cellAddress := netip.MustParseAddr("9.9.9.9")
	dialer := &routingDialer{routes: map[string]string{
		netip.AddrPortFrom(hubAddress, standardNHPUDPPort).String():  net.JoinHostPort("127.0.0.1", strconv.Itoa(hubExchange.endpoint.Port)),
		netip.AddrPortFrom(cellAddress, standardNHPUDPPort).String(): net.JoinHostPort("127.0.0.1", strconv.Itoa(cellEP.Port)),
	}}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(qurl.HubBootstrap{
			Host:               hubHost,
			Port:               standardNHPUDPPort,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(hubExchange.endpoint.ServerStaticPub),
		}),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "authenticated-invalid-assignment-matrix"),
		qurl.WithAgentRuntimeUDPResolver(&hostRoutedResolver{answers: map[string]netip.Addr{
			hubHost:  hubAddress,
			cellHost: cellAddress,
		}}),
		qurl.WithAgentRuntimeUDPDialer(dialer),
		qurl.WithAgentRuntimeUDPBounds(2*time.Second, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(2, 30*time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	if client != nil || bindingNonNil || !errors.Is(err, qurl.ErrAssignmentInvalidResponse) {
		t.Fatalf("invalid-assignment registration mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t invalid_response=%t err=%v",
			err, client != nil, bindingNonNil, errors.Is(err, qurl.ErrAssignmentInvalidResponse), err)
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("invalid-assignment registration reflected the enrollment credential")
	}
	if got := cell.receivedCount(); got != 0 {
		t.Fatalf("invalid-assignment registration sent %d assigned-cell datagrams, want 0 (a rejected assignment is never dialed)", got)
	}
	// Stronger than a silent cell: the rejected endpoint is never even dialed.
	cellDialAddress := netip.AddrPortFrom(cellAddress, standardNHPUDPPort).String()
	if dialed := dialer.snapshot(); slices.Contains(dialed, cellDialAddress) {
		t.Fatalf("invalid-assignment registration dialed the rejected assigned cell %q; dial sequence = %q", cellDialAddress, dialed)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "authenticated_invalid_assignment_matrix")

	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE authenticated_invalid_assignment_matrix conforming_control=accepted invalid_cases=%d rejection=ErrAssignmentInvalidResponse expired_lease_sentinel=ErrAssignmentLeaseExpired retryable_recast=0 unauthenticated_conflation=0 hub_flights_per_case=2 persisted_assignments=0 assigned_cell_datagrams=0 lifecycle_http_calls=0",
		len(cases))
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
