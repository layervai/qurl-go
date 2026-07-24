package nativeudp_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

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
	respondCorrectly nhpResponder = iota // authenticated reply of the correct type
	respondWrongKey                      // authenticated reply built with a different server static key
	respondOversize                      // a datagram larger than the 4096-byte NHP buffer
)

// loopbackNHPServer is a loopback NHP responder. It opens the agent's initiator
// packet with the responder-role helpers and answers according to its configured
// behavior, recording how many initiator datagrams it received.
type loopbackNHPServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	altPriv    []byte // used by respondWrongKey to sign under an unpinned key
	agentPub   []byte
	behavior   nhpResponder
	done       chan struct{}

	mu       sync.Mutex
	received int
}

func newLoopbackNHPServer(t *testing.T, serverPriv, agentPub []byte, behavior nhpResponder) *loopbackNHPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &loopbackNHPServer{
		t:          t,
		conn:       conn,
		serverPriv: serverPriv,
		altPriv:    mustNHPPriv(t),
		agentPub:   agentPub,
		behavior:   behavior,
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
		if _, err := s.conn.WriteToUDP(resp, raddr); err != nil {
			s.t.Logf("loopback server: write reply: %v", err)
		}
	}
}

func (s *loopbackNHPServer) buildResponse(msg *relayknock.Reply) []byte {
	switch s.behavior {
	case respondOversize:
		// A datagram one full NHP buffer over the 4096-byte ceiling; the client
		// reads PacketBufferSize+1 bytes and rejects it before any decrypt.
		return mustNHPRand(s.t, 5000)
	case respondWrongKey:
		return s.buildReply(nhpReplyTypeFor(msg.Type), s.altPriv, msg.Counter)
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
func newLoopbackNHPExchange(t *testing.T, behavior nhpResponder) (*loopbackNHPServer, nativeudp.Endpoint, nativeudp.Options) {
	t.Helper()
	serverPriv, serverPub := mustNHPKeypair(t)
	devicePriv := mustNHPPriv(t)
	srv := newLoopbackNHPServer(t, serverPriv, nhpPubOf(t, devicePriv), behavior)
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
}

func hubAndCellExchanges() []nhpExchange {
	return []nhpExchange{
		{"hub_assignment_lst", nativeudp.AssignmentList},
		{"assigned_cell_knock", nativeudp.Knock},
		{"assigned_cell_register", nativeudp.Register},
		{"assigned_cell_exit", nativeudp.Exit},
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
