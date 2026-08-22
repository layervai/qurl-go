package nativeudp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// This file covers the two session-control entry points over real loopback
// sockets: KnockWithReknock's KNK->COK->RKN->ACK sequence and Exit's single
// NHP_EXT transaction. The responder here opens RKN with the exact cookie it
// issued, so a re-knock the transport failed to bind to that cookie never
// reaches a reply at all.

var (
	sessionCookie      = bytes.Repeat([]byte{0x5a}, 32)
	sessionOtherCookie = bytes.Repeat([]byte{0xa5}, 32)
)

type sessionBehavior int

const (
	sessionCookieThenACK          sessionBehavior = iota // COK for KNK, counter-echoing ACK for RKN
	sessionDirectACK                                     // ACK for KNK; no cookie challenge at all
	sessionCookieWrongTransaction                        // COK whose body trxId is not the KNK counter
	sessionCookieMalformedBody                           // COK whose body is not one strict JSON object
	sessionCookieShortCookie                             // COK whose cookie decodes to 31 bytes
	sessionCookieWrongKey                                // COK signed by a key the endpoint does not pin
	sessionSecondCookie                                  // a second COK answers the RKN
	sessionReknockWrongType                              // NHP_RAK answers the RKN
	sessionReknockWrongCounter                           // ACK that does not echo the RKN counter
	sessionReknockWrongKey                               // RKN ACK signed by another static key
	sessionReknockSilent                                 // the RKN is never answered
)

// sessionServer answers one native session-control sequence. Unlike fakeServer
// it can open NHP_RKN, which requires the exact cookie from its own COK.
type sessionServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	altPriv    []byte
	agentPub   []byte
	behavior   sessionBehavior
	done       chan struct{}

	mu       sync.Mutex
	types    []int
	bodies   [][]byte
	counters []uint64
}

func newSessionServer(t *testing.T, serverPriv, agentPub []byte, behavior sessionBehavior) *sessionServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	server := &sessionServer{
		t: t, conn: conn, serverPriv: serverPriv, altPriv: mustPriv(t),
		agentPub: agentPub, behavior: behavior, done: make(chan struct{}),
	}
	go server.serve()
	t.Cleanup(func() {
		// The socket may already be closed by a test that kills the responder
		// mid-sequence; a second Close is harmless and keeps the wait uniform.
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("session server did not stop after socket close")
		}
	})
	return server
}

func (s *sessionServer) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *sessionServer) target() string { return s.conn.LocalAddr().String() }

func (s *sessionServer) snapshot() (types []int, bodies [][]byte, counters []uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bodies = make([][]byte, len(s.bodies))
	for i := range s.bodies {
		bodies[i] = bytes.Clone(s.bodies[i])
	}
	return append([]int(nil), s.types...), bodies, append([]uint64(nil), s.counters...)
}

func (s *sessionServer) serve() {
	defer close(s.done)
	buffer := make([]byte, 1<<16)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return // conn closed
		}
		packet := bytes.Clone(buffer[:n])
		request, err := s.open(packet)
		if err != nil {
			s.t.Errorf("open session packet: %v", err)
			continue
		}
		s.mu.Lock()
		s.types = append(s.types, request.Type)
		s.bodies = append(s.bodies, bytes.Clone(request.Body))
		s.counters = append(s.counters, request.Counter)
		s.mu.Unlock()

		reply := s.reply(request)
		if reply == nil {
			continue
		}
		if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
			s.t.Logf("write session reply: %v", err)
		}
	}
}

// open accepts an ordinary initiator packet, falling back to the cookie-bound
// NHP_RKN open. A re-knock that opens under a cookie this server never issued
// would mean the header digest is not actually bound to the challenge.
func (s *sessionServer) open(packet []byte) (*relayknock.Reply, error) {
	if request, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, packet); err == nil {
		return request, nil
	}
	request, err := relayknocktest.OpenReknockMessage(s.serverPriv, s.agentPub, sessionCookie, packet)
	if err != nil {
		return nil, err
	}
	if _, err := relayknocktest.OpenReknockMessage(s.serverPriv, s.agentPub, sessionOtherCookie, packet); err == nil {
		s.t.Error("NHP_RKN opened under a cookie this server never issued: the header digest is not cookie-bound")
	}
	return request, nil
}

func (s *sessionServer) reply(request *relayknock.Reply) []byte {
	if request.Type == relayknock.TypeReknock {
		return s.reknockReply(request.Counter)
	}
	return s.knockReply(request.Counter)
}

func (s *sessionServer) knockReply(counter uint64) []byte {
	body := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter, base64.StdEncoding.EncodeToString(sessionCookie)))
	serverPriv := s.serverPriv
	switch s.behavior {
	case sessionDirectACK:
		return s.build(relayknock.TypeACK, s.serverPriv, counter, []byte(`{"admitted":true}`))
	case sessionCookieWrongTransaction:
		body = []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter+1, base64.StdEncoding.EncodeToString(sessionCookie)))
	case sessionCookieMalformedBody:
		body = []byte(`{"trxId":`)
	case sessionCookieShortCookie:
		body = []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter, base64.StdEncoding.EncodeToString(sessionCookie[:31])))
	case sessionCookieWrongKey:
		serverPriv = s.altPriv
	}
	// The COK's own wire counter is deliberately unconstrained: only body.trxId
	// correlates the challenge to the KNK, so answer on a counter that differs.
	return s.build(relayknock.TypeCookieChallenge, serverPriv, counter+99, body)
}

func (s *sessionServer) reknockReply(counter uint64) []byte {
	switch s.behavior {
	case sessionReknockSilent:
		return nil
	case sessionSecondCookie:
		body := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter, base64.StdEncoding.EncodeToString(sessionCookie)))
		return s.build(relayknock.TypeCookieChallenge, s.serverPriv, counter, body)
	case sessionReknockWrongType:
		return s.build(relayknock.TypeRegisterAck, s.serverPriv, counter, []byte(`{"admitted":true}`))
	case sessionReknockWrongCounter:
		return s.build(relayknock.TypeACK, s.serverPriv, counter+1, []byte(`{"admitted":true}`))
	case sessionReknockWrongKey:
		return s.build(relayknock.TypeACK, s.altPriv, counter, []byte(`{"admitted":true}`))
	default:
		return s.build(relayknock.TypeACK, s.serverPriv, counter, []byte(`{"admitted":true}`))
	}
}

func (s *sessionServer) build(replyType int, serverPriv []byte, counter uint64, body []byte) []byte {
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         mustPreamble(s.t),
		Body:             body,
	})
	if err != nil {
		s.t.Errorf("build session reply: %v", err)
		return nil
	}
	return packet
}

// countingResolver answers each lookup from answers in turn (the last answer
// repeats) and records how many lookups the transport performed, which is how a
// test proves each exchange re-resolved rather than reusing a cached address.
type countingResolver struct {
	answers [][]netip.Addr

	mu    sync.Mutex
	calls int
}

func (r *countingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	answer := r.answers[min(r.calls, len(r.answers)-1)]
	r.calls++
	return answer, nil
}

func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// sessionDialer routes every dial to one target and can run a hook before the
// Nth dial, which lets a test kill the responder between two legs of a sequence.
type sessionDialer struct {
	mu         sync.Mutex
	target     string
	calls      int
	beforeDial func(call int)
}

func (d *sessionDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	hook := d.beforeDial
	d.mu.Unlock()
	if hook != nil {
		hook(call)
	}
	d.mu.Lock()
	target := d.target
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (d *sessionDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func sessionSetup(t *testing.T, behavior sessionBehavior) (*sessionServer, nativeudp.Endpoint, nativeudp.Options, *sessionDialer, *countingResolver) {
	t.Helper()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newSessionServer(t, serverPriv, pubOf(t, devicePriv), behavior)
	dialer := &sessionDialer{target: server.target()}
	resolver := &countingResolver{answers: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8")}}}
	return server,
		nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub},
		nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: resolver, Dialer: dialer, Timeout: 2 * time.Second},
		dialer, resolver
}

func TestKnockWithReknock_CookieBoundSequence(t *testing.T) {
	t.Parallel()
	server, endpoint, options, dialer, resolver := sessionSetup(t, sessionCookieThenACK)
	knockBody := []byte(`{"leg":"knock","resource":"demo"}`)
	reknockBody := []byte(`{"leg":"reknock","resource":"demo"}`)

	reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, knockBody, reknockBody, options)
	if err != nil {
		t.Fatalf("KnockWithReknock: %v", err)
	}
	if !reply.IsACK() || string(reply.Body) != `{"admitted":true}` {
		t.Fatalf("final reply type/body = %d/%q, want ACK/{\"admitted\":true}", reply.Type, reply.Body)
	}

	types, bodies, counters := server.snapshot()
	wantTypes := []int{relayknock.TypeKnock, relayknock.TypeReknock}
	if len(types) != 2 || types[0] != wantTypes[0] || types[1] != wantTypes[1] {
		t.Fatalf("request types = %v, want %v", types, wantTypes)
	}
	// The transport never rewrites headerType inside an authenticated body: each
	// leg carries exactly the bytes the caller supplied for it.
	if !bytes.Equal(bodies[0], knockBody) || !bytes.Equal(bodies[1], reknockBody) {
		t.Fatalf("request bodies = %q / %q, want %q / %q", bodies[0], bodies[1], knockBody, reknockBody)
	}
	if counters[0] == counters[1] {
		t.Fatalf("RKN reused the KNK counter %d; each leg needs fresh message randomness", counters[0])
	}
	// KNK and RKN are separate exchanges, so the host is resolved again for RKN.
	if resolver.count() != 2 || dialer.count() != 2 {
		t.Fatalf("lookups/dials = %d/%d, want 2/2 (fresh DNS and a fresh socket per leg)", resolver.count(), dialer.count())
	}
}

func TestKnockWithReknock_DirectACKSkipsReknock(t *testing.T) {
	t.Parallel()
	server, endpoint, options, dialer, resolver := sessionSetup(t, sessionDirectACK)

	reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, []byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`), options)
	if err != nil || !reply.IsACK() {
		t.Fatalf("direct ACK reply/error = %#v/%v, want an ACK", reply, err)
	}
	types, _, _ := server.snapshot()
	if len(types) != 1 || types[0] != relayknock.TypeKnock {
		t.Fatalf("request types = %v, want one NHP_KNK: an admitted knock must not emit RKN", types)
	}
	if resolver.count() != 1 || dialer.count() != 1 {
		t.Fatalf("lookups/dials = %d/%d, want 1/1", resolver.count(), dialer.count())
	}
}

// TestKnockWithReknock_ReknockFollowsFreshDNSToAnotherReplica pins the documented
// replica behavior: because DNS is resolved again for RKN, the second leg may
// land on a different cell replica. Both replicas share the pinned static key and
// the stateless COK-signing key, so the re-knock still authenticates.
func TestKnockWithReknock_ReknockFollowsFreshDNSToAnotherReplica(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	agentPub := pubOf(t, devicePriv)
	first := newSessionServer(t, serverPriv, agentPub, sessionCookieThenACK)
	second := newSessionServer(t, serverPriv, agentPub, sessionCookieThenACK)

	firstAddr := netip.MustParseAddr("9.9.9.9")
	secondAddr := netip.MustParseAddr("149.112.112.112")
	const assignedPort = 443
	resolver := &countingResolver{answers: [][]netip.Addr{{firstAddr}, {secondAddr}}}
	dialer := &addressRoutingDialer{routes: map[string]string{
		netip.AddrPortFrom(firstAddr, assignedPort).String():  first.target(),
		netip.AddrPortFrom(secondAddr, assignedPort).String(): second.target(),
	}}
	endpoint := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
	options := nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: resolver, Dialer: dialer, Timeout: 2 * time.Second}

	reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, []byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`), options)
	if err != nil || !reply.IsACK() {
		t.Fatalf("cross-replica reply/error = %#v/%v, want an ACK", reply, err)
	}
	firstTypes, _, _ := first.snapshot()
	secondTypes, _, _ := second.snapshot()
	if len(firstTypes) != 1 || firstTypes[0] != relayknock.TypeKnock {
		t.Fatalf("first replica saw %v, want only the NHP_KNK", firstTypes)
	}
	if len(secondTypes) != 1 || secondTypes[0] != relayknock.TypeReknock {
		t.Fatalf("second replica saw %v, want only the NHP_RKN: DNS was not re-resolved before RKN", secondTypes)
	}
}

func TestKnockWithReknock_RejectionsAreTerminal(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		behavior sessionBehavior
		want     error
		flights  int
	}{
		{name: "cookie transaction mismatch", behavior: sessionCookieWrongTransaction, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "malformed cookie body", behavior: sessionCookieMalformedBody, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "short cookie", behavior: sessionCookieShortCookie, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "cookie from an unpinned key", behavior: sessionCookieWrongKey, want: nativeudp.ErrServerUnauthenticated, flights: 1},
		{name: "second cookie challenge", behavior: sessionSecondCookie, want: relayknock.ErrMalformedReply, flights: 2},
		{name: "reknock answered with RAK", behavior: sessionReknockWrongType, want: relayknock.ErrMalformedReply, flights: 2},
		{name: "reknock ACK counter mismatch", behavior: sessionReknockWrongCounter, want: relayknock.ErrMalformedReply, flights: 2},
		{name: "reknock ACK from an unpinned key", behavior: sessionReknockWrongKey, want: nativeudp.ErrServerUnauthenticated, flights: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server, endpoint, options, dialer, _ := sessionSetup(t, test.behavior)

			reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, []byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`), options)
			if reply != nil || !errors.Is(err, test.want) {
				t.Fatalf("reply/error = %#v/%v, want nil/errors.Is(%v)", reply, err, test.want)
			}
			types, _, _ := server.snapshot()
			if len(types) != test.flights || dialer.count() != test.flights {
				t.Fatalf("flights/dials = %d/%d, want exactly %d: a rejected leg must not retry or fall through", len(types), dialer.count(), test.flights)
			}
		})
	}
}

// TestKnockWithReknock_ResponderRestartsBetweenLegs kills the cell process after
// it has issued the authenticated COK. The re-knock must fail as a transport
// fault, and no partial state (the KNK's own reply, or an unauthenticated
// substitute) may be returned in its place.
func TestKnockWithReknock_ResponderRestartsBetweenLegs(t *testing.T) {
	t.Parallel()
	server, endpoint, options, dialer, _ := sessionSetup(t, sessionCookieThenACK)
	// The socket deadline bounds the case where the platform answers a dead port
	// with silence instead of ICMP; either way the outcome class is the same.
	options.Timeout = 300 * time.Millisecond
	dialer.beforeDial = func(call int) {
		if call == 2 {
			// Synchronously before the RKN datagram is written: the responder that
			// issued the cookie is gone by the time the second leg starts.
			_ = server.conn.Close()
		}
	}

	reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, []byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`), options)
	if reply != nil {
		t.Fatalf("reply = %#v, want nil: a dead responder must not yield an admitted session", reply)
	}
	if !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
	if errors.Is(err, nativeudp.ErrServerUnauthenticated) || errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("a missing reply was classified as a received datagram: %v", err)
	}
	types, _, _ := server.snapshot()
	if len(types) != 1 || types[0] != relayknock.TypeKnock {
		t.Fatalf("responder saw %v, want only the NHP_KNK it answered before dying", types)
	}
}

func TestKnockWithReknock_SilentReknockIsTransportFailure(t *testing.T) {
	t.Parallel()
	server, endpoint, options, _, _ := sessionSetup(t, sessionReknockSilent)
	options.Timeout = 150 * time.Millisecond

	reply, err := nativeudp.KnockWithReknock(context.Background(), endpoint, []byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`), options)
	if reply != nil || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("silent reknock reply/error = %#v/%v, want nil/ErrTransport", reply, err)
	}
	types, _, _ := server.snapshot()
	if len(types) != 2 || types[1] != relayknock.TypeReknock {
		t.Fatalf("responder saw %v, want the RKN to have been sent", types)
	}
}

func TestKnockWithReknock_ValidatesBothLegsBeforeIO(t *testing.T) {
	t.Parallel()
	_, endpoint, options, dialer, _ := sessionSetup(t, sessionCookieThenACK)
	//nolint:staticcheck // deliberately passing a nil context to prove it fails closed.
	if _, err := nativeudp.KnockWithReknock(nil, endpoint, nil, nil, options); !errors.Is(err, nativeudp.ErrInvalidRequest) {
		t.Fatalf("nil-context error = %v, want ErrInvalidRequest", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nativeudp.KnockWithReknock(ctx, endpoint, nil, nil, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled-context error = %v, want context.Canceled", err)
	}
	if dialer.count() != 0 {
		t.Fatalf("dials = %d, want 0: validation precedes all I/O", dialer.count())
	}
}

func TestExit_AcceptsOnlyCounterEchoingACK(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		behavior behavior
		want     error
	}{
		{name: "counter-echoing ACK", behavior: behaviorNormal},
		{name: "cookie challenge", behavior: behaviorCookie, want: relayknock.ErrMalformedReply},
		{name: "cookie challenge on another counter", behavior: behaviorCookieWrongCounter, want: relayknock.ErrMalformedReply},
		{name: "ACK counter mismatch", behavior: behaviorWrongCounter, want: relayknock.ErrMalformedReply},
		{name: "wrong reply type", behavior: behaviorWrongType, want: relayknock.ErrMalformedReply},
		{name: "unpinned server key", behavior: behaviorWrongKey, want: nativeudp.ErrServerUnauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server, endpoint, options := newLoopbackExchange(t, test.behavior)
			reply, err := nativeudp.Exit(context.Background(), endpoint, []byte(`{"reason":"clean"}`), options)
			if test.want == nil {
				if err != nil || !reply.IsACK() || string(reply.Body) != `{"ok":true}` {
					t.Fatalf("Exit reply/error = %#v/%v, want an ACK", reply, err)
				}
			} else if reply != nil || !errors.Is(err, test.want) {
				t.Fatalf("Exit reply/error = %#v/%v, want nil/errors.Is(%v)", reply, err, test.want)
			}
			if got := server.receivedTypes(); len(got) != 1 || got[0] != relayknock.TypeExit {
				t.Fatalf("received types = %v, want [%d] (NHP_EXT)", got, relayknock.TypeExit)
			}
		})
	}
}

func TestExit_SilentResponderIsTransportFailure(t *testing.T) {
	t.Parallel()
	_, endpoint, options := newLoopbackExchange(t, behaviorSilent)
	options.Timeout = 150 * time.Millisecond
	reply, err := nativeudp.Exit(context.Background(), endpoint, nil, options)
	if reply != nil || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("silent exit reply/error = %#v/%v, want nil/ErrTransport", reply, err)
	}
}
