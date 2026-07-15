package nativeudp_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// This file exercises the native-UDP transport end to end over real loopback
// sockets against a responder built with relayknocktest (the server-role mirror of
// relayknock). Run with -race to fence the socket/cancellation paths.

// behavior selects how the fake server answers one initiator datagram.
type behavior int

const (
	behaviorNormal       behavior = iota // correct reply type, echoed counter
	behaviorCookie                       // NHP_COK overload cookie-challenge
	behaviorWrongCounter                 // correct type, counter+1
	behaviorWrongType                    // the other reply type (KNK->RAK, REG->ACK)
	behaviorWrongKey                     // built with a different server static key
	behaviorGarbage                      // random non-NHP bytes
	behaviorEmpty                        // zero-length datagram
	behaviorTooShort                     // a sub-header-length datagram
	behaviorOversize                     // a datagram larger than the NHP buffer
	behaviorSilent                       // never reply
)

// fakeServer is a loopback NHP responder. It opens the agent's initiator packet
// and answers according to behavior. It records how many datagrams it received.
type fakeServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	altPriv    []byte // used by behaviorWrongKey
	agentPub   []byte
	behavior   behavior
	replyBody  []byte
	done       chan struct{}

	mu       sync.Mutex
	received int
}

func newFakeServer(t *testing.T, serverPriv, agentPub []byte, b behavior) *fakeServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &fakeServer{
		t:          t,
		conn:       conn,
		serverPriv: serverPriv,
		altPriv:    mustPriv(t),
		agentPub:   agentPub,
		behavior:   b,
		replyBody:  []byte(`{"ok":true}`),
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
			t.Error("fake UDP server did not stop after socket close")
		}
	})
	return s
}

func (s *fakeServer) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *fakeServer) receivedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received
}

func (s *fakeServer) serve() {
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
			s.t.Logf("server: open initiator: %v", err)
			continue
		}
		resp := s.buildResponse(msg)
		if resp == nil {
			continue // silent
		}
		if _, err := s.conn.WriteToUDP(resp, raddr); err != nil {
			s.t.Logf("server: write reply: %v", err)
		}
	}
}

func (s *fakeServer) buildResponse(msg *relayknock.Reply) []byte {
	normalType := replyTypeFor(msg.Type)
	switch s.behavior {
	case behaviorSilent:
		return nil
	case behaviorGarbage:
		return mustRand(s.t, 400)
	case behaviorEmpty:
		return []byte{}
	case behaviorTooShort:
		return mustRand(s.t, 100)
	case behaviorOversize:
		return mustRand(s.t, 5000)
	case behaviorWrongKey:
		return s.buildReply(normalType, s.altPriv, msg.Counter)
	case behaviorWrongCounter:
		return s.buildReply(normalType, s.serverPriv, msg.Counter+1)
	case behaviorWrongType:
		other := relayknock.TypeRegisterAck
		if msg.Type == relayknock.TypeRegister {
			other = relayknock.TypeACK
		}
		return s.buildReply(other, s.serverPriv, msg.Counter)
	case behaviorCookie:
		return s.buildReply(relayknock.TypeCookieChallenge, s.serverPriv, msg.Counter)
	default: // behaviorNormal
		return s.buildReply(normalType, s.serverPriv, msg.Counter)
	}
}

// buildReply builds a server-originated reply of replyType, signed by serverPriv,
// echoing counter. Roles are swapped relative to a knock: DeviceStaticPriv is the
// server static private key and ServerStaticPub is the agent static public key.
func (s *fakeServer) buildReply(replyType int, serverPriv []byte, counter uint64) []byte {
	packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustRandGlobal(32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         mustPreamble(),
		Body:             s.replyBody,
	})
	if err != nil {
		s.t.Errorf("build reply: %v", err)
		return nil
	}
	return packet
}

func replyTypeFor(initiatorType int) int {
	if initiatorType == relayknock.TypeRegister {
		return relayknock.TypeRegisterAck
	}
	return relayknock.TypeACK
}

// loopback returns a globally routable address so the production transport's
// non-public-address rejection remains active in tests. loopbackDialer never
// dials it; it maps that synthetic destination to the local fake server.
type loopback struct{}

func (loopback) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type loopbackDialer struct{}

func (loopbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}

func loopbackOptions(devicePriv []byte) nativeudp.Options {
	return nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: loopback{}, Dialer: loopbackDialer{}, Timeout: 2 * time.Second}
}

func newLoopbackExchange(t *testing.T, b behavior) (*fakeServer, nativeudp.Endpoint, nativeudp.Options) {
	t.Helper()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	srv := newFakeServer(t, serverPriv, pubOf(t, devicePriv), b)
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: srv.port(), ServerStaticPub: serverPub}
	return srv, ep, loopbackOptions(devicePriv)
}

func TestExchange_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		reqType int
	}{
		{"knock -> ack", relayknock.TypeKnock},
		{"register -> rak", relayknock.TypeRegister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, ep, opts := newLoopbackExchange(t, behaviorNormal)

			reply, err := nativeudp.Exchange(context.Background(), ep, tc.reqType, []byte(`{"body":1}`), opts)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if tc.reqType == relayknock.TypeKnock && !reply.IsACK() {
				t.Fatalf("reply type = %d, want ACK", reply.Type)
			}
			if tc.reqType == relayknock.TypeRegister && !reply.IsRegisterAck() {
				t.Fatalf("reply type = %d, want RAK", reply.Type)
			}
			if string(reply.Body) != `{"ok":true}` {
				t.Fatalf("reply body = %q", reply.Body)
			}
		})
	}
}

func TestKnockAndRegisterHelpers(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorNormal)

	ack, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if err != nil || !ack.IsACK() {
		t.Fatalf("Knock: reply=%v err=%v", ack, err)
	}
	rak, err := nativeudp.Register(context.Background(), ep, nil, opts)
	if err != nil || !rak.IsRegisterAck() {
		t.Fatalf("Register: reply=%v err=%v", rak, err)
	}
}

func TestExchange_CookieChallengeIsRetryable(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorCookie)

	reply, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if err != nil {
		t.Fatalf("Knock returned error for cookie-challenge, want retryable reply: %v", err)
	}
	if !reply.IsCookieChallenge() {
		t.Fatalf("reply type = %d, want NHP_COK cookie-challenge", reply.Type)
	}
}

func TestExchange_RejectsBadReplies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		beh     behavior
		reqType int
		wantIs  error
	}{
		{"wrong server key", behaviorWrongKey, relayknock.TypeKnock, nativeudp.ErrServerUnauthenticated},
		{"garbage datagram", behaviorGarbage, relayknock.TypeKnock, nativeudp.ErrServerUnauthenticated},
		{"too short datagram", behaviorTooShort, relayknock.TypeKnock, nativeudp.ErrServerUnauthenticated},
		{"oversize datagram", behaviorOversize, relayknock.TypeKnock, nativeudp.ErrServerUnauthenticated},
		{"wrong counter", behaviorWrongCounter, relayknock.TypeKnock, relayknock.ErrMalformedReply},
		{"wrong reply type", behaviorWrongType, relayknock.TypeRegister, relayknock.ErrMalformedReply},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, ep, opts := newLoopbackExchange(t, tc.beh)

			_, err := nativeudp.Exchange(context.Background(), ep, tc.reqType, nil, opts)
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("error = %v, want errors.Is %v", err, tc.wantIs)
			}
			if errors.Is(tc.wantIs, nativeudp.ErrServerUnauthenticated) && errors.Is(err, relayknock.ErrMalformedReply) {
				t.Fatalf("decrypt-stage error exposed ErrMalformedReply instead of only ErrServerUnauthenticated: %v", err)
			}
		})
	}
}

func TestExchange_TimeoutWhenSilent(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorSilent)
	opts.Timeout = 150 * time.Millisecond

	start := time.Now()
	_, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s, want ~150ms", elapsed)
	}
}

func TestExchange_CancellationUnblocksRead(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorSilent)
	opts.Timeout = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := nativeudp.Knock(ctx, ep, nil, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("cancellation took %s, want prompt unblock (~100ms)", elapsed)
	}
}

// TestExchange_MultiAddressFallback proves a transport fault against the first
// resolved address falls through to the next, while a bad reply does not.
func TestExchange_MultiAddressFallback(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	srv := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)
	port := srv.port()

	bad := netip.MustParseAddr("1.1.1.1")
	good := netip.MustParseAddr("1.0.0.1")
	res := resolverReturning([]netip.Addr{bad, good})

	badAddr := netip.AddrPortFrom(bad, uint16(port)).String()
	dialer := &sequencedDialer{fail: map[string]bool{badAddr: true}, real: loopbackDialer{}}

	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: port, ServerStaticPub: serverPub}
	opts := nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: res, Dialer: dialer, Timeout: 2 * time.Second}

	reply, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if err != nil {
		t.Fatalf("Knock did not fall through to the reachable address: %v", err)
	}
	if !reply.IsACK() {
		t.Fatalf("reply type = %d, want ACK", reply.Type)
	}
	if !dialer.dialed(badAddr) {
		t.Fatal("expected the bad address to be attempted first")
	}
}

// TestExchange_UnauthenticatedFirstAddressDoesNotFallThrough proves that a
// received datagram is a definitive authentication result. A hostile first DNS
// address must not be masked by retrying a second address that would answer with
// the pinned key.
func TestExchange_UnauthenticatedFirstAddressDoesNotFallThrough(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		behavior behavior
	}{
		{"wrong server key", behaviorWrongKey},
		{"zero-length datagram", behaviorEmpty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			agentPub := pubOf(t, devicePriv)
			badServer := newFakeServer(t, serverPriv, agentPub, tc.behavior)
			goodServer := newFakeServer(t, serverPriv, agentPub, behaviorNormal)

			first := netip.MustParseAddr("9.9.9.9")
			second := netip.MustParseAddr("149.112.112.112")
			const assignedPort = 62206
			dialer := &addressRoutingDialer{routes: map[string]string{
				netip.AddrPortFrom(first, assignedPort).String():  net.JoinHostPort("127.0.0.1", fmt.Sprint(badServer.port())),
				netip.AddrPortFrom(second, assignedPort).String(): net.JoinHostPort("127.0.0.1", fmt.Sprint(goodServer.port())),
			}}

			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning([]netip.Addr{first, second}),
				Dialer:           dialer,
				Timeout:          2 * time.Second,
			}
			if _, err := nativeudp.Knock(context.Background(), ep, nil, opts); !errors.Is(err, nativeudp.ErrServerUnauthenticated) {
				t.Fatalf("error = %v, want ErrServerUnauthenticated", err)
			}
			if badServer.receivedCount() != 1 {
				t.Fatalf("first server received %d datagrams, want 1", badServer.receivedCount())
			}
			if goodServer.receivedCount() != 0 {
				t.Fatalf("second server received %d datagrams, want 0 after authentication failure", goodServer.receivedCount())
			}
		})
	}
}

// TestExchange_NoFallbackBeyondAssignment proves the transport tries only the
// assignment's resolved addresses and never a hidden fallback: when every resolved
// address fails to dial, it returns ErrTransport rather than succeeding elsewhere.
func TestExchange_NoFallbackBeyondAssignment(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	// A live server exists, but the resolver never returns its address; a correct
	// transport must not reach it.
	srv := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)

	a := netip.MustParseAddr("208.67.222.222")
	b := netip.MustParseAddr("208.67.220.220")
	res := resolverReturning([]netip.Addr{a, b})
	dialer := &sequencedDialer{fail: map[string]bool{
		netip.AddrPortFrom(a, uint16(srv.port())).String(): true,
		netip.AddrPortFrom(b, uint16(srv.port())).String(): true,
	}, real: &net.Dialer{}}

	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: srv.port(), ServerStaticPub: serverPub}
	opts := nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: res, Dialer: dialer, Timeout: time.Second}

	if _, err := nativeudp.Knock(context.Background(), ep, nil, opts); !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport (no fallback)", err)
	}
	if srv.receivedCount() != 0 {
		t.Fatalf("server received %d datagrams; transport must not reach an unresolved host", srv.receivedCount())
	}
}

func TestExchange_ResolveFailureIsTyped(t *testing.T) {
	t.Parallel()
	_, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	res := resolverFuncExternal(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("nxdomain")
	})
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: serverPub}
	opts := nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: res}
	if _, err := nativeudp.Knock(context.Background(), ep, nil, opts); !errors.Is(err, nativeudp.ErrResolve) {
		t.Fatalf("error = %v, want ErrResolve", err)
	}
}

// TestExchange_ErrorsScrubSecrets asserts a rejection error never contains the
// device static private key or the application body bytes.
func TestExchange_ErrorsScrubSecrets(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorWrongKey)
	secretBody := []byte("SUPER-SECRET-BODY-MARKER")

	_, err := nativeudp.Knock(context.Background(), ep, secretBody, opts)
	if err == nil {
		t.Fatal("expected a rejection error")
	}
	msg := err.Error()
	if strings.Contains(msg, string(secretBody)) {
		t.Fatalf("error leaked the application body: %q", msg)
	}
	if strings.Contains(msg, hex.EncodeToString(opts.DeviceStaticPriv)) {
		t.Fatalf("error leaked the device private key: %q", msg)
	}
}

// --- external test helpers ---

type resolverFuncExternal func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFuncExternal) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func resolverReturning(addrs []netip.Addr) nativeudp.Resolver {
	return resolverFuncExternal(func(context.Context, string, string) ([]netip.Addr, error) {
		return addrs, nil
	})
}

type sequencedDialer struct {
	fail map[string]bool
	real nativeudp.Dialer

	mu     sync.Mutex
	dialAt map[string]bool
}

type addressRoutingDialer struct {
	routes map[string]string
}

func (d *addressRoutingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, ok := d.routes[address]
	if !ok {
		return nil, fmt.Errorf("no test route for %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (d *sequencedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	if d.dialAt == nil {
		d.dialAt = map[string]bool{}
	}
	d.dialAt[address] = true
	shouldFail := d.fail[address]
	d.mu.Unlock()
	if shouldFail {
		return nil, fmt.Errorf("dial %s: injected failure", address)
	}
	return d.real.DialContext(ctx, network, address)
}

func (d *sequencedDialer) dialed(address string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialAt[address]
}

func mustKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func mustPriv(t *testing.T) []byte {
	t.Helper()
	priv, _ := mustKeypair(t)
	return priv
}

func pubOf(t *testing.T, priv []byte) []byte {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("import priv: %v", err)
	}
	return key.PublicKey().Bytes()
}

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return b
}

func mustRandGlobal(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func mustPreamble() uint32 {
	b := mustRandGlobal(4)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
