package nativeudp_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/udpfence"
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
	behaviorNormal             behavior = iota // correct reply type, echoed counter
	behaviorCookie                             // NHP_COK overload cookie-challenge
	behaviorCookieWrongCounter                 // NHP_COK with counter+1
	behaviorWrongCounter                       // correct type, counter+1
	behaviorWrongType                          // the other reply type (KNK->RAK, REG->ACK)
	behaviorWrongKey                           // built with a different server static key
	behaviorGarbage                            // random non-NHP bytes
	behaviorEmpty                              // zero-length datagram
	behaviorTooShort                           // a sub-header-length datagram
	behaviorOversize                           // a datagram larger than the NHP buffer
	behaviorSilent                             // never reply
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
	// echoRequestBody answers with the initiator's own body instead of the fixed
	// replyBody, so a caller running several exchanges at once can prove the reply
	// it received belongs to the request it sent.
	echoRequestBody bool
	done            chan struct{}

	mu       sync.Mutex
	received int
	types    []int
	sizes    []int
	bodies   [][]byte
}

func newFakeServer(t *testing.T, serverPriv, agentPub []byte, b behavior, configure ...func(*fakeServer)) *fakeServer {
	t.Helper()
	return newFakeServerOn(t, "udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, serverPriv, agentPub, b, configure...)
}

// withBodyEcho makes the responder answer with the initiator's own body. It is a
// constructor option rather than a settable field because the serve goroutine
// reads it: configuring after construction would be a data race under -race.
func withBodyEcho(s *fakeServer) { s.echoRequestBody = true }

// newFakeServerOn binds the responder to an explicit network/address so a test
// can drive a real udp6 socket; newFakeServer keeps the udp4 loopback default.
func newFakeServerOn(t *testing.T, network string, laddr *net.UDPAddr, serverPriv, agentPub []byte, b behavior, configure ...func(*fakeServer)) *fakeServer {
	t.Helper()
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		t.Fatalf("listen %s: %v", network, err)
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
	for _, apply := range configure {
		apply(s)
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

func (s *fakeServer) receivedTypes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.types...)
}

func (s *fakeServer) receivedSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.sizes...)
}

func (s *fakeServer) receivedBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	bodies := make([][]byte, len(s.bodies))
	for i := range s.bodies {
		bodies[i] = append([]byte(nil), s.bodies[i]...)
	}
	return bodies
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
		s.sizes = append(s.sizes, n)
		s.mu.Unlock()

		msg, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, pkt)
		if err != nil {
			s.t.Logf("server: open initiator: %v", err)
			continue
		}
		s.mu.Lock()
		s.types = append(s.types, msg.Type)
		s.bodies = append(s.bodies, append([]byte(nil), msg.Body...))
		s.mu.Unlock()
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
	body := s.replyBody
	if s.echoRequestBody {
		body = msg.Body
	}
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
		return s.buildReply(normalType, s.altPriv, msg.Counter, body)
	case behaviorWrongCounter:
		return s.buildReply(normalType, s.serverPriv, msg.Counter+1, body)
	case behaviorWrongType:
		other := relayknock.TypeRegisterAck
		if msg.Type == relayknock.TypeRegister {
			other = relayknock.TypeACK
		}
		return s.buildReply(other, s.serverPriv, msg.Counter, body)
	case behaviorCookie:
		return s.buildReply(relayknock.TypeCookieChallenge, s.serverPriv, msg.Counter, body)
	case behaviorCookieWrongCounter:
		return s.buildReply(relayknock.TypeCookieChallenge, s.serverPriv, msg.Counter+1, body)
	default: // behaviorNormal
		return s.buildReply(normalType, s.serverPriv, msg.Counter, body)
	}
}

// buildReply builds a server-originated reply of replyType, signed by serverPriv,
// echoing counter. Roles are swapped relative to a knock: DeviceStaticPriv is the
// server static private key and ServerStaticPub is the agent static public key.
func (s *fakeServer) buildReply(replyType int, serverPriv []byte, counter uint64, body []byte) []byte {
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
		s.t.Errorf("build reply: %v", err)
		return nil
	}
	return packet
}

func replyTypeFor(initiatorType int) int {
	switch initiatorType {
	case relayknock.TypeListRequest:
		return relayknock.TypeListResult
	case relayknock.TypeRegister:
		return relayknock.TypeRegisterAck
	default:
		return relayknock.TypeACK
	}
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
		{"list -> list result", relayknock.TypeListRequest},
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
			if tc.reqType == relayknock.TypeListRequest && !reply.IsListResult() {
				t.Fatalf("reply type = %d, want LRT", reply.Type)
			}
			if string(reply.Body) != `{"ok":true}` {
				t.Fatalf("reply body = %q", reply.Body)
			}
		})
	}
}

func TestRoundTripHelpers(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorNormal)

	ack, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if err != nil || !ack.IsACK() {
		t.Fatalf("Knock: reply=%v err=%v", ack, err)
	}
	lrt, err := nativeudp.List(context.Background(), ep, nil, opts)
	if err != nil || !lrt.IsListResult() {
		t.Fatalf("List: reply=%v err=%v", lrt, err)
	}
	rak, err := nativeudp.Register(context.Background(), ep, nil, opts)
	if err != nil || !rak.IsRegisterAck() {
		t.Fatalf("Register: reply=%v err=%v", rak, err)
	}
}

type countingLoopbackDialer struct {
	mu     sync.Mutex
	target string
	calls  int
}

func (d *countingLoopbackDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *countingLoopbackDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestSendOTP_IsOneDatagramWithNoReplyWaitOrAddressFallback(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorSilent)
	dialer := &countingLoopbackDialer{target: server.conn.LocalAddr().String()}
	opts := nativeudp.Options{
		DeviceStaticPriv: devicePriv,
		Resolver: resolverReturning([]netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("9.9.9.9"),
		}),
		Dialer: dialer, Timeout: 10 * time.Second, MaxAddresses: 2,
	}
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
	start := time.Now()
	if err := nativeudp.SendOTP(context.Background(), ep, []byte(`{"otp":true}`), opts); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("SendOTP waited for a reply: %s", elapsed)
	}
	deadline := time.Now().Add(time.Second)
	for len(server.receivedTypes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dialer.count() != 1 || server.receivedCount() != 1 {
		t.Fatalf("OTP dial/datagram counts = %d/%d, want 1/1", dialer.count(), server.receivedCount())
	}
	if got := server.receivedTypes(); len(got) != 1 || got[0] != relayknock.TypeOTP {
		t.Fatalf("OTP received types = %v, want [%d]", got, relayknock.TypeOTP)
	}
}

func TestRegistrationPacketsAvoidIPFragmentation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		send func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) error
	}{
		{
			name: "otp",
			send: nativeudp.SendOTP,
		},
		{
			name: "register",
			send: func(ctx context.Context, ep nativeudp.Endpoint, body []byte, opts nativeudp.Options) error {
				_, err := nativeudp.Register(ctx, ep, body, opts)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)
			ticket, err := conformance.AssignmentTicket()
			if err != nil {
				t.Fatalf("load QAT1 fixture: %v", err)
			}
			body := []byte(fmt.Sprintf(
				`{"usrId":"key_123456789012","devId":"qurl-go-production-ticket-proof","aspId":"agent","pass":"lv_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","usrData":{"query":"agent_registration_otp","version":1,"assignment_ticket":%q}}`,
				ticket.Golden.Token,
			))
			if len(body)+240+16 <= 1472 {
				t.Fatalf("QAT1 registration packet fixture is only %d bytes; test no longer crosses IPv4 MTU", len(body)+240+16)
			}
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning([]netip.Addr{netip.MustParseAddr("8.8.8.8")}),
				Dialer:           &countingLoopbackDialer{target: server.conn.LocalAddr().String()},
			}
			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
			if err := tc.send(context.Background(), ep, body, opts); err != nil {
				t.Fatalf("send large %s: %v", tc.name, err)
			}
			deadline := time.Now().Add(time.Second)
			for len(server.receivedBodies()) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			sizes := server.receivedSizes()
			bodies := server.receivedBodies()
			if len(sizes) != 1 || sizes[0] > 1232 {
				t.Fatalf("%s packet sizes = %v, want one packet at most 1232 bytes", tc.name, sizes)
			}
			if len(bodies) != 1 || !bytes.Equal(bodies[0], body) {
				t.Fatalf("%s server did not recover the exact compressed body", tc.name)
			}
		})
	}
}

func TestRegistrationPacketRejectsUncompressibleFragment(t *testing.T) {
	t.Parallel()
	// Both compressing header types share the ceiling, so both must refuse to put
	// a fragmenting datagram on the wire rather than truncating or sending it.
	for _, tc := range []struct {
		name string
		send func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) error
	}{
		{name: "otp", send: nativeudp.SendOTP},
		{
			name: "register",
			send: func(ctx context.Context, ep nativeudp.Endpoint, body []byte, opts nativeudp.Options) error {
				_, err := nativeudp.Register(ctx, ep, body, opts)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorSilent)
			body := mustRand(t, 1300)
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning([]netip.Addr{netip.MustParseAddr("8.8.8.8")}),
				Dialer:           &countingLoopbackDialer{target: server.conn.LocalAddr().String()},
			}
			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
			err := tc.send(context.Background(), ep, body, opts)
			if err == nil || !errors.Is(err, nativeudp.ErrInvalidRequest) {
				t.Fatalf("%s uncompressible fragment error = %v, want ErrInvalidRequest", tc.name, err)
			}
			if server.receivedCount() != 0 {
				t.Fatalf("server received %d datagrams after fragmentation reject, want 0", server.receivedCount())
			}
		})
	}
}

// TestPayloadStraddlesUnfragmentedCeiling pins the exact boundary at which OTP and
// REG switch to compression. The at-ceiling body is incompressible, so if the
// transport compressed one byte too eagerly the packet would grow past the
// ceiling and be rejected instead of sent; the one-byte-over body is compressible,
// so failing to compress it would put an oversize datagram on the wire.
func TestPayloadStraddlesUnfragmentedCeiling(t *testing.T) {
	t.Parallel()
	// maxUnfragmentedPayload (1232, the IPv6 minimum-MTU UDP payload ceiling)
	// less the 240-byte NHP header and the body's 16-byte AEAD tag: the largest
	// body that still fits uncompressed.
	const largestUncompressedBody = 1232 - 240 - 16
	for _, send := range []struct {
		name string
		send func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) error
	}{
		{name: "otp", send: nativeudp.SendOTP},
		{
			name: "register",
			send: func(ctx context.Context, ep nativeudp.Endpoint, body []byte, opts nativeudp.Options) error {
				_, err := nativeudp.Register(ctx, ep, body, opts)
				return err
			},
		},
	} {
		for _, tc := range []struct {
			name     string
			body     []byte
			wantSize int // 0 means "at most the ceiling"
		}{
			{
				name:     "at the ceiling, sent uncompressed",
				body:     mustRand(t, largestUncompressedBody),
				wantSize: 1232,
			},
			{
				name: "one byte over the ceiling, compressed under it",
				body: bytes.Repeat([]byte{'a'}, largestUncompressedBody+1),
			},
			{
				// The whole legal body range stays inside the ceiling as long as it
				// compresses: the plaintext ceiling is not itself a send limit.
				name: "plaintext ceiling, compressed under the fragmentation ceiling",
				body: bytes.Repeat([]byte{'a'}, nhpcontract.MaxApplicationBodySize),
			},
		} {
			t.Run(send.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				serverPriv, serverPub := mustKeypair(t)
				devicePriv := mustPriv(t)
				server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)
				opts := nativeudp.Options{
					DeviceStaticPriv: devicePriv,
					Resolver:         resolverReturning([]netip.Addr{netip.MustParseAddr("8.8.8.8")}),
					Dialer:           &countingLoopbackDialer{target: server.conn.LocalAddr().String()},
					Timeout:          2 * time.Second,
				}
				ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
				if err := send.send(context.Background(), ep, tc.body, opts); err != nil {
					t.Fatalf("send %d-byte body: %v", len(tc.body), err)
				}
				deadline := time.Now().Add(2 * time.Second)
				for len(server.receivedBodies()) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				sizes := server.receivedSizes()
				bodies := server.receivedBodies()
				if len(sizes) != 1 {
					t.Fatalf("packet sizes = %v, want exactly one datagram", sizes)
				}
				switch {
				case tc.wantSize != 0 && sizes[0] != tc.wantSize:
					t.Fatalf("packet size = %d, want exactly %d (header+body+tag, uncompressed)", sizes[0], tc.wantSize)
				case sizes[0] > 1232:
					t.Fatalf("packet size = %d, want at most the 1232-byte unfragmented ceiling", sizes[0])
				}
				if len(bodies) != 1 || !bytes.Equal(bodies[0], tc.body) {
					t.Fatalf("server recovered %d bytes, want the exact %d-byte body", len(bodies[0]), len(tc.body))
				}
			})
		}
	}
}

// TestSendOTP_RejectsBeforeAnyDatagram covers the pre-I/O gates on the
// fire-and-forget path. Each rejection must happen before the single OTP
// datagram is dispatched: an OTP that reached the cell would have already
// triggered an email whose code a retry then invalidates.
func TestSendOTP_RejectsBeforeAnyDatagram(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		body   []byte
		mutate func(*nativeudp.Endpoint, *nativeudp.Options)
		want   error
	}{
		{
			name:   "blank host",
			mutate: func(ep *nativeudp.Endpoint, _ *nativeudp.Options) { ep.Host = "" },
			want:   nativeudp.ErrInvalidEndpoint,
		},
		{
			name:   "port out of range",
			mutate: func(ep *nativeudp.Endpoint, _ *nativeudp.Options) { ep.Port = 70000 },
			want:   nativeudp.ErrInvalidEndpoint,
		},
		{
			name:   "server key wrong length",
			mutate: func(ep *nativeudp.Endpoint, _ *nativeudp.Options) { ep.ServerStaticPub = make([]byte, 16) },
			want:   nativeudp.ErrInvalidEndpoint,
		},
		{
			name:   "server key low order",
			mutate: func(ep *nativeudp.Endpoint, _ *nativeudp.Options) { ep.ServerStaticPub = make([]byte, 32) },
			want:   nativeudp.ErrInvalidEndpoint,
		},
		{
			name:   "device key wrong length",
			mutate: func(_ *nativeudp.Endpoint, opts *nativeudp.Options) { opts.DeviceStaticPriv = make([]byte, 31) },
			want:   nativeudp.ErrInvalidRequest,
		},
		{
			name: "body over the plaintext ceiling",
			body: make([]byte, nhpcontract.MaxApplicationBodySize+1),
			want: nativeudp.ErrInvalidRequest,
		},
		{
			// A body at the plaintext ceiling is always compressed, and zlib expands
			// incompressible input: the sealed result no longer fits the NHP
			// plaintext ceiling, so packet construction rejects it before the socket.
			name: "largest legal body, incompressible",
			body: mustRand(t, nhpcontract.MaxApplicationBodySize),
			want: nativeudp.ErrInvalidRequest,
		},
		{
			name: "resolution failure",
			mutate: func(_ *nativeudp.Endpoint, opts *nativeudp.Options) {
				opts.Resolver = resolverFuncExternal(func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, errors.New("nxdomain")
				})
			},
			want: nativeudp.ErrResolve,
		},
		{
			name: "no public address",
			mutate: func(_ *nativeudp.Endpoint, opts *nativeudp.Options) {
				opts.Resolver = resolverReturning([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
			},
			want: nativeudp.ErrResolve,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorSilent)
			dialer := &countingLoopbackDialer{target: server.conn.LocalAddr().String()}
			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning([]netip.Addr{netip.MustParseAddr("8.8.8.8")}),
				Dialer:           dialer,
			}
			if tc.mutate != nil {
				tc.mutate(&ep, &opts)
			}

			if err := nativeudp.SendOTP(context.Background(), ep, tc.body, opts); !errors.Is(err, tc.want) {
				t.Fatalf("SendOTP error = %v, want errors.Is %v", err, tc.want)
			}
			if dialer.count() != 0 || server.receivedCount() != 0 {
				t.Fatalf("rejected OTP still dialed/sent %d/%d times, want 0/0", dialer.count(), server.receivedCount())
			}
		})
	}
}

func TestSendOTP_NilOrCancelledContext(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorSilent)
	dialer := &countingLoopbackDialer{target: server.conn.LocalAddr().String()}
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: server.port(), ServerStaticPub: serverPub}
	opts := nativeudp.Options{
		DeviceStaticPriv: devicePriv,
		Resolver:         resolverReturning([]netip.Addr{netip.MustParseAddr("8.8.8.8")}),
		Dialer:           dialer,
	}

	//nolint:staticcheck // deliberately passing a nil context to prove it fails closed.
	if err := nativeudp.SendOTP(nil, ep, nil, opts); !errors.Is(err, nativeudp.ErrInvalidRequest) {
		t.Fatalf("nil-context error = %v, want ErrInvalidRequest", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := nativeudp.SendOTP(ctx, ep, nil, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled-context error = %v, want context.Canceled", err)
	}
	if dialer.count() != 0 || server.receivedCount() != 0 {
		t.Fatalf("dead context still dialed/sent %d/%d times, want 0/0", dialer.count(), server.receivedCount())
	}
}

// TestSendOTP_TransportFailureIsNeitherRetriedNorFannedOut pins the documented
// one-datagram rule: a failed OTP write is reported, never re-driven against
// another resolved address, because the first copy may already have been
// delivered and emailed.
func TestSendOTP_TransportFailureIsNeitherRetriedNorFannedOut(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorSilent)

	dead := netip.MustParseAddr("9.9.9.9")
	live := netip.MustParseAddr("149.112.112.112")
	const assignedPort = 443
	// Only the second address has a route: a transport that fanned out would find
	// the live responder, and one that retried would dial twice.
	dialer := &addressRoutingDialer{routes: map[string]string{
		netip.AddrPortFrom(live, assignedPort).String(): server.conn.LocalAddr().String(),
	}}
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
	opts := nativeudp.Options{
		DeviceStaticPriv: devicePriv,
		Resolver:         resolverReturning([]netip.Addr{dead, live}),
		Dialer:           dialer,
		MaxAddresses:     2,
	}

	if err := nativeudp.SendOTP(context.Background(), ep, []byte(`{"otp":true}`), opts); !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("SendOTP error = %v, want ErrTransport", err)
	}
	if server.receivedCount() != 0 {
		t.Fatalf("OTP reached the second address %d times; it must never fan out", server.receivedCount())
	}
}

// lifecycleAuthorityError stands in for qurl's typed recovery-authority error.
type lifecycleAuthorityError struct{ reason string }

func (e *lifecycleAuthorityError) Error() string { return "qurl: not authorized: " + e.reason }

// TestFenceRejectionSurvivesTheTransportBoundary is the reason udpfence exists:
// the lifecycle's typed authority error must reach the caller of a public entry
// point as the identical value — not reclassified as ErrTransport — and no
// datagram may leave while the fence is closed.
func TestFenceRejectionSurvivesTheTransportBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		call func(context.Context, nativeudp.Endpoint, nativeudp.Options) error
	}{
		{
			name: "SendOTP",
			call: func(ctx context.Context, ep nativeudp.Endpoint, opts nativeudp.Options) error {
				return nativeudp.SendOTP(ctx, ep, nil, opts)
			},
		},
		{
			name: "Knock",
			call: func(ctx context.Context, ep nativeudp.Endpoint, opts nativeudp.Options) error {
				_, err := nativeudp.Knock(ctx, ep, nil, opts)
				return err
			},
		},
		{
			name: "KnockWithReknock",
			call: func(ctx context.Context, ep nativeudp.Endpoint, opts nativeudp.Options) error {
				_, err := nativeudp.KnockWithReknock(ctx, ep, nil, nil, opts)
				return err
			},
		},
		{
			name: "AssignmentList",
			call: func(ctx context.Context, ep nativeudp.Endpoint, opts nativeudp.Options) error {
				_, err := nativeudp.AssignmentList(ctx, ep, nil, opts)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, ep, opts := newLoopbackExchange(t, behaviorNormal)
			authority := &lifecycleAuthorityError{reason: "assignment lease revoked"}
			ctx := udpfence.With(context.Background(), func() error { return authority })

			err := tc.call(ctx, ep, opts)
			// Identity, not errors.Is: errors.Is would also accept a wrapped or
			// reclassified error, which is precisely what must not happen here.
			//nolint:errorlint // identity comparison is the assertion.
			if err != error(authority) {
				t.Fatalf("error = %#v, want the lifecycle's own authority error unchanged", err)
			}
			var typed *lifecycleAuthorityError
			if !errors.As(err, &typed) || typed != authority {
				t.Fatalf("errors.As recovered %#v, want the original typed error", typed)
			}
			if errors.Is(err, nativeudp.ErrTransport) {
				t.Fatalf("fence rejection was reclassified as a transport fault: %v", err)
			}
			if server.receivedCount() != 0 {
				t.Fatalf("server received %d datagrams behind a closed fence, want 0", server.receivedCount())
			}
		})
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

func TestExchange_ListRejectsCookieChallenge(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorCookie)
	if _, err := nativeudp.List(context.Background(), ep, nil, opts); !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("List cookie-challenge error = %v, want ErrMalformedReply", err)
	}
}

func TestExchange_KnockCookieChallengePrecedesCounterCheck(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorCookieWrongCounter)
	reply, err := nativeudp.Knock(context.Background(), ep, nil, opts)
	if err != nil {
		t.Fatalf("mismatched-counter knock COK = %v, want retryable reply", err)
	}
	if !reply.IsCookieChallenge() {
		t.Fatalf("reply type = %d, want NHP_COK cookie-challenge", reply.Type)
	}
}

func TestExchange_RegisterRejectsCookieChallenge(t *testing.T) {
	t.Parallel()
	for _, b := range []behavior{behaviorCookie, behaviorCookieWrongCounter} {
		_, ep, opts := newLoopbackExchange(t, b)
		if _, err := nativeudp.Register(context.Background(), ep, nil, opts); !errors.Is(err, relayknock.ErrMalformedReply) {
			t.Fatalf("register COK behavior %d error = %v, want ErrMalformedReply", b, err)
		}
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

func mustPreamble(t *testing.T) uint32 {
	t.Helper()
	return binary.BigEndian.Uint32(mustRand(t, 4))
}
