package nativeudp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// These tests exercise the native-UDP transport's pre-I/O validation and its
// authentication/correlation layer directly (white-box), including a byte-exact
// consumption of the shared qurl-conformance NHP_RAK vector. Socket behavior is in
// the external transport_test.go.

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// TestDecryptAndCorrelate_ConformanceRAK feeds the frozen reference-server NHP_RAK
// vector (the same artifact relayknock's golden test pins) through the native
// path's authentication + correlation. Because the native transport decrypts with
// relayknock.DecryptReply exactly as the relay path does, an accepted RAK here
// proves the native path is wire-compatible with the deployed server for the
// end-to-end packet/body — the shared vector, not a native-specific corpus.
func TestDecryptAndCorrelate_ConformanceRAK(t *testing.T) {
	f, err := conformance.AgentRegistrationGolden()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-registration vectors: %v", err)
	}
	vec := f.RakSuccess
	if vec.PacketHex == "" {
		t.Fatal("qurl-conformance rak_success missing packet_hex")
	}
	counter, err := strconv.ParseUint(vec.CounterHex, 16, 64)
	if err != nil {
		t.Fatalf("parse counter_hex %q: %v", vec.CounterHex, err)
	}

	devicePriv := mustHexBytes(t, vec.AgentStaticPrivHex)
	serverPub := mustHexBytes(t, vec.ServerStaticPubHex)
	packet := mustHexBytes(t, vec.PacketHex)

	// A native NHP_REG whose counter matches accepts the frozen RAK.
	reply, err := decryptAndCorrelate(devicePriv, serverPub, relayknock.TypeRegister, counter, packet)
	if err != nil {
		t.Fatalf("decryptAndCorrelate accepted RAK: %v", err)
	}
	if !reply.IsRegisterAck() {
		t.Fatalf("reply.Type = %d, want NHP_RAK", reply.Type)
	}
	if got := hex.EncodeToString(reply.Body); got != vec.BodyHex {
		t.Fatalf("RAK body mismatch:\n got=%s\nwant=%s", got, vec.BodyHex)
	}

	// A mismatched request counter is a malformed reply, not an accepted one.
	if _, err := decryptAndCorrelate(devicePriv, serverPub, relayknock.TypeRegister, counter+1, packet); !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("wrong-counter error = %v, want ErrMalformedReply", err)
	}

	// The RAK answers a register, not a knock: presenting it as a knock reply is a
	// malformed pairing.
	if _, err := decryptAndCorrelate(devicePriv, serverPub, relayknock.TypeKnock, counter, packet); !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("wrong-request-type error = %v, want ErrMalformedReply", err)
	}

	// A wrong pinned server key fails authentication before any correlation check.
	otherPub := freshX25519Pub(t)
	if _, err := decryptAndCorrelate(devicePriv, otherPub, relayknock.TypeRegister, counter, packet); !errors.Is(err, ErrServerUnauthenticated) {
		t.Fatalf("wrong-key error = %v, want ErrServerUnauthenticated", err)
	}
}

// TestDecryptAndCorrelate_ConformanceLRT consumes the shared assignment result
// packet byte-for-byte. Besides proving the new LST path accepts the reference
// server's authenticated LRT, the negative assertions pin the two correlation
// fields that live outside the AEAD and the out-of-band hub identity.
func TestDecryptAndCorrelate_ConformanceLRT(t *testing.T) {
	f, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-assignment vectors: %v", err)
	}
	vec := f.InitialAssignment.Result
	if vec.HeaderType != conformance.AgentAssignmentResultHeaderType || vec.PacketHex == "" {
		t.Fatalf("initial result header/packet = %d/%t, want NHP_LRT with packet", vec.HeaderType, vec.PacketHex != "")
	}
	counter, err := strconv.ParseUint(vec.Counter, 10, 64)
	if err != nil {
		t.Fatalf("parse counter %q: %v", vec.Counter, err)
	}

	agentPriv := mustHexBytes(t, f.Keys.Agent.StaticPrivHex)
	hubPub := mustHexBytes(t, f.Keys.Hub.StaticPubHex)
	packet := mustHexBytes(t, vec.PacketHex)
	reply, err := decryptAndCorrelate(agentPriv, hubPub, relayknock.TypeListRequest, counter, packet)
	if err != nil {
		t.Fatalf("decryptAndCorrelate accepted LRT: %v", err)
	}
	if reply.Type != conformance.AgentAssignmentResultHeaderType || string(reply.Body) != vec.BodyJSON {
		t.Fatalf("LRT type/body = %d/%q, want %d/%q", reply.Type, reply.Body, conformance.AgentAssignmentResultHeaderType, vec.BodyJSON)
	}

	if _, err := decryptAndCorrelate(agentPriv, hubPub, relayknock.TypeListRequest, counter+1, packet); !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("wrong-counter error = %v, want ErrMalformedReply", err)
	}
	if _, err := decryptAndCorrelate(agentPriv, hubPub, relayknock.TypeRegister, counter, packet); !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("wrong-request-type error = %v, want ErrMalformedReply", err)
	}
	if _, err := decryptAndCorrelate(agentPriv, freshX25519Pub(t), relayknock.TypeListRequest, counter, packet); !errors.Is(err, ErrServerUnauthenticated) {
		t.Fatalf("wrong-key error = %v, want ErrServerUnauthenticated", err)
	}
}

func TestDecryptAndCorrelate_RejectsMalformedDatagram(t *testing.T) {
	devicePriv := freshX25519Priv(t)
	serverPub := freshX25519Pub(t)
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{name: "too short", pkt: make([]byte, 100)},
		{name: "garbage header-sized", pkt: mustRandom(t, 240)},
		{name: "garbage with body", pkt: mustRandom(t, 400)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decryptAndCorrelate(devicePriv, serverPub, relayknock.TypeKnock, 1, tc.pkt); !errors.Is(err, ErrServerUnauthenticated) {
				t.Fatalf("error = %v, want ErrServerUnauthenticated", err)
			}
		})
	}
}

func TestExchange_ValidatesBeforeIO(t *testing.T) {
	goodPriv := freshX25519Priv(t)
	goodPub := freshX25519Pub(t)
	// A resolver/dialer that would panic if reached proves validation is pre-I/O.
	failResolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("resolver must not be reached for invalid input")
		return nil, nil
	})

	cases := []struct {
		name    string
		ep      Endpoint
		ht      int
		body    []byte
		opts    Options
		wantErr error
	}{
		{
			name:    "blank host",
			ep:      Endpoint{Host: "", Port: 62206, ServerStaticPub: goodPub},
			ht:      relayknock.TypeKnock,
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "port out of range",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 70000, ServerStaticPub: goodPub},
			ht:      relayknock.TypeKnock,
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "server key wrong length",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: make([]byte, 16)},
			ht:      relayknock.TypeKnock,
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "server key low order",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: make([]byte, 32)},
			ht:      relayknock.TypeKnock,
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "one-way header type (OTP)",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: goodPub},
			ht:      relayknock.TypeOTP,
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "device key wrong length",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: goodPub},
			ht:      relayknock.TypeKnock,
			opts:    Options{DeviceStaticPriv: make([]byte, 31), Resolver: failResolver},
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "body over the plaintext ceiling",
			ep:      Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: goodPub},
			ht:      relayknock.TypeKnock,
			body:    make([]byte, nhpcontract.MaxApplicationBodySize+1),
			opts:    Options{DeviceStaticPriv: goodPriv, Resolver: failResolver},
			wantErr: ErrInvalidRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Exchange(context.Background(), tc.ep, tc.ht, tc.body, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Exchange error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestExchange_NilOrCancelledContext(t *testing.T) {
	ep := Endpoint{Host: "cell0.nhp.test", Port: 62206, ServerStaticPub: freshX25519Pub(t)}
	opts := Options{DeviceStaticPriv: freshX25519Priv(t)}

	//nolint:staticcheck // deliberately passing a nil context to prove it fails closed.
	if _, err := Exchange(nil, ep, relayknock.TypeKnock, nil, opts); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil-context error = %v, want ErrInvalidRequest", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Exchange(ctx, ep, relayknock.TypeKnock, nil, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled-context error = %v, want context.Canceled", err)
	}
}

func TestBuildPacketClassifiesEntropyFailureAsTransport(t *testing.T) {
	serverPub := freshX25519Pub(t)
	devicePriv := freshX25519Priv(t)
	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })

	rand.Reader = iotest.ErrReader(errors.New("injected entropy failure"))
	_, _, err := buildPacket(relayknock.TypeListRequest, serverPub, devicePriv, nil)
	if !errors.Is(err, ErrTransport) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("buildPacket error = %v, want only ErrTransport", err)
	}
}

func TestBuildPacketDrawsAndWipesRandomnessOnce(t *testing.T) {
	serverPub := freshX25519Pub(t)
	devicePriv := freshX25519Priv(t)
	reader := &recordingEntropyReader{}
	originalReader := rand.Reader
	rand.Reader = reader
	t.Cleanup(func() { rand.Reader = originalReader })

	_, counter, err := buildPacket(relayknock.TypeListRequest, serverPub, devicePriv, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 {
		t.Fatalf("entropy reads = %d, want 1", reader.calls)
	}
	const wantCounter = 0x2122232425262728
	if counter != wantCounter {
		t.Fatalf("counter = %#x, want %#x", counter, wantCounter)
	}
	if !bytes.Equal(reader.buffer, make([]byte, len(reader.buffer))) {
		t.Fatalf("packet randomness was not wiped: %x", reader.buffer)
	}
}

func TestResolveAddresses_CapAndEmpty(t *testing.T) {
	many := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.4.4"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
	}
	got, err := resolveAddresses(context.Background(), "cell0.nhp.test", Options{
		Resolver:     resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return many, nil }),
		MaxAddresses: 2,
	})
	if err != nil {
		t.Fatalf("resolveAddresses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved %d addresses, want cap of 2", len(got))
	}

	_, err = resolveAddresses(context.Background(), "cell0.nhp.test", Options{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }),
	})
	if !errors.Is(err, ErrResolve) {
		t.Fatalf("empty-resolution error = %v, want ErrResolve", err)
	}

	nonPublic := []netip.Addr{
		netip.MustParseAddr("0.1.2.3"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("169.254.1.2"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("192.0.0.1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.88.99.1"),
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("240.0.0.1"),
		netip.MustParseAddr("100::1"),
		netip.MustParseAddr("64:ff9b::1"),
		netip.MustParseAddr("64:ff9b:1::1"),
		netip.MustParseAddr("2001::1"),
		netip.MustParseAddr("2001:2::1"),
		netip.MustParseAddr("2001:10::1"),
		netip.MustParseAddr("2001:20::1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2002::1"),
		netip.MustParseAddr("3fff::1"),
		netip.MustParseAddr("5f00::1"),
		netip.MustParseAddr("fec0::1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fc00::1"),
	}
	_, err = resolveAddresses(context.Background(), "cell0.nhp.test", Options{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nonPublic, nil }),
	})
	if !errors.Is(err, ErrResolve) {
		t.Fatalf("private-only resolution error = %v, want ErrResolve", err)
	}
}

func TestReplyTypeAllowed(t *testing.T) {
	cases := []struct {
		req, reply int
		want       bool
	}{
		{relayknock.TypeKnock, relayknock.TypeACK, true},
		{relayknock.TypeKnock, relayknock.TypeCookieChallenge, true},
		{relayknock.TypeKnock, relayknock.TypeRegisterAck, false},
		{relayknock.TypeListRequest, relayknock.TypeListResult, true},
		{relayknock.TypeListRequest, relayknock.TypeCookieChallenge, false},
		{relayknock.TypeListRequest, relayknock.TypeACK, false},
		{relayknock.TypeRegister, relayknock.TypeRegisterAck, true},
		{relayknock.TypeRegister, relayknock.TypeCookieChallenge, true},
		{relayknock.TypeRegister, relayknock.TypeACK, false},
		{relayknock.TypeOTP, relayknock.TypeACK, false},
	}
	for _, tc := range cases {
		if got := replyTypeAllowed(tc.req, tc.reply); got != tc.want {
			t.Errorf("replyTypeAllowed(%d,%d) = %v, want %v", tc.req, tc.reply, got, tc.want)
		}
	}
}

func TestSendOneRejectsShortDatagramWrite(t *testing.T) {
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return shortWriteConn{}, nil
	})
	if _, err := sendOne(context.Background(), dialer, "192.0.2.1:62206", []byte{1, 2, 3}, time.Second, make([]byte, nhpwire.PacketBufferSize+1)); err == nil || !strings.Contains(err.Error(), "short datagram write") {
		t.Fatalf("short write error = %v", err)
	}
}

func TestSendOnePreservesOversizeBytesWhenReadAlsoReturnsError(t *testing.T) {
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return oversizeReadConn{}, nil
	})
	reply, err := sendOne(context.Background(), dialer, "192.0.2.1:62206", []byte{1}, time.Second, make([]byte, nhpwire.PacketBufferSize+1))
	if err != nil {
		t.Fatalf("sendOne returned truncation error instead of oversize bytes: %v", err)
	}
	if len(reply) != nhpwire.PacketBufferSize+1 {
		t.Fatalf("reply length = %d, want %d", len(reply), nhpwire.PacketBufferSize+1)
	}
}

// --- test helpers ---

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type recordingEntropyReader struct {
	calls  int
	buffer []byte
}

func (r *recordingEntropyReader) Read(p []byte) (int, error) {
	r.calls++
	r.buffer = p
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

type shortWriteConn struct{}

func (shortWriteConn) Read([]byte) (int, error)         { return 0, errors.New("unexpected read") }
func (shortWriteConn) Write(p []byte) (int, error)      { return len(p) - 1, nil }
func (shortWriteConn) Close() error                     { return nil }
func (shortWriteConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (shortWriteConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

type oversizeReadConn struct{ shortWriteConn }

func (oversizeReadConn) Read(p []byte) (int, error) {
	clear(p)
	return len(p), errors.New("message too long")
}

func (oversizeReadConn) Write(p []byte) (int, error) { return len(p), nil }

func freshX25519Priv(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key.Bytes()
}

func freshX25519Pub(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key.PublicKey().Bytes()
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return b
}
