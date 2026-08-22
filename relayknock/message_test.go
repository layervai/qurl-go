package relayknock_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// Tests for the list/query and registration message types (NHP_LST / NHP_LRT /
// NHP_OTP / NHP_REG / NHP_RAK), their transport-neutral codec plumbing, and the
// browser-only HTTP Knock/RelayPost boundary. The wire format itself is
// fenced byte-for-byte by knock_golden_test.go — the transcript is independent
// of the header type — so these tests fence the type plumbing around it with
// symmetric round trips: a packet built with the device key (relayknock's
// initiator API) opens with the server key via relayknocktest.OpenInitiatorMessage
// (the responder-role open, the same direction the reference server reads an
// initiator packet), and a fabricated reply built with relayknocktest.BuildReply
// opens under relayknock.DecryptReply. This is an EXTERNAL test package: the
// initiator/reply split now lives across relayknock (public), relayknocktest
// (server helpers), and the internal nhpwire codec, so the tests exercise all
// three through their exported surfaces.

// testKeyPair derives a deterministic X25519 key pair from a repeated seed
// byte, so failures reproduce without golden fixtures (clamping is internal to
// X25519Public, so any 32 bytes are a valid scalar).
func testKeyPair(t *testing.T, seed byte) (priv, pub []byte) {
	t.Helper()
	priv = bytes.Repeat([]byte{seed}, 32)
	pub, err := nhpwire.X25519Public(priv)
	if err != nil {
		t.Fatalf("derive test pub from seed %#x: %v", seed, err)
	}
	return priv, pub
}

// TestBuildMessage_SymmetricRoundTrip builds each new initiator message type
// with the device key and opens it with the server key, asserting the wire type
// and that body/counter/timestamp survive the round trip.
func TestBuildMessage_SymmetricRoundTrip(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	tests := []struct {
		name       string
		headerType int
		wantWire   int
	}{
		{name: "list request", headerType: relayknock.TypeListRequest, wantWire: 5},
		{name: "otp", headerType: relayknock.TypeOTP, wantWire: 12},
		{name: "register", headerType: relayknock.TypeRegister, wantWire: 13},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				counter   = uint64(0xfeedfacecafebeef)
				timestamp = uint64(1700000000123456789)
			)
			body := []byte("opaque application bytes: " + tt.name)

			packet, err := relayknock.BuildMessage(tt.headerType, &relayknock.KnockInputs{
				DeviceStaticPriv: devicePriv,
				ServerStaticPub:  serverPub,
				EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
				TimestampNanos:   timestamp,
				Counter:          counter,
				Preamble:         0xdeadbeef,
				Body:             body,
			})
			if err != nil {
				t.Fatalf("BuildMessage(%d): %v", tt.headerType, err)
			}

			// Server-side open: the recipient's static private key plus the
			// sender's static public key.
			got, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet)
			if err != nil {
				t.Fatalf("OpenInitiatorMessage: %v", err)
			}
			if got.Type != tt.wantWire {
				t.Errorf("Type = %d, want %d", got.Type, tt.wantWire)
			}
			if !bytes.Equal(got.Body, body) {
				t.Errorf("Body = %q, want %q", got.Body, body)
			}
			if got.Counter != counter {
				t.Errorf("Counter = %#x, want %#x", got.Counter, counter)
			}
			if got.TimestampNanos != timestamp {
				t.Errorf("TimestampNanos = %d, want %d", got.TimestampNanos, timestamp)
			}
		})
	}
}

// TestListRequestResult_PreservesCorrelationMetadata exercises the complete
// transport-neutral LST/LRT codec pair. The result intentionally echoes the
// request counter, which is the correlation invariant a native UDP transport
// must enforce after DecryptReply authenticates the server. LST/LRT itself has
// no relay-HTTP or application-body behavior here.
func TestListRequestResult_PreservesCorrelationMetadata(t *testing.T) {
	agentPriv, agentPub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	const requestCounter = uint64(0x0102030405060708)

	request, err := relayknock.BuildMessage(relayknock.TypeListRequest, &relayknock.KnockInputs{
		DeviceStaticPriv: agentPriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x31}, 32),
		TimestampNanos:   1700000000123456789,
		Counter:          requestCounter,
		Preamble:         0x11223344,
		Body:             []byte("opaque list/query request"),
	})
	if err != nil {
		t.Fatalf("BuildMessage(TypeListRequest): %v", err)
	}
	openedRequest, err := relayknocktest.OpenInitiatorMessage(serverPriv, agentPub, request)
	if err != nil {
		t.Fatalf("OpenInitiatorMessage(LST): %v", err)
	}
	if openedRequest.Type != relayknock.TypeListRequest {
		t.Fatalf("request type = %d, want %d (NHP_LST)", openedRequest.Type, relayknock.TypeListRequest)
	}

	result, err := relayknocktest.BuildReply(relayknock.TypeListResult, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  agentPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x32}, 32),
		TimestampNanos:   1700000000123457789,
		Counter:          openedRequest.Counter,
		Preamble:         0x55667788,
		Body:             []byte("opaque list/query result"),
	})
	if err != nil {
		t.Fatalf("BuildReply(TypeListResult): %v", err)
	}
	openedResult, err := relayknock.DecryptReply(agentPriv, serverPub, result)
	if err != nil {
		t.Fatalf("DecryptReply(LRT): %v", err)
	}
	if !openedResult.IsListResult() {
		t.Fatalf("result type = %d, want %d (NHP_LRT)", openedResult.Type, relayknock.TypeListResult)
	}
	if openedResult.Type != 6 {
		t.Fatalf("NHP_LRT wire type = %d, want 6", openedResult.Type)
	}
	if openedResult.Counter != openedRequest.Counter {
		t.Fatalf("result counter %#x does not echo request counter %#x", openedResult.Counter, openedRequest.Counter)
	}
	if openedResult.IsACK() || openedResult.IsCookieChallenge() || openedResult.IsRegisterAck() {
		t.Fatalf("NHP_LRT matched another reply predicate: %#v", openedResult)
	}
}

// TestBuildMessage_KnockMatchesBuildKnock pins the BuildKnock delegation:
// BuildMessage(TypeKnock, inp) and BuildKnock(inp) emit identical bytes for
// identical inputs.
func TestBuildMessage_KnockMatchesBuildKnock(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)
	inp := &relayknock.KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1700000000123456789,
		Counter:          42,
		Preamble:         0x01020304,
		Body:             []byte("knock body"),
	}

	viaKnock, err := relayknock.BuildKnock(inp)
	if err != nil {
		t.Fatalf("BuildKnock: %v", err)
	}
	viaMessage, err := relayknock.BuildMessage(relayknock.TypeKnock, inp)
	if err != nil {
		t.Fatalf("BuildMessage(TypeKnock): %v", err)
	}
	if !bytes.Equal(viaKnock, viaMessage) {
		t.Fatal("BuildMessage(TypeKnock) and BuildKnock produced different packets for identical inputs")
	}
}

// TestBuildMessage_RejectsNonInitiatorTypes verifies BuildMessage fails closed
// for the server-originated reply types and for unknown types — an agent never
// builds those.
func TestBuildMessage_RejectsNonInitiatorTypes(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)
	inp := &relayknock.KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1,
		Counter:          1,
		Preamble:         1,
		Body:             []byte("x"),
	}

	for _, typ := range []int{relayknock.TypeRegisterAck, relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, 0, 8, 99} {
		packet, err := relayknock.BuildMessage(typ, inp)
		if err == nil {
			t.Errorf("BuildMessage(%d) succeeded, want reject", typ)
		}
		if packet != nil {
			t.Errorf("BuildMessage(%d) returned a packet alongside the reject", typ)
		}
	}
}

// TestRelayPost_CarriesBrowserControlPackets pins the raw public browser-relay
// escape hatch after the typed HTTP lifecycle helpers are retired. A caller can
// still build NHP_RKN or NHP_EXT and carry the exact bytes through RelayPost.
func TestRelayPost_CarriesBrowserControlPackets(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)

	for _, tt := range []struct {
		name       string
		headerType int
		cookie     []byte
		body       []byte
	}{
		{name: "reknock", headerType: relayknock.TypeReknock, cookie: bytes.Repeat([]byte{0x44}, 32), body: []byte("browser control")},
		{name: "exit", headerType: relayknock.TypeExit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := relayknock.BuildMessage(tt.headerType, &relayknock.KnockInputs{
				DeviceStaticPriv: devicePriv,
				ServerStaticPub:  serverPub,
				EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
				TimestampNanos:   1700000000123456789,
				Counter:          42,
				Preamble:         0x01020304,
				Body:             tt.body,
				Cookie:           tt.cookie,
			})
			if err != nil {
				t.Fatalf("BuildMessage(%d): %v", tt.headerType, err)
			}

			wantReply := []byte{byte(relayknock.TypeACK), byte(tt.headerType)}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/relay/cell-key-fingerprint" {
					t.Errorf("relay path = %q, want /relay/cell-key-fingerprint", r.URL.Path)
				}
				if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
					t.Errorf("Content-Type = %q, want application/octet-stream", got)
				}
				gotPacket, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Errorf("read relay request: %v", readErr)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if !bytes.Equal(gotPacket, packet) {
					t.Error("RelayPost changed the caller-built browser control packet")
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(wantReply)
			}))
			defer srv.Close()

			gotReply, err := relayknock.RelayPost(context.Background(), nil, srv.URL, "cell-key-fingerprint", packet)
			if err != nil {
				t.Fatalf("RelayPost: %v", err)
			}
			if !bytes.Equal(gotReply, wantReply) {
				t.Fatalf("RelayPost reply = %x, want %x", gotReply, wantReply)
			}
		})
	}
}

func TestRelayPost_RejectsAgentLifecyclePacketsBeforeHTTP(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer srv.Close()

	for _, tt := range []struct {
		name       string
		headerType int
	}{
		{name: "assignment", headerType: relayknock.TypeListRequest},
		{name: "otp", headerType: relayknock.TypeOTP},
		{name: "registration", headerType: relayknock.TypeRegister},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := relayknock.BuildMessage(tt.headerType, &relayknock.KnockInputs{
				DeviceStaticPriv: devicePriv,
				ServerStaticPub:  serverPub,
				EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
				TimestampNanos:   1700000000123456789,
				Counter:          42,
				Preamble:         0x01020304,
				Body:             []byte("native UDP only"),
			})
			if err != nil {
				t.Fatalf("BuildMessage(%d): %v", tt.headerType, err)
			}
			if _, err := relayknock.RelayPost(context.Background(), nil, srv.URL, "cell-key-fingerprint", packet); err == nil || !strings.Contains(err.Error(), "browser relay accepts only") {
				t.Fatalf("RelayPost(%d) error = %v, want browser-relay type rejection", tt.headerType, err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("agent lifecycle packets reached HTTP %d times, want 0", requests)
	}
}

// TestRelayPost_NonOKStatusIsRelayError pins the public transport-fault contract:
// RelayPost's calling contract is 200 with reply packet bytes, so every other
// status is a *RelayError carrying the numeric status. A consumer branches on
// that concrete type to separate "the relay could not deliver this" from an
// authenticated server deny riding inside a decryptable reply, so the type and
// the Status field are both load-bearing API. The relay's response body is
// appended as detail only when it carries one — an empty body must not leave a
// dangling separator in the message.
func TestRelayPost_NonOKStatusIsRelayError(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)

	packet, err := relayknock.BuildMessage(relayknock.TypeKnock, &relayknock.KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1700000000123456789,
		Counter:          42,
		Preamble:         0x01020304,
		Body:             []byte("knock body"),
	})
	if err != nil {
		t.Fatalf("BuildMessage(TypeKnock): %v", err)
	}

	tests := []struct {
		name    string
		status  int
		body    string
		wantSub string
	}{
		{name: "unknown server", status: http.StatusNotFound, body: "unknown server id", wantSub: "unknown server id"},
		{name: "forward failure", status: http.StatusBadGateway, body: "forward failed", wantSub: "forward failed"},
		{name: "shutting down", status: http.StatusServiceUnavailable, body: "", wantSub: "-> 503"},
		{name: "unexpected redirect body", status: http.StatusNoContent, body: "", wantSub: "-> 204"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			reply, err := relayknock.RelayPost(context.Background(), nil, srv.URL, "cell-key-fingerprint", packet)
			if err == nil {
				t.Fatalf("RelayPost accepted status %d and returned %d reply bytes", tt.status, len(reply))
			}
			if reply != nil {
				t.Errorf("RelayPost returned reply bytes alongside the error: %x", reply)
			}
			var relayErr *relayknock.RelayError
			if !errors.As(err, &relayErr) {
				t.Fatalf("error %q is not *relayknock.RelayError; a consumer cannot branch on the transport fault", err)
			}
			if relayErr.Status != tt.status {
				t.Errorf("RelayError.Status = %d, want %d", relayErr.Status, tt.status)
			}
			if !strings.Contains(relayErr.Error(), tt.wantSub) {
				t.Errorf("RelayError.Error() = %q, does not contain %q", relayErr.Error(), tt.wantSub)
			}
			if tt.body == "" && strings.HasSuffix(relayErr.Error(), ": ") {
				t.Errorf("RelayError.Error() = %q, has a dangling detail separator for an empty relay body", relayErr.Error())
			}
		})
	}
}

func TestRelayPost_RejectsMalformedPacketBeforeHTTP(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer srv.Close()

	if _, err := relayknock.RelayPost(context.Background(), nil, srv.URL, "cell-key-fingerprint", []byte{1, 2, 3}); err == nil || !strings.Contains(err.Error(), "malformed NHP packet") {
		t.Fatalf("RelayPost(short packet) error = %v, want malformed-packet rejection", err)
	}
	if requests != 0 {
		t.Fatalf("malformed packet reached HTTP %d times, want 0", requests)
	}
}

// fabricateRAK builds a server-originated NHP_RAK via relayknocktest.BuildReply
// with the roles swapped: the server's static key is the initiator of the fresh
// reply handshake and the agent's static public key is the responder — the same
// direction as the golden ack vector.
// It returns an error instead of failing the test itself: httptest handlers
// run on their own goroutines, where t.Fatalf would only Goexit the handler —
// each caller reports the error on whichever goroutine it owns.
func fabricateRAK(serverPriv, devicePub []byte, counter uint64, body []byte) ([]byte, error) {
	return relayknocktest.BuildReply(relayknock.TypeRegisterAck, &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, 32),
		TimestampNanos:   1700000000987654321,
		Counter:          counter,
		Preamble:         0xa1b2c3d4,
		Body:             body,
	})
}

// TestDecryptReply_RegisterAck opens a fabricated NHP_RAK as an agent would and
// asserts the type predicates: RAK is a reply type, so the exported DecryptReply
// accepts it and it decrypts exactly like the golden ack, only the Type differs.
func TestDecryptReply_RegisterAck(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	body := []byte("registration acknowledged")

	rak, err := fabricateRAK(serverPriv, devicePub, 7, body)
	if err != nil {
		t.Fatalf("fabricate NHP_RAK: %v", err)
	}
	reply, err := relayknock.DecryptReply(devicePriv, serverPub, rak)
	if err != nil {
		t.Fatalf("DecryptReply: %v", err)
	}
	if !reply.IsRegisterAck() {
		t.Errorf("IsRegisterAck() = false for an NHP_RAK (Type = %d)", reply.Type)
	}
	if reply.IsACK() {
		t.Error("IsACK() = true for an NHP_RAK, want false")
	}
	if reply.Type != relayknock.TypeRegisterAck {
		t.Errorf("Type = %d, want %d (TypeRegisterAck)", reply.Type, relayknock.TypeRegisterAck)
	}
	if !bytes.Equal(reply.Body, body) {
		t.Errorf("Body = %q, want %q", reply.Body, body)
	}
}

// TestKnock_RejectsMismatchedReply pins the defense-in-depth pairing: the reply
// header's type and counter ride outside the AEAD, so Knock itself —
// not just the caller's predicates — must reject an authenticated reply whose
// type the request cannot elicit or whose counter does not echo the request.
func TestKnock_RejectsMismatchedReply(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	tests := []struct {
		name       string
		replyType  int
		counterOff uint64
		wantSub    string
	}{
		{name: "RAK to a knock", replyType: relayknock.TypeRegisterAck, wantSub: "not a valid reply"},
		{name: "counter not echoed", replyType: relayknock.TypeACK, counterOff: 1, wantSub: "does not echo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				packet, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read posted packet: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				req, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet)
				if err != nil {
					t.Errorf("server-side open of posted packet: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				reply, err := relayknocktest.BuildReply(tt.replyType, &relayknock.KnockInputs{
					DeviceStaticPriv: serverPriv,
					ServerStaticPub:  devicePub,
					EphemeralPriv:    bytes.Repeat([]byte{0x45}, 32),
					TimestampNanos:   1700000000987654321,
					Counter:          req.Counter + tt.counterOff,
					Preamble:         0xa1b2c3d4,
					Body:             []byte("mismatched reply"),
				})
				if err != nil {
					t.Errorf("fabricate mismatched reply: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(reply)
			}))
			defer srv.Close()

			_, err := relayknock.Knock(context.Background(), srv.URL, serverPub, []byte("request body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
			if err == nil {
				t.Fatal("Knock succeeded, want mismatch rejection")
			}
			if !errors.Is(err, relayknock.ErrMalformedReply) {
				t.Errorf("error %q is not relayknock.ErrMalformedReply; a consumer taxonomy cannot map it", err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

// TestKnock_RoundTrip exercises the production Knock front door end-to-end
// against a fabricated matched NHP_ACK. The knock/ack golden vector is a
// standalone reply that does not correlate to a request, so this is the test
// that proves the KNK→ACK qURL resolve path. It enforces counter echo and the
// ACK/COK reply gate: a reply whose counter
// echoes the knock is accepted (IsACK, body recovered), and a reply whose
// counter does not echo is rejected as ErrMalformedReply.
func TestKnock_RoundTrip(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	const admission = "authorized admission body"

	// ackServer fabricates an NHP_ACK whose counter is the knock's counter plus
	// counterOffset (0 = a conforming echo; non-zero = a mis-correlated reply).
	ackServer := func(counterOffset uint64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			packet, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read posted packet: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			req, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet)
			if err != nil {
				t.Errorf("server-side open of knock: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			ack, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{
				DeviceStaticPriv: serverPriv,
				ServerStaticPub:  devicePub,
				EphemeralPriv:    bytes.Repeat([]byte{0x53}, 32),
				TimestampNanos:   1700000000123456789,
				Counter:          req.Counter + counterOffset,
				Preamble:         0xa1b2c3d4,
				Body:             []byte(admission),
			})
			if err != nil {
				t.Errorf("fabricate ACK: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(ack)
		}))
	}

	t.Run("matched counter is accepted", func(t *testing.T) {
		srv := ackServer(0)
		defer srv.Close()
		reply, err := relayknock.Knock(context.Background(), srv.URL, serverPub, []byte("knock body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
		if err != nil {
			t.Fatalf("Knock with a matched ACK: %v", err)
		}
		if !reply.IsACK() {
			t.Errorf("reply.Type = %d, want NHP_ACK (IsACK)", reply.Type)
		}
		if string(reply.Body) != admission {
			t.Errorf("reply.Body = %q, want %q", reply.Body, admission)
		}
	})

	t.Run("non-echoed counter is rejected as ErrMalformedReply", func(t *testing.T) {
		srv := ackServer(1)
		defer srv.Close()
		_, err := relayknock.Knock(context.Background(), srv.URL, serverPub, []byte("knock body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
		if !errors.Is(err, relayknock.ErrMalformedReply) {
			t.Fatalf("Knock with a mis-correlated ACK: err = %v, want ErrMalformedReply", err)
		}
	})
}

// TestKnock_CookieChallengeBeforeCounterCheck pins the overload-signal ordering:
// an authenticated NHP_COK is a valid reply to a knock, and Knock
// must return it as a cookie-challenge (the "server busy, retry later" signal a
// caller branches with IsCookieChallenge) BEFORE applying the counter-echo
// check. A COK is not a protocol transaction — the reference server documents it
// as "not handled as a transaction" and only stamps it with the request counter
// as a relay-routing concession — so a COK whose counter does not correlate (an
// older/clustered server, a window boundary, a non-conforming relay) must not be
// downgraded to ErrMalformedReply and lose the retryable overload outcome on the
// hot path. Here the fabricated COK deliberately carries a non-matching counter.
func TestKnock_CookieChallengeBeforeCounterCheck(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("server-side open: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// NHP_COK answering the knock, but with a counter that does NOT echo the
		// request — the case the reorder must tolerate as overload, not reject.
		cok, err := relayknocktest.BuildReply(relayknock.TypeCookieChallenge, &relayknock.KnockInputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    bytes.Repeat([]byte{0x48}, 32),
			TimestampNanos:   1700000000987654321,
			Counter:          req.Counter + 1,
			Preamble:         0xa1b2c3d4,
			Body:             nil,
		})
		if err != nil {
			t.Errorf("fabricate COK: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(cok)
	}))
	defer srv.Close()

	reply, err := relayknock.Knock(context.Background(), srv.URL, serverPub, []byte("request body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
	if err != nil {
		t.Fatalf("Knock returned an error for an overload NHP_COK; the retryable signal was lost: %v", err)
	}
	if !reply.IsCookieChallenge() {
		t.Fatalf("reply Type = %d, want NHP_COK (IsCookieChallenge); the caller cannot detect overload", reply.Type)
	}
	if reply.IsACK() {
		t.Error("IsACK() = true for an NHP_COK, want false")
	}
}

// TestDecryptReply_UnknownType pins the explicit rejection of header types this
// package does not speak: the type field is not AEAD-covered, so garbage there
// decrypts fine and must be refused by the type gate, not by a silent
// all-predicates-false Reply. Fabricated via the internal nhpwire codec, which
// applies no type restriction.
func TestDecryptReply_UnknownType(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	pkt, err := nhpwire.BuildMessage(99, &nhpwire.Inputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x46}, 32),
		TimestampNanos:   1700000000987654321,
		Counter:          5,
		Preamble:         0xa1b2c3d4,
		Body:             []byte("type 99"),
	})
	if err != nil {
		t.Fatalf("fabricate type-99 packet: %v", err)
	}
	_, err = relayknock.DecryptReply(devicePriv, serverPub, pkt)
	if !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("DecryptReply on an unknown header type: err = %v, want ErrMalformedReply", err)
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error %q does not name the unknown type", err)
	}
}

// TestBuildReply_RejectsInitiatorTypes verifies relayknocktest.BuildReply fails
// closed for the initiator types (an agent's message kinds) and unknown types —
// the mirror of relayknock.BuildMessage's reply-type rejection.
func TestBuildReply_RejectsInitiatorTypes(t *testing.T) {
	serverPriv, devicePub := testKeyPair(t, 0x22)
	inp := &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1,
		Counter:          1,
		Preamble:         1,
		Body:             []byte("x"),
	}
	for _, typ := range []int{relayknock.TypeKnock, relayknock.TypeListRequest, relayknock.TypeOTP, relayknock.TypeRegister, 0, 99} {
		if pkt, err := relayknocktest.BuildReply(typ, inp); err == nil || pkt != nil {
			t.Errorf("BuildReply(%d) = (%v, %v), want reject", typ, pkt, err)
		}
	}
}

// TestKnock_InputValidation locks the outbound knock validation contract:
// bad key material errors out before any relay POST.
func TestKnock_InputValidation(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("input validation must reject before any relay POST")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := relayknock.Knock(context.Background(), srv.URL, serverPub[:31], []byte("x"), relayknock.KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Knock(short server pub) = %v, want server-static-pub size error", err)
	}
	nonCanonical := bytes.Repeat([]byte{0xff}, 32)
	if _, err := relayknock.Knock(context.Background(), srv.URL, nonCanonical, []byte("x"), relayknock.KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Knock(non-canonical server pub) = %v, want unusable-server-key error", err)
	}
	if _, err := relayknock.Knock(context.Background(), srv.URL, serverPub, []byte("x"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv[:16]}); err == nil || !strings.Contains(err.Error(), "device static priv") {
		t.Errorf("Knock(short device priv) = %v, want device-static-priv size error", err)
	}
}

// TestDecryptReply_RejectsInitiatorTypes pins the exported reply gate: every
// authenticated initiator type is refused by DecryptReply, so a direct caller
// can never receive a Reply that matches no Is* predicate. The responder-role
// OpenInitiatorMessage still opens each one.
func TestDecryptReply_RejectsInitiatorTypes(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	for _, tc := range []struct {
		name       string
		headerType int
	}{
		{name: "knock", headerType: relayknock.TypeKnock},
		{name: "list request", headerType: relayknock.TypeListRequest},
		{name: "otp", headerType: relayknock.TypeOTP},
		{name: "register", headerType: relayknock.TypeRegister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := relayknock.BuildMessage(tc.headerType, &relayknock.KnockInputs{
				DeviceStaticPriv: devicePriv,
				ServerStaticPub:  serverPub,
				EphemeralPriv:    bytes.Repeat([]byte{0x55}, 32),
				TimestampNanos:   1700000000123456789,
				Counter:          9,
				Preamble:         0x0a0b0c0d,
				Body:             []byte("initiator body"),
			})
			if err != nil {
				t.Fatalf("BuildMessage(%d): %v", tc.headerType, err)
			}
			if _, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet); err != nil {
				t.Fatalf("OpenInitiatorMessage(%d) = %v, want accept", tc.headerType, err)
			}
			if _, err := relayknock.DecryptReply(serverPriv, devicePub, packet); err == nil {
				t.Fatal("DecryptReply accepted an initiator type, want reject")
			} else if !errors.Is(err, relayknock.ErrMalformedReply) {
				t.Errorf("DecryptReply(%d) error %q, want ErrMalformedReply", tc.headerType, err)
			}
		})
	}
}

// TestBuildReply_RoundTripsUnderDecryptReply verifies relayknocktest.BuildReply
// produces every reply type such that relayknock.DecryptReply opens it exactly
// like a real server reply.
func TestBuildReply_RoundTripsUnderDecryptReply(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	tests := []struct {
		name      string
		replyType int
		wantIsRAK bool
		wantIsACK bool
		wantIsLRT bool
	}{
		{name: "ack", replyType: relayknock.TypeACK, wantIsACK: true},
		{name: "list result", replyType: relayknock.TypeListResult, wantIsLRT: true},
		{name: "cookie challenge", replyType: relayknock.TypeCookieChallenge},
		{name: "register ack", replyType: relayknock.TypeRegisterAck, wantIsRAK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const counter = uint64(0x0102030405060708)
			body := []byte("reply body: " + tt.name)
			reply, err := relayknocktest.BuildReply(tt.replyType, &relayknock.KnockInputs{
				DeviceStaticPriv: serverPriv,
				ServerStaticPub:  devicePub,
				EphemeralPriv:    bytes.Repeat([]byte{0x77}, 32),
				TimestampNanos:   1700000000111111111,
				Counter:          counter,
				Preamble:         0x0badf00d,
				Body:             body,
			})
			if err != nil {
				t.Fatalf("BuildReply(%d): %v", tt.replyType, err)
			}
			got, err := relayknock.DecryptReply(devicePriv, serverPub, reply)
			if err != nil {
				t.Fatalf("DecryptReply: %v", err)
			}
			if got.Type != tt.replyType {
				t.Errorf("Type = %d, want %d", got.Type, tt.replyType)
			}
			if got.Counter != counter {
				t.Errorf("Counter = %#x, want %#x", got.Counter, counter)
			}
			if got.IsRegisterAck() != tt.wantIsRAK {
				t.Errorf("IsRegisterAck() = %v, want %v", got.IsRegisterAck(), tt.wantIsRAK)
			}
			if got.IsACK() != tt.wantIsACK {
				t.Errorf("IsACK() = %v, want %v", got.IsACK(), tt.wantIsACK)
			}
			if got.IsListResult() != tt.wantIsLRT {
				t.Errorf("IsListResult() = %v, want %v", got.IsListResult(), tt.wantIsLRT)
			}
			if !bytes.Equal(got.Body, body) {
				t.Errorf("Body = %q, want %q", got.Body, body)
			}
		})
	}
}
