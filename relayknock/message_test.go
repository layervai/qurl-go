package relayknock

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for the registration message types (NHP_OTP / NHP_REG / NHP_RAK) and
// their orchestrators (BuildMessage, Exchange, Send). The wire format itself is
// fenced byte-for-byte by knock_golden_test.go — the transcript is independent
// of the header type — so these tests fence the type plumbing around it with
// symmetric round trips: a packet built with the device key opens with the
// server key (DecryptReply's transcript is role-symmetric), which is exactly
// how the reference responder reads an initiator packet.

// testKeyPair derives a deterministic X25519 key pair from a repeated seed
// byte, so failures reproduce without golden fixtures (clamping is internal to
// x25519Public, so any 32 bytes are a valid scalar).
func testKeyPair(t *testing.T, seed byte) (priv, pub []byte) {
	t.Helper()
	priv = bytes.Repeat([]byte{seed}, 32)
	pub, err := x25519Public(priv)
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
		{name: "otp", headerType: TypeOTP, wantWire: 12},
		{name: "register", headerType: TypeRegister, wantWire: 13},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				counter   = uint64(0xfeedfacecafebeef)
				timestamp = uint64(1700000000123456789)
			)
			body := []byte("opaque application bytes: " + tt.name)

			packet, err := BuildMessage(tt.headerType, &KnockInputs{
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
			got, err := DecryptReply(serverPriv, devicePub, packet)
			if err != nil {
				t.Fatalf("DecryptReply: %v", err)
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

// TestBuildMessage_KnockMatchesBuildKnock pins the BuildKnock delegation:
// BuildMessage(TypeKnock, inp) and BuildKnock(inp) emit identical bytes for
// identical inputs.
func TestBuildMessage_KnockMatchesBuildKnock(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)
	inp := &KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1700000000123456789,
		Counter:          42,
		Preamble:         0x01020304,
		Body:             []byte("knock body"),
	}

	viaKnock, err := BuildKnock(inp)
	if err != nil {
		t.Fatalf("BuildKnock: %v", err)
	}
	viaMessage, err := BuildMessage(TypeKnock, inp)
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
	inp := &KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
		TimestampNanos:   1,
		Counter:          1,
		Preamble:         1,
		Body:             []byte("x"),
	}

	for _, typ := range []int{TypeRegisterAck, TypeACK, TypeCookieChallenge, 0, 8, 99} {
		packet, err := BuildMessage(typ, inp)
		if err == nil {
			t.Errorf("BuildMessage(%d) succeeded, want reject", typ)
		}
		if packet != nil {
			t.Errorf("BuildMessage(%d) returned a packet alongside the reject", typ)
		}
	}
}

// TestExchange_RejectsNonRoundTripTypes verifies Exchange fails closed — before
// any relay POST — for the one-way TypeOTP (which has no reply to exchange) and
// for non-initiator/unknown types.
func TestExchange_RejectsNonRoundTripTypes(t *testing.T) {
	_, serverPub := testKeyPair(t, 0x22)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("Exchange must reject the header type before any relay POST")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Exchange(context.Background(), srv.URL, serverPub, TypeOTP, []byte("x"), KnockOptions{})
	if err == nil {
		t.Fatal("Exchange(TypeOTP) succeeded, want reject")
	}
	if !strings.Contains(err.Error(), "Send") {
		t.Errorf("Exchange(TypeOTP) error %q does not point the caller at Send", err)
	}

	for _, typ := range []int{TypeACK, TypeCookieChallenge, TypeRegisterAck, 0, 99} {
		if _, err := Exchange(context.Background(), srv.URL, serverPub, typ, []byte("x"), KnockOptions{}); err == nil {
			t.Errorf("Exchange(%d) succeeded, want reject", typ)
		}
	}
}

// fabricateRAK builds a server-originated NHP_RAK via the internal buildMessage
// with the roles swapped: the server's static key is the initiator of the fresh
// reply handshake and the agent's static public key is the responder — the same
// direction as the golden ack vector.
// It returns an error instead of failing the test itself: httptest handlers
// run on their own goroutines, where t.Fatalf would only Goexit the handler —
// each caller reports the error on whichever goroutine it owns.
func fabricateRAK(serverPriv, devicePub []byte, counter uint64, body []byte) ([]byte, error) {
	return buildMessage(nhpRAK, &KnockInputs{
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
// asserts the type predicates: DecryptReply is type-agnostic, so a RAK decrypts
// exactly like the golden ack and only the Type differs.
func TestDecryptReply_RegisterAck(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	body := []byte("registration acknowledged")

	rak, err := fabricateRAK(serverPriv, devicePub, 7, body)
	if err != nil {
		t.Fatalf("fabricate NHP_RAK: %v", err)
	}
	reply, err := DecryptReply(devicePriv, serverPub, rak)
	if err != nil {
		t.Fatalf("DecryptReply: %v", err)
	}
	if !reply.IsRegisterAck() {
		t.Errorf("IsRegisterAck() = false for an NHP_RAK (Type = %d)", reply.Type)
	}
	if reply.IsACK() {
		t.Error("IsACK() = true for an NHP_RAK, want false")
	}
	if reply.Type != TypeRegisterAck {
		t.Errorf("Type = %d, want %d (TypeRegisterAck)", reply.Type, TypeRegisterAck)
	}
	if !bytes.Equal(reply.Body, body) {
		t.Errorf("Body = %q, want %q", reply.Body, body)
	}
}

// TestExchange_RegisterRoundTrip runs the full NHP_REG round trip against an
// httptest relay whose handler plays the server: it opens the posted packet
// with the server static key, asserts it is an NHP_REG carrying the caller's
// body, and answers with a fabricated NHP_RAK correlated by the request
// counter.
func TestExchange_RegisterRoundTrip(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	regBody := []byte("serialized registration body")
	rakBody := []byte("registration ack body")

	counterCh := make(chan uint64, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/relay/" + PubKeyFingerprint(serverPub); r.URL.Path != want {
			t.Errorf("relay path = %q, want %q", r.URL.Path, want)
		}
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := DecryptReply(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("server-side open of posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if req.Type != TypeRegister {
			t.Errorf("posted packet type = %d, want %d (TypeRegister)", req.Type, TypeRegister)
		}
		if !bytes.Equal(req.Body, regBody) {
			t.Errorf("posted body = %q, want %q", req.Body, regBody)
		}
		counterCh <- req.Counter

		rak, err := fabricateRAK(serverPriv, devicePub, req.Counter, rakBody)
		if err != nil {
			t.Errorf("fabricate NHP_RAK: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(rak)
	}))
	defer srv.Close()

	reply, err := Exchange(context.Background(), srv.URL, serverPub, TypeRegister, regBody, KnockOptions{
		DeviceStaticPriv: devicePriv,
	})
	if err != nil {
		t.Fatalf("Exchange(TypeRegister): %v", err)
	}
	if !reply.IsRegisterAck() {
		t.Errorf("reply.Type = %d, want %d (NHP_RAK)", reply.Type, TypeRegisterAck)
	}
	if !bytes.Equal(reply.Body, rakBody) {
		t.Errorf("reply body = %q, want %q", reply.Body, rakBody)
	}
	if requestCounter := <-counterCh; reply.Counter != requestCounter {
		t.Errorf("reply counter %#x does not correlate with request counter %#x", reply.Counter, requestCounter)
	}
}

// TestSend_PostsOTPPacket verifies the packet Send actually posts: the relay
// handler opens it with the server static key, asserts it is an NHP_OTP
// carrying the caller's body, and acknowledges with the conforming
// 202-empty-body dispatch ack.
func TestSend_PostsOTPPacket(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	otpBody := []byte("serialized otp request body")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/relay/" + PubKeyFingerprint(serverPub); r.URL.Path != want {
			t.Errorf("relay path = %q, want %q", r.URL.Path, want)
		}
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := DecryptReply(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("server-side open of posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if req.Type != TypeOTP {
			t.Errorf("posted packet type = %d, want %d (TypeOTP)", req.Type, TypeOTP)
		}
		if !bytes.Equal(req.Body, otpBody) {
			t.Errorf("posted body = %q, want %q", req.Body, otpBody)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := Send(context.Background(), srv.URL, serverPub, otpBody, KnockOptions{
		DeviceStaticPriv: devicePriv,
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// TestSend_RelayContract pins Send's HTTP-layer dispatch contract: 202 with an
// empty body is the only success; a 200 with reply bytes, a 202 with a body,
// and relay 5xx faults all fail with a *RelayError that carries the status and
// states the retry semantics.
func TestSend_RelayContract(t *testing.T) {
	_, serverPub := testKeyPair(t, 0x22)

	tests := []struct {
		name     string
		status   int
		respBody []byte
		wantErr  bool
	}{
		{name: "202 empty is the success", status: http.StatusAccepted, respBody: nil, wantErr: false},
		{name: "200 with reply bytes", status: http.StatusOK, respBody: []byte{0xde, 0xad, 0xbe, 0xef}, wantErr: true},
		{name: "200 empty", status: http.StatusOK, respBody: nil, wantErr: true},
		{name: "202 with body", status: http.StatusAccepted, respBody: []byte("forwarded"), wantErr: true},
		{name: "503 service unavailable", status: http.StatusServiceUnavailable, respBody: []byte("relay draining"), wantErr: true},
		{name: "504 gateway timeout", status: http.StatusGatewayTimeout, respBody: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				if len(tt.respBody) > 0 {
					_, _ = w.Write(tt.respBody)
				}
			}))
			defer srv.Close()

			err := Send(context.Background(), srv.URL, serverPub, []byte("otp request"), KnockOptions{})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Send: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Send succeeded, want error")
			}
			var relayErr *RelayError
			if !errors.As(err, &relayErr) {
				t.Fatalf("Send error is %T, want *RelayError", err)
			}
			if relayErr.Status != tt.status {
				t.Errorf("RelayError.Status = %d, want %d", relayErr.Status, tt.status)
			}
			if !strings.Contains(err.Error(), "retry") {
				t.Errorf("Send error %q does not state the retry semantics", err)
			}
		})
	}
}

// TestExchange_RejectsMismatchedReply pins the defense-in-depth pairing: the
// reply header's type and counter ride outside the AEAD, so Exchange itself —
// not just the caller's predicates — must reject an authenticated reply whose
// type the request cannot elicit or whose counter does not echo the request.
func TestExchange_RejectsMismatchedReply(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	tests := []struct {
		name       string
		reqType    int
		replyType  int
		counterOff uint64
		wantSub    string
	}{
		{name: "RAK to a knock", reqType: TypeKnock, replyType: nhpRAK, wantSub: "not a valid reply"},
		{name: "ACK to a register", reqType: TypeRegister, replyType: nhpACK, wantSub: "not a valid reply"},
		{name: "COK to a register", reqType: TypeRegister, replyType: nhpCOK, wantSub: "not a valid reply"},
		{name: "counter not echoed", reqType: TypeRegister, replyType: nhpRAK, counterOff: 1, wantSub: "does not echo"},
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
				req, err := DecryptReply(serverPriv, devicePub, packet)
				if err != nil {
					t.Errorf("server-side open of posted packet: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				reply, err := buildMessage(tt.replyType, &KnockInputs{
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

			_, err := Exchange(context.Background(), srv.URL, serverPub, tt.reqType, []byte("request body"), KnockOptions{DeviceStaticPriv: devicePriv})
			if err == nil {
				t.Fatal("Exchange succeeded, want mismatch rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

// TestDecryptReply_UnknownType pins the explicit rejection of header types this
// package does not speak: the type field is not AEAD-covered, so garbage there
// decrypts fine and must be refused by the type gate, not by a silent
// all-predicates-false Reply.
func TestDecryptReply_UnknownType(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	pkt, err := buildMessage(99, &KnockInputs{
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
	_, err = DecryptReply(devicePriv, serverPub, pkt)
	if err == nil {
		t.Fatal("DecryptReply accepted an unknown header type, want rejection")
	}
	if !strings.Contains(err.Error(), "unknown NHP header type 99") {
		t.Errorf("error %q does not name the unknown type", err)
	}
}

// TestSendExchange_InputValidation locks the buildOutbound validation contract
// as surfaced through Send and Exchange: bad key sizes error out before any
// relay POST.
func TestSendExchange_InputValidation(t *testing.T) {
	devicePriv, _ := testKeyPair(t, 0x11)
	_, serverPub := testKeyPair(t, 0x22)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("input validation must reject before any relay POST")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := Send(context.Background(), srv.URL, serverPub[:31], []byte("x"), KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Send(short server pub) = %v, want server-static-pub size error", err)
	}
	if err := Send(context.Background(), srv.URL, serverPub, []byte("x"), KnockOptions{DeviceStaticPriv: devicePriv[:16]}); err == nil || !strings.Contains(err.Error(), "device static priv") {
		t.Errorf("Send(short device priv) = %v, want device-static-priv size error", err)
	}
	if _, err := Exchange(context.Background(), srv.URL, serverPub[:31], TypeRegister, []byte("x"), KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Exchange(short server pub) = %v, want server-static-pub size error", err)
	}
}

// TestSend_TransportFault locks the Status-0 RelayError contract for a
// transport-level failure (no HTTP response at all).
func TestSend_TransportFault(t *testing.T) {
	_, serverPub := testKeyPair(t, 0x22)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.Close() // connection refused from here on

	err := Send(context.Background(), srv.URL, serverPub, []byte("x"), KnockOptions{})
	if err == nil {
		t.Fatal("Send to a closed relay succeeded, want transport fault")
	}
	var re *RelayError
	if !errors.As(err, &re) {
		t.Fatalf("Send transport fault is %T, want *RelayError", err)
	}
	if re.Status != 0 {
		t.Errorf("transport fault Status = %d, want 0 (no HTTP response)", re.Status)
	}
}
