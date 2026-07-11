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
// server key via decryptMessage (the transcript is role-symmetric), which is
// exactly how the reference responder reads an initiator packet. Reply-type
// opens go through the exported DecryptReply, which additionally gates out
// initiator types.

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
			got, err := decryptMessage(serverPriv, devicePub, packet)
			if err != nil {
				t.Fatalf("decryptMessage: %v", err)
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

// fabricateACK builds a server-originated NHP_ACK the same way fabricateRAK
// builds an NHP_RAK — internal buildMessage with the roles swapped (server
// static key as the fresh handshake's initiator, agent static public key as the
// responder), the direction of the golden ack vector. It returns an error rather
// than failing the test so an httptest handler goroutine can surface it itself.
func fabricateACK(serverPriv, devicePub []byte, counter uint64, body []byte) ([]byte, error) {
	return buildMessage(nhpACK, &KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x47}, 32),
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
		req, err := decryptMessage(serverPriv, devicePub, packet)
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

// TestKnock_RoundTrip runs the full NHP_KNK happy path through the production
// Knock front door against an httptest relay whose handler plays the server: it
// opens the posted packet with the server static key, asserts it is an NHP_KNK
// carrying the caller's body, and answers with a fabricated NHP_ACK correlated by
// the request counter. This is the matched KNK↔ACK pair TestExchange_RegisterRoundTrip
// is for REG↔RAK: it exercises the production resolve path's counter-echo +
// replyTypeAllowed enforcement end to end (the knock/ack goldens are not a matched
// pair). The negative subcase pins the counter fence — an ACK whose counter does
// not echo the request fails closed with ErrMalformedReply.
func TestKnock_RoundTrip(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	knockBody := []byte("serialized knock body")
	ackBody := []byte("authorized admission body")

	// newRelay plays the server, echoing the request counter shifted by
	// counterOff into the fabricated ACK (0 = a correct echo, nonzero = a reply
	// that must fail the counter fence).
	newRelay := func(counterOff uint64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if want := "/relay/" + PubKeyFingerprint(serverPub); r.URL.Path != want {
				t.Errorf("relay path = %q, want %q", r.URL.Path, want)
			}
			packet, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read posted packet: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			req, err := decryptMessage(serverPriv, devicePub, packet)
			if err != nil {
				t.Errorf("server-side open of posted packet: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if req.Type != TypeKnock {
				t.Errorf("posted packet type = %d, want %d (TypeKnock)", req.Type, TypeKnock)
			}
			if !bytes.Equal(req.Body, knockBody) {
				t.Errorf("posted body = %q, want %q", req.Body, knockBody)
			}
			ack, err := fabricateACK(serverPriv, devicePub, req.Counter+counterOff, ackBody)
			if err != nil {
				t.Errorf("fabricate NHP_ACK: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(ack)
		}))
	}

	t.Run("counter echoed", func(t *testing.T) {
		srv := newRelay(0)
		defer srv.Close()

		reply, err := Knock(context.Background(), srv.URL, serverPub, knockBody, KnockOptions{
			DeviceStaticPriv: devicePriv,
		})
		if err != nil {
			t.Fatalf("Knock: %v", err)
		}
		if !reply.IsACK() {
			t.Errorf("reply.Type = %d, want %d (NHP_ACK / IsACK)", reply.Type, TypeACK)
		}
		if reply.IsCookieChallenge() {
			t.Error("IsCookieChallenge() = true for an NHP_ACK, want false")
		}
		if !bytes.Equal(reply.Body, ackBody) {
			t.Errorf("reply body = %q, want %q", reply.Body, ackBody)
		}
	})

	t.Run("counter not echoed", func(t *testing.T) {
		srv := newRelay(1)
		defer srv.Close()

		_, err := Knock(context.Background(), srv.URL, serverPub, knockBody, KnockOptions{
			DeviceStaticPriv: devicePriv,
		})
		if err == nil {
			t.Fatal("Knock accepted an ACK that does not echo the request counter, want reject")
		}
		if !errors.Is(err, ErrMalformedReply) {
			t.Errorf("error %q is not ErrMalformedReply; a consumer taxonomy cannot map it", err)
		}
	})
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
		req, err := decryptMessage(serverPriv, devicePub, packet)
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
				req, err := decryptMessage(serverPriv, devicePub, packet)
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
			if !errors.Is(err, ErrMalformedReply) {
				t.Errorf("error %q is not ErrMalformedReply; a consumer taxonomy cannot map it", err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

// TestExchange_CookieChallengeBeforeCounterCheck pins the overload-signal
// ordering: an authenticated NHP_COK is a valid reply to a knock, and Exchange
// must return it as a cookie-challenge (the "server busy, retry later" signal a
// caller branches with IsCookieChallenge) BEFORE applying the counter-echo
// check. A COK is not a protocol transaction — the reference server documents it
// as "not handled as a transaction" and only stamps it with the request counter
// as a relay-routing concession — so a COK whose counter does not correlate (an
// older/clustered server, a window boundary, a non-conforming relay) must not be
// downgraded to ErrMalformedReply and lose the retryable overload outcome on the
// hot path. Here the fabricated COK deliberately carries a non-matching counter.
func TestExchange_CookieChallengeBeforeCounterCheck(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := decryptMessage(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("server-side open of posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// NHP_COK answering the knock, but with a counter that does NOT echo the
		// request — the case the reorder must tolerate as overload, not reject.
		cok, err := buildMessage(nhpCOK, &KnockInputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    bytes.Repeat([]byte{0x46}, 32),
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

	reply, err := Exchange(context.Background(), srv.URL, serverPub, TypeKnock, []byte("request body"), KnockOptions{DeviceStaticPriv: devicePriv})
	if err != nil {
		t.Fatalf("Exchange returned an error for an overload NHP_COK; the retryable signal was lost: %v", err)
	}
	if !reply.IsCookieChallenge() {
		t.Fatalf("reply Type = %d, want NHP_COK (IsCookieChallenge); the caller cannot detect overload", reply.Type)
	}
	if reply.IsACK() {
		t.Error("IsACK() = true for an NHP_COK, want false")
	}
}

// TestExchange_CookieChallengeForRegister is the register-side parallel of
// TestExchange_CookieChallengeBeforeCounterCheck: a register is a Noise-handshake
// initiation the server can cookie-challenge under load, so an authenticated
// NHP_COK is a valid overload reply to an NHP_REG too, and Exchange must return it
// as a cookie-challenge (the retryable "server busy" signal a caller branches with
// IsCookieChallenge) — NOT ErrMalformedReply. Before this fix replyTypeAllowed
// excluded nhpCOK for TypeRegister, so a register under overload fell through to
// the hard ErrMalformedReply failure. Like the knock case, the fabricated COK
// carries a non-matching counter to prove the overload short-circuit runs before
// the counter-echo check.
func TestExchange_CookieChallengeForRegister(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := decryptMessage(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("server-side open of posted packet: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// NHP_COK answering the register, but with a counter that does NOT echo the
		// request — the case the reorder must tolerate as overload, not reject.
		cok, err := buildMessage(nhpCOK, &KnockInputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    bytes.Repeat([]byte{0x46}, 32),
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

	reply, err := Exchange(context.Background(), srv.URL, serverPub, TypeRegister, []byte("request body"), KnockOptions{DeviceStaticPriv: devicePriv})
	if err != nil {
		t.Fatalf("Exchange returned an error for an overload NHP_COK to a register; the retryable signal was lost: %v", err)
	}
	if !reply.IsCookieChallenge() {
		t.Fatalf("reply Type = %d, want NHP_COK (IsCookieChallenge); the caller cannot detect overload", reply.Type)
	}
	if reply.IsRegisterAck() {
		t.Error("IsRegisterAck() = true for an NHP_COK, want false")
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

// TestDecryptReply_RejectsInitiatorType pins the exported reply gate: an
// authenticated packet carrying an initiator type (here NHP_REG) is refused by
// DecryptReply, so a direct caller can never receive a Reply that matches no
// Is* predicate. decryptMessage (unexported, responder role) still opens it.
func TestDecryptReply_RejectsInitiatorType(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)

	// A server-role open of an agent's REG packet: decryptMessage accepts it.
	reg, err := BuildMessage(TypeRegister, &KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x55}, 32),
		TimestampNanos:   1700000000123456789,
		Counter:          9,
		Preamble:         0x0a0b0c0d,
		Body:             []byte("reg body"),
	})
	if err != nil {
		t.Fatalf("BuildMessage(TypeRegister): %v", err)
	}
	if _, err := decryptMessage(serverPriv, devicePub, reg); err != nil {
		t.Fatalf("decryptMessage(REG) = %v, want accept", err)
	}
	if _, err := DecryptReply(serverPriv, devicePub, reg); err == nil {
		t.Fatal("DecryptReply accepted an initiator type, want reject")
	} else if !strings.Contains(err.Error(), "initiator-only") {
		t.Errorf("DecryptReply(REG) error %q does not name the initiator-only cause", err)
	}
}

// TestDecryptMessage_RejectsTamperedReply exercises decryptMessage's rejection
// paths — the crypto/authentication fences the exported DecryptReply and the
// Exchange resolve path both inherit. A valid NHP_ACK is built server→agent (the
// golden-ack direction) and then each subcase tampers one field minimally to trip
// exactly one guard: the two length bounds, the header digest, the static-key
// match (opened against the wrong server key), the ss-keyed timestamp open (server
// authentication), and the body open. The digest covers header[0:offDigest], so
// the timestamp subcase re-stamps it after corrupting the sealed timestamp — that
// way the digest gate passes and the authentication open is the guard that fails,
// not the digest.
func TestDecryptMessage_RejectsTamperedReply(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	_, otherServerPub := testKeyPair(t, 0x33)

	valid, err := fabricateACK(serverPriv, devicePub, 0x1234, []byte("authorized admission body"))
	if err != nil {
		t.Fatalf("fabricate valid NHP_ACK: %v", err)
	}
	// Sanity: the untampered packet opens, so every rejection below is the tamper
	// and not a broken fixture.
	if _, err := decryptMessage(devicePriv, serverPub, valid); err != nil {
		t.Fatalf("valid NHP_ACK did not open: %v", err)
	}

	// tamperedCopy returns a fresh copy of valid with fn applied, keeping each
	// subcase's mutation off the shared fixture.
	tamperedCopy := func(fn func(pkt []byte)) []byte {
		c := append([]byte(nil), valid...)
		fn(c)
		return c
	}

	tests := []struct {
		name      string
		packet    []byte
		serverPub []byte // expected server static pub passed to decryptMessage
		wantSub   string
	}{
		{
			name:      "reply too short",
			packet:    make([]byte, headerSize-1),
			serverPub: serverPub,
			wantSub:   "reply too short",
		},
		{
			name:      "reply too long",
			packet:    make([]byte, packetBufferSize+1),
			serverPub: serverPub,
			wantSub:   "reply too long",
		},
		{
			name: "header digest mismatch",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offDigest] ^= 0xff // corrupt the stored header digest
			}),
			serverPub: serverPub,
			wantSub:   "digest mismatch",
		},
		{
			name:      "unexpected server static key",
			packet:    valid, // untampered; opened against the wrong server key
			serverPub: otherServerPub,
			wantSub:   "unexpected server",
		},
		{
			name: "server authentication (timestamp open) fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offTimestamp] ^= 0xff // corrupt the sealed timestamp...
				// ...then re-stamp the digest so the digest gate passes and the
				// ss-keyed timestamp open is the guard that trips.
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:headerSize]))
			}),
			serverPub: serverPub,
			wantSub:   "server authentication failed",
		},
		{
			name: "body open fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[headerSize] ^= 0xff // corrupt the sealed body (outside the digest)
			}),
			serverPub: serverPub,
			wantSub:   "open body",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decryptMessage(devicePriv, tt.serverPub, tt.packet); err == nil {
				t.Fatal("decryptMessage accepted a tampered/invalid reply, want reject")
			} else if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}
