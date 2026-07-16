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
// NHP_OTP / NHP_REG / NHP_RAK), their codec plumbing, and the existing HTTP
// orchestrators (BuildMessage, Exchange, Send). The wire format itself is
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

	_, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, relayknock.TypeOTP, []byte("x"), relayknock.KnockOptions{})
	if err == nil {
		t.Fatal("Exchange(TypeOTP) succeeded, want reject")
	}
	if !strings.Contains(err.Error(), "Send") {
		t.Errorf("Exchange(TypeOTP) error %q does not point the caller at Send", err)
	}

	for _, typ := range []int{relayknock.TypeListRequest, relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, relayknock.TypeRegisterAck, 0, 99} {
		if _, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, typ, []byte("x"), relayknock.KnockOptions{}); err == nil {
			t.Errorf("Exchange(%d) succeeded, want reject", typ)
		}
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
		if want := "/relay/" + relayknock.PubKeyFingerprint(serverPub); r.URL.Path != want {
			t.Errorf("relay path = %q, want %q", r.URL.Path, want)
		}
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
		if req.Type != relayknock.TypeRegister {
			t.Errorf("posted packet type = %d, want %d (TypeRegister)", req.Type, relayknock.TypeRegister)
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

	reply, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, relayknock.TypeRegister, regBody, relayknock.KnockOptions{
		DeviceStaticPriv: devicePriv,
	})
	if err != nil {
		t.Fatalf("Exchange(TypeRegister): %v", err)
	}
	if !reply.IsRegisterAck() {
		t.Errorf("reply.Type = %d, want %d (NHP_RAK)", reply.Type, relayknock.TypeRegisterAck)
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
		if want := "/relay/" + relayknock.PubKeyFingerprint(serverPub); r.URL.Path != want {
			t.Errorf("relay path = %q, want %q", r.URL.Path, want)
		}
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
		if req.Type != relayknock.TypeOTP {
			t.Errorf("posted packet type = %d, want %d (TypeOTP)", req.Type, relayknock.TypeOTP)
		}
		if !bytes.Equal(req.Body, otpBody) {
			t.Errorf("posted body = %q, want %q", req.Body, otpBody)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := relayknock.Send(context.Background(), srv.URL, serverPub, otpBody, relayknock.KnockOptions{
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

			err := relayknock.Send(context.Background(), srv.URL, serverPub, []byte("otp request"), relayknock.KnockOptions{})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Send: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Send succeeded, want error")
			}
			var relayErr *relayknock.RelayError
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
		{name: "ACK to a register", reqType: relayknock.TypeRegister, replyType: relayknock.TypeACK, wantSub: "not a valid reply"},
		{name: "counter not echoed", reqType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, counterOff: 1, wantSub: "does not echo"},
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

			_, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, tt.reqType, []byte("request body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
			if err == nil {
				t.Fatal("Exchange succeeded, want mismatch rejection")
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

// TestExchange_AdmitsCookieChallengeToRegister verifies an NHP_COK answer to a
// registration is admitted (not rejected as a mismatched pairing), so the caller
// can branch it with IsCookieChallenge as "retry later".
func TestExchange_AdmitsCookieChallengeToRegister(t *testing.T) {
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
		cok, err := relayknocktest.BuildReply(relayknock.TypeCookieChallenge, &relayknock.KnockInputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    bytes.Repeat([]byte{0x47}, 32),
			TimestampNanos:   1700000000987654321,
			Counter:          req.Counter,
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

	reply, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, relayknock.TypeRegister, []byte("reg body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
	if err != nil {
		t.Fatalf("Exchange(TypeRegister) with COK reply: %v", err)
	}
	if !reply.IsCookieChallenge() {
		t.Errorf("reply.Type = %d, want NHP_COK", reply.Type)
	}
}

// TestKnock_RoundTrip exercises the production Knock front door end-to-end
// against a fabricated matched NHP_ACK. The knock/ack golden vector is a
// standalone reply that does not correlate to a request, so this is the test
// that proves the KNK→ACK delegation through Exchange (the qURL resolve path,
// which now enforces counter-echo + replyTypeAllowed): a reply whose counter
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

	reply, err := relayknock.Exchange(context.Background(), srv.URL, serverPub, relayknock.TypeKnock, []byte("request body"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv})
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

	if err := relayknock.Send(context.Background(), srv.URL, serverPub[:31], []byte("x"), relayknock.KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Send(short server pub) = %v, want server-static-pub size error", err)
	}
	if err := relayknock.Send(context.Background(), srv.URL, serverPub, []byte("x"), relayknock.KnockOptions{DeviceStaticPriv: devicePriv[:16]}); err == nil || !strings.Contains(err.Error(), "device static priv") {
		t.Errorf("Send(short device priv) = %v, want device-static-priv size error", err)
	}
	if _, err := relayknock.Exchange(context.Background(), srv.URL, serverPub[:31], relayknock.TypeRegister, []byte("x"), relayknock.KnockOptions{}); err == nil || !strings.Contains(err.Error(), "server static pub") {
		t.Errorf("Exchange(short server pub) = %v, want server-static-pub size error", err)
	}
}

// TestSend_TransportFault locks the Status-0 RelayError contract for a
// transport-level failure (no HTTP response at all).
func TestSend_TransportFault(t *testing.T) {
	_, serverPub := testKeyPair(t, 0x22)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.Close() // connection refused from here on

	err := relayknock.Send(context.Background(), srv.URL, serverPub, []byte("x"), relayknock.KnockOptions{})
	if err == nil {
		t.Fatal("Send to a closed relay succeeded, want transport fault")
	}
	var re *relayknock.RelayError
	if !errors.As(err, &re) {
		t.Fatalf("Send transport fault is %T, want *RelayError", err)
	}
	if re.Status != 0 {
		t.Errorf("transport fault Status = %d, want 0 (no HTTP response)", re.Status)
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
