package relayknock_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// TestKnock_MintedKeyRoundTripsThroughAnUnknownInitiatorResponder drives the
// production relay Knock with no device key, so it mints a throwaway identity
// per call, against a responder that has never seen that identity. This is the
// shape of a request a server authenticates by its body rather than by a
// registered device: the responder learns the initiator key from the packet,
// and seals its reply to that key.
//
// It pins both halves. The client half: every Knock without a device key uses
// a fresh one, and still opens a reply sealed to it. The responder half:
// OpenUnknownInitiatorMessage returns exactly the key OpenInitiatorMessage
// accepts for that packet.
func TestKnock_MintedKeyRoundTripsThroughAnUnknownInitiatorResponder(t *testing.T) {
	serverPriv, serverPub := testKeyPair(t, 0x22)

	var mu sync.Mutex
	var seenKeys [][]byte
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
		request, devicePub, err := relayknocktest.OpenUnknownInitiatorMessage(serverPriv, packet)
		if err != nil {
			t.Errorf("open a knock from an unknown initiator: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if request.Type != relayknock.TypeKnock {
			t.Errorf("request type = %d, want NHP_KNK", request.Type)
		}
		// The known-device open must agree: the learned key is the one it
		// accepts, so the two helpers describe one packet the same way.
		known, err := relayknocktest.OpenInitiatorMessage(serverPriv, devicePub, packet)
		if err != nil {
			t.Errorf("known-device open with the learned key: %v", err)
		} else if known.Counter != request.Counter || !bytes.Equal(known.Body, request.Body) {
			t.Error("the two responder opens disagree about the same packet")
		}
		mu.Lock()
		seenKeys = append(seenKeys, devicePub)
		mu.Unlock()

		reply, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub, // the reply is sealed to the learned key
			EphemeralPriv:    bytes.Repeat([]byte{0x47}, 32),
			TimestampNanos:   1700000000987654321,
			Counter:          request.Counter,
			Preamble:         0xa1b2c3d4,
			Body:             append([]byte("echo: "), request.Body...),
		})
		if err != nil {
			t.Errorf("build reply: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(reply)
	}))
	defer srv.Close()

	const knocks = 3
	for i := range knocks {
		body := []byte{'k', 'n', 'o', 'c', 'k', byte('0' + i)}
		reply, err := relayknock.Knock(context.Background(), srv.URL, serverPub, body, relayknock.KnockOptions{})
		if err != nil {
			t.Fatalf("knock %d: %v", i, err)
		}
		if !reply.IsACK() || string(reply.Body) != "echo: "+string(body) {
			t.Fatalf("knock %d: reply type %d body %q", i, reply.Type, reply.Body)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenKeys) != knocks {
		t.Fatalf("responder saw %d knocks, want %d", len(seenKeys), knocks)
	}
	for i := range seenKeys {
		if len(seenKeys[i]) != 32 {
			t.Fatalf("knock %d: learned key is %d bytes, want 32", i, len(seenKeys[i]))
		}
		for j := range i {
			if bytes.Equal(seenKeys[i], seenKeys[j]) {
				t.Fatalf("knocks %d and %d presented the same initiator key; a knock with no device key must mint a fresh one", j, i)
			}
		}
	}
}

// TestOpenUnknownInitiatorMessage_AdmitsOnlyInitiatorTypes pins the type gate
// the two responder opens share: every initiator type opens, and an
// authenticated packet carrying a reply type is refused without handing back
// the key it carried.
func TestOpenUnknownInitiatorMessage_AdmitsOnlyInitiatorTypes(t *testing.T) {
	devicePriv, devicePub := testKeyPair(t, 0x11)
	serverPriv, serverPub := testKeyPair(t, 0x22)
	inputs := func() *relayknock.KnockInputs {
		return &relayknock.KnockInputs{
			DeviceStaticPriv: devicePriv,
			ServerStaticPub:  serverPub,
			EphemeralPriv:    bytes.Repeat([]byte{0x33}, 32),
			TimestampNanos:   1700000000123456789,
			Counter:          7,
			Preamble:         0x0a0b0c0d,
			Body:             []byte("body"),
		}
	}

	for _, headerType := range []int{
		relayknock.TypeKnock, relayknock.TypeListRequest, relayknock.TypeOTP,
		relayknock.TypeRegister, relayknock.TypeExit,
	} {
		packet, err := relayknock.BuildMessage(headerType, inputs())
		if err != nil {
			t.Fatalf("BuildMessage(%d): %v", headerType, err)
		}
		message, learned, err := relayknocktest.OpenUnknownInitiatorMessage(serverPriv, packet)
		if err != nil {
			t.Fatalf("initiator type %d: %v", headerType, err)
		}
		if message.Type != headerType || message.Counter != 7 || string(message.Body) != "body" {
			t.Fatalf("initiator type %d opened as %+v", headerType, message)
		}
		if !bytes.Equal(learned, devicePub) {
			t.Fatalf("initiator type %d: learned key %x, want %x", headerType, learned, devicePub)
		}
	}

	// A reply type is authentic here (the builder is role-symmetric) but is
	// not something an initiator sends.
	for _, replyType := range []int{
		relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, relayknock.TypeRegisterAck,
	} {
		packet, err := relayknocktest.BuildReply(replyType, inputs())
		if err != nil {
			t.Fatalf("BuildReply(%d): %v", replyType, err)
		}
		message, learned, err := relayknocktest.OpenUnknownInitiatorMessage(serverPriv, packet)
		if err == nil || !strings.Contains(err.Error(), "not an initiator message") {
			t.Fatalf("reply type %d: error = %v, want the initiator type gate", replyType, err)
		}
		if message != nil || learned != nil {
			t.Fatalf("reply type %d: refused open returned %+v and key %x", replyType, message, learned)
		}
	}

	// A packet that does not authenticate returns nothing either.
	packet, err := relayknock.BuildMessage(relayknock.TypeKnock, inputs())
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xff
	if message, learned, err := relayknocktest.OpenUnknownInitiatorMessage(serverPriv, packet); err == nil || message != nil || learned != nil {
		t.Fatalf("tampered packet opened as %+v, key %x, err %v", message, learned, err)
	}
}
