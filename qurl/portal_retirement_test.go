package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

func TestPortalRetirementExactIdentityAndTerminalKeyWipe(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	agent, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ack, _ := parseAck([]byte(`{"sessId":18446744073709551615,"cellId":"cell0","sessIssuedAtMillis":1234,"runId":"0123456789abcdef","runAttempt":1}`))
	calls := 0
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != "https://relay.example/relay/"+relayknock.PubKeyFingerprint(server.PublicKey().Bytes()) {
			t.Fatal("wrong immutable endpoint")
		}
		raw, _ := io.ReadAll(req.Body)
		message, err := relayknocktest.OpenInitiatorMessage(server.Bytes(), agent.PublicKey().Bytes(), raw)
		if err != nil {
			t.Fatal(err)
		}
		var body nativeExactSessionCloseBody
		if json.Unmarshal(message.Body, &body) != nil || message.Type != relayknock.TypeExit || body.SessionID != ^uint64(0) || body.SessionIssuedAtMillis != 1234 || body.RunID != "0123456789abcdef" || body.RunAttempt != 1 || body.CellID != "cell0" {
			t.Fatal("wrong exact EXT")
		}
		state := "closing"
		if calls == 2 {
			state = "closed"
		}
		response := fmt.Sprintf(`{"errCode":"0","cellId":"cell0","sessId":18446744073709551615,"sessIssuedAtMillis":1234,"runId":"0123456789abcdef","runAttempt":1,"closeEventId":"0123456789abcdef0123456789abcdef","state":%q}`, state)
		eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
		packet, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{DeviceStaticPriv: server.Bytes(), ServerStaticPub: agent.PublicKey().Bytes(), EphemeralPriv: eph.Bytes(), Counter: message.Counter, TimestampNanos: uint64(time.Now().UnixNano()), Body: []byte(response)})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(packet))}, nil
	})
	retirement, err := newPortalRetirement(ack, agent.Bytes(), server.PublicKey().Bytes(), "https://relay.example", doer)
	if err != nil {
		t.Fatal(err)
	}
	h := &ResourceHandle{SessionID: 1, retirement: retirement}
	retained := retirement.key
	first, err := h.RetireSession(context.Background())
	if err != nil || first.State != "closing" {
		t.Fatalf("first retirement: %v", err)
	}
	if bytes.Equal(retained, make([]byte, 32)) {
		t.Fatal("wiped before terminal proof")
	}
	second, err := h.RetireSession(context.Background())
	if err != nil || second.State != "closed" {
		t.Fatalf("terminal retirement: %v", err)
	}
	if !bytes.Equal(retained, make([]byte, 32)) {
		t.Fatal("terminal key not wiped")
	}
	second.State = "corrupt"
	second.SessionReceipt.SessionID = 0
	cached, cacheErr := h.RetireSession(context.Background())
	if cacheErr != nil || cached.State != "closed" || cached.SessionReceipt.SessionID != ^uint64(0) {
		t.Fatal("caller mutated terminal cache")
	}
	if _, err = h.RetireSession(context.Background()); err != nil || calls != 2 {
		t.Fatal("terminal idempotency made another request")
	}
	rendered := fmt.Sprintf("%v %#v", h, h)
	encoded, _ := json.Marshal(h)
	if strings.Contains(rendered, string(agent.Bytes())) || strings.Contains(string(encoded), "retirement") {
		t.Fatal("private retirement state exposed")
	}
}
func TestPortalRetirementRejectsMissingAndMalformedReceipt(t *testing.T) {
	for _, body := range []string{`{}`, `{"sessId":1,"cellId":"cell0","sessIssuedAtMillis":"1234","runId":"0123456789abcdef","runAttempt":1}`, `{"sessId":1,"cellId":"cell0","sessIssuedAtMillis":1234,"runId":"bad","runAttempt":1}`} {
		ack, err := parseAck([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = newPortalRetirement(ack, make([]byte, 32), make([]byte, 32), "https://relay.example", nil); err == nil {
			t.Fatal("malformed receipt accepted")
		}
	}
	if _, err := (&ResourceHandle{}).RetireSession(context.Background()); err == nil {
		t.Fatal("unretained handle accepted")
	}
}

func TestPortalRetirementRejectsUnboundRepliesWithoutWipingKey(t *testing.T) {
	for _, mode := range []string{"counter", "type", "receipt", "peer", "transport"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := ecdh.X25519().GenerateKey(rand.Reader)
			agent, _ := ecdh.X25519().GenerateKey(rand.Reader)
			ack, _ := parseAck([]byte(`{"sessId":123,"cellId":"cell0","sessIssuedAtMillis":1234,"runId":"0123456789abcdef","runAttempt":1}`))
			doer := doerFunc(func(req *http.Request) (*http.Response, error) {
				if mode == "transport" {
					return nil, fmt.Errorf("synthetic transport failure")
				}
				raw, _ := io.ReadAll(req.Body)
				message, err := relayknocktest.OpenInitiatorMessage(server.Bytes(), agent.PublicKey().Bytes(), raw)
				if err != nil {
					t.Fatal(err)
				}
				counter := message.Counter
				if mode == "counter" {
					counter++
				}
				typ := relayknock.TypeACK
				if mode == "type" {
					typ = relayknock.TypeCookieChallenge
				}
				sid := 123
				if mode == "receipt" {
					sid++
				}
				signer := server
				if mode == "peer" {
					signer, _ = ecdh.X25519().GenerateKey(rand.Reader)
				}
				body := fmt.Sprintf(`{"errCode":"0","cellId":"cell0","sessId":%d,"sessIssuedAtMillis":1234,"runId":"0123456789abcdef","runAttempt":1,"closeEventId":"0123456789abcdef0123456789abcdef","state":"closed"}`, sid)
				eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
				packet, err := relayknocktest.BuildReply(typ, &relayknock.KnockInputs{DeviceStaticPriv: signer.Bytes(), ServerStaticPub: agent.PublicKey().Bytes(), EphemeralPriv: eph.Bytes(), Counter: counter, TimestampNanos: uint64(time.Now().UnixNano()), Body: []byte(body)})
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(packet))}, nil
			})
			r, err := newPortalRetirement(ack, agent.Bytes(), server.PublicKey().Bytes(), "https://relay.example", doer)
			if err != nil {
				t.Fatal(err)
			}
			h := &ResourceHandle{retirement: r}
			if _, err = h.RetireSession(context.Background()); err == nil {
				t.Fatal("unbound reply accepted")
			}
			if !bytes.Equal(r.key, agent.Bytes()) || r.terminal != nil {
				t.Fatal("failed cleanup lost key or invented terminal result")
			}
		})
	}
}
