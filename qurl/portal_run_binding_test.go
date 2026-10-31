package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

func TestEnterPortalCleanupRunBinding(t *testing.T) {
	for _, mode := range []string{"default", "cleanup", "wrong-echo", "missing-echo"} {
		t.Run(mode, func(t *testing.T) {
			server, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, trust := mintSigner(t)
			params := validCreateParams(t)
			params.CellPublicKey = server.PublicKey().Bytes()
			link, err := CreatePortalWithParams(context.Background(), signer, params)
			if err != nil {
				t.Fatal(err)
			}
			frag, err := VerifyLink(link, trust)
			if err != nil {
				t.Fatal(err)
			}
			agent, err := b64url.DecodeString(frag.Claims.QurlUserPublicKeyB64)
			if err != nil {
				t.Fatal(err)
			}
			var runID string
			calls := 0
			doer := doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				message, err := relayknocktest.OpenInitiatorMessage(server.Bytes(), agent, raw)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]json.RawMessage
				if err = json.Unmarshal(message.Body, &body); err != nil {
					t.Fatal(err)
				}
				var response string
				if calls == 1 {
					var header int
					var asp string
					_ = json.Unmarshal(body["headerType"], &header)
					_ = json.Unmarshal(body["aspId"], &asp)
					if message.Type != relayknock.TypeKnock || header != relayknock.TypeKnock || asp != "qurl" {
						t.Fatal("changed public admission contract")
					}
					if mode == "default" {
						if _, ok := body["runId"]; ok {
							t.Fatal("default run id present")
						}
						if _, ok := body["runAttempt"]; ok {
							t.Fatal("default attempt present")
						}
					} else {
						if json.Unmarshal(body["runId"], &runID) != nil || ValidateCycleRunID(runID) != nil || string(body["runAttempt"]) != "1" {
							t.Fatal("missing opt-in binding")
						}
					}
					echo := runID
					if mode == "wrong-echo" {
						echo = "fedcba9876543210"
						if echo == runID {
							echo = "0123456789abcdef"
						}
					}
					if mode == "missing-echo" {
						echo = ""
					}
					response = fmt.Sprintf(`{"errCode":"0","sessId":17,"opnTime":5,"redirectUrl":"https://content.example/owned","aspToken":"AQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","cellId":"cell0","sessIssuedAtMillis":1234,"runId":%q,"runAttempt":1}`, echo)
				} else {
					var ext nativeExactSessionCloseBody
					if json.Unmarshal(message.Body, &ext) != nil || message.Type != relayknock.TypeExit || ext.RunID != runID || ext.RunAttempt != 1 || ext.SessionID != 17 || ext.SessionIssuedAtMillis != 1234 || ext.CellID != "cell0" {
						t.Fatal("EXT changed authority")
					}
					response = fmt.Sprintf(`{"errCode":"0","cellId":"cell0","sessId":17,"sessIssuedAtMillis":1234,"runId":%q,"runAttempt":1,"closeEventId":"0123456789abcdef0123456789abcdef","state":"closed"}`, runID)
				}
				eph, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{DeviceStaticPriv: server.Bytes(), ServerStaticPub: agent, EphemeralPriv: eph.Bytes(), Counter: message.Counter, TimestampNanos: uint64(time.Now().UnixNano()), Body: []byte(response)})
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(packet))}, nil
			})
			h, err := EnterPortalWith(context.Background(), link, Config{TrustStore: trust, RelayAllowlist: relayExampleAllowlist(), HTTPClient: doer, RetainNativeSessionForCleanup: mode != "default"})
			if mode == "wrong-echo" || mode == "missing-echo" {
				if !errors.Is(err, ErrMalformedReply) || h != nil || calls != 1 {
					t.Fatal("invalid authoritative echo accepted")
				}
				return
			}
			if err != nil || h == nil {
				t.Fatalf("EnterPortal: %v", err)
			}
			if mode == "cleanup" {
				result, err := h.RetireSession(context.Background())
				if err != nil || result == nil || result.State != "closed" || calls != 2 {
					t.Fatalf("retire: %v", err)
				}
			} else if h.retirement != nil {
				t.Fatal("default retained key")
			}
		})
	}
}
