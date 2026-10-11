package qurl

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/relayknock"
)

func TestConsumerProofIndependentVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/consumer_proof_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Proof     ConsumerProof `json:"proof"`
		Challenge string        `json:"challenge_b64"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		challenge, err := vector.Proof.Challenge()
		if err != nil || base64.RawURLEncoding.EncodeToString(challenge[:]) != vector.Challenge {
			t.Fatalf("proof vector mismatch: %v", err)
		}
	}
}

func TestConsumerEnrollmentUnsupportedCellReceivesNoPrivateContinuation(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewConsumerEnrollmentClient(fixture.crid, key.Bytes(), fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	fixture.peer.respond(cridLinkDenied(t, "52601"))
	_, err = client.Exchange(t.Context(), ConsumerEnrollmentOperation{Action: "verify", EnrollmentReference: strings.Repeat("secret", 4), VerificationCode: "12345678"})
	if !errors.Is(err, ErrCRIDLinkUnavailable) {
		t.Fatalf("unsupported: %v", err)
	}
	knocks := fixture.peer.seen()
	if len(knocks) != 1 || bytes.Contains(knocks[0].body, []byte("secret")) || bytes.Contains(knocks[0].body, []byte("12345678")) {
		t.Fatal("private continuation sent before capability discovery")
	}
}

func TestConsumerEnrollmentKeepsPeerAndRejectsMismatchedAction(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewConsumerEnrollmentClient(fixture.crid, key.Bytes(), fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fixture.peer.respondWith(func(_ cridLinkKnock) cridLinkAnswer {
		calls++
		action := "info"
		data := map[string]any{"crid": fixture.crid, "policy": ConsumerAccessPolicy{Mode: "review", Version: 1}, "origin": fixture.cfg.CRIDLink.LinkOrigin, "relying_party_id": "qurl.link", "server_time": int64(1791689400)}
		if calls > 1 {
			action = "verify"
			data = map[string]any{"status": "active"}
		}
		raw, err := json.Marshal(map[string]any{"errCode": "52609", "redirectInfo": map[string]any{"version": 1, "action": action, "data": data}})
		if err != nil {
			t.Fatal(err)
		}
		return cridLinkAnswer{replyType: relayknock.TypeACK, body: raw}
	})
	_, err = client.Exchange(t.Context(), ConsumerEnrollmentOperation{Action: "status", EnrollmentReference: strings.Repeat("a", 32)})
	if !errors.Is(err, ErrCRIDLinkProtocol) {
		t.Fatalf("mismatched action accepted: %v", err)
	}
	knocks := fixture.peer.seen()
	if len(knocks) != 2 || !bytes.Equal(knocks[0].devicePub, key.PublicKey().Bytes()) || !bytes.Equal(knocks[0].devicePub, knocks[1].devicePub) {
		t.Fatal("consumer peer changed during enrollment")
	}
}

func TestConsumerAdmissionRejectsClaimsForAnotherLeafBeforeOpening(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewConsumerEnrollmentClient(fixture.crid, peer.Bytes(), fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := fragmentFromLink(fixture.link)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fixture.peer.respondWith(func(_ cridLinkKnock) cridLinkAnswer {
		calls++
		action := "info"
		data := map[string]any{"crid": fixture.crid, "policy": ConsumerAccessPolicy{Mode: "keys", Version: 1}, "origin": fixture.cfg.CRIDLink.LinkOrigin, "relying_party_id": "qurl.link", "server_time": int64(1791689400)}
		if calls > 1 {
			action = "mint"
			data = map[string]any{"crid": fixture.crid, "claims_b64": fragment.ClaimsB64, "sig_b64": fragment.SigB64}
		}
		raw, err := json.Marshal(map[string]any{"errCode": "52609", "redirectInfo": map[string]any{"version": 1, "action": action, "data": data}})
		if err != nil {
			t.Fatal(err)
		}
		return cridLinkAnswer{replyType: relayknock.TypeACK, body: raw}
	})
	admission, err := client.MintAdmission(t.Context(), strings.Repeat("a", 32), leaf.Bytes())
	if admission != nil || !errors.Is(err, ErrInvalidAPIResponse) {
		t.Fatalf("wrong leaf claims accepted: %v", err)
	}
	if len(fixture.peer.seen()) != 2 {
		t.Fatal("unverified claims reached admission")
	}
	private, err := base64.RawURLEncoding.DecodeString(fragment.Secret.QurlUserPrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	admission, err = client.MintAdmission(t.Context(), strings.Repeat("a", 32), private)
	if err != nil || admission == nil {
		t.Fatalf("matching leaf refused: %v", err)
	}
	raw, err := json.Marshal(admission)
	if err != nil || string(raw) != "{}" {
		t.Fatal("admission exposes leaf capability through JSON")
	}
	if strings.Contains(admission.String(), fragment.Secret.QurlUserPrivateKeyB64) {
		t.Fatal("admission log exposes key")
	}
}
