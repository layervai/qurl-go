package qurl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/internal/testkeys"
)

// Audit reproduction: API echo and issuer verification both pass for a
// link whose resource key does not match the independently held CRID.
func TestVerifyLinkForCRIDRejectsEchoWithForeignSignedLink(t *testing.T) {
	held, matching, foreign := cridKeyMatchFixture(t)
	signer, err := GenerateLocalSigner("audit-issuer")
	if err != nil {
		t.Fatal(err)
	}
	der, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStoreFromDER(map[string][]byte{signer.KID(): der})
	if err != nil {
		t.Fatal(err)
	}
	link, err := CreatePortalWithParams(context.Background(), signer, CreateParams{
		CellPublicKey: testkeys.X25519Public(), RelayURL: "https://relay.example.com",
		ResourcePublicKey: foreign, JTI: "audit_foreign_resource", IssuedAt: 1700000000,
		NotBefore: 1700000000, Expiry: 1700003600,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"crid": held, "qurl": link, "type": "qv2"}})
	}))
	defer api.Close()
	client, err := NewClient(BearerToken("audit-local-only"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := client.ShareResource(context.Background(), held, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.VerifyCRID(matching); err != nil {
		t.Fatal(err)
	}
	fragment, err := VerifyLink(shared.Link, trust)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := base64.RawURLEncoding.DecodeString(fragment.Claims.ResourcePublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := crid.KeyMatches(held, delivered)
	if err != nil || matches {
		t.Fatalf("expected foreign key: match=%v err=%v", matches, err)
	}
	if _, err := VerifyLinkForCRID(shared.Link, held, trust); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("binding error = %v", err)
	}
	if _, err := EnterPortalWith(context.Background(), shared.Link, Config{TrustStore: trust, ExpectedCRID: held, RelayAllowlist: NewRelayAllowlist([]string{"relay.example.com"})}); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("open must reject before network: %v", err)
	}
	for _, expected := range []string{"", "invalid", held[:59], "p44jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw743out3lhq"} {
		if _, err := VerifyLinkForCRID(link, expected, trust); err == nil {
			t.Fatal("accepted invalid CRID")
		}
	}
	matchingLink, err := CreatePortalWithParams(context.Background(), signer, CreateParams{
		CellPublicKey: testkeys.X25519Public(), RelayURL: "https://relay.example.com",
		ResourcePublicKey: matching, JTI: "matching_resource", IssuedAt: 1700000000,
		NotBefore: 1700000000, Expiry: 1700003600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkForCRID(matchingLink, held, trust); err != nil {
		t.Fatal(err)
	}
	otherSigner, err := GenerateLocalSigner(signer.KID())
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := otherSigner.PublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	otherTrust, err := NewTrustStoreFromDER(map[string][]byte{signer.KID(): otherDER})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkForCRID(matchingLink, held, otherTrust); !errors.Is(err, ErrSignature) {
		t.Fatalf("accepted wrong issuer: %v", err)
	}
	if _, err := VerifyLinkForCRID(matchingLink, held, nil); err == nil {
		t.Fatal("accepted missing issuer trust")
	}
	if _, err := VerifyLinkForCRID("https://example.com/unsigned", held, trust); err == nil {
		t.Fatal("accepted unsigned URL")
	}
}
