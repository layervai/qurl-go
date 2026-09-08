package qurl

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
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
	doer := &capturingDoer{}
	if _, err := EnterPortalWith(context.Background(), shared.Link, Config{TrustStore: trust, ExpectedCRID: held, RelayAllowlist: NewRelayAllowlist([]string{"relay.example.com"}), HTTPClient: doer}); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("open must reject before network: %v", err)
	}
	if doer.gotURL != "" {
		t.Fatal("mismatched CRID caused an access request")
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
	// Keep the matching digest but change the version and recompute its checksum.
	encoding := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	unknown, err := encoding.DecodeString(held)
	if err != nil {
		t.Fatal(err)
	}
	unknown[0] = 0x7f
	binary.BigEndian.PutUint32(unknown[len(unknown)-4:], crc32.Checksum(unknown[:len(unknown)-4], crc32.MakeTable(crc32.Castagnoli)))
	for _, tc := range []struct {
		name, value string
		want        error
	}{
		{"empty", "", ErrNoCRID},
		{"malformed", "invalid", crid.ErrLength},
		{"truncated", held[:59], crid.ErrLength},
		{"unsupported-matching-digest", encoding.EncodeToString(unknown), ErrUnsupportedCRIDVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyLinkForCRID(matchingLink, tc.value, trust); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	installStaticProvider(t, trust, relayExampleAllowlist())
	transport := installCapturingTransport(t)
	if err := VerifyPortalLink(t.Context(), matchingLink, held); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPortalLink(t.Context(), link, held); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("default verifier accepted foreign key: %v", err)
	}
	if _, err := EnterPortalForCRID(t.Context(), link, held); !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("default opener accepted foreign key: %v", err)
	}
	if _, err := EnterPortalForCRID(t.Context(), matchingLink, ""); !errors.Is(err, ErrNoCRID) {
		t.Fatalf("empty CRID must not disable binding: %v", err)
	}
	if err := VerifyPortalLink(t.Context(), matchingLink, ""); !errors.Is(err, ErrNoCRID) {
		t.Fatalf("empty verifier CRID: %v", err)
	}
	if transport.gotURL != "" {
		t.Fatal("default verifier or rejected opener sent an access request")
	}
	providerErr := errors.New("provider unavailable")
	installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
		return nil, nil, providerErr
	}))
	if err := VerifyPortalLink(t.Context(), matchingLink, held); !errors.Is(err, providerErr) {
		t.Fatalf("provider error lost: %v", err)
	}
	if _, err := EnterPortalForCRID(t.Context(), matchingLink, held); !errors.Is(err, providerErr) {
		t.Fatalf("opener provider error lost: %v", err)
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
