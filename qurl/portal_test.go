package qurl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// b64url is the single pinned qURL wire encoding (unpadded base64url), used here
// to assemble fixture parts. It matches qv2's internal decoder/encoder; using the
// stdlib form directly keeps the qv2 public surface from widening just for tests.
var b64url = base64.RawURLEncoding

// EnterPortal is tested at its SEAMS, not end to end: a self-built mock NHP
// responder would be the SDK's own crypto on both ends (weaker evidence than the
// relayknock golden vectors, which fence both wire directions against external
// js-agent fixtures). So:
//
//   - bucket A: the security GATES (config, relay allowlist, signature/kid), pure;
//   - bucket B: orchestration up to the relay POST, asserting the derived route,
//     using the vendored signature vector so no new signing code is needed;
//   - bucket C: reply interpretation, pure, via interpretReply.
//
// The two seams left to inspection are one-liners (in-link priv -> Knock; Knock's
// reply -> interpretReply), both backed by the golden vectors for the crypto.

// vendoredAcceptLink builds a valid qURL link plus a matching trust store from the
// vendored issuer-signature vector's ACCEPT case. The signature is real (it is the
// committed cross-language vector), so EnterPortal's parse+verify+route runs for
// real without this test minting anything. The secret part is synthesized — PoP
// matching is a server-side check EnterPortal does not perform — so a placeholder
// 32-byte key is sufficient to satisfy the strict secret parser.
func vendoredAcceptLink(t *testing.T) (link string, ts *qv2.TrustStore, cellFingerprint string) {
	t.Helper()
	vf, err := qv2.LoadVectorFile("../qv2/testdata/issuer_signature_vectors.json")
	if err != nil {
		t.Fatalf("load signature vectors: %v", err)
	}
	var accept *qv2.SignatureVector
	for i := range vf.Vectors {
		if vf.Vectors[i].Expect == qv2.ExpectAccept {
			accept = &vf.Vectors[i]
			break
		}
	}
	if accept == nil {
		t.Fatal("no accept vector in the vendored signature file")
	}

	der, err := b64url.DecodeString(vf.Issuer.SPKIDERB64)
	if err != nil {
		t.Fatalf("decode issuer spki: %v", err)
	}
	ts, err = qv2.NewTrustStoreFromDER(map[string][]byte{vf.Issuer.KID: der})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}

	// A synthesized secret: base64url of {"qurl_user_private_key_b64":"<32 bytes>"}.
	secretJSON := `{"qurl_user_private_key_b64":"` + b64url.EncodeToString(make([]byte, 32)) + `"}`
	secretB64 := b64url.EncodeToString([]byte(secretJSON))

	body, err := qv2.BuildFragment(accept.ClaimsB64, secretB64, mustDecode(t, accept.SigB64Raw))
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	link = "https://qurl.link/#" + body

	// The accept vector's cell key is 32 bytes of 0x44 (fingerprint uzkUFcBeOdc);
	// recompute it rather than hardcode so the expected route stays derived.
	frag, err := qv2.ParseFragment(body)
	if err != nil {
		t.Fatalf("ParseFragment: %v", err)
	}
	cellPub, err := qv2.DecodeCellPublicKey(frag.Claims)
	if err != nil {
		t.Fatalf("decode cell key: %v", err)
	}
	return link, ts, relayknock.PubKeyFingerprint(cellPub)
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	b, err := b64url.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode %q: %v", b64, err)
	}
	return b
}

// freshTrustStore mints an unrelated issuer key under a kid that is NOT the
// vendored vector's kid, so a vector-signed link resolves to ErrUnknownKID against
// it.
func freshTrustStore(t *testing.T) *qv2.TrustStore {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	ts, err := qv2.NewTrustStoreFromDER(map[string][]byte{"unrelated-kid": der})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}
	return ts
}

// allowAll is the relay allowlist for the vendored vector's relay_url
// (https://relay.example.com).
func relayExampleAllowlist() *qv2.RelayAllowlist {
	return qv2.NewRelayAllowlist([]string{"relay.example.com"})
}

// --- Bucket A: gates -------------------------------------------------------

func TestEnterPortal_EmptyConfig_FailsClosed(t *testing.T) {
	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2.a.b.c")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty default config: want ErrNotConfigured, got %v", err)
	}
}

func TestEnterPortalWith_MissingAllowlist_FailsClosed(t *testing.T) {
	_, ts, _ := vendoredAcceptLink(t)
	_, err := EnterPortalWith(context.Background(), "https://qurl.link/#qv2.a.b.c", Config{TrustStore: ts})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing allowlist: want ErrNotConfigured, got %v", err)
	}
}

func TestEnterPortalWith_RelayOffAllowlist_Rejected(t *testing.T) {
	link, ts, _ := vendoredAcceptLink(t)
	// Allowlist a DIFFERENT host than the verified relay_url, so validation fails
	// AFTER the signature verifies (proving the post-verify ordering).
	cfg := Config{TrustStore: ts, RelayAllowlist: qv2.NewRelayAllowlist([]string{"not-the-relay.example.org"})}
	_, err := EnterPortalWith(context.Background(), link, cfg)
	if !errors.Is(err, qv2.ErrRelayURL) {
		t.Fatalf("relay off allowlist: want ErrRelayURL, got %v", err)
	}
}

func TestEnterPortalWith_UnknownKID_Rejected(t *testing.T) {
	link, _, _ := vendoredAcceptLink(t)
	// A trust store that does NOT contain the vector's kid: build one from a
	// freshly minted, unrelated issuer key under a different kid.
	other := freshTrustStore(t)
	cfg := Config{TrustStore: other, RelayAllowlist: relayExampleAllowlist()}
	_, err := EnterPortalWith(context.Background(), link, cfg)
	if !errors.Is(err, qv2.ErrUnknownKID) {
		t.Fatalf("unknown kid: want ErrUnknownKID, got %v", err)
	}
}

// --- Bucket B: orchestration up to the relay POST --------------------------

// capturingDoer records the relay POST URL and returns a transport error to
// short-circuit before any reply decryption — the goal is to prove EnterPortal
// reached the right route, not to mock a server.
type capturingDoer struct {
	gotURL string
}

func (d *capturingDoer) Do(req *http.Request) (*http.Response, error) {
	d.gotURL = req.URL.String()
	return nil, errors.New("short-circuit: do not actually POST in tests")
}

func TestEnterPortalWith_RoutesToDerivedRelayURL(t *testing.T) {
	link, ts, cellFingerprint := vendoredAcceptLink(t)
	doer := &capturingDoer{}
	cfg := Config{TrustStore: ts, RelayAllowlist: relayExampleAllowlist(), HTTPClient: doer}

	_, err := EnterPortalWith(context.Background(), link, cfg)

	// The knock is built and POSTed; the capturing client fails the transport, so
	// EnterPortal surfaces a relayknock.RelayError — proving it got past parse,
	// verify, relay validation, serverId derivation, and knock construction.
	var relayErr *relayknock.RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("want a *relayknock.RelayError after the POST, got %v", err)
	}
	wantURL := "https://relay.example.com/relay/" + cellFingerprint
	if doer.gotURL != wantURL {
		t.Fatalf("relay POST routed to %q, want %q", doer.gotURL, wantURL)
	}
}

// --- Bucket C: reply interpretation ----------------------------------------

func TestInterpretReply_SuccessACK(t *testing.T) {
	reply := &relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`{"errCode":"0","opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`),
	}
	h, err := interpretReply(reply)
	if err != nil {
		t.Fatalf("success ACK: %v", err)
	}
	if h.RedirectURL != "https://r_x.qurl.site/path" {
		t.Fatalf("RedirectURL = %q", h.RedirectURL)
	}
	if h.OpenSeconds != 900 {
		t.Fatalf("OpenSeconds = %d, want 900", h.OpenSeconds)
	}
}

func TestInterpretReply_ServerDeny(t *testing.T) {
	reply := &relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`{"errCode":"52024"}`), // qURL session-expired deny
	}
	_, err := interpretReply(reply)
	var deny *ServerDenyError
	if !errors.As(err, &deny) {
		t.Fatalf("want *ServerDenyError, got %v", err)
	}
	if deny.ErrCode != "52024" {
		t.Fatalf("deny ErrCode = %q, want 52024", deny.ErrCode)
	}
}

func TestInterpretReply_CookieChallenge(t *testing.T) {
	reply := &relayknock.Reply{Type: relayknock.TypeCookieChallenge}
	_, err := interpretReply(reply)
	if !errors.Is(err, ErrServerOverloaded) {
		t.Fatalf("cookie challenge: want ErrServerOverloaded, got %v", err)
	}
}

func TestInterpretReply_SuccessButNoRedirect(t *testing.T) {
	// An empty body is a zero-value ACK: success errCode, but no redirect. Pin the
	// behavior — a handle with an empty RedirectURL, no error (the server vouched
	// for admission; the missing redirect is the caller's to handle).
	reply := &relayknock.Reply{Type: relayknock.TypeACK, Body: nil}
	h, err := interpretReply(reply)
	if err != nil {
		t.Fatalf("empty-body ACK: unexpected error %v", err)
	}
	if h.RedirectURL != "" {
		t.Fatalf("empty-body ACK: RedirectURL = %q, want empty", h.RedirectURL)
	}
}

func TestInterpretReply_UnexpectedType(t *testing.T) {
	reply := &relayknock.Reply{Type: 99}
	_, err := interpretReply(reply)
	if err == nil || !strings.Contains(err.Error(), "unexpected NHP reply type") {
		t.Fatalf("unexpected type: want a clear error, got %v", err)
	}
}
