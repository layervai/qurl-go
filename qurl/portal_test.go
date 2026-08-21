package qurl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// b64url (the single pinned unpadded-base64url wire encoding) is declared in
// create.go and shared package-wide; these tests reuse it to assemble fixture
// parts so the test and mint paths encode identically.

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
func vendoredAcceptLink(t *testing.T) (link string, ts *TrustStore, cellFingerprint string) {
	t.Helper()
	vf, err := qv2.LoadVectorBytes(conformance.IssuerSignatureVectors())
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
	ts, err = NewTrustStoreFromDER(map[string][]byte{vf.Issuer.KID: der})
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
	transport, err := qv2.EncodeTransportFragment(body)
	if err != nil {
		t.Fatalf("EncodeTransportFragment: %v", err)
	}
	link = "https://qurl.link/#" + transport

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

// freshP256SPKIDER mints a fresh P-256 key and returns its public key in DER SPKI
// form — the trust-store load shape NewTrustStoreFromDER consumes and the issuer-key
// shape a discovery manifest carries (base64url-encoded). Shared by freshTrustStore
// and the discovery test's issuer fixtures so the keygen+marshal prologue lives once.
func freshP256SPKIDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return der
}

// freshTrustStore mints an unrelated issuer key under a kid that is NOT the
// vendored vector's kid, so a vector-signed link resolves to ErrUnknownKID against
// it.
func freshTrustStore(t *testing.T) *TrustStore {
	t.Helper()
	ts, err := NewTrustStoreFromDER(map[string][]byte{"unrelated-kid": freshP256SPKIDER(t)})
	if err != nil {
		t.Fatalf("new trust store: %v", err)
	}
	return ts
}

// allowAll is the relay allowlist for the vendored vector's relay_url
// (https://relay.example.com).
func relayExampleAllowlist() *RelayAllowlist {
	return NewRelayAllowlist([]string{"relay.example.com"})
}

// --- Bucket A: gates -------------------------------------------------------

func TestEnterPortal_EmptyConfig_FailsClosed(t *testing.T) {
	_, err := EnterPortal(context.Background(), "https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty default config: want ErrNotConfigured, got %v", err)
	}
}

func TestEnterPortalWith_MissingAllowlist_FailsClosed(t *testing.T) {
	_, ts, _ := vendoredAcceptLink(t)
	_, err := EnterPortalWith(context.Background(), "https://qurl.link/#qv2t1.1.1.1.AQ.AQ.AQ", Config{TrustStore: ts})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing allowlist: want ErrNotConfigured, got %v", err)
	}
}

func TestEnterPortalWith_RelayOffAllowlist_Rejected(t *testing.T) {
	link, ts, _ := vendoredAcceptLink(t)
	// Allowlist a DIFFERENT host than the verified relay_url, so validation fails
	// AFTER the signature verifies (proving the post-verify ordering).
	cfg := Config{TrustStore: ts, RelayAllowlist: NewRelayAllowlist([]string{"not-the-relay.example.org"})}
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
	// EnterPortal surfaces a qurl.RelayError — proving it got past parse,
	// verify, relay validation, serverId derivation, and knock construction.
	var relayErr *RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("want a *qurl.RelayError after the POST, got %v", err)
	}
	wantURL := "https://relay.example.com/relay/" + cellFingerprint
	if doer.gotURL != wantURL {
		t.Fatalf("relay POST routed to %q, want %q", doer.gotURL, wantURL)
	}
}

func TestNormalizeRelayErrorPreservesWrappedContext(t *testing.T) {
	coreErr := &relayknock.RelayError{Status: http.StatusBadGateway, Msg: "relay unavailable"}
	err := normalizeRelayError(fmt.Errorf("knock context: %w", coreErr), ErrMalformedReply)

	if !strings.Contains(err.Error(), "qurl: knock context") {
		t.Fatalf("normalized error lost wrapper context: %v", err)
	}
	var relayErr *RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("normalized error: want *qurl.RelayError, got %T: %v", err, err)
	}
	if relayErr.Status != http.StatusBadGateway || relayErr.Msg != "relay unavailable" {
		t.Fatalf("RelayError = %#v", relayErr)
	}
	var unwrapped *relayknock.RelayError
	if !errors.As(err, &unwrapped) {
		t.Fatalf("normalized error should preserve original relayknock error chain")
	}

	direct := normalizeRelayError(coreErr, ErrMalformedReply)
	if got, want := direct.Error(), "qurl: relay unavailable"; got != want {
		t.Fatalf("direct relay error = %q, want %q", got, want)
	}
}

// TestNormalizeRelayError_MalformedReplyMapsToClass pins the #54 fix at the
// mapping seam both front doors share: a relayknock.ErrMalformedReply (the
// counter/type-mismatch Knock refuses on a byzantine relay) is re-wrapped
// under the caller's selected malformed-reply sentinel rather than passing
// through as a raw string. The original relayknock sentinel stays matchable
// through the wrap so a caller can still detect the underlying cause.
func TestNormalizeRelayError_MalformedReplyMapsToClass(t *testing.T) {
	core := fmt.Errorf("%w: reply counter 7 does not echo request counter 6", relayknock.ErrMalformedReply)
	for _, class := range []error{ErrMalformedReply, ErrRegisterReplyMalformed} {
		got := normalizeRelayError(core, class)
		if !errors.Is(got, class) {
			t.Errorf("normalizeRelayError(malformed, %v): result %v does not match the class sentinel", class, got)
		}
		if !errors.Is(got, relayknock.ErrMalformedReply) {
			t.Errorf("normalizeRelayError(malformed, %v): lost the underlying relayknock.ErrMalformedReply", class)
		}
		var relayErr *RelayError
		if errors.As(got, &relayErr) {
			t.Errorf("normalizeRelayError(malformed, %v): a malformed-reply fault must not present as *RelayError", class)
		}
	}
}

// --- Bucket C: reply interpretation ----------------------------------------

func TestInterpretReply_SuccessACK(t *testing.T) {
	reply := &relayknock.Reply{
		Type: relayknock.TypeACK,
		Body: []byte(`{"errCode":"0","sessId":123,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`),
	}
	h, err := interpretReply(reply)
	if err != nil {
		t.Fatalf("success ACK: %v", err)
	}
	if h.ResourceURL != "https://r_x.qurl.site/path" {
		t.Fatalf("ResourceURL = %q", h.ResourceURL)
	}
	if h.OpenSeconds != 900 {
		t.Fatalf("OpenSeconds = %d, want 900", h.OpenSeconds)
	}
	if h.SessionID != 123 {
		t.Fatalf("SessionID = %d, want 123", h.SessionID)
	}
}

func TestInterpretReply_RejectsMissingOrZeroSessionID(t *testing.T) {
	for name, body := range map[string]string{
		"missing": `{"errCode":"0","opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"zero":    `{"errCode":"0","sessId":0,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
	} {
		t.Run(name, func(t *testing.T) {
			handle, err := interpretReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)})
			if handle != nil || !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("interpretReply = %#v, %v; want ErrMalformedReply", handle, err)
			}
		})
	}
}

func TestInterpretReply_RejectsInvalidSessionAndLifetimeShapes(t *testing.T) {
	tests := map[string]string{
		"null session":      `{"errCode":"0","sessId":null,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"negative session":  `{"errCode":"0","sessId":-1,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"string session":    `{"errCode":"0","sessId":"123","opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"fraction session":  `{"errCode":"0","sessId":1.5,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"exponent session":  `{"errCode":"0","sessId":1e2,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"session overflow":  `{"errCode":"0","sessId":18446744073709551616,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"duplicate session": `{"errCode":"0","sessId":123,"sessId":124,"opnTime":900,"redirectUrl":"https://r_x.qurl.site/path"}`,
		"zero open time":    `{"errCode":"0","sessId":123,"opnTime":0,"redirectUrl":"https://r_x.qurl.site/path"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			handle, err := interpretReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)})
			if handle != nil || !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("interpretReply = %#v, %v; want ErrMalformedReply", handle, err)
			}
		})
	}
}

func TestInterpretReply_AcceptsMaxUint32OpenTime(t *testing.T) {
	handle, err := interpretReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(`{"errCode":"0","sessId":123,"opnTime":4294967295,"redirectUrl":"https://r_x.qurl.site/path"}`)})
	if err != nil || handle == nil || handle.OpenSeconds != ^uint32(0) {
		t.Fatalf("max uint32 open time = %#v, %v; want accepted", handle, err)
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

func TestInterpretReply_ServerDenyRequiresSessionIDOmission(t *testing.T) {
	for name, body := range map[string]string{
		"nonzero":   `{"errCode":"52024","sessId":123}`,
		"zero":      `{"errCode":"52024","sessId":0}`,
		"null":      `{"errCode":"52024","sessId":null}`,
		"string":    `{"errCode":"52024","sessId":"123"}`,
		"duplicate": `{"errCode":"52024","sessId":0,"sessId":0}`,
		"omitted":   `{"errCode":"52024"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := interpretReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(body)})
			if name != "omitted" {
				if !errors.Is(err, ErrMalformedReply) {
					t.Fatalf("deny with session error = %v, want ErrMalformedReply", err)
				}
				return
			}
			var deny *ServerDenyError
			if !errors.As(err, &deny) || deny.ErrCode != "52024" {
				t.Fatalf("deny with omitted session = %v, want ServerDenyError", err)
			}
		})
	}
}

func TestInterpretReply_CookieChallenge(t *testing.T) {
	reply := &relayknock.Reply{Type: relayknock.TypeCookieChallenge}
	_, err := interpretReply(reply)
	if !errors.Is(err, ErrServerOverloaded) {
		t.Fatalf("cookie challenge: want ErrServerOverloaded, got %v", err)
	}
}

func TestInterpretReply_NilReply(t *testing.T) {
	_, err := interpretReply(nil)
	if !errors.Is(err, ErrMalformedReply) {
		t.Fatalf("nil reply: want ErrMalformedReply, got %v", err)
	}
}

func TestInterpretReply_SuccessButNoResourceURL(t *testing.T) {
	// A success ACK with no resource URL (here an empty body -> zero-value
	// success ACK) is not actionable: the caller has nothing to reach. It must
	// fail closed with ErrMalformedReply, not hand back an empty handle.
	reply := &relayknock.Reply{Type: relayknock.TypeACK, Body: nil}
	_, err := interpretReply(reply)
	if !errors.Is(err, ErrMalformedReply) {
		t.Fatalf("success ACK with no resource URL: want ErrMalformedReply, got %v", err)
	}
}

func TestInterpretReply_UnexpectedType(t *testing.T) {
	reply := &relayknock.Reply{Type: 99}
	_, err := interpretReply(reply)
	if !errors.Is(err, ErrMalformedReply) {
		t.Fatalf("unexpected type: want ErrMalformedReply, got %v", err)
	}
	if !strings.Contains(err.Error(), "unexpected qURL platform reply type") {
		t.Fatalf("unexpected type: error should name the cause, got %v", err)
	}
}

// TestNotConfiguredMessagesNameTheRightEntryPoint pins the rendered text, which
// is the entire point of the ErrNotConfigured split: the sentinel used to name
// EnterPortal, so an agent that called ConnectAgentRuntime was told to go read
// the link-opening docs. errors.Is cannot catch that regressing, because the
// sentinel identity is what stayed the same.
func TestNotConfiguredMessagesNameTheRightEntryPoint(t *testing.T) {
	if got := ErrNotConfigured.Error(); strings.Contains(got, "EnterPortal") {
		t.Fatalf("bare sentinel names an entry point: %q", got)
	}

	// The agent-runtime path must not mention EnterPortal at all.
	agentErr := ErrNoDeploymentHub
	if !errors.Is(agentErr, ErrNotConfigured) {
		t.Fatalf("agent hub error no longer wraps ErrNotConfigured: %v", agentErr)
	}
	if strings.Contains(agentErr.Error(), "EnterPortal") {
		t.Fatalf("agent hub error names EnterPortal: %q", agentErr)
	}
	if !strings.Contains(agentErr.Error(), "WithAgentRuntimeHub") {
		t.Fatalf("agent hub error dropped its actionable remedy: %q", agentErr)
	}

	// The opener path must still say which call needs configuring. Use the
	// missing-trust-store gate: EnterPortal with no deployment at all fails
	// earlier, in the deployment loader, which supplies its own context.
	_, openErr := EnterPortalWith(context.Background(), "https://example.test/#x", Config{})
	if !errors.Is(openErr, ErrNotConfigured) {
		t.Fatalf("EnterPortalWith error = %v, want ErrNotConfigured", openErr)
	}
	if !strings.Contains(openErr.Error(), "EnterPortal requires qURL opener config") {
		t.Fatalf("opener error no longer names its entry point: %q", openErr)
	}

	// Every ErrNotConfigured a caller can reach must carry some context beyond
	// the bare sentinel, or the split has regressed back to an unhelpful message.
	var nilStatic *StaticProvider
	_, _, staticErr := nilStatic.Resolve(context.Background())
	if got := staticErr.Error(); got == ErrNotConfigured.Error() {
		t.Fatalf("nil StaticProvider returns the bare sentinel with no context: %q", got)
	}
}
