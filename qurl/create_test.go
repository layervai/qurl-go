package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// CreatePortal is proved to be the INVERSE of EnterPortal: a link it mints is
// driven back through EnterPortalWith (the locked enter verb) and through
// qv2.FragmentFromLinkAndVerify (the verifier core) using a trust store holding
// the mint signer's public key. The round-trip exercises the real verify path, so
// the two verbs are provably symmetric — not two parallel implementations. A
// post-mint tamper is rejected with qv2.ErrSignature specifically, isolating the
// signature-binding property from parser/encoding faults.

const createTestRelayURL = "https://relay.example.com"

// mintSignerSeq gives every minted signer a process-unique kid so a trust store
// built for one signer genuinely lacks another signer's kid (distinguishing
// ErrUnknownKID from ErrSignature).
var mintSignerSeq atomic.Uint64

// mintSigner returns a fresh local issuer signer plus a trust store holding its
// public key under its kid — the same DER load path production uses for KMS
// GetPublicKey output.
func mintSigner(t *testing.T) (*qv2.LocalSigner, *TrustStore) {
	t.Helper()
	kid := fmt.Sprintf("qurl-issuer-key-create-test-%d", mintSignerSeq.Add(1))
	signer, err := qv2.GenerateLocalSigner(kid)
	if err != nil {
		t.Fatalf("GenerateLocalSigner: %v", err)
	}
	der, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	ts, err := NewTrustStoreFromDER(map[string][]byte{signer.KID(): der})
	if err != nil {
		t.Fatalf("NewTrustStoreFromDER: %v", err)
	}
	return signer, ts
}

// validCreateParams builds a CreateParams with realistic, strict-parseable
// bindings: a real 32-byte X25519 cell key and a real P-256 SPKI resource key, so
// the only thing under test is the verb, not fixture shape.
func validCreateParams(t *testing.T) CreateParams {
	t.Helper()
	cellKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate cell key: %v", err)
	}
	return CreateParams{
		CellPublicKey:     cellKey.PublicKey().Bytes(),
		RelayURL:          createTestRelayURL,
		ResourcePublicKey: mustResourceKeyDER(t),
		CellID:            "cell-create-test",
		JTI:               "qurl_01JCREATEPORTAL",
		IssuedAt:          1781910000,
		NotBefore:         1781910000,
		Expiry:            1781910300,
	}
}

// mustResourceKeyDER returns a real P-256 public key in DER SPKI form (the shape a
// KMS resource key takes), so the resource-key length-window check in the strict
// parser passes with realistic bytes.
func mustResourceKeyDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resource key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource SPKI: %v", err)
	}
	return der
}

// TestCreatePortal_EnterPortalSymmetry is the headline proof: a CreatePortal link
// is accepted by the locked EnterPortal verb. EnterPortalWith runs parse → verify
// issuer sig → validate relay_url → derive serverId → build + POST the knock; a
// capturing HTTP client short-circuits the transport, so reaching a
// qurl.RelayError proves every pre-POST step passed on the minted link, and
// the captured URL proves the route derived from the minted cell key.
func TestCreatePortal_EnterPortalSymmetry(t *testing.T) {
	signer, ts := mintSigner(t)
	params := validCreateParams(t)

	link, err := CreatePortal(context.Background(), signer, params)
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if !strings.HasPrefix(link, LinkBaseURL+"#qv2.") {
		t.Fatalf("link is not a qv2 qURL link: %q", link)
	}

	doer := &capturingDoer{}
	cfg := Config{TrustStore: ts, RelayAllowlist: relayExampleAllowlist(), HTTPClient: doer}
	_, err = EnterPortalWith(context.Background(), link, cfg)

	var relayErr *RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("minted link through EnterPortalWith: want a *qurl.RelayError after the POST, got %v", err)
	}

	// Route is derived from the cell key the mint bound into the claims.
	wantURL := createTestRelayURL + "/relay/" + relayknock.PubKeyFingerprint(params.CellPublicKey)
	if doer.gotURL != wantURL {
		t.Fatalf("relay POST routed to %q, want %q", doer.gotURL, wantURL)
	}
}

// TestCreatePortal_VerifierRoundTrip drives the minted link through the verifier
// core directly and asserts the bound claims and the per-qURL keypair survive the
// round-trip: the recovered claim fields equal the mint inputs, and the secret's
// private key derives the public key bound in the claims (an internally consistent
// fresh keypair).
func TestCreatePortal_VerifierRoundTrip(t *testing.T) {
	signer, ts := mintSigner(t)
	params := validCreateParams(t)

	link, err := CreatePortal(context.Background(), signer, params)
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}

	frag, err := qv2.FragmentFromLinkAndVerify(link, ts.core())
	if err != nil {
		t.Fatalf("FragmentFromLinkAndVerify of minted link: %v", err)
	}
	c := frag.Claims
	if c.V != qv2.Version || c.Iss != qv2.Issuer || c.Kid != signer.KID() {
		t.Fatalf("pinned/stamped claims wrong: v=%d iss=%q kid=%q", c.V, c.Iss, c.Kid)
	}
	if c.RelayURL != params.RelayURL || c.Jti != params.JTI || c.CellID != params.CellID {
		t.Fatalf("bound claims wrong: relay=%q jti=%q cell_id=%q", c.RelayURL, c.Jti, c.CellID)
	}
	if c.Exp != params.Expiry || c.Nbf != params.NotBefore || c.Iat != params.IssuedAt {
		t.Fatalf("window wrong: iat=%d nbf=%d exp=%d", c.Iat, c.Nbf, c.Exp)
	}

	// The secret's private key must derive the public key bound into the claims:
	// proof the verb generated one consistent fresh keypair, not mismatched halves.
	priv, err := qv2.DecodeQurlUserPrivateKey(frag.Secret)
	if err != nil {
		t.Fatalf("decode secret private key: %v", err)
	}
	derived, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("rebuild ecdh private key: %v", err)
	}
	if b64url.EncodeToString(derived.PublicKey().Bytes()) != c.QurlUserPublicKeyB64 {
		t.Fatal("secret private key does not derive the public key bound in the claims")
	}
}

// TestCreatePortal_FreshKeyPerCall proves each mint generates a distinct per-qURL
// keypair (and distinct fragments) even with identical params — the per-qURL key
// is ephemeral by design.
func TestCreatePortal_FreshKeyPerCall(t *testing.T) {
	signer, ts := mintSigner(t)
	params := validCreateParams(t)

	linkA, err := CreatePortal(context.Background(), signer, params)
	if err != nil {
		t.Fatalf("CreatePortal A: %v", err)
	}
	linkB, err := CreatePortal(context.Background(), signer, params)
	if err != nil {
		t.Fatalf("CreatePortal B: %v", err)
	}
	if linkA == linkB {
		t.Fatal("two mints with identical params produced identical links (key not fresh)")
	}

	fragA, err := qv2.FragmentFromLinkAndVerify(linkA, ts.core())
	if err != nil {
		t.Fatalf("verify A: %v", err)
	}
	fragB, err := qv2.FragmentFromLinkAndVerify(linkB, ts.core())
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	if fragA.Claims.QurlUserPublicKeyB64 == fragB.Claims.QurlUserPublicKeyB64 {
		t.Fatal("two mints produced the same per-qURL public key")
	}
}

// TestCreatePortal_TamperRejected proves the issuer signature binds the exact
// minted claims: tampering a still-valid claim field (jti) after the mint and
// reassembling under the ORIGINAL signature fails verification with ErrSignature.
// The tampered fragment is well-formed and strict-parseable, so this isolates the
// signature property from parser/encoding rejection.
func TestCreatePortal_TamperRejected(t *testing.T) {
	signer, ts := mintSigner(t)

	link, err := CreatePortal(context.Background(), signer, validCreateParams(t))
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}

	tampered := tamperJTI(t, link)

	// Sanity: tampering changed the link.
	if tampered == link {
		t.Fatal("fixture: tampered link must differ from the minted link")
	}

	// Through the verifier core.
	if _, err := qv2.FragmentFromLinkAndVerify(tampered, ts.core()); !errors.Is(err, qv2.ErrSignature) {
		t.Fatalf("tampered claims via verifier: want ErrSignature, got %v", err)
	}
	// And through the locked enter verb — same fail-closed result.
	cfg := Config{TrustStore: ts, RelayAllowlist: relayExampleAllowlist(), HTTPClient: &capturingDoer{}}
	if _, err := EnterPortalWith(context.Background(), tampered, cfg); !errors.Is(err, qv2.ErrSignature) {
		t.Fatalf("tampered claims via EnterPortalWith: want ErrSignature, got %v", err)
	}
}

// tamperJTI re-parses a minted link, changes the jti to another VALID value,
// re-encodes Part 1, and reassembles the fragment under the ORIGINAL signature and
// secret. The result is a well-formed, strict-parseable fragment whose claims no
// longer match the signature.
func tamperJTI(t *testing.T, link string) string {
	t.Helper()
	frag, err := qv2.ParseFragment(link[strings.IndexByte(link, '#')+1:])
	if err != nil {
		t.Fatalf("ParseFragment(minted): %v", err)
	}
	tamperedClaims := *frag.Claims
	tamperedClaims.Jti = frag.Claims.Jti + "-tampered"

	claimsJSON := mustJSON(t, tamperedClaims)
	claimsB64 := b64url.EncodeToString(claimsJSON)

	body, err := qv2.BuildFragment(claimsB64, frag.SecretB64, mustDecode(t, frag.SigB64))
	if err != nil {
		t.Fatalf("BuildFragment(tampered): %v", err)
	}
	return LinkBaseURL + "#" + body
}

// mustJSON marshals v to JSON, matching the canonical claims encoding the mint
// path uses (encoding/json), so the tampered Part 1 is byte-shaped like a real
// claims part.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestCreatePortal_UnknownIssuerRejected proves a link minted by one signer does
// not verify against a trust store that lacks that signer's kid.
func TestCreatePortal_UnknownIssuerRejected(t *testing.T) {
	signer, _ := mintSigner(t)
	_, otherTS := mintSigner(t) // a DIFFERENT signer's key under a different kid

	link, err := CreatePortal(context.Background(), signer, validCreateParams(t))
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if _, err := qv2.FragmentFromLinkAndVerify(link, otherTS.core()); !errors.Is(err, qv2.ErrUnknownKID) {
		t.Fatalf("foreign trust store: want ErrUnknownKID, got %v", err)
	}
}

// TestCreatePortal_ParamValidation proves the verb fails closed (before any keygen
// or signing) on a nil signer and on each missing required binding, and that an
// invalid signed window (nbf>exp) surfaces from the strict parser.
func TestCreatePortal_ParamValidation(t *testing.T) {
	signer, _ := mintSigner(t)
	base := validCreateParams(t)

	if _, err := CreatePortal(context.Background(), nil, base); !errors.Is(err, ErrInvalidCreateParams) {
		t.Fatalf("nil signer: want ErrInvalidCreateParams, got %v", err)
	}

	cases := map[string]func(p *CreateParams){
		"missing cell key":     func(p *CreateParams) { p.CellPublicKey = nil },
		"missing relay url":    func(p *CreateParams) { p.RelayURL = "" },
		"missing resource key": func(p *CreateParams) { p.ResourcePublicKey = nil },
		"missing jti":          func(p *CreateParams) { p.JTI = "" },
		// Zero-value time fields are missing-required-input faults too, so they
		// share the ErrInvalidCreateParams class rather than leaking ErrStrictParse.
		"missing issued_at":  func(p *CreateParams) { p.IssuedAt = 0 },
		"missing not_before": func(p *CreateParams) { p.NotBefore = 0 },
		"missing expiry":     func(p *CreateParams) { p.Expiry = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validCreateParams(t)
			mutate(&p)
			if _, err := CreatePortal(context.Background(), signer, p); !errors.Is(err, ErrInvalidCreateParams) {
				t.Fatalf("%s: want ErrInvalidCreateParams, got %v", name, err)
			}
		})
	}

	t.Run("invalid window nbf>exp", func(t *testing.T) {
		p := validCreateParams(t)
		p.NotBefore = p.Expiry + 1
		_, err := CreatePortal(context.Background(), signer, p)
		if !errors.Is(err, qv2.ErrStrictParse) {
			t.Fatalf("nbf>exp: want wrapped qv2.ErrStrictParse, got %v", err)
		}
	})
}
