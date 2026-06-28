package qv2_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/layervai/qurl-go/internal/qv2"
)

// ExampleParseAndVerify verifies a qURL v2 fragment's issuer signature against a
// trust store. ParseAndVerify strict-parses the fragment, then checks the signature
// over the EXACT received claim bytes — never a re-serialization — so a verified
// fragment is safe to act on. (qurl.EnterPortal does this for you as step one of
// opening a link; this shows the crypto core directly.)
func ExampleParseAndVerify() {
	// An issuer key and the matching single-key trust store.
	signer, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trustStore := trustStoreFor(signer)

	fragment := mintFragment(signer)

	frag, err := qv2.ParseAndVerify(fragment, trustStore)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified! version:", frag.Claims.V, "issuer:", frag.Claims.Iss)
	// Output: verified! version: 2 issuer: qurl-service
}

// Example_forgedLinkRejected shows the core security guarantee in action: only a
// link signed by an issuer key in your trust store verifies. A link forged by a
// different key — even one that stamps a kid you recognize — fails closed with an
// error that matches qv2.ErrSignature, so nothing downstream (relay routing, the
// knock) ever runs on claims that don't verify.
func Example_forgedLinkRejected() {
	// The real issuer your deployment trusts.
	trusted, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trustStore := trustStoreFor(trusted)

	// An attacker mints a link with their OWN key but stamps the same kid. Its own
	// self-signature is internally consistent, so the forgery is only caught at the
	// verifier — against the trusted public key.
	attacker, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	forged := mintFragment(attacker)

	_, err = qv2.ParseAndVerify(forged, trustStore)
	fmt.Println("rejected:", errors.Is(err, qv2.ErrSignature))
	// Output: rejected: true
}

// --- example helpers ---

// trustStoreFor builds a single-key trust store from a signer's public key, keyed
// by the kid the signer stamps into claims.
func trustStoreFor(signer *qv2.LocalSigner) *qv2.TrustStore {
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	ts, err := qv2.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
	if err != nil {
		panic(err)
	}
	return ts
}

// mintFragment assembles and signs a complete qv2.<claims>.<secret>.<sig> fragment
// using only the qv2 mint API (SignClaims + BuildFragment), mirroring what
// qurl.CreatePortal does at the library's top layer.
func mintFragment(signer *qv2.LocalSigner) string {
	b64 := base64.RawURLEncoding

	// The per-link X25519 keypair: the private half rides in the secret, the public
	// half is bound into the signed claims.
	userKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	claims := &qv2.Claims{
		V:                    qv2.Version,
		Iss:                  qv2.Issuer,
		Iat:                  1_700_000_000,
		Nbf:                  1_700_000_000,
		Exp:                  1_700_003_600,
		Jti:                  "qurl_demo_0003",
		CellPublicKeyB64:     b64.EncodeToString(newX25519PublicKeyBytes()),
		RelayURL:             "https://relay.example.com",
		ResourcePublicKeyB64: b64.EncodeToString(newP256SPKIBytes()),
		QurlUserPublicKeyB64: b64.EncodeToString(userKey.PublicKey().Bytes()),
	}

	// Sign the exact claim bytes; SignClaims stamps the signer's kid and returns the
	// canonical Part-1 string plus the raw 64-byte signature.
	claimsB64, rawSig, err := qv2.SignClaims(context.Background(), signer, claims)
	if err != nil {
		panic(err)
	}

	// Part 2 (the secret) is base64url(JSON{"qurl_user_private_key_b64": <key>}).
	secretJSON, err := json.Marshal(qv2.Secret{
		QurlUserPrivateKeyB64: b64.EncodeToString(userKey.Bytes()),
	})
	if err != nil {
		panic(err)
	}
	secretB64 := b64.EncodeToString(secretJSON)

	fragment, err := qv2.BuildFragment(claimsB64, secretB64, rawSig)
	if err != nil {
		panic(err)
	}
	return fragment
}

// newX25519PublicKeyBytes returns a fresh raw 32-byte X25519 public key.
func newX25519PublicKeyBytes() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// newP256SPKIBytes returns a fresh P-256 public key in DER SPKI form (the resource
// public key shape).
func newP256SPKIBytes() []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}
