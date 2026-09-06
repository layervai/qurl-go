package qurl_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/layervai/qurl-go/internal/testkeys"
	"github.com/layervai/qurl-go/qurl"
)

// ExampleVerifyLink verifies a qURL v2 fragment's issuer signature against a
// trust store. VerifyLink strict-parses the fragment, then checks the signature
// over the EXACT received claim bytes — never a re-serialization — so a verified
// fragment is safe to act on. (qurl.EnterPortal does this for you as step one of
// opening a link; this shows the crypto core directly.)
func ExampleVerifyLink() {
	// An issuer key and the matching single-key trust store.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trustStore := exampleTrustStoreFor(signer)

	link := mintLink(signer)

	frag, err := qurl.VerifyLink(link, trustStore)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified! version:", frag.Claims.V, "issuer:", frag.Claims.Iss)
	// Output: verified! version: 2 issuer: qurl-service
}

// Example_forgedLinkRejected shows the core security guarantee in action: only a
// link signed by an issuer key in your trust store verifies. A link forged by a
// different key — even one that stamps a kid you recognize — fails closed with an
// error that matches qurl.ErrSignature, so nothing downstream (relay routing, the
// knock) ever runs on claims that don't verify.
func Example_forgedLinkRejected() {
	// The real issuer your deployment trusts.
	trusted, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trustStore := exampleTrustStoreFor(trusted)

	// An attacker mints a link with their OWN key but stamps the same kid. Its own
	// self-signature is internally consistent, so the forgery is only caught at the
	// verifier — against the trusted public key.
	attacker, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	forged := mintLink(attacker)

	_, err = qurl.VerifyLink(forged, trustStore)
	fmt.Println("rejected:", errors.Is(err, qurl.ErrSignature))
	// Output: rejected: true
}

// --- example helpers ---

// exampleTrustStoreFor builds a single-key trust store from a signer's public key, keyed
// by the kid the signer stamps into claims.
func exampleTrustStoreFor(signer *qurl.LocalSigner) *qurl.TrustStore {
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	ts, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
	if err != nil {
		panic(err)
	}
	return ts
}

func mintLink(signer *qurl.LocalSigner) string {
	link, err := qurl.CreatePortalWithParams(context.Background(), signer, qurl.CreateParams{
		CellPublicKey:     testkeys.X25519Public(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: testkeys.P256SPKI(),
		JTI:               "qurl_demo_0003",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		panic(err)
	}
	return link
}
