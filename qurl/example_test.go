package qurl_test

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/layervai/qurl-go/internal/testkeys"
	"github.com/layervai/qurl-go/qurl"
)

// Example is the fastest end-to-end tour that runs offline today: mint a signed qURL
// link with a local issuer key, then verify it with a trust store built from that
// issuer's public key. Minting and verifying are fully self-contained; only the final
// live open (qurl.EnterPortal) needs a deployed relay. Everything here uses the single
// qurl package.
func Example() {
	ctx := context.Background()

	// 1. The issuer signing key. In production this is a KMS-resident key reached
	//    through the Signer seam; for local development a software key works and needs
	//    no AWS dependency.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// 2. Mint the link. CellPublicKey is the NHP cell's raw X25519 key and
	//    ResourcePublicKey is the protected resource's P-256 key in DER form — both
	//    come from your deployment. Here we generate throwaway keys so the example is
	//    self-contained. CreatePortal generates the per-link keypair for you.
	link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
		CellPublicKey:     testkeys.X25519Public(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: testkeys.P256SPKI(),
		JTI:               "qurl_demo_0001",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		panic(err)
	}

	// 3. Build the verifier's trust store from the issuer's published public key,
	//    keyed by the same kid the signer stamps into the link.
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{
		signer.KID(): pubDER,
	})
	if err != nil {
		panic(err)
	}

	// 4. Verify the issuer signature over the exact claim bytes. A tampered or
	//    untrusted link fails here, before anything acts on it.
	frag, err := qurl.VerifyLink(link, trust)
	if err != nil {
		panic(err)
	}

	fmt.Println("relay:", frag.Claims.RelayURL)
	fmt.Println("jti:  ", frag.Claims.Jti)
	// Output:
	// relay: https://relay.example.com
	// jti:   qurl_demo_0001
}

// ExampleCreatePortal mints a qURL link on the issuer side. The returned link is a
// standard https://qurl.link/#... URL; everything sensitive rides in the fragment
// after '#', which browsers never send to the origin.
func ExampleCreatePortal() {
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	link, err := qurl.CreatePortal(context.Background(), signer, qurl.CreateParams{
		CellPublicKey:     testkeys.X25519Public(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: testkeys.P256SPKI(),
		JTI:               "qurl_demo_0002",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(link, "https://qurl.link/#"))
	// Output: true
}

// ExampleNewStaticProvider wires the trust anchors an opener needs so the
// one-argument EnterPortal can resolve them at startup. A StaticProvider holds a fixed
// set of issuer keys and a relay allowlist; install it once with SetDefaultProvider
// and then call EnterPortal(ctx, link) with no per-call config.
func ExampleNewStaticProvider() {
	// The issuer public key you trust, keyed by its kid (published out of band, or
	// resolved from a discovery manifest — see NewDiscoveryProvider).
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trust := trustStoreFor(signer)

	// The relays your deployment permits. An empty allowlist rejects every link
	// (fail closed), so enumerate your relays explicitly.
	allowlist := qurl.NewRelayAllowlist([]string{"relay.example.com"})

	provider, err := qurl.NewStaticProvider(trust, allowlist)
	if err != nil {
		panic(err)
	}

	// Install once at startup. Now qurl.EnterPortal(ctx, link) resolves through it.
	qurl.SetDefaultProvider(provider)
	defer qurl.SetDefaultProvider(nil) // example hygiene; real deployments leave it installed

	fmt.Println(qurl.DefaultProvider() != nil)
	// Output: true
}

// Example_rejectsForgedLink shows the core security guarantee: only a link signed by an
// issuer key in your trust store verifies. A link forged by a different key — even one
// that stamps a kid you recognize — fails closed with an error matching
// qurl.ErrSignature, so nothing downstream ever acts on it.
func Example_rejectsForgedLink() {
	// The real issuer your deployment trusts.
	trusted, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trust := trustStoreFor(trusted)

	// An attacker mints a link with their OWN key but stamps the same kid.
	attacker, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	forged, err := qurl.CreatePortal(context.Background(), attacker, qurl.CreateParams{
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

	_, err = qurl.VerifyLink(forged, trust)
	fmt.Println("rejected:", errors.Is(err, qurl.ErrSignature))
	// Output: rejected: true
}

// trustStoreFor builds a single-key trust store from a local signer's published public
// key, keyed by the kid the signer stamps into links.
func trustStoreFor(signer *qurl.LocalSigner) *qurl.TrustStore {
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
	if err != nil {
		panic(err)
	}
	return trust
}
