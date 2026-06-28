package qurl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

// Example is the fastest offline tour: mint a signed qURL link with a local issuer
// key, then verify it with a trust store built from that issuer's public key.
// LayerV provides the resource config for production; this example generates
// throwaway values so it runs without platform access. Everything here uses the
// single qurl package.
func Example() {
	ctx := context.Background()

	// 1. The issuer signing key. In production this is a KMS-resident key reached
	//    through the Signer seam; for local development a software key works and needs
	//    no AWS dependency.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// 2. Create the resource config. In production, LayerV provides these values
	//    when you protect the private service. The demo generates throwaway values so
	//    it runs offline.
	resource := qurl.Resource{
		AccessPublicKey:  exampleX25519Public(),
		AccessURL:        "https://access.qurl.link",
		ResourceIdentity: exampleP256SPKI(),
		Label:            "demo-resource",
	}

	// 3. Mint the link. The SDK generates the per-link credential and link id for
	//    you; this example pins the id/time only so the output is stable.
	link, err := qurl.CreatePortal(ctx, signer, resource,
		qurl.WithLinkID("qurl_demo_0001"),
		qurl.WithIssuedAt(time.Unix(1_700_000_000, 0)),
		qurl.ValidFor(time.Hour),
	)
	if err != nil {
		panic(err)
	}

	// 4. Build the verifier's trust store from the issuer's published public key,
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

	// 5. Verify the issuer signature over the exact claim bytes. A tampered or
	//    untrusted link fails here, before anything acts on it.
	frag, err := qurl.VerifyLink(link, trust)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified:", frag.Claims.Jti)
	// Output:
	// verified: qurl_demo_0001
}

// ExampleCreatePortal mints a qURL link on the issuer side. The returned link is a
// standard https://qurl.link/#... URL; everything sensitive rides in the fragment
// after '#', which browsers never send to the origin.
func ExampleCreatePortal() {
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	resource := qurl.Resource{
		AccessPublicKey:  exampleX25519Public(),
		AccessURL:        "https://access.qurl.link",
		ResourceIdentity: exampleP256SPKI(),
	}

	link, err := qurl.CreatePortal(context.Background(), signer, resource, qurl.ValidFor(time.Hour))
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(link, "https://qurl.link/#"))
	// Output: true
}

// ExampleNewStaticProvider wires opener config once so the one-argument
// EnterPortal can resolve it at startup. StaticProvider is useful for tests and
// manually pinned LayerV config.
func ExampleNewStaticProvider() {
	// The issuer public key you trust, keyed by its kid.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	trust := trustStoreFor(signer)

	// The qURL platform access hosts from opener config. An empty allowlist rejects
	// every link (fail closed).
	allowlist := qurl.NewRelayAllowlist([]string{"access.qurl.link"})

	provider, err := qurl.NewStaticProvider(trust, allowlist)
	if err != nil {
		panic(err)
	}

	// Install once at startup. SetDefaultProvider sets process-global state, so this
	// example restores it on return (hygiene for other tests); a real application
	// installs it once and leaves it set. Now qurl.EnterPortal(ctx, link) resolves
	// through it.
	qurl.SetDefaultProvider(provider)
	defer qurl.SetDefaultProvider(nil)

	fmt.Println(qurl.DefaultProvider() != nil)
	// Output: true
}

// Example_rejectsForgedLink shows the core security guarantee: only a link signed by an
// issuer key in your trust store verifies. A link forged by a different key — even one
// that stamps a kid you recognize — fails closed with an error matching
// qurl.ErrSignature, so nothing downstream ever acts on it.
func Example_rejectsForgedLink() {
	// The real issuer your opener config trusts.
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
	resource := qurl.Resource{
		AccessPublicKey:  exampleX25519Public(),
		AccessURL:        "https://access.qurl.link",
		ResourceIdentity: exampleP256SPKI(),
	}
	forged, err := qurl.CreatePortal(context.Background(), attacker, resource, qurl.ValidFor(time.Hour))
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

func exampleX25519Public() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

func exampleP256SPKI() []byte {
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
