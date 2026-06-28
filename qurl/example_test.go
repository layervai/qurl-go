package qurl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/qv2"
)

// Example is the fastest end-to-end tour of the SDK that runs offline today: mint
// a signed qURL link with a local issuer key, then parse and verify it with a
// trust store built from that issuer's public key. Minting and verifying are fully
// self-contained; only the final live open (EnterPortal) needs a deployed relay.
func Example() {
	ctx := context.Background()

	// 1. The issuer signing key. In production this is a KMS-resident key reached
	//    through the qv2.Signer seam; for local development a software key works and
	//    needs no AWS dependency.
	signer, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// 2. Mint the link. CellPublicKey is the NHP cell's raw X25519 key and
	//    ResourcePublicKey is the protected resource's P-256 key in DER form — both
	//    come from your deployment. Here we generate throwaway keys so the example is
	//    self-contained. CreatePortal generates the per-link keypair for you.
	link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
		CellPublicKey:     newX25519PublicKey(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: newP256SPKI(),
		JTI:               "qurl_demo_0001",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		panic(err)
	}

	// 3. Build the verifier's trust store from the issuer's published public key,
	//    keyed by the same kid the signer stamps into the claims.
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	trustStore, err := qv2.NewTrustStoreFromDER(map[string][]byte{
		signer.KID(): pubDER,
	})
	if err != nil {
		panic(err)
	}

	// 4. Parse the fragment and verify the issuer signature over the exact claim
	//    bytes. A tampered link fails here, before anything acts on it.
	frag, err := qv2.FragmentFromLinkAndVerify(link, trustStore)
	if err != nil {
		panic(err)
	}

	fmt.Println("version:", frag.Claims.V)
	fmt.Println("relay:  ", frag.Claims.RelayURL)
	fmt.Println("jti:    ", frag.Claims.Jti)
	// Output:
	// version: 2
	// relay:   https://relay.example.com
	// jti:     qurl_demo_0001
}

// ExampleCreatePortal mints a qURL link on the issuer side. The returned link is a
// standard https://qurl.link/#qv2.<claims>.<secret>.<sig> URL; everything sensitive
// rides in the fragment after '#', which browsers never send to the origin.
func ExampleCreatePortal() {
	signer, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	link, err := qurl.CreatePortal(context.Background(), signer, qurl.CreateParams{
		CellPublicKey:     newX25519PublicKey(),
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: newP256SPKI(),
		JTI:               "qurl_demo_0002",
		IssuedAt:          1_700_000_000,
		NotBefore:         1_700_000_000,
		Expiry:            1_700_003_600,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(link, "https://qurl.link/#qv2."))
	// Output: true
}

// ExampleNewStaticProvider wires the trust anchors an opener needs so the
// one-argument EnterPortal can resolve them at startup. A StaticProvider holds a
// fixed set of issuer keys and a relay allowlist; install it once with
// SetDefaultProvider and then call EnterPortal(ctx, link) with no per-call config.
func ExampleNewStaticProvider() {
	// The issuer public key you trust, keyed by its kid (published out of band, or
	// resolved from a discovery manifest — see NewDiscoveryProvider).
	signer, err := qv2.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}
	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	trustStore, err := qv2.NewTrustStoreFromDER(map[string][]byte{
		signer.KID(): pubDER,
	})
	if err != nil {
		panic(err)
	}

	// The relays your deployment permits. An empty allowlist rejects every link
	// (fail closed), so enumerate your relays explicitly.
	allowlist := qv2.NewRelayAllowlist([]string{"relay.example.com"})

	provider, err := qurl.NewStaticProvider(trustStore, allowlist)
	if err != nil {
		panic(err)
	}

	// Install once at startup. Now qurl.EnterPortal(ctx, link) resolves through it.
	qurl.SetDefaultProvider(provider)
	defer qurl.SetDefaultProvider(nil) // example hygiene; real deployments leave it installed

	fmt.Println(qurl.DefaultProvider() != nil)
	// Output: true
}

// --- example helpers (throwaway keys so the examples are self-contained) ---

// newX25519PublicKey returns a fresh raw 32-byte X25519 public key, the shape
// CreateParams.CellPublicKey expects.
func newX25519PublicKey() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// newP256SPKI returns a fresh P-256 public key in DER SPKI form, the shape
// CreateParams.ResourcePublicKey expects (and what AWS KMS GetPublicKey returns).
func newP256SPKI() []byte {
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
