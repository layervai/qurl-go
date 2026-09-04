package qurl_test

import (
	"context"
	"fmt"
	"os"

	"github.com/layervai/qurl-go/qurl"
)

// ExampleEnterPortal is the COMPLETE opener integration. It is not an excerpt
// and it is not simplified for documentation: if opening a link needs more than
// this, this example must grow, and simplicity_test.go fails the build.
func ExampleEnterPortal() {
	handle, err := qurl.EnterPortal(context.Background(), "https://qurl.link/#qv2t1.1.1.1.…")
	if err != nil {
		return
	}
	// The placeholder link cannot verify, so EnterPortal returns above and this
	// never prints. The empty Output directive below is what makes `go test`
	// actually RUN this example rather than only compile it.
	fmt.Println(handle.ResourceURL)

	// Output:
}

func ExamplePortalSession() {
	// Explicit opener config requires a trusted public issuer key, its key ID,
	// and the deployment's relay host. These are not issuer credentials.
	issuerDER, err := os.ReadFile("/etc/layerv/qurl/issuer-public-key.der")
	if err != nil {
		return
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{"deployment-issuer": issuerDER})
	if err != nil {
		return
	}
	// Retain this config and session for retries of the same verified link.
	cfg := qurl.Config{
		TrustStore:     trust,
		RelayAllowlist: qurl.NewRelayAllowlist([]string{"relay.example.com:443"}),
		PortalSession:  &qurl.PortalSession{},
	}
	handle, err := qurl.EnterPortalWith(context.Background(), "https://qurl.link/#qv2t1.1.1.1.…", cfg)
	if err != nil {
		return
	}
	fmt.Println(handle.ResourceURL)

	// Output:
}
