package qurl_test

import (
	"context"
	"errors"
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

// ExampleOpenCRID is the COMPLETE integration for a program that holds only a
// CRID: no link, no account, no credentials. The SDK asks for a link, checks
// it against the CRID, and opens it. Like ExampleEnterPortal, this is not an
// excerpt, and simplicity_test.go holds it to the same budget.
func ExampleOpenCRID() {
	handle, err := qurl.OpenCRID(context.Background(), "ae4jqpd7eaoslq7j…")
	if err != nil {
		return
	}
	// The placeholder is not a CRID, so OpenCRID refuses it above, before it
	// resolves any configuration or sends anything, and this never prints.
	fmt.Println(handle.ResourceURL)

	// Output:
}

// ExampleRequestCRIDLink takes the two steps apart, for a program that tells
// its user who published a resource before opening it. The publisher name is
// self-declared and unverified: it is printed quoted, next to its status.
func ExampleRequestCRIDLink() {
	const resourceCRID = "ae4jqpd7eaoslq7j…"
	issued, err := qurl.RequestCRIDLink(context.Background(), resourceCRID)
	if err != nil {
		return
	}
	fmt.Printf("Publisher: %q (verified: %t)\n", issued.Publisher.Name, issued.Publisher.Verified)
	// Open the link bound to the same CRID. The link is a credential: use it,
	// never print it.
	handle, err := qurl.EnterPortalForCRID(context.Background(), issued.Link, resourceCRID)
	if err != nil {
		return
	}
	fmt.Println(handle.ResourceURL)

	// Output:
}

// ExampleCheckCRIDLinkConfig asks, before there is a CRID to open, whether a
// link can be requested at all. It reads the deployment and sends nothing. A
// program with another way to open a resource uses the answer to choose.
func ExampleCheckCRIDLinkConfig() {
	err := qurl.CheckCRIDLinkConfig()
	switch {
	case err == nil:
		// A request can be sent. Whether a link is issued is the server's answer.
	case errors.Is(err, qurl.ErrCRIDLinkMisconfigured):
		// The deployment names an endpoint that cannot be used. Report err.
	case errors.Is(err, qurl.ErrCRIDLinkNotConfigured):
		// The deployment names no endpoint. Opening by CRID is not offered here.
	default:
		// The deployment itself could not be read. Report err.
	}

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
