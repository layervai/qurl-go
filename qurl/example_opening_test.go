package qurl_test

import (
	"bytes"
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

// ExampleOpenCRIDAsDevice opens a resource by CRID as a registered device. A
// device that the owner of a private resource allowed can open that resource
// this way, and so can the owner's own device. The SDK sends the first link
// request under a random key. It uses the device key for one second request,
// and only when the server answers the first one with "not found".
//
// This is the whole integration. The SDK resolves the configuration, as it
// does for OpenCRID.
func ExampleOpenCRIDAsDevice() {
	// The device's static private key, the key KnockRegisteredAgent takes. It
	// stays yours: clear it when you no longer need it.
	devicePrivateKey := registeredDevicePrivateKey()
	defer clear(devicePrivateKey)
	handle, err := qurl.OpenCRIDAsDevice(context.Background(), devicePrivateKey, "ae4jqpd7eaoslq7j…")
	if err != nil {
		return
	}
	// The placeholder is not a CRID, so the call refuses it above, before it
	// resolves any configuration or sends anything, and this never prints.
	fmt.Println(handle.ResourceURL)

	// Output:
}

// ExampleOpenCRIDAsDeviceWith is the same open with explicit configuration,
// for a program that does not use the SDK's own resolution. The four values of
// the configuration come from the deployment operator. None of them is a
// secret. The device key is not part of the configuration.
func ExampleOpenCRIDAsDeviceWith() {
	issuerDER, err := os.ReadFile("/etc/layerv/qurl/issuer-public-key.der")
	if err != nil {
		return
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{"deployment-issuer": issuerDER})
	if err != nil {
		return
	}
	// Exactly one cell: the link request is sealed to its key.
	cells, err := qurl.NewCellCatalog([]qurl.CellEntry{{
		CellID: "cell0", Host: "cell0.example.com", Port: 443, ServerPublicKeyB64: "BASE64_X25519_CELL_KEY",
	}})
	if err != nil {
		return
	}
	cfg := qurl.Config{
		TrustStore:     trust,
		Cells:          cells,
		RelayAllowlist: qurl.NewRelayAllowlist([]string{"relay.example.com"}),
		CRIDLink:       &qurl.CRIDLinkConfig{RelayURL: "https://relay.example.com", LinkOrigin: "https://links.example.com"},
	}
	devicePrivateKey := registeredDevicePrivateKey()
	defer clear(devicePrivateKey)
	handle, err := qurl.OpenCRIDAsDeviceWith(context.Background(), devicePrivateKey, "ae4jqpd7eaoslq7j…", cfg)
	if err != nil {
		return
	}
	fmt.Println(handle.ResourceURL)

	// Output:
}

// registeredDevicePrivateKey stands in for the key of a registered device. A
// program gets it from AgentRuntimeBinding.TakeDeviceStaticPrivateKey, or from
// where it keeps that key. The bytes here are a placeholder, not a key.
func registeredDevicePrivateKey() []byte { return bytes.Repeat([]byte{0x01}, 32) }

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
