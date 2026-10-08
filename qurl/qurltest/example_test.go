package qurltest_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/qurl/qurltest"
)

// ExampleCRIDLinkServer tests code that asks for a link by CRID, without a
// server. The calls are the production calls: the SDK builds the request,
// authenticates the reply, and checks the link, exactly as it does in service.
func ExampleCRIDLinkServer() {
	server := qurltest.NewCRIDLinkServer()
	ctx := context.Background()

	// The server issues a link for its CRID.
	issued, err := qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config())
	if err != nil {
		fmt.Println("request failed:", err)
		return
	}
	fmt.Printf("publisher %q, verified: %t\n", issued.Publisher.Name, issued.Publisher.Verified)

	// The same call when the server refuses it.
	server.Refuse("52602")
	_, err = qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config())
	fmt.Println("not found:", errors.Is(err, qurl.ErrCRIDLinkNotFound))

	// Output:
	// publisher "Example Publisher", verified: false
	// not found: true
}

// ExampleCRIDLinkServer_PrivateFor tests code that opens a private resource as
// a registered device, without a server. The server issues its link only to
// the device key it was told to allow.
func ExampleCRIDLinkServer_PrivateFor() {
	server := qurltest.NewCRIDLinkServer()
	ctx := context.Background()

	// A device key for the test, and a server that allows that device.
	device, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("generate a key:", err)
		return
	}
	server.PrivateFor(device.PublicKey().Bytes())

	// A client that is not a device gets "not found" after one request.
	_, err = qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config())
	fmt.Println("not as a device, not found:", errors.Is(err, qurl.ErrCRIDLinkNotFound))

	// The device gets the link. Its first request is sent under a random key
	// and is answered "not found". Only then does it ask under its own key.
	issued, err := qurl.RequestCRIDLinkAsDeviceWith(ctx, device.Bytes(), server.CRID(), server.Config())
	if err != nil {
		fmt.Println("request failed:", err)
		return
	}
	fmt.Printf("as the device: publisher %q\n", issued.Publisher.Name)
	for i, request := range server.Requests()[1:] {
		fmt.Printf("request %d of the device call, under the device key: %t\n", i+1, request.AsDevice)
	}

	// Output:
	// not as a device, not found: true
	// as the device: publisher "Example Publisher"
	// request 1 of the device call, under the device key: false
	// request 2 of the device call, under the device key: true
}
