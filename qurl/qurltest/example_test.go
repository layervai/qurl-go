package qurltest_test

import (
	"context"
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
