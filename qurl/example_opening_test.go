package qurl_test

import (
	"context"
	"fmt"

	"github.com/layervai/qurl-go/qurl"
)

// ExampleEnterPortal is the COMPLETE opener integration. It is not an excerpt
// and it is not simplified for documentation: if opening a link needs more than
// this, this example must grow, and simplicity_test.go fails the build.
func ExampleEnterPortal() {
	handle, err := qurl.EnterPortal(context.Background(), "https://qurl.link/#qv2.…")
	if err != nil {
		return
	}
	// The placeholder link cannot verify, so EnterPortal returns above and this
	// never prints. The empty Output directive below is what makes `go test`
	// actually RUN this example rather than only compile it.
	fmt.Println(handle.ResourceURL)

	// Output:
}
