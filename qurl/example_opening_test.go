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
	fmt.Println(handle.ResourceURL)
}
