package qurl_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/layervai/qurl-go/qurl"
)

func ExampleClient_ListResources() {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[{"crid":"ahpviqz46qwcvx56glfatm3p3ooccwfcf2it4sdgjervwdkapykw3o3qdq2a","type":"transit","status":"active"}],"meta":{"request_id":"req_example","has_more":false}}`)
	}))
	defer api.Close()
	client, err := qurl.NewClient(qurl.BearerToken("lv_example_only"), qurl.WithBaseURL(api.URL))
	if err != nil {
		panic(err)
	}
	page, err := client.ListResources(context.Background(), qurl.ResourceListOptions{Limit: 20})
	if err != nil {
		panic(err)
	}
	for _, resource := range page.Data {
		fmt.Println(resource.Type, resource.Status, resource.TargetURL == nil)
	}
	fmt.Println(page.Meta.RequestID)
	// Output:
	// transit active true
	// req_example
}
