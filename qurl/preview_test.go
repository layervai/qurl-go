package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreviewOwnerAPIAndBoundedDeviceSurface(t *testing.T) {
	crid := "qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq"
	methods := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer preview-owner" {
			t.Error("missing owner credential")
		}
		methods = append(methods, r.Method)
		if strings.HasSuffix(r.URL.Path, "/uploads") {
			fmt.Fprint(w, `{"preview":{"revision":2},"upload_id":"asset","url":"https://s3.example.test","headers":{"If-None-Match":"*","Content-Type":"image/png"}}`)
		} else {
			fmt.Fprint(w, `{"revision":1,"description":"Public preview"}`)
		}
	}))
	defer server.Close()
	client, err := NewClient(BearerToken("preview-owner"), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Preview(context.Background(), crid); err != nil {
		t.Fatal(err)
	}
	text := "Public preview"
	if _, err = client.UpdatePreview(context.Background(), crid, PreviewPatch{Description: &text}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.CreatePreviewUpload(context.Background(), crid, PreviewUploadRequest{Revision: 1, ContentType: "image/png", Size: 4, Alt: "Guide"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET,PATCH,POST" {
		t.Fatal(methods)
	}
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{{"GET", "/v1/resources/r_test/preview", true}, {"PATCH", "/v1/resources/r_test/preview", true}, {"POST", "/v1/resources/r_test/preview/uploads", true}, {"PUT", "/v1/resources/r_test/preview", false}, {"POST", "/internal/v1/preview/complete", false}, {"GET", "/v1/resources/r_test/preview/uploads", false}} {
		if registeredAgentResourceRouteAllowed(tc.method, tc.path) != tc.allowed {
			t.Fatal(tc)
		}
	}
}
