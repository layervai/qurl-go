package qurl

import (
	"context"
	"encoding/json"
	"errors"
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
		expected := "/v1/resources/" + crid + "/preview"
		if r.Method == http.MethodPost {
			expected += "/uploads"
		}
		if r.URL.Path != expected {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Method == http.MethodPatch {
			var patch PreviewPatch
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
			}
			if patch.Revision != 1 || patch.Description == nil || *patch.Description != "Public preview" || patch.MediaIDs != nil {
				t.Errorf("patch = %+v", patch)
			}
		}
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
	if _, err = client.UpdatePreview(context.Background(), crid, PreviewPatch{Revision: 1, Description: &text}); err != nil {
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

func TestPreviewUploadRejectsInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		name, url, header, id string
		status                int
	}{
		{"http", "http://s3.example.test", "If-None-Match", "asset", 200},
		{"no host", "https:///file", "If-None-Match", "asset", 200},
		{"user", "https://user@s3.example.test", "If-None-Match", "asset", 200},
		{"fragment", "https://s3.example.test/#frag", "If-None-Match", "asset", 200},
		{"no headers", "https://s3.example.test", "", "asset", 200},
		{"no id", "https://s3.example.test", "If-None-Match", "", 200},
		{"authorization", "https://s3.example.test", "aUtHoRiZaTiOn", "asset", 200},
		{"cookie", "https://s3.example.test", "Cookie", "asset", 200},
		{"host", "https://s3.example.test", "Host", "asset", 200},
		{"proxy", "https://s3.example.test", "Proxy-Authorization", "asset", 200},
		{"stale", "https://s3.example.test", "If-None-Match", "asset", 409},
		{"unverified", "https://s3.example.test", "If-None-Match", "asset", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				headers := map[string]string{}
				if tc.header != "" {
					headers[tc.header] = "*"
				}
				if err := json.NewEncoder(w).Encode(PreviewUploadForm{URL: tc.url, UploadID: tc.id, Headers: headers}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := NewClient(BearerToken("owner"), WithBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.CreatePreviewUpload(context.Background(), "qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq", PreviewUploadRequest{})
			if err == nil || result != nil {
				t.Fatalf("result=%v err=%v", result, err)
			}
			if tc.status == 200 && !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatal(err)
			}
		})
	}
}

func TestPreviewPatchMediaPresence(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  *[]string
		want string
	}{
		{"unchanged", nil, ""},
		{"empty", new([]string), "[]"},
		{"remove", &[]string{}, "[]"},
		{"retain", &[]string{"asset"}, `["asset"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if string(body["media_ids"]) != tc.want || string(body["revision"]) != "9" {
					t.Errorf("body=%s", body)
				}
				fmt.Fprint(w, `{"revision":10}`)
			}))
			defer server.Close()
			client, err := NewClient(BearerToken("owner"), WithBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UpdatePreview(context.Background(), "qe4jqpd7eaoslq7jinmjv4yikgzmcxgpjfsuobiniqnko32lpw742pueoujq", PreviewPatch{Revision: 9, MediaIDs: tc.ids}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
