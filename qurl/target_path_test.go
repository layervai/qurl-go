package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestPortalTargetPathReleasedConformance(t *testing.T) {
	t.Parallel()
	artifact, err := conformance.TargetPathV1()
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Contract.MaxBytes != maxTargetPathLength || artifact.Contract.WireField != "target_path" {
		t.Fatal("target-path contract changed")
	}
	for _, tc := range artifact.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/"+testConnectorCRID+"/qurls" {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				value, present := body["target_path"]
				if present != tc.Present || (present && value != *tc.Value) {
					t.Errorf("wire target_path = %v (present %v)", value, present)
				}
				data := map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "qurl_link": "https://qurl.link/at_test"}
				if tc.Present {
					data["target_path"] = *tc.Value
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
					t.Error(err)
				}
			}))
			defer api.Close()
			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatal(err)
			}
			var opts []PortalOption
			if tc.Present {
				opts = append(opts, WithTargetPath(*tc.Value))
			}
			resource := client.ResourceByCRID(testConnectorCRID)
			connector := &ConnectorResource{client: client, CRID: testConnectorCRID}
			for _, mint := range []func() (*Portal, error){
				func() (*Portal, error) { return client.CreatePortal(context.Background(), resource, opts...) },
				func() (*Portal, error) { return resource.CreatePortal(context.Background(), opts...) },
				func() (*Portal, error) { return connector.CreatePortal(context.Background(), opts...) },
			} {
				portal, err := mint()
				if tc.Outcome == conformance.ExpectReject {
					if !errors.Is(err, ErrInvalidPortalRequest) || portal != nil || attempts.Load() != 0 {
						t.Fatalf("rejected input: portal=%v error=%v requests=%d", portal, err, attempts.Load())
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if (portal.TargetPath != nil) != tc.Present || (tc.Present && *portal.TargetPath != *tc.Value) {
					t.Fatal("recorded target path differs from the wire response")
				}
			}
			if tc.Outcome == conformance.ExpectAccept && attempts.Load() != 3 {
				t.Fatalf("accepted input requests = %d, want 3", attempts.Load())
			}
		})
	}
}

func TestPortalTargetPathResponseMustMatchRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		field    string
		forURL   bool
		withPath bool
	}{
		{name: "omitted", withPath: true},
		{name: "null", field: `,"target_path":null`, withPath: true},
		{name: "empty", field: `,"target_path":""`, withPath: true},
		{name: "different", field: `,"target_path":"/sibling"`, withPath: true},
		{name: "noncanonical", field: `,"target_path":"/view/../file"`, withPath: true},
		{name: "unexpected scope", field: `,"target_path":"/view/file"`},
		{name: "unscoped null", field: `,"target_path":null`},
		{name: "URL resource null", field: `,"target_path":null`, forURL: true},
		{name: "URL resource scope", field: `,"target_path":"/view/file"`, forURL: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attempts.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{"resource_id":"` + testConnectorID + `","crid":"` + testConnectorCRID + `","qurl_link":"https://qurl.link/at_test"` + tc.field + `}}`))
			}))
			defer api.Close()
			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatal(err)
			}
			var portal *Portal
			if tc.forURL {
				portal, _, err = client.CreatePortalForURL(context.Background(), "https://example.com")
			} else {
				var opts []PortalOption
				if tc.withPath {
					opts = append(opts, WithTargetPath("/view/file"))
				}
				portal, err = client.CreatePortal(context.Background(), client.ResourceByCRID(testConnectorCRID), opts...)
			}
			if !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrAPIRequestOutcomeUnknown) || portal != nil || attempts.Load() != 1 {
				t.Fatalf("portal=%v error=%v requests=%d, want fail closed without replay", portal, err, attempts.Load())
			}
		})
	}
}
