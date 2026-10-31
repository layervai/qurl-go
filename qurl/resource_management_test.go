// Contract source: qurl-service 376752482f42b43630b9d0d5734ff3be1048e341,
// api/openapi.yaml resource, per-qURL summary, and paged session operations.
// Do not substitute the /v1/qurls compatibility response for resource detail.
package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagementRESTJourney(t *testing.T) {
	t.Parallel()
	const cursor = "next+/=?&"
	resource := map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "type": "url", "status": "active", "private": false}
	prefix := "/v1/resources/" + testConnectorCRID
	var calls atomic.Int32
	patches := make(chan map[string]json.RawMessage, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer lv_management_fixture" {
			t.Error("management request lost authentication")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		write := func(data any, meta map[string]any) {
			if err := json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": meta}); err != nil {
				t.Error(err)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources":
			q := r.URL.Query()
			if q.Get("limit") != "2" || q.Get("cursor") != cursor || q.Get("status") != "active,revoked" || q.Get("alias") != "docs" || q.Get("type") != "url" {
				t.Errorf("resource query = %v", q)
			}
			write([]any{resource, map[string]any{"resource_id": testOtherConnectorID, "type": "transit", "status": "active", "internal_token": "must-not-surface"}}, map[string]any{"request_id": "req_list", "has_more": true, "next_cursor": cursor, "page_size": 2})
		case r.Method == http.MethodGet && r.URL.Path == prefix:
			write(map[string]any{"resource": resource, "qurls": []any{map[string]any{"qurl_id": "q_owned", "one_time_use": false, "max_sessions": 0, "use_count": 0}}}, map[string]any{"request_id": "req_detail"})
		case r.Method == http.MethodPatch && r.URL.Path == prefix:
			var patch map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			patches <- patch
			write(resource, map[string]any{"request_id": "req_update"})
		case r.Method == http.MethodGet && r.URL.Path == prefix+"/qurls":
			if r.URL.Query().Get("limit") != "1" || r.URL.Query().Get("cursor") != cursor {
				t.Errorf("portal query = %v", r.URL.Query())
			}
			write([]any{map[string]any{"qurl_id": "q_owned", "status": "active", "use_count": 0}}, map[string]any{"request_id": "req_links", "has_more": false})
		case r.Method == http.MethodGet && r.URL.Path == prefix+"/sessions":
			if r.URL.Query().Get("paged") != "true" || r.URL.Query().Get("cursor") != cursor {
				t.Errorf("session query = %v", r.URL.Query())
			}
			write([]any{map[string]any{"session_id": "session/owned", "qurl_id": "q_owned", "src_ip": "192.0.2.1", "created_at": "2026-10-30T12:00:00Z"}}, map[string]any{"request_id": "req_sessions", "has_more": false})
		case r.Method == http.MethodDelete && r.URL.EscapedPath() == prefix+"/sessions/session%2Fowned":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == prefix+"/sessions":
			if r.URL.Query().Get("paged") != "true" || r.URL.Query().Get("cursor") != cursor {
				t.Errorf("termination query = %v", r.URL.Query())
			}
			write(map[string]any{"terminated": 2}, map[string]any{"request_id": "req_terminate", "has_more": true, "next_cursor": cursor})
		case r.Method == http.MethodDelete && r.URL.Path == prefix:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected management request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client, err := NewClient(BearerToken("lv_management_fixture"), WithBaseURL(api.URL), WithHTTPClient(api.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	page, err := client.ListResources(ctx, ResourceListOptions{Cursor: cursor, Limit: 2, Alias: "docs", Status: []string{"active", "revoked"}, Type: "url"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 2 || page.Meta.RequestID != "req_list" || page.Meta.NextCursor != cursor {
		t.Fatalf("resource page = %+v", page)
	}
	redacted, err := json.Marshal(page.Data[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target_url", "description", "tags", "custom_domain", "alias", "preserve_host", "qurl_count", "slug", "must-not-surface", "internal_token"} {
		if strings.Contains(string(redacted), field) {
			t.Errorf("redacted resource exposed %s", field)
		}
	}
	if page.Data[1].QURLCount != nil || page.Data[1].TargetURL != nil {
		t.Fatal("omitted fields were fabricated")
	}
	detail, err := client.GetResource(ctx, testConnectorCRID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Meta.RequestID != "req_detail" || detail.Data.Resource.CRID != testConnectorCRID || len(detail.Data.QURLs) != 1 {
		t.Fatalf("detail = %+v", detail)
	}
	portal := detail.Data.QURLs[0]
	if portal.OneTimeUse == nil || *portal.OneTimeUse || portal.MaxSessions == nil || *portal.MaxSessions != 0 || portal.UseCount == nil || *portal.UseCount != 0 {
		t.Fatal("explicit false/zero values were lost")
	}
	empty := ""
	tags := []string{}
	updated, err := client.UpdateResource(ctx, testConnectorCRID, ResourceUpdate{Description: &empty, Tags: &tags, ClearAlias: true})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Meta.RequestID != "req_update" {
		t.Fatal("update dropped request id")
	}
	patch := <-patches
	if string(patch["description"]) != `""` || string(patch["tags"]) != "[]" || string(patch["alias"]) != "null" || len(patch) != 3 {
		t.Fatalf("patch = %s", patch)
	}
	links, err := client.ListPortals(ctx, testConnectorCRID, PageOptions{Cursor: cursor, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(links.Data) != 1 || links.Data[0].Label != nil || links.Data[0].TargetPath != nil || links.Meta.RequestID != "req_links" {
		t.Fatalf("links = %+v", links)
	}
	sessions, err := client.ListSessions(ctx, testConnectorCRID, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions.Data) != 1 || sessions.Data[0].SourceIP != "192.0.2.1" || sessions.Meta.RequestID != "req_sessions" {
		t.Fatalf("sessions = %+v", sessions)
	}
	if err := client.TerminateSession(ctx, testConnectorCRID, sessions.Data[0].SessionID); err != nil {
		t.Fatal(err)
	}
	terminated, err := client.TerminateSessions(ctx, testConnectorCRID, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if terminated.Data == nil || terminated.Data.Terminated == nil || *terminated.Data.Terminated != 2 || terminated.Meta.NextCursor != cursor {
		t.Fatalf("termination = %+v", terminated)
	}
	if err := client.RevokeResource(ctx, testConnectorCRID); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 8 {
		t.Fatalf("requests = %d, want 8", calls.Load())
	}
}

func TestResourceUpdateAliasPresence(t *testing.T) {
	t.Parallel()
	alias := "docs"
	for _, tc := range []struct {
		name   string
		update ResourceUpdate
		want   string
	}{
		{"omitted", ResourceUpdate{}, "{}"},
		{"set", ResourceUpdate{Alias: &alias}, `{"alias":"docs"}`},
		{"clear", ResourceUpdate{ClearAlias: true}, `{"alias":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.update)
			if err != nil || string(got) != tc.want {
				t.Fatalf("wire = %s, %v; want %s", got, err, tc.want)
			}
		})
	}
	if _, err := json.Marshal(ResourceUpdate{Alias: &alias, ClearAlias: true}); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("alias conflict = %v", err)
	}
}

type managementCall struct {
	name string
	call func(*Client) error
}

func managementCalls() []managementCall {
	ctx := context.Background()
	description := "updated"
	return []managementCall{
		{"list resources", func(c *Client) error { _, err := c.ListResources(ctx, ResourceListOptions{}); return err }},
		{"get resource", func(c *Client) error { _, err := c.GetResource(ctx, testConnectorCRID); return err }},
		{"update resource", func(c *Client) error {
			_, err := c.UpdateResource(ctx, testConnectorCRID, ResourceUpdate{Description: &description})
			return err
		}},
		{"revoke resource", func(c *Client) error { return c.RevokeResource(ctx, testConnectorCRID) }},
		{"list portals", func(c *Client) error { _, err := c.ListPortals(ctx, testConnectorCRID, PageOptions{}); return err }},
		{"list sessions", func(c *Client) error { _, err := c.ListSessions(ctx, testConnectorCRID, ""); return err }},
		{"terminate session", func(c *Client) error { return c.TerminateSession(ctx, testConnectorCRID, "owned") }},
		{"terminate page", func(c *Client) error { _, err := c.TerminateSessions(ctx, testConnectorCRID, ""); return err }},
	}
}

func TestManagementRejectsNilClientsAndWrongSuccessStatuses(t *testing.T) {
	t.Parallel()
	for _, tc := range managementCalls() {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(nil); !errors.Is(err, ErrInvalidClientConfig) {
				t.Fatalf("nil client = %v", err)
			}
			var calls int
			client, err := NewClient(BearerToken("lv_fixture"), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
			})))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.call(client); !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("wrong success status = %v", err)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1 (no replay)", calls)
			}
		})
	}
}

func TestManagementInvalidInputsDoNotDispatch(t *testing.T) {
	t.Parallel()
	client, err := NewClient(BearerToken("lv_fixture"), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid input reached transport")
		return nil, errors.New("unexpected request")
	})))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	alias := "docs"
	checks := []func() error{
		func() error { _, err := client.ListResources(ctx, ResourceListOptions{Limit: -1}); return err },
		func() error { _, err := client.ListResources(ctx, ResourceListOptions{Limit: 101}); return err },
		func() error {
			_, err := client.ListPortals(ctx, testConnectorCRID, PageOptions{Limit: 101})
			return err
		},
		func() error { _, err := client.GetResource(ctx, "at_private_credential"); return err },
		func() error { _, err := client.UpdateResource(ctx, testConnectorCRID, ResourceUpdate{}); return err },
		func() error {
			_, err := client.UpdateResource(ctx, testConnectorCRID, ResourceUpdate{Alias: &alias, ClearAlias: true})
			return err
		},
		func() error { return client.TerminateSession(ctx, testConnectorCRID, "..") },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, ErrInvalidResourceRequest) {
			t.Errorf("case %d = %v", i, err)
		}
	}
}

func TestManagementMalformedResponsesFailClosed(t *testing.T) {
	t.Parallel()
	get := func(c *Client) error { _, err := c.GetResource(context.Background(), testConnectorCRID); return err }
	list := func(c *Client) error {
		_, err := c.ListResources(context.Background(), ResourceListOptions{})
		return err
	}
	links := func(c *Client) error {
		_, err := c.ListPortals(context.Background(), testConnectorCRID, PageOptions{})
		return err
	}
	sessions := func(c *Client) error {
		_, err := c.ListSessions(context.Background(), testConnectorCRID, "")
		return err
	}
	terminate := func(c *Client) error {
		_, err := c.TerminateSessions(context.Background(), testConnectorCRID, "")
		return err
	}
	for _, tc := range []struct {
		name, body string
		call       func(*Client) error
	}{
		{"missing detail", `{}`, get},
		{"missing resource", `{"data":{}}`, get},
		{"bad identity", `{"data":{"resource":{"resource_id":"at_private_canary"}}}`, get},
		{"wrong identity", fmt.Sprintf(`{"data":{"resource":{"resource_id":%q}}}`, testOtherConnectorID), get},
		{"wrong key binding", fmt.Sprintf(`{"data":{"resource":{"crid":%q,"resource_id":%q}}}`, testConnectorCRID, testOtherConnectorID), get},
		{"missing array", `{}`, list},
		{"null array", `{"data":null}`, list},
		{"bad row", `{"data":[{}]}`, list},
		{"cursor missing", `{"data":[],"meta":{"has_more":true}}`, list},
		{"negative page size", `{"data":[],"meta":{"page_size":-1}}`, list},
		{"bad link", `{"data":[{"qurl_id":"at_private_canary"}]}`, links},
		{"bad session", `{"data":[{"session_id":""}]}`, sessions},
		{"missing count", `{"data":{}}`, terminate},
		{"null count", `{"data":{"terminated":null}}`, terminate},
		{"negative count", `{"data":{"terminated":-1}}`, terminate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			client, err := NewClient(BearerToken("lv_fixture"), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})))
			if err != nil {
				t.Fatal(err)
			}
			err = tc.call(client)
			if !errors.Is(err, ErrInvalidAPIResponse) || strings.Contains(err.Error(), "private_canary") {
				t.Fatalf("malformed response = %v", err)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestManagementFilteredEmptyPageKeepsCursorAndLegacyLocator(t *testing.T) {
	t.Parallel()
	client, err := NewClient(BearerToken("lv_fixture"), WithHTTPClient(doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("status") != "" || req.URL.Query().Get("limit") != "" {
			t.Errorf("defaults added filters: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":[],"meta":{"has_more":true,"next_cursor":"opaque"}}`))}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListResources(context.Background(), ResourceListOptions{})
	if err != nil || len(page.Data) != 0 || page.Meta.NextCursor != "opaque" {
		t.Fatalf("filtered page = %+v, %v", page, err)
	}
	if got, err := managementPath(client, testConnectorID); err != nil || got != "/v1/resources/"+testConnectorID {
		t.Fatalf("legacy locator = %q, %v", got, err)
	}
}

func TestAPIResponseDecodeErrorDoesNotPrintPrivateValues(t *testing.T) {
	t.Parallel()
	const canary = "private-response-date-canary"
	raw := fmt.Sprintf(`{"data":{"resource":{"crid":%q,"created_at":%q}}}`, testConnectorCRID, canary)
	client, err := NewClient(BearerToken("lv_fixture"), WithHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw))}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetResource(context.Background(), testConnectorCRID)
	var cause *time.ParseError
	if !errors.Is(err, ErrInvalidAPIResponse) || !errors.As(err, &cause) || strings.Contains(err.Error(), canary) {
		t.Fatalf("decode error lost its class/cause or leaked the value: %v", err)
	}
}

func TestManagedResourceJSONDoesNotGainFields(t *testing.T) {
	t.Parallel()
	var resource ManagedResource
	const raw = `{"crid":"ahpviqz46qwcvx56glfatm3p3ooccwfcf2it4sdgjervwdkapykw3o3qdq2a","type":"transit","status":"active"}`
	if err := json.Unmarshal([]byte(raw), &resource); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if err := json.Unmarshal([]byte(raw), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("round trip changed redacted shape: %s", encoded)
	}
}
