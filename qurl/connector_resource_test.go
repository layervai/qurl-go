package qurl

// Wire-contract provenance:
//   - layervai/qurl-service@109523a4f37c10fb09733d8823e5a085116c972a
//     api/openapi.yaml: /v1/resources, /v1/resources/{id}, ResourceData, Meta.
//   - layervai/qurl-go@5ba76c1986bb5e33e3b795139b4ae1ffef86f8fb
//     qurl/client.go: post-dispatch outcome-unknown request semantics.
//   - layervai/qurl-connector@290d9ea3c67e253191b1d85edcb560eda1fa5674
//     pkg/apiclient/resources_test.go and pkg/bootstrap/tunnel_identity_test.go.
//
// Keep the exact request and distinct create/list/detail response fixtures below
// aligned with the current producers; umbrella tracking is qurl-connector#421.
// The connector SHA still models a legacy 409 resource_revoked response. Its
// cutover must replace that fixture with the service's 410 resource_tombstoned
// contract rather than carrying the legacy classifier into the SDK.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testConnectorID   = "r_connect1234"
	testConnectorSlug = "prod-dashboard"
	testKnockID       = "qurl-tunnel-server"
	testDeviceToken   = "lv_device_credential"
)

func TestClient_EnsureConnectorResourceContract(t *testing.T) {
	t.Parallel()

	for _, foundExisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("found_existing=%t", foundExisting), func(t *testing.T) {
			t.Parallel()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/proxy/v1/resources" || r.URL.RawQuery != "" {
					t.Fatalf("request = %s %s?%s, want POST /proxy/v1/resources", r.Method, r.URL.Path, r.URL.RawQuery)
				}
				assertConnectorAuthorization(t, r)
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("Content-Type = %q, want application/json", got)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if len(body) != 3 || body["type"] != "tunnel" || body["slug"] != testConnectorSlug || body["find_or_create"] != true {
					t.Fatalf("request body = %#v, want exact connector find-or-create wire body", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"data":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":"dashboard-display"},"meta":{"request_id":"req-1","found_existing":%t}}`, testConnectorID, testKnockID, testConnectorSlug, foundExisting)
			}))
			defer api.Close()

			client := newConnectorTestClient(t, api.URL+"/proxy")
			result, err := client.EnsureConnectorResource(context.Background(), testConnectorSlug)
			if err != nil {
				t.Fatalf("EnsureConnectorResource: %v", err)
			}
			resource := result.Resource
			if resource.ResourceID != testConnectorID || resource.KnockResourceID != testKnockID || resource.Status != "active" || resource.Slug != testConnectorSlug {
				t.Fatalf("resource = %#v", resource)
			}
			if resource.Alias == nil || *resource.Alias != "dashboard-display" {
				t.Fatalf("alias = %v, want distinct display alias", resource.Alias)
			}
			encoded, err := json.Marshal(resource)
			if err != nil {
				t.Fatalf("marshal ConnectorResource: %v", err)
			}
			var public map[string]any
			if err := json.Unmarshal(encoded, &public); err != nil {
				t.Fatalf("unmarshal ConnectorResource: %v", err)
			}
			if _, exposed := public["type"]; exposed {
				t.Fatalf("ConnectorResource JSON exposes producer type: %s", encoded)
			}
			if result.FoundExisting != foundExisting {
				t.Fatalf("FoundExisting = %t, want %t", result.FoundExisting, foundExisting)
			}
		})
	}
}

func TestClient_GetConnectorResourceDetailEnvelope(t *testing.T) {
	t.Parallel()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/resources/"+testConnectorID || r.URL.RawQuery != "" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		assertConnectorAuthorization(t, r)
		if got := r.Header.Get("Content-Type"); got != "" {
			t.Fatalf("GET Content-Type = %q, want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"resource":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":null},"qurls":[]},"meta":{"request_id":"req-2"}}`, testConnectorID, testKnockID, testConnectorSlug)
	}))
	defer api.Close()

	resource, err := newConnectorTestClient(t, api.URL).GetConnectorResource(context.Background(), testConnectorID)
	if err != nil {
		t.Fatalf("GetConnectorResource: %v", err)
	}
	if resource.ResourceID != testConnectorID || resource.Slug != testConnectorSlug || resource.Alias != nil {
		t.Fatalf("resource = %#v", resource)
	}
}

func TestClient_GetConnectorResourceBySlugDoesNotConflateAlias(t *testing.T) {
	t.Parallel()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/resources" {
			t.Fatalf("request = %s %s, want GET /v1/resources", r.Method, r.URL.Path)
		}
		if got := r.URL.Query(); len(got) != 1 || got.Get("slug") != testConnectorSlug {
			t.Fatalf("query = %v, want only slug=%q", got, testConnectorSlug)
		}
		assertConnectorAuthorization(t, r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":[{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":"renamed-display"}],"meta":{"request_id":"req-3"}}`, testConnectorID, testKnockID, testConnectorSlug)
	}))
	defer api.Close()

	resource, err := newConnectorTestClient(t, api.URL).GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
	if err != nil {
		t.Fatalf("GetConnectorResourceBySlug: %v", err)
	}
	if resource.Slug != testConnectorSlug || resource.Alias == nil || *resource.Alias != "renamed-display" {
		t.Fatalf("resource slug/alias = %q/%v", resource.Slug, resource.Alias)
	}
}

func TestClient_DeleteConnectorResourceNoBody(t *testing.T) {
	t.Parallel()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/resources/"+testConnectorID || r.URL.RawQuery != "" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		assertConnectorAuthorization(t, r)
		if got := r.Header.Get("Content-Type"); got != "" {
			t.Fatalf("DELETE Content-Type = %q, want empty", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	if err := newConnectorTestClient(t, api.URL).DeleteConnectorResource(context.Background(), testConnectorID); err != nil {
		t.Fatalf("DeleteConnectorResource: %v", err)
	}
}

func TestClient_DeleteConnectorResourceRequiresExactEmpty204(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "200", status: http.StatusOK},
		{name: "202", status: http.StatusAccepted},
		{name: "nonempty 204", status: http.StatusNoContent, body: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newConnectorTestClient(t, "http://localhost")
			client.httpClient = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodDelete || r.URL.Path != "/v1/resources/"+testConnectorID {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				assertConnectorAuthorization(t, r)
				return &http.Response{
					StatusCode: tt.status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Request:    r,
				}, nil
			})
			err := client.DeleteConnectorResource(context.Background(), testConnectorID)
			if !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("error = %v, want invalid API and connector response sentinels", err)
			}
			if !errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Fatalf("error = %v, want mutation outcome unknown", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if !errors.As(err, &outcomeUnknown) {
				t.Fatalf("error = %v, want internal outcome marker preserved", err)
			}
		})
	}
}

func TestClient_ConnectorResourceRequiresExactJSONStatus(t *testing.T) {
	t.Parallel()

	ensureBody := fmt.Sprintf(`{"data":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":false}}`, testConnectorID, testKnockID, testConnectorSlug)
	detailBody := fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}}`, testConnectorID, testKnockID, testConnectorSlug)
	listBody := fmt.Sprintf(`{"data":[{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}]}`, testConnectorID, testKnockID, testConnectorSlug)
	tests := []struct {
		name        string
		status      int
		body        string
		call        func(*Client) error
		wantUnknown bool
	}{
		{name: "ensure 200", status: http.StatusOK, body: ensureBody, call: ensureConnectorResourceError, wantUnknown: true},
		{name: "ensure 202", status: http.StatusAccepted, body: ensureBody, call: ensureConnectorResourceError, wantUnknown: true},
		{name: "get id 201", status: http.StatusCreated, body: detailBody, call: getConnectorResourceError},
		{name: "get id 204", status: http.StatusNoContent, call: getConnectorResourceError},
		{name: "get slug 201", status: http.StatusCreated, body: listBody, call: getConnectorResourceBySlugError},
		{name: "get slug 204", status: http.StatusNoContent, call: getConnectorResourceBySlugError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newConnectorTestClient(t, "http://localhost")
			client.httpClient = staticConnectorResponseDoer(tt.status, tt.body)
			err := tt.call(client)
			if !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("error = %v, want invalid API and connector response", err)
			}
			if got := errors.Is(err, ErrConnectorResourceOutcomeUnknown); got != tt.wantUnknown {
				t.Fatalf("ErrConnectorResourceOutcomeUnknown = %t, want %t; error=%v", got, tt.wantUnknown, err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if !errors.As(err, &outcomeUnknown) {
				t.Fatalf("post-dispatch response failure lost frozen internal outcome marker: %v", err)
			}
		})
	}
}

func TestClient_ConnectorResourceCreatePortal(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertConnectorAuthorization(t, r)
		switch requests.Add(1) {
		case 1:
			fmt.Fprintf(w, `{"data":[{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}]}`, testConnectorID, testKnockID, testConnectorSlug)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/"+testConnectorID+"/qurls" {
				t.Fatalf("portal request = %s %s", r.Method, r.URL.Path)
			}
			fmt.Fprintf(w, `{"data":{"resource_id":%q,"qurl_link":"https://qurl.link/at_connector"}}`, testConnectorID)
		default:
			t.Fatalf("unexpected request %d", requests.Load())
		}
	}))
	defer api.Close()

	resource, err := newConnectorTestClient(t, api.URL).GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
	if err != nil {
		t.Fatalf("GetConnectorResourceBySlug: %v", err)
	}
	portal, err := resource.CreatePortal(context.Background(), ValidFor(time.Minute))
	if err != nil {
		t.Fatalf("CreatePortal: %v", err)
	}
	if portal.ResourceID != testConnectorID {
		t.Fatalf("portal resource_id = %q", portal.ResourceID)
	}
}

func TestClient_ConnectorResourceTypedAPIErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		code   string
		call   func(*Client) error
		want   error
	}{
		{name: "ensure slug conflict", status: http.StatusConflict, code: "slug_in_use", call: func(c *Client) error {
			_, err := c.EnsureConnectorResource(context.Background(), testConnectorSlug)
			return err
		}, want: ErrConnectorResourceSlugConflict},
		{name: "ensure tombstone", status: http.StatusGone, code: "resource_tombstoned", call: func(c *Client) error {
			_, err := c.EnsureConnectorResource(context.Background(), testConnectorSlug)
			return err
		}, want: ErrConnectorResourceRevoked},
		{name: "ensure 410 wrong code remains raw", status: http.StatusGone, code: "resource_revoked", call: ensureConnectorResourceError},
		{name: "ensure code on wrong status remains raw", status: http.StatusConflict, code: "resource_tombstoned", call: ensureConnectorResourceError},
		{name: "ensure 404 remains raw", status: http.StatusNotFound, code: "resource_not_found", call: ensureConnectorResourceError},
		{name: "get id not found", status: http.StatusNotFound, code: "resource_not_found", call: getConnectorResourceError, want: ErrConnectorResourceNotFound},
		{name: "get id tombstone", status: http.StatusGone, code: "resource_tombstoned", call: getConnectorResourceError, want: ErrConnectorResourceRevoked},
		{name: "get id 410 wrong code remains raw", status: http.StatusGone, code: "resource_revoked", call: getConnectorResourceError},
		{name: "get id 409 remains raw", status: http.StatusConflict, code: "slug_in_use", call: getConnectorResourceError},
		{name: "slug lookup 404 remains raw", status: http.StatusNotFound, code: "resource_not_found", call: getConnectorResourceBySlugError},
		{name: "slug lookup 410 remains raw", status: http.StatusGone, code: "resource_tombstoned", call: getConnectorResourceBySlugError},
		{name: "slug lookup 409 remains raw", status: http.StatusConflict, code: "slug_in_use", call: getConnectorResourceBySlugError},
		{name: "delete not found", status: http.StatusNotFound, code: "resource_not_found", call: deleteConnectorResourceError, want: ErrConnectorResourceNotFound},
		{name: "delete 410 remains raw", status: http.StatusGone, code: "resource_tombstoned", call: deleteConnectorResourceError},
		{name: "delete 409 remains raw", status: http.StatusConflict, code: "slug_in_use", call: deleteConnectorResourceError},
		{name: "device credential unauthorized remains raw", status: http.StatusUnauthorized, code: "invalid_api_key", call: ensureConnectorResourceError},
	}
	typedErrors := []error{ErrConnectorResourceNotFound, ErrConnectorResourceRevoked, ErrConnectorResourceSlugConflict}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertConnectorAuthorization(t, r)
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tt.status)
				fmt.Fprintf(w, `{"error":{"code":%q,"detail":"contract test"}}`, tt.code)
			}))
			defer api.Close()

			err := tt.call(newConnectorTestClient(t, api.URL))
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			for _, typedErr := range typedErrors {
				if !errors.Is(tt.want, typedErr) && errors.Is(err, typedErr) {
					t.Fatalf("error = %v unexpectedly matches %v", err, typedErr)
				}
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tt.status || apiErr.Code != tt.code {
				t.Fatalf("error lost *APIError: %v", err)
			}
			if errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Fatalf("authoritative non-2xx unexpectedly has mutation ambiguity: %v", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if errors.As(err, &outcomeUnknown) {
				t.Fatalf("authoritative non-2xx unexpectedly has internal outcome marker: %v", err)
			}
		})
	}
}

func ensureConnectorResourceError(c *Client) error {
	_, err := c.EnsureConnectorResource(context.Background(), testConnectorSlug)
	return err
}

func getConnectorResourceError(c *Client) error {
	_, err := c.GetConnectorResource(context.Background(), testConnectorID)
	return err
}

func getConnectorResourceBySlugError(c *Client) error {
	_, err := c.GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
	return err
}

func deleteConnectorResourceError(c *Client) error {
	return c.DeleteConnectorResource(context.Background(), testConnectorID)
}

func TestClient_ConnectorResourceMutation5xxOutcomeUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      int
		call        func(*Client) error
		wantUnknown bool
	}{
		{name: "ensure 500", status: http.StatusInternalServerError, call: ensureConnectorResourceError, wantUnknown: true},
		{name: "ensure 502", status: http.StatusBadGateway, call: ensureConnectorResourceError, wantUnknown: true},
		{name: "delete 500", status: http.StatusInternalServerError, call: deleteConnectorResourceError, wantUnknown: true},
		{name: "delete 502", status: http.StatusBadGateway, call: deleteConnectorResourceError, wantUnknown: true},
		{name: "get id 500", status: http.StatusInternalServerError, call: getConnectorResourceError},
		{name: "get slug 502", status: http.StatusBadGateway, call: getConnectorResourceBySlugError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newConnectorTestClient(t, "http://localhost")
			client.httpClient = staticConnectorResponseDoer(tt.status, `{"error":{"code":"internal_error","detail":"upstream failed"}}`)
			err := tt.call(client)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tt.status || apiErr.Code != "internal_error" {
				t.Fatalf("error lost API response: %v", err)
			}
			if got := errors.Is(err, ErrConnectorResourceOutcomeUnknown); got != tt.wantUnknown {
				t.Fatalf("ErrConnectorResourceOutcomeUnknown = %t, want %t; error=%v", got, tt.wantUnknown, err)
			}
			if errors.Is(err, ErrConnectorResourceNotFound) || errors.Is(err, ErrConnectorResourceRevoked) || errors.Is(err, ErrConnectorResourceSlugConflict) {
				t.Fatalf("5xx was misclassified as lifecycle result: %v", err)
			}
			if errors.Is(err, ErrInvalidAPIResponse) || errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("5xx was misclassified as an invalid response: %v", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if errors.As(err, &outcomeUnknown) {
				t.Fatalf("received 5xx unexpectedly has transport/post-success marker: %v", err)
			}
		})
	}
}

func TestClient_ConnectorResourceSuccessfulResponseValidation(t *testing.T) {
	t.Parallel()

	valid := fmt.Sprintf(`{"data":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":false}}`, testConnectorID, testKnockID, testConnectorSlug)
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "malformed JSON", body: `{"data":`, want: ErrInvalidConnectorResourceResponse},
		{name: "missing resource id", body: strings.Replace(valid, `"resource_id":"`+testConnectorID+`",`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "missing knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`",`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "whitespace knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`"`, `"knock_resource_id":" `+testKnockID+` "`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "wrong type", body: strings.Replace(valid, `"type":"tunnel"`, `"type":"url"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "unknown status", body: strings.Replace(valid, `"status":"active"`, `"status":"pending"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "wrong slug", body: strings.Replace(valid, `"slug":"`+testConnectorSlug+`"`, `"slug":"other-dashboard"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "invalid alias", body: strings.Replace(valid, `},"meta"`, `,"alias":"bad alias"},"meta"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "missing found existing", body: strings.Replace(valid, `,"meta":{"found_existing":false}`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "detail envelope on create", body: fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}},"meta":{"found_existing":false}}`, testConnectorID, testKnockID, testConnectorSlug), want: ErrInvalidConnectorResourceResponse},
		{name: "revoked success row", body: strings.Replace(valid, `"status":"active"`, `"status":"revoked"`, 1), want: ErrInvalidConnectorResourceResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, tt.body)
			}))
			defer api.Close()

			_, err := newConnectorTestClient(t, api.URL).EnsureConnectorResource(context.Background(), testConnectorSlug)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if tt.name == "malformed JSON" && !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("malformed response lost ErrInvalidAPIResponse: %v", err)
			}
			if !errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Fatalf("successful ensure contract failure lost outcome ambiguity: %v", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if !errors.As(err, &outcomeUnknown) {
				t.Fatalf("successful ensure contract failure lost internal outcome marker: %v", err)
			}
		})
	}
}

func TestClient_ConnectorResourceRevokedSuccessRows(t *testing.T) {
	t.Parallel()

	detail := fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"revoked","slug":%q}}}`, testConnectorID, testKnockID, testConnectorSlug)
	client := newConnectorTestClient(t, "http://localhost")
	client.httpClient = staticConnectorResponseDoer(http.StatusOK, detail)
	if _, err := client.GetConnectorResource(context.Background(), testConnectorID); !errors.Is(err, ErrConnectorResourceRevoked) || errors.Is(err, ErrInvalidConnectorResourceResponse) {
		t.Fatalf("detail revoked row = %v, want revoked", err)
	}

	list := fmt.Sprintf(`{"data":[{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"revoked","slug":%q}]}`, testConnectorID, testKnockID, testConnectorSlug)
	client.httpClient = staticConnectorResponseDoer(http.StatusOK, list)
	if _, err := client.GetConnectorResourceBySlug(context.Background(), testConnectorSlug); !errors.Is(err, ErrInvalidConnectorResourceResponse) || errors.Is(err, ErrConnectorResourceRevoked) {
		t.Fatalf("active-only slug revoked row = %v, want invalid response", err)
	}
}

func TestClient_GetConnectorResourceBySlugCardinality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want error
	}{
		{name: "not found", data: `[]`, want: ErrConnectorResourceNotFound},
		{name: "null data", data: `null`, want: ErrInvalidConnectorResourceResponse},
		{name: "ambiguous", data: fmt.Sprintf(`[{"resource_id":%q},{"resource_id":"r_second1234"}]`, testConnectorID), want: ErrConnectorResourceAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"data":%s}`, tt.data)
			}))
			defer api.Close()
			_, err := newConnectorTestClient(t, api.URL).GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestClient_GetConnectorResourceBySlugRejectsMissingData(t *testing.T) {
	t.Parallel()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"meta":{"request_id":"req-missing-data"}}`)
	}))
	defer api.Close()
	_, err := newConnectorTestClient(t, api.URL).GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
	if !errors.Is(err, ErrInvalidConnectorResourceResponse) || errors.Is(err, ErrConnectorResourceNotFound) {
		t.Fatalf("error = %v, want malformed response and not not-found", err)
	}
}

func TestClient_GetConnectorResourceRejectsFlatOrMismatchedDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "flat data",
			body: fmt.Sprintf(`{"data":{"resource_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}`, testConnectorID, testKnockID, testConnectorSlug),
		},
		{
			name: "mismatched id",
			body: fmt.Sprintf(`{"data":{"resource":{"resource_id":"r_other123456","knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}}`, testKnockID, testConnectorSlug),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, tt.body)
			}))
			defer api.Close()
			_, err := newConnectorTestClient(t, api.URL).GetConnectorResource(context.Background(), testConnectorID)
			if !errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("error = %v, want malformed detail", err)
			}
		})
	}
}

func TestClient_ConnectorResourceRejectsInvalidInputsWithoutNetwork(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := newConnectorTestClient(t, "http://localhost:1")
	client.httpClient = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})
	if _, err := client.EnsureConnectorResource(context.Background(), "Bad Slug"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("invalid slug: %v", err)
	} else {
		assertNoConnectorMutationOutcome(t, err)
	}
	if _, err := client.GetConnectorResourceBySlug(context.Background(), "ab"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("short slug: %v", err)
	}
	if _, err := client.GetConnectorResource(context.Background(), "../resource"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("invalid id: %v", err)
	}
	if err := client.DeleteConnectorResource(context.Background(), "r_short"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("invalid delete id: %v", err)
	} else {
		assertNoConnectorMutationOutcome(t, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("network calls = %d, want 0", calls.Load())
	}
}

func assertNoConnectorMutationOutcome(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
		t.Fatalf("pre-dispatch error has public mutation ambiguity: %v", err)
	}
	var outcomeUnknown *apiRequestOutcomeUnknownError
	if errors.As(err, &outcomeUnknown) {
		t.Fatalf("pre-dispatch error has internal outcome marker: %v", err)
	}
}

func TestClient_ConnectorResourceMutationOutcomeUnknownBoundary(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("transport failed after dispatch")
	mutations := []struct {
		name string
		call func(*Client) error
	}{
		{name: "ensure", call: ensureConnectorResourceError},
		{name: "delete", call: deleteConnectorResourceError},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name+" transport", func(t *testing.T) {
			t.Parallel()
			client := newConnectorTestClient(t, "http://localhost")
			client.httpClient = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, transportErr
			})
			err := mutation.call(client)
			if !errors.Is(err, transportErr) || !errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Fatalf("error = %v, want transport cause and public mutation ambiguity", err)
			}
			if errors.Is(err, ErrInvalidAPIResponse) || errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("transport failure mislabeled invalid response: %v", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if !errors.As(err, &outcomeUnknown) {
				t.Fatalf("transport failure lost internal outcome marker: %v", err)
			}
		})

		t.Run(mutation.name+" successful status unreadable body", func(t *testing.T) {
			t.Parallel()
			status := http.StatusCreated
			if mutation.name == "delete" {
				status = http.StatusNoContent
			}
			readErr := errors.New("response read failed")
			client := newConnectorTestClient(t, "http://localhost")
			client.httpClient = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       &errorReadCloser{err: readErr},
					Request:    r,
				}, nil
			})
			err := mutation.call(client)
			if !errors.Is(err, readErr) || !errors.Is(err, ErrConnectorResourceOutcomeUnknown) || !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("error = %v, want read cause, ambiguity, and invalid-response sentinels", err)
			}
		})
	}

	for _, mutation := range mutations {
		t.Run(mutation.name+" authorizer failure is pre-dispatch", func(t *testing.T) {
			t.Parallel()
			authErr := errors.New("credential unavailable")
			var calls atomic.Int32
			client := &Client{
				credentials: CredentialProviderFunc(func(context.Context, *http.Request) error { return authErr }),
				baseURL:     "http://localhost",
				httpClient: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return nil, errors.New("unexpected dispatch")
				}),
			}
			err := mutation.call(client)
			if !errors.Is(err, authErr) {
				t.Fatalf("error = %v, want authorizer cause", err)
			}
			if errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Fatalf("pre-dispatch authorizer failure has mutation ambiguity: %v", err)
			}
			var outcomeUnknown *apiRequestOutcomeUnknownError
			if errors.As(err, &outcomeUnknown) {
				t.Fatalf("pre-dispatch authorizer failure has internal outcome marker: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("HTTP dispatches = %d, want 0", calls.Load())
			}
		})
	}
}

func TestClient_ConnectorResourceLookupRetainsOnlyFrozenInternalOutcomeMarker(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("lookup transport failed")
	client := newConnectorTestClient(t, "http://localhost")
	client.httpClient = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})
	err := getConnectorResourceError(client)
	if !errors.Is(err, transportErr) {
		t.Fatalf("error = %v, want transport cause", err)
	}
	if errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
		t.Fatalf("read matched mutation-specific public sentinel: %v", err)
	}
	var outcomeUnknown *apiRequestOutcomeUnknownError
	if !errors.As(err, &outcomeUnknown) {
		t.Fatalf("read lost frozen internal outcome marker: %v", err)
	}

	readErr := errors.New("lookup response read failed")
	client.httpClient = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &errorReadCloser{err: readErr},
			Request:    r,
		}, nil
	})
	err = getConnectorResourceBySlugError(client)
	if !errors.Is(err, readErr) || !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) {
		t.Fatalf("error = %v, want read cause and invalid-response sentinels", err)
	}
	if errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
		t.Fatalf("read matched mutation-specific public sentinel: %v", err)
	}
	outcomeUnknown = nil
	if !errors.As(err, &outcomeUnknown) {
		t.Fatalf("read response failure lost frozen internal outcome marker: %v", err)
	}
}

func TestClient_ConnectorResourceRedirectDoesNotForwardDeviceCredential(t *testing.T) {
	t.Parallel()

	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, err := newConnectorTestClient(t, source.URL).EnsureConnectorResource(context.Background(), testConnectorSlug)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect = %v, want *APIError 307", err)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target calls = %d, want 0", targetCalls.Load())
	}
}

func newConnectorTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := NewClient(BearerToken(testDeviceToken), WithBaseURL(baseURL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func staticConnectorResponseDoer(status int, body string) HTTPDoer {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})
}

func assertConnectorAuthorization(t *testing.T, r *http.Request) {
	t.Helper()
	if got, want := r.Header.Get("Authorization"), "Bearer "+testDeviceToken; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errorReadCloser struct {
	err error
}

func (r *errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *errorReadCloser) Close() error             { return nil }
