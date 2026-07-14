package qurl

// Wire-contract provenance:
//   - layervai/qurl-service@0188c5ce56b469f409edec83e96c651010fb56e2
//     api/openapi.yaml: /v1/resources, /v1/resources/{id}, ResourceId,
//     ResourceData, Meta, the exact shared slug/alias grammar, and the explicit
//     opaque connector_routing_id contract.
//   - layervai/qurl-service@5d8086c91059c3ff132f493ce6ab45c37d47e015
//     internal/domain/resource_key.go: strict canonical resource-public-key
//     decoding and DER SPKI length bounds; api/openapi.yaml: genuine canonical
//     P-256 resource-key examples; internal/domain/{slug,alias}.go: the same
//     exact shared slug/alias grammar.
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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
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

const (
	// Real P-256 DER SPKI public keys from the fenced qurl-service OpenAPI
	// examples keep lifecycle fixtures on the canonical public resource ID.
	testConnectorID      = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2cTVv5_3eeYCcLLq5ROYCqcmY50HiKZ9ATglIkPnCji1E_S63UMtXba1moR8-Q6EV7oM6zwwh9_j2CDujzXvLA"
	testOtherConnectorID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZLdT1C_J8lCh_mpQXJMoRzKi3Q_C5TnVQFYW0Cz5L5Jo83djulhze84U_rrhnUVQQRajXmUQKn-VQ8jR-qatA"
	// Deliberately opaque rather than derived in this SDK test: the producer
	// owns routing-label derivation and the SDK must consume the field verbatim.
	testConnectorRoutingID = "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testConnectorSlug      = "prod-dashboard"
	testKnockID            = "qurl-tunnel-server"
	testDeviceToken        = "lv_device_credential"
)

func TestConnectorResourcePublicShape(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[ConnectorResource]()
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.IsExported() {
			got = append(got, field.Name)
		}
	}
	want := []string{"ResourceID", "ConnectorRoutingID", "KnockResourceID", "Slug", "Alias"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ConnectorResource exported fields = %v, want %v; cycle RunID and producer type/status are not resource fields", got, want)
	}
}

func TestConnectorResourcePublicKeyFixturesAreCanonicalP256(t *testing.T) {
	t.Parallel()

	for i, fixture := range []string{testConnectorID, testOtherConnectorID} {
		der, err := base64.RawURLEncoding.Strict().DecodeString(fixture)
		if err != nil {
			t.Fatalf("fixture %d strict base64url decode: %v", i, err)
		}
		if got := base64.RawURLEncoding.EncodeToString(der); got != fixture {
			t.Fatalf("fixture %d is not canonical unpadded base64url", i)
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("fixture %d parse PKIX public key: %v", i, err)
		}
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("fixture %d public key = %T, want ECDSA P-256", i, parsed)
		}
		if publicKey.Curve != elliptic.P256() {
			t.Fatalf("fixture %d curve = %v, want P-256", i, publicKey.Curve)
		}
		publicKeyBytes, err := publicKey.Bytes()
		if err != nil {
			t.Fatalf("fixture %d serialize P-256 point: %v", i, err)
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKeyBytes); err != nil {
			t.Fatalf("fixture %d has invalid P-256 point: %v", i, err)
		}
		canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatalf("fixture %d marshal PKIX public key: %v", i, err)
		}
		if !bytes.Equal(canonicalDER, der) {
			t.Fatalf("fixture %d DER is not canonical PKIX SPKI", i)
		}
	}
}

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
				fmt.Fprintf(w, `{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":"dashboard-display"},"meta":{"request_id":"req-1","found_existing":%t}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug, foundExisting)
			}))
			defer api.Close()

			client := newConnectorTestClient(t, api.URL+"/proxy")
			result, err := client.EnsureConnectorResource(context.Background(), testConnectorSlug)
			if err != nil {
				t.Fatalf("EnsureConnectorResource: %v", err)
			}
			resource := result.Resource
			if resource.ResourceID != testConnectorID || resource.ConnectorRoutingID != testConnectorRoutingID || resource.KnockResourceID != testKnockID || resource.Slug != testConnectorSlug {
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
			if _, exposed := public["status"]; exposed {
				t.Fatalf("ConnectorResource JSON exposes producer status: %s", encoded)
			}
			if got := public["resource_id"]; got != testConnectorID {
				t.Fatalf("ConnectorResource JSON resource_id = %v", got)
			}
			if got := public["connector_routing_id"]; got != testConnectorRoutingID {
				t.Fatalf("ConnectorResource JSON connector_routing_id = %v", got)
			}
			if got := public["knock_resource_id"]; got != testKnockID {
				t.Fatalf("ConnectorResource JSON knock_resource_id = %v", got)
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
		fmt.Fprintf(w, `{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":null},"qurls":[]},"meta":{"request_id":"req-2"}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	}))
	defer api.Close()

	resource, err := newConnectorTestClient(t, api.URL).GetConnectorResource(context.Background(), testConnectorID)
	if err != nil {
		t.Fatalf("GetConnectorResource: %v", err)
	}
	if resource.ResourceID != testConnectorID || resource.ConnectorRoutingID != testConnectorRoutingID || resource.KnockResourceID != testKnockID || resource.Slug != testConnectorSlug || resource.Alias != nil {
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
		fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q,"alias":"renamed-display"}],"meta":{"request_id":"req-3"}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	}))
	defer api.Close()

	resource, err := newConnectorTestClient(t, api.URL).GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
	if err != nil {
		t.Fatalf("GetConnectorResourceBySlug: %v", err)
	}
	if resource.ResourceID != testConnectorID || resource.ConnectorRoutingID != testConnectorRoutingID || resource.KnockResourceID != testKnockID || resource.Slug != testConnectorSlug || resource.Alias == nil || *resource.Alias != "renamed-display" {
		t.Fatalf("resource = %#v", resource)
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
			client.httpClient = doerFunc(func(r *http.Request) (*http.Response, error) {
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

	ensureBody := fmt.Sprintf(`{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":false}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	detailBody := fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	listBody := fmt.Sprintf(`{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}]}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
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
			fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}]}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
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

	valid := fmt.Sprintf(`{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":false}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "malformed JSON", body: `{"data":`, want: ErrInvalidConnectorResourceResponse},
		{name: "missing resource id", body: strings.Replace(valid, `"resource_id":"`+testConnectorID+`",`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "legacy storage resource id", body: strings.Replace(valid, testConnectorID, "r_legacy12345", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "padded resource id", body: strings.Replace(valid, testConnectorID, testConnectorID+"=", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "non-canonical resource id", body: strings.Replace(valid, testConnectorID, testConnectorID[:len(testConnectorID)-1]+"B", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "missing connector routing id", body: strings.Replace(valid, `"connector_routing_id":"`+testConnectorRoutingID+`",`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "short connector routing id", body: strings.Replace(valid, testConnectorRoutingID, testConnectorRoutingID[:len(testConnectorRoutingID)-1], 1), want: ErrInvalidConnectorResourceResponse},
		{name: "uppercase connector routing id", body: strings.Replace(valid, testConnectorRoutingID, "c-A"+testConnectorRoutingID[3:], 1), want: ErrInvalidConnectorResourceResponse},
		{name: "invalid connector routing alphabet", body: strings.Replace(valid, testConnectorRoutingID, "c-0"+testConnectorRoutingID[3:], 1), want: ErrInvalidConnectorResourceResponse},
		{name: "routing id cross-wired as public resource id", body: strings.Replace(valid, testConnectorID, testConnectorRoutingID, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "public resource id cross-wired as routing id", body: strings.Replace(valid, testConnectorRoutingID, testConnectorID, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "routing id cross-wired as knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`"`, `"knock_resource_id":"`+testConnectorRoutingID+`"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "public resource id cross-wired as knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`"`, `"knock_resource_id":"`+testConnectorID+`"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "missing knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`",`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "whitespace knock id", body: strings.Replace(valid, `"knock_resource_id":"`+testKnockID+`"`, `"knock_resource_id":" `+testKnockID+` "`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "wrong type", body: strings.Replace(valid, `"type":"tunnel"`, `"type":"url"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "unknown status", body: strings.Replace(valid, `"status":"active"`, `"status":"pending"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "wrong slug", body: strings.Replace(valid, `"slug":"`+testConnectorSlug+`"`, `"slug":"other-dashboard"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "invalid alias", body: strings.Replace(valid, `},"meta"`, `,"alias":"bad alias"},"meta"`, 1), want: ErrInvalidConnectorResourceResponse},
		{name: "missing found existing", body: strings.Replace(valid, `,"meta":{"found_existing":false}`, "", 1), want: ErrInvalidConnectorResourceResponse},
		{name: "detail envelope on create", body: fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}},"meta":{"found_existing":false}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug), want: ErrInvalidConnectorResourceResponse},
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
			if !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("invalid successful response lost ErrInvalidAPIResponse: %v", err)
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

	getByID := func(t *testing.T, body string) error {
		t.Helper()
		client := newConnectorTestClient(t, "http://localhost")
		client.httpClient = staticConnectorResponseDoer(http.StatusOK, body)
		_, err := client.GetConnectorResource(context.Background(), testConnectorID)
		return err
	}
	getBySlug := func(t *testing.T, body string) error {
		t.Helper()
		client := newConnectorTestClient(t, "http://localhost")
		client.httpClient = staticConnectorResponseDoer(http.StatusOK, body)
		_, err := client.GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
		return err
	}

	detail := fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"revoked","slug":%q}}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	if err := getByID(t, detail); !errors.Is(err, ErrConnectorResourceRevoked) || errors.Is(err, ErrInvalidConnectorResourceResponse) {
		t.Fatalf("detail revoked row = %v, want revoked", err)
	}

	invalidDetails := []struct {
		name string
		body string
	}{
		{name: "missing connector routing id", body: strings.Replace(detail, `"connector_routing_id":"`+testConnectorRoutingID+`",`, "", 1)},
		{name: "missing knock id", body: strings.Replace(detail, `"knock_resource_id":"`+testKnockID+`",`, "", 1)},
		{name: "routing id cross-wired as knock id", body: strings.Replace(detail, `"knock_resource_id":"`+testKnockID+`"`, `"knock_resource_id":"`+testConnectorRoutingID+`"`, 1)},
		{name: "invalid slug", body: strings.Replace(detail, testConnectorSlug, "Bad Slug", 1)},
		{name: "invalid alias", body: strings.Replace(detail, `"slug":"`+testConnectorSlug+`"`, `"slug":"`+testConnectorSlug+`","alias":"Bad Alias"`, 1)},
	}
	for _, tt := range invalidDetails {
		t.Run(tt.name, func(t *testing.T) {
			if err := getByID(t, tt.body); !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) || errors.Is(err, ErrConnectorResourceRevoked) {
				t.Fatalf("malformed revoked detail row = %v, want invalid response", err)
			}
		})
	}

	list := fmt.Sprintf(`{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"revoked","slug":%q}]}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug)
	if err := getBySlug(t, list); !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) || errors.Is(err, ErrConnectorResourceRevoked) {
		t.Fatalf("active-only slug revoked row = %v, want invalid response", err)
	}
}

func TestClient_GetConnectorResourceBySlugCardinality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        string
		want        error
		wantInvalid bool
	}{
		{name: "not found", data: `[]`, want: ErrConnectorResourceNotFound},
		{name: "null data", data: `null`, want: ErrInvalidConnectorResourceResponse, wantInvalid: true},
		{name: "ambiguous", data: fmt.Sprintf(`[{"resource_id":%q},{"resource_id":%q}]`, testConnectorID, testOtherConnectorID), want: ErrConnectorResourceAmbiguous, wantInvalid: true},
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
			if got := errors.Is(err, ErrInvalidAPIResponse); got != tt.wantInvalid {
				t.Fatalf("ErrInvalidAPIResponse = %t, want %t; error=%v", got, tt.wantInvalid, err)
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
	if !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) || errors.Is(err, ErrConnectorResourceNotFound) {
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
			body: fmt.Sprintf(`{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}`, testConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug),
		},
		{
			name: "mismatched id",
			body: fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q}}}`, testOtherConnectorID, testConnectorRoutingID, testKnockID, testConnectorSlug),
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
			if !errors.Is(err, ErrInvalidAPIResponse) || !errors.Is(err, ErrInvalidConnectorResourceResponse) {
				t.Fatalf("error = %v, want malformed detail", err)
			}
		})
	}
}

func TestClient_ConnectorResourceRejectsInvalidInputsWithoutNetwork(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := newConnectorTestClient(t, "http://localhost:1")
	client.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
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
	if err := client.DeleteConnectorResource(context.Background(), "r_legacy12345"); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("invalid delete id: %v", err)
	} else {
		assertNoConnectorMutationOutcome(t, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("network calls = %d, want 0", calls.Load())
	}
}

func TestConnectorSlugAndAliasGrammar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "minimum length", value: "a-b", want: true},
		{name: "maximum length", value: "a" + strings.Repeat("b", 62) + "c", want: true},
		{name: "empty", value: ""},
		{name: "below minimum", value: "ab"},
		{name: "above maximum", value: "a" + strings.Repeat("b", 63) + "c"},
		{name: "leading digit", value: "1bc"},
		{name: "leading hyphen", value: "-bc"},
		{name: "trailing hyphen", value: "ab-"},
		{name: "uppercase", value: "Abc"},
		{name: "underscore", value: "a_b"},
		{name: "space", value: "a b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := connectorSlugPattern.MatchString(tt.value); got != tt.want {
				t.Fatalf("connectorSlugPattern.MatchString(%q) = %t, want %t", tt.value, got, tt.want)
			}
			err := validateConnectorSlug(tt.value)
			if tt.want && err != nil {
				t.Fatalf("validateConnectorSlug(%q) = %v, want nil", tt.value, err)
			}
			if !tt.want && !errors.Is(err, ErrInvalidResourceRequest) {
				t.Fatalf("validateConnectorSlug(%q) = %v, want ErrInvalidResourceRequest", tt.value, err)
			}
		})
	}
}

func TestConnectorResourceIDContract(t *testing.T) {
	t.Parallel()

	wellSizedNonDER := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 91))
	offCurveP256DER := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7VDGkLaZfQLKvxScAKGCA1Y3p6jNG6d0f66a4Wib8NP8CRZJoEm1jRQej5f0aRzejaH5N7ChvQkiISohN2KVOQ"
	nonCanonical := testConnectorID[:len(testConnectorID)-1] + "B"
	standardBase64 := strings.Replace(testConnectorID, "_", "/", 1)

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "real P-256 public key", id: testConnectorID, want: true},
		{name: "other real P-256 public key", id: testOtherConnectorID, want: true},
		{name: "well-sized non-DER bytes", id: wellSizedNonDER},
		{name: "off-curve P-256 DER", id: offCurveP256DER},
		{name: "legacy storage id", id: "r_legacy12345"},
		{name: "empty", id: ""},
		{name: "padded", id: testConnectorID + "="},
		{name: "standard base64 alphabet", id: standardBase64},
		{name: "non-canonical trailing bits", id: nonCanonical},
		{name: "embedded carriage return", id: testConnectorID[:50] + "\r" + testConnectorID[50:]},
		{name: "embedded line feed", id: testConnectorID[:50] + "\n" + testConnectorID[50:]},
		{name: "trailing carriage return", id: testConnectorID + "\r"},
		{name: "trailing line feed", id: testConnectorID + "\n"},
		{name: "below decoded length", id: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, minConnectorResourcePublicKeyDERBytes-1))},
		{name: "above decoded length", id: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, maxConnectorResourcePublicKeyDERBytes+1))},
		{name: "invalid unpadded length", id: strings.Repeat("A", 109)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isValidConnectorResourceID(tt.id); got != tt.want {
				t.Fatalf("isValidConnectorResourceID() = %t, want %t", got, tt.want)
			}
			err := validateConnectorResourceID(tt.id)
			if tt.want && err != nil {
				t.Fatalf("validateConnectorResourceID() = %v, want nil", err)
			}
			if !tt.want && !errors.Is(err, ErrInvalidResourceRequest) {
				t.Fatalf("validateConnectorResourceID() = %v, want ErrInvalidResourceRequest", err)
			}
		})
	}
}

func TestConnectorRoutingIDContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "producer opaque routing id", id: testConnectorRoutingID, want: true},
		{name: "other valid routing id", id: "c-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbq", want: true},
		{name: "empty", id: ""},
		{name: "missing prefix", id: testConnectorRoutingID[2:]},
		{name: "wrong prefix", id: "r-" + testConnectorRoutingID[2:]},
		{name: "short", id: testConnectorRoutingID[:len(testConnectorRoutingID)-1]},
		{name: "long", id: testConnectorRoutingID + "a"},
		{name: "uppercase", id: "c-A" + testConnectorRoutingID[3:]},
		{name: "digit zero", id: "c-0" + testConnectorRoutingID[3:]},
		{name: "digit one", id: "c-1" + testConnectorRoutingID[3:]},
		{name: "digit eight", id: "c-8" + testConnectorRoutingID[3:]},
		{name: "hyphen in digest", id: "c--" + testConnectorRoutingID[3:]},
		{name: "leading whitespace", id: " " + testConnectorRoutingID},
		{name: "trailing newline", id: testConnectorRoutingID + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := connectorRoutingIDPattern.MatchString(tt.id); got != tt.want {
				t.Fatalf("connector routing ID validity = %t, want %t", got, tt.want)
			}
		})
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
			client.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
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
			client.httpClient = doerFunc(func(r *http.Request) (*http.Response, error) {
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
				httpClient: doerFunc(func(*http.Request) (*http.Response, error) {
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
	client.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
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
	client.httpClient = doerFunc(func(r *http.Request) (*http.Response, error) {
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
	return doerFunc(func(r *http.Request) (*http.Response, error) {
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

type errorReadCloser struct {
	err error
}

func (r *errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *errorReadCloser) Close() error             { return nil }
