package qurl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/crid"
)

// cridKeyMatchFixture returns a (CRID, matching DER key, non-matching DER
// key) triple from the released conformance artifact, so these tests bind
// the client surface to the same frozen contract the crid package proves
// itself against rather than to hand-rolled strings.
func cridKeyMatchFixture(t *testing.T) (heldCRID string, matchingDER, foreignDER []byte) {
	t.Helper()
	cf, err := conformance.CRIDV1()
	if err != nil {
		t.Fatalf("load conformance artifact: %v", err)
	}
	cases := make(map[string]conformance.CRIDV1KeyMatchCase, len(cf.KeyMatchCases))
	for _, kc := range cf.KeyMatchCases {
		cases[kc.Name] = kc
	}
	match, ok := cases["match_production"]
	if !ok {
		t.Fatal("artifact is missing the match_production key-match case")
	}
	mismatch, ok := cases["mismatch_wrong_key"]
	if !ok {
		t.Fatal("artifact is missing the mismatch_wrong_key key-match case")
	}
	if mismatch.CRID != match.CRID {
		t.Fatalf("fixture drift: mismatch_wrong_key holds %q, want %q", mismatch.CRID, match.CRID)
	}
	matchingDER, err = base64.RawURLEncoding.Strict().DecodeString(match.DERSPKIB64URL)
	if err != nil {
		t.Fatalf("decode matching key: %v", err)
	}
	foreignDER, err = base64.RawURLEncoding.Strict().DecodeString(mismatch.DERSPKIB64URL)
	if err != nil {
		t.Fatalf("decode foreign key: %v", err)
	}
	return match.CRID, matchingDER, foreignDER
}

func TestClient_ShareResource(t *testing.T) {
	heldCRID, _, _ := cridKeyMatchFixture(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer lv_test_123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/r_demo1234567/share" {
			t.Fatalf("request = %s %s, want POST /v1/resources/r_demo1234567/share", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode share body: %v", err)
		}
		assertJSONField(t, body, "ttl_seconds", float64(90))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"qurl":"https://qurl.link/at_demo123#qv2t1.1.1.1.AQ.AQ.AQ","qurl_id":"q_a1b2c3d4e5f","crid":%q,"type":"qv2","expires_at":"2026-08-13T20:10:00Z","expires_in_seconds":600,"single_use":true}}`, heldCRID)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	share, err := client.ShareResource(context.Background(), "r_demo1234567", &ShareResourceOptions{TTL: 90 * time.Second})
	if err != nil {
		t.Fatalf("ShareResource: %v", err)
	}
	if share.Link != "https://qurl.link/at_demo123#qv2t1.1.1.1.AQ.AQ.AQ" || share.CRID != heldCRID || share.Type != "qv2" {
		t.Fatalf("share = %#v", share)
	}
	// The revocation handle for this one link — without it the link is
	// unrevocable, since it is never retrievable again.
	if share.QURLID != "q_a1b2c3d4e5f" {
		t.Fatalf("QURLID = %q, want the minted link's id", share.QURLID)
	}
	if want := time.Date(2026, 8, 13, 20, 10, 0, 0, time.UTC); !share.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", share.ExpiresAt, want)
	}
	// The lifetime fields report the server's grant (600s here), never an
	// echo of the requested 90s TTL.
	if share.ExpiresInSeconds != 600 || !share.SingleUse {
		t.Fatalf("share lifetime = %#v", share)
	}
}

// TestClient_ShareResourceQURLIDRevokesTheMintedLink proves the composition
// the qurl_id field exists for: share mints a link and hands back its id,
// and that id spends verbatim at RevokePortal — the same revoke call a
// CreatePortal link uses, because the platform mints one kind of qURL. Before
// the id was on the wire a share link had no individual revocation handle at
// all (the link is shown once), so deleting the whole resource was the only
// lever.
func TestClient_ShareResourceQURLIDRevokesTheMintedLink(t *testing.T) {
	var revokes atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/resources/r_demo1234567/share":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{"qurl":"https://qurl.link/at_demo123#qv2t1.1.1.1.AQ.AQ.AQ","qurl_id":"q_a1b2c3d4e5f","type":"qv2","expires_in_seconds":300,"single_use":false}}`)
		case r.Method == http.MethodDelete:
			revokes.Add(1)
			// The share link's id lands in the qURL segment unaltered, under
			// the resource the caller shared.
			if want := "/v1/resources/r_demo1234567/qurls/q_a1b2c3d4e5f"; r.URL.Path != want {
				t.Errorf("revoke path = %q, want %q", r.URL.Path, want)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	share, err := client.ShareResource(context.Background(), "r_demo1234567", nil)
	if err != nil {
		t.Fatalf("ShareResource: %v", err)
	}
	if share.QURLID == "" {
		t.Fatal("share returned no QURLID — the minted link would be unrevocable")
	}
	if err := client.RevokePortal(context.Background(), "r_demo1234567", share.QURLID); err != nil {
		t.Fatalf("RevokePortal with the share link's id: %v", err)
	}
	if revokes.Load() != 1 {
		t.Fatalf("revoke requests = %d, want 1", revokes.Load())
	}
}

// TestClient_ShareResourceOmittedQURLIDIsEmpty pins the older-server
// posture: qurl_id is absent from servers predating the field, and that is an
// empty QURLID rather than a failed share. The field follows crid's additive
// posture, not qurl's fail-closed one — a caller that can still use the link
// should still get it, and only loses the revocation handle.
func TestClient_ShareResourceOmittedQURLIDIsEmpty(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"qurl":"https://qurl.link/at_old","type":"qv2","expires_in_seconds":300,"single_use":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	share, err := client.ShareResource(context.Background(), "r_demo1234567", nil)
	if err != nil {
		t.Fatalf("ShareResource against a server without qurl_id: %v", err)
	}
	if share.QURLID != "" {
		t.Fatalf("QURLID = %q, want empty when the API omits qurl_id", share.QURLID)
	}
	if share.Link != "https://qurl.link/at_old" {
		t.Fatalf("Link = %q, want the share to still succeed", share.Link)
	}
}

// TestClient_ShareResourceAcceptsCRIDIdentifier proves the dual-accepted
// addressing contract from the client side: a CRID travels the same {id}
// path segment as a public-key resource id, verbatim, and a nil options
// pointer sends an empty JSON body with no ttl_seconds key at all — zero is
// "server default", never an explicit 0.
func TestClient_ShareResourceAcceptsCRIDIdentifier(t *testing.T) {
	heldCRID, _, _ := cridKeyMatchFixture(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources/"+heldCRID+"/share" {
			t.Fatalf("request = %s %s, want POST /v1/resources/%s/share", r.Method, r.URL.Path, heldCRID)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode share body: %v", err)
		}
		if len(body) != 0 {
			t.Fatalf("share body = %#v, want an empty object with ttl_seconds omitted", body)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"qurl":"https://qurl.link/at_bycrid","crid":%q,"type":"qv2","expires_in_seconds":300,"single_use":false}}`, heldCRID)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test_123"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	share, err := client.ShareResource(context.Background(), heldCRID, nil)
	if err != nil {
		t.Fatalf("ShareResource by CRID: %v", err)
	}
	if share.Link != "https://qurl.link/at_bycrid" || share.SingleUse {
		t.Fatalf("share = %#v", share)
	}
	if !share.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %s, want zero when the API omits expires_at", share.ExpiresAt)
	}
}

// TestClient_ShareResourceZeroTTLOmitsField pins the options-struct half of
// the server-default rule: an explicit zero TTL omits ttl_seconds entirely —
// zero is "server default", never an explicit 0 on the wire.
func TestClient_ShareResourceZeroTTLOmitsField(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode share body: %v", err)
		}
		if _, ok := body["ttl_seconds"]; ok {
			t.Fatalf("share body = %#v, want ttl_seconds omitted so the server default applies", body)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"qurl":"https://qurl.link/at_default","type":"qv2","expires_in_seconds":300,"single_use":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "r_demo1234567", &ShareResourceOptions{TTL: 0}); err != nil {
		t.Fatalf("ShareResource with zero TTL: %v", err)
	}
}

func TestClient_ShareResourceAPIErrorPassthrough(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"resource_not_found","title":"Not Found","detail":"no resource for that identifier"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ShareResource(context.Background(), "r_missing1234", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound || apiErr.Code != "resource_not_found" {
		t.Fatalf("api error = %#v", apiErr)
	}
	if errors.Is(err, ErrTemporaryAccessLinksDisabled) {
		t.Fatalf("404 must not read as the dark-environment sentinel: %v", err)
	}
}

// TestClient_ShareResourceDarkEnvironment pins the one endpoint-specific
// mapping: a 503 means the environment is not serving temporary access
// links, and callers get a branchable sentinel without losing the *APIError.
func TestClient_ShareResourceDarkEnvironment(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"code":"temporary_access_links_disabled","title":"Service Unavailable","detail":"temporary access links are not enabled for this environment"}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ShareResource(context.Background(), "r_demo1234567", nil)
	if !errors.Is(err, ErrTemporaryAccessLinksDisabled) {
		t.Fatalf("want ErrTemporaryAccessLinksDisabled, got %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("dark-environment error must keep the *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("APIError status = %d, want %d", apiErr.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestClient_ShareResourceMissingQURLFailsClosed(t *testing.T) {
	heldCRID, _, _ := cridKeyMatchFixture(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"crid":%q,"type":"qv2","expires_in_seconds":600,"single_use":false}}`, heldCRID)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ShareResource(context.Background(), "r_demo1234567", nil)
	if !errors.Is(err, ErrInvalidAPIResponse) || !strings.Contains(err.Error(), "missing qurl") {
		t.Fatalf("want ErrInvalidAPIResponse with missing qurl detail, got %v", err)
	}
}

func TestClient_ShareResourceValidation(t *testing.T) {
	client, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "", nil); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("empty id: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "   ", nil); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("whitespace id: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "r_demo1234567", &ShareResourceOptions{TTL: -time.Second}); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("negative ttl: want ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "r_demo1234567", &ShareResourceOptions{TTL: 500 * time.Millisecond}); !errors.Is(err, ErrInvalidResourceRequest) || !strings.Contains(err.Error(), "whole seconds") {
		t.Fatalf("sub-second ttl: want whole-seconds ErrInvalidResourceRequest, got %v", err)
	}
	if _, err := client.ShareResource(context.Background(), "r_demo1234567", &ShareResourceOptions{TTL: 90*time.Second + 500*time.Millisecond}); !errors.Is(err, ErrInvalidResourceRequest) || !strings.Contains(err.Error(), "whole seconds") {
		t.Fatalf("fractional-second ttl: want whole-seconds ErrInvalidResourceRequest, got %v", err)
	}
	var nilClient *Client
	if _, err := nilClient.ShareResource(context.Background(), "r_demo1234567", nil); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil client: want ErrInvalidClientConfig, got %v", err)
	}
}

// TestClient_ResolveResourceDeprecatedAliasDelegatesToShare pins the
// compatibility shim for the one minor cycle it lives: the deprecated
// ResolveResource name and its ResolveResourceOptions / ResolvedAccess types
// are the share API under the old spelling, not a copy of it. A caller that
// has not renamed yet compiles unchanged and sends POST
// /v1/resources/{id}/share — never the retired /resolve suffix — so it needs
// a qurl-service that serves the share route.
func TestClient_ResolveResourceDeprecatedAliasDelegatesToShare(t *testing.T) {
	var paths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode share body: %v", err)
		}
		assertJSONField(t, body, "ttl_seconds", float64(90))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"qurl":"https://qurl.link/at_alias","qurl_id":"q_alias1234567","type":"qv2","expires_in_seconds":300,"single_use":false}}`)
	}))
	defer api.Close()

	client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	access, err := client.ResolveResource(context.Background(), "r_demo1234567", &ResolveResourceOptions{TTL: 90 * time.Second})
	if err != nil {
		t.Fatalf("ResolveResource (deprecated alias): %v", err)
	}
	if len(paths) != 1 || paths[0] != "POST /v1/resources/r_demo1234567/share" {
		t.Fatalf("deprecated alias sent %v, want exactly [POST /v1/resources/r_demo1234567/share]", paths)
	}
	// The old result type is the share type under another name: it feeds the
	// share-typed API directly, with no conversion.
	shareTyped := func(l *ShareLink) string { return l.QURLID }
	if got := shareTyped(access); got != "q_alias1234567" {
		t.Fatalf("QURLID through the alias = %q, want q_alias1234567", got)
	}
}

// TestShareLinkVerifyCRID drives the trust story end to end against the
// conformance fixtures: the committed key verifies, a well-formed foreign key
// is the detected substitution, and both no-CRID and locally invalid CRID
// responses fail closed with their own matchable classes.
func TestShareLinkVerifyCRID(t *testing.T) {
	heldCRID, matchingDER, foreignDER := cridKeyMatchFixture(t)

	share := &ShareLink{CRID: heldCRID}
	if err := share.VerifyCRID(matchingDER); err != nil {
		t.Fatalf("committed key must verify: %v", err)
	}

	err := share.VerifyCRID(foreignDER)
	if !errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("foreign key: want ErrCRIDMismatch, got %v", err)
	}

	if err := (&ShareLink{}).VerifyCRID(matchingDER); !errors.Is(err, ErrNoCRID) {
		t.Fatalf("no crid: want ErrNoCRID, got %v", err)
	}
	var nilShare *ShareLink
	if err := nilShare.VerifyCRID(matchingDER); !errors.Is(err, ErrNoCRID) {
		t.Fatalf("nil share link: want ErrNoCRID, got %v", err)
	}

	invalid := &ShareLink{CRID: "Not A CRID!"}
	err = invalid.VerifyCRID(matchingDER)
	if !errors.Is(err, crid.ErrCharset) {
		t.Fatalf("locally invalid crid: want crid.ErrCharset, got %v", err)
	}
	if errors.Is(err, ErrCRIDMismatch) {
		t.Fatalf("locally invalid crid must not read as a key mismatch: %v", err)
	}
}

// TestClient_ProtectURLCarriesOptionalCRID pins the additive Resource field:
// a server that returns crid populates it, and one that predates the field
// leaves it empty — with omitempty keeping persisted JSON byte-stable for
// pre-CRID resources.
func TestClient_ProtectURLCarriesOptionalCRID(t *testing.T) {
	heldCRID, _, _ := cridKeyMatchFixture(t)
	for _, tt := range []struct {
		name     string
		body     string
		wantCRID string
	}{
		{
			name:     "server returns crid",
			body:     fmt.Sprintf(`{"data":{"resource_id":"r_demo1234567","crid":%q,"target_url":"https://internal.example.com/dashboard","status":"active"}}`, heldCRID),
			wantCRID: heldCRID,
		},
		{
			name:     "older server omits crid",
			body:     `{"data":{"resource_id":"r_demo1234567","target_url":"https://internal.example.com/dashboard","status":"active"}}`,
			wantCRID: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.body)
			}))
			defer api.Close()

			client, err := NewClient(BearerToken("lv_test"), WithBaseURL(api.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			resource, err := client.ProtectURL(context.Background(), "https://internal.example.com/dashboard")
			if err != nil {
				t.Fatalf("ProtectURL: %v", err)
			}
			if resource.CRID != tt.wantCRID {
				t.Fatalf("resource CRID = %q, want %q", resource.CRID, tt.wantCRID)
			}

			raw, err := json.Marshal(resource)
			if err != nil {
				t.Fatalf("Marshal Resource: %v", err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("Unmarshal Resource JSON: %v", err)
			}
			if tt.wantCRID == "" {
				if _, ok := body["crid"]; ok {
					t.Fatalf("pre-CRID resource JSON grew a crid key: %s", raw)
				}
			} else {
				assertJSONField(t, body, "crid", tt.wantCRID)
			}
		})
	}
}
