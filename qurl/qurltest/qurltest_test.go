package qurltest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/testkeys"
	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/qurl/qurltest"
)

// These tests use the double the way a consumer does: through the exported
// qurl calls, with the Config the double hands out. What they hold is that the
// double answers, and that the SDK still decides.

// refusals is the SDK's error for each refusal code of a CRID link request.
var refusals = map[string]error{
	"52601": qurl.ErrCRIDLinkUnavailable,
	"52602": qurl.ErrCRIDLinkNotFound,
	"52603": qurl.ErrCRIDLinkRateLimited,
	"52604": qurl.ErrCRIDResourceOffline,
	"52605": qurl.ErrCRIDResourceClosed,
	"52606": qurl.ErrInvalidCRIDLinkRequest,
}

func loadVectors(t *testing.T) *conformance.CRIDLinkKnockV1File {
	t.Helper()
	vectors, err := conformance.CRIDLinkKnockV1()
	if err != nil {
		t.Fatalf("the CRID link knock artifact must load: %v", err)
	}
	return vectors
}

func TestCRIDLinkServer_IssuesALinkTheSDKAccepts(t *testing.T) {
	vectors := loadVectors(t)
	server := qurltest.NewCRIDLinkServer()
	if server.CRID() != vectors.Fixtures.CRID {
		t.Fatalf("CRID() = %q, the artifact's fixture CRID is %q", server.CRID(), vectors.Fixtures.CRID)
	}
	cfg := server.Config()

	issued, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), cfg)
	if err != nil {
		t.Fatalf("RequestCRIDLinkWith: %v", err)
	}
	// The link is the public fixture link, not one made for this package.
	if issued.Link != vectors.Fixtures.Link {
		t.Fatal("the issued link is not the artifact's fixture link")
	}
	// The opener's own verification accepts it for the CRID, under the same
	// trust store. Requesting a link and opening one are the same decision.
	if _, err := qurl.VerifyLinkForCRID(issued.Link, server.CRID(), cfg.TrustStore); err != nil {
		t.Fatalf("the issued link does not verify for the CRID: %v", err)
	}
	// The display metadata is what the artifact declares for this reply.
	var want *conformance.CRIDLinkKnockV1LinkInfo
	for _, c := range vectors.ACKCases {
		if c.Name == "link_issued" {
			want = c.Expected.Info
		}
	}
	if want == nil || want.Publisher.Name == "" {
		t.Fatal("the artifact declares no metadata for its link_issued reply")
	}
	if issued.Publisher.Name != want.Publisher.Name || issued.Publisher.Verified || issued.QURLID != want.QURLID ||
		issued.ExpiresAt.IsZero() || issued.ResourceCreatedAt == nil {
		t.Fatalf("issued = %v, want the artifact's metadata %+v", issued, *want)
	}

	if got := server.Requests(); !slices.Equal(got, []qurltest.CRIDLinkRequest{{CRID: server.CRID()}}) {
		t.Fatalf("Requests() = %+v, want one request for the CRID with no user agent", got)
	}
}

func TestCRIDLinkServer_AnswersEachRefusalCode(t *testing.T) {
	vectors := loadVectors(t)
	// The table above is every refusal the contract defines. If the artifact
	// gains or loses a code, this test has to change with it.
	var declared []string
	for code := range vectors.ErrorCodes {
		if code != conformance.CRIDLinkKnockV1CodeLinkIssued {
			declared = append(declared, code)
		}
	}
	slices.Sort(declared)
	known := make([]string, 0, len(refusals))
	for code := range refusals {
		known = append(known, code)
	}
	slices.Sort(known)
	if !slices.Equal(known, declared) {
		t.Fatalf("this test knows the refusal codes %v, the artifact declares %v", known, declared)
	}

	server := qurltest.NewCRIDLinkServer()
	for _, code := range known {
		t.Run(code, func(t *testing.T) {
			server.Refuse(code)
			issued, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), server.Config())
			if issued != nil {
				t.Fatal("a refusal returned a link")
			}
			for otherCode, sentinel := range refusals {
				if got, want := errors.Is(err, sentinel), otherCode == code; got != want {
					t.Fatalf("code %s: error %v matches the error for %s = %t, want %t", code, err, otherCode, got, want)
				}
			}
			var deny *qurl.ServerDenyError
			if !errors.As(err, &deny) || deny.ErrCode != code {
				t.Fatalf("code %s is not a *qurl.ServerDenyError carrying its code: %v", code, err)
			}
		})
	}

	// Any other decimal code is answered too. The SDK reports it as a generic
	// deny that carries the code and matches none of the six.
	for _, code := range []string{"51002", "52607", "1"} {
		t.Run(code, func(t *testing.T) {
			server.Refuse(code)
			issued, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), server.Config())
			var deny *qurl.ServerDenyError
			if issued != nil || !errors.As(err, &deny) || deny.ErrCode != code {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want a *qurl.ServerDenyError carrying %q", issued, err, code)
			}
			for refusal, sentinel := range refusals {
				if errors.Is(err, sentinel) {
					t.Fatalf("code %s matches the error for %s", code, refusal)
				}
			}
		})
	}

	// Issue ends the refusal.
	server.Issue()
	if _, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), server.Config()); err != nil {
		t.Fatalf("after Issue: %v", err)
	}
}

// By default the server holds one resource. Another CRID gets the answer a
// server gives for a CRID it does not know, and never the fixture link.
func TestCRIDLinkServer_AnotherCRIDIsNotFound(t *testing.T) {
	vectors := loadVectors(t)
	server := qurltest.NewCRIDLinkServer()
	for name, other := range map[string]string{
		"a CRID of another key":                vectors.Fixtures.UnrelatedCRID,
		"the same key in the test environment": vectors.Fixtures.TestEnvironmentCRID,
	} {
		issued, err := qurl.RequestCRIDLinkWith(t.Context(), other, server.Config())
		if issued != nil || !errors.Is(err, qurl.ErrCRIDLinkNotFound) {
			t.Fatalf("%s: RequestCRIDLinkWith = %v, %v; want ErrCRIDLinkNotFound", name, issued, err)
		}
	}
	if got := len(server.Requests()); got != 2 {
		t.Fatalf("the server saw %d requests, want 2", got)
	}
}

// The double cannot turn a check off, and it has nothing to turn one off with.
// The link is accepted only because the configuration is the one it verifies
// under. Change what the SDK holds, and the SDK rejects the same reply.
func TestCRIDLinkServer_DoesNotWeakenVerification(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	issuerKID := server.Deployment().Issuers[0].Kid
	trust := func(kid string) *qurl.TrustStore {
		store, err := qurl.NewTrustStoreFromDER(map[string][]byte{kid: testkeys.P256SPKI()})
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	for _, tc := range []struct {
		name  string
		edit  func(cfg *qurl.Config)
		class qurl.CRIDLinkRejectClass
		also  error
	}{
		{
			"the link is on another origin than the one configured",
			func(cfg *qurl.Config) { cfg.CRIDLink.LinkOrigin = "https://links.example.com" },
			qurl.CRIDLinkRejectOrigin, nil,
		},
		{
			"the trust store does not know the issuer",
			func(cfg *qurl.Config) { cfg.TrustStore = trust("another-issuer") },
			qurl.CRIDLinkRejectIssuerSignature, qurl.ErrUnknownKID,
		},
		{
			"the trust store holds another key under the issuer's id",
			func(cfg *qurl.Config) { cfg.TrustStore = trust(issuerKID) },
			qurl.CRIDLinkRejectIssuerSignature, qurl.ErrSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := server.Config()
			tc.edit(&cfg)
			issued, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), cfg)
			var rejected *qurl.CRIDLinkRejectedError
			if issued != nil || !errors.As(err, &rejected) || !errors.Is(err, qurl.ErrCRIDLinkRejected) {
				t.Fatalf("RequestCRIDLinkWith = %v, %v; want the link rejected", issued, err)
			}
			if rejected.Class != tc.class {
				t.Fatalf("rejected by the %q check, want %q", rejected.Class, tc.class)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Fatalf("error = %v, want it to match %v too", err, tc.also)
			}
		})
	}

	// The whole exported surface. A method that changed what the SDK checks
	// would have to be added here first, where a reviewer sees it.
	var methods []string
	surface := reflect.TypeFor[*qurltest.CRIDLinkServer]()
	for i := range surface.NumMethod() {
		methods = append(methods, surface.Method(i).Name)
	}
	if want := []string{"CRID", "Client", "Config", "Deployment", "Issue", "Refuse", "Requests", "RoundTrip"}; !slices.Equal(methods, want) {
		t.Fatalf("CRIDLinkServer methods = %v, want %v", methods, want)
	}
}

// Deployment is the same configuration as a file. Code that resolves its
// configuration from QURL_DEPLOYMENT reaches the server through it.
func TestCRIDLinkServer_Deployment(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	raw, err := json.Marshal(server.Deployment())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := qurl.LoadDeployment(path); err != nil {
		t.Fatalf("the deployment does not decode: %v", err)
	}
	t.Setenv(qurl.EnvDeploymentPath, path)

	// The file offers the request, and says so without one being sent.
	if err := qurl.CheckCRIDLinkConfig(); err != nil {
		t.Fatalf("CheckCRIDLinkConfig() = %v, want a request that can be sent", err)
	}
	if got := len(server.Requests()); got != 0 {
		t.Fatalf("checking the configuration sent %d requests", got)
	}

	// The one-argument call uses the default HTTP client. For this test that
	// is the server. This test must not run in parallel with another one.
	prior := http.DefaultTransport
	http.DefaultTransport = server
	t.Cleanup(func() { http.DefaultTransport = prior })

	issued, err := qurl.RequestCRIDLink(t.Context(), server.CRID())
	if err != nil {
		t.Fatalf("RequestCRIDLink: %v", err)
	}
	if _, err := qurl.VerifyLinkForCRID(issued.Link, server.CRID(), server.Config().TrustStore); err != nil {
		t.Fatalf("the issued link does not verify for the CRID: %v", err)
	}
	if got := len(server.Requests()); got != 1 {
		t.Fatalf("the server saw %d requests, want 1", got)
	}
}

// The server answers the link request only. The link names a cell of the
// vectors, so an open by CRID gets the link and then stops before it sends
// anything else.
func TestCRIDLinkServer_OpenStopsAfterTheLink(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	handle, err := qurl.OpenCRIDWith(t.Context(), server.CRID(), server.Config())
	if handle != nil || !errors.Is(err, qurl.ErrCellNotInCatalog) {
		t.Fatalf("OpenCRIDWith = %v, %v; want ErrCellNotInCatalog after the link", handle, err)
	}
	if got := len(server.Requests()); got != 1 {
		t.Fatalf("the server saw %d requests, want the one link request", got)
	}
}

func TestCRIDLinkServer_RecordsWhatWasSent(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	for _, userAgent := range []string{"example-tool/1.2", "", "example-tool\t1.2"} {
		cfg := server.Config()
		cfg.CRIDLink.UserAgent = userAgent
		if _, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), cfg); err != nil {
			t.Fatalf("user agent %q: %v", userAgent, err)
		}
	}
	// The last value holds a tab, so the SDK sends no user agent for it.
	want := []qurltest.CRIDLinkRequest{
		{CRID: server.CRID(), UserAgent: "example-tool/1.2"}, {CRID: server.CRID()}, {CRID: server.CRID()},
	}
	if got := server.Requests(); !slices.Equal(got, want) {
		t.Fatalf("Requests() = %+v\nwant         %+v", got, want)
	}

	// Config returns a fresh value each time: setting a user agent on one does
	// not reach the next.
	if got := server.Config().CRIDLink.UserAgent; got != "" {
		t.Fatalf("a later Config carries the user agent %q of an earlier one", got)
	}
}

// What is not a request to this server gets an HTTP error, as from a relay,
// and is not recorded. The SDK reports it as a relay fault.
func TestCRIDLinkServer_RefusesWhatIsNotItsRequest(t *testing.T) {
	server, other := qurltest.NewCRIDLinkServer(), qurltest.NewCRIDLinkServer()

	// A request sealed to another server's key, sent to this one.
	cfg := other.Config()
	cfg.HTTPClient = server.Client()
	_, err := qurl.RequestCRIDLinkWith(t.Context(), other.CRID(), cfg)
	var relayErr *qurl.RelayError
	if !errors.As(err, &relayErr) || relayErr.Status != http.StatusNotFound {
		t.Fatalf("a request for another server = %v, want a relay fault with status 404", err)
	}

	// Any other HTTP request through the client.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET through the client = %d, want 404", resp.StatusCode)
	}

	// A caller that has already given up.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config()); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled request = %v, want context.Canceled", err)
	}

	if got := len(server.Requests()) + len(other.Requests()); got != 0 {
		t.Fatalf("%d requests were recorded, want none", got)
	}
}

func TestCRIDLinkServer_RefusePanicsOnWhatIsNotARefusal(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	for _, code := range []string{"", "0", "00", "052601", "52600", " 52601", "52601 ", "-1", "not found", "5260a"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Refuse(%q) did not panic", code)
				}
			}()
			server.Refuse(code)
		}()
	}
	// None of them took effect.
	if _, err := qurl.RequestCRIDLinkWith(t.Context(), server.CRID(), server.Config()); err != nil {
		t.Fatalf("a refused Refuse changed the answer: %v", err)
	}
}

func TestCRIDLinkServer_ConcurrentUse(t *testing.T) {
	server := qurltest.NewCRIDLinkServer()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Go(func() {
			if i%2 == 0 {
				server.Issue()
			}
			_, errs[i] = qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config())
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := len(server.Requests()); got != callers {
		t.Fatalf("the server recorded %d requests, want %d", got, callers)
	}
}
