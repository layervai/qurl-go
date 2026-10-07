package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const privacyTestTargetURL = "https://internal.example.com/app"

// privacyTestAPI answers the three calls that can create a resource and keeps
// the exact bytes each one sent.
type privacyTestAPI struct {
	t *testing.T
	// resourceMembers is spliced into every resource row the API returns, so a
	// test chooses what the service says about privacy and access requests.
	resourceMembers string
	bodies          []string
}

func (a *privacyTestAPI) Do(req *http.Request) (*http.Response, error) {
	a.t.Helper()
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	a.bodies = append(a.bodies, string(raw))

	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("request body is not JSON: %w", err)
	}
	status := http.StatusOK
	var body string
	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/v1/qurls":
		body = fmt.Sprintf(`{"data":{"resource_id":%q,"crid":%q,"qurl_link":"https://links.example.test/placeholder"}}`,
			testConnectorID, testConnectorCRID)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/resources" && probe.Type == producerConnectorResourceType:
		status = http.StatusCreated
		body = fmt.Sprintf(`{"data":{"resource_id":%q,"crid":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q%s},"meta":{"found_existing":false}}`,
			testConnectorID, testConnectorCRID, testConnectorRoutingID, testKnockID, testConnectorSlug, a.resourceMembers)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/resources":
		status = http.StatusCreated
		body = fmt.Sprintf(`{"data":{"resource_id":%q,"crid":%q,"target_url":%q,"status":"active"%s}}`,
			testConnectorID, testConnectorCRID, privacyTestTargetURL, a.resourceMembers)
	default:
		a.t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
		status, body = http.StatusNotFound, `{"error":{"code":"not_found"}}`
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func newPrivacyTestClient(t *testing.T, resourceMembers string) (*Client, *privacyTestAPI) {
	t.Helper()
	api := &privacyTestAPI{t: t, resourceMembers: resourceMembers}
	client, err := NewClient(BearerToken("lv_test_privacy"),
		WithBaseURL("https://api.example.test"), WithHTTPClient(api))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, api
}

// privacyCreateCalls is every call that can create a resource. legacyBody is
// the exact request each one sent before privacy could be stated, and must
// still send when it is not.
var privacyCreateCalls = []struct {
	name       string
	legacyBody string
	call       func(*Client, []ResourceCreateOption) error
}{
	{
		name:       "ProtectURL",
		legacyBody: `{"target_url":"https://internal.example.com/app","alias":"app"}`,
		call: func(c *Client, privacy []ResourceCreateOption) error {
			opts := []ResourceOption{WithAlias("app")}
			for _, opt := range privacy {
				opts = append(opts, opt)
			}
			_, err := c.ProtectURL(context.Background(), privacyTestTargetURL, opts...)
			return err
		},
	},
	{
		name:       "CreateResource",
		legacyBody: `{"target_url":"https://internal.example.com/app"}`,
		call: func(c *Client, privacy []ResourceCreateOption) error {
			var opts []ResourceOption
			for _, opt := range privacy {
				opts = append(opts, opt)
			}
			_, err := c.CreateResource(context.Background(), privacyTestTargetURL, opts...)
			return err
		},
	},
	{
		name:       "CreatePortalForURL",
		legacyBody: `{"target_url":"https://internal.example.com/app","expires_in":"1h","one_time_use":true}`,
		call: func(c *Client, privacy []ResourceCreateOption) error {
			opts := []PortalOption{ValidFor(time.Hour), OneTimeUse()}
			for _, opt := range privacy {
				opts = append(opts, opt)
			}
			_, _, err := c.CreatePortalForURL(context.Background(), privacyTestTargetURL, opts...)
			return err
		},
	},
	{
		name:       "EnsureConnectorResourceWithOptions",
		legacyBody: `{"type":"tunnel","slug":"prod-dashboard","find_or_create":true}`,
		call: func(c *Client, privacy []ResourceCreateOption) error {
			var opts []ConnectorResourceOption
			for _, opt := range privacy {
				opts = append(opts, opt)
			}
			_, err := c.EnsureConnectorResourceWithOptions(context.Background(), testConnectorSlug, opts...)
			return err
		},
	},
}

// A call that does not state privacy sends byte for byte what it sent before
// the option existed: no "private" member at all, so the service default
// applies.
func TestCreateCallsSendNoPrivacyUnlessStated(t *testing.T) {
	for _, create := range privacyCreateCalls {
		t.Run(create.name, func(t *testing.T) {
			client, api := newPrivacyTestClient(t, "")
			if err := create.call(client, nil); err != nil {
				t.Fatalf("%s: %v", create.name, err)
			}
			if len(api.bodies) != 1 {
				t.Fatalf("requests = %d, want 1", len(api.bodies))
			}
			if got := api.bodies[0]; got != create.legacyBody {
				t.Fatalf("request body = %s\nwant the unchanged body %s", got, create.legacyBody)
			}
		})
	}

	t.Run("EnsureConnectorResource", func(t *testing.T) {
		client, api := newPrivacyTestClient(t, "")
		if _, err := client.EnsureConnectorResource(context.Background(), testConnectorSlug); err != nil {
			t.Fatalf("EnsureConnectorResource: %v", err)
		}
		const want = `{"type":"tunnel","slug":"prod-dashboard","find_or_create":true}`
		if len(api.bodies) != 1 || api.bodies[0] != want {
			t.Fatalf("request bodies = %q, want exactly %s", api.bodies, want)
		}
	})
}

// Stating privacy sends exactly that value. A stated false is the case a
// plain omitempty boolean would drop, which would turn "make it public" into
// "take the default".
func TestCreateCallsSendStatedPrivacy(t *testing.T) {
	for _, create := range privacyCreateCalls {
		for _, private := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/private=%t", create.name, private), func(t *testing.T) {
				client, api := newPrivacyTestClient(t, "")
				if err := create.call(client, []ResourceCreateOption{WithPrivate(private)}); err != nil {
					t.Fatalf("%s: %v", create.name, err)
				}
				if len(api.bodies) != 1 {
					t.Fatalf("requests = %d, want 1", len(api.bodies))
				}

				var got, want map[string]any
				if err := json.Unmarshal([]byte(api.bodies[0]), &got); err != nil {
					t.Fatalf("decode request body %s: %v", api.bodies[0], err)
				}
				if err := json.Unmarshal([]byte(create.legacyBody), &want); err != nil {
					t.Fatal(err)
				}
				stated, present := got["private"]
				if !present {
					t.Fatalf("request body %s has no \"private\" member, want private: %t", api.bodies[0], private)
				}
				if stated != private {
					t.Fatalf("request body %s states private = %#v, want %t", api.bodies[0], stated, private)
				}
				// Nothing else about the request changes.
				delete(got, "private")
				if len(got) != len(want) {
					t.Fatalf("request body %s has members beyond %s and private", api.bodies[0], create.legacyBody)
				}
				for key, value := range want {
					if got[key] != value {
						t.Fatalf("request body %s changed %q from %#v", api.bodies[0], key, value)
					}
				}
			})
		}
	}
}

// Privacy is security-relevant, so an option list that states both values is
// refused before any request rather than resolved by position. The same value
// twice is one statement.
func TestCreateCallsRefuseContradictoryPrivacy(t *testing.T) {
	wantKind := map[string]error{
		"ProtectURL":                         ErrInvalidResourceRequest,
		"CreateResource":                     ErrInvalidResourceRequest,
		"CreatePortalForURL":                 ErrInvalidPortalRequest,
		"EnsureConnectorResourceWithOptions": ErrInvalidResourceRequest,
	}
	for _, create := range privacyCreateCalls {
		t.Run(create.name, func(t *testing.T) {
			for _, order := range [][]bool{{true, false}, {false, true}, {true, true, false}} {
				client, api := newPrivacyTestClient(t, "")
				var opts []ResourceCreateOption
				for _, private := range order {
					opts = append(opts, WithPrivate(private))
				}
				err := create.call(client, opts)
				if !errors.Is(err, wantKind[create.name]) {
					t.Errorf("privacy stated as %v: error = %v, want %v", order, err, wantKind[create.name])
				}
				if len(api.bodies) != 0 {
					t.Errorf("privacy stated as %v reached the API: %q", order, api.bodies)
				}
			}
			for _, private := range []bool{true, false} {
				client, api := newPrivacyTestClient(t, "")
				if err := create.call(client, []ResourceCreateOption{WithPrivate(private), WithPrivate(private)}); err != nil {
					t.Errorf("private=%t stated twice: %v", private, err)
				}
				if len(api.bodies) != 1 || !strings.Contains(api.bodies[0], fmt.Sprintf(`"private":%t`, private)) {
					t.Errorf("private=%t stated twice sent %q", private, api.bodies)
				}
			}
		})
	}
}

// Minting a link for a resource that already exists cannot choose its privacy.
// Every path to that call refuses the option and sends nothing.
func TestCreatePortalRefusesPrivacyForAnExistingResource(t *testing.T) {
	for _, private := range []bool{true, false} {
		client, api := newPrivacyTestClient(t, "")
		resource := client.ResourceByCRID(testConnectorCRID)
		connector := &ConnectorResource{client: client, CRID: testConnectorCRID}

		calls := map[string]func() error{
			"Client.CreatePortal": func() error {
				_, err := client.CreatePortal(context.Background(), resource, ValidFor(time.Hour), WithPrivate(private))
				return err
			},
			"Resource.CreatePortal": func() error {
				_, err := resource.CreatePortal(context.Background(), WithPrivate(private))
				return err
			},
			"ConnectorResource.CreatePortal": func() error {
				_, err := connector.CreatePortal(context.Background(), WithPrivate(private), WithLabel("Alice"))
				return err
			},
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, ErrInvalidPortalRequest) {
				t.Errorf("%s with private=%t: error = %v, want ErrInvalidPortalRequest", name, private, err)
			}
		}
		if len(api.bodies) != 0 {
			t.Errorf("a refused option reached the API: %q", api.bodies)
		}
	}
}

func TestEnsureConnectorResourceWithOptionsRejectsNilOption(t *testing.T) {
	client, api := newPrivacyTestClient(t, "")
	_, err := client.EnsureConnectorResourceWithOptions(context.Background(), testConnectorSlug, nil)
	if !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("nil option: error = %v, want ErrInvalidResourceRequest", err)
	}
	if len(api.bodies) != 0 {
		t.Fatalf("a nil option reached the API: %q", api.bodies)
	}

	var nilClient *Client
	if _, err := nilClient.EnsureConnectorResourceWithOptions(context.Background(), testConnectorSlug, WithPrivate(true)); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil client: error = %v, want ErrInvalidClientConfig", err)
	}
}

// privacyReadCases are what a service can say about the two members, and what
// the SDK must report for each. "Did not say" stays nil; it is never turned
// into false, and never into true.
var privacyReadCases = []struct {
	name               string
	members            string
	wantPrivate        *bool
	wantAccessRequests *bool
}{
	{name: "neither member"},
	{name: "private, requests off", members: `,"private":true,"access_requests":false`, wantPrivate: reported(true), wantAccessRequests: reported(false)},
	{name: "private, requests on", members: `,"private":true,"access_requests":true`, wantPrivate: reported(true), wantAccessRequests: reported(true)},
	{name: "public", members: `,"private":false,"access_requests":false`, wantPrivate: reported(false), wantAccessRequests: reported(false)},
	{name: "only privacy", members: `,"private":false`, wantPrivate: reported(false)},
	{name: "only access requests", members: `,"access_requests":true`, wantAccessRequests: reported(true)},
	{name: "explicit nulls", members: `,"private":null,"access_requests":null`},
}

// reported is a value the service stated, as opposed to nil for one it did not.
func reported(value bool) *bool { return &value }

func assertTriState(t *testing.T, what string, got, want *bool) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s = not reported, want %t", what, *want)
	case want == nil:
		t.Errorf("%s = %t, want not reported", what, *got)
	case *got != *want:
		t.Errorf("%s = %t, want %t", what, *got, *want)
	}
}

// assertTriStateJSON checks the stored form: a reported value is written, a
// reported false included, and an unreported one is left out.
func assertTriStateJSON(t *testing.T, value any, private, accessRequests *bool) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]*bool{"private": private, "access_requests": accessRequests} {
		got, present := stored[key]
		switch {
		case want == nil && present:
			t.Errorf("stored JSON %s has %q, want it left out when the service did not say", raw, key)
		case want != nil && !present:
			t.Errorf("stored JSON %s lost %q = %t", raw, key, *want)
		case want != nil && got != *want:
			t.Errorf("stored JSON %s has %q = %#v, want %t", raw, key, got, *want)
		}
	}
}

func TestProtectURLReportsPrivacyAndAccessRequests(t *testing.T) {
	for _, test := range privacyReadCases {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPrivacyTestClient(t, test.members)
			resource, err := client.ProtectURL(context.Background(), privacyTestTargetURL)
			if err != nil {
				t.Fatalf("ProtectURL: %v", err)
			}
			assertTriState(t, "Resource.Private", resource.Private, test.wantPrivate)
			assertTriState(t, "Resource.AccessRequests", resource.AccessRequests, test.wantAccessRequests)
			assertTriStateJSON(t, resource, test.wantPrivate, test.wantAccessRequests)

			// A stored handle reads back with the same three states.
			raw, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			var restored Resource
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			assertTriState(t, "restored Resource.Private", restored.Private, test.wantPrivate)
			assertTriState(t, "restored Resource.AccessRequests", restored.AccessRequests, test.wantAccessRequests)
		})
	}
}

func TestConnectorResourceReportsPrivacyAndAccessRequests(t *testing.T) {
	row := func(members string) string {
		return fmt.Sprintf(`{"resource_id":%q,"crid":%q,"connector_routing_id":%q,"knock_resource_id":%q,"type":"tunnel","status":"active","slug":%q%s}`,
			testConnectorID, testConnectorCRID, testConnectorRoutingID, testKnockID, testConnectorSlug, members)
	}
	reads := []struct {
		name string
		// respond builds the status and body of the one endpoint the read uses.
		respond func(members string) (int, string)
		read    func(*Client) (*ConnectorResource, error)
	}{
		{
			name: "EnsureConnectorResource",
			respond: func(members string) (int, string) {
				return http.StatusCreated, `{"data":` + row(members) + `,"meta":{"found_existing":true}}`
			},
			read: func(c *Client) (*ConnectorResource, error) {
				result, err := c.EnsureConnectorResource(context.Background(), testConnectorSlug)
				if err != nil {
					return nil, err
				}
				return result.Resource, nil
			},
		},
		{
			name: "EnsureConnectorResourceWithOptions",
			respond: func(members string) (int, string) {
				return http.StatusCreated, `{"data":` + row(members) + `,"meta":{"found_existing":false}}`
			},
			read: func(c *Client) (*ConnectorResource, error) {
				result, err := c.EnsureConnectorResourceWithOptions(context.Background(), testConnectorSlug)
				if err != nil {
					return nil, err
				}
				return result.Resource, nil
			},
		},
		{
			name: "GetConnectorResource",
			respond: func(members string) (int, string) {
				return http.StatusOK, `{"data":{"resource":` + row(members) + `,"qurls":[]}}`
			},
			read: func(c *Client) (*ConnectorResource, error) {
				return c.GetConnectorResource(context.Background(), testConnectorCRID)
			},
		},
		{
			name: "GetConnectorResourceBySlug",
			respond: func(members string) (int, string) {
				return http.StatusOK, `{"data":[` + row(members) + `]}`
			},
			read: func(c *Client) (*ConnectorResource, error) {
				return c.GetConnectorResourceBySlug(context.Background(), testConnectorSlug)
			},
		},
	}
	for _, read := range reads {
		for _, test := range privacyReadCases {
			t.Run(read.name+"/"+test.name, func(t *testing.T) {
				status, body := read.respond(test.members)
				client, err := NewClient(BearerToken(testDeviceToken),
					WithBaseURL("https://api.example.test"), WithHTTPClient(staticConnectorResponseDoer(status, body)))
				if err != nil {
					t.Fatal(err)
				}
				resource, err := read.read(client)
				if err != nil {
					t.Fatalf("%s: %v", read.name, err)
				}
				assertTriState(t, "ConnectorResource.Private", resource.Private, test.wantPrivate)
				assertTriState(t, "ConnectorResource.AccessRequests", resource.AccessRequests, test.wantAccessRequests)
				assertTriStateJSON(t, resource, test.wantPrivate, test.wantAccessRequests)
			})
		}
	}
}

// The answer to the one-call create does not report privacy. The handle it
// returns says so with nil, whatever the caller stated: the SDK reports what
// the service said, not what was asked for.
func TestCreatePortalForURLLeavesPrivacyUnreported(t *testing.T) {
	for _, opts := range [][]PortalOption{nil, {WithPrivate(true)}, {WithPrivate(false)}} {
		client, _ := newPrivacyTestClient(t, "")
		_, resource, err := client.CreatePortalForURL(context.Background(), privacyTestTargetURL, opts...)
		if err != nil {
			t.Fatalf("CreatePortalForURL: %v", err)
		}
		if resource.Private != nil || resource.AccessRequests != nil {
			t.Fatalf("resource reports private=%v access_requests=%v, want both unreported", resource.Private, resource.AccessRequests)
		}
	}
	if resource := (&Client{}).ResourceByCRID(testConnectorCRID); resource.Private != nil || resource.AccessRequests != nil {
		t.Fatal("a handle built from a stored CRID reports privacy it never read")
	}
}

// A member of the wrong type is a broken answer, not "false" and not "did not
// say". It fails closed like every other malformed success.
func TestResourcePrivacyMembersMustBeBooleans(t *testing.T) {
	for _, members := range []string{
		`,"private":"true"`, `,"private":1`, `,"private":{}`,
		`,"access_requests":"false"`, `,"access_requests":0`, `,"access_requests":[]`,
	} {
		t.Run(members, func(t *testing.T) {
			client, _ := newPrivacyTestClient(t, members)
			if resource, err := client.ProtectURL(context.Background(), privacyTestTargetURL); !errors.Is(err, ErrInvalidAPIResponse) {
				t.Errorf("ProtectURL = %#v, %v; want ErrInvalidAPIResponse", resource, err)
			}
			result, err := client.EnsureConnectorResourceWithOptions(context.Background(), testConnectorSlug)
			if !errors.Is(err, ErrInvalidConnectorResourceResponse) || !errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
				t.Errorf("EnsureConnectorResourceWithOptions = %#v, %v; want an invalid response with an unknown outcome", result, err)
			}
		})
	}
}
