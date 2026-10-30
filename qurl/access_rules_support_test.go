package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestAccessRuleBridgeExactMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		if !registeredAgentResourceRouteAllowed(method, "/v1/me/access-rules") {
			t.Errorf("%s access-rule route denied", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		if registeredAgentResourceRouteAllowed(method, "/v1/me/access-rules") {
			t.Errorf("%s access-rule route allowed", method)
		}
	}
	for _, path := range []string{"/v1/me/access-rules/", "/v1/me/access-rules/x", "/v1/me/access_rules"} {
		if registeredAgentResourceRouteAllowed(http.MethodGet, path) {
			t.Errorf("near miss allowed: %s", path)
		}
	}
}

func TestEmailDomainPolicyValidationAndSnapshotFence(t *testing.T) {
	decode := func(raw string) ConsumerAccessPolicy {
		t.Helper()
		var p ConsumerAccessPolicy
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := decode(`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["Person@other.com"]}`)
	if err := p.validate(); err != nil {
		t.Fatalf("valid domain policy rejected: %v", err)
	}
	private := true
	different := decode(`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["Other@other.com"]}`)
	if consumerCreationPolicyConfirmed(&private, &different, &p, true) {
		t.Fatal("different mailbox exception confirmed")
	}
	for _, raw := range []string{
		`{"mode":"email_domain","version":1,"email_domain":"Example.com"}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a@OTHER.com"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a@other.com","a@other.com"]}`,
		`{"mode":"review","version":1,"email_domain":"example.com"}`,
		`{"mode":"contract","version":1,"contract_id":"contains spaces"}`,
	} {
		if err := decode(raw).validate(); err == nil {
			t.Errorf("unsafe policy accepted: %s", raw)
		}
	}
}

func TestUpdateConsumerAccessRejectsDifferentMailboxExceptions(t *testing.T) {
	policy := ConsumerAccessPolicy{Mode: "email_domain", Version: 2, EmailDomain: "example.com", AllowedEmails: []string{"Partner@other.com"}}
	for _, emails := range [][]string{{"Partner@other.com"}, {"Other@other.com"}, nil} {
		echoed := policy
		echoed.AllowedEmails = emails
		client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(*http.Request) (*http.Response, error) {
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "consumer_access": echoed}})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}
		err := client.UpdateConsumerAccess(context.Background(), testConnectorCRID, 1, policy)
		if same := len(emails) == 1 && emails[0] == "Partner@other.com"; same != (err == nil) {
			t.Fatalf("allowed_emails %v: %v", emails, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatalf("allowed_emails %v: %v", emails, err)
		}
	}
}

func TestAccessRuleBridgeRejectsQueriesAndSelectingOrigins(t *testing.T) {
	base, _ := url.Parse("https://api.example.test/prefix")
	for _, target := range []string{"https://api.example.test/prefix/v1/me/access-rules?cursor=x", "https://api.example.test/prefix/v1/me/access-rules?", "https://other.test/prefix/v1/me/access-rules", "https://api.example.test/v1/me/access-rules"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if validateRegisteredAgentResourceRequest(base, req) == nil {
			t.Errorf("unsafe route accepted: %s", target)
		}
	}
}

func ExampleConsumerAccessPolicy_Validate() {
	policy := ConsumerAccessPolicy{Mode: "email_domain", Version: 1, EmailDomain: "example.com", AllowedEmails: []string{"Partner@outside.example"}}
	fmt.Println(policy.Validate())
	// Output: <nil>
}
