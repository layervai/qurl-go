package qurl

import (
	"context"
	"encoding/json"
	"fmt"
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
