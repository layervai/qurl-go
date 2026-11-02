package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConsumerPolicyRejectsUnknownModesAndPrivacyConflicts(t *testing.T) {
	for _, policy := range []ConsumerAccessPolicy{{Mode: "unknown", Version: 1}, {Mode: "review", Version: 0}, {Mode: "review", Version: 2}, {Mode: "contract", Version: 1}, {Mode: "review", Version: 1, ContractID: "unexpected"}} {
		var cfg resourceOptions
		if err := WithConsumerAccess(policy).applyResourceOption(&cfg); !errors.Is(err, ErrInvalidResourceRequest) {
			t.Fatalf("invalid policy accepted: %v", err)
		}
	}
	for _, firstPrivate := range []bool{false, true} {
		var cfg resourceOptions
		if firstPrivate {
			if err := WithPrivate(false).applyResourceOption(&cfg); err != nil {
				t.Fatal(err)
			}
			if err := WithConsumerAccess(ConsumerAccessPolicy{Mode: "review", Version: 1}).applyResourceOption(&cfg); !errors.Is(err, ErrInvalidResourceRequest) {
				t.Fatal("public then policy must fail")
			}
		} else {
			if err := WithConsumerAccess(ConsumerAccessPolicy{Mode: "review", Version: 1}).applyResourceOption(&cfg); err != nil {
				t.Fatal(err)
			}
			if err := WithPrivate(false).applyResourceOption(&cfg); !errors.Is(err, ErrInvalidResourceRequest) {
				t.Fatal("policy then public must fail")
			}
		}
	}
}

func TestConsumerManagementUsesScopeVersionAndRejectsEmptyDecision(t *testing.T) {
	calls := 0
	client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != "/v1/resources/"+testConnectorCRID+"/consumer-grants/"+strings.Repeat("a", 64)+"/approve" {
			t.Fatalf("wrong scoped request %s %s", req.Method, req.URL.Path)
		}
		var body ConsumerGrantApproval
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.ExpectedVersion != 3 || body.CredentialID != "" || body.EntitlementID != "" {
			t.Fatalf("unexpected review body: %+v", body)
		}
		raw := `{"data":{"id":"` + strings.Repeat("a", 64) + `","status":"active","version":4}}`
		if calls == 2 {
			raw = `{"data":null}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw))}, nil
	})}
	grant, err := client.ApproveConsumerGrant(context.Background(), testConnectorCRID, strings.Repeat("a", 64), ConsumerGrantApproval{ExpectedVersion: 3})
	if err != nil || grant.Version != 4 {
		t.Fatalf("approval: %+v %v", grant, err)
	}
	grant, err = client.ApproveConsumerGrant(context.Background(), testConnectorCRID, strings.Repeat("a", 64), ConsumerGrantApproval{ExpectedVersion: 3})
	if grant != nil || !errors.Is(err, ErrInvalidAPIResponse) {
		t.Fatalf("empty decision accepted: %+v %v", grant, err)
	}
}

func TestApproveConsumerGrantSendsApprovalExpiry(t *testing.T) {
	expiresAt := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		expiry *time.Time
		want   string
	}{{&expiresAt, `"expires_at":"2026-11-06T12:00:00Z"`}, {nil, ""}} {
		client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if test.want != "" && !strings.Contains(string(raw), test.want) || test.want == "" && strings.Contains(string(raw), "expires_at") {
				t.Fatalf("approval body %s, want expiry %q", raw, test.want)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"id":"new-grant","status":"active","version":1,"expires_at":"2026-11-06T12:00:00Z"}}`))}, nil
		})}
		grant, err := client.ApproveConsumerGrant(context.Background(), testConnectorCRID, "new", ConsumerGrantApproval{CredentialKind: "device", CredentialID: "d", CredentialPublicKey: "k", ExpiresAt: test.expiry})
		if err != nil || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(expiresAt) {
			t.Fatalf("approval: %+v %v", grant, err)
		}
	}
}

func TestUpdateConsumerPolicyAcceptsFlatResourceAndRejectsMismatch(t *testing.T) {
	policy := ConsumerAccessPolicy{Mode: "review", Version: 2}
	for _, mode := range []string{"review", "keys"} {
		client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPatch || req.URL.Path != "/v1/resources/"+testConnectorCRID {
				t.Fatal("wrong policy route")
			}
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "consumer_access": ConsumerAccessPolicy{Mode: mode, Version: 2}}})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		})}
		err := client.UpdateConsumerAccess(context.Background(), testConnectorCRID, 1, policy)
		if mode == "review" && err != nil {
			t.Fatal(err)
		}
		if mode != "review" && !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatalf("mismatched policy accepted: %v", err)
		}
	}
}

func TestConsumerCreationConfirmsPrivatePolicyAndKeepsExistingRevision(t *testing.T) {
	for _, connector := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			policy   *ConsumerAccessPolicy
			private  bool
			existing bool
			ok       bool
		}{
			{"new", &ConsumerAccessPolicy{Mode: "review", Version: 1}, true, false, true},
			{"unsupported", nil, true, false, false},
			{"existing", &ConsumerAccessPolicy{Mode: "review", Version: 3}, true, true, true},
			{"new_wrong_revision", &ConsumerAccessPolicy{Mode: "review", Version: 3}, true, false, false},
			{"changed_mode", &ConsumerAccessPolicy{Mode: "keys", Version: 3}, true, true, false},
			{"public", &ConsumerAccessPolicy{Mode: "review", Version: 1}, false, false, false},
		} {
			t.Run(fmt.Sprintf("connector=%t/%s", connector, tc.name), func(t *testing.T) {
				calls := 0
				api := doerFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					var sent struct {
						ConsumerAccess *ConsumerAccessPolicy `json:"consumer_access"`
						Private        *bool                 `json:"private"`
					}
					if err := json.NewDecoder(req.Body).Decode(&sent); err != nil {
						t.Fatal(err)
					}
					if sent.Private == nil || !*sent.Private || sent.ConsumerAccess == nil || sent.ConsumerAccess.Version != 1 {
						t.Fatal("private creation request changed")
					}
					data := map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "private": tc.private, "consumer_access": tc.policy, "status": "active", "target_url": privacyTestTargetURL}
					if connector {
						data["type"] = "tunnel"
						data["slug"] = testConnectorSlug
						data["connector_routing_id"] = testConnectorRoutingID
						data["knock_resource_id"] = testKnockID
					}
					body, err := json.Marshal(map[string]any{"data": data, "meta": map[string]any{"found_existing": tc.existing}})
					if err != nil {
						t.Fatal(err)
					}
					return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
				})
				client, err := NewClient(BearerToken("lv_test_policy"), WithBaseURL("https://api.example.test"), WithHTTPClient(api))
				if err != nil {
					t.Fatal(err)
				}
				expected := ConsumerAccessPolicy{Mode: "review", Version: 1}
				if connector {
					var result *EnsureConnectorResourceResult
					result, err = client.EnsureConnectorResourceWithOptions(t.Context(), testConnectorSlug, WithConsumerAccess(expected))
					if tc.ok && (result == nil || result.Resource.ConsumerAccess.Version != tc.policy.Version) {
						t.Fatal("lost current Connector policy")
					}
				} else {
					var result *Resource
					result, err = client.ProtectURL(t.Context(), privacyTestTargetURL, WithConsumerAccess(expected))
					if tc.ok && (result == nil || result.ConsumerAccess.Version != tc.policy.Version) {
						t.Fatal("lost current URL policy")
					}
				}
				if tc.ok && err != nil {
					t.Fatal(err)
				}
				if !tc.ok && !errors.Is(err, ErrInvalidAPIResponse) {
					t.Fatalf("unconfirmed policy accepted: %v", err)
				}
				if calls != 1 {
					t.Fatal("creation performed a second mutation")
				}
			})
		}
	}
}

func TestPaidConsumerPolicyConfirmsPriceAndAccountByValue(t *testing.T) {
	policy := ConsumerAccessPolicy{Mode: "contract", Version: 1, ContractID: "sale", Payment: &CRIDPaymentPolicy{AccountID: "acct_publisher", PriceID: "price_product", AccessSeconds: 3600}}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	copyPayment := *policy.Payment
	actual := policy
	actual.Payment = &copyPayment
	private := true
	if !consumerCreationPolicyConfirmed(&private, &actual, &policy, false) {
		t.Fatal("equal payment policies rejected")
	}
	actual.Payment.PriceID = "price_other"
	if consumerCreationPolicyConfirmed(&private, &actual, &policy, false) {
		t.Fatal("changed payment price accepted")
	}
	for _, p := range []ConsumerAccessPolicy{{Mode: "review", Version: 1, Payment: policy.Payment}, {Mode: "contract", Version: 1, ContractID: "sale", Payment: &CRIDPaymentPolicy{AccountID: "acct_wrong/route", PriceID: "price_product"}}} {
		if err := p.validate(); err == nil {
			t.Fatal("invalid payment policy accepted")
		}
	}
}

func TestPublisherStripeEndpointsValidateAccountFeeAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		connect, valid   bool
	}{
		{"connect", "/v1/payments/connect", `{"data":{"url":"https://connect.stripe.com/oauth/authorize?state=fixture"}}`, true, true},
		{"wrong redirect", "/v1/payments/connect", `{"data":{"url":"https://connect.stripe.com.attacker.test/oauth"}}`, true, false},
		{"account", "/v1/payments/account", `{"data":{"account_id":"acct_publisher","layerv_fee_percent":3}}`, false, true},
		{"fee changed", "/v1/payments/account", `{"data":{"account_id":"acct_publisher","layerv_fee_percent":4}}`, false, false},
		{"missing account", "/v1/payments/account", `{"data":{}}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := doerFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != tc.path {
					t.Fatalf("unexpected path %s", req.URL.Path)
				}
				if tc.connect && req.Method != http.MethodPost || !tc.connect && req.Method != http.MethodGet {
					t.Fatal("wrong payment method")
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			client, err := NewClient(BearerToken("lv_test_policy"), WithBaseURL("https://api.example.test"), WithHTTPClient(transport))
			if err != nil {
				t.Fatal(err)
			}
			if tc.connect {
				_, err = client.ConnectPublisherStripe(t.Context())
			} else {
				_, err = client.PublisherStripeAccount(t.Context())
			}
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("invalid response accepted: %v", err)
			}
		})
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
	private := true
	var cfg resourceOptions
	if err := WithConsumerAccess(p).applyResourceOption(&cfg); err != nil || !consumerCreationPolicyConfirmed(&private, &p, &p, false) {
		t.Fatalf("email domain creation not confirmed: %v", err)
	}
	different := decode(`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["Other@other.com"]}`)
	if consumerCreationPolicyConfirmed(&private, &different, &p, true) {
		t.Fatal("different mailbox exception confirmed")
	}
	if newer := decode(`{"mode":"email_domain","version":3,"email_domain":"example.com","allowed_emails":["Person@other.com"]}`); !consumerCreationPolicyConfirmed(&private, &newer, &p, true) {
		t.Fatal("existing resource with a newer revision of the same policy not confirmed")
	}
	if !(ConsumerAccessPolicy{Mode: "keys", Version: 1}).SameDefinition(ConsumerAccessPolicy{Mode: "keys", Version: 2, AllowedEmails: []string{}}) {
		t.Fatal("nil and empty mailbox exceptions differ")
	}
	for _, raw := range []string{
		`{"mode":"email_domain","version":1,"email_domain":"Example.com"}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a@OTHER.com"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a@other.com","a@other.com"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["Name <a@other.com>"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a@other.com (comment)"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a\u202e@other.com"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":["a\u0007@other.com"]}`,
		`{"mode":"email_domain","version":1,"email_domain":"example.com","allowed_emails":[" a@other.com"]}`,
		`{"mode":"review","version":1,"email_domain":"example.com"}`,
		`{"mode":"contract","version":1,"contract_id":"contains spaces"}`,
	} {
		if err := decode(raw).validate(); err == nil {
			t.Errorf("unsafe policy accepted: %s", raw)
		}
	}
}

func TestUpdateConsumerAccessRejectsDifferentMailboxExceptions(t *testing.T) {
	// The service echoes mailbox exceptions verbatim and in order, so a reorder is a different answer.
	policy := ConsumerAccessPolicy{Mode: "email_domain", Version: 2, EmailDomain: "example.com", AllowedEmails: []string{"z@other.com", "Partner@other.com"}}
	for _, emails := range [][]string{{"z@other.com", "Partner@other.com"}, {"Partner@other.com", "z@other.com"}, {"z@other.com", "Other@other.com"}, nil} {
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
		if same := slices.Equal(emails, policy.AllowedEmails); same != (err == nil) {
			t.Fatalf("allowed_emails %v: %v", emails, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatalf("allowed_emails %v: %v", emails, err)
		}
	}
}

func TestApprovalExpiresInTravelsWithReviewAndKeysPolicies(t *testing.T) {
	var sent ConsumerAccessPolicy
	client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Policy ConsumerAccessPolicy `json:"consumer_access"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		sent = body.Policy
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "consumer_access": body.Policy}})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
	policy := ConsumerAccessPolicy{Mode: "review", Version: 2, ApprovalExpiresIn: "7d"}
	if err := client.UpdateConsumerAccess(context.Background(), testConnectorCRID, 1, policy); err != nil || sent.ApprovalExpiresIn != "7d" {
		t.Fatalf("approval_expires_in not sent: %v %+v", err, sent)
	}
	if other := (ConsumerAccessPolicy{Mode: "review", Version: 2, ApprovalExpiresIn: "30d"}); policy.SameDefinition(other) {
		t.Fatal("different approval lifetimes compared equal")
	}
	if err := (ConsumerAccessPolicy{Mode: "email_capture", Version: 1, ApprovalExpiresIn: "7d"}).validate(); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("approval_expires_in accepted outside review and keys: %v", err)
	}
	for value, valid := range map[string]bool{"1h": true, "90m": true, "365d": true, "1w": true, "8760h": true, "59m": false, "0d": false, "366d": false, "53w": false, "forever": false, "-1d": false, "d": false, "9223372036854775807d": false} {
		if err := (ConsumerAccessPolicy{Mode: "keys", Version: 1, ApprovalExpiresIn: value}).validate(); (err == nil) != valid {
			t.Errorf("approval_expires_in %q: %v", value, err)
		}
	}
}

func TestApprovalExpiresInComparesInStoredForm(t *testing.T) {
	sent := ConsumerAccessPolicy{Mode: "review", Version: 2, ApprovalExpiresIn: "1w"}
	for stored, same := range map[string]bool{"7d": true, "168h": true, "30d": false, "": false} {
		client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(*http.Request) (*http.Response, error) {
			echoed := sent
			echoed.ApprovalExpiresIn = stored
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "consumer_access": echoed}})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}
		if err := client.UpdateConsumerAccess(context.Background(), testConnectorCRID, 1, sent); (err == nil) != same || err != nil && !errors.Is(err, ErrInvalidAPIResponse) {
			t.Errorf("stored %q: %v", stored, err)
		}
	}
}
