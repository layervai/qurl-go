package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
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

func TestPublisherStripeDeviceSetup(t *testing.T) {
	state := strings.Repeat("a", 43) + ".12345"
	var calls int
	transport := doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer lv_test_policy" {
			t.Fatal("missing authenticated POST")
		}
		var response string
		switch req.URL.Path {
		case "/v1/payments/connect":
			if req.URL.Query().Get("loopback_port") != "12345" {
				t.Fatal("missing loopback port")
			}
			response = `{"data":{"url":"https://connect.stripe.com/oauth/authorize?state=` + state + `"}}`
		case "/v1/payments/connect/complete":
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["state"] != state || body["code"] != "code" {
				t.Fatal("wrong consent proof")
			}
			response = `{"data":{"url":"https://example.test/billing"}}`
		case "/v1/payments/prices":
			var body struct {
				Name     string `json:"name"`
				Amount   int64  `json:"amount"`
				Interval string `json:"interval"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Name != "App" || body.Amount != 500 || body.Interval != "month" {
				t.Fatal("wrong price input")
			}
			response = `{"data":{"account_id":"acct_owner","price_id":"price_new"}}`
		default:
			t.Fatalf("unexpected payment route %s", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	client, err := NewClient(BearerToken("lv_test_policy"), WithBaseURL("https://api.example.test"), WithHTTPClient(transport))
	if err != nil {
		t.Fatal(err)
	}
	if _, expected, err := client.ConnectPublisherStripeForDevice(t.Context(), 12345); err != nil || expected != state {
		t.Fatalf("wrong consent state: %v", err)
	}
	if err = client.CompletePublisherStripe(t.Context(), state, "code"); err != nil {
		t.Fatal(err)
	}
	policy, err := client.CreatePublisherStripePrice(t.Context(), "App", 500, "month")
	if err != nil || policy.AccountID != "acct_owner" || policy.PriceID != "price_new" || calls != 3 {
		t.Fatalf("price response = %+v, err = %v, calls = %d", policy, err, calls)
	}
}

func TestPublisherStripeDeviceRejectsInvalidConsent(t *testing.T) {
	nonce := strings.Repeat("a", 43)
	response := ""
	client, err := NewClient(BearerToken("lv_test_policy"), WithBaseURL("https://api.example.test"), WithHTTPClient(doerFunc(func(_ *http.Request) (*http.Response, error) {
		if response == "" {
			t.Fatal("invalid input reached the API")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{0, 1023, 65536} {
		if _, _, err := client.ConnectPublisherStripeForDevice(t.Context(), port); !errors.Is(err, ErrInvalidResourceRequest) {
			t.Fatalf("port %d: %v", port, err)
		}
	}
	for _, state := range []string{"", nonce + ".012345", "!" + nonce[1:]} {
		if err := client.CompletePublisherStripe(t.Context(), state, "code"); !errors.Is(err, ErrInvalidResourceRequest) {
			t.Fatalf("invalid state accepted: %v", err)
		}
	}
	if err := client.CompletePublisherStripe(t.Context(), nonce, ""); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("missing code accepted: %v", err)
	}
	if _, err := client.CreatePublisherStripePrice(t.Context(), "App", 49, ""); !errors.Is(err, ErrInvalidResourceRequest) {
		t.Fatalf("invalid amount accepted: %v", err)
	}
	for _, path := range []string{
		"connect.stripe.com/oauth/authorize?state=" + nonce + ".12346",
		"connect.stripe.com/oauth/authorize?state=" + nonce + ".12345&state=other",
		"connect.stripe.com/oauth/authorize?state=" + nonce,
		"connect.stripe.com/oauth/authorize?state=short.12345",
		"connect.stripe.com/oauth/authorize?state=!" + nonce[1:] + ".12345",
		"connect.stripe.com/unexpected?state=" + nonce + ".12345",
		"stripe.example.test/oauth/authorize?state=" + nonce + ".12345",
	} {
		response = `{"data":{"url":"https://` + path + `"}}`
		if _, _, err := client.ConnectPublisherStripeForDevice(t.Context(), 12345); !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatalf("invalid consent URL accepted: %v", err)
		}
	}
	for _, data := range []string{
		`{"account_id":"other","price_id":"price_new"}`,
		`{"account_id":"acct_owner","price_id":"other"}`,
		`{"account_id":"acct_owner","price_id":"price_new","access_seconds":60}`,
	} {
		response = `{"data":` + data + `}`
		if _, err := client.CreatePublisherStripePrice(t.Context(), "App", 500, ""); !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatalf("invalid price receipt accepted: %v", err)
		}
	}
}

func TestConsumerEmailDomainPolicy(t *testing.T) {
	for _, tc := range []struct {
		mode, domain string
		valid        bool
	}{
		{"email_domain", "layerv.ai", true},
		{"email_domain", "", false},
		{"email_domain", "LayerV.ai", false},
		{"email_domain", "*.layerv.ai", false},
		{"email_domain", "https://layerv.ai", false},
		{"email_domain", "layerv.ai.", false},
		{"email_domain", "-invalid.ai", false},
		{"keys", "layerv.ai", false},
	} {
		t.Run(tc.mode+"/"+tc.domain, func(t *testing.T) {
			var policy ConsumerAccessPolicy
			raw, _ := json.Marshal(map[string]any{"mode": tc.mode, "version": 1, "email_domain": tc.domain})
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatal(err)
			}
			if err := policy.validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
	var expected, changed ConsumerAccessPolicy
	json.Unmarshal([]byte(`{"mode":"email_domain","version":1,"email_domain":"layerv.ai"}`), &expected)
	json.Unmarshal([]byte(`{"mode":"email_domain","version":1,"email_domain":"outside.test"}`), &changed)
	private := true
	if !consumerCreationPolicyConfirmed(&private, &expected, &expected, false) || consumerCreationPolicyConfirmed(&private, &changed, &expected, true) || expected.equal(changed) {
		t.Fatal("email-domain creation or policy comparison lost its exact domain")
	}
}

func TestUpdateConsumerEmailDomainPolicyChecksReadback(t *testing.T) {
	policy := ConsumerAccessPolicy{Mode: "email_domain", Version: 2, EmailDomain: "layerv.ai"}
	for _, domain := range []string{"layerv.ai", "outside.test"} {
		client := &Client{baseURL: "https://api.example.test", credentials: BearerToken("test"), httpClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			var body struct {
				Policy   ConsumerAccessPolicy `json:"consumer_access"`
				Expected int64                `json:"expected_consumer_access_version"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Expected != 1 || !body.Policy.equal(policy) {
				t.Fatal("policy write lost its domain or revision")
			}
			actual := policy
			actual.EmailDomain = domain
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"resource_id": testConnectorID, "crid": testConnectorCRID, "consumer_access": actual}})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}
		err := client.UpdateConsumerAccess(t.Context(), testConnectorCRID, 1, policy)
		if domain == "layerv.ai" && err != nil {
			t.Fatal(err)
		}
		if domain != "layerv.ai" && !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatal("changed email domain accepted")
		}
	}
}
