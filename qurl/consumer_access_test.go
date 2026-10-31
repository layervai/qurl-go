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
