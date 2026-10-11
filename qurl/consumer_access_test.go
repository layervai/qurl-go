package qurl

import (
	"context"
	"encoding/json"
	"errors"
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
