package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const accessRulesItemsJSON = `[` +
	`{"id":"0b7e1c2a-4f5d-4e6a-9b8c-1d2e3f4a5b6c","name":"Paid","mode":"contract","contract_id":"c_1","payment":{"price_id":"price_1PqA2b","access_seconds":0}},` +
	`{"id":"1c8f2d3b-5a6e-4f7b-8c9d-2e3f4a5b6c7d","name":"Quick look","mode":"public","link_limits":{"expires_in":"1h","one_time_use":false,"session_duration":"30m"}},` +
	`{"id":"2d9a3e4c-6b7f-4a8c-9d0e-3f4a5b6c7d8e","name":"Team","mode":"email_domain","email_domain":"example.com","allowed_emails":["Pat@partner.test"]},` +
	`{"id":"3e0b4f5d-7c8a-4b9d-8e1f-4a5b6c7d8e9f","name":"Reviewed","mode":"review","approval_expires_in":"7d"}]`

func newAccessRulesTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	api := httptest.NewServer(handler)
	t.Cleanup(api.Close)
	return newConnectorTestClient(t, api.URL)
}

// TestClient_AccessRulesRoundTrip reads a library and saves its items back:
// every modeled field, including payment and an explicit one_time_use:false,
// must reach the wire exactly as it was read.
func TestClient_AccessRulesRoundTrip(t *testing.T) {
	saved := make(chan string, 1)
	client := newAccessRulesTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/me/access-rules" || r.URL.RawQuery != "" {
			t.Errorf("request = %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Method == http.MethodPut {
			saved <- string(body)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"account_id":"acct_ns","version":4,"items":%s,"built_ins":[{"id":"builtin_review","name":"Review","mode":"review"}],"quick_share_rule_id":"paid","future":1},"meta":{"request_id":"req_1"}}`, accessRulesItemsJSON)
	})

	rules, err := client.AccessRules(context.Background())
	if err != nil {
		t.Fatalf("AccessRules: %v", err)
	}
	if rules.AccountID != "acct_ns" || rules.Version != 4 || len(rules.Items) != 4 || len(rules.BuiltIns) != 1 || rules.QuickShareRuleID != "paid" {
		t.Fatalf("rules = %+v", rules)
	}
	if p := rules.Items[0].Payment; p == nil || p.PriceID != "price_1PqA2b" || p.AccessSeconds != 0 {
		t.Fatalf("payment = %+v", p)
	}

	if _, err := client.SaveAccessRules(context.Background(), AccessRulesUpdate{Version: rules.Version, Items: rules.Items}); err != nil {
		t.Fatalf("SaveAccessRules: %v", err)
	}
	if got, want := <-saved, `{"version":4,"items":`+accessRulesItemsJSON+`}`; got != want {
		t.Fatalf("PUT body =\n%s\nwant\n%s", got, want)
	}
}

// TestClient_AccessRulesKeepUnknownFields saves back rule fields a newer
// service added, on the rule and inside its settings, exactly as read.
func TestClient_AccessRulesKeepUnknownFields(t *testing.T) {
	const items = `[` +
		`{"id":"0b7e1c2a-4f5d-4e6a-9b8c-1d2e3f4a5b6c","name":"Paid","mode":"contract","contract_id":"c_1","payment":{"price_id":"price_1","access_seconds":0,"trial":{"days":7}},"region":"eu"},` +
		`{"id":"1c8f2d3b-5a6e-4f7b-8c9d-2e3f4a5b6c7d","name":"Quick look","mode":"public","link_limits":{"expires_in":"1h","max_opens":3}},` +
		`{"id":"2d9a3e4c-6b7f-4a8c-9d0e-3f4a5b6c7d8e","name":"Reviewed","mode":"review"}]`
	saved := make(chan string, 1)
	client := newAccessRulesTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			saved <- string(body)
		}
		fmt.Fprintf(w, `{"data":{"account_id":"a","version":2,"items":%s,"built_ins":[]}}`, items)
	})
	rules, err := client.AccessRules(context.Background())
	if err != nil {
		t.Fatalf("AccessRules: %v", err)
	}
	for i, want := range []bool{true, true, false} {
		if got := rules.Items[i].HasUnknownFields(); got != want {
			t.Errorf("item %d HasUnknownFields = %v, want %v", i, got, want)
		}
	}
	if p := rules.Items[0].Payment; p == nil || p.PriceID != "price_1" || string(p.Unknown["trial"]) != `{"days":7}` || string(rules.Items[0].Unknown["region"]) != `"eu"` {
		t.Fatalf("item 0 = %+v, payment %+v", rules.Items[0], p)
	}
	if _, err := client.SaveAccessRules(context.Background(), AccessRulesUpdate{Version: rules.Version, Items: rules.Items}); err != nil {
		t.Fatalf("SaveAccessRules: %v", err)
	}
	if got, want := <-saved, `{"version":2,"items":`+items+`}`; got != want {
		t.Fatalf("PUT body =\n%s\nwant\n%s", got, want)
	}
}

// A member that differs from a modeled field only in case would be read as
// that field and written back under its name, so it is refused.
func TestAccessRuleRefusesCaseVariantFields(t *testing.T) {
	for _, raw := range []string{`{"id":"r","name":"x","mode":"review","Mode":"public"}`, `{"id":"r","name":"x","mode":"public","link_limits":{"expires_in":"1h","Expires_In":"30d"}}`} {
		var rule AccessRule
		if err := json.Unmarshal([]byte(raw), &rule); err == nil {
			t.Errorf("%s: accepted as %+v", raw, rule)
		}
	}
}

func TestAccessRulesUpdateWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		update AccessRulesUpdate
		want   string
	}{
		{"new library keeps quick share", AccessRulesUpdate{}, `{"version":0,"items":[]}`},
		{"reset quick share", AccessRulesUpdate{Version: 2, Items: []AccessRule{}, QuickShareRuleID: "once"}, `{"version":2,"items":[],"quick_share_rule_id":"once"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := make(chan string, 1)
			client := newAccessRulesTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				saved <- string(body)
				fmt.Fprint(w, `{"data":{"account_id":"a","version":3,"items":[],"built_ins":[]}}`)
			})
			rules, err := client.SaveAccessRules(context.Background(), tc.update)
			if err != nil || rules.Version != 3 {
				t.Fatalf("SaveAccessRules = %+v, %v", rules, err)
			}
			if got := <-saved; got != tc.want {
				t.Fatalf("PUT body = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestClient_SaveAccessRulesClassifiesRejections(t *testing.T) {
	for _, tc := range []struct {
		status    int
		want, not error
	}{
		{http.StatusConflict, ErrAccessRulesConflict, ErrInvalidAccessRules},
		{http.StatusBadRequest, ErrInvalidAccessRules, ErrAccessRulesConflict},
	} {
		client := newAccessRulesTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(tc.status)
			fmt.Fprintf(w, `{"status":%d,"code":"x","title":"x"}`, tc.status)
		})
		_, err := client.SaveAccessRules(context.Background(), AccessRulesUpdate{Version: 1})
		var apiErr *APIError
		if !errors.Is(err, tc.want) || errors.Is(err, tc.not) || !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
			t.Errorf("%d: err = %v, want %v wrapping the *APIError", tc.status, err, tc.want)
		}
	}
}

func TestClient_AccessRulesRejectsIncompleteLibrary(t *testing.T) {
	for _, body := range []string{
		`{"data":null}`,
		`{"data":{"account_id":"a","items":[],"built_ins":[]}}`,
		`{"data":{"account_id":"a","version":null,"items":[],"built_ins":[]}}`,
		`{"data":{"account_id":"a","version":1,"built_ins":[]}}`,
		`{"data":{"version":1,"items":[],"built_ins":[]}}`,
		`{"data":{"account_id":"a","version":1,"items":[]}}`,
	} {
		client := newAccessRulesTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, body)
		})
		if _, err := client.AccessRules(context.Background()); !errors.Is(err, ErrInvalidAPIResponse) {
			t.Errorf("%s: err = %v, want ErrInvalidAPIResponse", body, err)
		}
	}
}

func TestClient_SaveAccessRulesRejectsInvalidUTF8Name(t *testing.T) {
	client := newAccessRulesTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an invalid name must not reach the service")
	})
	_, err := client.SaveAccessRules(context.Background(), AccessRulesUpdate{Items: []AccessRule{{ID: "r", Name: "bad\xff", Mode: "review"}}})
	if !errors.Is(err, ErrInvalidAccessRules) {
		t.Fatalf("err = %v, want ErrInvalidAccessRules", err)
	}
}

func TestClient_AccessRulesNilClient(t *testing.T) {
	var client *Client
	if _, err := client.AccessRules(context.Background()); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("AccessRules err = %v", err)
	}
	if _, err := client.SaveAccessRules(context.Background(), AccessRulesUpdate{}); !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("SaveAccessRules err = %v", err)
	}
}
