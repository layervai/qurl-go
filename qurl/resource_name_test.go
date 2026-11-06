package qurl

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Every call that can create a resource sends WithName as the public "name".
func TestCreateCallsSendName(t *testing.T) {
	for _, create := range privacyCreateCalls {
		t.Run(create.name, func(t *testing.T) {
			client, api := newPrivacyTestClient(t, "")
			if err := create.call(client, []ResourceCreateOption{WithName("Team dashboard")}); err != nil {
				t.Fatalf("%s: %v", create.name, err)
			}
			if len(api.bodies) != 1 || !strings.Contains(api.bodies[0], `"name":"Team dashboard"`) {
				t.Fatalf("request bodies = %q, want a name member", api.bodies)
			}
		})
	}
}

func TestWithNameRejectedBeforeSending(t *testing.T) {
	for _, create := range privacyCreateCalls {
		t.Run(create.name, func(t *testing.T) {
			client, api := newPrivacyTestClient(t, "")
			err := create.call(client, []ResourceCreateOption{WithName("  ")})
			if !errors.Is(err, ErrInvalidResourceRequest) && !errors.Is(err, ErrInvalidPortalRequest) {
				t.Fatalf("err = %v, want an invalid request error", err)
			}
			if len(api.bodies) != 0 {
				t.Fatalf("sent %d requests, want none", len(api.bodies))
			}
		})
	}

	t.Run("CreatePortal", func(t *testing.T) {
		client, api := newPrivacyTestClient(t, "")
		_, err := client.ResourceByCRID(testConnectorCRID).CreatePortal(context.Background(), WithName("Team dashboard"))
		if !errors.Is(err, ErrInvalidPortalRequest) || len(api.bodies) != 0 {
			t.Fatalf("err = %v, requests = %d; want ErrInvalidPortalRequest and none sent", err, len(api.bodies))
		}
	})
}

func TestNameRequiredErrorMatchesSentinel(t *testing.T) {
	client, err := NewClient(BearerToken("lv_test_name"), WithBaseURL("https://api.example.test"),
		WithHTTPClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"name_required","detail":"name is required: the public name recipients see for this resource"}}`)),
				Request:    req,
			}, nil
		})))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ProtectURL(context.Background(), privacyTestTargetURL)
	var apiErr *APIError
	if !errors.Is(err, ErrResourceNameRequired) || !errors.As(err, &apiErr) || errors.Is(err, ErrAPIRequestOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrResourceNameRequired with an *APIError", err)
	}
	if errors.Is(&APIError{StatusCode: http.StatusBadRequest, Code: "invalid_request"}, ErrResourceNameRequired) {
		t.Fatal("another 400 must not match ErrResourceNameRequired")
	}
}
