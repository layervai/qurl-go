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
	wantKind := map[string]error{
		"ProtectURL":                         ErrInvalidResourceRequest,
		"CreateResource":                     ErrInvalidResourceRequest,
		"CreatePortalForURL":                 ErrInvalidPortalRequest,
		"EnsureConnectorResourceWithOptions": ErrInvalidResourceRequest,
	}
	for _, create := range privacyCreateCalls {
		t.Run(create.name, func(t *testing.T) {
			client, api := newPrivacyTestClient(t, "")
			for _, name := range []string{"  ", " Team", "Team\ndashboard", "Team\x00", "Team\u2028x", "Team\u202ex", strings.Repeat("x", 101), "\xff"} {
				err := create.call(client, []ResourceCreateOption{WithName(name)})
				if !errors.Is(err, wantKind[create.name]) {
					t.Fatalf("WithName(%q) err = %v, want %v", name, err, wantKind[create.name])
				}
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
	_, _, err = client.CreatePortalForURL(context.Background(), privacyTestTargetURL)
	if !errors.Is(err, ErrResourceNameRequired) {
		t.Fatalf("CreatePortalForURL err = %v, want ErrResourceNameRequired", err)
	}
	_, err = client.EnsureConnectorResource(context.Background(), testConnectorSlug)
	if !errors.Is(err, ErrResourceNameRequired) || errors.Is(err, ErrConnectorResourceOutcomeUnknown) {
		t.Fatalf("EnsureConnectorResource err = %v, want ErrResourceNameRequired", err)
	}
	_, err = client.ProtectURL(context.Background(), privacyTestTargetURL)
	var apiErr *APIError
	if !errors.Is(err, ErrResourceNameRequired) || !errors.As(err, &apiErr) || errors.Is(err, ErrAPIRequestOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrResourceNameRequired with an *APIError", err)
	}
	empty := ""
	_, err = client.UpdatePreview(context.Background(), testConnectorCRID, PreviewPatch{Revision: 1, Name: &empty})
	if !errors.Is(err, ErrResourceNameRequired) {
		t.Fatalf("UpdatePreview err = %v, want ErrResourceNameRequired", err)
	}
	if errors.Is(&APIError{StatusCode: http.StatusBadRequest, Code: "invalid_request"}, ErrResourceNameRequired) {
		t.Fatal("another 400 must not match ErrResourceNameRequired")
	}
}

// The limit counts characters, not bytes, like the service.
func TestWithNameAcceptsHundredCharacters(t *testing.T) {
	client, api := newPrivacyTestClient(t, "")
	if _, err := client.ProtectURL(context.Background(), privacyTestTargetURL, WithName(strings.Repeat("é", 100))); err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
	if len(api.bodies) != 1 {
		t.Fatalf("requests = %d, want 1", len(api.bodies))
	}
}
