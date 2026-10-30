package qurl

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResourceItemIDsRejectCredentialsAndNavigationBeforeAuthorization(t *testing.T) {
	const resourceCRID = "ahpviqz46qwcvx56glfatm3p3ooccwfcf2it4sdgjervwdkapykw3o3qdq2a"
	for _, id := range []string{"", " ", ".", "..", "at_synthetic_secret", " at_synthetic_secret "} {
		t.Run(id, func(t *testing.T) {
			client, err := NewClient(CredentialProviderFunc(func(context.Context, *http.Request) error {
				t.Error("invalid item ID reached authorization")
				return errors.New("unexpected authorization")
			}), WithBaseURL("https://api.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			client.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
				t.Error("invalid item ID reached transport")
				return nil, errors.New("unexpected transport")
			})
			calls := map[string]func() error{
				"revoke portal": func() error { return client.RevokePortal(context.Background(), resourceCRID, id) },
				"resend invitation": func() error {
					_, err := client.ResendConsumerInvitation(context.Background(), resourceCRID, id, 1)
					return err
				},
				"revoke invitation": func() error {
					_, err := client.RevokeConsumerInvitation(context.Background(), resourceCRID, id, 1)
					return err
				},
				"approve grant": func() error {
					_, err := client.ApproveConsumerGrant(context.Background(), resourceCRID, id, ConsumerGrantApproval{ExpectedVersion: 1})
					return err
				},
				"deny grant": func() error {
					_, err := client.DenyConsumerGrant(context.Background(), resourceCRID, id, 1)
					return err
				},
				"revoke grant": func() error {
					_, err := client.RevokeConsumerGrant(context.Background(), resourceCRID, id, 1)
					return err
				},
			}
			for name, call := range calls {
				err := call()
				if !errors.Is(err, ErrInvalidPortalRequest) && !errors.Is(err, ErrInvalidResourceRequest) {
					t.Fatalf("%s: want validation error, got %v", name, err)
				}
				if strings.Contains(err.Error(), "synthetic_secret") {
					t.Fatalf("%s leaked credential", name)
				}
			}
		})
	}
}

func TestResourceItemIDKeepsOpaqueSeparatorsInOneSegment(t *testing.T) {
	const resourceCRID = "ahpviqz46qwcvx56glfatm3p3ooccwfcf2it4sdgjervwdkapykw3o3qdq2a"
	client, err := NewClient(BearerToken("lv_test"), WithBaseURL("https://api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client.httpClient = doerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if !strings.Contains(request.URL.EscapedPath(), "/r%3F%2F%231/") {
			t.Errorf("opaque ID escaped path: %s", request.URL.EscapedPath())
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"r?/#1","version":2}}`))}, nil
	})
	if _, err := client.ResendConsumerInvitation(context.Background(), resourceCRID, "r?/#1", 1); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}
