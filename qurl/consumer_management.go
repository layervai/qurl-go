package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ConsumerInvitation records the verified-mailbox invitation's current state.
type ConsumerInvitation struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	Status         string    `json:"status"`
	Delivery       string    `json:"delivery"`
	Version        int64     `json:"version"`
	ExpiresAt      time.Time `json:"expires_at"`
	SessionCleanup string    `json:"session_cleanup,omitempty"`
}

// ConsumerGrant is a publisher-scoped decision. Contract grants omit identity.
type ConsumerGrant struct {
	ID                  string     `json:"id"`
	Status              string     `json:"status"`
	Version             int64      `json:"version"`
	CredentialKind      string     `json:"credential_kind,omitempty"`
	CredentialID        string     `json:"credential_id,omitempty"`
	CredentialPublicKey string     `json:"credential_public_key_b64,omitempty"`
	Email               string     `json:"email,omitempty"`
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	EntitlementID       string     `json:"entitlement_id,omitempty"`
	SessionCleanup      string     `json:"session_cleanup,omitempty"`
}

// ConsumerGrantApproval supplies one review, key opt-in, or trusted entitlement.
// EntitlementID is a publisher backend receipt, not proof of payment by this SDK.
type ConsumerGrantApproval struct {
	ExpectedVersion     int64      `json:"expected_version"`
	CredentialKind      string     `json:"credential_kind,omitempty"`
	CredentialID        string     `json:"credential_id,omitempty"`
	CredentialPublicKey string     `json:"credential_public_key_b64,omitempty"`
	EntitlementID       string     `json:"entitlement_id,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

type consumerVersionRequest struct {
	ExpectedVersion int64 `json:"expected_version"`
}

func (c *Client) consumerManagement(ctx context.Context, crid, method, suffix string, body, response any) error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorCRID(crid); err != nil {
		return err
	}
	return c.doJSONStatus(ctx, method, "/v1/resources/"+url.PathEscape(crid)+suffix, body, response, http.StatusOK)
}

// InviteConsumer mails a publisher-only invitation. It returns no invitation secret.
func (c *Client) InviteConsumer(ctx context.Context, crid, email string) (*ConsumerInvitation, error) {
	var response apiEnvelope[*ConsumerInvitation]
	err := c.consumerManagement(ctx, crid, http.MethodPost, "/invitations", struct {
		Email string `json:"email"`
	}{email}, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// ResendConsumerInvitation rotates the invitation link using its current version.
func (c *Client) ResendConsumerInvitation(ctx context.Context, crid, id string, version int64) (*ConsumerInvitation, error) {
	var response apiEnvelope[*ConsumerInvitation]
	err := c.consumerManagement(ctx, crid, http.MethodPost, "/invitations/"+url.PathEscape(id)+"/resend", consumerVersionRequest{version}, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// RevokeConsumerInvitation removes the invitation and any grant it created.
func (c *Client) RevokeConsumerInvitation(ctx context.Context, crid, id string, version int64) (*ConsumerInvitation, error) {
	var response apiEnvelope[*ConsumerInvitation]
	suffix := "/invitations/" + url.PathEscape(id) + "?expected_version=" + fmt.Sprint(version)
	err := c.consumerManagement(ctx, crid, http.MethodDelete, suffix, nil, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// ApproveConsumerGrant approves a review, opts in a key with id new, or fulfills a contract.
func (c *Client) ApproveConsumerGrant(ctx context.Context, crid, id string, approval ConsumerGrantApproval) (*ConsumerGrant, error) {
	var response apiEnvelope[*ConsumerGrant]
	err := c.consumerManagement(ctx, crid, http.MethodPost, "/consumer-grants/"+url.PathEscape(id)+"/approve", approval, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// DenyConsumerGrant refuses a pending review with a version guard.
func (c *Client) DenyConsumerGrant(ctx context.Context, crid, id string, version int64) (*ConsumerGrant, error) {
	var response apiEnvelope[*ConsumerGrant]
	err := c.consumerManagement(ctx, crid, http.MethodPost, "/consumer-grants/"+url.PathEscape(id)+"/deny", consumerVersionRequest{version}, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// RevokeConsumerGrant removes access; inspect SessionCleanup before reporting stream removal.
func (c *Client) RevokeConsumerGrant(ctx context.Context, crid, id string, version int64) (*ConsumerGrant, error) {
	var response apiEnvelope[*ConsumerGrant]
	suffix := "/consumer-grants/" + url.PathEscape(id) + "?expected_version=" + fmt.Sprint(version)
	err := c.consumerManagement(ctx, crid, http.MethodDelete, suffix, nil, &response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.ID == "" || response.Data.Version < 1 {
		return nil, fmt.Errorf("%w: missing consumer decision", ErrInvalidAPIResponse)
	}
	return response.Data, nil
}

// ConsumerPage preserves the service cursor without exposing storage keys.
type ConsumerPage[T any] struct {
	Data []T `json:"data"`
	Meta struct {
		NextCursor string `json:"next_cursor,omitempty"`
	} `json:"meta"`
}

// ListConsumerInvitations returns one publisher-owned page.
func (c *Client) ListConsumerInvitations(ctx context.Context, crid, cursor string) (*ConsumerPage[ConsumerInvitation], error) {
	var response ConsumerPage[ConsumerInvitation]
	err := c.consumerManagement(ctx, crid, http.MethodGet, "/invitations?cursor="+url.QueryEscape(cursor), nil, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// ListConsumerGrants returns one publisher-owned page, with identity omitted for contracts.
func (c *Client) ListConsumerGrants(ctx context.Context, crid, cursor string) (*ConsumerPage[ConsumerGrant], error) {
	var response ConsumerPage[ConsumerGrant]
	err := c.consumerManagement(ctx, crid, http.MethodGet, "/consumer-grants?cursor="+url.QueryEscape(cursor), nil, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}
