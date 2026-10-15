package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ConsumerAccessPolicy selects the publisher's private access flow.
type ConsumerAccessPolicy struct {
	EmailFallback bool   `json:"email_fallback,omitempty"`
	Mode          string `json:"mode"`
	Version       int64  `json:"version"`
	ContractID    string `json:"contract_id,omitempty"`
}

func (p ConsumerAccessPolicy) validate() error {
	if p.Version < 1 || p.Version > 9007199254740991 {
		return fmt.Errorf("%w: invalid consumer policy version", ErrInvalidResourceRequest)
	}
	switch p.Mode {
	case "keys", "invite_only", "email_capture", "review":
		if p.ContractID != "" {
			return fmt.Errorf("%w: contract_id requires contract mode", ErrInvalidResourceRequest)
		}
	case "contract":
		if strings.TrimSpace(p.ContractID) == "" || len(p.ContractID) > 128 {
			return fmt.Errorf("%w: contract mode requires a bounded contract_id", ErrInvalidResourceRequest)
		}
	default:
		return fmt.Errorf("%w: unknown consumer access mode", ErrInvalidResourceRequest)
	}
	return nil
}

// WithConsumerAccess creates a private resource with a consumer policy.
// Change an existing policy through UpdateConsumerAccess instead.
func WithConsumerAccess(policy ConsumerAccessPolicy) ConsumerAccessOption {
	return ConsumerAccessOption{policy: policy}
}

// ConsumerAccessOption applies to URL and Connector resource creation.
type ConsumerAccessOption struct{ policy ConsumerAccessPolicy }

func (o ConsumerAccessOption) applyResourceOption(cfg *resourceOptions) error {
	if o.policy.Version != 1 {
		return fmt.Errorf("%w: new consumer policy requires version 1", ErrInvalidResourceRequest)
	}
	if err := o.policy.validate(); err != nil {
		return err
	}
	if err := statePrivacy(&cfg.private, true, ErrInvalidResourceRequest); err != nil {
		return err
	}
	cfg.consumerAccess = &o.policy
	return nil
}

func (o ConsumerAccessOption) applyConnectorResourceOption(cfg *connectorResourceOptions) error {
	if o.policy.Version != 1 {
		return fmt.Errorf("%w: new consumer policy requires version 1", ErrInvalidResourceRequest)
	}
	if err := o.policy.validate(); err != nil {
		return err
	}
	if err := statePrivacy(&cfg.private, true, ErrInvalidResourceRequest); err != nil {
		return err
	}
	cfg.consumerAccess = &o.policy
	return nil
}

// UpdateConsumerAccess changes one private policy with a version guard.
func (c *Client) UpdateConsumerAccess(ctx context.Context, resourceCRID string, expectedVersion int64, policy ConsumerAccessPolicy) error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorCRID(resourceCRID); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	if expectedVersion < 0 || policy.Version != expectedVersion+1 {
		return fmt.Errorf("%w: policy version must follow expected version", ErrInvalidResourceRequest)
	}
	body := struct {
		Policy          ConsumerAccessPolicy `json:"consumer_access"`
		ExpectedVersion int64                `json:"expected_consumer_access_version"`
	}{policy, expectedVersion}
	var response apiEnvelope[*createResourceResponse]
	if err := c.doJSONStatus(ctx, http.MethodPatch, "/v1/resources/"+url.PathEscape(resourceCRID), body, &response, http.StatusOK); err != nil {
		return err
	}
	if response.Data == nil {
		return fmt.Errorf("%w: missing resource", ErrInvalidAPIResponse)
	}
	resource, err := response.Data.resource()
	if err != nil {
		return err
	}
	if resource.CRID != resourceCRID || resource.ConsumerAccess == nil || *resource.ConsumerAccess != policy {
		return fmt.Errorf("%w: consumer policy response mismatch", ErrInvalidAPIResponse)
	}
	return nil
}

func consumerCreationPolicyConfirmed(private *bool, actual, expected *ConsumerAccessPolicy, foundExisting bool) bool {
	if expected == nil {
		return true
	}
	if private == nil || !*private || actual == nil || actual.validate() != nil || actual.Mode != expected.Mode || actual.ContractID != expected.ContractID || actual.EmailFallback != expected.EmailFallback {
		return false
	}
	return actual.Version == expected.Version || (foundExisting && actual.Version > expected.Version)
}
