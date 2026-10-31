package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// ConsumerAccessPolicy selects the publisher's private access flow.
type ConsumerAccessPolicy struct {
	Mode          string   `json:"mode"`
	Version       int64    `json:"version"`
	ContractID    string   `json:"contract_id,omitempty"`
	EmailDomain   string   `json:"email_domain,omitempty"`
	AllowedEmails []string `json:"allowed_emails,omitempty"`
	// ApprovalExpiresIn bounds each review approval or key opt-in, such as
	// "7d" (1h to 365d). The service sets and enforces each grant's expiry.
	ApprovalExpiresIn string `json:"approval_expires_in,omitempty"`
}

// Validate checks the supported admission modes and their parameters.
func (p ConsumerAccessPolicy) Validate() error { return p.validate() }

var (
	consumerDomainPattern    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	consumerReferencePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

func (p ConsumerAccessPolicy) validate() error {
	if p.Version < 1 || p.Version > 9007199254740991 {
		return fmt.Errorf("%w: invalid consumer policy version", ErrInvalidResourceRequest)
	}
	if p.Mode == "email_domain" {
		if len(p.EmailDomain) > 253 || !consumerDomainPattern.MatchString(p.EmailDomain) || len(p.AllowedEmails) > 256 {
			return fmt.Errorf("%w: invalid email domain policy", ErrInvalidResourceRequest)
		}
		seen := make(map[string]bool, len(p.AllowedEmails))
		for _, email := range p.AllowedEmails {
			if !validMailbox(email) || seen[email] {
				return fmt.Errorf("%w: invalid mailbox exception", ErrInvalidResourceRequest)
			}
			seen[email] = true
		}
	} else if p.EmailDomain != "" || len(p.AllowedEmails) != 0 {
		return fmt.Errorf("%w: email fields require email_domain mode", ErrInvalidResourceRequest)
	}
	if p.ApprovalExpiresIn != "" && p.Mode != "review" && p.Mode != "keys" {
		return fmt.Errorf("%w: approval_expires_in requires review or keys mode", ErrInvalidResourceRequest)
	}
	switch p.Mode {
	case "keys", "invite_only", "email_capture", "email_domain", "review":
		if p.ContractID != "" {
			return fmt.Errorf("%w: contract_id requires contract mode", ErrInvalidResourceRequest)
		}
	case "contract":
		if !consumerReferencePattern.MatchString(p.ContractID) {
			return fmt.Errorf("%w: contract mode requires a bounded contract_id", ErrInvalidResourceRequest)
		}
	default:
		return fmt.Errorf("%w: unknown consumer access mode", ErrInvalidResourceRequest)
	}
	return nil
}

// validMailbox accepts one bare address with a lowercase domain; the local
// part keeps its case.
func validMailbox(email string) bool {
	address, err := mail.ParseAddress(email)
	at := strings.LastIndexByte(email, '@')
	return err == nil && address.Name == "" && address.Address == email && len(email) <= 254 && at >= 1 &&
		email[at+1:] == strings.ToLower(email[at+1:]) &&
		!strings.ContainsFunc(email, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
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
	if resource.CRID != resourceCRID || resource.ConsumerAccess == nil || !resource.ConsumerAccess.Equal(policy) {
		return fmt.Errorf("%w: consumer policy response mismatch", ErrInvalidAPIResponse)
	}
	return nil
}

func consumerCreationPolicyConfirmed(private *bool, actual, expected *ConsumerAccessPolicy, foundExisting bool) bool {
	if expected == nil {
		return true
	}
	if private == nil || !*private || actual == nil || actual.validate() != nil || !actual.SameDefinition(*expected) {
		return false
	}
	return actual.Version == expected.Version || (foundExisting && actual.Version > expected.Version)
}

// Equal includes every policy field, including owner-only mailbox exceptions.
func (p ConsumerAccessPolicy) Equal(other ConsumerAccessPolicy) bool {
	return p.Version == other.Version && p.SameDefinition(other)
}

// SameDefinition compares every field except Version.
func (p ConsumerAccessPolicy) SameDefinition(other ConsumerAccessPolicy) bool {
	return p.Mode == other.Mode && p.ContractID == other.ContractID && p.EmailDomain == other.EmailDomain && p.ApprovalExpiresIn == other.ApprovalExpiresIn && slices.Equal(p.AllowedEmails, other.AllowedEmails)
}
