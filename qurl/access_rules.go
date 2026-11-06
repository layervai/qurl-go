package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"
)

// ErrInvalidAccessRules is returned by SaveAccessRules when the library cannot
// be saved: a rule name is not valid UTF-8 (rejected before any request), or
// the service answered 400. A service rejection keeps its *APIError, which
// carries the reason.
var ErrInvalidAccessRules = errors.New("qurl: invalid access rules")

// ErrAccessRulesConflict is returned by SaveAccessRules when the library
// changed since the version that was sent. Read it again, merge, and retry.
// The underlying *APIError remains matchable with errors.As.
var ErrAccessRulesConflict = errors.New("qurl: access rules changed since last read")

const accessRulesPath = "/v1/me/access-rules"

// AccessRule is one saved access-rule preset: the admission policy and share
// settings a client applies when it shares with the rule. Saving or editing a
// rule grants no access and never changes an existing resource or link.
//
// Fields follow the service's AccessRule schema, and the service is the
// authority on their rules: Mode names a consumer access mode or "public";
// EmailDomain and AllowedEmails are for email_domain, ContractID and Payment for
// contract, LinkLimits for public, and ApprovalExpiresIn for review and keys.
// Name is display text; escape it before showing it.
type AccessRule struct {
	ID                string                `json:"id"`
	Name              string                `json:"name"`
	Mode              string                `json:"mode"`
	EmailDomain       string                `json:"email_domain,omitempty"`
	AllowedEmails     []string              `json:"allowed_emails,omitempty"`
	ContractID        string                `json:"contract_id,omitempty"`
	LinkLimits        *AccessRuleLinkLimits `json:"link_limits,omitempty"`
	ApprovalExpiresIn string                `json:"approval_expires_in,omitempty"`
	Payment           *AccessRulePayment    `json:"payment,omitempty"`
}

// AccessRuleLinkLimits makes a public rule share a new temporary link with
// these limits instead of the resource's permanent address. Durations use the
// link-create grammar ("1h", "7d"). A nil OneTimeUse means false; keeping it a
// pointer writes back exactly what was read.
type AccessRuleLinkLimits struct {
	ExpiresIn       string `json:"expires_in"`
	OneTimeUse      *bool  `json:"one_time_use,omitempty"`
	SessionDuration string `json:"session_duration,omitempty"`
}

// AccessRulePayment is a contract rule's Stripe price and access duration: a
// CRIDPaymentPolicy without its account. Saving it checks nothing with Stripe.
// To apply it, send a CRIDPaymentPolicy with the account from
// PublisherStripeAccount and these two values. AccessSeconds zero lasts for the
// resource's lifetime.
type AccessRulePayment struct {
	PriceID       string `json:"price_id"`
	AccessSeconds int64  `json:"access_seconds"`
}

// AccessRules is the authenticated account's rule library. Items are the
// account's own rules; BuiltIns are the service's read-only choices. An empty
// QuickShareRuleID means the client default, "once". AccountID partitions a
// private sync cache.
type AccessRules struct {
	AccountID        string       `json:"account_id"`
	Version          int64        `json:"version"`
	Items            []AccessRule `json:"items"`
	BuiltIns         []AccessRule `json:"built_ins"`
	QuickShareRuleID string       `json:"quick_share_rule_id,omitempty"`
}

// AccessRulesUpdate replaces the custom library at the version last read
// (zero for a new library). Items is the complete library; nil saves none.
//
// An empty QuickShareRuleID keeps the saved quick-share rule (the service
// clears it if the rule it names is removed). Send "once" to restore the
// default, or a catalog default, built-in ID, or the ID of a rule in Items.
type AccessRulesUpdate struct {
	Version          int64        `json:"version"`
	Items            []AccessRule `json:"items"`
	QuickShareRuleID string       `json:"quick_share_rule_id,omitempty"`
}

// AccessRules reads the authenticated account's rule library. The credential
// needs qurl:read; a registered device linked to the account is accepted.
// API failures surface as *APIError; an unlinked anonymous device receives 403
// with code device_not_linked.
func (c *Client) AccessRules(ctx context.Context) (*AccessRules, error) {
	return c.accessRules(ctx, http.MethodGet, nil)
}

// SaveAccessRules replaces the account's custom rules if update.Version still
// matches, and returns the saved library with its new version. A version
// mismatch matches ErrAccessRulesConflict, and a rejected library matches
// ErrInvalidAccessRules. The service validates every rule;
// rule fields this SDK does not model are not preserved. The credential needs
// qurl:write; a registered device linked to the account is accepted.
func (c *Client) SaveAccessRules(ctx context.Context, update AccessRulesUpdate) (*AccessRules, error) {
	// encoding/json replaces malformed UTF-8 with U+FFFD, so an invalid name
	// would be saved as a different name than the caller passed. Name is the
	// only free-text display field; the service validates the others.
	for _, rule := range update.Items {
		if !utf8.ValidString(rule.Name) {
			return nil, fmt.Errorf("%w: rule name is not valid UTF-8", ErrInvalidAccessRules)
		}
	}
	if update.Items == nil {
		update.Items = []AccessRule{} // the service requires an array, not null
	}
	rules, err := c.accessRules(ctx, http.MethodPut, update)
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusConflict:
			return nil, fmt.Errorf("%w: %w", ErrAccessRulesConflict, err)
		case http.StatusBadRequest:
			return nil, fmt.Errorf("%w: %w", ErrInvalidAccessRules, err)
		}
	}
	return rules, err
}

func (c *Client) accessRules(ctx context.Context, method string, body any) (*AccessRules, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	var env apiEnvelope[*accessRulesWire]
	if err := c.doJSONStatus(ctx, method, accessRulesPath, body, &env, http.StatusOK); err != nil {
		return nil, err
	}
	if env.Data == nil || env.Data.AccountID == "" || env.Data.Version == nil || env.Data.Items == nil || env.Data.BuiltIns == nil {
		return nil, fmt.Errorf("%w: incomplete access rules library", ErrInvalidAPIResponse)
	}
	rules := env.Data.AccessRules
	rules.Version = *env.Data.Version
	return &rules, nil
}

// accessRulesWire shadows AccessRules.Version so a missing version fails
// closed instead of reading as a new library.
type accessRulesWire struct {
	AccessRules
	Version *int64 `json:"version"`
}
