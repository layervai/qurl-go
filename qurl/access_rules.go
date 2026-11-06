package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
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
//
// Fields this SDK does not model, such as ones a newer service adds, are kept
// in Unknown (and in the nested settings' Unknown) exactly as read and sent
// back unchanged. Check HasUnknownFields before editing or applying a rule: a
// setting dropped because it is not understood could share more openly than
// the rule says. Listing, saving back unchanged and deleting are safe.
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
	// Unknown holds the rule fields this SDK does not model, by JSON name.
	// A name the SDK models, in any case, is refused when the rule is written.
	Unknown map[string]json.RawMessage `json:"-"`
}

// HasUnknownFields reports whether the rule, its link limits or its payment
// holds a field this SDK does not model.
func (r AccessRule) HasUnknownFields() bool {
	return len(r.Unknown) > 0 || r.LinkLimits != nil && len(r.LinkLimits.Unknown) > 0 || r.Payment != nil && len(r.Payment.Unknown) > 0
}

// MarshalJSON writes the rule's fields, then Unknown.
func (r AccessRule) MarshalJSON() ([]byte, error) {
	type plain AccessRule
	return marshalKeepingUnknown(plain(r), r.Unknown)
}

// UnmarshalJSON reads the rule, keeping fields this SDK does not model in Unknown.
func (r *AccessRule) UnmarshalJSON(data []byte) error {
	type plain AccessRule
	return unmarshalKeepingUnknown(data, (*plain)(r), &r.Unknown)
}

// AccessRuleLinkLimits makes a public rule share a new temporary link with
// these limits instead of the resource's permanent address. Durations use the
// link-create grammar ("1h", "7d"). A nil OneTimeUse means false; keeping it a
// pointer writes back exactly what was read.
type AccessRuleLinkLimits struct {
	ExpiresIn       string `json:"expires_in"`
	OneTimeUse      *bool  `json:"one_time_use,omitempty"`
	SessionDuration string `json:"session_duration,omitempty"`
	// Unknown holds the fields this SDK does not model; see AccessRule.
	Unknown map[string]json.RawMessage `json:"-"`
}

// MarshalJSON writes the limits, then Unknown.
func (l AccessRuleLinkLimits) MarshalJSON() ([]byte, error) {
	type plain AccessRuleLinkLimits
	return marshalKeepingUnknown(plain(l), l.Unknown)
}

// UnmarshalJSON reads the limits, keeping fields this SDK does not model in Unknown.
func (l *AccessRuleLinkLimits) UnmarshalJSON(data []byte) error {
	type plain AccessRuleLinkLimits
	return unmarshalKeepingUnknown(data, (*plain)(l), &l.Unknown)
}

// AccessRulePayment is a contract rule's Stripe price and access duration: a
// CRIDPaymentPolicy without its account. Saving it checks nothing with Stripe.
// To apply it, send a CRIDPaymentPolicy with the account from
// PublisherStripeAccount and these two values. AccessSeconds zero lasts for the
// resource's lifetime.
type AccessRulePayment struct {
	PriceID       string `json:"price_id"`
	AccessSeconds int64  `json:"access_seconds"`
	// Unknown holds the fields this SDK does not model; see AccessRule.
	Unknown map[string]json.RawMessage `json:"-"`
}

// MarshalJSON writes the payment, then Unknown.
func (p AccessRulePayment) MarshalJSON() ([]byte, error) {
	type plain AccessRulePayment
	return marshalKeepingUnknown(plain(p), p.Unknown)
}

// UnmarshalJSON reads the payment, keeping fields this SDK does not model in Unknown.
func (p *AccessRulePayment) UnmarshalJSON(data []byte) error {
	type plain AccessRulePayment
	return unmarshalKeepingUnknown(data, (*plain)(p), &p.Unknown)
}

// marshalKeepingUnknown writes v's JSON object with unknown's members appended.
// A member named like one of v's fields, in any case, is refused: the service
// would read it as that field.
func marshalKeepingUnknown(v any, unknown map[string]json.RawMessage) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil || len(unknown) == 0 {
		return data, err
	}
	for name := range unknown {
		if field := modeledField(reflect.TypeOf(v), name); field != "" {
			return nil, fmt.Errorf("qurl: unknown access rule field %q names the field %q", name, field)
		}
	}
	extra, err := json.Marshal(unknown)
	if err != nil {
		return nil, err
	}
	if string(data) == "{}" {
		return extra, nil
	}
	return append(append(data[:len(data)-1], ','), extra[1:]...), nil
}

// modeledField returns the JSON name of struct t's field that name matches
// ignoring case, as encoding/json matches it, or "" when none does.
func modeledField(t reflect.Type, name string) string {
	for i := range t.NumField() {
		if tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); tag != "-" && strings.EqualFold(tag, name) {
			return tag
		}
	}
	return ""
}

// unmarshalKeepingUnknown decodes data into the struct v points to and puts
// every member that names none of its fields in *unknown (nil when none).
// encoding/json matches names ignoring case, so a member that differs from a
// field's name only in case is refused rather than read as that field.
func unmarshalKeepingUnknown(data []byte, v any, unknown *map[string]json.RawMessage) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	t := reflect.TypeOf(v).Elem()
	for name := range fields {
		switch field := modeledField(t, name); field {
		case "":
		case name:
			delete(fields, name)
		default:
			return fmt.Errorf("qurl: access rule field %q differs from %q only in case", name, field)
		}
	}
	*unknown = nil
	if len(fields) > 0 {
		*unknown = fields
	}
	return nil
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
// ErrInvalidAccessRules. The service validates every rule; each rule's Unknown
// fields are sent as they are. The credential needs
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
