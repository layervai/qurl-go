package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ConsumerAccessPolicy selects the publisher's private access flow.
type ConsumerAccessPolicy struct {
	Mode        string             `json:"mode"`
	Version     int64              `json:"version"`
	ContractID  string             `json:"contract_id,omitempty"`
	Payment     *CRIDPaymentPolicy `json:"payment,omitempty"`
	EmailDomain string             `json:"email_domain,omitempty"`
}

func (p ConsumerAccessPolicy) validate() error {
	if p.Version < 1 || p.Version > 9007199254740991 {
		return fmt.Errorf("%w: invalid consumer policy version", ErrInvalidResourceRequest)
	}
	if p.Mode == "email_domain" {
		if len(p.EmailDomain) > 253 || !consumerEmailDomain.MatchString(p.EmailDomain) {
			return fmt.Errorf("%w: email_domain requires one lowercase DNS domain", ErrInvalidResourceRequest)
		}
	} else if p.EmailDomain != "" {
		return fmt.Errorf("%w: email_domain field requires email_domain mode", ErrInvalidResourceRequest)
	}
	if p.Payment != nil && (p.Mode != "contract" || !stripeAccountID.MatchString(p.Payment.AccountID) || !stripePriceID.MatchString(p.Payment.PriceID) || p.Payment.AccessSeconds < 0 || p.Payment.AccessSeconds > 315360000) {
		return fmt.Errorf("%w: invalid Stripe payment policy", ErrInvalidResourceRequest)
	}
	switch p.Mode {
	case "keys", "invite_only", "email_capture", "email_domain", "review":
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
	if resource.CRID != resourceCRID || (policy.Payment != nil && (resource.Private == nil || !*resource.Private)) || resource.ConsumerAccess == nil || !resource.ConsumerAccess.equal(policy) {
		return fmt.Errorf("%w: consumer policy response mismatch", ErrInvalidAPIResponse)
	}
	return nil
}

func consumerCreationPolicyConfirmed(private *bool, actual, expected *ConsumerAccessPolicy, foundExisting bool) bool {
	if expected == nil {
		return true
	}
	if private == nil || !*private || actual == nil || actual.validate() != nil || actual.Mode != expected.Mode || actual.ContractID != expected.ContractID || actual.EmailDomain != expected.EmailDomain || !sameCRIDPayment(actual.Payment, expected.Payment) {
		return false
	}
	return actual.Version == expected.Version || (foundExisting && actual.Version > expected.Version)
}

// CRIDPaymentPolicy attaches a Stripe price to new or existing contract access.
// The publisher must connect this account first. LayerV collects three percent.
type CRIDPaymentPolicy struct {
	AccountID     string `json:"account_id"`
	PriceID       string `json:"price_id"`
	AccessSeconds int64  `json:"access_seconds"`
}

var (
	consumerEmailDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	stripeAccountID     = regexp.MustCompile(`^acct_[A-Za-z0-9]{1,128}$`)
	stripePriceID       = regexp.MustCompile(`^price_[A-Za-z0-9]{1,128}$`)
)

func sameCRIDPayment(a, b *CRIDPaymentPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (p ConsumerAccessPolicy) equal(other ConsumerAccessPolicy) bool {
	return p.Mode == other.Mode && p.Version == other.Version && p.ContractID == other.ContractID && p.EmailDomain == other.EmailDomain && sameCRIDPayment(p.Payment, other.Payment)
}

// ConnectPublisherStripe returns the Stripe-hosted publisher consent URL.
func (c *Client) ConnectPublisherStripe(ctx context.Context) (string, error) {
	link, err := c.connectPublisherStripe(ctx, "/v1/payments/connect")
	if err != nil {
		return "", err
	}
	return link.String(), nil
}

// ConnectPublisherStripeForDevice returns Stripe consent with a local browser return.
func (c *Client) ConnectPublisherStripeForDevice(ctx context.Context, port int) (string, error) {
	if port < 1024 || port > 65535 {
		return "", fmt.Errorf("%w: invalid Stripe return port", ErrInvalidResourceRequest)
	}
	link, err := c.connectPublisherStripe(ctx, "/v1/payments/connect?loopback_port="+strconv.Itoa(port))
	if err != nil {
		return "", err
	}
	statePort, valid := publisherStripeReturnPort(link.Query().Get("state"))
	if link.Path != "/oauth/authorize" || !valid || statePort != port {
		return "", ErrInvalidAPIResponse
	}
	return link.String(), nil
}

func (c *Client) connectPublisherStripe(ctx context.Context, path string) (*url.URL, error) {
	var response apiEnvelope[struct {
		URL string `json:"url"`
	}]
	if err := c.doJSONStatus(ctx, http.MethodPost, path, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	u, err := url.Parse(response.Data.URL)
	if err != nil || u.Scheme != "https" || u.Host != "connect.stripe.com" || u.User != nil {
		return nil, ErrInvalidAPIResponse
	}
	return u, nil
}

var publisherStripeNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func publisherStripeReturnPort(state string) (int, bool) {
	nonce, suffix, loopback := strings.Cut(state, ".")
	if !publisherStripeNonce.MatchString(nonce) {
		return 0, false
	}
	if !loopback {
		return 0, true
	}
	port, err := strconv.Atoi(suffix)
	return port, err == nil && port >= 1024 && port <= 65535 && strconv.Itoa(port) == suffix
}

// CompletePublisherStripe binds Stripe consent to the authenticated publisher.
func (c *Client) CompletePublisherStripe(ctx context.Context, state, code string) error {
	if _, valid := publisherStripeReturnPort(state); !valid || len(code) < 1 || len(code) > 1024 {
		return fmt.Errorf("%w: invalid Stripe consent return", ErrInvalidResourceRequest)
	}
	body := struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}{State: state, Code: code}
	var response apiEnvelope[struct{}]
	return c.doJSONStatus(ctx, http.MethodPost, "/v1/payments/connect/complete", body, &response, http.StatusOK)
}

// CreatePublisherStripePrice creates or reuses a price on the caller's connected
// Stripe account. Amount is in US cents. An empty interval means pay once.
func (c *Client) CreatePublisherStripePrice(ctx context.Context, name string, amount int64, interval string) (*CRIDPaymentPolicy, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 100 || strings.ContainsFunc(name, unicode.IsControl) ||
		amount < 50 || amount > 99999999 || (interval != "" && interval != "month" && interval != "year") {
		return nil, fmt.Errorf("%w: invalid Stripe price", ErrInvalidResourceRequest)
	}
	body := struct {
		Name     string `json:"name"`
		Amount   int64  `json:"amount"`
		Interval string `json:"interval,omitempty"`
	}{Name: name, Amount: amount, Interval: interval}
	var response apiEnvelope[CRIDPaymentPolicy]
	if err := c.doJSONStatus(ctx, http.MethodPost, "/v1/payments/prices", body, &response, http.StatusOK); err != nil {
		return nil, err
	}
	policy := response.Data
	if !stripeAccountID.MatchString(policy.AccountID) || !stripePriceID.MatchString(policy.PriceID) || policy.AccessSeconds != 0 {
		return nil, ErrInvalidAPIResponse
	}
	return &policy, nil
}

// PublisherStripeAccount returns the account connected by this publisher.
func (c *Client) PublisherStripeAccount(ctx context.Context) (string, error) {
	var response apiEnvelope[struct {
		AccountID  string `json:"account_id"`
		FeePercent int    `json:"layerv_fee_percent"`
	}]
	if err := c.doJSONStatus(ctx, http.MethodGet, "/v1/payments/account", nil, &response, http.StatusOK); err != nil {
		return "", err
	}
	if response.Data.FeePercent != 3 || (response.Data.AccountID != "" && !stripeAccountID.MatchString(response.Data.AccountID)) {
		return "", ErrInvalidAPIResponse
	}
	return response.Data.AccountID, nil
}
