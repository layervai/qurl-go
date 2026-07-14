package qurl

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// producerConnectorResourceType is the qurl-service discriminator for qURL
// Connector resources. It is deliberately private: customers interact with
// ConnectorResource, not the producer's generic resource taxonomy.
const producerConnectorResourceType = "tunnel"

var (
	// qurl-service's OpenAPI contract intentionally gives immutable connector
	// slugs and mutable aliases the same exact lowercase 3-64 character grammar.
	connectorSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)
	// connectorRoutingIDPattern mirrors qurl-service's opaque, server-derived
	// reverse-connection routing label. The SDK validates and consumes this
	// value verbatim; it must never derive the label from ResourceID.
	connectorRoutingIDPattern = regexp.MustCompile(`^c-[a-z2-7]{52}$`)

	// ErrConnectorResourceNotFound is returned when a qURL Connector resource
	// lookup or deletion cannot find a resource owned by the current credential.
	ErrConnectorResourceNotFound = errors.New("qurl: qURL Connector resource not found")

	// ErrConnectorResourceRevoked is returned when a resource detail row has
	// status revoked. Its slug may be reusable after an ordinary delete.
	ErrConnectorResourceRevoked = errors.New("qurl: qURL Connector resource revoked")

	// ErrConnectorResourceTombstoned is returned for an exact 410
	// resource_tombstoned response. The resource lifecycle is closed and its
	// slug must not be retried as an ordinary revoked-resource reuse.
	ErrConnectorResourceTombstoned = errors.New("qurl: qURL Connector resource tombstoned")

	// ErrConnectorResourceSlugConflict is returned when an idempotent qURL
	// Connector ensure cannot resolve a slug collision to one active resource.
	// The SDK does not retry automatically. A caller may retry this error once;
	// a second conflict requires operator remediation rather than another retry
	// loop.
	ErrConnectorResourceSlugConflict = errors.New("qurl: qURL Connector resource slug conflict")

	// ErrConnectorResourceAmbiguous is returned when a slug lookup violates the
	// producer's zero-or-one cardinality contract.
	ErrConnectorResourceAmbiguous = errors.New("qurl: qURL Connector resource ambiguous")

	// ErrInvalidConnectorResourceResponse is returned when a successful response
	// violates the qURL Connector resource contract. It wraps and therefore also
	// matches ErrInvalidAPIResponse. Neither sentinel is retry advice; inspect the
	// Connector-specific error before deciding whether a retry is safe.
	ErrInvalidConnectorResourceResponse = fmt.Errorf("qurl: invalid qURL Connector resource response: %w", ErrInvalidAPIResponse)

	// ErrConnectorResourceOutcomeUnknown is returned when an ensure or delete was
	// dispatched but the SDK cannot prove whether it committed. A nominal success
	// status with a response that violates the endpoint contract is not accepted
	// as proof of commit. For ensure, reconcile by immutable slug before retrying.
	// For delete, read the resource and reconcile its lifecycle before deciding
	// whether another delete is safe.
	ErrConnectorResourceOutcomeUnknown = errors.New("qurl: qURL Connector resource mutation outcome unknown")
)

// ConnectorResource is a resource managed by qURL Connector. ResourceID and
// Slug are immutable identities. ConnectorRoutingID and KnockResourceID are
// explicit control-plane values for reverse-connection routing and NHP
// admission respectively; neither is an identity or derivable from another
// field. Alias is a separate, mutable display handle. RunID is intentionally
// absent; [NewCycleRunID] creates separate ephemeral correlation. JSON
// persistence cannot preserve the unexported client binding used by
// CreatePortal; call GetConnectorResource or GetConnectorResourceBySlug to
// obtain a newly bound handle.
type ConnectorResource struct {
	client *Client

	// ResourceID is the producer-issued protected-resource P-256 public key in
	// canonical unpadded-base64url DER SPKI form. The SDK validates its wire
	// encoding, DER structure, key type, curve, and point. It is distinct from
	// ConnectorRoutingID and KnockResourceID.
	ResourceID string `json:"resource_id"`
	// ConnectorRoutingID is the opaque routing label returned by the producer.
	// qURL Connector uses it verbatim and never derives it from ResourceID.
	ConnectorRoutingID string `json:"connector_routing_id"`
	// KnockResourceID is the placement-neutral NHP target returned by the
	// producer for qURL Connector admission.
	KnockResourceID string `json:"knock_resource_id"`
	// Slug is the immutable owner-scoped qURL Connector identity.
	Slug string `json:"slug"`
	// Alias is optional mutable display metadata and is never used as identity.
	Alias *string `json:"alias,omitempty"`
}

// EnsureConnectorResourceResult reports the active qURL Connector resource
// selected by EnsureConnectorResource and whether it existed before the request.
type EnsureConnectorResourceResult struct {
	// Resource is the active qURL Connector resource selected by the ensure.
	Resource *ConnectorResource
	// FoundExisting reports whether the producer selected a pre-existing row.
	FoundExisting bool
}

// CreatePortal mints a qURL link for the qURL Connector resource.
func (r *ConnectorResource) CreatePortal(ctx context.Context, opts ...PortalOption) (*Portal, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: qURL Connector resource must not be nil", ErrInvalidPortalRequest)
	}
	if r.client == nil {
		return nil, fmt.Errorf("%w: qURL Connector resource is not bound to a client", ErrInvalidPortalRequest)
	}
	return r.client.CreatePortal(ctx, r.client.ResourceByID(r.ResourceID), opts...)
}

type ensureConnectorResourceRequest struct {
	Type string `json:"type"`
	Slug string `json:"slug"`
	// FindOrCreate is fixed true by the Connector ensure wire contract.
	FindOrCreate bool `json:"find_or_create"`
}

// connectorResourceWire mirrors the producer's generic resource payload. Type
// is validated here and intentionally omitted from the exported SDK entity.
type connectorResourceWire struct {
	ResourceID         string  `json:"resource_id"`
	ConnectorRoutingID string  `json:"connector_routing_id"`
	KnockResourceID    string  `json:"knock_resource_id"`
	Type               string  `json:"type"`
	Status             string  `json:"status"`
	Slug               string  `json:"slug"`
	Alias              *string `json:"alias,omitempty"`
}

// connectorResourceResponse is the create envelope. The producer intentionally
// uses three distinct shapes: create returns a flat data object, detail nests
// data.resource, and slug lookup returns data[]. Keep them separate so one
// endpoint cannot silently accept another endpoint's successful payload.
type connectorResourceResponse struct {
	Data connectorResourceWire `json:"data"`
	Meta struct {
		FoundExisting *bool `json:"found_existing"`
	} `json:"meta"`
}

type connectorResourceExpectation struct {
	slug         string
	resourceID   string
	allowRevoked bool
}

// EnsureConnectorResource finds or creates the active qURL Connector resource
// for slug. The private wire request includes qurl-service's resource type.
// FoundExisting reports whether the service returned an already-active row.
// The SDK does not retry a 409 slug conflict automatically; see
// ErrConnectorResourceSlugConflict for the bounded caller retry contract.
func (c *Client) EnsureConnectorResource(ctx context.Context, slug string) (*EnsureConnectorResourceResult, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorSlug(slug); err != nil {
		return nil, err
	}

	req := ensureConnectorResourceRequest{
		Type:         producerConnectorResourceType,
		Slug:         slug,
		FindOrCreate: true,
	}
	var response connectorResourceResponse
	// The producer returns 201 for both newly-created and found-existing rows.
	// Any other 2xx arrives after a mutation may have committed, so status drift
	// is response ambiguity rather than a benign alternate success.
	if err := c.doJSONStatus(ctx, http.MethodPost, "/v1/resources", req, &response, http.StatusCreated); err != nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationEnsure, err)
	}
	resource, err := response.Data.connectorResource(c, connectorResourceExpectation{
		slug: slug,
	})
	if err != nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationEnsure, err)
	}
	if response.Meta.FoundExisting == nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationEnsure, invalidConnectorResourceResponse("missing meta.found_existing"))
	}
	return &EnsureConnectorResourceResult{
		Resource:      resource,
		FoundExisting: *response.Meta.FoundExisting,
	}, nil
}

// GetConnectorResource fetches a qURL Connector resource by immutable resource
// id.
func (c *Client) GetConnectorResource(ctx context.Context, resourceID string) (*ConnectorResource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorResourceID(resourceID); err != nil {
		return nil, err
	}

	var response apiEnvelope[struct {
		Resource *connectorResourceWire `json:"resource"`
	}]
	path := "/v1/resources/" + url.PathEscape(resourceID)
	if err := c.doJSONStatus(ctx, http.MethodGet, path, nil, &response, http.StatusOK); err != nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationGetByID, err)
	}
	if response.Data.Resource == nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationGetByID,
			invalidConnectorResourceResponse("resource detail has missing or null resource"))
	}
	resource, err := response.Data.Resource.connectorResource(c, connectorResourceExpectation{
		resourceID:   resourceID,
		allowRevoked: true,
	})
	if err != nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationGetByID, err)
	}
	return resource, nil
}

// GetConnectorResourceBySlug fetches the single active qURL Connector resource
// for an immutable owner-scoped slug. Alias is returned as metadata and never
// used as identity.
func (c *Client) GetConnectorResourceBySlug(ctx context.Context, slug string) (*ConnectorResource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorSlug(slug); err != nil {
		return nil, err
	}

	// The producer's slug lookup is server-side active-only and returns 0 or 1
	// row. OpenAPI makes slug mutually exclusive with status/type, so this query
	// must contain only slug; more than one row is true producer ambiguity.
	query := url.Values{}
	query.Set("slug", slug)
	// The pointer data type distinguishes an explicit empty list (not found)
	// from missing or null data (a malformed successful response).
	var response apiEnvelope[*[]connectorResourceWire]
	if err := c.doJSONStatus(ctx, http.MethodGet, "/v1/resources?"+query.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationGetBySlug, err)
	}
	if response.Data == nil {
		return nil, classifyConnectorResourceError(connectorResourceOperationGetBySlug,
			invalidConnectorResourceResponse("resource list has missing or null data"))
	}
	switch len(*response.Data) {
	case 0:
		return nil, classifyConnectorResourceError(connectorResourceOperationGetBySlug,
			fmt.Errorf("%w: slug %q", ErrConnectorResourceNotFound, slug))
	case 1:
		resource, err := (*response.Data)[0].connectorResource(c, connectorResourceExpectation{
			slug: slug,
		})
		if err != nil {
			return nil, classifyConnectorResourceError(connectorResourceOperationGetBySlug, err)
		}
		return resource, nil
	default:
		// The ambiguous and both invalid-response sentinels are intentional:
		// callers can match the cardinality invariant breach, the Connector
		// contract, or the generic successful-response contract.
		return nil, classifyConnectorResourceError(connectorResourceOperationGetBySlug,
			fmt.Errorf("%w: %w", ErrConnectorResourceAmbiguous,
				invalidConnectorResourceResponsef("slug %q returned %d resources", slug, len(*response.Data))))
	}
}

// DeleteConnectorResource revokes a qURL Connector resource by immutable resource id.
// The 204 response has no JSON body; other successful resource methods retain
// the SDK's fail-closed response decoding.
func (c *Client) DeleteConnectorResource(ctx context.Context, resourceID string) error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorResourceID(resourceID); err != nil {
		return err
	}
	path := "/v1/resources/" + url.PathEscape(resourceID)
	if err := c.doNoContent(ctx, http.MethodDelete, path, http.StatusNoContent); err != nil {
		return classifyConnectorResourceError(connectorResourceOperationDelete, err)
	}
	return nil
}

func (r connectorResourceWire) connectorResource(client *Client, expect connectorResourceExpectation) (*ConnectorResource, error) {
	// Validate the complete row before lifecycle classification. qurl-service's
	// shared create/detail/list serializer returns resource_id,
	// connector_routing_id, knock_resource_id, type, and slug for both active and
	// revoked Connector rows; an incomplete revoked row is producer drift.
	if expect.resourceID != "" {
		if r.ResourceID != expect.resourceID {
			return nil, invalidConnectorResourceResponsef("requested resource_id %q returned %q", expect.resourceID, r.ResourceID)
		}
	} else if !isValidConnectorResourceID(r.ResourceID) {
		return nil, invalidConnectorResourceResponse("missing or invalid resource_id")
	}
	if !connectorRoutingIDPattern.MatchString(r.ConnectorRoutingID) {
		return nil, invalidConnectorResourceResponsef("resource %q has missing or invalid connector_routing_id", r.ResourceID)
	}
	// knock_resource_id is an opaque, ASP-defined NHP admission target. The
	// producer owns its grammar; the SDK enforces only transport-safe exact bytes:
	// presence, no surrounding whitespace, and no control characters. Do not add
	// an SDK-local length or placement parser: the capped response bounds input,
	// while the opaque value can evolve without a client release.
	if trimmedKnockID := strings.TrimSpace(r.KnockResourceID); trimmedKnockID == "" {
		return nil, invalidConnectorResourceResponse("missing knock_resource_id")
	} else if r.KnockResourceID != trimmedKnockID {
		return nil, invalidConnectorResourceResponsef("resource %q has knock_resource_id with leading or trailing whitespace", r.ResourceID)
	} else if !utf8.ValidString(r.KnockResourceID) {
		return nil, invalidConnectorResourceResponsef("resource %q has knock_resource_id with invalid UTF-8", r.ResourceID)
	} else if strings.IndexFunc(r.KnockResourceID, unicode.IsControl) >= 0 {
		return nil, invalidConnectorResourceResponsef("resource %q has knock_resource_id with a control character", r.ResourceID)
	}
	// The producer guarantees three distinct identity/routing/admission values.
	// ResourceID and ConnectorRoutingID are already distinct by their disjoint
	// validated grammars. The explicit checks below cover the opaque admission
	// value, whose producer-owned grammar provides no equivalent guarantee.
	// Slug is customer-chosen and is not part of that invariant; it may
	// legitimately equal an otherwise valid routing or admission value.
	if r.ResourceID == r.KnockResourceID ||
		r.ConnectorRoutingID == r.KnockResourceID {
		return nil, invalidConnectorResourceResponsef("resource %q has identity, routing, or admission values cross-wired", r.ResourceID)
	}
	if r.Type != producerConnectorResourceType {
		return nil, invalidConnectorResourceResponsef("resource %q has type %q, want %q", r.ResourceID, r.Type, producerConnectorResourceType)
	}
	if !connectorSlugPattern.MatchString(r.Slug) {
		return nil, invalidConnectorResourceResponsef("resource %q has missing or invalid slug", r.ResourceID)
	}
	if expect.slug != "" && r.Slug != expect.slug {
		return nil, invalidConnectorResourceResponsef("requested slug %q returned %q", expect.slug, r.Slug)
	}
	// Alias is display metadata, but the producer applies the same OpenAPI regex
	// as slug. A grammar change requires a coordinated producer/SDK release.
	if r.Alias != nil && !connectorSlugPattern.MatchString(*r.Alias) {
		return nil, invalidConnectorResourceResponsef("resource %q has an invalid alias", r.ResourceID)
	}
	// The fenced qurl-service ResourceStatus schema is active/revoked only.
	// Anything else is producer drift, not a transitional state to accept.
	if r.Status == "revoked" {
		if !expect.allowRevoked {
			return nil, invalidConnectorResourceResponsef("active-only qURL Connector operation returned revoked resource %q", r.ResourceID)
		}
		return nil, fmt.Errorf("%w: resource %q", ErrConnectorResourceRevoked, r.ResourceID)
	}
	if r.Status != "active" {
		return nil, invalidConnectorResourceResponsef("resource %q has status %q, want active", r.ResourceID, r.Status)
	}
	return &ConnectorResource{
		client:             client,
		ResourceID:         r.ResourceID,
		ConnectorRoutingID: r.ConnectorRoutingID,
		KnockResourceID:    r.KnockResourceID,
		Slug:               r.Slug,
		Alias:              r.Alias,
	}, nil
}

func validateConnectorSlug(slug string) error {
	if !connectorSlugPattern.MatchString(slug) {
		return fmt.Errorf("%w: qURL Connector slug must be 3-64 lowercase alphanumeric or hyphen characters, start with a letter, and end alphanumeric", ErrInvalidResourceRequest)
	}
	return nil
}

func validateConnectorResourceID(resourceID string) error {
	if !isValidConnectorResourceID(resourceID) {
		return fmt.Errorf("%w: qURL Connector resource id must be a canonical unpadded base64url P-256 DER SPKI public key", ErrInvalidResourceRequest)
	}
	return nil
}

func isValidConnectorResourceID(resourceID string) bool {
	der, err := b64url.DecodeString(resourceID)
	if err != nil {
		return false
	}
	// An exact round trip rejects padding, alternate alphabets, embedded CR/LF,
	// non-zero trailing bits, and every other non-canonical spelling.
	if b64url.EncodeToString(der) != resourceID {
		return false
	}
	publicKey, err := ParseP256PublicKeyDER(der)
	if err != nil {
		return false
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	return err == nil && bytes.Equal(canonicalDER, der)
}

// connectorResourceOperation drives lifecycle-specific error classification.
// Ensure and delete are mutations whose post-dispatch failures may have an
// unknown outcome; both getters are side-effect-free reads.
type connectorResourceOperation uint8

const (
	connectorResourceOperationEnsure connectorResourceOperation = iota
	connectorResourceOperationGetByID
	connectorResourceOperationGetBySlug
	connectorResourceOperationDelete
)

func classifyConnectorResourceError(operation connectorResourceOperation, err error) error {
	isMutation := operation == connectorResourceOperationEnsure || operation == connectorResourceOperationDelete
	if isMutation {
		var outcomeUnknown *apiRequestOutcomeUnknownError
		// Preserve the SDK-wide post-dispatch marker for errors.As and add the
		// public Connector reconciliation sentinel for errors.Is. Invalid-response
		// mutations also remain matchable as ErrInvalidAPIResponse and
		// ErrInvalidConnectorResourceResponse below.
		switch {
		case errors.As(err, &outcomeUnknown):
			err = fmt.Errorf("%w: %w", ErrConnectorResourceOutcomeUnknown, err)
		case errors.Is(err, ErrInvalidAPIResponse):
			// Semantic validation after a decoded ensure response reaches this
			// branch; transport/body contract failures already carry the marker.
			err = fmt.Errorf("%w: %w", ErrConnectorResourceOutcomeUnknown, &apiRequestOutcomeUnknownError{err: err})
		}
	}
	if errors.Is(err, ErrInvalidAPIResponse) {
		if errors.Is(err, ErrInvalidConnectorResourceResponse) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrInvalidConnectorResourceResponse, err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	// An authoritative 4xx proves the mutation was rejected. Any surfaced 1xx,
	// 3xx, or 5xx cannot prove whether a dispatched mutation committed; refused
	// redirects are included because the producer may redirect after commit.
	if isMutation && (apiErr.StatusCode < http.StatusBadRequest || apiErr.StatusCode >= http.StatusInternalServerError) {
		return fmt.Errorf("%w: %w", ErrConnectorResourceOutcomeUnknown, err)
	}
	switch operation {
	case connectorResourceOperationEnsure:
		switch {
		case apiErr.StatusCode == http.StatusConflict && apiErr.Code == "slug_in_use":
			return fmt.Errorf("%w: %w", ErrConnectorResourceSlugConflict, err)
		case apiErr.StatusCode == http.StatusGone && apiErr.Code == "resource_tombstoned":
			return fmt.Errorf("%w: %w", ErrConnectorResourceTombstoned, err)
		}
	case connectorResourceOperationGetByID:
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("%w: %w", ErrConnectorResourceNotFound, err)
		case http.StatusGone:
			if apiErr.Code == "resource_tombstoned" {
				return fmt.Errorf("%w: %w", ErrConnectorResourceTombstoned, err)
			}
		}
	case connectorResourceOperationDelete:
		// The producer's DELETE contract is 204/401/404/500 and deliberately
		// permits revoking tombstoned resources with 204. Preserve an unexpected
		// 410 as its raw APIError instead of inventing idempotent-delete semantics.
		if apiErr.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %w", ErrConnectorResourceNotFound, err)
		}
	}
	return err
}

// invalidConnectorResourceResponse reports a decoded Connector contract breach
// without assigning mutation semantics. classifyConnectorResourceError adds the
// outcome-unknown marker for mutations; semantic read failures remain ordinary
// invalid responses because they cannot have committed state.
func invalidConnectorResourceResponse(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConnectorResourceResponse, detail)
}

func invalidConnectorResourceResponsef(format string, args ...any) error {
	return invalidConnectorResourceResponse(fmt.Sprintf(format, args...))
}
