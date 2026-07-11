package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const tunnelResourceType = "tunnel"

var (
	// qurl-service's OpenAPI contract intentionally gives immutable tunnel slugs
	// and mutable aliases the same exact lowercase 3-64 character grammar.
	tunnelSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)
	// The /v1/resources/{id} producer contract pins exactly 11 characters after
	// the r_ prefix. Keep this coupled to the fenced OpenAPI provenance in tests.
	tunnelResourceIDPattern = regexp.MustCompile(`^r_[a-z0-9_-]{11}$`)

	// ErrTunnelResourceNotFound is returned when a tunnel resource lookup or
	// deletion cannot find a resource owned by the current credential.
	ErrTunnelResourceNotFound = errors.New("qurl: tunnel resource not found")

	// ErrTunnelResourceRevoked is returned when a resource lookup observes a
	// revoked row or a 410 tombstone. An ordinary DELETE-revoked slug may be
	// reusable; the 410 case is the distinct lifecycle-closed state.
	ErrTunnelResourceRevoked = errors.New("qurl: tunnel resource revoked")

	// ErrTunnelResourceSlugConflict is returned when an idempotent tunnel
	// ensure cannot resolve a slug collision to one active resource. The SDK
	// does not retry automatically. A caller may retry this error once; a second
	// conflict requires operator remediation rather than another retry loop.
	ErrTunnelResourceSlugConflict = errors.New("qurl: tunnel resource slug conflict")

	// ErrInvalidTunnelResourceResponse is returned when a successful response
	// violates the qURL Connector resource contract.
	ErrInvalidTunnelResourceResponse = errors.New("qurl: invalid tunnel resource response")

	// ErrTunnelResourceOutcomeUnknown is returned when an ensure or delete was
	// dispatched but the SDK cannot prove whether it committed. For ensure,
	// reconcile by immutable slug before retrying. For delete, read the resource
	// and reconcile its lifecycle before deciding whether another delete is safe.
	ErrTunnelResourceOutcomeUnknown = errors.New("qurl: tunnel resource mutation outcome unknown")
)

// TunnelResource is a qURL Connector reverse-tunnel resource. ResourceID and
// Slug are immutable identities. Alias is a separate, mutable display handle.
// JSON persistence cannot preserve the unexported client binding used by
// CreatePortal; call GetTunnelResource or GetTunnelResourceBySlug to obtain a
// newly bound handle.
type TunnelResource struct {
	client *Client

	ResourceID      string  `json:"resource_id"`
	KnockResourceID string  `json:"knock_resource_id"`
	Type            string  `json:"type"`
	Status          string  `json:"status"`
	Slug            string  `json:"slug"`
	Alias           *string `json:"alias,omitempty"`
}

// EnsureTunnelResourceResult reports the active tunnel resource selected by
// EnsureTunnelResource and whether it existed before the request.
type EnsureTunnelResourceResult struct {
	Resource      *TunnelResource
	FoundExisting bool
}

// CreatePortal mints a qURL link for the tunnel resource.
func (r *TunnelResource) CreatePortal(ctx context.Context, opts ...PortalOption) (*Portal, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: tunnel resource must not be nil", ErrInvalidPortalRequest)
	}
	if r.client == nil {
		return nil, fmt.Errorf("%w: tunnel resource is not bound to a client", ErrInvalidPortalRequest)
	}
	return r.client.CreatePortal(ctx, r.resourceHandle(), opts...)
}

func (r *TunnelResource) resourceHandle() *Resource {
	if r == nil {
		return nil
	}
	return &Resource{
		client:          r.client,
		ID:              r.ResourceID,
		Type:            r.Type,
		KnockResourceID: r.KnockResourceID,
		Slug:            r.Slug,
		Status:          r.Status,
		Alias:           r.Alias,
	}
}

type ensureTunnelResourceRequest struct {
	Type         string `json:"type"`
	Slug         string `json:"slug"`
	FindOrCreate bool   `json:"find_or_create"`
}

type tunnelResourceMeta struct {
	FoundExisting *bool `json:"found_existing"`
}

type tunnelResourceResponse struct {
	Data TunnelResource     `json:"data"`
	Meta tunnelResourceMeta `json:"meta"`
}

type tunnelResourceListResponse struct {
	// Pointer distinguishes the explicit empty list (not found) from missing or
	// null data (a malformed successful response).
	Data *[]TunnelResource `json:"data"`
}

type tunnelResourceDetailResponse struct {
	Data struct {
		Resource TunnelResource `json:"resource"`
	} `json:"data"`
}

// EnsureTunnelResource finds or creates the active tunnel resource for slug.
// It sends exactly {"type":"tunnel","slug":slug,"find_or_create":true}.
// FoundExisting reports whether the service returned an already-active row.
// The SDK does not retry a 409 slug conflict automatically; see
// ErrTunnelResourceSlugConflict for the bounded caller retry contract.
func (c *Client) EnsureTunnelResource(ctx context.Context, slug string) (*EnsureTunnelResourceResult, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTunnelSlug(slug); err != nil {
		return nil, err
	}

	req := ensureTunnelResourceRequest{
		Type:         tunnelResourceType,
		Slug:         slug,
		FindOrCreate: true,
	}
	var response tunnelResourceResponse
	// The producer returns 201 for both newly-created and found-existing rows.
	// Any other 2xx arrives after a mutation may have committed, so status drift
	// is response ambiguity rather than a benign alternate success.
	if err := c.doJSONStatus(ctx, http.MethodPost, "/v1/resources", req, &response, http.StatusCreated); err != nil {
		return nil, classifyTunnelResourceError(tunnelResourceOperationEnsure, err)
	}
	if response.Meta.FoundExisting == nil {
		return nil, classifyTunnelResourceError(tunnelResourceOperationEnsure, ensureTunnelResourceOutcomeUnknown(invalidTunnelResourceResponse("missing meta.found_existing")))
	}
	resource, err := response.Data.tunnelResource(c, slug, "", tunnelResourceOperationEnsure)
	if err != nil {
		return nil, classifyTunnelResourceError(tunnelResourceOperationEnsure, ensureTunnelResourceOutcomeUnknown(err))
	}
	return &EnsureTunnelResourceResult{
		Resource:      resource,
		FoundExisting: *response.Meta.FoundExisting,
	}, nil
}

// GetTunnelResource fetches a tunnel resource by immutable resource id.
func (c *Client) GetTunnelResource(ctx context.Context, resourceID string) (*TunnelResource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTunnelResourceID(resourceID); err != nil {
		return nil, err
	}

	var response tunnelResourceDetailResponse
	path := "/v1/resources/" + url.PathEscape(resourceID)
	if err := c.doJSONStatus(ctx, http.MethodGet, path, nil, &response, http.StatusOK); err != nil {
		return nil, classifyTunnelResourceError(tunnelResourceOperationGetByID, err)
	}
	return response.Data.Resource.tunnelResource(c, "", resourceID, tunnelResourceOperationGetByID)
}

// GetTunnelResourceBySlug fetches the single active tunnel resource for an
// immutable owner-scoped slug. Alias is returned as metadata and never used as
// identity.
func (c *Client) GetTunnelResourceBySlug(ctx context.Context, slug string) (*TunnelResource, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTunnelSlug(slug); err != nil {
		return nil, err
	}

	// The producer's slug lookup is server-side active-only and returns 0 or 1
	// row. OpenAPI makes slug mutually exclusive with status/type, so this query
	// must contain only slug; more than one row is true producer ambiguity.
	query := url.Values{}
	query.Set("slug", slug)
	var response tunnelResourceListResponse
	if err := c.doJSONStatus(ctx, http.MethodGet, "/v1/resources?"+query.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, classifyTunnelResourceError(tunnelResourceOperationGetBySlug, err)
	}
	if response.Data == nil {
		return nil, invalidTunnelResourceResponse("resource list has missing or null data")
	}
	switch len(*response.Data) {
	case 0:
		return nil, fmt.Errorf("%w: slug %q", ErrTunnelResourceNotFound, slug)
	case 1:
		return (*response.Data)[0].tunnelResource(c, slug, "", tunnelResourceOperationGetBySlug)
	default:
		// Both sentinels are intentional: callers can match the cardinality
		// invariant breach or the broader invalid-response contract.
		return nil, fmt.Errorf("%w: %w: slug %q returned %d resources", ErrAmbiguousResource, ErrInvalidTunnelResourceResponse, slug, len(*response.Data))
	}
}

// DeleteTunnelResource revokes a tunnel resource by immutable resource id.
// The 204 response has no JSON body; other successful resource methods retain
// the SDK's fail-closed response decoding.
func (c *Client) DeleteTunnelResource(ctx context.Context, resourceID string) error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateTunnelResourceID(resourceID); err != nil {
		return err
	}
	path := "/v1/resources/" + url.PathEscape(resourceID)
	if err := c.doNoContent(ctx, http.MethodDelete, path, http.StatusNoContent); err != nil {
		return classifyTunnelResourceError(tunnelResourceOperationDelete, err)
	}
	return nil
}

func (r TunnelResource) tunnelResource(client *Client, expectedSlug, expectedID string, operation tunnelResourceOperation) (*TunnelResource, error) {
	if !tunnelResourceIDPattern.MatchString(r.ResourceID) {
		return nil, invalidTunnelResourceResponse("missing or invalid resource_id")
	}
	if expectedID != "" && r.ResourceID != expectedID {
		return nil, invalidTunnelResourceResponse("requested resource_id %q returned %q", expectedID, r.ResourceID)
	}
	if trimmedKnockID := strings.TrimSpace(r.KnockResourceID); trimmedKnockID == "" {
		return nil, invalidTunnelResourceResponse("missing knock_resource_id")
	} else if r.KnockResourceID != trimmedKnockID {
		return nil, invalidTunnelResourceResponse("resource %q has knock_resource_id with leading or trailing whitespace", r.ResourceID)
	}
	if r.Type != tunnelResourceType {
		return nil, invalidTunnelResourceResponse("resource %q has type %q, want %q", r.ResourceID, r.Type, tunnelResourceType)
	}
	// The fenced qurl-service ResourceStatus schema is active/revoked only.
	// Anything else is producer drift, not a transitional state to accept.
	if r.Status == "revoked" {
		if operation != tunnelResourceOperationGetByID {
			return nil, invalidTunnelResourceResponse("active-only tunnel operation returned revoked resource %q", r.ResourceID)
		}
		return nil, fmt.Errorf("%w: resource %q", ErrTunnelResourceRevoked, r.ResourceID)
	}
	if r.Status != "active" {
		return nil, invalidTunnelResourceResponse("resource %q has status %q, want active", r.ResourceID, r.Status)
	}
	if !tunnelSlugPattern.MatchString(r.Slug) {
		return nil, invalidTunnelResourceResponse("resource %q has missing or invalid slug", r.ResourceID)
	}
	if expectedSlug != "" && r.Slug != expectedSlug {
		return nil, invalidTunnelResourceResponse("requested slug %q returned %q", expectedSlug, r.Slug)
	}
	// Alias is display metadata rather than identity, but the producer's alias
	// field is still constrained by the same exact OpenAPI regex as slug.
	if r.Alias != nil && !tunnelSlugPattern.MatchString(*r.Alias) {
		return nil, invalidTunnelResourceResponse("resource %q has an invalid alias", r.ResourceID)
	}
	r.client = client
	return &r, nil
}

func validateTunnelSlug(slug string) error {
	if !tunnelSlugPattern.MatchString(slug) {
		return fmt.Errorf("%w: tunnel slug must be 3-64 lowercase alphanumeric or hyphen characters, start with a letter, and end alphanumeric", ErrInvalidResourceRequest)
	}
	return nil
}

func validateTunnelResourceID(resourceID string) error {
	if !tunnelResourceIDPattern.MatchString(resourceID) {
		return fmt.Errorf("%w: tunnel resource id must match r_ followed by 11 lowercase alphanumeric, underscore, or hyphen characters", ErrInvalidResourceRequest)
	}
	return nil
}

type tunnelResourceOperation uint8

const (
	tunnelResourceOperationEnsure tunnelResourceOperation = iota
	tunnelResourceOperationGetByID
	tunnelResourceOperationGetBySlug
	tunnelResourceOperationDelete
)

func classifyTunnelResourceError(operation tunnelResourceOperation, err error) error {
	isMutation := operation == tunnelResourceOperationEnsure || operation == tunnelResourceOperationDelete
	if isMutation {
		var outcomeUnknown *apiRequestOutcomeUnknownError
		if errors.As(err, &outcomeUnknown) {
			err = fmt.Errorf("%w: %w", ErrTunnelResourceOutcomeUnknown, err)
		}
	}
	if errors.Is(err, ErrInvalidAPIResponse) {
		return fmt.Errorf("%w: %w", ErrInvalidTunnelResourceResponse, err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if isMutation && apiErr.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("%w: %w", ErrTunnelResourceOutcomeUnknown, err)
	}
	switch operation {
	case tunnelResourceOperationEnsure:
		switch {
		case apiErr.StatusCode == http.StatusConflict && apiErr.Code == "slug_in_use":
			return fmt.Errorf("%w: %w", ErrTunnelResourceSlugConflict, err)
		case apiErr.StatusCode == http.StatusGone && apiErr.Code == "resource_tombstoned":
			return fmt.Errorf("%w: %w", ErrTunnelResourceRevoked, err)
		}
	case tunnelResourceOperationGetByID:
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("%w: %w", ErrTunnelResourceNotFound, err)
		case http.StatusGone:
			if apiErr.Code != "resource_tombstoned" {
				return err
			}
			return fmt.Errorf("%w: %w", ErrTunnelResourceRevoked, err)
		}
	case tunnelResourceOperationDelete:
		if apiErr.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %w", ErrTunnelResourceNotFound, err)
		}
	case tunnelResourceOperationGetBySlug:
		// Slug lookup is a 200 list contract. Its only not-found signal is an
		// empty data array; preserve every non-2xx response as its raw APIError.
	}
	return err
}

func ensureTunnelResourceOutcomeUnknown(err error) error {
	var outcomeUnknown *apiRequestOutcomeUnknownError
	if errors.As(err, &outcomeUnknown) {
		return err
	}
	return &apiRequestOutcomeUnknownError{err: err}
}

func invalidTunnelResourceResponse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTunnelResourceResponse, fmt.Sprintf(format, args...))
}
