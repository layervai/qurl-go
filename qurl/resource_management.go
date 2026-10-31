package qurl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/layervai/qurl-go/crid"
)

// ManagementMeta preserves correlation and pagination without inventing omitted values.
type ManagementMeta struct {
	RequestID  string `json:"request_id,omitempty"`
	PageSize   *int   `json:"page_size,omitempty"`
	HasMore    *bool  `json:"has_more,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// ManagementResponse preserves the service envelope and correlation metadata.
type ManagementResponse[T any] struct {
	Data *T             `json:"data"`
	Meta ManagementMeta `json:"meta"`
}

// ManagementPage is one service page. An empty filtered page can still have a cursor.
type ManagementPage[T any] struct {
	Data []T            `json:"data"`
	Meta ManagementMeta `json:"meta"`
}

// ManagedResource is management metadata, not a bound URL publishing handle.
// Optional content fields stay absent on connector-owned upload responses.
type ManagedResource struct {
	ResourceID            string                `json:"resource_id,omitempty"`
	CRID                  string                `json:"crid,omitempty"`
	Type                  string                `json:"type,omitempty"`
	Status                string                `json:"status,omitempty"`
	TargetURL             *string               `json:"target_url,omitempty"`
	Description           *string               `json:"description,omitempty"`
	Tags                  []string              `json:"tags,omitempty"`
	CustomDomain          *string               `json:"custom_domain,omitempty"`
	Alias                 *string               `json:"alias,omitempty"`
	Slug                  *string               `json:"slug,omitempty"`
	PreserveHost          *bool                 `json:"preserve_host,omitempty"`
	Private               *bool                 `json:"private,omitempty"`
	AccessRequests        *bool                 `json:"access_requests,omitempty"`
	ConsumerAccess        *ConsumerAccessPolicy `json:"consumer_access,omitempty"`
	ConsumerAccessVersion *int64                `json:"consumer_access_version,omitempty"`
	AllowedDeviceKeys     []string              `json:"allowed_device_keys,omitempty"`
	SessionDurationCap    *int64                `json:"session_duration_cap,omitempty"`
	QURLCount             *int64                `json:"qurl_count,omitempty"`
	DesiredState          string                `json:"desired_state,omitempty"`
	ServingEpoch          *int64                `json:"serving_epoch,omitempty"`
	KnockResourceID       string                `json:"knock_resource_id,omitempty"`
	ConnectorRoutingID    string                `json:"connector_routing_id,omitempty"`
	CreatedAt             *time.Time            `json:"created_at,omitempty"`
	ExpiresAt             *time.Time            `json:"expires_at,omitempty"`
	TombstonedAt          *time.Time            `json:"tombstoned_at,omitempty"`
}

// PortalSummary describes an existing link, not a mint receipt or bearer token.
// Label and TargetPath remain absent when the management API redacts upload content.
type PortalSummary struct {
	QURLID          string     `json:"qurl_id"`
	Label           *string    `json:"label,omitempty"`
	Status          string     `json:"status,omitempty"`
	OneTimeUse      *bool      `json:"one_time_use,omitempty"`
	MaxSessions     *int       `json:"max_sessions,omitempty"`
	SessionDuration *int64     `json:"session_duration,omitempty"`
	UseCount        *int64     `json:"use_count,omitempty"`
	QURLSite        string     `json:"qurl_site,omitempty"`
	TargetPath      *string    `json:"target_path,omitempty"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// ResourceDetail includes only a bounded, unordered link preview. Use ListPortals
// for the complete paginated set; absence from this preview is not revocation.
type ResourceDetail struct {
	Resource *ManagedResource `json:"resource"`
	QURLs    []PortalSummary  `json:"qurls,omitempty"`
}

// ResourceListOptions filters one resource page. Omitted Status does not add an
// active-only filter. Limit zero leaves the service default in force.
type ResourceListOptions struct {
	Cursor string
	Limit  int
	Alias  string
	Slug   string
	Status []string
	Type   string
}

// PageOptions selects one link page.
type PageOptions struct {
	Cursor string
	Limit  int
}

// ResourceUpdate uses pointers so omitted fields differ from explicit empty values.
// Set ClearAlias to send JSON null; Alias and ClearAlias are mutually exclusive.
// The service validates field bounds and consumer-policy update combinations.
type ResourceUpdate struct {
	Description                   *string               `json:"description,omitempty"`
	Tags                          *[]string             `json:"tags,omitempty"`
	CustomDomain                  *string               `json:"custom_domain,omitempty"`
	PreserveHost                  *bool                 `json:"preserve_host,omitempty"`
	Alias                         *string               `json:"alias,omitempty"`
	ClearAlias                    bool                  `json:"-"`
	ConsumerAccess                *ConsumerAccessPolicy `json:"consumer_access,omitempty"`
	ExpectedConsumerAccessVersion *int64                `json:"expected_consumer_access_version,omitempty"`
	AccessRequests                *bool                 `json:"access_requests,omitempty"`
	AllowedDeviceKeys             *[]string             `json:"allowed_device_keys,omitempty"`
	AllowedDeviceKeysAdd          *[]string             `json:"allowed_device_keys_add,omitempty"`
	AllowedDeviceKeysRemove       *[]string             `json:"allowed_device_keys_remove,omitempty"`
}

// MarshalJSON preserves the API's omitted/string/null alias update semantics.
func (u ResourceUpdate) MarshalJSON() ([]byte, error) {
	type plain ResourceUpdate
	if u.ClearAlias {
		if u.Alias != nil {
			return nil, fmt.Errorf("%w: Alias and ClearAlias conflict", ErrInvalidResourceRequest)
		}
		return json.Marshal(struct {
			plain
			Alias any `json:"alias"`
		}{plain: plain(u)})
	}
	return json.Marshal(plain(u))
}

// ResourceSession is an observed management-API session, not native CLOSED evidence.
type ResourceSession struct {
	SessionID  string     `json:"session_id"`
	QURLID     string     `json:"qurl_id,omitempty"`
	SourceIP   string     `json:"src_ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// SessionTerminationPage reports one bounded bulk-termination request.
// Continue with Meta.NextCursor; a single page does not mean every session closed.
type SessionTerminationPage struct {
	Data *struct {
		Terminated *int64 `json:"terminated"`
	} `json:"data"`
	Meta ManagementMeta `json:"meta"`
}

func managementPath(c *Client, id string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if crid.Validate(id) != nil && !isValidConnectorResourceID(id) {
		return "", fmt.Errorf("%w: use a valid CRID or legacy resource public key", ErrInvalidResourceRequest)
	}
	return "/v1/resources/" + url.PathEscape(id), nil
}

func managementQuery(cursor string, limit int) (url.Values, error) {
	if limit < 0 || limit > 100 {
		return nil, fmt.Errorf("%w: page limit must be 1-100 or omitted", ErrInvalidResourceRequest)
	}
	q := make(url.Values)
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit != 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return q, nil
}

func validateManagedResource(r *ManagedResource) error {
	if r == nil || (r.CRID == "" && r.ResourceID == "") ||
		(r.CRID != "" && crid.Validate(r.CRID) != nil) ||
		(r.ResourceID != "" && !isValidConnectorResourceID(r.ResourceID)) ||
		(r.CRID != "" && r.ResourceID != "" && !nativeConnectorCRIDMatches(r.CRID, r.ResourceID)) {
		return fmt.Errorf("%w: missing or invalid resource identity", ErrInvalidAPIResponse)
	}
	return nil
}

func validateManagementMeta(meta ManagementMeta) error {
	if meta.PageSize != nil && *meta.PageSize < 0 {
		return fmt.Errorf("%w: negative management page size", ErrInvalidAPIResponse)
	}
	if meta.HasMore != nil && *meta.HasMore && meta.NextCursor == "" {
		return fmt.Errorf("%w: incomplete management pagination", ErrInvalidAPIResponse)
	}
	return nil
}

// ListResources returns one page; cursor and filters remain caller-owned.
func (c *Client) ListResources(ctx context.Context, options ResourceListOptions) (*ManagementPage[ManagedResource], error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	q, err := managementQuery(options.Cursor, options.Limit)
	if err != nil {
		return nil, err
	}
	if options.Alias != "" {
		q.Set("alias", options.Alias)
	}
	if options.Slug != "" {
		q.Set("slug", options.Slug)
	}
	if len(options.Status) > 0 {
		q.Set("status", strings.Join(options.Status, ","))
	}
	if options.Type != "" {
		q.Set("type", options.Type)
	}
	var response ManagementPage[ManagedResource]
	if err := c.doJSONStatus(ctx, http.MethodGet, "/v1/resources?"+q.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, fmt.Errorf("%w: resource page has no array", ErrInvalidAPIResponse)
	}
	for i := range response.Data {
		if err := validateManagedResource(&response.Data[i]); err != nil {
			return nil, err
		}
	}
	if err := validateManagementMeta(response.Meta); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetResource reads resource metadata and its bounded link preview.
func (c *Client) GetResource(ctx context.Context, id string) (*ManagementResponse[ResourceDetail], error) {
	path, err := managementPath(c, id)
	if err != nil {
		return nil, err
	}
	var response ManagementResponse[ResourceDetail]
	if err := c.doJSONStatus(ctx, http.MethodGet, path, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, fmt.Errorf("%w: missing resource detail", ErrInvalidAPIResponse)
	}
	if err := validateManagedResource(response.Data.Resource); err != nil {
		return nil, err
	}
	r := response.Data.Resource
	if r.CRID != id && r.ResourceID != id {
		return nil, fmt.Errorf("%w: resource identity differs from request", ErrInvalidAPIResponse)
	}
	for _, portal := range response.Data.QURLs {
		if err := validateResourceItemID(portal.QURLID, ErrInvalidAPIResponse); err != nil {
			return nil, err
		}
	}
	return &response, nil
}

// UpdateResource changes resource metadata. Privacy cannot change after creation.
func (c *Client) UpdateResource(ctx context.Context, id string, update ResourceUpdate) (*ManagementResponse[ManagedResource], error) {
	path, err := managementPath(c, id)
	if err != nil {
		return nil, err
	}
	if update == (ResourceUpdate{}) {
		return nil, fmt.Errorf("%w: resource update is empty", ErrInvalidResourceRequest)
	}
	var response ManagementResponse[ManagedResource]
	if err := c.doJSONStatus(ctx, http.MethodPatch, path, update, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if err := validateManagedResource(response.Data); err != nil {
		return nil, invalidAPIResponseOutcome("invalid resource update response", err)
	}
	if response.Data.CRID != id && response.Data.ResourceID != id {
		return nil, invalidAPIResponseOutcome("resource update identity differs from request", nil)
	}
	return &response, nil
}

// RevokeResource revokes the resource, not just one link. Use RevokePortal for
// a child link. API success does not independently confirm native session CLOSED.
func (c *Client) RevokeResource(ctx context.Context, id string) error {
	path, err := managementPath(c, id)
	if err != nil {
		return err
	}
	return c.deleteNoContent(ctx, path)
}

// ListPortals returns a complete page of per-link summaries for one resource.
// Unlike GetResource's preview, successive cursor pages cover the full set.
func (c *Client) ListPortals(ctx context.Context, id string, options PageOptions) (*ManagementPage[PortalSummary], error) {
	path, err := managementPath(c, id)
	if err != nil {
		return nil, err
	}
	q, err := managementQuery(options.Cursor, options.Limit)
	if err != nil {
		return nil, err
	}
	var response ManagementPage[PortalSummary]
	if err := c.doJSONStatus(ctx, http.MethodGet, path+"/qurls?"+q.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, fmt.Errorf("%w: link page has no array", ErrInvalidAPIResponse)
	}
	for _, portal := range response.Data {
		if err := validateResourceItemID(portal.QURLID, ErrInvalidAPIResponse); err != nil {
			return nil, err
		}
	}
	if err := validateManagementMeta(response.Meta); err != nil {
		return nil, err
	}
	return &response, nil
}

// ListSessions always opts into bounded pagination, never the legacy full scan.
func (c *Client) ListSessions(ctx context.Context, id, cursor string) (*ManagementPage[ResourceSession], error) {
	path, err := managementPath(c, id)
	if err != nil {
		return nil, err
	}
	q := url.Values{"paged": {"true"}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var response ManagementPage[ResourceSession]
	if err := c.doJSONStatus(ctx, http.MethodGet, path+"/sessions?"+q.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, fmt.Errorf("%w: session page has no array", ErrInvalidAPIResponse)
	}
	for _, session := range response.Data {
		if err := validateResourceItemID(session.SessionID, ErrInvalidAPIResponse); err != nil {
			return nil, err
		}
	}
	if err := validateManagementMeta(response.Meta); err != nil {
		return nil, err
	}
	return &response, nil
}

// TerminateSession requests removal of exactly one session.
func (c *Client) TerminateSession(ctx context.Context, id, sessionID string) error {
	path, err := managementPath(c, id)
	if err != nil {
		return err
	}
	if err := validateResourceItemID(sessionID, ErrInvalidResourceRequest); err != nil {
		return err
	}
	return c.deleteNoContent(ctx, path+"/sessions/"+url.PathEscape(sessionID))
}

// TerminateSessions requests termination of one bounded page. Follow the cursor
// explicitly; do not retry an ambiguous mutation as though no work took place.
func (c *Client) TerminateSessions(ctx context.Context, id, cursor string) (*SessionTerminationPage, error) {
	path, err := managementPath(c, id)
	if err != nil {
		return nil, err
	}
	q := url.Values{"paged": {"true"}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var response SessionTerminationPage
	if err := c.doJSONStatus(ctx, http.MethodDelete, path+"/sessions?"+q.Encode(), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.Terminated == nil || *response.Data.Terminated < 0 {
		return nil, invalidAPIResponseOutcome("missing or invalid session termination count", nil)
	}
	if err := validateManagementMeta(response.Meta); err != nil {
		return nil, invalidAPIResponseOutcome("invalid session termination pagination", err)
	}
	return &response, nil
}
