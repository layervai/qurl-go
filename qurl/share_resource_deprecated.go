package qurl

import "context"

// ResolveResourceOptions is the former name of ShareResourceOptions.
//
// Deprecated: use ShareResourceOptions.
type ResolveResourceOptions = ShareResourceOptions

// ResolvedAccess is the former name of ShareLink.
//
// Deprecated: use ShareLink.
type ResolvedAccess = ShareLink

// ResolveResource is the former name of ShareResource. It delegates
// unchanged, so existing callers keep compiling for one minor cycle.
//
// Deprecated: use ShareResource. This wrapper now calls
// POST /v1/resources/{id}/share, exactly like ShareResource, and therefore
// needs a qurl-service that serves the share route: the service keeps
// /resolve only as a deprecated alias for older SDK builds, and this SDK no
// longer sends it.
func (c *Client) ResolveResource(ctx context.Context, resourceID string, opts *ResolveResourceOptions) (*ResolvedAccess, error) {
	return c.ShareResource(ctx, resourceID, opts)
}
