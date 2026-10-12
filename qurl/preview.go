package qurl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PreviewMedia is one processed image or silent clip. The first item is the cover.
type PreviewMedia struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Alt      string `json:"alt"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Cover    string `json:"cover,omitempty"`
	Fallback string `json:"fallback,omitempty"`
	Image    string `json:"image,omitempty"`
	Clip     string `json:"clip,omitempty"`
}

// PreviewUpload is a pending job. Processing expires after thirty minutes.
type PreviewUpload struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Alt       string `json:"alt"`
	ExpiresAt int64  `json:"expires_at"` // Unix seconds.
}

// PreviewCard carries public display text and short-lived media URLs.
type PreviewCard struct {
	Description string         `json:"description,omitempty"`
	Media       []PreviewMedia `json:"media,omitempty"`
}

// ResourcePreview belongs to one CRID, separately from private owner notes.
type ResourcePreview struct {
	Revision    int64           `json:"revision"`
	Description string          `json:"description,omitempty"`
	Media       []PreviewMedia  `json:"media,omitempty"`
	Uploads     []PreviewUpload `json:"uploads,omitempty"`
	Card        *PreviewCard    `json:"card,omitempty"`
}

// PreviewPatch uses the last revision. Nil fields are unchanged; an empty media
// list removes all ready media and cancels pending jobs.
type PreviewPatch struct {
	Revision    int64     `json:"revision"`
	Description *string   `json:"description,omitempty"`
	MediaIDs    *[]string `json:"media_ids,omitempty"`
}

// PreviewUploadRequest reserves a verified publisher's exact-size upload.
type PreviewUploadRequest struct {
	Revision    int64  `json:"revision"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Alt         string `json:"alt"`
	ReplaceID   string `json:"replace_id,omitempty"`
}

// PreviewUploadForm expires after five minutes. Upload the file with Headers
// directly to URL, without the API credential. Processing is asynchronous.
type PreviewUploadForm struct {
	Preview  ResourcePreview   `json:"preview"`
	UploadID string            `json:"upload_id"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
}

func previewPath(c *Client, crid string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := validateConnectorCRID(crid); err != nil {
		return "", err
	}
	return "/v1/resources/" + url.PathEscape(crid) + "/preview", nil
}

// Preview reads current metadata and processing state for an owned CRID.
func (c *Client) Preview(ctx context.Context, crid string) (*ResourcePreview, error) {
	path, err := previewPath(c, crid)
	if err != nil {
		return nil, err
	}
	var result ResourcePreview
	if err = c.doJSONStatus(ctx, http.MethodGet, path, nil, &result, http.StatusOK); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdatePreview edits public card metadata. A stale revision returns 409.
func (c *Client) UpdatePreview(ctx context.Context, crid string, patch PreviewPatch) (*ResourcePreview, error) {
	path, err := previewPath(c, crid)
	if err != nil {
		return nil, err
	}
	if patch.MediaIDs != nil && *patch.MediaIDs == nil {
		ids := []string{}
		patch.MediaIDs = &ids
	}
	var result ResourcePreview
	if err = c.doJSONStatus(ctx, http.MethodPatch, path, patch, &result, http.StatusOK); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreatePreviewUpload returns a form only for a currently verified publisher.
// Retain existing media until the returned processing job becomes ready.
func (c *Client) CreatePreviewUpload(ctx context.Context, crid string, input PreviewUploadRequest) (*PreviewUploadForm, error) {
	path, err := previewPath(c, crid)
	if err != nil {
		return nil, err
	}
	var result PreviewUploadForm
	if err = c.doJSONStatus(ctx, http.MethodPost, path+"/uploads", input, &result, http.StatusOK); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(result.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(result.Headers) == 0 || result.UploadID == "" {
		return nil, fmt.Errorf("%w: invalid preview upload form", ErrInvalidAPIResponse)
	}
	for name := range result.Headers {
		switch strings.ToLower(name) {
		case "authorization", "cookie", "host", "proxy-authorization":
			return nil, fmt.Errorf("%w: credential header in preview upload form", ErrInvalidAPIResponse)
		}
	}
	return &result, nil
}
