package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/layervai/qurl-go/crid"
)

// ErrTemporaryAccessLinksDisabled is returned by ShareResource when the
// LayerV API answers 503: the environment is not currently serving temporary
// access links (the surface is dark or administratively disabled), which is a
// service posture rather than anything wrong with the request. Callers that
// treat sharing as optional can branch on this sentinel and fall back; the
// underlying *APIError remains matchable with errors.As.
var ErrTemporaryAccessLinksDisabled = errors.New("qurl: temporary access links are disabled")

// ErrNoCRID is returned when a CRID-addressed operation or explicit CRID
// verifier receives no CRID, including a manually constructed ShareLink.
// Verification fails closed — absence is not a mismatch, but it is not a
// pass either.
var ErrNoCRID = errors.New("qurl: no crid to verify against")

// ErrCRIDMismatch is returned when a response has a different CRID, a supplied
// or signed key does not derive the held CRID, or a link verifier receives a
// malformed expected CRID (with the crid package's parse error also wrapped).
// Fail closed and do not use the returned link or mismatched key.
var ErrCRIDMismatch = errors.New("qurl: resource CRID mismatch")

// ShareResourceOptions customizes ShareResource. The zero value (or a nil
// pointer) requests the server defaults.
type ShareResourceOptions struct {
	// TTL asks for how long the minted share link should stay valid. If
	// omitted (zero), the field is not sent and the API applies its default
	// lifetime; the LayerV API remains the source of truth for account
	// limits. The wire carries whole integer seconds, so nonzero durations
	// must be whole seconds — sub-second remainders are rejected rather
	// than rounded.
	TTL time.Duration
}

// ShareLink is a freshly minted share link — a short-lived qURL access link
// — for a protected resource. It is the counterpart of Portal: both are
// minted access links, but ShareResource is the path addressed by CRID and verifiable with VerifyCRID.
type ShareLink struct {
	// Link is the access link. When it is qv2-shaped, open it with
	// EnterPortal; ShareResource deliberately does not parse or verify it.
	Link string
	// QURLID identifies this specific minted link. Pass it to RevokePortal —
	// with the same CRID you shared — to revoke this one link while
	// the resource's other links keep working. Empty when the API omits it
	// and the link has no individual revocation handle. Capture it alongside Link:
	// neither is retrievable after this response.
	QURLID string
	// CRID is the resource's required Cryptographic Resource ID.
	// Tie it to a key you hold with VerifyCRID.
	CRID string
	// Type is the link type reported by the API (for example "qv2").
	Type string
	// ExpiresAt is the link expiration time; zero when the API omits it.
	ExpiresAt time.Time
	// ExpiresInSeconds is the link lifetime reported by the API.
	ExpiresInSeconds int
	// SingleUse reports whether the link expires on first successful use.
	SingleUse bool
}

type shareResourceRequest struct {
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

type shareResourceResponse struct {
	QURL             string     `json:"qurl"`
	QURLID           string     `json:"qurl_id"`
	CRID             string     `json:"crid"`
	Type             string     `json:"type"`
	ExpiresAt        *time.Time `json:"expires_at"`
	ExpiresInSeconds int        `json:"expires_in_seconds"`
	SingleUse        bool       `json:"single_use"`
}

func (r shareResourceResponse) shareLink() (*ShareLink, error) {
	if strings.TrimSpace(r.QURL) == "" {
		return nil, fmt.Errorf("%w: missing qurl", ErrInvalidAPIResponse)
	}
	link := &ShareLink{
		Link:             r.QURL,
		QURLID:           r.QURLID,
		CRID:             r.CRID,
		Type:             r.Type,
		ExpiresInSeconds: r.ExpiresInSeconds,
		SingleUse:        r.SingleUse,
	}
	if r.ExpiresAt != nil {
		link.ExpiresAt = *r.ExpiresAt
	}
	return link, nil
}

// ShareResource asks LayerV to mint a fresh share link — a short-lived qURL
// access link — for an existing CRID. Public keys are verification data,
// not resource locators.
//
// The CRID is safe to paste anywhere; the share link is the secret, and
// sharing is what turns the identifier into access. Each link expires on its
// own — share again whenever you need a fresh one.
//
// opts may be nil. If TTL is omitted (zero), the API applies its default
// lifetime; the LayerV API remains the source of truth for account limits.
//
// The returned link is not opened, parsed, or verified here. When
// ShareLink.Link is qv2-shaped, the composition is ShareResource →
// EnterPortal: share mints the link over the credentialed API, and
// EnterPortal is the verifying opener. To bind the response to a resource
// key you already hold, call ShareLink.VerifyCRID before trusting a
// delivered key. To bind the link itself, use EnterPortalForCRID or
// VerifyLinkForCRID with the independently held CRID.
//
// The minted link is revocable on its own: keep ShareLink.QURLID and pass it
// to RevokePortal with the same resourceCRID to kill that one link without
// disturbing the resource's others. Like Link, it is not retrievable after
// this call returns.
//
// A 503 from this endpoint means the environment is not serving temporary
// access links and surfaces as ErrTemporaryAccessLinksDisabled; other API
// failures surface as *APIError exactly like the rest of the client.
func (c *Client) ShareResource(ctx context.Context, resourceCRID string, opts *ShareResourceOptions) (*ShareLink, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if err := crid.Validate(resourceCRID); err != nil {
		return nil, fmt.Errorf("%w: share requires a valid CRID: %w", ErrInvalidResourceRequest, err)
	}
	var reqBody shareResourceRequest
	if opts != nil {
		if opts.TTL < 0 {
			return nil, fmt.Errorf("%w: ttl must not be negative", ErrInvalidResourceRequest)
		}
		if opts.TTL%time.Second != 0 {
			return nil, fmt.Errorf("%w: ttl duration must be whole seconds", ErrInvalidResourceRequest)
		}
		reqBody.TTLSeconds = int64(opts.TTL / time.Second)
	}

	path := "/v1/resources/" + url.PathEscape(resourceCRID) + "/share"
	var env apiEnvelope[shareResourceResponse]
	if err := c.postJSON(ctx, path, reqBody, &env); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusServiceUnavailable {
			return nil, fmt.Errorf("%w: %w", ErrTemporaryAccessLinksDisabled, err)
		}
		return nil, err
	}
	if env.Data.CRID == "" {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAPIResponse, ErrNoCRID)
	}
	if env.Data.CRID != resourceCRID {
		return nil, fmt.Errorf("%w: %w: share response CRID does not match the requested CRID", ErrInvalidAPIResponse, ErrCRIDMismatch)
	}
	return env.Data.shareLink()
}

// VerifyCRID checks only the response CRID against the supplied key. It does
// not inspect the link; use VerifyLinkForCRID to bind its signed resource key.
// It ties this response to a resource public key the caller already holds by
// re-deriving the CRID from
// derSPKI (the DER SubjectPublicKeyInfo bytes, exactly as delivered) and
// comparing it to l.CRID in constant time. nil means the key is the one the
// CRID commits to. Any non-nil error is a fail-closed "do not use this key
// on the strength of this response": ErrNoCRID when the response carried no
// CRID, the crid package's typed sentinels when the held CRID fails the
// local gate, and ErrCRIDMismatch when a well-formed key simply is not the
// committed one — the substitution the identifier exists to detect.
func (l *ShareLink) VerifyCRID(derSPKI []byte) error {
	if l == nil || l.CRID == "" {
		return fmt.Errorf("%w: share link has no crid", ErrNoCRID)
	}
	ok, err := crid.KeyMatches(l.CRID, derSPKI)
	if err != nil {
		return fmt.Errorf("qurl: verify crid: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: crid %s", ErrCRIDMismatch, l.CRID)
	}
	return nil
}
