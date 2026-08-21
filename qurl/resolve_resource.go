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

// ErrTemporaryAccessLinksDisabled is returned by ResolveResource when the
// LayerV API answers 503: the environment is not currently serving temporary
// access links (the surface is dark or administratively disabled), which is a
// service posture rather than anything wrong with the request. Callers that
// treat resolve as optional can branch on this sentinel and fall back; the
// underlying *APIError remains matchable with errors.As.
var ErrTemporaryAccessLinksDisabled = errors.New("qurl: temporary access links are disabled")

// ErrNoCRID is returned by VerifyCRID when there is no CRID to verify
// against: the server omitted the field (older server or keyless resource).
// Verification fails closed — absence is not a mismatch, but it is not a
// pass either.
var ErrNoCRID = errors.New("qurl: no crid to verify against")

// ErrCRIDMismatch is returned by VerifyCRID when the supplied resource key
// does not derive the held CRID. This is the substitution the identifier
// exists to detect: fail closed and do not use the key.
var ErrCRIDMismatch = errors.New("qurl: resource key does not derive the held crid")

// ResolveResourceOptions customizes ResolveResource. The zero value (or a
// nil pointer) requests the server defaults.
type ResolveResourceOptions struct {
	// TTL asks for how long the minted access link should stay valid. If
	// omitted (zero), the field is not sent and the API applies its default
	// lifetime; the LayerV API remains the source of truth for account
	// limits. The wire carries whole integer seconds, so nonzero durations
	// must be whole seconds — sub-second remainders are rejected rather
	// than rounded.
	TTL time.Duration
}

// ResolvedAccess is a freshly minted access link for a protected resource.
// It is the counterpart of Portal — both are minted access links, but
// ResolveResource is the path addressed by resource id or CRID and
// verifiable with VerifyCRID.
type ResolvedAccess struct {
	// Link is the access link. When it is qv2-shaped, open it with
	// EnterPortal; ResolveResource deliberately does not parse or verify it.
	Link string
	// QURLID identifies this specific minted link. Pass it to RevokePortal —
	// with the same resource id you resolved — to revoke this one link while
	// the resource's other links keep working. Empty when the API omits it
	// (a server predating the field), which is the only case where a
	// resolve-minted link has no individual revocation handle. Capture it
	// alongside Link: neither is retrievable after this response.
	QURLID string
	// CRID is the resource's Cryptographic Resource ID, when returned by the
	// API (older servers and keyless resources omit it). Tie it to a key you
	// hold with VerifyCRID.
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

type resolveResourceRequest struct {
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

type resolveResourceResponse struct {
	QURL             string     `json:"qurl"`
	QURLID           string     `json:"qurl_id"`
	CRID             string     `json:"crid"`
	Type             string     `json:"type"`
	ExpiresAt        *time.Time `json:"expires_at"`
	ExpiresInSeconds int        `json:"expires_in_seconds"`
	SingleUse        bool       `json:"single_use"`
}

func (r resolveResourceResponse) resolvedAccess() (*ResolvedAccess, error) {
	if strings.TrimSpace(r.QURL) == "" {
		return nil, fmt.Errorf("%w: missing qurl", ErrInvalidAPIResponse)
	}
	access := &ResolvedAccess{
		Link:             r.QURL,
		QURLID:           r.QURLID,
		CRID:             r.CRID,
		Type:             r.Type,
		ExpiresInSeconds: r.ExpiresInSeconds,
		SingleUse:        r.SingleUse,
	}
	if r.ExpiresAt != nil {
		access.ExpiresAt = *r.ExpiresAt
	}
	return access, nil
}

// ResolveResource asks LayerV to mint a fresh access link for an existing
// resource. resourceID accepts either identifier form the platform serves —
// the public-key resource id or the resource's CRID — and, like the other
// resource methods, is validated for presence only: the server is
// authoritative for which identifiers resolve, so the SDK does not pre-judge
// the form locally.
//
// opts may be nil. If TTL is omitted (zero), the API applies its default
// lifetime; the LayerV API remains the source of truth for account limits.
//
// The returned link is not opened, parsed, or verified here. When
// ResolvedAccess.Link is qv2-shaped, the composition is
// ResolveResource → EnterPortal: resolve mints the link over the
// credentialed API, and EnterPortal is the verifying opener. To bind the
// response to a resource key you already hold, call
// ResolvedAccess.VerifyCRID before trusting a delivered key.
//
// The minted link is revocable on its own: keep ResolvedAccess.QURLID and
// pass it to RevokePortal with the same resourceID to kill that one link
// without disturbing the resource's others. Like Link, it is not retrievable
// after this call returns.
//
// A 503 from this endpoint means the environment is not serving temporary
// access links and surfaces as ErrTemporaryAccessLinksDisabled; other API
// failures surface as *APIError exactly like the rest of the client.
func (c *Client) ResolveResource(ctx context.Context, resourceID string, opts *ResolveResourceOptions) (*ResolvedAccess, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	if strings.TrimSpace(resourceID) == "" {
		return nil, fmt.Errorf("%w: resource id must not be empty", ErrInvalidResourceRequest)
	}
	var reqBody resolveResourceRequest
	if opts != nil {
		if opts.TTL < 0 {
			return nil, fmt.Errorf("%w: ttl must not be negative", ErrInvalidResourceRequest)
		}
		if opts.TTL%time.Second != 0 {
			return nil, fmt.Errorf("%w: ttl duration must be whole seconds", ErrInvalidResourceRequest)
		}
		reqBody.TTLSeconds = int64(opts.TTL / time.Second)
	}

	path := "/v1/resources/" + url.PathEscape(resourceID) + "/resolve"
	var env apiEnvelope[resolveResourceResponse]
	if err := c.postJSON(ctx, path, reqBody, &env); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusServiceUnavailable {
			return nil, fmt.Errorf("%w: %w", ErrTemporaryAccessLinksDisabled, err)
		}
		return nil, err
	}
	return env.Data.resolvedAccess()
}

// VerifyCRID is the CRID trust story in one call: it ties this response to a
// resource public key the caller already holds by re-deriving the CRID from
// derSPKI (the DER SubjectPublicKeyInfo bytes, exactly as delivered) and
// comparing it to r.CRID in constant time. nil means the key is the one the
// CRID commits to. Any non-nil error is a fail-closed "do not use this key
// on the strength of this response": ErrNoCRID when the response carried no
// CRID, the crid package's typed sentinels when the held CRID fails the
// local gate, and ErrCRIDMismatch when a well-formed key simply is not the
// committed one — the substitution the identifier exists to detect.
func (r *ResolvedAccess) VerifyCRID(derSPKI []byte) error {
	if r == nil || r.CRID == "" {
		return fmt.Errorf("%w: resolve response carried no crid (older server or keyless resource)", ErrNoCRID)
	}
	ok, err := crid.KeyMatches(r.CRID, derSPKI)
	if err != nil {
		return fmt.Errorf("qurl: verify crid: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: crid %s", ErrCRIDMismatch, r.CRID)
	}
	return nil
}
