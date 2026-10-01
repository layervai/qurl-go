package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"
)

// ErrInvalidPublisherName is returned by SetPublisherName when the name cannot
// be used: either it can never be valid and was rejected before any request
// (invalid UTF-8, or far longer than any name the service accepts), or the
// service answered 400 because the name breaks its naming rules. In the second
// case the underlying *APIError remains matchable with errors.As and carries
// the service's reason.
var ErrInvalidPublisherName = errors.New("qurl: invalid publisher name")

// maxPublisherNameBytes bounds a name before it is sent. It is deliberately far
// above anything the service accepts: the service owns the naming rules, and
// this only keeps an absurd payload off the wire.
const maxPublisherNameBytes = 1024

const publisherPath = "/v1/me/publisher"

// Publisher describes who published a resource: the name the resource owner
// chose for itself, and whether the platform has verified that owner.
//
// It is metadata asserted by the service. It is NOT covered by CRID or link
// verification: ShareLink.VerifyCRID, VerifyLinkForCRID, VerifyPortalLink, and
// EnterPortalForCRID bind only the resource key and the signed link. A CRID or
// link that verifies says nothing about the publisher reported beside it.
//
// Name is self-declared. Whoever owns the resource picked it, so treat it as
// attacker-choosable text wherever it is displayed: render it quoted with
// control and other non-printing characters escaped (strconv.Quote and the %q
// verb both do this), never interpolate it raw into a terminal, a log line, or
// markup, and never let it stand in for the verification status. Name is empty
// when the publisher has not set one.
//
// Verified is true only when the service explicitly reported a verified
// publisher. Today no publisher is verified, so every Publisher reports false.
// Present an unverified publisher as unverified, clearly and next to the name
// — a self-declared name must never read as a confirmed identity.
//
// The zero value means "no name, unverified". Every gap decodes to it: a
// service that predates the field, a missing publisher object, and a missing or
// null verified flag all report Verified == false.
type Publisher struct {
	// Name is the publisher's self-declared display name, or empty when none is
	// set. Untrusted text; escape it before display.
	Name string
	// Verified reports whether the platform has verified this publisher. False
	// for every publisher today.
	Verified bool
}

// publisherWire is the service's publisher object. It is decoded leniently on
// purpose: absent and null members leave the fail-closed zero values, and
// unknown members are ignored so a newer service keeps working. Only the JSON
// literal true can set Verified.
type publisherWire struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

func (w publisherWire) publisher() Publisher {
	return Publisher(w)
}

type setPublisherNameRequest struct {
	// No omitempty: an empty name is the explicit request to remove it.
	Name string `json:"name"`
}

// Publisher returns the publisher profile of the authenticated owner — the
// name and verification status the service attaches to this owner's resources
// when they are shared. The credential needs qurl:read; a registered agent's
// device credential is accepted.
//
// The result carries the same caveats as every Publisher: it is asserted by
// the service, and Verified is false for every publisher today. API failures
// surface as *APIError exactly like the rest of the client.
func (c *Client) Publisher(ctx context.Context) (*Publisher, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	var env apiEnvelope[*publisherWire]
	if err := c.doJSONStatus(ctx, http.MethodGet, publisherPath, nil, &env, http.StatusOK); err != nil {
		return nil, err
	}
	return publisherFromEnvelope(env)
}

// SetPublisherName sets the name the authenticated owner publishes under, and
// returns the resulting profile. An empty name removes the current one. The
// credential needs qurl:write; a registered agent's device credential is
// accepted.
//
// The name is self-declared: setting it does not verify the publisher, and the
// returned Verified is whatever the service reports (false today). There is no
// way to request verification through this call.
//
// The service is the authority on which names are acceptable. Only a name that
// can never be valid is rejected here, before any request: invalid UTF-8, or a
// name far beyond the service's length limit. Both, and a 400 from the service,
// match ErrInvalidPublisherName; a service rejection also keeps its *APIError.
// Other API failures surface as *APIError exactly like the rest of the client.
func (c *Client) SetPublisherName(ctx context.Context, name string) (*Publisher, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidClientConfig)
	}
	// encoding/json replaces malformed UTF-8 with U+FFFD, so an invalid name
	// would be stored as a different name than the caller passed.
	if !utf8.ValidString(name) {
		return nil, fmt.Errorf("%w: name is not valid UTF-8", ErrInvalidPublisherName)
	}
	if len(name) > maxPublisherNameBytes {
		return nil, fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidPublisherName, maxPublisherNameBytes)
	}
	var env apiEnvelope[*publisherWire]
	if err := c.doJSONStatus(ctx, http.MethodPatch, publisherPath, setPublisherNameRequest{Name: name}, &env, http.StatusOK); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest {
			return nil, fmt.Errorf("%w: %w", ErrInvalidPublisherName, err)
		}
		return nil, err
	}
	return publisherFromEnvelope(env)
}

// publisherFromEnvelope requires the profile object itself. Its members stay
// lenient, but a successful response with no data at all is not a profile.
func publisherFromEnvelope(env apiEnvelope[*publisherWire]) (*Publisher, error) {
	if env.Data == nil {
		return nil, fmt.Errorf("%w: missing publisher data", ErrInvalidAPIResponse)
	}
	publisher := env.Data.publisher()
	return &publisher, nil
}
