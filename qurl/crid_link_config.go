package qurl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/layervai/qurl-go/internal/x25519key"
)

// Where a CRID link request goes.
//
// Opening a link needs no address of its own: the link's signed claims name the
// cell that holds the resource. A client that holds only a CRID has no claims
// yet, so the three facts its first packet depends on have to come from
// deployment configuration instead:
//
//   - the relay that carries the request,
//   - the server public key the request is sealed to, and
//   - the origin every issued link must be on.
//
// The relay and the origin are the "crid_link" object of a deployment. The key
// is not repeated there: it is the key of the deployment's one cell, read from
// the same catalog that link opens use, so the two can never name different
// servers. A CRID is a commitment, never an address, so nothing here is derived
// from the CRID itself.

// DeploymentCRIDLink is the "crid_link" object of a deployment file: where a
// client that holds only a CRID asks for a link, and which origin an issued
// link must be on. It is the file shape; CRIDLinkConfig is what a Config
// carries.
type DeploymentCRIDLink struct {
	// RelayURL is the HTTPS base URL of the relay that carries the request. Its
	// host must be listed in the deployment's relay_allowlist.
	RelayURL string `json:"relay_url"`
	// LinkOrigin is the bare HTTPS origin issued links are on, for example
	// "https://qurl.link": scheme and host, a port only when it is not the
	// default, and nothing else.
	LinkOrigin string `json:"link_origin"`
}

// CRIDLinkConfig tells RequestCRIDLinkWith and OpenCRIDWith where to send a
// CRID link request. Set it on Config.CRIDLink. The deployment resolution
// behind RequestCRIDLink and OpenCRID fills it from the deployment's
// "crid_link" object.
//
// The server public key is deliberately not a field. A request is sealed to
// the one cell in Config.Cells, and a config that names no cell or several
// cannot make the request (ErrCRIDLinkMisconfigured): the SDK does not choose
// a cell for a CRID.
type CRIDLinkConfig struct {
	// RelayURL is the HTTPS base URL of the relay that carries the request. It
	// must pass Config.RelayAllowlist, exactly as a link's own relay URL does.
	RelayURL string
	// LinkOrigin is the bare HTTPS origin an issued link must be on, compared
	// as text. A link on any other origin is rejected.
	LinkOrigin string
	// UserAgent optionally names the calling program to the server, for
	// example "example-tool/1.2". It travels inside the encrypted request.
	// Empty sends none. A value that holds a control character (U+0000 to
	// U+001F, or U+007F), U+2028 or U+2029 anywhere sends none either: it is
	// left out, and the request is still made. Otherwise a value longer than
	// 256 bytes of UTF-8 is cut to the longest prefix that fits and ends on a
	// character boundary.
	UserAgent string
}

// ErrCRIDLinkNotConfigured reports that the resolved configuration cannot make
// a CRID link request. Either it names no CRID link endpoint, or it names one
// that cannot be used. It wraps ErrNotConfigured, and the message says which.
// No request is sent.
//
// The second case also matches ErrCRIDLinkMisconfigured. An error that matches
// this one and not that one means there is no endpoint at all: the request is
// not offered by this configuration.
//
// The deployment embedded in this build names no CRID link endpoint, so
// RequestCRIDLink and OpenCRID return this error until a deployment file named
// by QURL_DEPLOYMENT supplies one. RequestCRIDLinkWith and OpenCRIDWith read it
// from Config.CRIDLink.
var ErrCRIDLinkNotConfigured = fmt.Errorf("%w: no usable CRID link endpoint", ErrNotConfigured)

// ErrCRIDLinkMisconfigured reports that the configuration names a CRID link
// endpoint and the endpoint cannot be used. Its relay URL or its link origin
// is missing or wrong, or the configuration does not name exactly one usable
// cell to seal the request to. The message says which. No request is sent.
//
// It wraps ErrCRIDLinkNotConfigured, so it matches ErrNotConfigured too. Code
// that tells the two cases apart tests for this error first.
//
// A deployment file whose "crid_link" object has an unknown member, or a
// member of the wrong type, is neither of the two. That file does not decode,
// and the error is the one LoadDeployment returns.
var ErrCRIDLinkMisconfigured = fmt.Errorf("%w: the configuration names one that cannot be used", ErrCRIDLinkNotConfigured)

// CheckCRIDLinkConfig reports whether RequestCRIDLink and OpenCRID could send
// a request at all with the configuration this process resolves. It needs no
// CRID. It sends nothing and creates nothing: it reads the deployment, the
// file named by QURL_DEPLOYMENT or the one embedded in the build, and checks
// it.
//
// nil means a request can be sent. It does not mean the server will issue a
// link. Otherwise the error is the one RequestCRIDLink returns for the same
// configuration before it sends anything:
//
//   - ErrCRIDLinkNotConfigured, and not ErrCRIDLinkMisconfigured, when the
//     deployment names no CRID link endpoint.
//   - ErrCRIDLinkMisconfigured when it names one that cannot be used.
//   - The error from the deployment itself when the file cannot be read or
//     decoded, or carries no issuer keys.
//
// With a Provider installed the answer is always the first one. A Provider
// supplies no CRID link endpoint, so it is not asked: asking could be network
// I/O.
//
// RequestCRIDLink checks the CRID before it looks at the configuration, so a
// CRID it cannot request hides this answer. Call CheckCRIDLinkConfig to learn
// whether the request is offered, whatever the CRID.
func CheckCRIDLinkConfig() error {
	if DefaultProvider() != nil {
		return errNoCRIDLinkEndpoint()
	}
	cfg, err := defaultDeploymentConfig()
	if err != nil {
		return err
	}
	return CheckCRIDLinkConfigWith(cfg)
}

// CheckCRIDLinkConfigWith is CheckCRIDLinkConfig for an explicit Config. It
// reports whether RequestCRIDLinkWith and OpenCRIDWith could send a request
// with cfg, and it runs the same checks they run before they send one. A cfg
// with no TrustStore is ErrNotConfigured, as it is for those calls.
func CheckCRIDLinkConfigWith(cfg Config) error {
	_, err := resolveCRIDLinkEndpoint(cfg)
	return err
}

// errNoCRIDLinkEndpoint is the one error for a configuration that names no
// CRID link endpoint. It has one message for every source of a Config, so it
// names each remedy and says which source has none: with a Provider installed
// the deployment file is not read, and editing it would change nothing.
func errNoCRIDLinkEndpoint() error {
	return fmt.Errorf(
		"%w: the configuration names none (set Config.CRIDLink, or add \"crid_link\" to the deployment file named by %s; an installed Provider supplies none)",
		ErrCRIDLinkNotConfigured, EnvDeploymentPath)
}

// cridLinkEndpoint is a validated CRID link endpoint: everything the first
// packet needs, resolved before any network I/O.
type cridLinkEndpoint struct {
	relayURL        string
	linkOrigin      string
	userAgent       string
	serverPublicKey []byte
}

// resolveCRIDLinkEndpoint validates the CRID link part of cfg. It is the single
// place the rules are applied, for a deployment-resolved Config and a
// hand-built one alike, and it runs on every request, so a Config cannot reach
// the network with an endpoint that was never checked.
func resolveCRIDLinkEndpoint(cfg Config) (*cridLinkEndpoint, error) {
	// A trust store is always required: an issued link is used only after its
	// issuer signature verifies, so a request without one could never succeed.
	if cfg.TrustStore == nil {
		return nil, fmt.Errorf("%w: a CRID link request requires qURL opener config", ErrNotConfigured)
	}
	if cfg.CRIDLink == nil {
		return nil, errNoCRIDLinkEndpoint()
	}
	// From here on the configuration names an endpoint, so every fault is a
	// misconfigured one. A caller can tell it from a configuration that does
	// not offer the request at all.
	if err := validateCRIDLinkRelayURL(cfg.CRIDLink.RelayURL, cfg.RelayAllowlist); err != nil {
		return nil, fmt.Errorf("%w: relay URL: %w", ErrCRIDLinkMisconfigured, err)
	}
	if err := validateCRIDLinkOrigin(cfg.CRIDLink.LinkOrigin); err != nil {
		return nil, fmt.Errorf("%w: link origin %w", ErrCRIDLinkMisconfigured, err)
	}

	// The request is sealed to the deployment's cell. With no cell there is no
	// key; with several, choosing one would be a guess about where the resource
	// lives, and a wrong guess sends the CRID to a server that never held it.
	serverPublicKey, cells := cfg.Cells.soleServerPublicKey()
	switch {
	case cells == 0:
		return nil, fmt.Errorf(
			"%w: the request is sealed to the deployment's cell, and the configuration names no cell",
			ErrCRIDLinkMisconfigured)
	case cells > 1:
		return nil, fmt.Errorf(
			"%w: the configuration names %d cells, and a CRID link request does not choose between cells",
			ErrCRIDLinkMisconfigured, cells)
	}
	// A catalog entry is length-checked only. Refuse a key that cannot carry a
	// key agreement here, as a configuration fault, rather than as an untyped
	// transport error after the request was assembled.
	if err := x25519key.ValidatePublic(serverPublicKey); err != nil {
		return nil, fmt.Errorf("%w: the cell's server public key is unusable: %w", ErrCRIDLinkMisconfigured, err)
	}
	return &cridLinkEndpoint{
		relayURL:        cfg.CRIDLink.RelayURL,
		linkOrigin:      cfg.CRIDLink.LinkOrigin,
		userAgent:       cfg.CRIDLink.UserAgent,
		serverPublicKey: serverPublicKey,
	}, nil
}

// validateCRIDLinkRelayURL applies the relay rules a link's own relay URL
// passes — HTTPS, a host, no userinfo, on the allowlist — and one more that
// only a configured base URL needs: no query and no fragment, because the
// request path is appended to it.
func validateCRIDLinkRelayURL(relayURL string, allow *RelayAllowlist) error {
	if err := ValidateRelayURL(relayURL, allow); err != nil {
		return err
	}
	u, err := url.Parse(relayURL)
	if err != nil {
		// Unreachable: ValidateRelayURL parsed the same string.
		return fmt.Errorf("%w: unparseable url", ErrRelayURL)
	}
	if u.RawQuery != "" || u.ForceQuery || strings.Contains(relayURL, "#") {
		return fmt.Errorf("%w: a relay base URL carries no query or fragment", ErrRelayURL)
	}
	return nil
}

// validateCRIDLinkOrigin requires the one canonical spelling of an HTTPS
// origin: "https://", a lowercase host, and a port only when it is not 443.
//
// The strictness is what makes the link check a comparison of text. An issued
// link is accepted only if it starts with this exact string, so a second
// spelling of the same origin here — an upper-case host, an explicit default
// port, a trailing slash — would not be a harmless variant: it would reject
// every link the server issues. Refusing it in configuration turns that into
// one clear error instead.
func validateCRIDLinkOrigin(origin string) error {
	const form = "must be a bare https origin such as https://qurl.link, with no userinfo, path, query, or fragment"
	u, err := url.Parse(origin)
	if err != nil {
		return errors.New(form)
	}
	// normalizedHTTPSOrigin rejects every authority that is not exactly a host
	// with an optional numeric port. The text comparison then rejects whatever
	// a parser would have separated out: a path, a query, a fragment, userinfo,
	// or a scheme that is not spelled in lower case.
	_, port, ok := normalizedHTTPSOrigin(u)
	if !ok || "https://"+u.Host != origin {
		return errors.New(form)
	}
	if u.Host != strings.ToLower(u.Host) {
		return errors.New("must spell its host in lower case")
	}
	if written := u.Port(); written != "" && (written != port || port == "443") {
		return errors.New("must omit the default port and write any other port without leading zeros")
	}
	return nil
}
