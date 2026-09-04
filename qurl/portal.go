// Package qurl is the Go SDK for the LayerV qURL Platform. Most integrations
// protect a private URL with Client.ProtectURL, mint short-lived links with
// Resource.CreatePortal, and share those links with callers.
//
// LayerV hosts qURL. Applications provide LayerV credentials and the target URL
// they want to protect; the platform creates or reuses the backing resource.
//
// EnterPortal is for services and agents that open received qURL links
// programmatically. It verifies a link locally before asking qURL for access,
// then returns a ResourceHandle with the reachable resource URL. Low-level offline
// signed-fragment helpers exist for conformance and protocol integrations, but
// the platform client is the default application surface.
package qurl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// Config carries opener configuration for EnterPortalWith. Most applications
// install a Provider once and call EnterPortal; Config is the explicit seam for
// tests and advanced clients.
type Config struct {
	// TrustStore resolves trusted issuer keys. REQUIRED.
	TrustStore *TrustStore
	// Cells maps cell id to native NHP UDP endpoint. When the verified link names
	// a cell in this catalog the knock goes straight there over UDP and the relay
	// is never contacted, so RelayAllowlist and HTTPClient are unused for that
	// open. Optional; nil routes every open through the relay. A link naming a
	// cell OUTSIDE the catalog falls back to the relay when RelayAllowlist is
	// set, and fails with ErrCellNotInCatalog when it is not — cells without an
	// allowlist is the native-UDP-only shape.
	Cells *CellCatalog
	// RelayAllowlist is the qURL platform access endpoint allowlist. REQUIRED
	// unless Cells covers every link this opener will see — it gates the relay
	// path only, and there is no relay to gate on the native UDP path.
	RelayAllowlist *RelayAllowlist
	// HTTPClient is the client used for the relay request. Optional; nil uses the
	// default client. Advanced callers with fixed-egress requirements can supply
	// their own client. Unused on the native UDP path.
	HTTPClient HTTPDoer
	// PortalSession retains this visitor's private capability across retries or
	// renewals of one verified link, including an initial knock whose reply was
	// lost. Optional; nil makes each EnterPortalWith call an independent visit.
	// Copy a shared Config per visit and assign a separate zero-value session;
	// retain that copy when retrying the same link for the same visitor.
	PortalSession *PortalSession
}

// HTTPDoer is the subset of *http.Client EnterPortal needs, narrowed so a caller
// can inject a fixed-egress or test client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ResourceHandle is the result of a successful EnterPortal: the reachable
// resource URL and the access lifetime reported by qURL.
type ResourceHandle struct {
	// ResourceURL is the reachable resource location.
	ResourceURL string
	// OpenSeconds is how long access stays open, as reported by qURL (0 when not
	// provided).
	OpenSeconds uint32
	// SessionID is the nonzero server-assigned NHP access-session identity.
	SessionID uint64

	// authProviderToken is the signed qurl_vsession value from the authenticated
	// NHP ACK. Keep it private so ordinary formatting and JSON cannot expose it.
	authProviderToken string
}

const qurlVsessionCookieName = "qurl_vsession"

const maxContentRedirects = 10

// AuthorizeContentRequest adds the application-session cookie to a request for
// this handle's exact HTTPS origin. It authorizes this request only. A caller
// that follows redirects must call AuthorizeContentRequest again from its
// CheckRedirect function; the origin check then refuses a different host,
// scheme, or port. Do not rely on http.Client's default redirect policy: it can
// copy Cookie headers to subdomains. Set CheckRedirect to
// ResourceHandle.CheckContentRedirect. The token never appears in the URL.
// Repeated calls replace the qurl_vsession cookie and preserve other valid
// request cookies.
func (h *ResourceHandle) AuthorizeContentRequest(req *http.Request) error {
	if h == nil || req == nil || req.URL == nil || !validAuthProviderToken(h.authProviderToken) {
		return fmt.Errorf("%w: invalid content access handle", ErrInvalidContentRequest)
	}
	granted, err := url.Parse(h.ResourceURL)
	if err != nil {
		return fmt.Errorf("%w: invalid granted content origin", ErrInvalidContentRequest)
	}
	grantedHost, grantedPort, grantedOK := normalizedHTTPSOrigin(granted)
	if !grantedOK {
		return fmt.Errorf("%w: invalid granted content origin", ErrInvalidContentRequest)
	}
	requestHost, requestPort, requestOK := normalizedHTTPSOrigin(req.URL)
	if !requestOK || requestHost != grantedHost || requestPort != grantedPort {
		return fmt.Errorf("%w: content request does not match the granted origin", ErrInvalidContentRequest)
	}

	// Cookie response attributes such as Secure and HttpOnly are not serialized
	// in a request Cookie header. The exact HTTPS-origin checks above are the
	// enforcement boundary. Rebuild the valid request cookies so a retry cannot
	// leave an old or duplicate qurl_vsession value in the request.
	cookies := req.Cookies()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != qurlVsessionCookieName {
			req.AddCookie(cookie)
		}
	}
	req.AddCookie(&http.Cookie{
		Name:     qurlVsessionCookieName,
		Value:    h.authProviderToken,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// CheckContentRedirect is the safe http.Client.CheckRedirect policy for a
// protected-content request. It preserves Go's default 10-request limit and
// re-authorizes only redirects that remain on the granted HTTPS origin.
func (h *ResourceHandle) CheckContentRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxContentRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", ErrTooManyContentRedirects, maxContentRedirects)
	}
	return h.AuthorizeContentRequest(req)
}

// normalizedHTTPSOrigin compares URL origins without treating the implicit
// HTTPS port and :443 as different origins. It also rejects credentials and
// malformed or nonnumeric explicit ports before a bearer can be attached.
func normalizedHTTPSOrigin(u *url.URL) (host, port string, ok bool) {
	if u == nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil ||
		u.Opaque != "" || strings.Contains(u.Host, "@") {
		return "", "", false
	}
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", false
	}
	port = u.Port()
	if port == "" {
		// Port returns an empty string for both an absent port and some malformed
		// manually constructed authorities. Only the canonical host-only forms
		// are valid here.
		canonicalHost := host
		if strings.Contains(host, ":") {
			canonicalHost = "[" + host + "]"
		}
		if !strings.EqualFold(u.Host, canonicalHost) {
			return "", "", false
		}
		return host, "443", true
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", "", false
	}
	if !strings.EqualFold(u.Host, net.JoinHostPort(host, port)) {
		return "", "", false
	}
	return host, strconv.FormatUint(portNumber, 10), true
}

// String returns a redacted representation that never includes the private
// application-session bearer.
func (h ResourceHandle) String() string {
	return fmt.Sprintf("qurl.ResourceHandle{ResourceURL:%q, OpenSeconds:%d, SessionID:%d, AuthProviderToken:[REDACTED]}", h.ResourceURL, h.OpenSeconds, h.SessionID)
}

// GoString returns the same redacted representation as String.
func (h ResourceHandle) GoString() string { return h.String() }

// ErrNotConfigured reports that a required piece of qURL configuration is
// absent. The message deliberately names no entry point: the same sentinel is
// wrapped by the agent-runtime path, where naming EnterPortal sent operators
// looking at a function they never called. Each return site adds its own
// context.
var ErrNotConfigured = errors.New("qurl: not configured")

// ErrInvalidContentRequest reports that a request cannot safely receive the
// application-session cookie from a ResourceHandle. It is a local caller or
// handle-use error, not a malformed platform reply.
var ErrInvalidContentRequest = errors.New("qurl: invalid content request")

// ErrTooManyContentRedirects reports that CheckContentRedirect stopped a
// protected-content request after the standard 10-request redirect limit.
var ErrTooManyContentRedirects = errors.New("qurl: too many content redirects")

// ErrCellNotInCatalog reports that a verified link names a cell the configured
// CellCatalog has no endpoint for, while no relay transport is configured to
// fall back through. It is the loud half of the transport rule: a cells-only
// opener (Config.Cells set, Config.RelayAllowlist nil — e.g. a StaticProvider
// built without an allowlist) has declared that every open goes over native
// UDP, so a link outside its catalog is refused rather than silently
// downgraded to the HTTPS relay. Openers that configure a relay allowlist
// never see this error; their unknown-cell opens use the relay by design.
var ErrCellNotInCatalog = errors.New("qurl: link names a cell with no native UDP endpoint in the catalog, and no relay transport is configured")

// EnterPortal opens a qURL link using the process-wide default Provider
// (SetDefaultProvider). Applications install opener config once at startup, then
// open links with no per-call config.
//
// The resolved config decides the transport: a link naming a cell in the cell
// catalog (a CellProvider's cells, or the deployment's) is knocked directly
// over native UDP; any other link uses the HTTPS relay when a relay allowlist
// is configured and fails with ErrCellNotInCatalog when none is. A provider
// without cells therefore serves relay-only opens — see CellProvider.
//
// Without an installed provider, EnterPortal falls back to the deployment: the
// file named by QURL_DEPLOYMENT, then the one embedded in the build. When that
// deployment carries no issuer keys, it fails with ErrNoDeployment (which wraps
// ErrNotConfigured) rather than open a link it cannot verify. Tests and
// advanced integrations can inject config with StaticProvider,
// DiscoveryProvider, or EnterPortalWith.
//
// Each call starts an independent visit. If a single-use visit is committed but
// its reply is lost, another EnterPortal call cannot recover that visit. With
// server renewal-proof enforcement, a second open of a consumed single-use link
// is denied. Callers that need same-visitor retries or renewals must use
// EnterPortalWith and retain one Config.PortalSession across those calls.
func EnterPortal(ctx context.Context, qurlLink string) (*ResourceHandle, error) {
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return EnterPortalWith(ctx, qurlLink, cfg)
}

// EnterPortalWith opens a qURL link using the supplied Config. It is the
// injectable seam behind EnterPortal for tests and advanced callers.
// Retain Config.PortalSession to retry one visit; nil starts a new visitor.
func EnterPortalWith(ctx context.Context, qurlLink string, cfg Config) (*ResourceHandle, error) {
	// A trust store is always required: nothing below runs on unverified claims.
	if cfg.TrustStore == nil {
		return nil, fmt.Errorf("%w: EnterPortal requires qURL opener config", ErrNotConfigured)
	}
	// With neither a cell catalog nor a relay allowlist there is no transport this
	// open could ever use. That is a configuration fault, not a link fault, so it
	// is reported here — before parsing — and every link fails it identically.
	// Which of the two is actually needed depends on the cell the claims name, so
	// that check necessarily happens after verification.
	if cfg.Cells == nil && cfg.RelayAllowlist == nil {
		return nil, fmt.Errorf("%w: EnterPortal requires qURL opener config", ErrNotConfigured)
	}

	// 1+2. Parse the fragment and verify the issuer signature. FragmentFromLinkAndVerify
	// strict-parses then checks the signature over the exact received claims bytes;
	// nothing downstream runs until the signature is good.
	frag, err := qv2.FragmentFromLinkAndVerify(qurlLink, cfg.TrustStore.core())
	if err != nil {
		return nil, err
	}
	claims := frag.Claims

	// 3. Decode the verified platform access key. It both encrypts the knock and
	// identifies the cell — the relay routes by a fingerprint of this same key —
	// so it must be in hand before a transport can be chosen.
	cellPub, err := qv2.DecodeCellPublicKey(claims)
	if err != nil {
		// Unreachable in practice: a verified claim already passed the parser's
		// 32-byte platform access key length check. Kept as defense in depth.
		return nil, fmt.Errorf("qurl: decode verified platform access key: %w", err)
	}

	// 4. Choose the transport. The knock is the same opaque NHP packet either
	// way; the relay is a browser compatibility shim, not part of the protocol.
	// A cell we know how to reach is knocked directly over UDP, dropping the
	// relay and every HTTP dependency with it. Otherwise fall back to the relay,
	// whose URL must clear the allowlist before it is acted on.
	cellEndpoint, useNativeUDP := cfg.Cells.lookup(cellPub)
	if !useNativeUDP {
		if cfg.RelayAllowlist == nil {
			// Reachable only with a catalog configured (the no-transport case
			// already failed before parsing): this opener is native-UDP-only by
			// configuration, and the verified link names a cell outside its
			// catalog. Refuse loudly with the cell's identity rather than treat a
			// deliberate cells-only config as a configuration fault.
			return nil, fmt.Errorf("%w (cell fingerprint %s)", ErrCellNotInCatalog, relayknock.PubKeyFingerprint(cellPub))
		}
		if err := qv2.ValidateRelayURL(claims.RelayURL, cfg.RelayAllowlist.core()); err != nil {
			return nil, err
		}
	}

	// 5. Build the platform access request from the link's per-qURL key, the
	// LayerV-provided access key, the resource identity, and the signed claims.
	devicePriv, err := qv2.DecodeQurlUserPrivateKey(frag.Secret)
	if err != nil {
		return nil, fmt.Errorf("qurl: decode per-qURL private key: %w", err)
	}
	session := cfg.PortalSession
	if session == nil {
		session = &PortalSession{}
	}
	sessionSecret, err := session.secretFor(frag)
	if err != nil {
		return nil, err
	}
	body, err := buildKnockBody(frag, sessionSecret)
	if err != nil {
		return nil, err
	}

	// 6. Ask the qURL platform for one-shot access using the in-link key. The
	// caller's egress IP is the one the platform opens access for (see
	// ResourceHandle) — that holds on both transports, since either way the
	// packet arrives from this process.
	//
	// The reply is authenticated to cellPub, which came from the verified claims.
	// That is what makes the carrier untrusted: a relay cannot forge a reply or
	// substitute a resource URL, and neither can anything on the UDP path.
	var reply *relayknock.Reply
	if useNativeUDP {
		reply, err = nativeudp.Knock(ctx, nativeudp.Endpoint{
			Host:            cellEndpoint.Host,
			Port:            cellEndpoint.Port,
			ServerStaticPub: cellPub,
		}, body, nativeudp.Options{DeviceStaticPriv: devicePriv})
	} else {
		reply, err = relayknock.Knock(ctx, claims.RelayURL, cellPub, body, relayknock.KnockOptions{
			HTTPClient:       cfg.HTTPClient,
			DeviceStaticPriv: devicePriv,
		})
	}
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}

	return interpretReply(reply)
}

// Compile-time guard: the public platform error wrapper must stay
// field-identical with the internal transport error shape. The struct
// conversion fails to compile if either side drifts.
var _ = RelayError(relayknock.RelayError{})

// normalizeRelayError maps a relayknock transport/reply error into the qURL
// taxonomy. An HTTP-transport fault (*relayknock.RelayError) becomes the public
// *RelayError view. A malformed-reply fault (relayknock.ErrMalformedReply — a
// counter/type-mismatch reply Knock refused above the crypto) is re-wrapped
// under malformedClass, the caller's front-door malformed-reply sentinel
// (for example, ErrMalformedReply for the portal),
// so a byzantine-relay reply surfaces as a taxonomy error rather than a raw
// string. Anything else passes through unchanged.
func normalizeRelayError(err error, malformedClass error) error {
	var relayErr *relayknock.RelayError
	if errors.As(err, &relayErr) {
		re := RelayError(*relayErr)
		return &relayErrorView{err: err, relay: &re}
	}
	if errors.Is(err, relayknock.ErrMalformedReply) {
		return fmt.Errorf("%w: %w", malformedClass, err)
	}
	return err
}

type relayErrorView struct {
	err   error
	relay *RelayError
}

func (e *relayErrorView) Error() string {
	return ensureQurlPrefix(e.err.Error())
}

func (e *relayErrorView) Unwrap() error {
	return e.err
}

func (e *relayErrorView) As(target any) bool {
	// Keep the public *qurl.RelayError reachable while Unwrap preserves the
	// internal *relayknock.RelayError and any wrapped context/cancellation cause.
	if relay, ok := target.(**RelayError); ok {
		*relay = e.relay
		return true
	}
	return false
}

// interpretReply maps a decrypted, authenticated qURL platform reply to a ResourceHandle or
// an error. A cookie-challenge (server overload) is surfaced as a typed retryable
// error; a non-ACK is unexpected; an ACK with a server deny carries the errCode.
func interpretReply(reply *relayknock.Reply) (*ResourceHandle, error) {
	if reply == nil {
		return nil, fmt.Errorf("%w: empty qURL platform reply", ErrMalformedReply)
	}
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, fmt.Errorf("%w: unexpected qURL platform reply type %d", ErrMalformedReply, reply.Type)
	}

	ack, err := parseAck(reply.Body)
	if err != nil {
		return nil, err
	}
	if !ack.isSuccess() {
		if ack.SessionID.Present {
			return nil, fmt.Errorf("%w: deny ACK carried an NHP session id", ErrMalformedReply)
		}
		if !ack.OpenTime.Present || ack.OpenTime.Value != 0 {
			return nil, fmt.Errorf("%w: deny ACK carried a missing or nonzero open time", ErrMalformedReply)
		}
		if ack.AuthProviderToken != "" {
			return nil, fmt.Errorf("%w: deny ACK carried an auth provider token", ErrMalformedReply)
		}
		if !isCanonicalKnockDenyCode(ack.ErrCode) {
			return nil, fmt.Errorf("%w: deny ACK carried a noncanonical error code", ErrMalformedReply)
		}
		return nil, &ServerDenyError{ErrCode: ack.ErrCode}
	}
	if !ack.SessionID.Present || ack.SessionID.Value == 0 {
		return nil, fmt.Errorf("%w: success ACK carried no NHP session id", ErrMalformedReply)
	}
	if !ack.OpenTime.Present || ack.OpenTime.Value == 0 {
		return nil, fmt.Errorf("%w: success ACK carried an invalid open time", ErrMalformedReply)
	}
	// A success ACK that carries no resource URL is not actionable — the caller has
	// nothing to reach. Fail closed rather than hand back an empty handle.
	if ack.RedirectURL == "" {
		return nil, fmt.Errorf("%w: success ACK carried no resource URL (errCode=%q)", ErrMalformedReply, ack.ErrCode)
	}
	granted, err := url.Parse(ack.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("%w: success ACK carried an invalid resource URL", ErrMalformedReply)
	}
	if _, _, ok := normalizedHTTPSOrigin(granted); !ok {
		return nil, fmt.Errorf("%w: success ACK carried an invalid resource URL", ErrMalformedReply)
	}
	if !validAuthProviderToken(ack.AuthProviderToken) {
		return nil, fmt.Errorf("%w: success ACK carried an invalid auth provider token", ErrMalformedReply)
	}
	return &ResourceHandle{
		ResourceURL: ack.RedirectURL, OpenSeconds: ack.OpenTime.Value, SessionID: ack.SessionID.Value,
		authProviderToken: ack.AuthProviderToken,
	}, nil
}

// resolveDefaultConfig builds the EnterPortal Config from the process-wide default
// provider, falling back to the deployment (QURL_DEPLOYMENT, then embedded) when
// none is installed; a deployment with no issuer keys yields ErrNoDeployment. With
// a provider installed it resolves opener config; a provider that itself fails
// closed propagates that error unchanged so EnterPortal refuses for the provider's
// stated reason.
//
// The HTTPClient is intentionally left nil here (default client). A caller that
// needs custom transport uses EnterPortalWith with an explicit Config.HTTPClient.
func resolveDefaultConfig(ctx context.Context) (Config, error) {
	p := DefaultProvider()
	if p == nil {
		// No provider installed is the COMMON case, not an error: fall back to the
		// deployment this build ships (or the QURL_DEPLOYMENT override). That is
		// what lets an integrator call EnterPortal with no setup at all.
		return defaultDeploymentConfig()
	}
	ts, allow, err := p.Resolve(ctx)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{TrustStore: ts, RelayAllowlist: allow}
	// A provider that also knows the deployment's cells opts into native UDP by
	// implementing CellProvider. A provider without cells — no CellProvider, or
	// a ResolveCells that returns nil — yields relay-only config on purpose:
	// the HTTPS relay is that provider's declared transport (see CellProvider),
	// not a quiet downgrade. StaticProvider carries whatever cells its
	// constructor was given; DiscoveryProvider is relay-only because its
	// manifest wire format has no cells.
	if cp, ok := p.(CellProvider); ok {
		cells, err := cp.ResolveCells(ctx)
		if err != nil {
			return Config{}, err
		}
		cfg.Cells = cells
	}
	return cfg, nil
}

// CellProvider is an optional Provider extension that also supplies the
// deployment's native UDP cell catalog. A Provider that implements it lets
// EnterPortal knock catalog cells directly instead of through the relay.
//
// The transport rule is explicit: a provider WITHOUT cells — one that does not
// implement CellProvider, or whose ResolveCells returns a nil catalog — serves
// every open over the HTTPS relay transport. That is the right shape for
// relay-based deployments (browsers can only deliver a knock over HTTPS, and
// the discovery manifest format carries no cells); it is never the right shape
// for a pinned native-UDP opener, which supplies cells and can omit the relay
// allowlist entirely so an open that cannot go over native UDP fails with
// ErrCellNotInCatalog instead of quietly using the relay.
type CellProvider interface {
	Provider
	ResolveCells(ctx context.Context) (*CellCatalog, error)
}
