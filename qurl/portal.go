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
	"net/http"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// Config carries opener configuration for EnterPortalWith. Most applications
// install a Provider once and call EnterPortal; Config is the explicit seam for
// tests and advanced clients.
type Config struct {
	// TrustStore resolves trusted issuer keys. REQUIRED.
	TrustStore *TrustStore
	// RelayAllowlist is the qURL platform access endpoint allowlist. REQUIRED.
	RelayAllowlist *RelayAllowlist
	// HTTPClient is the client used for the qURL platform request. Optional; nil
	// uses the default client. Advanced callers with fixed-egress requirements can
	// supply their own client.
	HTTPClient HTTPDoer
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
}

// ErrNotConfigured is returned by EnterPortal when opener config is missing.
var ErrNotConfigured = errors.New("qurl: EnterPortal requires qURL opener config")

// EnterPortal opens a qURL link using the process-wide default Provider
// (SetDefaultProvider). Applications install opener config once at startup, then
// open links with no per-call config.
//
// Without an installed provider, EnterPortal fails closed with ErrNotConfigured.
// Tests and advanced integrations can inject config with StaticProvider,
// DiscoveryProvider, or EnterPortalWith.
func EnterPortal(ctx context.Context, qurlLink string) (*ResourceHandle, error) {
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return EnterPortalWith(ctx, qurlLink, cfg)
}

// EnterPortalWith opens a qURL link using the supplied Config. It is the
// injectable seam behind EnterPortal for tests and advanced callers.
func EnterPortalWith(ctx context.Context, qurlLink string, cfg Config) (*ResourceHandle, error) {
	if cfg.TrustStore == nil || cfg.RelayAllowlist == nil {
		return nil, ErrNotConfigured
	}

	// 1+2. Parse the fragment and verify the issuer signature. FragmentFromLinkAndVerify
	// strict-parses then checks the signature over the exact received claims bytes;
	// nothing downstream runs until the signature is good.
	frag, err := qv2.FragmentFromLinkAndVerify(qurlLink, cfg.TrustStore.core())
	if err != nil {
		return nil, err
	}
	claims := frag.Claims

	// 3. The platform access URL is now trusted to act on; validate HTTPS and
	// the configured allowlist before making a request.
	if err := qv2.ValidateRelayURL(claims.RelayURL, cfg.RelayAllowlist.core()); err != nil {
		return nil, err
	}

	// 4. Decode the verified platform access key used by the wire request.
	cellPub, err := qv2.DecodeCellPublicKey(claims)
	if err != nil {
		// Unreachable in practice: a verified claim already passed the parser's
		// 32-byte platform access key length check. Kept as defense in depth.
		return nil, fmt.Errorf("qurl: decode verified platform access key: %w", err)
	}

	// 5. Build the platform access request from the link's per-qURL key, the
	// LayerV-provided access key, the resource identity, and the signed claims.
	devicePriv, err := qv2.DecodeQurlUserPrivateKey(frag.Secret)
	if err != nil {
		return nil, fmt.Errorf("qurl: decode per-qURL private key: %w", err)
	}
	body, err := buildKnockBody(frag)
	if err != nil {
		return nil, err
	}

	// 6. Ask the qURL platform for one-shot access using the in-link key. The
	// caller's egress IP is the one the platform opens access for (see
	// ResourceHandle).
	reply, err := relayknock.Knock(ctx, claims.RelayURL, cellPub, body, relayknock.KnockOptions{
		HTTPClient:       cfg.HTTPClient,
		DeviceStaticPriv: devicePriv,
	})
	if err != nil {
		return nil, normalizeRelayError(err)
	}

	return interpretReply(reply)
}

// Compile-time guard: the public platform error wrapper must stay
// field-identical with the internal transport error shape. The struct
// conversion fails to compile if either side drifts.
var _ = RelayError(relayknock.RelayError{})

func normalizeRelayError(err error) error {
	var relayErr *relayknock.RelayError
	if errors.As(err, &relayErr) {
		re := RelayError(*relayErr)
		return &relayErrorView{err: err, relay: &re}
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
		return nil, &ServerDenyError{ErrCode: ack.ErrCode}
	}
	// A success ACK that carries no resource URL is not actionable — the caller has
	// nothing to reach. Fail closed rather than hand back an empty handle.
	if ack.RedirectURL == "" {
		return nil, fmt.Errorf("%w: success ACK carried no resource URL (errCode=%q)", ErrMalformedReply, ack.ErrCode)
	}
	return &ResourceHandle{ResourceURL: ack.RedirectURL, OpenSeconds: ack.OpenTime}, nil
}

// resolveDefaultConfig builds the EnterPortal Config from the process-wide default
// provider. With no provider installed it fails closed with ErrNotConfigured. With
// a provider installed it resolves opener config; a provider that itself fails
// closed propagates that error unchanged so EnterPortal refuses for the provider's
// stated reason.
//
// The HTTPClient is intentionally left nil here (default client). A caller that
// needs custom transport uses EnterPortalWith with an explicit Config.HTTPClient.
func resolveDefaultConfig(ctx context.Context) (Config, error) {
	p := DefaultProvider()
	if p == nil {
		return Config{}, ErrNotConfigured
	}
	ts, allow, err := p.Resolve(ctx)
	if err != nil {
		return Config{}, err
	}
	return Config{TrustStore: ts, RelayAllowlist: allow}, nil
}
