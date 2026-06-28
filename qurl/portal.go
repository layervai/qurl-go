// Package qurl is the top-level entry point of the qURL Go SDK. It provides the two
// verbs most integrations need: CreatePortal mints a signed, expiring qURL link on
// the issuer side, and EnterPortal performs the opener flow for a received link.
//
// Applications normally install deployment trust anchors and the relay allowlist once
// through a Provider, then call EnterPortal with no per-call trust config. Minting and
// local verification work offline; a live open also requires the deployment's qURL
// admission service to accept the knock.
//
// EnterPortal stitches the two lower layers together in the protocol order:
//
//  1. Parse the #<version>.<claims>.<secret>.<sig> fragment.
//  2. Verify the issuer signature locally (REQUIRED — not optional for a
//     first-party client) against the issuer trust store.
//  3. Validate relay_url (HTTPS + allowlist) — ONLY after the signature verifies,
//     because relay_url is attacker-controlled until then.
//  4. Derive serverId = PubKeyFingerprint(cell_public_key).
//  5. Build an NHP knock using the per-qURL private key (from the link's secret
//     block) as the agent static identity and the cell public key as the server
//     static key, carrying the resource public key as the knock resource identity
//     and the signed claims as encrypted user data.
//  6. POST the opaque packet to relay_url + "/relay/" + serverId and decrypt the
//     authenticated reply.
//
// No external key is needed: the per-qURL credential rides inside the link. The
// caller supplies only trust anchors (which issuer keys to trust) and the relay
// allowlist — both deployment config, not per-link secrets.
package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// Config carries the deployment trust anchors EnterPortal needs. Neither is a
// per-link secret: the per-qURL credential is in the link itself. Both fail
// closed when empty (an empty trust store rejects every signature; an empty
// allowlist rejects every relay_url), so a misconfigured caller cannot resolve.
type Config struct {
	// TrustStore resolves a claim's kid to the issuer public key. REQUIRED.
	TrustStore *TrustStore
	// RelayAllowlist is the set of relay host[:port] origins a verified relay_url
	// may target. REQUIRED.
	RelayAllowlist *RelayAllowlist
	// HTTPClient is the client used for the relay POST. Optional; nil uses the
	// default client. Pin this to a fixed egress when the knock and the subsequent
	// resource request must share a source IP (see ResourceHandle).
	HTTPClient HTTPDoer
}

// HTTPDoer is the subset of *http.Client EnterPortal needs, narrowed so a caller
// can inject a fixed-egress or test client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ResourceHandle is the result of a successful EnterPortal: the resource URL returned
// after admission plus the facts a caller needs to actually use it.
//
// Same-egress-IP invariant: the NHP server opened access for the SOURCE IP of the
// relay POST. Any request the caller now makes to RedirectURL MUST egress from that
// same IP, or it will arrive at a server that opened access for a different
// address. Behind a rotating-egress NAT/proxy pool, pin the
// EnterPortal HTTPClient and the resource request to the same exit.
type ResourceHandle struct {
	// RedirectURL is the reachable resource location the server returned in the
	// authorized NHP_ACK (the qurl.site URL). Empty only if the server omitted it.
	RedirectURL string
	// OpenSeconds is how long access stays open for this admission,
	// as reported by the server (0 when not provided).
	OpenSeconds uint32
}

// ErrNotConfigured is returned by EnterPortal when Config is missing a trust
// store or relay allowlist (the fail-closed default).
var ErrNotConfigured = errors.New("qurl: EnterPortal requires a trust store and relay allowlist")

// EnterPortal opens a qURL link using the process-wide default credential provider
// (SetDefaultProvider). It is the locked, single-argument entry verb: a deployment
// installs its trust anchors / relay allowlist once at startup and then opens links
// with no per-call trust config.
//
// It resolves the provider for the trust anchors and relay allowlist, then delegates
// to EnterPortalWith — so the provider only SUPPLIES the trust material; the real
// verify + post-verify relay-allowlist enforcement is EnterPortalWith's, unchanged.
//
// Without an installed provider, EnterPortal fails closed with ErrNotConfigured.
// The SDK implements the local security checks and the core knock construction; completing
// a live open also requires the deployment's qURL admission service to be online.
// Tests and controlled integrations can inject anchors via a StaticProvider /
// DiscoveryProvider, or call EnterPortalWith directly.
func EnterPortal(ctx context.Context, qurlLink string) (*ResourceHandle, error) {
	cfg, err := resolveDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return EnterPortalWith(ctx, qurlLink, cfg)
}

// EnterPortalWith opens a qURL link using the supplied Config. It is the injectable
// seam behind EnterPortal: callers with their own trust anchors / relay allowlist
// (and tests using the vector issuer kid) use it directly.
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

	// 3. relay_url is now trusted to act on — validate HTTPS + allowlist.
	if err := qv2.ValidateRelayURL(claims.RelayURL, cfg.RelayAllowlist.core()); err != nil {
		return nil, err
	}

	// 4. Derive the relay routing id from the VERIFIED cell key.
	cellPub, err := qv2.DecodeCellPublicKey(claims)
	if err != nil {
		// Unreachable in practice: a verified claim already passed the parser's
		// 32-byte cell-key length check. Kept as defense in depth.
		return nil, fmt.Errorf("qurl: decode verified cell public key: %w", err)
	}

	// 5. Build the knock: device identity = the per-qURL private key from the
	// link's secret, server static key = the cell public key, resource identity =
	// the resource public key, user data = the signed claims.
	devicePriv, err := qv2.DecodeQurlUserPrivateKey(frag.Secret)
	if err != nil {
		return nil, fmt.Errorf("qurl: decode per-qURL private key: %w", err)
	}
	body, err := buildKnockBody(frag)
	if err != nil {
		return nil, err
	}

	// 6. One-shot relay knock using the in-link per-qURL key. The caller's egress
	// IP is the one the server opens access for (see ResourceHandle).
	reply, err := relayknock.Knock(ctx, claims.RelayURL, cellPub, body, relayknock.KnockOptions{
		HTTPClient:       cfg.HTTPClient,
		DeviceStaticPriv: devicePriv,
	})
	if err != nil {
		return nil, normalizeRelayError(err)
	}

	return interpretReply(reply)
}

// Compile-time guard: normalizeRelayError hand-copies relayknock.RelayError into the
// public RelayError, so the two must stay field-identical (a struct conversion only
// compiles when fields match) — drift becomes a build break here, like the Claims/Secret
// guards in facade.go.
var _ = RelayError(relayknock.RelayError{})

func normalizeRelayError(err error) error {
	var relayErr *relayknock.RelayError
	if errors.As(err, &relayErr) {
		return &RelayError{Status: relayErr.Status, Msg: relayErr.Msg}
	}
	return err
}

// interpretReply maps a decrypted, authenticated NHP reply to a ResourceHandle or
// an error. A cookie-challenge (server overload) is surfaced as a typed retryable
// error; a non-ACK is unexpected; an ACK with a server deny carries the errCode.
func interpretReply(reply *relayknock.Reply) (*ResourceHandle, error) {
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, fmt.Errorf("%w: unexpected NHP reply type %d (want ACK or cookie-challenge)", ErrMalformedReply, reply.Type)
	}

	ack, err := parseAck(reply.Body)
	if err != nil {
		return nil, err
	}
	if !ack.isSuccess() {
		return nil, &ServerDenyError{ErrCode: ack.ErrCode}
	}
	// A success ACK that carries no redirectUrl is not actionable — the caller has
	// nothing to reach. Fail closed rather than hand back an empty handle (matching
	// the seed smoke client's "success ACK carried no redirectUrl" rejection).
	if ack.RedirectURL == "" {
		return nil, fmt.Errorf("%w: success ACK carried no redirectUrl (errCode=%q)", ErrMalformedReply, ack.ErrCode)
	}
	return &ResourceHandle{RedirectURL: ack.RedirectURL, OpenSeconds: ack.OpenTime}, nil
}

// resolveDefaultConfig builds the EnterPortal Config from the process-wide default
// provider. With no provider installed it fails closed with ErrNotConfigured (the
// production issuer trust anchors / relay allowlist are not yet published, so an
// un-configured process must refuse rather than trust anything). With a provider
// installed it resolves the trust anchors + relay allowlist; a provider that itself
// fails closed (stale/unverifiable discovery manifest, missing anchors) propagates
// that error unchanged so EnterPortal refuses for the provider's stated reason.
//
// The HTTPClient is intentionally left nil here (default client). A caller that needs
// a pinned egress for the same-egress-IP invariant uses EnterPortalWith with an
// explicit Config.HTTPClient — the provider supplies trust material, not transport.
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
