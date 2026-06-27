package qurl

import (
	"context"
	"errors"
	"sync"

	"github.com/layervai/qurl-go/qv2"
)

// Trust/relay credential provider for the one-argument EnterPortal.
//
// EnterPortal needs two pieces of DEPLOYMENT config to open a link: the issuer
// trust anchors (kid -> P-256 public key) that verify the qv2 issuer signature, and
// the relay allowlist enforced AFTER the signature verifies. Neither is a per-link
// secret — the per-qURL credential rides inside the link itself. A Provider resolves
// exactly those two pieces, so callers get the locked one-arg verb without
// hand-wiring Config, while EnterPortalWith stays the explicit-config seam.
//
// The Provider SUPPLIES the trust material; it never enforces it. EnterPortal feeds
// the resolved *qv2.TrustStore / *qv2.RelayAllowlist straight into EnterPortalWith,
// which runs the real verify + post-verify relay-allowlist ordering. A provider
// cannot weaken or bypass that gate — at worst it supplies an empty store/allowlist,
// which fails closed (an empty trust store rejects every signature; an empty
// allowlist rejects every relay_url).

// Provider resolves the trust anchors and relay allowlist for EnterPortal.
//
// Resolve is called once per EnterPortal. An implementation MAY cache and refresh so a
// per-open call is cheap; it MAY also return a freshly rotated trust store (qv2 rotation
// is overlap-publish via the published map, so a provider re-publishes a superset map on
// rotation and outstanding links signed under either kid keep verifying). Resolve MUST
// fail closed: on any doubt about freshness/authenticity it returns an error rather than
// a partial or stale result, so EnterPortal refuses rather than trusting unverifiable
// anchors.
//
// Both returned values must be non-nil on success; a nil trust store or allowlist
// makes EnterPortalWith return ErrNotConfigured.
type Provider interface {
	Resolve(ctx context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error)
}

// StaticProvider is a Provider backed by fixed, in-process trust anchors and relay
// allowlist. It is the simplest concrete provider: tests, pinned deployments, and
// the embedded production defaults (once the prod anchors are published) use it. It
// performs no I/O and never changes after construction, so it is safe for concurrent
// Resolve calls.
//
// Rotation with a StaticProvider is a process-level operation: build a new
// StaticProvider whose trust store carries the overlap set (old + new kid) and swap
// it in via SetDefaultProvider (or hand it to EnterPortalWith). The store itself is
// immutable.
type StaticProvider struct {
	trustStore *qv2.TrustStore
	allowlist  *qv2.RelayAllowlist
}

// NewStaticProvider builds a StaticProvider from an already-constructed trust store
// and relay allowlist. Both are REQUIRED and must be non-nil — a static provider
// with a missing half would resolve to a config that fails closed downstream, so it
// is rejected at construction instead to surface the misconfiguration early.
func NewStaticProvider(ts *qv2.TrustStore, allow *qv2.RelayAllowlist) (*StaticProvider, error) {
	if ts == nil {
		return nil, errors.New("qurl: static provider requires a non-nil trust store")
	}
	if allow == nil {
		return nil, errors.New("qurl: static provider requires a non-nil relay allowlist")
	}
	return &StaticProvider{trustStore: ts, allowlist: allow}, nil
}

// Resolve returns the fixed trust store and allowlist. A nil receiver (a caller that
// ignored NewStaticProvider's construction error and installed the nil *StaticProvider)
// fails closed with ErrNotConfigured rather than panicking on the field read.
func (p *StaticProvider) Resolve(context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error) {
	if p == nil {
		return nil, nil, ErrNotConfigured
	}
	return p.trustStore, p.allowlist, nil
}

// defaultProvider is the process-wide provider the one-argument EnterPortal resolves
// through. It is settable (SetDefaultProvider) so a deployment can install its
// embedded defaults or a discovery provider ONCE at startup and then call the locked
// EnterPortal(ctx, link) everywhere with no per-call config.
//
// It is nil by default: the production qv2 issuer trust anchors and relay allowlist
// are not yet published (the qv2 admission contract is Proposed, not deployed), so an
// un-configured process MUST fail closed with ErrNotConfigured rather than trust
// anything. Installing a provider is what "lights up" the one-arg verb — no
// EnterPortal API change. Guarded by defaultProviderMu for race-free concurrent
// get/set (EnterPortal reads it under RLock).
var (
	defaultProviderMu sync.RWMutex
	defaultProvider   Provider
)

// SetDefaultProvider installs (or clears, with nil) the process-wide provider the
// one-argument EnterPortal resolves through. Call it once at startup. It is safe for
// concurrent use, and tests that swap it MUST restore the prior value (capture the
// DefaultProvider() return and reinstall via t.Cleanup) so a settable global does not
// bleed across tests.
func SetDefaultProvider(p Provider) {
	defaultProviderMu.Lock()
	defer defaultProviderMu.Unlock()
	defaultProvider = p
}

// DefaultProvider returns the currently installed process-wide provider, or nil if
// none is set. Exposed so a test can capture and restore the global around a swap.
func DefaultProvider() Provider {
	defaultProviderMu.RLock()
	defer defaultProviderMu.RUnlock()
	return defaultProvider
}
