package qurl

import (
	"context"
	"errors"
	"sync"
)

// Opener config provider for the one-argument EnterPortal.
//
// EnterPortal needs opener policy before it can open links. The policy is not an
// issuer credential: the per-qURL credential rides inside the link itself. A
// Provider resolves that policy so callers get the locked one-arg verb without
// hand-wiring Config, while EnterPortalWith stays the explicit-config seam.
//
// The Provider supplies config; it never bypasses verification. EnterPortal feeds
// the resolved trust policy into EnterPortalWith, which still verifies the link
// before using any platform access URL from it.

// Provider resolves opener config for EnterPortal.
//
// Resolve is called once per EnterPortal. An implementation MAY cache and
// refresh so a per-open call is cheap; it MAY also return freshly rotated opener
// config. Resolve MUST fail closed: on any doubt about freshness/authenticity it
// returns an error rather than a partial or stale result, so EnterPortal refuses
// rather than trusting unverifiable config.
//
// Both returned values must be non-nil on success; incomplete opener policy makes
// EnterPortalWith return ErrNotConfigured.
type Provider interface {
	Resolve(ctx context.Context) (*TrustStore, *RelayAllowlist, error)
}

// StaticProvider is a Provider backed by fixed, in-process opener config. It is
// the simplest concrete provider for tests and manually pinned config. It performs
// no I/O and never changes after construction, so it is safe for concurrent
// Resolve calls.
//
// Rotation with a StaticProvider is a process-level operation: build a new
// StaticProvider whose trust store carries the overlap set (old + new kid) and swap
// it in via SetDefaultProvider (or hand it to EnterPortalWith). The store itself is
// immutable.
type StaticProvider struct {
	trustStore *TrustStore
	allowlist  *RelayAllowlist
}

// NewStaticProvider builds a StaticProvider from already-constructed opener
// policy. Both values are REQUIRED and must be non-nil.
func NewStaticProvider(ts *TrustStore, allow *RelayAllowlist) (*StaticProvider, error) {
	if ts == nil {
		return nil, errors.New("qurl: static provider requires a non-nil trust store")
	}
	if allow == nil {
		return nil, errors.New("qurl: static provider requires a non-nil platform endpoint allowlist")
	}
	return &StaticProvider{trustStore: ts, allowlist: allow}, nil
}

// Resolve returns the fixed opener config. A nil receiver (a caller that
// ignored NewStaticProvider's construction error and installed the nil *StaticProvider)
// fails closed with ErrNotConfigured rather than panicking on the field read.
func (p *StaticProvider) Resolve(context.Context) (*TrustStore, *RelayAllowlist, error) {
	if p == nil {
		return nil, nil, ErrNotConfigured
	}
	return p.trustStore, p.allowlist, nil
}

// defaultProvider is the process-wide provider the one-argument EnterPortal resolves
// through. It is settable (SetDefaultProvider) so an application can install qURL
// opener config once at startup and then call EnterPortal(ctx, link) everywhere
// with no per-call config.
//
// It is nil by default, so an unconfigured process MUST fail closed with
// ErrNotConfigured rather than trust anything. Installing a provider is what
// lights up the one-arg verb. Guarded by defaultProviderMu for race-free
// concurrent get/set.
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
