package qurl

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Opener config provider for the one-argument EnterPortal.
//
// EnterPortal needs opener trust config before it can open links. That config is
// not an issuer credential: the per-qURL credential rides inside the link
// itself. A Provider resolves the trust config so callers get the locked one-arg
// verb without hand-wiring Config, while EnterPortalWith stays the
// explicit-config seam.
//
// The Provider supplies config; it never bypasses verification. EnterPortal feeds
// the resolved trust config into EnterPortalWith, which still verifies the link
// before using any platform access URL from it.

// Provider resolves opener config for EnterPortal.
//
// Resolve is called once per EnterPortal. An implementation MAY cache and
// refresh so a per-open call is cheap; it MAY also return freshly rotated opener
// config. Resolve MUST fail closed: on any doubt about freshness/authenticity it
// returns an error rather than a partial or stale result, so EnterPortal refuses
// rather than trusting unverifiable config.
//
// The trust store must be non-nil on success. The allowlist gates the HTTPS
// relay transport and may be nil only when the provider also supplies cell
// endpoints through CellProvider; config carrying neither transport makes
// EnterPortalWith return ErrNotConfigured.
//
// A Provider alone yields RELAY-ONLY opener config: every open it serves uses
// the HTTPS relay transport. Native UDP requires the provider to also supply
// cell endpoints via the CellProvider extension.
type Provider interface {
	Resolve(ctx context.Context) (*TrustStore, *RelayAllowlist, error)
}

// StaticProvider is a Provider backed by fixed, in-process opener config. It is
// the simplest concrete provider for tests and manually pinned config. It performs
// no I/O and never changes after construction, so it is safe for concurrent
// Resolve and ResolveCells calls.
//
// A StaticProvider implements CellProvider, and the cells its construction
// supplied decide the transport EnterPortal uses (see CellProvider for the
// rule). With cells and an allowlist, catalog cells are knocked directly over
// native UDP and unknown cells fall back to the relay. With cells alone the
// opener is native-UDP-only: a link naming a cell outside the catalog fails
// with ErrCellNotInCatalog instead of quietly using the relay. With an
// allowlist alone every open uses the HTTPS relay transport.
//
// Rotation with a StaticProvider is a process-level operation: build a new
// StaticProvider whose trust store carries the overlap set (old + new kid) and swap
// it in via SetDefaultProvider (or hand it to EnterPortalWith). The store itself is
// immutable.
type StaticProvider struct {
	trustStore *TrustStore
	allowlist  *RelayAllowlist
	cells      *CellCatalog
}

// NewStaticProvider builds a StaticProvider from already-constructed opener
// config. The trust store is REQUIRED and must be non-nil. The allowlist and
// cells are each optional, but at least one must be supplied — with neither
// there is no transport an open could ever use. Cells take the same shape a
// deployment file's cells do and are validated by NewCellCatalog: one bad
// entry fails construction rather than silently dropping a cell.
func NewStaticProvider(ts *TrustStore, allow *RelayAllowlist, cells []CellEntry) (*StaticProvider, error) {
	if ts == nil {
		return nil, errors.New("qurl: static provider requires a non-nil trust store")
	}
	var catalog *CellCatalog
	if len(cells) > 0 {
		var err error
		catalog, err = NewCellCatalog(cells)
		if err != nil {
			return nil, err
		}
	}
	if allow == nil && catalog == nil {
		return nil, errors.New("qurl: static provider requires a platform endpoint allowlist, cell endpoints, or both")
	}
	return &StaticProvider{trustStore: ts, allowlist: allow, cells: catalog}, nil
}

// Resolve returns the fixed opener config. A nil receiver (a caller that
// ignored NewStaticProvider's construction error and installed the nil *StaticProvider)
// fails closed, returning ErrNotConfigured rather than panicking on the field read.
func (p *StaticProvider) Resolve(context.Context) (*TrustStore, *RelayAllowlist, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("%w: nil opener provider installed", ErrNotConfigured)
	}
	return p.trustStore, p.allowlist, nil
}

// ResolveCells returns the fixed cell catalog, or nil when construction
// supplied no cells — the relay-only shape. A nil receiver fails closed exactly
// as Resolve does.
func (p *StaticProvider) ResolveCells(context.Context) (*CellCatalog, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil opener provider installed", ErrNotConfigured)
	}
	return p.cells, nil
}

// Compile-time guard: StaticProvider must keep supplying cells through the
// CellProvider extension, or the documented pinning path silently loses its
// native UDP transport.
var _ CellProvider = (*StaticProvider)(nil)

// defaultProvider is the process-wide provider the one-argument EnterPortal resolves
// through. It is settable (SetDefaultProvider) so an application can install qURL
// opener config once at startup and then call EnterPortal(ctx, link) everywhere
// with no per-call config.
//
// It is nil by default, and nil is the common case, not a failure: EnterPortal
// then resolves opener config from the deployment (QURL_DEPLOYMENT, then the
// embedded one), and only a deployment carrying no issuer keys refuses with
// ErrNoDeployment (which wraps ErrNotConfigured). Installing a provider
// overrides that fallback. Guarded by defaultProviderMu for race-free
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
