package qurl

import (
	"errors"
	"fmt"
	"strings"
)

// Native UDP cell endpoints.
//
// A qURL knock is an opaque NHP packet encrypted to the cell's public key. The
// relay does not read it, cannot alter it, and exists only so that BROWSERS —
// which cannot send UDP — can still deliver one. A Go program has no such
// limitation, so when the opener knows where the named cell listens it sends the
// same bytes straight there over UDP and skips the relay entirely.
//
// The endpoint is deployment knowledge, not link data: a link names a cell, it
// never says where that cell lives. Keeping the address out of the link means a
// forged or replayed link cannot aim a knock at an attacker-chosen host, and
// re-addressing a cell never invalidates already-minted links.

// CellEndpoint is one cell's native NHP UDP endpoint. It carries no key: the
// cell's public key is already in the link's SIGNED claims, so the endpoint
// supplies only the address and can never widen what the opener trusts.
type CellEndpoint struct {
	// Host is the cell's LayerV-owned DNS name, resolved on every exchange.
	Host string
	// Port is the cell's NHP UDP port.
	Port int
}

// CellCatalog maps a cell id to its native UDP endpoint. It is immutable after
// construction and safe for concurrent use.
type CellCatalog struct {
	byID map[string]CellEndpoint
}

// ErrNoCellEndpoints is returned when a catalog would be built with no usable
// entries. An empty catalog is indistinguishable from "no catalog" at open time,
// so it is rejected at construction where the mistake is still diagnosable.
var ErrNoCellEndpoints = errors.New("qurl: cell catalog has no endpoints")

// NewCellCatalog builds a catalog from cell id -> endpoint. Every entry must
// carry a non-empty host and a port in range; a single bad entry fails the whole
// catalog rather than silently dropping one cell, because a silently missing
// cell degrades to the relay instead of failing, which is exactly the kind of
// quiet fallback that hides a misconfiguration.
func NewCellCatalog(endpoints map[string]CellEndpoint) (*CellCatalog, error) {
	if len(endpoints) == 0 {
		return nil, ErrNoCellEndpoints
	}
	byID := make(map[string]CellEndpoint, len(endpoints))
	for cellID, ep := range endpoints {
		id := strings.TrimSpace(cellID)
		if id == "" {
			return nil, errors.New("qurl: cell catalog has an empty cell id")
		}
		host := strings.TrimSpace(ep.Host)
		if host == "" {
			return nil, fmt.Errorf("qurl: cell %q has no host", id)
		}
		if ep.Port <= 0 || ep.Port > 65535 {
			return nil, fmt.Errorf("qurl: cell %q has out-of-range port %d", id, ep.Port)
		}
		byID[id] = CellEndpoint{Host: host, Port: ep.Port}
	}
	return &CellCatalog{byID: byID}, nil
}

// Lookup returns the endpoint for cellID. A nil catalog, an empty cell id, or an
// unknown cell all report false, which routes that open through the relay — the
// correct behavior for a cell this build predates.
func (c *CellCatalog) Lookup(cellID string) (CellEndpoint, bool) {
	if c == nil || cellID == "" {
		return CellEndpoint{}, false
	}
	ep, ok := c.byID[cellID]
	return ep, ok
}
