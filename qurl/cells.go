package qurl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/layervai/qurl-go/relayknock"
)

// Native UDP cell endpoints.
//
// A qURL knock is an opaque NHP packet encrypted to the cell's public key. The
// relay does not read it, cannot alter it, and exists only so that BROWSERS —
// which cannot send UDP — can still deliver one. A Go program has no such
// limitation, so when the opener knows where the named cell listens it sends the
// same bytes straight there over UDP and skips the relay entirely.
//
// Entries are keyed by the cell's PUBLIC KEY, not by cell id. Two reasons:
// cell_id is an optional claim that real deployments do not always mint, so a
// catalog keyed on it silently degrades to the relay; and the relay itself
// already routes by a fingerprint of this key, so keying on it means the SDK and
// the relay agree on cell identity by construction rather than by convention.
//
// The endpoint is deployment knowledge, not link data: a link says which cell
// holds the resource, never where that cell lives. Keeping the address out of
// the link means a forged link cannot aim a knock at an attacker-chosen host,
// and re-addressing a cell never invalidates already-minted links.

// CellEndpoint is one cell's native NHP UDP endpoint.
type CellEndpoint struct {
	// CellID is a human-readable label for diagnostics. It is NOT used to match
	// links — the public key is.
	CellID string
	// Host is the cell's LayerV-owned DNS name, resolved on every exchange.
	Host string
	// Port is the cell's NHP UDP port.
	Port int
}

// CellEntry is one catalog entry as an operator writes it: where a cell lives,
// identified by the same public key its links carry.
type CellEntry struct {
	// ServerPublicKeyB64 is the cell's raw 32-byte X25519 NHP key, base64. Both
	// the standard and URL alphabets are accepted, padded or not, because this
	// value is copied between tools that disagree about padding.
	ServerPublicKeyB64 string
	CellID             string
	Host               string
	Port               int
}

// CellCatalog maps a cell's public-key fingerprint to its native UDP endpoint.
// It is immutable after construction and safe for concurrent use.
type CellCatalog struct {
	byFingerprint map[string]CellEndpoint
}

// ErrNoCellEndpoints is returned when a catalog would be built with no usable
// entries. An empty catalog is indistinguishable from "no catalog" at open time,
// so it is rejected at construction where the mistake is still diagnosable.
var ErrNoCellEndpoints = errors.New("qurl: cell catalog has no endpoints")

// NewCellCatalog builds a catalog from cell entries. Every entry must carry a
// valid 32-byte key, a host, and an in-range port; one bad entry fails the whole
// catalog rather than silently dropping a cell, because a silently missing cell
// degrades to the relay instead of failing — exactly the kind of quiet fallback
// that hides a misconfiguration.
func NewCellCatalog(entries []CellEntry) (*CellCatalog, error) {
	if len(entries) == 0 {
		return nil, ErrNoCellEndpoints
	}
	byFingerprint := make(map[string]CellEndpoint, len(entries))
	for _, entry := range entries {
		label := strings.TrimSpace(entry.CellID)
		if label == "" {
			label = "(unlabelled cell)"
		}
		key, err := decodeCellPublicKey(entry.ServerPublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("qurl: cell %s: %w", label, err)
		}
		host := strings.TrimSpace(entry.Host)
		if host == "" {
			return nil, fmt.Errorf("qurl: cell %s has no host", label)
		}
		if entry.Port <= 0 || entry.Port > 65535 {
			return nil, fmt.Errorf("qurl: cell %s has out-of-range port %d", label, entry.Port)
		}
		byFingerprint[relayknock.PubKeyFingerprint(key)] = CellEndpoint{
			CellID: entry.CellID, Host: host, Port: entry.Port,
		}
	}
	return &CellCatalog{byFingerprint: byFingerprint}, nil
}

// lookup returns the endpoint for the cell holding cellPub, which the caller
// must have taken from VERIFIED claims. A nil catalog or an unknown cell reports
// false, routing that open through the relay — the correct behavior for a cell
// this build predates.
func (c *CellCatalog) lookup(cellPub []byte) (CellEndpoint, bool) {
	if c == nil || len(cellPub) == 0 {
		return CellEndpoint{}, false
	}
	ep, ok := c.byFingerprint[relayknock.PubKeyFingerprint(cellPub)]
	return ep, ok
}

// decodeCellPublicKey accepts a raw 32-byte X25519 key in any common base64
// spelling. Operators copy these between Terraform, SSM, and JSON, which
// disagree about alphabet and padding; rejecting a correct key over punctuation
// would be friction with no security value, while the length check is what
// actually matters.
func decodeCellPublicKey(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, errors.New("has no server public key")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(trimmed); err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("server public key is %d bytes, want 32", len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("server public key is not valid base64")
}
