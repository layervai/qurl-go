package qurl

import (
	"crypto/subtle"
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
// catalog keyed on it refuses valid links without that claim; and the relay itself
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

// CellCatalog maps a cell's public-key fingerprint to its native UDP endpoint
// and retains the full key for a constant-time comparison after lookup. It is
// immutable after construction and safe for concurrent use.
type CellCatalog struct {
	byFingerprint map[string]catalogCell
}

type catalogCell struct {
	endpoint        CellEndpoint
	serverPublicKey [32]byte
}

// ErrNoCellEndpoints is returned when a catalog would be built with no usable
// entries. An empty catalog is indistinguishable from "no catalog" at open time,
// so it is rejected at construction where the mistake is still diagnosable.
var ErrNoCellEndpoints = errors.New("qurl: cell catalog has no endpoints")

// ErrCellCatalogKeyMismatch reports that the compact lookup fingerprint found
// a row whose full X25519 key differs from the signed link key. The SDK refuses
// before DNS, UDP, or relay I/O. This can mean corrupt catalog state or a rare
// 64-bit fingerprint collision.
var ErrCellCatalogKeyMismatch = errors.New("qurl: cell catalog fingerprint matched a different full key")

// NewCellCatalog builds a catalog from cell entries. Every entry must carry a
// valid 32-byte key, a host, and the standard NHP UDP port; one bad entry fails the whole
// catalog rather than silently dropping a cell and refusing its links later.
func NewCellCatalog(entries []CellEntry) (*CellCatalog, error) {
	if len(entries) == 0 {
		return nil, ErrNoCellEndpoints
	}
	byFingerprint := make(map[string]catalogCell, len(entries))
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
		if entry.Port != standardNHPUDPPort {
			return nil, fmt.Errorf("qurl: cell %s has unsupported UDP port %d (want %d)", label, entry.Port, standardNHPUDPPort)
		}
		fingerprint := relayknock.PubKeyFingerprint(key)
		// Two entries for one cell key is a misconfiguration, not a preference:
		// last-wins would silently pick an address the operator did not intend,
		// or silently drop a cell and make its links unusable.
		// buildTrustMaterial rejects duplicate issuer kids for the same reason.
		if prior, dup := byFingerprint[fingerprint]; dup {
			priorLabel := strings.TrimSpace(prior.endpoint.CellID)
			if priorLabel == "" {
				priorLabel = "(unlabelled cell)"
			}
			if subtle.ConstantTimeCompare(prior.serverPublicKey[:], key) != 1 {
				return nil, fmt.Errorf(
					"%w: cells %s and %s collide", ErrCellCatalogKeyMismatch, priorLabel, label)
			}
			return nil, fmt.Errorf(
				"qurl: cells %s and %s share a server public key", priorLabel, label)
		}
		var fullKey [32]byte
		copy(fullKey[:], key)
		byFingerprint[fingerprint] = catalogCell{
			endpoint:        CellEndpoint{CellID: entry.CellID, Host: host, Port: entry.Port},
			serverPublicKey: fullKey,
		}
	}
	return &CellCatalog{byFingerprint: byFingerprint}, nil
}

// lookup returns the endpoint for the cell holding cellPub, which the caller
// must have taken from VERIFIED claims. A nil catalog or an unknown cell reports
// false; the caller refuses unknown cells in a configured catalog. A matching 64-bit
// fingerprint with a different full key returns ErrCellCatalogKeyMismatch. It
// must never fall back or perform network I/O.
func (c *CellCatalog) lookup(cellPub []byte) (CellEndpoint, bool, error) {
	if c == nil || len(cellPub) == 0 {
		return CellEndpoint{}, false, nil
	}
	cell, ok := c.byFingerprint[relayknock.PubKeyFingerprint(cellPub)]
	if !ok {
		return CellEndpoint{}, false, nil
	}
	if len(cellPub) != len(cell.serverPublicKey) || subtle.ConstantTimeCompare(cell.serverPublicKey[:], cellPub) != 1 {
		return CellEndpoint{}, false, ErrCellCatalogKeyMismatch
	}
	return cell.endpoint, true, nil
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
