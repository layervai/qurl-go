package qurl

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Shipped deployment knowledge.
//
// Opening a link needs two static facts about LayerV: which issuer keys to trust,
// and where the cells listen. Neither is secret, neither is in the link, and
// neither changes often — so the SDK ships them, exactly as it already ships a
// default credential path for issuing. Without this every integrator writes the
// same ~100 lines of key decoding and endpoint wiring before their first open,
// which is the friction this file exists to delete.
//
// Precedence, most specific first:
//
//  1. a Provider installed with SetDefaultProvider  — full programmatic control
//  2. QURL_DEPLOYMENT=/path/to/deployment.json      — self-hosted and sandbox
//  3. the deployment shipped in this build          — the common case, zero config
//
// A build that ships no issuers still fails closed: EnterPortal returns
// ErrNotConfigured rather than opening a link it cannot verify.

// EnvDeploymentPath names a deployment JSON file that overrides the shipped one.
const EnvDeploymentPath = "QURL_DEPLOYMENT"

//go:embed deployment.json
var shippedDeploymentJSON []byte

// DeploymentCell is one cell's published identity: its id and where it listens
// for native NHP UDP. The cell's public key is NOT here — that travels in the
// link's signed claims, so this file can never widen what an opener trusts.
type DeploymentCell struct {
	CellID string `json:"cell_id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

// Deployment is the static, non-secret description of a qURL deployment.
type Deployment struct {
	// Issuers are the trusted issuer keys (kid -> P-256 SPKI DER, base64).
	Issuers []ManifestIssuer `json:"issuers"`
	// Cells are the native UDP endpoints openers may knock directly.
	Cells []DeploymentCell `json:"cells"`
	// RelayAllowlist gates the relay fallback for cells absent from Cells.
	RelayAllowlist []string `json:"relay_allowlist"`
}

// ErrNoDeployment reports that this build ships no issuer keys and no override
// was supplied, so there is nothing to verify links against.
var ErrNoDeployment = fmt.Errorf("%w: no issuer keys are configured (set %s)", ErrNotConfigured, EnvDeploymentPath)

// LoadDeployment reads and validates a deployment JSON file.
func LoadDeployment(path string) (*Deployment, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("qurl: read deployment %s: %w", path, err)
	}
	return parseDeployment(raw, path)
}

func parseDeployment(raw []byte, source string) (*Deployment, error) {
	var d Deployment
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	// A typo'd or stale field is a silent trust misconfiguration otherwise.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return nil, fmt.Errorf("qurl: parse deployment %s: %w", source, err)
	}
	return &d, nil
}

// config turns a Deployment into opener Config. Issuers are required; cells and
// the relay allowlist are each optional, but at least one must be present or no
// transport could ever carry an open.
func (d *Deployment) config() (Config, error) {
	if d == nil || len(d.Issuers) == 0 {
		return Config{}, ErrNoDeployment
	}
	// Reuse the manifest path's issuer decoding rather than re-implementing it, so
	// a deployment file and a discovery manifest agree byte-for-byte on what a
	// valid issuer key is.
	trust, allow, err := buildTrustMaterial(&Manifest{
		Issuers:        d.Issuers,
		RelayAllowlist: d.RelayAllowlist,
	})
	if err != nil {
		return Config{}, err
	}

	cfg := Config{TrustStore: trust}
	if len(d.RelayAllowlist) > 0 {
		cfg.RelayAllowlist = allow
	}
	if len(d.Cells) > 0 {
		endpoints := make(map[string]CellEndpoint, len(d.Cells))
		for _, cell := range d.Cells {
			endpoints[cell.CellID] = CellEndpoint{Host: cell.Host, Port: cell.Port}
		}
		catalog, err := NewCellCatalog(endpoints)
		if err != nil {
			return Config{}, err
		}
		cfg.Cells = catalog
	}
	if cfg.Cells == nil && cfg.RelayAllowlist == nil {
		return Config{}, fmt.Errorf("%w: deployment has neither cells nor a relay allowlist", ErrNotConfigured)
	}
	return cfg, nil
}

// defaultDeploymentConfig resolves opener config from the environment override
// or the shipped deployment, in that order.
func defaultDeploymentConfig() (Config, error) {
	if path := strings.TrimSpace(os.Getenv(EnvDeploymentPath)); path != "" {
		d, err := LoadDeployment(path)
		if err != nil {
			return Config{}, err
		}
		return d.config()
	}
	d, err := parseDeployment(shippedDeploymentJSON, "(shipped)")
	if err != nil {
		return Config{}, err
	}
	cfg, err := d.config()
	if errors.Is(err, ErrNoDeployment) {
		// Keep the actionable message: this build simply ships no trust yet.
		return Config{}, ErrNoDeployment
	}
	return cfg, err
}
