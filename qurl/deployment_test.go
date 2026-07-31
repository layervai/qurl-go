package qurl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/layervai/qurl-go/internal/qv2"
)

// writeVendoredDeployment writes a deployment file carrying the vendored issuer
// key and pointing "vector-cell" at an unreachable native UDP endpoint. It is
// the exact file an operator ships: non-secret, no key material to generate.
func writeVendoredDeployment(t *testing.T, withCells bool) string {
	t.Helper()
	vf, err := qv2.LoadVectorBytes(conformance.IssuerSignatureVectors())
	if err != nil {
		t.Fatalf("load signature vectors: %v", err)
	}
	d := Deployment{
		Issuers: []ManifestIssuer{{Kid: vf.Issuer.KID, SPKIDERB64: vf.Issuer.SPKIDERB64}},
	}
	if withCells {
		key := make([]byte, 32)
		for i := range key {
			key[i] = 0x44
		}
		d.Cells = []DeploymentCell{{
			CellID:             "vector-cell",
			Host:               "127.0.0.1",
			Port:               9,
			ServerPublicKeyB64: base64.RawURLEncoding.EncodeToString(key),
		}}
	} else {
		d.RelayAllowlist = []string{"relay.example.com"}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal deployment: %v", err)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write deployment: %v", err)
	}
	return path
}

// noDefaultProvider guarantees this test exercises the shipped/override path
// rather than a provider another test installed in the same process.
func noDefaultProvider(t *testing.T) {
	t.Helper()
	prior := DefaultProvider()
	SetDefaultProvider(nil)
	t.Cleanup(func() { SetDefaultProvider(prior) })
}

// TestEnterPortal_ZeroSetupOpensOverNativeUDP is the whole point of shipping a
// deployment: an integrator writes ONE line and gets a verified, relay-free open.
// No trust store to assemble, no key decoding, no allowlist, no provider.
func TestEnterPortal_ZeroSetupOpensOverNativeUDP(t *testing.T) {
	noDefaultProvider(t)
	link, _, _ := vendoredAcceptLink(t)
	t.Setenv(EnvDeploymentPath, writeVendoredDeployment(t, true))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// The entire integration surface, verbatim:
	_, err := EnterPortal(ctx, link)

	if err == nil {
		t.Fatal("expected a native UDP transport error against an unreachable cell")
	}
	if errors.Is(err, ErrNotConfigured) {
		t.Fatalf("zero-setup open failed on configuration: %v", err)
	}
	if !strings.Contains(err.Error(), "nativeudp:") {
		t.Fatalf("zero-setup open did not reach the native UDP transport: %v", err)
	}
}

// TestEnterPortal_ZeroSetupWithoutCellsUsesRelay proves a deployment that
// publishes no cells still opens — through the relay — so the same one-line call
// works against a deployment that has not enabled direct UDP.
func TestEnterPortal_ZeroSetupWithoutCellsUsesRelay(t *testing.T) {
	noDefaultProvider(t)
	link, _, _ := vendoredAcceptLink(t)
	t.Setenv(EnvDeploymentPath, writeVendoredDeployment(t, false))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := EnterPortal(ctx, link)
	if err == nil {
		t.Fatal("expected a relay transport error reaching relay.example.com")
	}
	if errors.Is(err, ErrNotConfigured) {
		t.Fatalf("relay-only deployment reported a configuration error: %v", err)
	}
	if strings.Contains(err.Error(), "nativeudp:") {
		t.Fatalf("a deployment with no cells still used native UDP: %v", err)
	}
}

// TestEnterPortal_NoDeploymentFailsClosed proves a build that ships no issuers
// refuses to open rather than trusting anything, and says what to set.
func TestEnterPortal_NoDeploymentFailsClosed(t *testing.T) {
	noDefaultProvider(t)
	link, _, _ := vendoredAcceptLink(t)
	t.Setenv(EnvDeploymentPath, "")

	_, err := EnterPortal(context.Background(), link)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured with no shipped issuers, got %v", err)
	}
	if !strings.Contains(err.Error(), EnvDeploymentPath) {
		t.Fatalf("error does not tell the caller what to set: %v", err)
	}
}

// TestLoadDeploymentRejectsUnknownFields proves a stale or misspelled key is a
// loud failure. A silently ignored field in a TRUST file is how a deployment
// ends up believing it configured something it did not.
func TestLoadDeploymentRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"issuers":[],"relay_allowlists":["x"]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadDeployment(path); err == nil {
		t.Fatal("a misspelled trust field was accepted")
	}
}
