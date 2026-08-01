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
			Port:               standardNHPUDPPort,
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

// TestDeploymentRejectsBlankOnlyRelayAllowlist proves a relay_allowlist of only
// blank entries is rejected at load. NewRelayAllowlist drops blanks, so such a
// list would look configured while rejecting every host — the open would die
// later at relay validation with a far less obvious diagnostic.
func TestDeploymentRejectsBlankOnlyRelayAllowlist(t *testing.T) {
	// The issuer key must be VALID. With a bogus key the config would fail in
	// buildTrustMaterial before the blank-only branch is ever reached, and this
	// test would pass even if that guard were deleted — proving nothing.
	vf, err := qv2.LoadVectorBytes(conformance.IssuerSignatureVectors())
	if err != nil {
		t.Fatalf("load signature vectors: %v", err)
	}
	d := &Deployment{
		Issuers:        []ManifestIssuer{{Kid: vf.Issuer.KID, SPKIDERB64: vf.Issuer.SPKIDERB64}},
		RelayAllowlist: []string{"  ", ""},
	}
	_, err = d.config()
	if err == nil {
		t.Fatal("a blank-only relay allowlist was accepted")
	}
	if !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("failed for the wrong reason, want the blank-allowlist guard: %v", err)
	}

	// Control: the same deployment with one usable entry must succeed, which is
	// what proves the rejection above came from blankness and nothing else.
	d.RelayAllowlist = []string{"  ", "relay.example.com"}
	if _, err := d.config(); err != nil {
		t.Fatalf("a deployment with one usable relay entry was rejected: %v", err)
	}
}

// TestLoadDeploymentRejectsTrailingData proves a second concatenated JSON value
// is rejected rather than silently ignored. A deployment file describes trust,
// so it gets the same strictness as an authenticated discovery manifest.
func TestLoadDeploymentRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	body := `{"issuers":[]}{"issuers":[{"kid":"sneaky","spki_der_b64":"x"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadDeployment(path); err == nil {
		t.Fatal("trailing JSON after the deployment object was silently ignored")
	}
}

// The Hub trust root is the registration-side equivalent of the issuer keys and
// cell endpoints: something the SDK knows about its own deployment, not
// something every integrator should retype. These pin the resolution so a future
// change cannot quietly put that burden back on the caller.

func TestDeploymentHubFromOverrideFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{
	  "issuers": [],
	  "cells": [],
	  "relay_allowlist": [],
	  "hub": {"host":"hub.example","port":443,"server_public_key_b64":"aGVsbG8="}
	}`), 0o600); err != nil {
		t.Fatalf("write deployment: %v", err)
	}
	t.Setenv(EnvDeploymentPath, path)

	hub, err := deploymentHub()
	if err != nil {
		t.Fatalf("deploymentHub: %v", err)
	}
	if hub.Host != "hub.example" || hub.Port != standardNHPUDPPort {
		t.Fatalf("hub = %+v", hub)
	}
}

// A deployment without a hub must report the actionable sentinel rather than a
// zero-valued hub, which would fail later and much less clearly.
func TestDeploymentHubAbsentIsActionable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"issuers":[],"cells":[],"relay_allowlist":[]}`), 0o600); err != nil {
		t.Fatalf("write deployment: %v", err)
	}
	t.Setenv(EnvDeploymentPath, path)

	if _, err := deploymentHub(); !errors.Is(err, ErrNoDeploymentHub) {
		t.Fatalf("got %v, want ErrNoDeploymentHub", err)
	}
}

// The returned hub must be a copy: mutating it cannot be allowed to repoint the
// hub for every later registration in the process.
func TestDeploymentHubReturnsCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{
	  "issuers": [], "cells": [], "relay_allowlist": [],
	  "hub": {"host":"hub.example","port":443,"server_public_key_b64":"aGVsbG8="}
	}`), 0o600); err != nil {
		t.Fatalf("write deployment: %v", err)
	}
	t.Setenv(EnvDeploymentPath, path)

	first, err := deploymentHub()
	if err != nil {
		t.Fatalf("deploymentHub: %v", err)
	}
	first.Host = "attacker.example"

	second, err := deploymentHub()
	if err != nil {
		t.Fatalf("deploymentHub second: %v", err)
	}
	if second.Host != "hub.example" {
		t.Fatalf("hub mutation leaked across calls: %+v", second)
	}
}

// Refresh must accept a zero-value hub and fall back to the shipped trust root,
// the same way registration does. Without this a caller had to carry the host,
// port, and key around solely to hand them back on renewal.
func TestRefreshAgentRuntimeAcceptsZeroHub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"issuers":[],"cells":[],"relay_allowlist":[]}`), 0o600); err != nil {
		t.Fatalf("write deployment: %v", err)
	}
	t.Setenv(EnvDeploymentPath, path)

	// This build ships no hub, so the zero-value path must surface the
	// actionable sentinel rather than a confusing endpoint-validation error.
	store := FileAgentState(filepath.Join(t.TempDir(), "agent-state.json"))
	_, _, err := RefreshAgentRuntime(context.Background(), HubBootstrap{}, store)
	if !errors.Is(err, ErrNoDeploymentHub) {
		t.Fatalf("zero hub with no shipped hub = %v, want ErrNoDeploymentHub", err)
	}
}
