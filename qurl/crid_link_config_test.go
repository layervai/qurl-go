package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
)

// Where the first packet goes, and what happens when the configuration cannot
// say. Every refusal here must come before any request: a CRID link request
// that cannot be addressed and verified is not sent to find that out.

func TestValidateCRIDLinkOrigin(t *testing.T) {
	for _, origin := range []string{
		"https://qurl.link",
		"https://links.example.org",
		"https://links.example.org:8443",
		"https://127.0.0.1:8443",
		"https://[::1]:8443",
		"https://xn--bcher-kva.example",
	} {
		if err := validateCRIDLinkOrigin(origin); err != nil {
			t.Errorf("validateCRIDLinkOrigin(%q) = %v, want accepted", origin, err)
		}
	}

	// Each of these is either not an https origin or a second spelling of one.
	// A second spelling is refused because an issued link is matched against
	// this string as text: it would reject every link the server issues.
	for _, origin := range []string{
		"",
		"qurl.link",
		"//qurl.link",
		"http://qurl.link",
		"ftp://qurl.link",
		"HTTPS://qurl.link",
		"https://QURL.link",
		"https://qurl.link/",
		"https://qurl.link/path",
		"https://qurl.link?x=1",
		"https://qurl.link?",
		"https://qurl.link#",
		"https://qurl.link#qv2t1",
		"https://user@qurl.link",
		"https://user:pass@qurl.link",
		"https://qurl.link:443",
		"https://qurl.link:0443",
		"https://qurl.link:08443",
		"https://qurl.link:0",
		"https://qurl.link:",
		"https://qurl.link:port",
		"https://qurl.link:99999",
		"https://",
		"https:///",
		"https://qurl.link ",
		" https://qurl.link",
		"https:qurl.link",
	} {
		if err := validateCRIDLinkOrigin(origin); err == nil {
			t.Errorf("validateCRIDLinkOrigin(%q) accepted a value that is not one canonical https origin", origin)
		}
	}
}

func TestResolveCRIDLinkEndpoint(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	base := fixture.cfg

	endpoint, err := resolveCRIDLinkEndpoint(base)
	if err != nil {
		t.Fatalf("the fixture configuration does not resolve: %v", err)
	}
	if endpoint.relayURL != fixture.peer.server.URL || endpoint.linkOrigin != cridLinkTestOrigin || endpoint.userAgent != "" ||
		!bytes.Equal(endpoint.serverPublicKey, fixture.peer.serverKey.PublicKey().Bytes()) {
		t.Fatalf("resolved endpoint = %+v", endpoint)
	}

	twoCells, err := NewCellCatalog([]CellEntry{
		{ServerPublicKeyB64: vectorCellKeyB64(t), CellID: "cell-a", Host: "a.example.com", Port: standardNHPUDPPort},
		{ServerPublicKeyB64: otherCellKeyB64(t), CellID: "cell-b", Host: "b.example.com", Port: standardNHPUDPPort},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayHost := strings.TrimPrefix(fixture.peer.server.URL, "https://")

	lowOrderCell, err := NewCellCatalog([]CellEntry{{
		ServerPublicKeyB64: lowOrderTestNHPServerPublicKeyB64, CellID: "low-order", Host: "cell.example.test", Port: standardNHPUDPPort,
	}})
	if err != nil {
		t.Fatal(err)
	}

	// none is a configuration with no endpoint at all. Every other case names
	// an endpoint that cannot be used, and a caller must be able to tell the
	// two apart: the first is "not offered here", the second is a fault.
	const none, unusable = false, true
	for _, tc := range []struct {
		name string
		edit func(cfg *Config)
		// misconfigured says whether the error must match
		// ErrCRIDLinkMisconfigured as well as ErrCRIDLinkNotConfigured.
		misconfigured bool
		// also is another sentinel the error must match; says is text the
		// message must contain so an operator can tell the cases apart.
		also error
		says string
	}{
		{"no endpoint", func(cfg *Config) { cfg.CRIDLink = nil }, none, nil, "crid_link"},
		// With no endpoint nothing else is looked at: it stays "none".
		{"no endpoint and no cell", func(cfg *Config) { cfg.CRIDLink, cfg.Cells = nil, nil }, none, nil, "names none"},
		{"no endpoint and no allowlist", func(cfg *Config) { cfg.CRIDLink, cfg.RelayAllowlist = nil, nil }, none, nil, "names none"},

		{"empty endpoint", func(cfg *Config) { cfg.CRIDLink = &CRIDLinkConfig{} }, unusable, ErrRelayURL, "relay URL"},
		{"no cell", func(cfg *Config) { cfg.Cells = nil }, unusable, nil, "names no cell"},
		{"several cells", func(cfg *Config) { cfg.Cells = twoCells }, unusable, nil, "names 2 cells"},
		// A catalog entry is only length-checked, so a key that cannot carry a
		// key agreement reaches this far and is refused here as configuration.
		{"unusable cell key", func(cfg *Config) { cfg.Cells = lowOrderCell }, unusable, nil, "server public key is unusable"},

		{"no relay URL", func(cfg *Config) { cfg.CRIDLink.RelayURL = "" }, unusable, ErrRelayURL, "relay URL"},
		{"relay over http", func(cfg *Config) { cfg.CRIDLink.RelayURL = "http://" + relayHost }, unusable, ErrRelayURL, "https"},
		{"relay not on the allowlist", func(cfg *Config) { cfg.CRIDLink.RelayURL = "https://relay.example.org" }, unusable, ErrRelayURL, "allowlist"},
		{"no allowlist", func(cfg *Config) { cfg.RelayAllowlist = nil }, unusable, ErrRelayURL, "allowlist"},
		{"empty allowlist", func(cfg *Config) { cfg.RelayAllowlist = NewRelayAllowlist(nil) }, unusable, ErrRelayURL, "allowlist"},
		{"relay with userinfo", func(cfg *Config) { cfg.CRIDLink.RelayURL = "https://user@" + relayHost }, unusable, ErrRelayURL, "userinfo"},
		{"relay with a query", func(cfg *Config) { cfg.CRIDLink.RelayURL = fixture.peer.server.URL + "?x=1" }, unusable, ErrRelayURL, "query"},
		{"relay with an empty query", func(cfg *Config) { cfg.CRIDLink.RelayURL = fixture.peer.server.URL + "?" }, unusable, ErrRelayURL, "query"},
		{"relay with a fragment", func(cfg *Config) { cfg.CRIDLink.RelayURL = fixture.peer.server.URL + "#x" }, unusable, ErrRelayURL, "fragment"},

		{"no link origin", func(cfg *Config) { cfg.CRIDLink.LinkOrigin = "" }, unusable, nil, "link origin"},
		{"link origin over http", func(cfg *Config) { cfg.CRIDLink.LinkOrigin = "http://qurl.link" }, unusable, nil, "link origin"},
		{"link origin with a slash", func(cfg *Config) { cfg.CRIDLink.LinkOrigin = "https://qurl.link/" }, unusable, nil, "link origin"},
		{"link origin in upper case", func(cfg *Config) { cfg.CRIDLink.LinkOrigin = "https://QURL.LINK" }, unusable, nil, "lower case"},
		{"link origin with the default port", func(cfg *Config) { cfg.CRIDLink.LinkOrigin = "https://qurl.link:443" }, unusable, nil, "default port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			endpointCopy := *base.CRIDLink
			cfg.CRIDLink = &endpointCopy
			doer := &refusingDoer{t: t}
			cfg.HTTPClient = doer
			tc.edit(&cfg)

			_, resolveErr := resolveCRIDLinkEndpoint(cfg)
			checkErr := CheckCRIDLinkConfigWith(cfg)
			issued, requestErr := RequestCRIDLinkWith(t.Context(), fixture.crid, cfg)
			handle, openErr := OpenCRIDWith(t.Context(), fixture.crid, cfg)
			if issued != nil || handle != nil {
				t.Fatal("an unconfigured request returned a result")
			}
			// The check says, without a CRID, what the two calls say with one.
			for call, err := range map[string]error{
				"resolveCRIDLinkEndpoint": resolveErr, "CheckCRIDLinkConfigWith": checkErr,
				"RequestCRIDLinkWith": requestErr, "OpenCRIDWith": openErr,
			} {
				if !errors.Is(err, ErrCRIDLinkNotConfigured) || !errors.Is(err, ErrNotConfigured) {
					t.Fatalf("%s error = %v, want ErrCRIDLinkNotConfigured", call, err)
				}
				if got := errors.Is(err, ErrCRIDLinkMisconfigured); got != tc.misconfigured {
					t.Fatalf("%s error = %v; matches ErrCRIDLinkMisconfigured = %t, want %t", call, err, got, tc.misconfigured)
				}
				if tc.also != nil && !errors.Is(err, tc.also) {
					t.Fatalf("%s error = %v, want it to match %v too", call, err, tc.also)
				}
				if !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("%s error %q does not say %q", call, err, tc.says)
				}
			}
			if doer.called || len(fixture.peer.seen()) != 0 {
				t.Fatal("a request was sent although the configuration cannot carry one")
			}
		})
	}

	// A trust store is the opener's own requirement, reported as it is for a
	// link open: the request is not configured at all, not just its endpoint.
	// That holds with an endpoint and without one.
	t.Run("no trust store", func(t *testing.T) {
		for name, cridLink := range map[string]*CRIDLinkConfig{"with an endpoint": base.CRIDLink, "without an endpoint": nil} {
			cfg := base
			cfg.TrustStore, cfg.CRIDLink = nil, cridLink
			_, requestErr := RequestCRIDLinkWith(t.Context(), fixture.crid, cfg)
			for call, err := range map[string]error{"RequestCRIDLinkWith": requestErr, "CheckCRIDLinkConfigWith": CheckCRIDLinkConfigWith(cfg)} {
				if !errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrCRIDLinkNotConfigured) || errors.Is(err, ErrCRIDLinkMisconfigured) {
					t.Fatalf("%s, %s: error = %v, want ErrNotConfigured and neither endpoint error", name, call, err)
				}
			}
		}
	})

	// The check passes exactly the configuration a request is sent with.
	t.Run("usable", func(t *testing.T) {
		if err := CheckCRIDLinkConfigWith(base); err != nil {
			t.Fatalf("CheckCRIDLinkConfigWith(the fixture configuration) = %v, want nil", err)
		}
		if got := len(fixture.peer.seen()); got != 0 {
			t.Fatalf("checking the configuration sent %d requests", got)
		}
	})

	// A relay base URL may carry a path prefix; the request path is appended.
	t.Run("relay with a path prefix", func(t *testing.T) {
		cfg := base
		endpointCopy := *base.CRIDLink
		endpointCopy.RelayURL = fixture.peer.server.URL + "/edge/"
		cfg.CRIDLink = &endpointCopy
		doer := &capturingDoer{}
		cfg.HTTPClient = doer
		_, _ = RequestCRIDLinkWith(t.Context(), fixture.crid, cfg)
		want := fixture.peer.server.URL + "/edge/relay/" + relayknock.PubKeyFingerprint(fixture.peer.serverKey.PublicKey().Bytes())
		if doer.gotURL != want {
			t.Fatalf("request URL = %q, want %q", doer.gotURL, want)
		}
	})
}

// The key a request is sealed to is the catalog's, and handing it out must
// not let a caller change the catalog.
func TestCellCatalogSoleServerPublicKey(t *testing.T) {
	var none *CellCatalog
	if key, cells := none.soleServerPublicKey(); key != nil || cells != 0 {
		t.Fatalf("nil catalog = %x, %d cells", key, cells)
	}

	catalog := unreachableCellCatalog(t, vectorCellKeyB64(t))
	key, cells := catalog.soleServerPublicKey()
	if cells != 1 || !bytes.Equal(key, bytes.Repeat([]byte{0x44}, 32)) {
		t.Fatalf("sole key = %x, %d cells", key, cells)
	}
	key[0] ^= 0xff
	again, _ := catalog.soleServerPublicKey()
	if !bytes.Equal(again, bytes.Repeat([]byte{0x44}, 32)) {
		t.Fatal("mutating the returned key changed the catalog")
	}
	if _, found, err := catalog.lookup(bytes.Repeat([]byte{0x44}, 32)); err != nil || !found {
		t.Fatalf("the catalog no longer finds its own cell: %v", err)
	}

	two, err := NewCellCatalog([]CellEntry{
		{ServerPublicKeyB64: vectorCellKeyB64(t), CellID: "cell-a", Host: "a.example.com", Port: standardNHPUDPPort},
		{ServerPublicKeyB64: otherCellKeyB64(t), CellID: "cell-b", Host: "b.example.com", Port: standardNHPUDPPort},
	})
	if err != nil {
		t.Fatal(err)
	}
	if key, cells := two.soleServerPublicKey(); key != nil || cells != 2 {
		t.Fatalf("two-cell catalog = %x, %d cells; a key must not be chosen", key, cells)
	}
}

// cridLinkDeploymentFile writes a deployment file that trusts signer, names one
// cell at cell.example.com, allows relay.example.com, and — when cridLinkJSON
// is non-empty — carries that text as its "crid_link" member.
func cridLinkDeploymentFile(t *testing.T, signer *LocalSigner, cellKey []byte, cridLinkJSON string) string {
	t.Helper()
	return cridLinkDeploymentFileFor(t, signer, cellKey, "cell.example.com", "relay.example.com", cridLinkJSON)
}

// cridLinkDeploymentFileFor is cridLinkDeploymentFile with the cell host and
// the allowed relay host chosen by the caller.
func cridLinkDeploymentFileFor(t *testing.T, signer *LocalSigner, cellKey []byte, cellHost, relayHost, cridLinkJSON string) string {
	t.Helper()
	issuerDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	deployment := map[string]any{
		"issuers": []map[string]string{{"kid": signer.KID(), "spki_der_b64": base64.RawURLEncoding.EncodeToString(issuerDER)}},
		"cells": []map[string]any{{
			"cell_id": "cell0", "host": cellHost, "port": standardNHPUDPPort,
			"server_public_key_b64": base64.StdEncoding.EncodeToString(cellKey),
		}},
		"relay_allowlist": []string{relayHost},
	}
	if cridLinkJSON != "" {
		deployment["crid_link"] = json.RawMessage(cridLinkJSON)
	}
	raw, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeploymentCRIDLink(t *testing.T) {
	signer, _ := mintSigner(t)
	cellKey := bytes.Repeat([]byte{0x44}, 32)
	const endpoint = `{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link"}`

	t.Run("carried into the opener config", func(t *testing.T) {
		deployment, err := LoadDeployment(cridLinkDeploymentFile(t, signer, cellKey, endpoint))
		if err != nil {
			t.Fatal(err)
		}
		if deployment.CRIDLink == nil || *deployment.CRIDLink != (DeploymentCRIDLink{
			RelayURL: "https://relay.example.com", LinkOrigin: "https://qurl.link",
		}) {
			t.Fatalf("decoded crid_link = %+v", deployment.CRIDLink)
		}
		cfg, err := deployment.config()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CRIDLink == nil || *cfg.CRIDLink != (CRIDLinkConfig{
			RelayURL: "https://relay.example.com", LinkOrigin: "https://qurl.link",
		}) {
			t.Fatalf("config CRIDLink = %+v", cfg.CRIDLink)
		}
		if _, err := resolveCRIDLinkEndpoint(cfg); err != nil {
			t.Fatalf("a well-formed deployment does not resolve: %v", err)
		}
		// The config owns its copy: changing it must not reach the deployment.
		cfg.CRIDLink.RelayURL = "https://changed.example.com"
		if deployment.CRIDLink.RelayURL != "https://relay.example.com" {
			t.Fatal("the config aliases the deployment's crid_link")
		}
		// The member survives a round trip under its wire name.
		encoded, err := json.Marshal(deployment)
		if err != nil || !strings.Contains(string(encoded), `"crid_link":`+endpoint) {
			t.Fatalf("re-encoded deployment = %s, %v", encoded, err)
		}
	})

	t.Run("absent leaves the opener as it was", func(t *testing.T) {
		for name, member := range map[string]string{"omitted": "", "null": "null"} {
			deployment, err := LoadDeployment(cridLinkDeploymentFile(t, signer, cellKey, member))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			cfg, err := deployment.config()
			if err != nil || deployment.CRIDLink != nil || cfg.CRIDLink != nil {
				t.Fatalf("%s: crid_link = %+v, config = %+v, %v", name, deployment.CRIDLink, cfg.CRIDLink, err)
			}
			if cfg.Cells == nil || cfg.TrustStore == nil {
				t.Fatalf("%s: the opener config lost its trust or its cells", name)
			}
		}
		// An absent member is not written back as an empty one.
		encoded, err := json.Marshal(Deployment{})
		if err != nil || strings.Contains(string(encoded), "crid_link") {
			t.Fatalf("an empty deployment encodes crid_link: %s, %v", encoded, err)
		}
	})

	// The file describes trust, so decoding is strict inside the new object as
	// well: a misspelled or unknown member is an error, not a silent default.
	t.Run("strict inside the object", func(t *testing.T) {
		noDefaultProvider(t)
		for name, member := range map[string]string{
			"unknown member":           `{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link","server_public_key_b64":"AAAA"}`,
			"misspelled member":        `{"relay_urls":"https://relay.example.com","link_origin":"https://qurl.link"}`,
			"not an object":            `"https://relay.example.com"`,
			"an array":                 `[{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link"}]`,
			"member of the wrong type": `{"relay_url":["https://relay.example.com"],"link_origin":"https://qurl.link"}`,
		} {
			path := cridLinkDeploymentFile(t, signer, cellKey, member)
			if _, err := LoadDeployment(path); err == nil {
				t.Errorf("%s: a malformed crid_link was accepted", name)
			}
			// The consequence, which the documentation states and an operator
			// has to know: a file that does not decode configures nothing, so
			// with it in place no link opens either.
			t.Setenv(EnvDeploymentPath, path)
			if _, err := resolveDefaultConfig(t.Context()); err == nil {
				t.Errorf("%s: a deployment file with a malformed crid_link still configured the opener", name)
			}
		}
	})

	// A wrong value in this optional object must not take link opening down
	// with it. The deployment still yields opener config; only the CRID request
	// reports the value, and reports it before sending anything. (A malformed
	// object is the case above: the strict decoder refuses the whole file.)
	t.Run("a wrong value does not stop link opens", func(t *testing.T) {
		for name, member := range map[string]string{
			"relay not on the allowlist": `{"relay_url":"https://relay.example.org","link_origin":"https://qurl.link"}`,
			"relay over http":            `{"relay_url":"http://relay.example.com","link_origin":"https://qurl.link"}`,
			"origin with a path":         `{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link/"}`,
			"empty object":               `{}`,
		} {
			deployment, err := LoadDeployment(cridLinkDeploymentFile(t, signer, cellKey, member))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			cfg, err := deployment.config()
			if err != nil {
				t.Fatalf("%s: a wrong crid_link value failed the opener config: %v", name, err)
			}
			if cfg.TrustStore == nil || cfg.Cells == nil {
				t.Fatalf("%s: the opener config is incomplete", name)
			}
			doer := &refusingDoer{t: t}
			cfg.HTTPClient = doer
			held, _, _ := cridKeyMatchFixture(t)
			if _, err := RequestCRIDLinkWith(t.Context(), held, cfg); !errors.Is(err, ErrCRIDLinkNotConfigured) {
				t.Fatalf("%s: error = %v, want ErrCRIDLinkNotConfigured", name, err)
			}
			if doer.called {
				t.Fatalf("%s: a request was sent", name)
			}
		}
	})
}

// TestCheckCRIDLinkConfig is the question a caller asks before it has a CRID,
// or with a CRID this SDK cannot request: is the request offered here at all?
// The answer comes from the deployment alone. Nothing is sent, and for every
// deployment it is the answer RequestCRIDLink gives for a CRID it can request.
func TestCheckCRIDLinkConfig(t *testing.T) {
	noDefaultProvider(t)
	signer, _ := mintSigner(t)
	cellKey := bytes.Repeat([]byte{0x44}, 32)
	held, matching, _ := cridKeyMatchFixture(t)
	const endpoint = `{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link"}`

	// A deployment that names an endpoint and two cells, and one that names an
	// endpoint and no issuer. Neither fits the one-cell helper.
	issuerDER, err := signer.PublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	twoCells := Deployment{
		Issuers: []ManifestIssuer{{Kid: signer.KID(), SPKIDERB64: base64.RawURLEncoding.EncodeToString(issuerDER)}},
		Cells: []DeploymentCell{
			{CellID: "cell-a", Host: "a.example.com", Port: standardNHPUDPPort, ServerPublicKeyB64: vectorCellKeyB64(t)},
			{CellID: "cell-b", Host: "b.example.com", Port: standardNHPUDPPort, ServerPublicKeyB64: otherCellKeyB64(t)},
		},
		RelayAllowlist: []string{"relay.example.com"},
		CRIDLink:       &DeploymentCRIDLink{RelayURL: "https://relay.example.com", LinkOrigin: "https://qurl.link"},
	}
	noIssuers := twoCells
	noIssuers.Issuers, noIssuers.Cells = nil, twoCells.Cells[:1]
	writeDeployment := func(deployment Deployment) string {
		raw, err := json.Marshal(deployment)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "deployment.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	file := func(cridLinkJSON string) string { return cridLinkDeploymentFile(t, signer, cellKey, cridLinkJSON) }

	// Every sentinel a configuration answer can match. The check and the
	// request must agree on each of them.
	sentinels := map[string]error{
		"ErrNotConfigured": ErrNotConfigured, "ErrCRIDLinkNotConfigured": ErrCRIDLinkNotConfigured,
		"ErrCRIDLinkMisconfigured": ErrCRIDLinkMisconfigured, "ErrRelayURL": ErrRelayURL,
		"ErrNoDeployment": ErrNoDeployment, "fs.ErrNotExist": fs.ErrNotExist,
	}
	// The answers, as the names of the sentinels each one matches. usable
	// matches none: the request can be sent, and the answer is nil.
	var (
		usable        []string
		notOffered    = []string{"ErrNotConfigured", "ErrCRIDLinkNotConfigured"}
		misconfigured = []string{"ErrNotConfigured", "ErrCRIDLinkNotConfigured", "ErrCRIDLinkMisconfigured"}
		wrongRelay    = []string{"ErrNotConfigured", "ErrCRIDLinkNotConfigured", "ErrCRIDLinkMisconfigured", "ErrRelayURL"}
	)
	for _, tc := range []struct {
		name string
		// path is what QURL_DEPLOYMENT names. Empty is the embedded deployment.
		path string
		want []string
		// unreadable marks a deployment that does not decode. Its error
		// matches none of the sentinels, and it is still not nil.
		unreadable bool
	}{
		{"the embedded deployment", "", notOffered, false},
		{"a file with no crid_link", file(""), notOffered, false},
		{"a null crid_link", file("null"), notOffered, false},
		{"a usable crid_link", file(endpoint), usable, false},
		{"an empty crid_link", file(`{}`), wrongRelay, false},
		{"a crid_link with no link origin", file(`{"relay_url":"https://relay.example.com"}`), misconfigured, false},
		{"a relay that is not on the allowlist", file(`{"relay_url":"https://relay.example.org","link_origin":"https://qurl.link"}`), wrongRelay, false},
		{"a link origin with a slash", file(`{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link/"}`), misconfigured, false},
		{"a crid_link and two cells", writeDeployment(twoCells), misconfigured, false},
		// The deployment itself is at fault, and that is the answer: the check
		// does not turn it into "not offered".
		{"a crid_link and no issuer", writeDeployment(noIssuers), []string{"ErrNotConfigured", "ErrNoDeployment"}, false},
		{"a file that is not there", filepath.Join(t.TempDir(), "absent.json"), []string{"fs.ErrNotExist"}, false},
		{"a crid_link with an unknown member", file(`{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link","extra":1}`), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvDeploymentPath, tc.path)
			transport := installCapturingTransport(t)

			checkErr := CheckCRIDLinkConfig()
			if transport.gotURL != "" {
				t.Fatalf("checking the configuration contacted %q", transport.gotURL)
			}
			canSend := len(tc.want) == 0 && !tc.unreadable
			if (checkErr == nil) != canSend {
				t.Fatalf("CheckCRIDLinkConfig() = %v, want a request that can be sent = %t", checkErr, canSend)
			}
			for name, sentinel := range sentinels {
				if got, want := errors.Is(checkErr, sentinel), slices.Contains(tc.want, name); got != want {
					t.Fatalf("CheckCRIDLinkConfig() = %v; matches %s = %t, want %t", checkErr, name, got, want)
				}
			}

			// The request agrees. With a usable configuration it gets as far as
			// the relay, which this transport fails. Otherwise it returns the
			// same error and sends nothing.
			_, requestErr := RequestCRIDLink(t.Context(), held)
			if canSend {
				var relayErr *RelayError
				if !errors.As(requestErr, &relayErr) || transport.gotURL == "" {
					t.Fatalf("the check passed, and RequestCRIDLink did not reach the relay: %v", requestErr)
				}
				return
			}
			if requestErr == nil || requestErr.Error() != checkErr.Error() {
				t.Fatalf("RequestCRIDLink error = %v\nCheckCRIDLinkConfig()  = %v\nwant the same answer", requestErr, checkErr)
			}
			if transport.gotURL != "" {
				t.Fatalf("a request was sent to %q although the check failed", transport.gotURL)
			}
		})
	}

	// What the check is for: a CRID this SDK cannot request hides the
	// configuration answer, and the check gives it anyway.
	t.Run("with a CRID that cannot be requested", func(t *testing.T) {
		t.Setenv(EnvDeploymentPath, "")
		reserved := testCRIDForKey(0x02, 24, matching)
		_, requestErr := RequestCRIDLink(t.Context(), reserved)
		if !errors.Is(requestErr, ErrUnsupportedCRIDVersion) || errors.Is(requestErr, ErrCRIDLinkNotConfigured) {
			t.Fatalf("RequestCRIDLink(reserved version) = %v, want the CRID refusal and no configuration answer", requestErr)
		}
		if err := CheckCRIDLinkConfig(); !errors.Is(err, ErrCRIDLinkNotConfigured) || errors.Is(err, ErrCRIDLinkMisconfigured) {
			t.Fatalf("CheckCRIDLinkConfig() = %v, want ErrCRIDLinkNotConfigured for the embedded deployment", err)
		}
	})

	// A Provider supplies no endpoint, so the answer is known without asking
	// it. It must not be asked: resolving may be network I/O.
	t.Run("with a Provider installed", func(t *testing.T) {
		// A deployment file that does name an endpoint must not be mixed in.
		t.Setenv(EnvDeploymentPath, cridLinkDeploymentFile(t, signer, cellKey, endpoint))
		resolved := 0
		installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
			resolved++
			return nil, nil, errors.New("the provider must not be asked")
		}))
		transport := installCapturingTransport(t)

		err := CheckCRIDLinkConfig()
		if !errors.Is(err, ErrCRIDLinkNotConfigured) || errors.Is(err, ErrCRIDLinkMisconfigured) {
			t.Fatalf("CheckCRIDLinkConfig() = %v, want ErrCRIDLinkNotConfigured and not ErrCRIDLinkMisconfigured", err)
		}
		if !strings.Contains(err.Error(), "Provider supplies none") {
			t.Fatalf("the answer does not tell a Provider user why: %v", err)
		}
		if resolved != 0 || transport.gotURL != "" {
			t.Fatalf("the check asked the provider %d times and contacted %q", resolved, transport.gotURL)
		}
	})
}

// TestRequestCRIDLink_ResolvesTheEndpointFromTheDeploymentFile is the
// one-argument path end to end up to the wire: QURL_DEPLOYMENT names a file,
// the file names the relay and the cell, and the request is POSTed to that
// relay under the route derived from that cell's key.
func TestRequestCRIDLink_ResolvesTheEndpointFromTheDeploymentFile(t *testing.T) {
	noDefaultProvider(t)
	signer, _ := mintSigner(t)
	cellKey := bytes.Repeat([]byte{0x44}, 32)
	t.Setenv(EnvDeploymentPath, cridLinkDeploymentFile(t, signer, cellKey,
		`{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link"}`))
	held, _, _ := cridKeyMatchFixture(t)
	want := "https://relay.example.com/relay/" + relayknock.PubKeyFingerprint(cellKey)

	for name, call := range map[string]func() error{
		"RequestCRIDLink": func() error { _, err := RequestCRIDLink(t.Context(), held); return err },
		"OpenCRID":        func() error { _, err := OpenCRID(t.Context(), held); return err },
	} {
		transport := installCapturingTransport(t)
		err := call()
		// The capturing transport fails the POST, so reaching a relay fault
		// proves the gate, the deployment resolution, the endpoint checks,
		// and the request construction all passed.
		var relayErr *RelayError
		if !errors.As(err, &relayErr) {
			t.Fatalf("%s error = %v, want a relay fault after the POST", name, err)
		}
		if transport.gotURL != want {
			t.Fatalf("%s POSTed to %q, want %q", name, transport.gotURL, want)
		}
	}
}

// TestCRIDLink_ZeroSetupFromADeploymentFile is the one-argument path with
// nothing injected: the deployment file is the only configuration, and the
// calls are the ones a customer writes. RequestCRIDLink goes all the way —
// request, authenticated reply, verified link — and OpenCRID is followed to
// the point where it hands the verified link to the native opener.
func TestCRIDLink_ZeroSetupFromADeploymentFile(t *testing.T) {
	noDefaultProvider(t)
	fixture := newCRIDLinkFixture(t)
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	relayHost := strings.TrimPrefix(fixture.peer.server.URL, "https://")
	// The cell is named at loopback. The native transport refuses to send
	// there, which ends the open without any network I/O and says which
	// transport took it.
	t.Setenv(EnvDeploymentPath, cridLinkDeploymentFileFor(t, fixture.signer,
		fixture.peer.serverKey.PublicKey().Bytes(), "127.0.0.1", relayHost,
		`{"relay_url":"`+fixture.peer.server.URL+`","link_origin":"`+cridLinkTestOrigin+`"}`))

	// The one-argument calls use the default HTTP client. For this test it
	// has to trust the peer's certificate, and nothing else changes.
	prior := http.DefaultTransport
	http.DefaultTransport = fixture.peer.server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prior })

	issued, err := RequestCRIDLink(t.Context(), fixture.crid)
	if err != nil {
		t.Fatalf("RequestCRIDLink: %v", err)
	}
	if issued.Link != fixture.link || issued.Publisher.Name != "Example Publisher" || issued.Publisher.Verified {
		t.Fatalf("RequestCRIDLink = %v", issued)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	handle, err := OpenCRID(ctx, fixture.crid)
	if handle != nil || err == nil {
		t.Fatalf("OpenCRID = %v, %v; want the native transport to refuse the loopback cell", handle, err)
	}
	// The request succeeded and the link verified, or the open would have
	// failed earlier and for a different reason: positively identify the
	// native transport rather than inferring it.
	if !strings.Contains(err.Error(), "nativeudp:") {
		t.Fatalf("OpenCRID did not reach the native opener: %v", err)
	}
	if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrCRIDLinkRejected) {
		t.Fatalf("OpenCRID failed before the open: %v", err)
	}
	if strings.Contains(err.Error(), fixture.link) || strings.Contains(err.Error(), "qv2t1.") {
		t.Fatalf("the open error carries the link: %v", err)
	}
	if got := len(fixture.peer.seen()); got != 2 {
		t.Fatalf("the cell saw %d link requests, want one per call", got)
	}
}

// TestShippedDeploymentNamesNoCRIDLinkEndpoint pins what this build does out of
// the box: the embedded deployment carries no CRID link endpoint, so a CRID
// link request is refused as not configured, with nothing sent. Adding the
// endpoint to qurl/deployment.json is a deliberate release step; this test and
// the documentation that describes the behavior change with it.
func TestShippedDeploymentNamesNoCRIDLinkEndpoint(t *testing.T) {
	shipped, err := parseDeployment(shippedDeploymentJSON, "(shipped)")
	if err != nil {
		t.Fatal(err)
	}
	if shipped.CRIDLink != nil {
		t.Fatalf("the embedded deployment names a CRID link endpoint (%+v); update the documented behavior with it", shipped.CRIDLink)
	}

	noDefaultProvider(t)
	t.Setenv(EnvDeploymentPath, "")
	transport := installCapturingTransport(t)
	held, _, _ := cridKeyMatchFixture(t)

	for name, call := range map[string]func() error{
		"RequestCRIDLink": func() error { _, err := RequestCRIDLink(t.Context(), held); return err },
		"OpenCRID":        func() error { _, err := OpenCRID(t.Context(), held); return err },
	} {
		err := call()
		if !errors.Is(err, ErrCRIDLinkNotConfigured) || !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s error = %v, want ErrCRIDLinkNotConfigured", name, err)
		}
		// The message says what to set, and where.
		if !strings.Contains(err.Error(), "crid_link") || !strings.Contains(err.Error(), EnvDeploymentPath) {
			t.Fatalf("%s error does not tell the caller what to configure: %v", name, err)
		}
	}
	if transport.gotURL != "" {
		t.Fatalf("an unconfigured request contacted %q", transport.gotURL)
	}

	// Link opening against the embedded deployment is unaffected.
	if _, err := resolveDefaultConfig(t.Context()); err != nil {
		t.Fatalf("the embedded deployment no longer resolves for link opens: %v", err)
	}
}

// A Provider supplies trust, not the CRID link endpoint. With one installed
// the one-argument calls say so instead of borrowing an endpoint from a
// deployment the provider was installed to replace.
func TestRequestCRIDLink_AProviderSuppliesNoEndpoint(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	provider, err := NewStaticProvider(fixture.cfg.TrustStore, fixture.cfg.RelayAllowlist, []CellEntry{{
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(fixture.peer.serverKey.PublicKey().Bytes()),
		CellID:             "crid-link-test-cell", Host: "cell.example.test", Port: standardNHPUDPPort,
	}})
	if err != nil {
		t.Fatal(err)
	}
	installDefaultProvider(t, provider)
	// A deployment file that does name an endpoint must not be mixed in.
	t.Setenv(EnvDeploymentPath, cridLinkDeploymentFile(t, fixture.signer, fixture.peer.serverKey.PublicKey().Bytes(),
		`{"relay_url":"https://relay.example.com","link_origin":"https://qurl.link"}`))
	transport := installCapturingTransport(t)

	for name, call := range map[string]func() error{
		"RequestCRIDLink": func() error { _, err := RequestCRIDLink(t.Context(), fixture.crid); return err },
		"OpenCRID":        func() error { _, err := OpenCRID(t.Context(), fixture.crid); return err },
	} {
		err := call()
		if !errors.Is(err, ErrCRIDLinkNotConfigured) {
			t.Fatalf("%s error = %v, want ErrCRIDLinkNotConfigured", name, err)
		}
		// The message has to be right for this caller too. With a Provider
		// installed the deployment file is not read, so the message must say a
		// Provider supplies no endpoint and name the remedy that does apply.
		if !strings.Contains(err.Error(), "Provider supplies none") || !strings.Contains(err.Error(), "Config.CRIDLink") {
			t.Fatalf("%s error does not tell a Provider user what to do: %v", name, err)
		}
	}
	if transport.gotURL != "" || len(fixture.peer.seen()) != 0 {
		t.Fatal("a provider-resolved config sent a CRID link request")
	}

	// A provider that fails is reported as its own failure, unchanged.
	providerErr := errors.New("provider unavailable")
	installDefaultProvider(t, providerFunc(func(context.Context) (*TrustStore, *RelayAllowlist, error) {
		return nil, nil, providerErr
	}))
	if _, err := RequestCRIDLink(t.Context(), fixture.crid); !errors.Is(err, providerErr) {
		t.Fatalf("provider error lost: %v", err)
	}
	if _, err := OpenCRID(t.Context(), fixture.crid); !errors.Is(err, providerErr) {
		t.Fatalf("provider error lost: %v", err)
	}
}
