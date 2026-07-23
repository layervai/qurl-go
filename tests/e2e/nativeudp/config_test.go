package nativeudp_test

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

const (
	strictEnv                = "QURL_GO_SANDBOX_STRICT"
	buildSHAEnv              = "QURL_GO_SANDBOX_EXPECTED_SHA"
	hubHostEnv               = "QURL_GO_SANDBOX_HUB_HOST"
	hubPortEnv               = "QURL_GO_SANDBOX_HUB_PORT"
	hubServerKeyEnv          = "QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64"
	enrollmentEnv            = "QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL"
	agentIDEnv               = "QURL_GO_SANDBOX_AGENT_ID"
	statePathEnv             = "QURL_GO_SANDBOX_STATE_PATH"
	provenancePathEnv        = "QURL_GO_SANDBOX_PROVENANCE_PATH"
	deploymentManifestSHAEnv = "QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"
	typedContractSHAEnv      = "QURL_GO_SANDBOX_TYPED_EVIDENCE_CONTRACT_SHA256"
	knockResourceIDEnv       = "QURL_GO_SANDBOX_KNOCK_RESOURCE_ID"
	expectedCellIDEnv        = "QURL_GO_SANDBOX_EXPECTED_CELL_ID"
	standardNHPUDPPort       = 62206
	x25519PublicKeyLength    = 32
)

type sandboxConfig struct {
	buildSHA         string
	hubHost          string
	hubPort          int
	hubServerKeyB64  string
	enrollment       string
	agentID          string
	statePath        string
	provenancePath   string
	deploymentSHA    string
	typedContractSHA string
	knockResourceID  string
	expectedCellID   string
}

func loadSandboxConfig(lookup func(string) string) (sandboxConfig, bool, error) {
	strict := lookup(strictEnv)
	switch strict {
	case "", "0", "false":
		return sandboxConfig{}, false, nil
	case "1", "true":
	default:
		return sandboxConfig{}, false, fmt.Errorf("%s must be true/1 or false/0", strictEnv)
	}

	required := []string{
		buildSHAEnv,
		hubHostEnv,
		hubPortEnv,
		hubServerKeyEnv,
		enrollmentEnv,
		agentIDEnv,
		statePathEnv,
		provenancePathEnv,
		deploymentManifestSHAEnv,
		typedContractSHAEnv,
		knockResourceIDEnv,
	}
	missing := make([]string, 0, len(required))
	for _, name := range required {
		if lookup(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return sandboxConfig{}, true, fmt.Errorf("strict native UDP sandbox proof is missing required environment: %s", strings.Join(missing, ", "))
	}

	port, err := strconv.Atoi(lookup(hubPortEnv))
	if err != nil || port != standardNHPUDPPort {
		return sandboxConfig{}, true, fmt.Errorf("%s must be the native NHP UDP port %d", hubPortEnv, standardNHPUDPPort)
	}
	cfg := sandboxConfig{
		buildSHA:         lookup(buildSHAEnv),
		hubHost:          lookup(hubHostEnv),
		hubPort:          port,
		hubServerKeyB64:  lookup(hubServerKeyEnv),
		enrollment:       lookup(enrollmentEnv),
		agentID:          lookup(agentIDEnv),
		statePath:        lookup(statePathEnv),
		provenancePath:   lookup(provenancePathEnv),
		deploymentSHA:    lookup(deploymentManifestSHAEnv),
		typedContractSHA: lookup(typedContractSHAEnv),
		knockResourceID:  lookup(knockResourceIDEnv),
		expectedCellID:   lookup(expectedCellIDEnv),
	}

	if !canonicalLowerHex(cfg.buildSHA, 40) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact 40-character lowercase Git SHA", buildSHAEnv)
	}
	for name, value := range map[string]string{
		hubHostEnv:               cfg.hubHost,
		hubServerKeyEnv:          cfg.hubServerKeyB64,
		enrollmentEnv:            cfg.enrollment,
		agentIDEnv:               cfg.agentID,
		statePathEnv:             cfg.statePath,
		provenancePathEnv:        cfg.provenancePath,
		deploymentManifestSHAEnv: cfg.deploymentSHA,
		typedContractSHAEnv:      cfg.typedContractSHA,
		knockResourceIDEnv:       cfg.knockResourceID,
		expectedCellIDEnv:        cfg.expectedCellID,
	} {
		if value != strings.TrimSpace(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return sandboxConfig{}, true, fmt.Errorf("%s must be canonical and contain no control characters", name)
		}
	}
	if len(cfg.enrollment) < 32 {
		return sandboxConfig{}, true, fmt.Errorf("%s must contain a server-minted credential of at least 32 bytes", enrollmentEnv)
	}
	if err := validateSandboxAgentID(cfg.agentID); err != nil {
		return sandboxConfig{}, true, fmt.Errorf("%s: %w", agentIDEnv, err)
	}
	if !filepath.IsAbs(cfg.statePath) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", statePathEnv)
	}
	if !filepath.IsAbs(cfg.provenancePath) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an absolute path", provenancePathEnv)
	}
	if !canonicalLowerHex(cfg.deploymentSHA, 64) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact lowercase SHA-256 digest", deploymentManifestSHAEnv)
	}
	if !canonicalLowerHex(cfg.typedContractSHA, 64) {
		return sandboxConfig{}, true, fmt.Errorf("%s must be an exact lowercase SHA-256 digest", typedContractSHAEnv)
	}
	paths := []struct {
		name string
		path string
	}{
		{name: statePathEnv, path: filepath.Clean(cfg.statePath)},
		{name: statePathEnv + " lock", path: filepath.Clean(cfg.statePath + ".lock")},
		{name: provenancePathEnv, path: filepath.Clean(cfg.provenancePath)},
		{name: provenancePathEnv + " temporary", path: filepath.Clean(cfg.provenancePath + ".tmp")},
	}
	seenPaths := make(map[string]string, len(paths))
	for _, candidate := range paths {
		if prior, exists := seenPaths[candidate.path]; exists {
			return sandboxConfig{}, true, fmt.Errorf("%s and %s must resolve to distinct paths", prior, candidate.name)
		}
		seenPaths[candidate.path] = candidate.name
	}
	serverKey, err := base64.StdEncoding.Strict().DecodeString(cfg.hubServerKeyB64)
	if err != nil || len(serverKey) != x25519PublicKeyLength || base64.StdEncoding.EncodeToString(serverKey) != cfg.hubServerKeyB64 {
		return sandboxConfig{}, true, fmt.Errorf("%s must be canonical padded base64 for one 32-byte X25519 public key", hubServerKeyEnv)
	}
	return cfg, true, nil
}

func canonicalLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func validateSandboxAgentID(agentID string) error {
	if len(agentID) < 2 || len(agentID) > 64 {
		return fmt.Errorf("agent id must contain 2-64 characters")
	}
	for i := range len(agentID) {
		b := agentID[i]
		lowerAlnum := b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
		if !lowerAlnum && (b != '-' || i == 0 || i == len(agentID)-1) {
			return fmt.Errorf("agent id must start and end with lowercase alphanumeric characters and contain only lowercase alphanumeric characters or hyphens")
		}
	}
	return nil
}

func TestSandboxConfigStrictMode(t *testing.T) {
	valid := map[string]string{
		strictEnv:                "true",
		buildSHAEnv:              strings.Repeat("a", 40),
		hubHostEnv:               "hub.nhp.layerv.ai",
		hubPortEnv:               strconv.Itoa(standardNHPUDPPort),
		hubServerKeyEnv:          base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		enrollmentEnv:            strings.Repeat("credential", 4),
		agentIDEnv:               "qurl-go-sandbox-123-1",
		statePathEnv:             filepath.Join(t.TempDir(), "agent-state.json"),
		provenancePathEnv:        filepath.Join(t.TempDir(), "provenance.json"),
		deploymentManifestSHAEnv: strings.Repeat("d", 64),
		typedContractSHAEnv:      strings.Repeat("e", 64),
		knockResourceIDEnv:       "knock-resource-id",
	}
	lookup := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}

	t.Run("disabled is an explicit skip", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(func(string) string { return "" })
		if enabled || err != nil || cfg != (sandboxConfig{}) {
			t.Fatalf("disabled config = %#v, %t, %v; want zero, false, nil", cfg, enabled, err)
		}
	})

	t.Run("strict accepts complete inputs", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(valid))
		if !enabled || err != nil || cfg.agentID != valid[agentIDEnv] {
			t.Fatalf("strict config = %#v, %t, %v", cfg, enabled, err)
		}
	})

	for _, name := range []string{deploymentManifestSHAEnv, typedContractSHAEnv} {
		t.Run("strict rejects noncanonical "+name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[name] = strings.Repeat("A", 64)
			cfg, enabled, err := loadSandboxConfig(lookup(values))
			if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), name) {
				t.Fatalf("noncanonical digest config = %#v, %t, %v", cfg, enabled, err)
			}
		})
	}

	t.Run("strict reports every missing prerequisite", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(map[string]string{strictEnv: "1"}))
		if !enabled || err == nil || cfg != (sandboxConfig{}) {
			t.Fatalf("missing config = %#v, %t, %v; want enabled failure", cfg, enabled, err)
		}
		for _, name := range []string{buildSHAEnv, hubHostEnv, hubPortEnv, hubServerKeyEnv, enrollmentEnv, agentIDEnv, statePathEnv, provenancePathEnv, deploymentManifestSHAEnv, typedContractSHAEnv, knockResourceIDEnv} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("missing-config error %q omits %s", err, name)
			}
		}
	})

	t.Run("invalid strict marker fails instead of disabling proof", func(t *testing.T) {
		cfg, enabled, err := loadSandboxConfig(lookup(map[string]string{strictEnv: "TRUE"}))
		if enabled || err == nil || cfg != (sandboxConfig{}) {
			t.Fatalf("invalid strict marker = %#v, %t, %v; want disabled-shape error", cfg, enabled, err)
		}
	})

	t.Run("strict rejects state and provenance path collisions", func(t *testing.T) {
		base := t.TempDir()
		tests := []struct {
			name       string
			state      string
			provenance string
		}{
			{
				name:       "same path",
				state:      filepath.Join(base, "shared.json"),
				provenance: filepath.Join(base, "shared.json"),
			},
			{
				name:       "provenance aliases state lock",
				state:      filepath.Join(base, "agent-state.json"),
				provenance: filepath.Join(base, "agent-state.json.lock"),
			},
			{
				name:       "state aliases provenance temporary",
				state:      filepath.Join(base, "provenance.json.tmp"),
				provenance: filepath.Join(base, "provenance.json"),
			},
			{
				name:       "cleaned paths alias",
				state:      filepath.Join(base, "agent-state.json"),
				provenance: filepath.Join(base, "nested", "..", "agent-state.json"),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				values := make(map[string]string, len(valid))
				for name, value := range valid {
					values[name] = value
				}
				values[statePathEnv] = tt.state
				values[provenancePathEnv] = tt.provenance
				cfg, enabled, err := loadSandboxConfig(lookup(values))
				if !enabled || err == nil || cfg != (sandboxConfig{}) || !strings.Contains(err.Error(), "must resolve to distinct paths") {
					t.Fatalf("colliding config = %#v, %t, %v; want enabled distinct-path failure", cfg, enabled, err)
				}
			})
		}
	})
}
