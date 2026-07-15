package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BootstrapAgent is now the pre-issued-key (PATH A) enrollment specialized to
// return the raw AgentState. It runs the same NHP engine as RegisterAgent's
// bootstrap path, so these tests drive it against the same fake relay+NHP server
// and fake qurl-service (registerHarness in register_test.go), with the bootstrap
// key kind and BootstrapOption inputs.

// bootstrapOpts points BootstrapAgent at the harness's fake API origin. The relay
// URL is carried by registration-info, so no relay option is needed.
func (h *registerHarness) bootstrapOpts(extra ...BootstrapOption) []BootstrapOption {
	return append([]BootstrapOption{WithBootstrapBaseURL(h.apiSrv.URL)}, extra...)
}

func TestBootstrapAgent_EnrollsRegistersAndSavesState(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.svc.expectedBearer = "lv_bootstrap_once"
	h.nhp.expectCredential = "lv_bootstrap_once"
	h.armDevicePubOnInfo()

	state, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", h.store, h.bootstrapOpts(WithAgentID("prod-us-east-1"))...)
	if err != nil {
		t.Fatalf("BootstrapAgent: %v", err)
	}
	if state.AgentID != "prod-us-east-1" {
		t.Fatalf("AgentID = %q, want prod-us-east-1", state.AgentID)
	}
	if state.RegisteredAt == nil || state.NHPPeer == nil {
		t.Fatalf("state not registered: %#v", state)
	}
	if state.DeviceAPIKey != "lv_device_secret" {
		t.Fatalf("DeviceAPIKey = %q, want lv_device_secret", state.DeviceAPIKey)
	}

	// State file is 0600 and the persisted keypair round-trips.
	info, err := os.Stat(h.statePath)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 0600", info.Mode().Perm())
	}
	loaded := h.loadState(t)
	if loaded.PrivateKeyB64 == "" || loaded.PublicKeyB64 != state.PublicKeyB64 {
		t.Fatalf("loaded state = %#v", loaded)
	}
}

func TestBootstrapAgent_RetriesIncompleteBootstrapWithSavedKeypair(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	// First attempt: completion fails transiently (502), leaving a keypair-only
	// state. The REG did happen, but no durable state was saved.
	h.svc.completionStatus = http.StatusBadGateway
	h.svc.completionCode = "upstream_unavailable"
	if _, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts()...); err == nil {
		t.Fatal("first BootstrapAgent succeeded, want transient completion failure")
	}
	firstState := h.loadState(t)
	if firstState.RegisteredAt != nil {
		t.Fatalf("incomplete state marked registered: %#v", firstState)
	}
	if firstState.PublicKeyB64 == "" {
		t.Fatal("incomplete state did not persist the keypair")
	}

	// Second attempt: completion succeeds. The same device key must be reused.
	h.svc.completionStatus = 0
	state, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts()...)
	if err != nil {
		t.Fatalf("second BootstrapAgent: %v", err)
	}
	if state.RegisteredAt == nil {
		t.Fatalf("second attempt not registered: %#v", state)
	}
	if state.PublicKeyB64 != firstState.PublicKeyB64 {
		t.Fatalf("bootstrap did not reuse the saved keypair: %q then %q", firstState.PublicKeyB64, state.PublicKeyB64)
	}
}

func TestBootstrapAgent_ReportsConsumedSetupKeyFromRAK(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.nhp.rakErrCode = rakBootstrapConsumed // 52108
	h.nhp.rakErrMsg = "setup key already consumed"
	h.armDevicePubOnInfo()

	_, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts()...)
	if !errors.Is(err, ErrBootstrapSetupKeyConsumed) {
		t.Fatalf("BootstrapAgent: want ErrBootstrapSetupKeyConsumed, got %v", err)
	}

	// The incomplete keypair-only state remains so an operator can inspect it.
	state := h.loadState(t)
	if state.PublicKeyB64 == "" || state.RegisteredAt != nil {
		t.Fatalf("incomplete saved state = %#v", state)
	}
}

func TestBootstrapAgent_ReportsConsumedSetupKeyFromCompletion(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.svc.completionStatus = http.StatusConflict
	h.svc.completionCode = "setup_key_consumed"
	h.armDevicePubOnInfo()

	_, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts()...)
	if !errors.Is(err, ErrBootstrapSetupKeyConsumed) {
		t.Fatalf("BootstrapAgent: want ErrBootstrapSetupKeyConsumed from completion, got %v", err)
	}
}

func TestBootstrapAgent_ReturnsRegisteredStateWithoutNetwork(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	first, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts()...)
	if err != nil {
		t.Fatalf("first BootstrapAgent: %v", err)
	}
	infoAfterFirst := h.svc.infoCalls.Load()

	second, err := BootstrapAgent(context.Background(), "lv_consumed_setup_key", h.store, h.bootstrapOpts()...)
	if err != nil {
		t.Fatalf("second BootstrapAgent: %v", err)
	}
	if got := h.svc.infoCalls.Load(); got != infoAfterFirst {
		t.Fatalf("fast path made %d extra registration-info calls, want 0", got-infoAfterFirst)
	}
	if second.AgentID != first.AgentID || second.PublicKeyB64 != first.PublicKeyB64 || second.NHPPeer == nil {
		t.Fatalf("second state = %#v, first = %#v", second, first)
	}
}

// TestBootstrapAgent_ReturnsKeylessLegacyStateWithoutNetwork exercises the
// requireDeviceKey=false fast path end to end: a legacy (bootstrap-era) state can
// be registered yet hold no DeviceAPIKey, and BootstrapAgent must return it
// directly with ZERO network I/O — unlike RegisterAgent (requireDeviceKey=true),
// which fails such a state closed with ErrDeviceCredentialMissing
// (TestRegisterAgent_FastPath_MissingDeviceKeyFailsClosed). A network-refusing
// HTTP client proves the fast path makes no call.
func TestBootstrapAgent_ReturnsKeylessLegacyStateWithoutNetwork(t *testing.T) {
	registeredAt := time.Now().UTC()
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-legacy"
	state.RegisteredAt = &registeredAt
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: validTestNHPServerPublicKeyB64,
		Host:         "nhp.layerv.ai",
		Port:         62206,
	}
	// No DeviceAPIKey and SchemaVersion 0: the keyless legacy shape.

	refusing := doerFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("BootstrapAgent made an unexpected network call to %s", req.URL)
		return nil, errors.New("network refused")
	})

	got, err := BootstrapAgent(context.Background(), "lv_setup_key",
		memoryAgentStateStore{state: state},
		WithBootstrapHTTPClient(refusing),
	)
	if err != nil {
		t.Fatalf("BootstrapAgent on a keyless legacy state: want the fast path to return it, got %v", err)
	}
	if got.AgentID != "agent-legacy" || got.RegisteredAt == nil {
		t.Fatalf("returned state = %#v, want the registered legacy state", got)
	}
	if got.DeviceAPIKey != "" {
		t.Fatalf("returned DeviceAPIKey = %q, want empty (keyless legacy state returned as-is)", got.DeviceAPIKey)
	}
}

func TestBootstrapAgent_RejectsMismatchedRequestedAgentIDOnFastPath(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindBootstrap
	h.armDevicePubOnInfo()

	if _, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts(WithAgentID("agent-one"))...); err != nil {
		t.Fatalf("first BootstrapAgent: %v", err)
	}
	// BootstrapAgent keeps its documented ErrInvalidBootstrapConfig class even
	// though the mismatch is detected inside the shared registration engine.
	_, err := BootstrapAgent(context.Background(), "lv_setup_once", h.store, h.bootstrapOpts(WithAgentID("agent-two"))...)
	if !errors.Is(err, ErrInvalidBootstrapConfig) || !strings.Contains(err.Error(), "does not match requested device id") {
		t.Fatalf("BootstrapAgent: want ErrInvalidBootstrapConfig device id mismatch, got %v", err)
	}
}

func TestBootstrapAgent_RejectsInvalidRegisteredStateWithoutNetwork(t *testing.T) {
	registeredAt := time.Now().UTC()
	validState, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	validState.AgentID = "agent-1"
	validState.RegisteredAt = &registeredAt
	validState.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: validTestNHPServerPublicKeyB64,
		Host:         "nhp.layerv.ai",
		Port:         62206,
		ExpireTime:   0,
	}

	tests := []struct {
		name string
		edit func(*AgentState)
		want string
	}{
		{
			name: "missing agent id",
			edit: func(state *AgentState) { state.AgentID = "" },
			want: "missing agent id",
		},
		{
			name: "bad peer key",
			edit: func(state *AgentState) { state.NHPPeer.PublicKeyB64 = "not-base64" },
			want: "not standard base64",
		},
		{
			name: "expired peer",
			edit: func(state *AgentState) { state.NHPPeer.ExpireTime = 1 },
			want: "peer is expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := *validState
			peer := *validState.NHPPeer
			state.NHPPeer = &peer
			tt.edit(&state)

			api := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("BootstrapAgent made an unexpected network call")
			}))
			defer api.Close()

			_, err := BootstrapAgent(context.Background(),
				"lv_consumed_setup_key",
				memoryAgentStateStore{state: &state},
				WithBootstrapBaseURL(api.URL),
			)
			if !errors.Is(err, ErrInvalidBootstrapConfig) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BootstrapAgent: want ErrInvalidBootstrapConfig containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestFileAgentState_RejectsGroupReadableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	raw := []byte(`{"private_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("LoadAgentState: want ErrInsecureAgentStatePermissions, got %v", err)
	}
}

func TestFileAgentState_RejectsOversizedState(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent-state.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxAgentStateBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized state: %v", err)
	}

	_, err := FileAgentState(path).LoadAgentState(context.Background())
	if !errors.Is(err, ErrInvalidAgentState) || !strings.Contains(err.Error(), "agent state exceeds") {
		t.Fatalf("LoadAgentState oversized: want ErrInvalidAgentState cap error, got %v", err)
	}
}

func TestFileAgentState_RejectsGroupWritableStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "agent-state.json")
	raw := []byte(`{"private_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("LoadAgentState loose dir: want ErrInsecureAgentStatePermissions, got %v", err)
	}
}

func TestFileAgentState_SaveRejectsGroupWritableStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	state := &AgentState{
		PrivateKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKeyB64:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
	}
	path := filepath.Join(dir, "agent-state.json")
	err := FileAgentState(path).SaveAgentState(context.Background(), state)
	if !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("SaveAgentState loose dir: want ErrInsecureAgentStatePermissions, got %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after rejected save: want not exist, got %v", err)
	}
}

func TestFileAgentState_RequiresExact0700StateDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "agent-state.json")
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	state.AgentID = "agent-mode-test"
	if err := FileAgentState(path).SaveAgentState(context.Background(), state); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("save under 0750 dir = %v, want ErrInsecureAgentStatePermissions", err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("load under 0750 dir = %v, want ErrInsecureAgentStatePermissions", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("load under 0500 dir = %v, want ErrInsecureAgentStatePermissions", err)
	}
}

func TestFileAgentState_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := FileAgentState(filepath.Join(t.TempDir(), "agent-state.json"))
	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadAgentState canceled context: want context.Canceled, got %v", err)
	}
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	if err := store.SaveAgentState(ctx, state); !errors.Is(err, context.Canceled) {
		t.Fatalf("SaveAgentState canceled context: want context.Canceled, got %v", err)
	}
}

func TestFileAgentState_RejectsSymlinkState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent-state.json")
	link := filepath.Join(dir, "agent-state-link.json")
	raw := []byte(`{"private_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	// A malformed state file (here a symlink) is a corrupt-content fault, so the
	// store returns the store-neutral ErrInvalidAgentState (not a front-door
	// class). RegisterAgent/BootstrapAgent re-wrap it in their own class.
	if _, err := FileAgentState(link).LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("LoadAgentState symlink: want ErrInvalidAgentState, got %v", err)
	}
}

// TestFileAgentState_V2FieldsRoundTripAndLegacyLoads verifies AgentState v2's
// additive schema: a v2 state (device key + relay + otp fields) round-trips, and
// a legacy pre-v2 file (no v2 fields) still loads and validates.
func TestFileAgentState_V2FieldsRoundTripAndLegacyLoads(t *testing.T) {
	registeredAt := time.Now().UTC().Round(time.Second)
	otpAt := registeredAt.Add(-time.Minute)

	// v2 round trip.
	v2Path := filepath.Join(secureAgentStateTestDir(t), "v2.json")
	v2Store := FileAgentState(v2Path)
	base, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	base.AgentID = "agent-v2"
	base.RegisteredAt = &registeredAt
	base.OTPRequestedAt = &otpAt
	base.NHPPeer = &NHPServerPeerInfo{PublicKeyB64: validTestNHPServerPublicKeyB64, Host: "h", Port: 1}
	base.SchemaVersion = agentStateSchemaVersion
	base.DeviceAPIKey = "lv_device_secret"
	base.RelayURL = "https://relay.example.test"
	base.KeyID = "key_abc"
	if err := v2Store.SaveAgentState(context.Background(), base); err != nil {
		t.Fatalf("save v2 state: %v", err)
	}
	loaded, err := v2Store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load v2 state: %v", err)
	}
	if loaded.DeviceAPIKey != "lv_device_secret" || loaded.RelayURL != "https://relay.example.test" || loaded.KeyID != "key_abc" || loaded.SchemaVersion != agentStateSchemaVersion {
		t.Fatalf("v2 fields did not round trip: %#v", loaded)
	}
	if loaded.OTPRequestedAt == nil || !loaded.OTPRequestedAt.Equal(otpAt) {
		t.Fatalf("OTPRequestedAt did not round trip: %#v", loaded.OTPRequestedAt)
	}

	// Legacy (pre-v2) file: only the original fields, written by hand.
	legacyPath := filepath.Join(secureAgentStateTestDir(t), "legacy.json")
	legacy := []byte(`{"agent_id":"agent-legacy","private_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public_key_b64":"","registered_at":"2026-01-01T00:00:00Z","nhp_server_peer":{"public_key_b64":"` + validTestNHPServerPublicKeyB64 + `","host":"nhp.layerv.ai","port":62206,"expire_time":0}}`)
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	loadedLegacy, err := FileAgentState(legacyPath).LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load legacy state: %v", err)
	}
	if loadedLegacy.SchemaVersion != 0 || loadedLegacy.DeviceAPIKey != "" {
		t.Fatalf("legacy state should have zero v2 fields: %#v", loadedLegacy)
	}
	if err := validateRegisteredAgentState(loadedLegacy, time.Now(), true, ErrInvalidBootstrapConfig); err != nil {
		t.Fatalf("legacy registered state should validate: %v", err)
	}
}

func secureAgentStateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestValidateRegisteredAgentState_PeerExpiryGatedOnRequirePeerLive verifies the
// fast-path peer-expiry gate: a RegisterAgent Client (requirePeerLive=false — it
// authorizes with the REST device key and never knocks the persisted peer) is not
// locked out by an expired NHP peer, while the knock-only BootstrapAgent path
// (requirePeerLive=true) still rejects it.
func TestValidateRegisteredAgentState_PeerExpiryGatedOnRequirePeerLive(t *testing.T) {
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	registeredAt := now.Add(-24 * time.Hour)
	state := &AgentState{
		AgentID:      "agent-expired-peer",
		RegisteredAt: &registeredAt,
		NHPPeer: &NHPServerPeerInfo{
			PublicKeyB64: validTestNHPServerPublicKeyB64,
			Host:         "nhp.layerv.ai",
			Port:         62206,
			ExpireTime:   now.Add(-time.Hour).Unix(), // expired an hour ago
		},
	}

	// REST-only RegisterAgent fast path: an expired-but-unused peer must not block it.
	if err := validateRegisteredAgentState(state, now, false, ErrInvalidRegisterConfig); err != nil {
		t.Errorf("requirePeerLive=false must accept an expired peer (a REST Client never knocks it): %v", err)
	}
	// Knock-only BootstrapAgent fast path: an expired peer it will knock is a real problem.
	err := validateRegisteredAgentState(state, now, true, ErrInvalidRegisterConfig)
	if err == nil {
		t.Error("requirePeerLive=true must reject an expired peer (the knock path uses it)")
	} else if !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Errorf("expired-peer rejection should wrap the config error: %v", err)
	}
}

func TestBootstrapAgent_Validation(t *testing.T) {
	if _, err := BootstrapAgent(context.Background(), "", memoryAgentStateStore{}); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("empty key: want ErrInvalidBootstrapConfig, got %v", err)
	}
	for _, key := range []string{" lv_bootstrap_once", "lv_bootstrap_once ", "lv_bootstrap\nonce"} {
		if _, err := BootstrapAgent(context.Background(), key, memoryAgentStateStore{}); !errors.Is(err, ErrInvalidBootstrapConfig) {
			t.Fatalf("non-exact setup key %q: want ErrInvalidBootstrapConfig, got %v", key, err)
		}
	}
	if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", nil); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("nil store: want ErrInvalidBootstrapConfig, got %v", err)
	}
	if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", memoryAgentStateStore{}, WithBootstrapBaseURL("ftp://bootstrap.example.com")); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("bad URL: want ErrInvalidBootstrapConfig, got %v", err)
	}
	if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", memoryAgentStateStore{}, WithBootstrapBaseURL("http://bootstrap.example.com")); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("plaintext non-loopback URL: want ErrInvalidBootstrapConfig, got %v", err)
	}
	if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", memoryAgentStateStore{}, WithBootstrapBaseURL("https://user:pass@bootstrap.example.com")); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("bootstrap URL with userinfo: want ErrInvalidBootstrapConfig, got %v", err)
	}
	for _, rawURL := range []string{"https://bootstrap.example.com/prefix?wrong=1", "https://bootstrap.example.com/prefix#wrong"} {
		if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", memoryAgentStateStore{}, WithBootstrapBaseURL(rawURL)); !errors.Is(err, ErrInvalidBootstrapConfig) {
			t.Fatalf("bootstrap URL %q: want ErrInvalidBootstrapConfig, got %v", rawURL, err)
		}
	}
	var bootstrapCfg bootstrapOptions
	if err := WithBootstrapBaseURL("https://bootstrap.example.com/custom/prefix/").applyBootstrapOption(&bootstrapCfg); err != nil {
		t.Fatalf("path-prefixed bootstrap URL: %v", err)
	}
	if bootstrapCfg.baseURL != "https://bootstrap.example.com/custom/prefix" {
		t.Fatalf("bootstrap path prefix = %q", bootstrapCfg.baseURL)
	}

	store := memoryAgentStateStore{state: &AgentState{PrivateKeyB64: "not-base64", PublicKeyB64: "also-bad"}}
	if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", store); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("bad saved keypair: want ErrInvalidBootstrapConfig, got %v", err)
	}
}

type memoryAgentStateStore struct {
	state *AgentState
}

func (s memoryAgentStateStore) LoadAgentState(context.Context) (*AgentState, error) {
	if s.state == nil {
		return nil, ErrAgentStateNotFound
	}
	return s.state, nil
}

func (s memoryAgentStateStore) SaveAgentState(context.Context, *AgentState) error {
	return nil
}
