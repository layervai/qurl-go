package qurl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestBootstrapAgent_GeneratesRegistersAndSavesState(t *testing.T) {
	var gotPublicKey string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agent/bootstrap" {
			t.Fatalf("request = %s %s, want POST /v1/agent/bootstrap", r.Method, r.URL.Path)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer lv_bootstrap_once"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		gotPublicKey = body["public_key"]
		if _, err := base64.StdEncoding.Strict().DecodeString(gotPublicKey); err != nil {
			t.Fatalf("public key is not standard base64: %q", gotPublicKey)
		}
		if body["agent_id"] != "prod-us-east-1" {
			t.Fatalf("agent_id = %q, want prod-us-east-1", body["agent_id"])
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"agent_id":"prod-us-east-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`)
	}))
	defer api.Close()

	path := filepath.Join(t.TempDir(), "agent-state.json")
	state, err := BootstrapAgent(context.Background(),
		"lv_bootstrap_once",
		FileAgentState(path),
		WithBootstrapBaseURL(api.URL),
		WithAgentID("prod-us-east-1"),
	)
	if err != nil {
		t.Fatalf("BootstrapAgent: %v", err)
	}
	if state.AgentID != "prod-us-east-1" || state.PublicKeyB64 != gotPublicKey {
		t.Fatalf("state = %#v, public key sent %q", state, gotPublicKey)
	}
	if state.NHPPeer == nil || state.NHPPeer.Host != "nhp.layerv.ai" || state.NHPPeer.Port != 62206 {
		t.Fatalf("NHP peer = %#v", state.NHPPeer)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := FileAgentState(path).LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState: %v", err)
	}
	if loaded.PrivateKeyB64 == "" || loaded.PublicKeyB64 != gotPublicKey {
		t.Fatalf("loaded state = %#v", loaded)
	}
}

func TestBootstrapAgent_RetriesIncompleteBootstrapWithSavedKeypair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	var publicKeys []string
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		publicKeys = append(publicKeys, body["public_key"])
		if call == 1 {
			http.Error(w, "temporary bootstrap failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"agent_id":"agent-2","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`)
	}))
	defer api.Close()

	if _, err := BootstrapAgent(context.Background(), "lv_setup_once", store, WithBootstrapBaseURL(api.URL)); err == nil {
		t.Fatal("first BootstrapAgent succeeded, want temporary failure")
	}
	state, err := BootstrapAgent(context.Background(), "lv_setup_once", store, WithBootstrapBaseURL(api.URL))
	if err != nil {
		t.Fatalf("second BootstrapAgent: %v", err)
	}
	if state.AgentID != "agent-2" || state.RegisteredAt == nil {
		t.Fatalf("state = %#v", state)
	}
	if len(publicKeys) != 2 {
		t.Fatalf("public key count = %d, want 2", len(publicKeys))
	}
	if publicKeys[0] == "" || publicKeys[0] != publicKeys[1] {
		t.Fatalf("bootstrap should reuse saved public key, got %q then %q", publicKeys[0], publicKeys[1])
	}
}

func TestBootstrapAgent_ReturnsRegisteredStateWithoutNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) > 1 {
			t.Fatalf("BootstrapAgent made an unexpected second network call")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`)
	}))
	defer api.Close()

	first, err := BootstrapAgent(context.Background(), "lv_setup_once", store, WithBootstrapBaseURL(api.URL))
	if err != nil {
		t.Fatalf("first BootstrapAgent: %v", err)
	}
	second, err := BootstrapAgent(context.Background(), "lv_consumed_setup_key", store, WithBootstrapBaseURL(api.URL))
	if err != nil {
		t.Fatalf("second BootstrapAgent: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("network calls = %d, want 1", calls.Load())
	}
	if second.AgentID != first.AgentID || second.PublicKeyB64 != first.PublicKeyB64 || second.NHPPeer == nil {
		t.Fatalf("second state = %#v, first = %#v", second, first)
	}
}

func TestBootstrapAgent_RejectsIncompleteRegistrationResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing registration time",
			body: `{"data":{"agent_id":"agent-1","registered_at":null,"nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`,
		},
		{
			name: "missing peer",
			body: `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z"}}`,
		},
		{
			name: "malformed peer key",
			body: `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"not-base64","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`,
		},
		{
			name: "short peer key",
			body: `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAA","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`,
		},
		{
			name: "missing peer host",
			body: `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"","port":62206,"expire_time":0}}}`,
		},
		{
			name: "missing peer port",
			body: `{"data":{"agent_id":"agent-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"nhp.layerv.ai","port":0,"expire_time":0}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.body)
			}))
			defer api.Close()

			path := filepath.Join(t.TempDir(), "agent-state.json")
			_, err := BootstrapAgent(context.Background(), "lv_setup_once", FileAgentState(path), WithBootstrapBaseURL(api.URL))
			if !errors.Is(err, ErrInvalidBootstrapConfig) {
				t.Fatalf("BootstrapAgent: want ErrInvalidBootstrapConfig, got %v", err)
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

func TestFileAgentState_RejectsGroupWritableStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})
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
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

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

	if _, err := FileAgentState(link).LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("LoadAgentState symlink: want ErrInvalidBootstrapConfig, got %v", err)
	}
}

func TestBootstrapAgent_Validation(t *testing.T) {
	if _, err := BootstrapAgent(context.Background(), "", memoryAgentStateStore{}); !errors.Is(err, ErrInvalidBootstrapConfig) {
		t.Fatalf("empty key: want ErrInvalidBootstrapConfig, got %v", err)
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
