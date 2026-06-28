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
		fmt.Fprint(w, `{"data":{"agent_id":"prod-us-east-1","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`)
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

func TestBootstrapAgent_ReusesSavedKeypair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	var publicKeys []string
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		publicKeys = append(publicKeys, body["public_key"])
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"agent_id":"agent-%d","registered_at":"2026-06-28T20:00:00Z","nhp_server_peer":{"public_key_b64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","host":"nhp.layerv.ai","port":62206,"expire_time":0}}}`, calls.Add(1))
	}))
	defer api.Close()

	for i := 0; i < 2; i++ {
		if _, err := BootstrapAgent(context.Background(), "lv_bootstrap_once", store, WithBootstrapBaseURL(api.URL)); err != nil {
			t.Fatalf("BootstrapAgent %d: %v", i+1, err)
		}
	}
	if len(publicKeys) != 2 {
		t.Fatalf("public key count = %d, want 2", len(publicKeys))
	}
	if publicKeys[0] == "" || publicKeys[0] != publicKeys[1] {
		t.Fatalf("bootstrap should reuse saved public key, got %q then %q", publicKeys[0], publicKeys[1])
	}
}

func TestFileAgentState_RejectsGroupReadableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	raw := []byte(`{"private_key_b64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("LoadAgentState: want ErrInsecureAgentStatePermissions, got %v", err)
	}
}

func TestFileAgentState_RejectsSymlinkState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent-state.json")
	link := filepath.Join(dir, "agent-state-link.json")
	raw := []byte(`{"private_key_b64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","public_key_b64":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="}`)
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
