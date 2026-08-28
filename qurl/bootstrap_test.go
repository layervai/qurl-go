package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/internal/x25519key"
)

func TestFileAgentState_NativeRoundTrip(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent-state.json")
	store := testFileAgentState(t, path)
	want := completedNativeTestState(t)
	expected := want.clone()
	if err := store.SaveAgentState(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	want.DeviceAPIKey = "mutated-after-save"
	got, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("native AgentState round trip mismatch:\nwant %#v\n got %#v", expected, got)
	}
}

func TestFileAgentState_RejectsUnknownOrTrailingJSON(t *testing.T) {
	const untrustedField = "lv_live_file_decode_secret"
	for name, raw := range map[string]string{
		"unknown field":           `{"private_key_b64":"x","public_key_b64":"y","` + untrustedField + `":true}`,
		"trailing value":          `{"private_key_b64":"x","public_key_b64":"y"} {}`,
		"duplicate top-level key": `{"private_key_b64":"x","private_key_b64":"y","public_key_b64":"z"}`,
		"duplicate nested key":    `{"private_key_b64":"x","public_key_b64":"y","assignment":{"cell_id":"cell0","cell_id":"cell1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(secureAgentStateTestDir(t), "agent-state.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
				t.Fatalf("load error = %v, want ErrInvalidAgentState", err)
			} else if strings.Contains(err.Error(), untrustedField) {
				t.Fatalf("load error reflected untrusted credential-file content: %v", err)
			}
		})
	}
}

func TestFileAgentState_RejectsInsecurePermissions(t *testing.T) {
	dir := secureAgentStateTestDir(t)
	path := filepath.Join(dir, "agent-state.json")
	store := testFileAgentState(t, path)
	if err := store.SaveAgentState(context.Background(), completedNativeTestState(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("group-readable file error = %v, want ErrInsecureAgentStatePermissions", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("insecure directory load error = %v, want ErrInsecureAgentStatePermissions", err)
	}
	if err := store.SaveAgentState(context.Background(), completedNativeTestState(t)); !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("insecure directory save error = %v, want ErrInsecureAgentStatePermissions", err)
	}
}

func TestFileAgentState_RejectsSymlinkAndOversize(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := secureAgentStateTestDir(t)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "agent-state.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
			t.Fatalf("symlink error = %v, want ErrInvalidAgentState", err)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(secureAgentStateTestDir(t), "agent-state.json")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", maxAgentStateBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := FileAgentState(path).LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
			t.Fatalf("oversize error = %v, want ErrInvalidAgentState", err)
		}
	})
}

// A keypair loaded from a store the SDK did not write is the one place the
// device identity can be split: signing with one private key while every
// authenticated exchange claims the persisted public key. Every branch below has
// to fail closed rather than normalize the state into agreement.
func TestEnsureKeypair_FailsClosedOnAMismatchedIdentity(t *testing.T) {
	valid, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	other, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	if valid.PublicKeyB64 == other.PublicKeyB64 {
		t.Fatal("two generated keypairs collided")
	}
	for name, state := range map[string]*AgentState{
		"public key belongs to another private key": {PrivateKeyB64: valid.PrivateKeyB64, PublicKeyB64: other.PublicKeyB64},
		"private key is not X25519":                 {PrivateKeyB64: base64.StdEncoding.EncodeToString(make([]byte, x25519key.Size-1)), PublicKeyB64: valid.PublicKeyB64},
		"private key is not base64":                 {PrivateKeyB64: "!!!not base64!!!", PublicKeyB64: valid.PublicKeyB64},
	} {
		t.Run(name, func(t *testing.T) {
			if err := state.ensureKeypair(ErrInvalidClientConfig); !errors.Is(err, ErrInvalidClientConfig) {
				t.Fatalf("ensureKeypair = %v, want ErrInvalidClientConfig", err)
			}
		})
	}

	t.Run("nil state", func(t *testing.T) {
		var absent *AgentState
		if err := absent.ensureKeypair(ErrInvalidClientConfig); !errors.Is(err, ErrInvalidClientConfig) {
			t.Fatalf("nil state ensureKeypair = %v, want ErrInvalidClientConfig", err)
		}
	})

	// An absent public key is derived rather than rejected: it is the one shape
	// that carries no contradictory claim about who this device is.
	t.Run("absent public key is derived from the private key", func(t *testing.T) {
		derived := &AgentState{PrivateKeyB64: valid.PrivateKeyB64}
		if err := derived.ensureKeypair(ErrInvalidClientConfig); err != nil {
			t.Fatalf("ensureKeypair with an absent public key: %v", err)
		}
		if derived.PublicKeyB64 != valid.PublicKeyB64 {
			t.Fatalf("derived public key = %q, want %q", derived.PublicKeyB64, valid.PublicKeyB64)
		}
	})
}

func TestFileAgentState_RespectsCanceledContext(t *testing.T) {
	store := testFileAgentState(t, filepath.Join(secureAgentStateTestDir(t), "agent-state.json"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load = %v", err)
	}
	if err := store.SaveAgentState(ctx, completedNativeTestState(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save = %v", err)
	}
}
