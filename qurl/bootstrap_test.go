package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFileAgentState_NativeRoundTrip(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent-state.json")
	store := FileAgentState(path)
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
		"unknown field":  `{"private_key_b64":"x","public_key_b64":"y","` + untrustedField + `":true}`,
		"trailing value": `{"private_key_b64":"x","public_key_b64":"y"} {}`,
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
	store := FileAgentState(path)
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

func TestFileAgentState_RespectsCanceledContext(t *testing.T) {
	store := FileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent-state.json"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.LoadAgentState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load = %v", err)
	}
	if err := store.SaveAgentState(ctx, completedNativeTestState(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save = %v", err)
	}
}
