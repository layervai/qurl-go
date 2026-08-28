//go:build (!linux || android) && (!darwin || ios) && !windows

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func secureAgentStateTestDirPlatform(*testing.T, string) {}

func securePrivateStateFilePlatform(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateStatePermissionsPlatform(t *testing.T, file, dir string) {
	t.Helper()
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
}

func makePrivateStateFileInsecurePlatform(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
}

func makePrivateStateDirInsecurePlatform(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAgentState_UnsupportedPlatformFailsBeforeMutation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "must-not-exist")
	if _, err := OpenFileAgentState(filepath.Join(dir, "agent.json")); !errors.Is(err, errPinnedStateUnsupported) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("OpenFileAgentState = %v, want unsupported continuity error", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported constructor mutated filesystem: %v", err)
	}
	if _, err := NewSealedFileAgentState(filepath.Join(dir, "sealed.json"), "test", unsupportedTestWrapper{}); !errors.Is(err, errPinnedStateUnsupported) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("NewSealedFileAgentState = %v, want unsupported continuity error", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported sealed constructor mutated filesystem: %v", err)
	}
	if reader, err := OpenFileAgentStateReadOnly(filepath.Join(dir, "agent-read-only.json")); reader != nil || !errors.Is(err, errPinnedStateUnsupported) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("OpenFileAgentStateReadOnly = (%T, %v), want unsupported continuity error", reader, err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported read-only constructor mutated filesystem: %v", err)
	}
	if reader, err := OpenSealedFileAgentStateReadOnly(filepath.Join(dir, "sealed-read-only.json"), "test", unsupportedTestWrapper{}); reader != nil || !errors.Is(err, errPinnedStateUnsupported) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("OpenSealedFileAgentStateReadOnly = (%T, %v), want unsupported continuity error", reader, err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported sealed read-only constructor mutated filesystem: %v", err)
	}
}

type unsupportedTestWrapper struct{}

func (unsupportedTestWrapper) WrapKey(_ context.Context, _ []byte, _ AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	return WrappedAgentStateKey{}, nil
}

func (unsupportedTestWrapper) UnwrapKey(_ context.Context, _ WrappedAgentStateKey, _ AgentStateKeyBinding) ([]byte, error) {
	return nil, nil
}
