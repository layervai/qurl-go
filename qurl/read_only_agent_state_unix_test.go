//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type readOnlyMetadata struct {
	mode    os.FileMode
	size    int64
	modTime time.Time
}

func statReadOnlyMetadata(t *testing.T, path string) readOnlyMetadata {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return readOnlyMetadata{mode: info.Mode(), size: info.Size(), modTime: info.ModTime()}
}

func writePlaintextAgentStateFixture(t *testing.T, path string, state *AgentState) {
	t.Helper()
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFileAgentStateReadOnly_NoExplicitMutationAndNoSaveCapability(t *testing.T) {
	dir := secureAgentStateTestDir(t)
	path := filepath.Join(dir, "agent-state.json")
	want := completedNativeTestState(t)
	writePlaintextAgentStateFixture(t, path, want)
	beforeFile := statReadOnlyMetadata(t, path)
	beforeDir := statReadOnlyMetadata(t, dir)

	original := defaultPinnedStateDirHooks
	var syncCalls atomic.Int32
	defaultPinnedStateDirHooks.syncFD = func(int) error {
		syncCalls.Add(1)
		return errors.New("read-only path attempted fsync")
	}
	t.Cleanup(func() { defaultPinnedStateDirHooks = original })

	reader, err := OpenFileAgentStateReadOnly(path)
	if err != nil {
		t.Fatalf("open read-only plaintext: %v", err)
	}
	if _, ok := reader.(interface {
		SaveAgentState(context.Context, *AgentState) error
	}); ok {
		t.Fatal("read-only API exposed SaveAgentState")
	}
	got, err := reader.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load read-only plaintext: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read-only plaintext mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close read-only plaintext: %v", err)
	}
	if syncCalls.Load() != 0 {
		t.Fatalf("read-only open/load/close called fsync %d times", syncCalls.Load())
	}
	if after := statReadOnlyMetadata(t, path); after != beforeFile {
		t.Fatalf("read-only open/load/close changed file metadata: before %#v after %#v", beforeFile, after)
	}
	if after := statReadOnlyMetadata(t, dir); after != beforeDir {
		t.Fatalf("read-only open/load/close changed directory metadata: before %#v after %#v", beforeDir, after)
	}
	if _, err := os.Lstat(path + agentSetupLockSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only API created setup lock: %v", err)
	}
}

func TestOpenFileAgentStateReadOnly_MissingPathsDoNotMutate(t *testing.T) {
	root := secureAgentStateTestDir(t)
	missingDir := filepath.Join(root, "must-not-exist")
	if reader, err := OpenFileAgentStateReadOnly(filepath.Join(missingDir, "agent-state.json")); reader != nil || err == nil {
		t.Fatalf("missing-directory open = (%T, %v), want nil error result", reader, err)
	}
	if _, err := os.Lstat(missingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-directory open mutated filesystem: %v", err)
	}

	path := filepath.Join(root, "missing-agent-state.json")
	beforeDir := statReadOnlyMetadata(t, root)
	reader, err := OpenFileAgentStateReadOnly(path)
	if err != nil {
		t.Fatalf("missing-file open: %v", err)
	}
	if state, err := reader.LoadAgentState(context.Background()); state != nil || !errors.Is(err, ErrAgentStateNotFound) {
		t.Fatalf("missing-file load = (%#v, %v), want nil ErrAgentStateNotFound", state, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-file read created state: %v", err)
	}
	if _, err := os.Lstat(path + agentSetupLockSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-file read created lock: %v", err)
	}
	if after := statReadOnlyMetadata(t, root); after != beforeDir {
		t.Fatalf("missing-file read changed directory metadata: before %#v after %#v", beforeDir, after)
	}
}

func TestOpenFileAgentStateReadOnly_FailsClosedOnMutationAndContinuityLoss(t *testing.T) {
	t.Run("permissions", func(t *testing.T) {
		dir := secureAgentStateTestDir(t)
		path := filepath.Join(dir, "agent-state.json")
		writePlaintextAgentStateFixture(t, path, completedNativeTestState(t))
		reader, err := OpenFileAgentStateReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.LoadAgentState(context.Background()); !errors.Is(err, ErrInsecureAgentStatePermissions) {
			t.Fatalf("group-readable load = %v, want insecure permissions", err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		dir := secureAgentStateTestDir(t)
		path := filepath.Join(dir, "agent-state.json")
		writePlaintextAgentStateFixture(t, path, completedNativeTestState(t))
		if err := os.Link(path, path+".hardlink"); err != nil {
			t.Fatal(err)
		}
		if reader, err := OpenFileAgentStateReadOnly(path); reader != nil || !errors.Is(err, ErrAgentStateContinuity) {
			t.Fatalf("hard-linked open = (%T, %v), want continuity failure", reader, err)
		}
	})

	t.Run("ancestor replacement", func(t *testing.T) {
		root := secureAgentStateTestDir(t)
		dir := filepath.Join(root, "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "agent-state.json")
		writePlaintextAgentStateFixture(t, path, completedNativeTestState(t))
		reader, err := OpenFileAgentStateReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writePlaintextAgentStateFixture(t, path, completedNativeTestState(t))
		if _, err := reader.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateContinuity) {
			t.Fatalf("replacement load = %v, want continuity failure", err)
		}
	})
}

func TestOpenSealedFileAgentStateReadOnly_NoExplicitMutationAndExpectedIdentity(t *testing.T) {
	dir := secureAgentStateTestDir(t)
	path := filepath.Join(dir, "agent-state.sealed.json")
	wrapper := &testAgentStateKeyWrapper{}
	writer, err := NewSealedFileAgentState(path, "test-wrapper", wrapper, WithExpectedSealedAgentID("agent-sealed-test"))
	if err != nil {
		t.Fatal(err)
	}
	want := testAgentState(t)
	if err := writer.SaveAgentState(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + agentSetupLockSuffix); err != nil {
		t.Fatal(err)
	}
	beforeFile := statReadOnlyMetadata(t, path)
	beforeDir := statReadOnlyMetadata(t, dir)

	original := defaultPinnedStateDirHooks
	var syncCalls atomic.Int32
	defaultPinnedStateDirHooks.syncFD = func(int) error {
		syncCalls.Add(1)
		return errors.New("read-only sealed path attempted fsync")
	}
	t.Cleanup(func() { defaultPinnedStateDirHooks = original })

	reader, err := OpenSealedFileAgentStateReadOnly(path, "test-wrapper", wrapper, WithExpectedSealedAgentID(want.AgentID))
	if err != nil {
		t.Fatalf("open read-only sealed: %v", err)
	}
	got, err := reader.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load read-only sealed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read-only sealed mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if syncCalls.Load() != 0 {
		t.Fatalf("read-only sealed open/load/close called fsync %d times", syncCalls.Load())
	}
	if after := statReadOnlyMetadata(t, path); after != beforeFile {
		t.Fatalf("read-only sealed changed file metadata: before %#v after %#v", beforeFile, after)
	}
	if after := statReadOnlyMetadata(t, dir); after != beforeDir {
		t.Fatalf("read-only sealed changed directory metadata: before %#v after %#v", beforeDir, after)
	}
	if _, err := os.Lstat(path + agentSetupLockSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only sealed created setup lock: %v", err)
	}

	unwrapsBefore := len(wrapper.unwrapBindings)
	mismatch, err := OpenSealedFileAgentStateReadOnly(path, "test-wrapper", wrapper, WithExpectedSealedAgentID("agent-other"))
	if err != nil {
		t.Fatalf("open mismatched read-only sealed: %v", err)
	}
	defer func() { _ = mismatch.Close() }()
	if _, err := mismatch.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("mismatched sealed load = %v, want invalid state", err)
	}
	if got := len(wrapper.unwrapBindings); got != unwrapsBefore {
		t.Fatalf("expected-id mismatch called unwrap: before %d after %d", unwrapsBefore, got)
	}
}

func TestOpenFileAgentStateReadOnly_DescriptorEntryMutationFailsClosed(t *testing.T) {
	dir := secureAgentStateTestDir(t)
	path := filepath.Join(dir, "agent-state.json")
	writePlaintextAgentStateFixture(t, path, completedNativeTestState(t))
	reader, err := OpenFileAgentStateReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	// A hard link proves both constructor and load inspect link count on the
	// descriptor and directory entry, not only pathname mode bits.
	if err := unix.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("post-open hardlink load = %v, want descriptor-entry continuity failure", err)
	}
}
