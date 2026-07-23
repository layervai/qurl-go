//go:build (!linux || android) && (!darwin || ios)

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
}

type unsupportedTestWrapper struct{}

func (unsupportedTestWrapper) WrapKey(_ context.Context, _ []byte, _ AgentStateKeyBinding) (WrappedAgentStateKey, error) {
	return WrappedAgentStateKey{}, nil
}

func (unsupportedTestWrapper) UnwrapKey(_ context.Context, _ WrappedAgentStateKey, _ AgentStateKeyBinding) ([]byte, error) {
	return nil, nil
}
