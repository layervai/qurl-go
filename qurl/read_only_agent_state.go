package qurl

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

// AgentStateReader is the compile-time read-only surface for inspecting a
// persisted local agent identity. Unlike AgentStateStore, it has no save
// capability. The caller owns the returned handle and must Close it.
type AgentStateReader interface {
	LoadAgentState(context.Context) (*AgentState, error)
	Close() error
}

type localAgentStateReader struct {
	dir      *pinnedStateDir
	name     string
	label    string
	maxBytes int
	decode   func(context.Context, []byte) (*AgentState, error)
	closeMu  sync.Mutex
	cleanup  *runtime.Cleanup
}

var _ AgentStateReader = (*localAgentStateReader)(nil)

// OpenFileAgentStateReadOnly pins an existing trusted 0700 state directory and
// returns a plaintext reader with no Save method. Open, load, and close perform
// no mkdir, chmod, fsync, lock creation, rename, unlink, or write. Every load
// still enforces no-follow traversal, effective-user ownership, 0600 mode,
// link-count one, and descriptor-to-directory-entry continuity.
//
// Linux and Darwin are supported, excluding Android and iOS. A missing state
// file is reported by LoadAgentState as ErrAgentStateNotFound. A missing
// directory fails construction without creating it.
func OpenFileAgentStateReadOnly(path string) (AgentStateReader, error) {
	dir, name, err := openPinnedStatePathReadOnly(path, "agent state")
	if err != nil {
		return nil, err
	}
	return newLocalAgentStateReader(dir, name, "agent state", maxAgentStateBytes, func(_ context.Context, raw []byte) (*AgentState, error) {
		return decodePlaintextAgentState(raw)
	}), nil
}

// OpenSealedFileAgentStateReadOnly pins an existing trusted 0700 state
// directory and returns a sealed reader with no Save method. It accepts the same
// provider and expected-agent-id options as NewSealedFileAgentState, including
// rejection of a mismatched authenticated envelope id before unwrapping.
// Filesystem open, load, and close are strictly read-only; UnwrapKey may still
// call the configured key provider.
func OpenSealedFileAgentStateReadOnly(path, providerID string, wrapper AgentStateKeyWrapper, opts ...SealedFileAgentStateOption) (AgentStateReader, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: sealed agent state path must not be empty", ErrInvalidBootstrapConfig)
	}
	cfg, err := validateSealedFileAgentStateOptions(providerID, wrapper, opts)
	if err != nil {
		return nil, err
	}
	dir, name, err := openPinnedStatePathReadOnly(path, "sealed agent state")
	if err != nil {
		return nil, err
	}
	return newLocalAgentStateReader(dir, name, "sealed agent state", maxSealedAgentStateEnvelope, func(ctx context.Context, raw []byte) (*AgentState, error) {
		return decodeSealedAgentState(ctx, raw, providerID, cfg.expectedAgentID, wrapper)
	}), nil
}

func newLocalAgentStateReader(
	dir *pinnedStateDir,
	name, label string,
	maxBytes int,
	decode func(context.Context, []byte) (*AgentState, error),
) *localAgentStateReader {
	reader := &localAgentStateReader{
		dir:      dir,
		name:     name,
		label:    label,
		maxBytes: maxBytes,
		decode:   decode,
	}
	cleanup := runtime.AddCleanup(reader, closePinnedStateDir, dir)
	reader.cleanup = &cleanup
	return reader
}

func (r *localAgentStateReader) LoadAgentState(ctx context.Context) (state *AgentState, resultErr error) {
	if r == nil || r.dir == nil || r.decode == nil {
		return nil, fmt.Errorf("%w: read-only agent state is not open", ErrAgentStateContinuity)
	}
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	resultErr = r.dir.withLease(func(impl *pinnedStateDirImpl) error {
		raw, err := impl.readFile(r.name, r.label, r.maxBytes, ErrAgentStateNotFound)
		if err != nil {
			return err
		}
		defer wipeBytes(raw)
		state, err = r.decode(ctx, raw)
		return err
	})
	runtime.KeepAlive(r)
	return state, resultErr
}

func (r *localAgentStateReader) Close() (resultErr error) {
	if r == nil || r.dir == nil {
		return fmt.Errorf("%w: read-only agent state is not open", ErrAgentStateContinuity)
	}
	r.closeMu.Lock()
	if r.cleanup != nil {
		r.cleanup.Stop()
		r.cleanup = nil
	}
	r.closeMu.Unlock()
	resultErr = r.dir.close()
	runtime.KeepAlive(r)
	return resultErr
}
