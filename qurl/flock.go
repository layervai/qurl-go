package qurl

import (
	"context"
	"fmt"
)

// agentSetupLockSuffix names the stable sidecar lockfile taken during setup.
const agentSetupLockSuffix = ".lock"

type setupLock interface {
	Close() error
}

type setupLockingAgentStateStore interface {
	setupLockPath() string
	acquireSetupLock(context.Context) (setupLock, error)
}

// fileSetupLock is the shared setup-lock behavior for SDK local-file stores.
// Embedding it provides one source for path derivation, typed error wrapping,
// and the injected lock seam used by failure tests.
type fileSetupLock struct {
	path     string
	lockFile func(context.Context, string) (setupLock, error)
}

func (l fileSetupLock) setupLockPath() string { return l.path + agentSetupLockSuffix }

func (l fileSetupLock) acquireSetupLock(ctx context.Context) (setupLock, error) {
	path := l.setupLockPath()
	lock, err := l.lockFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire %s: %w", ErrAgentSetupLock, path, err)
	}
	return lock, nil
}

// acquireAgentSetupLock takes the mandatory exclusive setup lock for SDK local
// file stores. Lock/open/wait failures fail closed because proceeding without
// serialization could mint competing identities. Custom and network stores
// retain the caller-serialization contract and receive a no-op release.
func acquireAgentSetupLock(ctx context.Context, store AgentStateStore) (func() error, error) {
	noop := func() error { return nil }
	fs, ok := store.(setupLockingAgentStateStore)
	if !ok {
		return noop, nil
	}
	lock, err := fs.acquireSetupLock(ctx)
	if err != nil {
		return nil, err
	}
	if lock == nil {
		return nil, ErrAgentSetupLock
	}
	return lock.Close, nil
}
