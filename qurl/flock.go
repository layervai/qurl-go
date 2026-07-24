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

type setupLockStoreBinder interface {
	bindStore(AgentStateStore) AgentStateStore
}

// setupLockReentryMarker is deliberately a denial-only context marker, not a
// lock or write capability. SDK callbacks receive it while a local store's
// setup lock is held so an accidental SaveAgentState call on that same public
// handle fails promptly instead of waiting on its own flock forever.
type setupLockReentryMarker struct {
	store AgentStateStore
}

type setupLockReentryContextKey struct{}

func markSetupLockReentry(ctx context.Context, store AgentStateStore) context.Context {
	if ctx == nil {
		return nil
	}
	base := baseAgentStateStore(store)
	switch base.(type) {
	case *FileAgentStateStore, *SealedFileAgentStateStore:
		return context.WithValue(ctx, setupLockReentryContextKey{}, setupLockReentryMarker{store: base})
	default:
		return ctx
	}
}

func rejectSetupLockReentry(ctx context.Context, store AgentStateStore) error {
	if ctx == nil {
		return nil
	}
	marker, ok := ctx.Value(setupLockReentryContextKey{}).(setupLockReentryMarker)
	if !ok || marker.store != baseAgentStateStore(store) {
		return nil
	}
	return fmt.Errorf("%w: reentrant save on the store whose setup lock is active", ErrAgentSetupLock)
}

type setupLockingAgentStateStore interface {
	acquireSetupLock(context.Context) (setupLock, error)
}

// acquireAgentSetupLock takes the mandatory exclusive setup lock for SDK local
// file stores. Lock/open/wait failures fail closed because proceeding without
// serialization could mint competing identities. Custom and network stores
// retain the caller-serialization contract and receive a no-op release.
func acquireAgentSetupLock(ctx context.Context, store AgentStateStore) (func() error, error) {
	_, release, err := acquireAgentSetupLockStore(ctx, store)
	return release, err
}

func acquireAgentSetupLockStore(ctx context.Context, store AgentStateStore) (AgentStateStore, func() error, error) {
	noop := func() error { return nil }
	fs, ok := store.(setupLockingAgentStateStore)
	if !ok {
		return store, noop, nil
	}
	lock, err := fs.acquireSetupLock(ctx)
	if err != nil {
		return nil, nil, err
	}
	if lock == nil {
		return nil, nil, ErrAgentSetupLock
	}
	lockedStore := store
	if binder, ok := lock.(setupLockStoreBinder); ok {
		lockedStore = binder.bindStore(store)
	}
	return lockedStore, lock.Close, nil
}
