package qurl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
)

// ErrAgentStateContinuity reports that an SDK-owned local state namespace no
// longer resolves to the directory capability pinned by its constructor. Local
// lifecycle operations fail closed on this error: continuing could split the
// mandatory setup lock from the credential file or commit into an attacker-
// substituted directory.
var ErrAgentStateContinuity = errors.New("qurl: agent state namespace continuity lost")

// AgentStateContinuity is the minimal public lifetime contract exposed by the
// SDK-owned local stores. Connector should construct one store for its process
// lifetime, defer Close, and call ValidateContinuity before handing a completed
// binding to another subsystem. The native lifecycle entry points also validate
// it internally.
type AgentStateContinuity interface {
	io.Closer
	ValidateContinuity() error
}

type pinnedStateDirOpenMode uint8

const (
	pinnedStateDirWritable pinnedStateDirOpenMode = iota
	pinnedStateDirReadOnly
)

var (
	_ func(string) AgentStateStore = FileAgentState
	_ AgentStateStore              = (*FileAgentStateStore)(nil)
	_ AgentStateContinuity         = (*FileAgentStateStore)(nil)
	_ AgentStateStore              = (*SealedFileAgentStateStore)(nil)
	_ AgentStateContinuity         = (*SealedFileAgentStateStore)(nil)
)

type pinnedStateDir struct {
	mu       sync.Mutex
	cond     *sync.Cond
	impl     *pinnedStateDirImpl
	refs     int
	closing  bool
	closed   bool
	closeErr error
}

type pinnedStateDirLease struct {
	once sync.Once
	dir  *pinnedStateDir
}

// pinnedSetupLockToken is an unforgeable, package-private capability carried
// only by the private store wrapper passed to a setup-lock callback. Pointer
// identity, rather than an fd number that the kernel can reuse, binds a write
// to one live lock acquisition.
type pinnedSetupLockToken struct {
	impl *pinnedStateDirImpl
}

type pinnedStateOperation struct {
	mu     sync.Mutex
	dir    *pinnedStateDir
	impl   *pinnedStateDirImpl
	lease  *pinnedStateDirLease
	active bool
}

func (o *pinnedStateOperation) implementation() (*pinnedStateDirImpl, error) {
	if o == nil {
		return nil, fmt.Errorf("%w: local state operation is nil", ErrAgentStateContinuity)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.active || o.impl == nil {
		return nil, fmt.Errorf("%w: local state operation has ended", ErrAgentStateContinuity)
	}
	return o.impl, nil
}

func (o *pinnedStateOperation) validate() error {
	impl, err := o.implementation()
	if err != nil {
		return err
	}
	return impl.validateContinuity()
}

func (o *pinnedStateOperation) release() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if !o.active {
		o.mu.Unlock()
		return nil
	}
	o.active = false
	lease := o.lease
	o.lease = nil
	o.mu.Unlock()
	return lease.release()
}

type retainedLocalAgentStateStore struct {
	base  AgentStateStore
	op    *pinnedStateOperation
	setup *pinnedSetupLockToken
}

// agentStateStoreDecorator is the package-private contract for SDK-internal
// wrappers that must preserve a local store's retained directory and setup-lock
// capabilities. Keeping this unexported prevents arbitrary application stores
// from acquiring either capability.
type agentStateStoreDecorator interface {
	decoratedAgentStateStore() AgentStateStore
	withDecoratedAgentStateStore(AgentStateStore) AgentStateStore
}

func (s *retainedLocalAgentStateStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	switch base := s.base.(type) {
	case *FileAgentStateStore:
		return base.loadAgentStateRetained(ctx, s.op)
	case *SealedFileAgentStateStore:
		return base.loadAgentStateRetained(ctx, s.op)
	default:
		return nil, fmt.Errorf("%w: unsupported retained local state store %T", ErrAgentStateContinuity, s.base)
	}
}

func (s *retainedLocalAgentStateStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	switch base := s.base.(type) {
	case *FileAgentStateStore:
		return base.saveAgentStateRetained(ctx, state, s.op, s.setup)
	case *SealedFileAgentStateStore:
		return base.saveAgentStateRetained(ctx, state, s.op, s.setup)
	default:
		return fmt.Errorf("%w: unsupported retained local state store %T", ErrAgentStateContinuity, s.base)
	}
}

func (s *retainedLocalAgentStateStore) ValidateContinuity() error {
	if s == nil || s.op == nil {
		return fmt.Errorf("%w: retained local state store is nil", ErrAgentStateContinuity)
	}
	return s.op.validate()
}

func (s *retainedLocalAgentStateStore) retainContinuity() (AgentStateStore, func() error, error) {
	if err := s.ValidateContinuity(); err != nil {
		return nil, nil, err
	}
	return s, func() error { return nil }, nil
}

func (s *retainedLocalAgentStateStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	impl, err := s.op.implementation()
	if err != nil {
		return nil, err
	}
	name, err := localStateStoreName(s.base)
	if err != nil {
		return nil, err
	}
	lock, err := s.op.dir.lockWithImpl(ctx, name+agentSetupLockSuffix, impl)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire pinned setup lock: %w", ErrAgentSetupLock, err)
	}
	return lock, nil
}

func (s *retainedLocalAgentStateStore) withSetup(token *pinnedSetupLockToken) AgentStateStore {
	return &retainedLocalAgentStateStore{base: s.base, op: s.op, setup: token}
}

func localStateStoreName(store AgentStateStore) (string, error) {
	switch store := store.(type) {
	case *FileAgentStateStore:
		return store.name, nil
	case *SealedFileAgentStateStore:
		return store.name, nil
	default:
		return "", fmt.Errorf("%w: unsupported local state store %T", ErrAgentStateContinuity, store)
	}
}

func baseAgentStateStore(store AgentStateStore) AgentStateStore {
	for {
		switch current := store.(type) {
		case *retainedLocalAgentStateStore:
			store = current.base
		case agentStateStoreDecorator:
			store = current.decoratedAgentStateStore()
		default:
			return store
		}
	}
}

func openPinnedStatePath(path, label string) (*pinnedStateDir, string, error) {
	return openPinnedStatePathWithMode(path, label, pinnedStateDirWritable)
}

func openPinnedStatePathReadOnly(path, label string) (*pinnedStateDir, string, error) {
	return openPinnedStatePathWithMode(path, label, pinnedStateDirReadOnly)
}

func openPinnedStatePathWithMode(path, label string, mode pinnedStateDirOpenMode) (*pinnedStateDir, string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", fmt.Errorf("%w: %s path must not be empty", ErrInvalidBootstrapConfig, label)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("%w: resolve %s path: %w", ErrInvalidBootstrapConfig, label, err)
	}
	absolute = filepath.Clean(absolute)
	absolute = canonicalPinnedStatePath(absolute)
	name := filepath.Base(absolute)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return nil, "", fmt.Errorf("%w: %s path must name a file", ErrInvalidBootstrapConfig, label)
	}
	impl, err := openPinnedStateDir(filepath.Dir(absolute), label, mode)
	if err != nil {
		return nil, "", err
	}
	if err := impl.validateInitialEntry(name, label); err != nil {
		if closeErr := impl.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: close rejected %s directory: %w", ErrAgentStateContinuity, label, closeErr))
		}
		return nil, "", err
	}
	dir := &pinnedStateDir{impl: impl, refs: 1}
	dir.cond = sync.NewCond(&dir.mu)
	return dir, name, nil
}

func (d *pinnedStateDir) retain() (*pinnedStateDirLease, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: local state directory is nil", ErrAgentStateContinuity)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.closing || d.impl == nil {
		return nil, fmt.Errorf("%w: local state store is closed", ErrAgentStateContinuity)
	}
	d.refs++
	return &pinnedStateDirLease{dir: d}, nil
}

func (l *pinnedStateDirLease) release() error {
	if l == nil {
		return nil
	}
	var releaseErr error
	l.once.Do(func() {
		d := l.dir
		if d == nil {
			return
		}
		d.mu.Lock()
		d.refs--
		if d.refs < 0 {
			releaseErr = fmt.Errorf("%w: local state reference underflow", ErrAgentStateContinuity)
			d.refs = 0
		}
		if d.refs == 0 {
			d.cond.Broadcast()
		}
		d.mu.Unlock()
		l.dir = nil
	})
	return releaseErr
}

func (d *pinnedStateDir) withLease(fn func(*pinnedStateDirImpl) error) error {
	lease, err := d.retain()
	if err != nil {
		return err
	}
	defer func() { _ = lease.release() }()
	return fn(d.impl)
}

func (d *pinnedStateDir) validate() error {
	return d.withLease(func(impl *pinnedStateDirImpl) error {
		return impl.validateContinuity()
	})
}

func (d *pinnedStateDir) retainOperation(base AgentStateStore) (AgentStateStore, func() error, error) {
	lease, err := d.retain()
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	impl := d.impl
	d.mu.Unlock()
	op := &pinnedStateOperation{dir: d, impl: impl, lease: lease, active: true}
	retained := &retainedLocalAgentStateStore{base: base, op: op}
	return retained, op.release, nil
}

func (d *pinnedStateDir) close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	if d.closed {
		err := d.closeErr
		d.mu.Unlock()
		return err
	}
	if d.closing {
		for !d.closed {
			d.cond.Wait()
		}
		err := d.closeErr
		d.mu.Unlock()
		return err
	}
	d.closing = true
	d.refs-- // release the public owner reference
	for d.refs != 0 {
		d.cond.Wait()
	}
	impl := d.impl
	d.impl = nil
	d.mu.Unlock()
	var closeErr error
	if impl != nil {
		if err := impl.close(); err != nil {
			closeErr = fmt.Errorf("%w: close pinned state directory: %w", ErrAgentStateContinuity, err)
		}
	}
	d.mu.Lock()
	d.closeErr = closeErr
	d.closed = true
	d.closing = false
	d.cond.Broadcast()
	d.mu.Unlock()
	return closeErr
}

func (o *pinnedStateOperation) load(ctx context.Context, name, label string, maxBytes int, notFound error) ([]byte, error) {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return nil, err
	}
	impl, err := o.implementation()
	if err != nil {
		return nil, err
	}
	return impl.readFile(name, label, maxBytes, notFound)
}

func (o *pinnedStateOperation) save(ctx context.Context, setup *pinnedSetupLockToken, name, label, tempPrefix string, raw []byte) error {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return err
	}
	impl, err := o.implementation()
	if err != nil {
		return err
	}
	return impl.writeFileAtomic(ctx, setup, name, label, tempPrefix, raw)
}

func retainAgentStateContinuity(store AgentStateStore) (AgentStateStore, func() error, func() error, error) {
	if decorator, ok := store.(agentStateStoreDecorator); ok {
		retained, validate, release, err := retainAgentStateContinuity(decorator.decoratedAgentStateStore())
		if err != nil {
			return nil, nil, nil, err
		}
		return decorator.withDecoratedAgentStateStore(retained), validate, release, nil
	}
	local, ok := store.(interface {
		retainContinuity() (AgentStateStore, func() error, error)
	})
	if !ok {
		return store, func() error { return nil }, func() error { return nil }, nil
	}
	retained, release, err := local.retainContinuity()
	if err != nil {
		return nil, nil, nil, err
	}
	return retained, func() error { return validateAgentStateStoreContinuity(retained) }, release, nil
}

func validateAgentStateStoreContinuity(store AgentStateStore) error {
	if decorator, ok := store.(agentStateStoreDecorator); ok {
		return validateAgentStateStoreContinuity(decorator.decoratedAgentStateStore())
	}
	local, ok := store.(interface{ ValidateContinuity() error })
	if !ok {
		return nil
	}
	return local.ValidateContinuity()
}
