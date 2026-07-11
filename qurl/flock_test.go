package qurl

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAcquireAgentSetupLock_SerializesSameFileStore proves the #48 advisory lock
// gives mutual exclusion for two holders sharing one FileAgentState path: while
// the first holds it, a second acquire blocks, and it only proceeds after the
// first releases. Run under -race, the two goroutines' ordering is observable
// through a shared counter guarded solely by the lock.
func TestAcquireAgentSetupLock_SerializesSameFileStore(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skipf("advisory flock is a no-op on %s; serialization is not guaranteed there", runtime.GOOS)
	}
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	// firstHeld closes once goroutine A holds the lock; firstReleasing records the
	// moment A is about to release so we can assert B did not enter before it.
	firstHeld := make(chan struct{})
	var aReleased atomic.Bool
	var bEnteredBeforeARelease atomic.Bool

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		release := acquireAgentSetupLock(context.Background(), store)
		close(firstHeld)
		// Hold long enough that B's acquire must block on the flock.
		time.Sleep(80 * time.Millisecond)
		aReleased.Store(true)
		release()
	}()

	go func() {
		defer wg.Done()
		<-firstHeld // ensure A holds the lock before B tries
		release := acquireAgentSetupLock(context.Background(), store)
		if !aReleased.Load() {
			bEnteredBeforeARelease.Store(true)
		}
		release()
	}()

	wg.Wait()
	if bEnteredBeforeARelease.Load() {
		t.Fatal("second holder entered the critical section before the first released; advisory lock did not serialize")
	}
}

// TestAcquireAgentSetupLock_NonFileStoreIsNoop confirms the lock only engages for
// the local file store: a non-file AgentStateStore gets a no-op release (the
// documented "one setup at a time" contract), and two acquires never block each
// other.
func TestAcquireAgentSetupLock_NonFileStoreIsNoop(t *testing.T) {
	store := &memAgentStore{}
	// Two back-to-back acquires must both return immediately (no serialization for
	// a non-file store); if the lock engaged, the second would block forever since
	// nothing releases between them.
	r1 := acquireAgentSetupLock(context.Background(), store)
	r2 := acquireAgentSetupLock(context.Background(), store)
	if r1 == nil || r2 == nil {
		t.Fatal("acquireAgentSetupLock must always return a non-nil release, even for a non-file store")
	}
	r1()
	r2()
}

// TestAcquireAgentSetupLock_CanceledContextIsAdvisory confirms a canceled context
// yields a no-op release rather than an error or a panic: acquisition failure
// must never harden the best-effort lock into a hard dependency.
func TestAcquireAgentSetupLock_CanceledContextIsAdvisory(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skipf("advisory flock is a no-op on %s", runtime.GOOS)
	}
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	// Hold the lock in a first acquire so a second, with a canceled context, cannot
	// get it and must fall back to a no-op release.
	hold := acquireAgentSetupLock(context.Background(), store)
	defer hold()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release := acquireAgentSetupLock(ctx, store) // must not block or panic
	release()                                    // must be safe even though no lock was taken
}

// memAgentStore is an in-memory AgentStateStore used to prove the advisory lock
// is scoped to the file store (a non-file store is a no-op). It is intentionally
// minimal: the lock helper only type-asserts the store, so its methods are never
// exercised here.
type memAgentStore struct {
	mu    sync.Mutex
	state *AgentState
}

func (m *memAgentStore) LoadAgentState(context.Context) (*AgentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return nil, ErrAgentStateNotFound
	}
	clone := *m.state
	return &clone, nil
}

func (m *memAgentStore) SaveAgentState(_ context.Context, s *AgentState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := *s
	m.state = &clone
	return nil
}
