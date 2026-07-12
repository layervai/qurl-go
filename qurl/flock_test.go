package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAcquireAgentSetupLock_SerializesSameFileStore proves the mandatory lock
// gives mutual exclusion for two holders sharing one FileAgentState path: while
// the first holds it, a second acquire blocks, and it only proceeds after the
// first releases. Run under -race, the two goroutines' ordering is observable
// through a shared counter guarded solely by the lock.
func TestAcquireAgentSetupLock_SerializesSameFileStore(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skipf("flock is unsupported on %s; local-file setup fails closed there", runtime.GOOS)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-state.json")
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
		release, err := acquireAgentSetupLock(context.Background(), store)
		if err != nil {
			// Always release the waiter even when acquisition regresses; otherwise
			// the test itself deadlocks and hides the useful lock error until timeout.
			close(firstHeld)
			t.Errorf("first acquire: %v", err)
			return
		}
		close(firstHeld)
		// Hold long enough that B's acquire must block on the flock.
		time.Sleep(80 * time.Millisecond)
		aReleased.Store(true)
		_ = release()
	}()

	go func() {
		defer wg.Done()
		<-firstHeld // ensure A holds the lock before B tries
		release, err := acquireAgentSetupLock(context.Background(), store)
		if err != nil {
			t.Errorf("second acquire: %v", err)
			return
		}
		if !aReleased.Load() {
			bEnteredBeforeARelease.Store(true)
		}
		_ = release()
	}()

	wg.Wait()
	if bEnteredBeforeARelease.Load() {
		t.Fatal("second holder entered the critical section before the first released; mandatory lock did not serialize")
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
	r1, err := acquireAgentSetupLock(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := acquireAgentSetupLock(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if r1 == nil || r2 == nil {
		t.Fatal("acquireAgentSetupLock must always return a non-nil release, even for a non-file store")
	}
	_ = r1()
	_ = r2()
}

// TestAcquireAgentSetupLock_CanceledContextFailsClosed confirms cancellation
// aborts acquisition rather than allowing setup to continue unlocked.
func TestAcquireAgentSetupLock_CanceledContextFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skipf("flock is unsupported on %s", runtime.GOOS)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-state.json")
	store := FileAgentState(path)

	// Hold the lock in a first acquire so a second, with a canceled context, cannot
	// get it and must fall back to a no-op release.
	hold, err := acquireAgentSetupLock(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireAgentSetupLock(ctx, store); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock: got %v, want context.Canceled", err)
	}
}

// memAgentStore is an in-memory AgentStateStore used to prove the SDK lock
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
