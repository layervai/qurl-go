//go:build unix

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestAcquireAgentSetupLock_EngagesOSAdvisoryLock proves the serialization is the
// OS advisory flock itself, not in-process goroutine scheduling: while
// acquireAgentSetupLock holds the lock, an INDEPENDENT file descriptor on the same
// sidecar (standing in for a second process) cannot take a non-blocking exclusive
// flock, and can only take it after the first holder releases. This is the
// cross-"process" guarantee issue #48 relies on, which a single-process
// same-FileAgentState test (which a plain mutex would also satisfy) cannot show.
func TestAcquireAgentSetupLock_EngagesOSAdvisoryLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store := FileAgentState(path)

	release := acquireAgentSetupLock(context.Background(), store)

	// A second, independent open of the same sidecar file gets its own open file
	// description, so its flock contends with the first exactly as another process
	// would (flock is per-description, not per-process).
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		release()
		t.Fatalf("open sidecar: %v", err)
	}
	defer func() { _ = f.Close() }()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		if err == nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		}
		release()
		t.Fatalf("second flock handle while the lock is held: err = %v, want EWOULDBLOCK/EAGAIN (the OS lock must block it)", err)
	}

	// After the first holder releases, the independent handle acquires it — proving
	// the block above was the held lock, not an unopenable sidecar.
	release()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("after release the second handle should acquire the lock, got %v", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
