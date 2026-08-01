//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAcquireAgentSetupLock_EngagesOSLock proves the serialization is the OS
// flock itself, not in-process goroutine scheduling: while
// acquireAgentSetupLock holds the lock, an INDEPENDENT file descriptor on the same
// sidecar (standing in for a second process) cannot take a non-blocking exclusive
// flock, and can only take it after the first holder releases. This is the
// cross-"process" guarantee issue #48 relies on, which a single-process
// same-FileAgentState test (which a plain mutex would also satisfy) cannot show.
func TestAcquireAgentSetupLock_EngagesOSLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-state.json")
	store := FileAgentState(path)

	release, err := acquireAgentSetupLock(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}

	// A second, independent open of the same sidecar file gets its own open file
	// description, so its flock contends with the first exactly as another process
	// would (flock is per-description, not per-process).
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = release()
		t.Fatalf("open sidecar: %v", err)
	}
	defer func() { _ = f.Close() }()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		if err == nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		}
		_ = release()
		t.Fatalf("second flock handle while the lock is held: err = %v, want EWOULDBLOCK/EAGAIN (the OS lock must block it)", err)
	}

	// After the first holder releases, the independent handle acquires it — proving
	// the block above was the held lock, not an unopenable sidecar.
	_ = release()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("after release the second handle should acquire the lock, got %v", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func TestAcquireAgentSetupLock_RejectsSymlinkSidecar(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "other-lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-state.json")
	if err := os.Symlink(target, path+agentSetupLockSuffix); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := acquireAgentSetupLock(context.Background(), FileAgentState(path)); !errors.Is(err, ErrAgentSetupLock) {
		t.Fatalf("symlink sidecar = %v, want ErrAgentSetupLock", err)
	}
}

func TestOpenSetupLockAt_BoundsCreateUnlinkRace(t *testing.T) {
	calls := 0
	openat := func(_ int, _ string, flags int, _ uint32) (int, error) {
		calls++
		if flags&unix.O_CREAT == 0 {
			return -1, unix.ENOENT
		}
		return -1, unix.EEXIST
	}

	if _, err := openSetupLockAtWith(0, "agent-state.lock", openat); err == nil || !strings.Contains(err.Error(), "16 open attempts") {
		t.Fatalf("adversarial create/unlink race error = %v, want bounded-attempt context", err)
	}
	if want := maxSetupLockOpenAttempts * 2; calls != want {
		t.Fatalf("openat calls = %d, want bounded %d", calls, want)
	}
}
