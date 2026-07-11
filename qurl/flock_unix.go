//go:build unix

package qurl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// flockRetryInterval is how often a blocked acquire re-checks the context while
// waiting for the mandatory lock. The lock is only contended when a second
// concurrent setup is mid-flight against the same FileAgentState, so this is a
// short poll, not a hot loop.
const (
	flockRetryInterval = 25 * time.Millisecond
	// Bound an adversarial create/unlink race so setup fails closed instead of
	// spinning forever while the sidecar name is unstable.
	maxSetupLockOpenAttempts = 16
)

type openatFunc func(int, string, int, uint32) (int, error)

// lockFileExclusive takes an exclusive flock on lockPath (a sidecar
// file beside the agent-state file, created 0600), creating it if absent. It
// polls with LOCK_NB so a wait honors ctx cancellation rather than blocking in
// the syscall forever. It returns a held setupLock — Close releases it — or an
// error if the lockfile cannot be opened or ctx is done before acquisition.
func lockFileExclusive(ctx context.Context, lockPath string) (setupLock, error) {
	// Create the state directory before opening the sidecar,
	// mirroring SaveAgentState's os.MkdirAll. On the very first registration the
	// state dir does not exist yet, and acquisition runs before SaveAgentState can
	// create it; without this the relative open below would fail with ENOENT.
	// Failure is fatal because setup must not proceed unlocked.
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := validateAgentStateDir(dir, "agent setup lock", ErrAgentSetupLock, ErrInsecureAgentStatePermissions); err != nil {
		return nil, err
	}
	// Open relative to a held, non-symlink directory descriptor and apply
	// O_NOFOLLOW to the final component. This protects the actual descriptor from
	// an Lstat/Open pathname-swap race rather than merely checking the path before
	// an ordinary OpenFile that would still follow a replacement symlink.
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open setup lock directory: %w", err)
	}
	defer func() { _ = unix.Close(dirFD) }()
	fd, err := openSetupLockAt(dirFD, filepath.Base(lockPath))
	if err != nil {
		return nil, fmt.Errorf("open setup lock file: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create agent setup lock file handle")
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = f.Close()
		return nil, errors.New("opened agent setup lock must be a regular 0600 file")
	}
	// Reuse a single retry timer across poll iterations rather than allocating a
	// fresh time.After every ~25ms: when the lock is held across a full enrollment
	// round-trip the poll can spin many times, and a per-iteration timer+channel
	// churns needlessly. The timer is created lazily on first contention so the
	// common uncontended acquire stays allocation-free.
	var retry *time.Timer
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	for {
		// Check before every attempt, including the uncontended fast path.
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			// A non-contention error (e.g. the platform refuses flock on this fd):
			// fail closed rather than spin. EWOULDBLOCK and EAGAIN are
			// the same errno on Linux/BSD today; match both via errors.Is so a future
			// platform split keeps the contention path intact.
			_ = f.Close()
			return nil, err
		}
		if retry == nil {
			retry = time.NewTimer(flockRetryInterval)
		} else {
			retry.Reset(flockRetryInterval)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-retry.C:
		}
	}
}

func openSetupLockAt(dirFD int, name string) (int, error) {
	return openSetupLockAtWith(dirFD, name, unix.Openat)
}

func openSetupLockAtWith(dirFD int, name string, openat openatFunc) (int, error) {
	for range maxSetupLockOpenAttempts {
		// Existing-file path: O_NOFOLLOW binds the check to the descriptor actually
		// opened, so a symlink swap fails with ELOOP.
		fd, err := openat(dirFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, err
		}

		// Creation path: O_CREAT|O_EXCL itself refuses an existing symlink and any
		// competing create. Darwin does not reliably support O_NOFOLLOW combined
		// with O_CREAT, so exclusivity supplies the no-follow guarantee here.
		fd, err = openat(dirFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return fd, nil
		}
		if errors.Is(err, unix.EEXIST) {
			continue // another process created it; reopen through O_NOFOLLOW
		}
		return -1, err
	}
	return -1, fmt.Errorf("setup lock file changed during %d open attempts", maxSetupLockOpenAttempts)
}
