//go:build unix

package qurl

import (
	"context"
	"os"
	"syscall"
	"time"
)

// flockRetryInterval is how often a blocked acquire re-checks the context while
// waiting for the advisory lock. The lock is only contended when a second
// concurrent setup is mid-flight against the same FileAgentState, so this is a
// short poll, not a hot loop.
const flockRetryInterval = 25 * time.Millisecond

// lockFileExclusive takes an advisory exclusive flock on lockPath (a sidecar
// file beside the agent-state file, created 0600), creating it if absent. It
// polls with LOCK_NB so a wait honors ctx cancellation rather than blocking in
// the syscall forever. It returns the held *os.File — closing it releases the
// lock and is the unlock — or an error if the lockfile cannot be opened or ctx
// is done before the lock is acquired. All failures are advisory: the caller
// proceeds without serialization rather than turning the best-effort lock into a
// hard dependency.
func lockFileExclusive(ctx context.Context, lockPath string) (*os.File, error) {
	// lockPath is the caller's own agent-state path plus a fixed ".lock" suffix,
	// not attacker-controlled input; the sidecar is created 0600 like the state
	// file it guards.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: lockPath derives from the caller-supplied FileAgentState path
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != syscall.EWOULDBLOCK {
			// A non-contention error (e.g. the platform refuses flock on this fd):
			// give up advisory locking rather than spin.
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(flockRetryInterval):
		}
	}
}
