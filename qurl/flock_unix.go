//go:build unix

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	// Best-effort: create the state directory before opening the sidecar,
	// mirroring SaveAgentState's os.MkdirAll. On the very first registration the
	// state dir does not exist yet, and the acquire runs BEFORE any SaveAgentState
	// creates it; without this the OpenFile below would fail ENOENT and the lock
	// would silently no-op, letting two concurrent first-runs each mint an
	// identity and race the save (issue #48). The MkdirAll error is deliberately
	// ignored — the OpenFile result still drives lock-vs-no-op, and a genuinely
	// unwritable dir just falls back to unserialized setup.
	_ = os.MkdirAll(filepath.Dir(lockPath), 0o700)
	// lockPath is the caller's own agent-state path plus a fixed ".lock" suffix,
	// not attacker-controlled input; the sidecar is created 0600 like the state
	// file it guards. The plain open (no O_NOFOLLOW / dir-mode hardening like the
	// state file's SaveAgentState path) is acceptable here: the sidecar is an
	// empty 0600 file that never holds a secret, and the lock is best-effort, so a
	// swapped or symlinked lockfile can only weaken serialization, not expose the
	// credential.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: lockPath derives from the caller-supplied FileAgentState path
	if err != nil {
		return nil, err
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
		// The ctx check is best-effort at loop entry: an UNCONTENDED lock is still
		// acquired even if ctx was already canceled, since ctx is only re-checked
		// between retries, not ahead of the first attempt. That is acceptable — the
		// run's subsequent network calls fail on the canceled ctx anyway, and the
		// lock releases via the returned file's Close (deferred in
		// acquireAgentSetupLock).
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
			// give up advisory locking rather than spin. EWOULDBLOCK and EAGAIN are
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
