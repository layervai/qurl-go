package qurl

import (
	"context"
	"strings"
)

// agentSetupLockSuffix names the sidecar advisory lockfile taken during
// first-registration setup. It sits beside the state file (state.json →
// state.json.lock) so the lock is held on a stable path while SaveAgentState
// atomically replaces the state file itself via a temp file + rename (locking the
// state file directly would fight that rename).
const agentSetupLockSuffix = ".lock"

// acquireAgentSetupLock takes an advisory, best-effort exclusive lock
// serializing concurrent first-registration setup for a single-host
// FileAgentState. It returns a release func to call when the critical section
// ends; release is always non-nil and safe to call (a no-op when no lock was
// taken).
//
// It is deliberately advisory and never fails the caller (issue #48): it engages
// ONLY for the local fileAgentStateStore — networked/shared AgentStateStore
// implementations cannot rely on flock and keep the documented "one setup at a
// time" contract — and if the lock cannot be acquired (unsupported platform,
// lockfile unopenable, or ctx canceled while waiting) it returns a no-op release
// so setup proceeds unserialized rather than turning the best-effort lock into a
// hard dependency.
func acquireAgentSetupLock(ctx context.Context, store AgentStateStore) func() {
	noop := func() {}

	fs, ok := store.(fileAgentStateStore)
	if !ok {
		return noop // not a local file store: keep the documented contract
	}
	path := strings.TrimSpace(fs.path)
	if path == "" {
		return noop
	}

	f, err := lockFileExclusive(ctx, path+agentSetupLockSuffix)
	if err != nil || f == nil {
		return noop // advisory: proceed without serialization on any failure
	}
	return func() {
		// Closing the fd releases the flock. The lockfile is intentionally left in
		// place (an empty 0600 sidecar) so the next run reuses it without a churn of
		// create/unlink races.
		_ = f.Close()
	}
}
