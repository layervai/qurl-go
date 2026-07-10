//go:build !unix

package qurl

import (
	"context"
	"errors"
	"os"
)

// errFlockUnsupported reports that advisory file locking is not implemented on
// this platform (for example Windows, which would need LockFileEx). The
// concurrent-setup lock is advisory and best-effort, so acquireAgentSetupLock
// treats this as "no lock taken" and proceeds — callers keep the documented
// "one setup at a time" contract on these platforms.
var errFlockUnsupported = errors.New("qurl: advisory file lock unsupported on this platform")

// lockFileExclusive is the no-op fallback on platforms without a stdlib flock.
// It never acquires a lock; the caller falls back to the documented single-flight
// contract.
func lockFileExclusive(_ context.Context, _ string) (*os.File, error) {
	return nil, errFlockUnsupported
}
