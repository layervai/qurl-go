//go:build !unix

package qurl

import (
	"context"
	"errors"
)

// errFlockUnsupported reports that mandatory file locking is not implemented on
// this platform (for example Windows, which would need LockFileEx). The
// local-file setup lock is mandatory, so SDK file-store registration fails
// closed on these platforms rather than risking competing identities.
var errFlockUnsupported = errors.New("qurl: mandatory file lock unsupported on this platform")

// lockFileExclusive reports the unsupported platform to the caller.
func lockFileExclusive(_ context.Context, _ string) (setupLock, error) {
	return nil, errFlockUnsupported
}
