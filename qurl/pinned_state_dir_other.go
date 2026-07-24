//go:build (!linux || android) && (!darwin || ios)

package qurl

import (
	"context"
	"errors"
)

var errPinnedStateUnsupported = errors.New("qurl: pinned local agent state is unsupported on this platform")

type pinnedStateDirHooks struct {
	syncFD func(int) error
	close  func(int) error
	rename func(int, string, int, string) error
	unlink func(int, string, int) error
}

type pinnedStateDirImpl struct {
	hooks pinnedStateDirHooks
}

func canonicalPinnedStatePath(path string) string { return path }

func openPinnedStateDir(_ string, _ string, _ pinnedStateDirOpenMode) (*pinnedStateDirImpl, error) {
	// Fail before creating a directory, lock, temp, or state file. Windows needs
	// a real CreateFile/LockFileEx/ACL/FlushFileBuffers implementation rather than
	// a pathname approximation; other platforms need equivalent reviewed support.
	return nil, errors.Join(ErrAgentStateContinuity, errPinnedStateUnsupported)
}

func (d *pinnedStateDirImpl) close() error { return nil }

func (d *pinnedStateDirImpl) validateInitialEntry(_, _ string) error {
	return errPinnedStateUnsupported
}

func (d *pinnedStateDirImpl) validateContinuity() error { return errPinnedStateUnsupported }

func (d *pinnedStateDirImpl) ownsSetupLock(*pinnedSetupLockToken) bool { return false }

func (d *pinnedStateDirImpl) readFile(_ string, _ string, _ int, _ error) ([]byte, error) {
	return nil, errPinnedStateUnsupported
}

func (d *pinnedStateDirImpl) writeFileAtomic(_ context.Context, _ *pinnedSetupLockToken, _, _, _ string, _ []byte) error {
	return errPinnedStateUnsupported
}

func (d *pinnedStateDir) lock(_ context.Context, _ string) (setupLock, error) {
	return nil, errPinnedStateUnsupported
}

func (d *pinnedStateDir) lockWithImpl(_ context.Context, _ string, _ *pinnedStateDirImpl) (setupLock, error) {
	return nil, errPinnedStateUnsupported
}
