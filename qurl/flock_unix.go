//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// flockRetryInterval bounds cancellation latency while another process owns
	// the mandatory setup lock.
	flockRetryInterval = 25 * time.Millisecond
	// maxSetupLockOpenAttempts bounds an adversarial create/unlink race.
	maxSetupLockOpenAttempts = 16
)

type openatFunc func(int, string, int, uint32) (int, error)

// openSetupLockAtWith is the injected syscall seam for the bounded create/open
// race test. Production locking uses the equivalent retained-directory method
// on pinnedStateDirImpl.
func openSetupLockAtWith(dirFD int, name string, openat openatFunc) (int, error) {
	for range maxSetupLockOpenAttempts {
		fd, err := openat(dirFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, err
		}
		fd, err = openat(dirFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
		if err == nil {
			return fd, nil
		}
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return -1, err
	}
	return -1, fmt.Errorf("setup lock file changed during %d open attempts", maxSetupLockOpenAttempts)
}
