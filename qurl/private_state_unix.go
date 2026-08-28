//go:build !windows

package qurl

import (
	"fmt"
	"os"
)

func validatePrivateStateFilePermissions(path, label string, info os.FileInfo, insecurePermissions error) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %o, want 0600 or stricter", insecurePermissions, path, info.Mode().Perm())
	}
	return nil
}

// statPrivateStateDir validates the immediate state directory and returns the
// same FileInfo so callers that enforce a stricter mode do not need a second
// Lstat.
func statPrivateStateDir(dir, label string, invalidConfig, insecurePermissions error) (os.FileInfo, error) {
	// This validates the immediate state directory; deployment/bootstrap is
	// responsible for placing it under trusted ancestors such as /var/lib/layerv.
	info, err := os.Lstat(dir) //nolint:gosec // caller-selected state directory is intentionally Lstat'd to reject symlinks
	if err != nil {
		return nil, fmt.Errorf("qurl: stat %s dir: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s dir must not be a symlink", invalidConfig, label)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s dir must be a directory", invalidConfig, label)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s dir has mode %o, want no group/other write", insecurePermissions, dir, info.Mode().Perm())
	}
	return info, nil
}

func validatePrivateStateDir(dir, label string, invalidConfig, insecurePermissions error) error {
	_, err := statPrivateStateDir(dir, label, invalidConfig, insecurePermissions)
	return err
}
