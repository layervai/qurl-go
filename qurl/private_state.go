package qurl

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func validatePrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: %s path must not be empty", invalidConfig, label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return notFound
		}
		return fmt.Errorf("qurl: stat %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s file must not be a symlink", invalidConfig, label)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s file must be regular", invalidConfig, label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %o, want 0600 or stricter", insecurePermissions, path, info.Mode().Perm())
	}
	return nil
}
