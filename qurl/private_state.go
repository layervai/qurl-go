package qurl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readPrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: %s path must not be empty", invalidConfig, label)
	}

	initialInfo, err := statPrivateStateFile(path, label, notFound, invalidConfig, insecurePermissions)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenInRoot(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, notFound
		}
		return nil, fmt.Errorf("qurl: open %s: %w", label, err)
	}
	defer func() {
		_ = file.Close()
	}()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("qurl: stat opened %s: %w", label, err)
	}
	latestInfo, err := statPrivateStateFile(path, label, notFound, invalidConfig, insecurePermissions)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(initialInfo, openedInfo) || !os.SameFile(latestInfo, openedInfo) {
		return nil, fmt.Errorf("%w: %s changed while opening", invalidConfig, label)
	}

	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("qurl: read %s: %w", label, err)
	}
	return raw, nil
}

func statPrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, notFound
		}
		return nil, fmt.Errorf("qurl: stat %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s file must not be a symlink", invalidConfig, label)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s file must be regular", invalidConfig, label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %o, want 0600 or stricter", insecurePermissions, path, info.Mode().Perm())
	}
	return info, nil
}
