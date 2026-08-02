package qurl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/layervai/qurl-go/internal/cryptoutil"
)

const (
	maxCredentialStateBytes = 64 << 10
	// Both full AgentState file stores share this bounded schema-growth budget.
	maxAgentStateBytes = 1 << 20
)

func readPrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) ([]byte, error) {
	return readPrivateStateFileBounded(path, label, maxCredentialStateBytes, notFound, invalidConfig, insecurePermissions)
}

func readPrivateStateFileBounded(path, label string, maxBytes int, notFound, invalidConfig, insecurePermissions error) ([]byte, error) {
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

	raw, err := readCappedBody(file, maxBytes, label)
	if err != nil {
		// An over-cap body is malformed input, not a transient fault. Classify it
		// once with the caller's invalid-config sentinel so every private-state
		// reader exposes the same errors.Is contract.
		var tooLarge *inputExceedsCapError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w: %w", invalidConfig, err)
		}
		return nil, fmt.Errorf("qurl: %w", err)
	}
	return raw, nil
}

func statPrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) (os.FileInfo, error) {
	info, err := os.Lstat(path) //nolint:gosec // caller-selected state path is intentionally Lstat'd to reject symlinks before opening
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
	if err := validatePrivateStateDir(filepath.Dir(path), label, invalidConfig, insecurePermissions); err != nil {
		return nil, err
	}
	return info, nil
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

// wipeBytes is the qurl package's concise alias for the shared scrub primitive.
func wipeBytes(b []byte) {
	cryptoutil.Wipe(b)
}
