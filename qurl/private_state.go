package qurl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxPrivateStateBytes = 64 << 10

type privateStateDirMode uint8

const (
	privateStateDirCompatible privateStateDirMode = iota
	privateStateDirExact0700
)

func readPrivateStateFile(path, label string, notFound, invalidConfig, insecurePermissions error) ([]byte, error) {
	return readPrivateStateFileBounded(path, label, maxPrivateStateBytes, privateStateDirCompatible, notFound, invalidConfig, insecurePermissions)
}

func readPrivateStateFileBounded(path, label string, maxBytes int, dirMode privateStateDirMode, notFound, invalidConfig, insecurePermissions error) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: %s path must not be empty", invalidConfig, label)
	}

	initialInfo, err := statPrivateStateFile(path, label, dirMode, notFound, invalidConfig, insecurePermissions)
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
	latestInfo, err := statPrivateStateFile(path, label, dirMode, notFound, invalidConfig, insecurePermissions)
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

type atomicTempFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type privateStateFileOps struct {
	mkdirAll   func(string, os.FileMode) error
	createTemp func(string, string) (atomicTempFile, error)
	rename     func(string, string) error
	remove     func(string) error
	syncDir    func(string, string) error
}

var defaultPrivateStateFileOps = privateStateFileOps{
	mkdirAll: os.MkdirAll,
	createTemp: func(dir, pattern string) (atomicTempFile, error) {
		return os.CreateTemp(dir, pattern)
	},
	rename:  os.Rename,
	remove:  os.Remove,
	syncDir: syncPrivateStateDir,
}

func writePrivateStateFileAtomic(ctx context.Context, path, label, tempPattern string, raw []byte, ops privateStateFileOps) error {
	if err := validateContext(ctx, ErrInvalidBootstrapConfig); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ops.mkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("qurl: create %s dir: %w", label, err)
	}
	if err := validateAgentStateDir(dir, label, ErrInvalidBootstrapConfig, ErrInsecureAgentStatePermissions); err != nil {
		return err
	}
	tmp, err := ops.createTemp(dir, tempPattern)
	if err != nil {
		return fmt.Errorf("qurl: create temp %s: %w", label, err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = ops.remove(tmpName)
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: write temp %s: %w", label, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: chmod temp %s: %w", label, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("qurl: sync temp %s: %w", label, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("qurl: close temp %s: %w", label, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.rename(tmpName, path); err != nil {
		return fmt.Errorf("qurl: replace %s: %w", label, err)
	}
	// Rename has already committed the new visible state. A following directory
	// sync error reports durability uncertainty; it cannot safely roll back the
	// replacement, and a normal retry/load recovers from the committed file.
	if err := ops.syncDir(dir, label); err != nil {
		return err
	}
	return nil
}

func statPrivateStateFile(path, label string, dirMode privateStateDirMode, notFound, invalidConfig, insecurePermissions error) (os.FileInfo, error) {
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
	validateDir := validatePrivateStateDir
	if dirMode == privateStateDirExact0700 {
		validateDir = validateAgentStateDir
	}
	if err := validateDir(filepath.Dir(path), label, invalidConfig, insecurePermissions); err != nil {
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

func validateAgentStateDir(dir, label string, invalidConfig, insecurePermissions error) error {
	info, err := statPrivateStateDir(dir, label, invalidConfig, insecurePermissions)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: %s dir has mode %o, want 0700", insecurePermissions, dir, info.Mode().Perm())
	}
	return nil
}

func syncPrivateStateDir(dir, label string) error {
	root := filepath.Dir(dir)
	name := filepath.Base(dir)
	if root == dir {
		name = "."
	}
	file, err := os.OpenInRoot(root, name)
	if err != nil {
		return fmt.Errorf("qurl: open %s dir for sync: %w", label, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("qurl: sync %s dir: %w", label, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("qurl: close %s dir: %w", label, err)
	}
	return nil
}
