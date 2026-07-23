//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const pinnedOpenAttempts = 32

type pinnedStateDirHooks struct {
	syncFD func(int) error
	close  func(int) error
	rename func(int, string, int, string) error
	unlink func(int, string, int) error
}

var defaultPinnedStateDirHooks = pinnedStateDirHooks{
	syncFD: unix.Fsync,
	close:  unix.Close,
	rename: unix.Renameat,
	unlink: unix.Unlinkat,
}

func canonicalPinnedStatePath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	// Darwin exposes these three immutable, root-owned compatibility aliases at
	// the filesystem root. Normalize them before component traversal so the
	// retained path itself contains no symlink component. No caller-controlled
	// or nested symlink receives this exception.
	for _, alias := range []string{"/var", "/tmp", "/etc"} {
		if path == alias || strings.HasPrefix(path, alias+"/") {
			return "/private" + path
		}
	}
	return path
}

type pinnedStateDirImpl struct {
	mu              sync.Mutex
	fd              int
	path            string
	stat            unix.Stat_t
	hooks           pinnedStateDirHooks
	activeLockFD    int
	activeLockName  string
	activeLockToken *pinnedSetupLockToken
	activeEntries   map[string]pinnedFileIdentity
}

type pinnedFileIdentity struct {
	dev    string
	ino    uint64
	exists bool
}

func openPinnedStateDir(path, label string) (*pinnedStateDirImpl, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s directory must resolve to an absolute path", ErrInvalidBootstrapConfig, label)
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open filesystem root: %w", ErrAgentStateContinuity, err)
	}
	currentFD := rootFD
	rootOpen := true
	closeCurrent := false
	defer func() {
		if closeCurrent {
			_ = unix.Close(currentFD)
		}
		if rootOpen {
			_ = unix.Close(rootFD)
		}
	}()
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return nil, fmt.Errorf("%w: stat filesystem root: %w", ErrAgentStateContinuity, err)
	}
	if err := validateTrustedAncestorStat(&rootStat, "filesystem root"); err != nil {
		return nil, err
	}

	clean := filepath.Clean(path)
	components := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	if clean == string(filepath.Separator) {
		components = nil
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("%w: invalid %s directory component", ErrInvalidBootstrapConfig, label)
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		created := false
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(currentFD, component, 0o700); err != nil {
				if !errors.Is(err, unix.EEXIST) {
					return nil, fmt.Errorf("%w: create %s directory component: %w", ErrAgentStateContinuity, label, err)
				}
			} else {
				created = true
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			return nil, fmt.Errorf("%w: open %s directory component without following links: %w", ErrAgentStateContinuity, label, openErr)
		}
		if created {
			if err := unix.Fchmod(nextFD, 0o700); err != nil {
				_ = unix.Close(nextFD)
				return nil, fmt.Errorf("%w: chmod created %s directory component: %w", ErrAgentStateContinuity, label, err)
			}
		}
		var nextStat unix.Stat_t
		if err := unix.Fstat(nextFD, &nextStat); err != nil {
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("%w: stat %s directory component: %w", ErrAgentStateContinuity, label, err)
		}
		if err := validateTrustedAncestorStat(&nextStat, label+" directory component"); err != nil {
			_ = unix.Close(nextFD)
			return nil, err
		}
		// Persist the created directory's own mode metadata before publishing its
		// edge in the parent. Repeating this sync for existing components closes a
		// retry after a prior process completed mkdir/chmod but lost the sync.
		if err := unix.Fsync(nextFD); err != nil {
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("%w: sync %s directory component: %w", ErrAgentStateContinuity, label, err)
		}
		// Sync every traversed parent edge, not only the process that observed a
		// successful mkdir. If a previous process crashed after mkdir but before
		// fsync, its retry still closes the durability gap.
		if err := defaultPinnedStateDirHooks.syncFD(currentFD); err != nil {
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("%w: sync %s parent edge: %w", ErrAgentStateContinuity, label, err)
		}
		if currentFD != rootFD {
			_ = unix.Close(currentFD)
		}
		currentFD = nextFD
		closeCurrent = true
	}
	if currentFD != rootFD {
		_ = unix.Close(rootFD)
		rootOpen = false
	}
	var stat unix.Stat_t
	if err := unix.Fstat(currentFD, &stat); err != nil {
		return nil, fmt.Errorf("%w: stat pinned %s directory: %w", ErrAgentStateContinuity, label, err)
	}
	if err := validatePinnedDirStat(&stat); err != nil {
		return nil, err
	}
	rootOpen = false
	closeCurrent = false
	return &pinnedStateDirImpl{
		fd: currentFD, path: clean, stat: stat,
		hooks:        defaultPinnedStateDirHooks,
		activeLockFD: -1,
	}, nil
}

func validatePinnedDirStat(stat *unix.Stat_t) error {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: pinned state path is not a directory", ErrAgentStateContinuity)
	}
	if stat.Mode&0o777 != 0o700 {
		return fmt.Errorf("%w: %w: state directory mode is %03o, want 700", ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, stat.Mode&0o777)
	}
	if int64(stat.Uid) != int64(unix.Geteuid()) {
		return fmt.Errorf("%w: state directory is not owned by the effective user", ErrAgentStateContinuity)
	}
	return nil
}

func validateTrustedAncestorStat(stat *unix.Stat_t, label string) error {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", ErrAgentStateContinuity, label)
	}
	uid := int64(stat.Uid)
	euid := int64(unix.Geteuid())
	if uid != 0 && uid != euid {
		return fmt.Errorf("%w: %s is not owned by root or the effective user", ErrAgentStateContinuity, label)
	}
	if stat.Mode&0o022 == 0 {
		return nil
	}
	// Root-owned sticky directories such as /tmp and Darwin's /private/tmp are
	// deliberate shared roots: sticky rename/unlink rules protect a root/euid-
	// owned child entry from other users. No other writable ancestor is trusted.
	if uid == 0 && stat.Mode&unix.S_ISVTX != 0 {
		return nil
	}
	return fmt.Errorf("%w: %w: %s mode is %04o; writable ancestors must be root-owned and sticky", ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label, stat.Mode&0o7777)
}

func (d *pinnedStateDirImpl) close() error {
	return d.hooks.close(d.fd)
}

func (d *pinnedStateDirImpl) validateInitialEntry(name, label string) error {
	_, err := d.captureEntry(name, label)
	return err
}

func (d *pinnedStateDirImpl) validateContinuity() error {
	var held unix.Stat_t
	if err := unix.Fstat(d.fd, &held); err != nil {
		return fmt.Errorf("%w: stat retained directory: %w", ErrAgentStateContinuity, err)
	}
	if err := validatePinnedDirStat(&held); err != nil {
		return err
	}
	if held.Dev != d.stat.Dev || held.Ino != d.stat.Ino {
		return fmt.Errorf("%w: retained directory identity changed", ErrAgentStateContinuity)
	}
	reopened, err := openExistingDirNoFollow(d.path)
	if err != nil {
		return fmt.Errorf("%w: reopen state directory: %w", ErrAgentStateContinuity, err)
	}
	defer func() { _ = unix.Close(reopened) }()
	var current unix.Stat_t
	if err := unix.Fstat(reopened, &current); err != nil {
		return fmt.Errorf("%w: stat reopened state directory: %w", ErrAgentStateContinuity, err)
	}
	if current.Dev != d.stat.Dev || current.Ino != d.stat.Ino {
		return fmt.Errorf("%w: state directory namespace was replaced", ErrAgentStateContinuity)
	}
	if err := validatePinnedDirStat(&current); err != nil {
		return err
	}
	d.mu.Lock()
	lockFD, lockName := d.activeLockFD, d.activeLockName
	activeEntries := make(map[string]pinnedFileIdentity, len(d.activeEntries))
	for name, identity := range d.activeEntries {
		activeEntries[name] = identity
	}
	d.mu.Unlock()
	if lockFD >= 0 {
		if err := d.validateOpenEntry(lockFD, lockName, "active agent setup lock"); err != nil {
			return err
		}
		for name, expected := range activeEntries {
			current, err := d.captureEntry(name, "active agent state")
			if err != nil {
				return err
			}
			if current != expected {
				return fmt.Errorf("%w: state entry changed while the setup lock was held", ErrAgentStateContinuity)
			}
		}
	}
	return nil
}

func openExistingDirNoFollow(path string) (int, error) {
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	currentFD := rootFD
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		_ = unix.Close(rootFD)
		return -1, err
	}
	if err := validateTrustedAncestorStat(&rootStat, "filesystem root"); err != nil {
		_ = unix.Close(rootFD)
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	if filepath.Clean(path) == string(filepath.Separator) {
		components = nil
	}
	for _, component := range components {
		nextFD, err := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			if currentFD != rootFD {
				_ = unix.Close(currentFD)
			}
			_ = unix.Close(rootFD)
			return -1, err
		}
		var nextStat unix.Stat_t
		if err := unix.Fstat(nextFD, &nextStat); err != nil {
			_ = unix.Close(nextFD)
			if currentFD != rootFD {
				_ = unix.Close(currentFD)
			}
			_ = unix.Close(rootFD)
			return -1, err
		}
		if err := validateTrustedAncestorStat(&nextStat, "state directory ancestor"); err != nil {
			_ = unix.Close(nextFD)
			if currentFD != rootFD {
				_ = unix.Close(currentFD)
			}
			_ = unix.Close(rootFD)
			return -1, err
		}
		if currentFD != rootFD {
			_ = unix.Close(currentFD)
		}
		currentFD = nextFD
	}
	if currentFD != rootFD {
		_ = unix.Close(rootFD)
	}
	return currentFD, nil
}

func validatePinnedRegularStat(stat *unix.Stat_t, label string) error {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s must be a regular file", ErrAgentStateContinuity, label)
	}
	if stat.Mode&0o777 != 0o600 {
		return fmt.Errorf("%w: %w: %s mode is %03o, want 600", ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label, stat.Mode&0o777)
	}
	if int64(stat.Uid) != int64(unix.Geteuid()) {
		return fmt.Errorf("%w: %s is not owned by the effective user", ErrAgentStateContinuity, label)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("%w: %s link count is %d, want 1", ErrAgentStateContinuity, label, stat.Nlink)
	}
	return nil
}

func (d *pinnedStateDirImpl) validateOpenEntry(fd int, name, label string) error {
	var opened, entry unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fmt.Errorf("%w: stat opened %s: %w", ErrAgentStateContinuity, label, err)
	}
	if err := validatePinnedRegularStat(&opened, label); err != nil {
		return err
	}
	if err := unix.Fstatat(d.fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("%w: stat %s directory entry: %w", ErrAgentStateContinuity, label, err)
	}
	if err := validatePinnedRegularStat(&entry, label); err != nil {
		return err
	}
	if opened.Dev != entry.Dev || opened.Ino != entry.Ino {
		return fmt.Errorf("%w: opened %s no longer matches its directory entry", ErrAgentStateContinuity, label)
	}
	return nil
}

func (d *pinnedStateDirImpl) readFile(name, label string, maxBytes int, notFound error) ([]byte, error) {
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			if err := d.recordActiveEntry(name, pinnedFileIdentity{}); err != nil {
				return nil, err
			}
			return nil, notFound
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.Join(ErrInvalidAgentState, fmt.Errorf("%w: %s entry is a symlink", ErrAgentStateContinuity, label))
		}
		return nil, fmt.Errorf("qurl: open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), label)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("qurl: create %s file handle", label)
	}
	defer func() { _ = file.Close() }()
	if err := d.validateOpenEntry(fd, name, label); err != nil {
		return nil, err
	}
	identity, err := identityForFD(fd)
	if err != nil {
		return nil, fmt.Errorf("%w: capture opened %s identity: %w", ErrAgentStateContinuity, label, err)
	}
	if err := d.recordActiveEntry(name, identity); err != nil {
		return nil, err
	}
	raw, err := readCappedBody(file, maxBytes, label)
	if err != nil {
		var tooLarge *inputExceedsCapError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidAgentState, err)
		}
		return nil, fmt.Errorf("qurl: %w", err)
	}
	if err := d.validateOpenEntry(fd, name, label); err != nil {
		return nil, err
	}
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (d *pinnedStateDirImpl) writeFileAtomic(ctx context.Context, token *pinnedSetupLockToken, name, label, tempPrefix string, raw []byte) (resultErr error) {
	if !d.ownsSetupLock(token) {
		return fmt.Errorf("%w: %s write requires the active setup lock", ErrAgentSetupLock, label)
	}
	if err := d.validateContinuity(); err != nil {
		return err
	}
	baseline, err := d.captureEntry(name, label)
	if err != nil {
		return err
	}
	if err := d.checkActiveEntry(name, baseline); err != nil {
		return err
	}
	tempName, fd, err := d.createExclusiveTemp(tempPrefix, label)
	if err != nil {
		return err
	}
	tempExists := true
	file := os.NewFile(uintptr(fd), tempName)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(d.fd, tempName, 0)
		return fmt.Errorf("qurl: create temp %s handle", label)
	}
	defer func() {
		if tempExists {
			unlinkErr := d.hooks.unlink(d.fd, tempName, 0)
			if unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT) {
				resultErr = errors.Join(resultErr, fmt.Errorf("qurl: remove temp %s: %w", label, unlinkErr))
			}
			// Persist cleanup of a credential-bearing temp entry. Even an
			// ambiguous unlink error receives a directory sync: the hook or
			// filesystem may have removed the name before returning the error.
			if !errors.Is(unlinkErr, unix.ENOENT) {
				if syncErr := d.hooks.syncFD(d.fd); syncErr != nil {
					resultErr = errors.Join(resultErr, fmt.Errorf("qurl: sync temp %s cleanup: %w", label, syncErr))
				}
			}
		}
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("qurl: close temp %s: %w", label, err))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("qurl: chmod temp %s: %w", label, err)
	}
	if err := d.validateOpenEntry(fd, tempName, "temp "+label); err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("qurl: write temp %s: %w", label, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("qurl: sync temp %s: %w", label, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The last check before the visibility commit binds both the retained
	// namespace and the exact temp inode that Renameat will move.
	if err := d.validateContinuity(); err != nil {
		return err
	}
	if err := d.validateOpenEntry(fd, tempName, "temp "+label); err != nil {
		return err
	}
	current, err := d.captureEntry(name, label)
	if err != nil {
		return err
	}
	if current != baseline {
		return fmt.Errorf("%w: %s entry changed before commit", ErrAgentStateContinuity, label)
	}
	if err := d.checkActiveEntry(name, current); err != nil {
		return err
	}
	if err := d.hooks.rename(d.fd, tempName, d.fd, name); err != nil {
		return fmt.Errorf("qurl: replace %s: %w", label, err)
	}
	tempExists = false
	if err := d.hooks.syncFD(d.fd); err != nil {
		return fmt.Errorf("qurl: sync %s directory: %w", label, err)
	}
	// Commit success is not reported unless the path still resolves to the pinned
	// directory and the visible entry is the exact inode just synced.
	if err := d.validateOpenEntry(fd, name, label); err != nil {
		return err
	}
	committed, err := identityForFD(fd)
	if err != nil {
		return fmt.Errorf("%w: capture committed %s identity: %w", ErrAgentStateContinuity, label, err)
	}
	d.updateActiveEntry(name, committed)
	if err := d.validateContinuity(); err != nil {
		return err
	}
	return nil
}

func (d *pinnedStateDirImpl) createExclusiveTemp(prefix, label string) (string, int, error) {
	for range pinnedOpenAttempts {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", -1, fmt.Errorf("qurl: generate temp %s name: %w", label, err)
		}
		name := prefix + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(d.fd, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, fmt.Errorf("qurl: create temp %s: %w", label, err)
		}
	}
	return "", -1, fmt.Errorf("qurl: create temp %s after %d attempts", label, pinnedOpenAttempts)
}

func identityForFD(fd int) (pinnedFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return pinnedFileIdentity{}, err
	}
	return pinnedFileIdentity{dev: fmt.Sprint(stat.Dev), ino: stat.Ino, exists: true}, nil
}

func (d *pinnedStateDirImpl) captureEntry(name, label string) (pinnedFileIdentity, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return pinnedFileIdentity{}, nil
		}
		if errors.Is(err, unix.ELOOP) {
			return pinnedFileIdentity{}, errors.Join(ErrInvalidAgentState, fmt.Errorf("%w: %s entry is a symlink", ErrAgentStateContinuity, label))
		}
		return pinnedFileIdentity{}, fmt.Errorf("%w: open existing %s: %w", ErrAgentStateContinuity, label, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := d.validateOpenEntry(fd, name, label); err != nil {
		return pinnedFileIdentity{}, err
	}
	return identityForFD(fd)
}

func (d *pinnedStateDirImpl) recordActiveEntry(name string, identity pinnedFileIdentity) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeLockFD < 0 {
		return nil
	}
	if previous, ok := d.activeEntries[name]; ok && previous != identity {
		return fmt.Errorf("%w: state entry changed while the setup lock was held", ErrAgentStateContinuity)
	}
	d.activeEntries[name] = identity
	return nil
}

func (d *pinnedStateDirImpl) checkActiveEntry(name string, identity pinnedFileIdentity) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeLockFD < 0 {
		return nil
	}
	if previous, ok := d.activeEntries[name]; ok && previous != identity {
		return fmt.Errorf("%w: state entry changed while the setup lock was held", ErrAgentStateContinuity)
	}
	if d.activeEntries == nil {
		d.activeEntries = make(map[string]pinnedFileIdentity)
	}
	d.activeEntries[name] = identity
	return nil
}

func (d *pinnedStateDirImpl) updateActiveEntry(name string, identity pinnedFileIdentity) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeLockFD < 0 {
		return
	}
	d.activeEntries[name] = identity
}

type pinnedSetupLock struct {
	file  *os.File
	dir   *pinnedStateDirImpl
	name  string
	lease *pinnedStateDirLease
	token *pinnedSetupLockToken
}

func (l *pinnedSetupLock) bindStore(store AgentStateStore) AgentStateStore {
	if decorator, ok := store.(agentStateStoreDecorator); ok {
		bound := l.bindStore(decorator.decoratedAgentStateStore())
		return decorator.withDecoratedAgentStateStore(bound)
	}
	retained, ok := store.(*retainedLocalAgentStateStore)
	if !ok || l == nil || l.token == nil {
		return store
	}
	return retained.withSetup(l.token)
}

func (d *pinnedStateDirImpl) ownsSetupLock(token *pinnedSetupLockToken) bool {
	if token == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activeLockFD >= 0 && d.activeLockToken == token
}

func (d *pinnedStateDir) lock(ctx context.Context, name string) (setupLock, error) {
	lease, err := d.retain()
	if err != nil {
		return nil, err
	}
	impl := lease.dir.impl
	lock, err := impl.acquireLock(ctx, name, lease)
	if err != nil {
		_ = lease.release()
		return nil, err
	}
	return lock, nil
}

func (d *pinnedStateDir) lockWithImpl(ctx context.Context, name string, impl *pinnedStateDirImpl) (setupLock, error) {
	if d == nil || impl == nil {
		return nil, fmt.Errorf("%w: retained state directory is nil", ErrAgentStateContinuity)
	}
	d.mu.Lock()
	same := d.impl == impl && !d.closed
	d.mu.Unlock()
	if !same {
		return nil, fmt.Errorf("%w: retained state directory changed", ErrAgentStateContinuity)
	}
	// The retained operation owns the directory reference. The setup lock must
	// not retain a second one, or closing the outer operation would deadlock on
	// a reference whose release is sequenced after lock release.
	return impl.acquireLock(ctx, name, nil)
}

func (d *pinnedStateDirImpl) acquireLock(ctx context.Context, name string, lease *pinnedStateDirLease) (setupLock, error) {
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	fd, created, err := d.openLock(name)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create agent setup lock file handle")
	}
	fail := func(err error) error {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close rejected agent setup lock: %w", closeErr))
		}
		return err
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, fail(err)
		}
	}
	if err := d.validateOpenEntry(fd, name, "agent setup lock"); err != nil {
		return nil, fail(err)
	}
	// Sync every open, including a retry that observes a lock created before a
	// previous process could durably publish its parent entry.
	if err := file.Sync(); err != nil {
		return nil, fail(fmt.Errorf("sync agent setup lock: %w", err))
	}
	if err := d.hooks.syncFD(d.fd); err != nil {
		return nil, fail(fmt.Errorf("sync agent setup lock directory: %w", err))
	}
	var retry *time.Timer
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, fail(err)
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			if err := d.validateOpenEntry(fd, name, "agent setup lock"); err != nil {
				return nil, fail(err)
			}
			if err := d.validateContinuity(); err != nil {
				return nil, fail(err)
			}
			d.mu.Lock()
			if d.activeLockFD >= 0 {
				d.mu.Unlock()
				return nil, fail(fmt.Errorf("%w: state store already owns an active setup lock", ErrAgentSetupLock))
			}
			token := &pinnedSetupLockToken{impl: d}
			d.activeLockFD = fd
			d.activeLockName = name
			d.activeLockToken = token
			d.activeEntries = make(map[string]pinnedFileIdentity)
			d.mu.Unlock()
			return &pinnedSetupLock{file: file, dir: d, name: name, lease: lease, token: token}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fail(err)
		}
		if retry == nil {
			retry = time.NewTimer(flockRetryInterval)
		} else {
			retry.Reset(flockRetryInterval)
		}
		select {
		case <-ctx.Done():
			return nil, fail(ctx.Err())
		case <-retry.C:
		}
	}
}

func (d *pinnedStateDirImpl) openLock(name string) (int, bool, error) {
	for range maxSetupLockOpenAttempts {
		fd, err := unix.Openat(d.fd, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			return fd, false, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, false, fmt.Errorf("open setup lock file: %w", err)
		}
		fd, err = unix.Openat(d.fd, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL|unix.O_NONBLOCK, 0o600)
		if err == nil {
			return fd, true, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return -1, false, fmt.Errorf("create setup lock file: %w", err)
		}
	}
	return -1, false, fmt.Errorf("setup lock file changed during %d open attempts", maxSetupLockOpenAttempts)
}

func (l *pinnedSetupLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	var result error
	if err := l.dir.validateOpenEntry(int(l.file.Fd()), l.name, "agent setup lock"); err != nil {
		result = err
	}
	if err := l.dir.validateContinuity(); err != nil {
		result = errors.Join(result, err)
	}
	l.dir.mu.Lock()
	if l.dir.activeLockFD == int(l.file.Fd()) && l.dir.activeLockName == l.name && l.dir.activeLockToken == l.token {
		l.dir.activeLockFD = -1
		l.dir.activeLockName = ""
		l.dir.activeLockToken = nil
		l.dir.activeEntries = nil
	} else {
		result = errors.Join(result, fmt.Errorf("%w: active setup lock ownership changed", ErrAgentStateContinuity))
	}
	l.dir.mu.Unlock()
	if err := l.file.Close(); err != nil {
		result = errors.Join(result, err)
	}
	l.file = nil
	if l.lease != nil {
		if err := l.lease.release(); err != nil {
			result = errors.Join(result, err)
		}
	}
	l.lease = nil
	return result
}
