//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPinnedAgentState_NestedDirectoryFsyncFailureRetriesDurably(t *testing.T) {
	root := secureAgentStateTestDir(t)
	stateDir := filepath.Join(root, "nested", "private")
	path := filepath.Join(stateDir, "agent-state.json")
	canonicalDir := canonicalPinnedStatePath(stateDir)
	edgeCount := len(strings.Split(strings.TrimPrefix(canonicalDir, string(filepath.Separator)), string(filepath.Separator)))
	failAt := int64(edgeCount - 1) // the edge that publishes "nested"
	sentinel := errors.New("fail first parent fsync")
	original := defaultPinnedStateDirHooks
	var calls atomic.Int64
	defaultPinnedStateDirHooks.syncFD = func(fd int) error {
		if calls.Add(1) == failAt {
			return sentinel
		}
		return unix.Fsync(fd)
	}
	t.Cleanup(func() { defaultPinnedStateDirHooks = original })

	if _, err := OpenFileAgentState(path); !errors.Is(err, sentinel) {
		t.Fatalf("first open = %v, want injected parent fsync failure", err)
	}
	if info, err := os.Lstat(filepath.Join(root, "nested")); err != nil || !info.IsDir() {
		t.Fatalf("failed open did not leave the mkdir-before-fsync edge for retry: info=%v err=%v", info, err)
	}

	defaultPinnedStateDirHooks = original
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatalf("retry open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatalf("retry save: %v", err)
	}
	reopened, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatalf("restart open: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.LoadAgentState(context.Background()); err != nil {
		t.Fatalf("restart load: %v", err)
	}
}

func TestPinnedAgentState_RejectsAncestorSymlinkWithoutMutation(t *testing.T) {
	root := secureAgentStateTestDir(t)
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "must-not-exist", "state.json")
	if _, err := OpenFileAgentState(path); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("open through ancestor symlink = %v, want ErrAgentStateContinuity", err)
	}
	if _, err := os.Lstat(filepath.Join(actual, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor mutated symlink target: %v", err)
	}
}

func TestPinnedAgentState_RejectsWritableNonStickyAncestorBeforeMutation(t *testing.T) {
	root := secureAgentStateTestDir(t)
	untrusted := filepath.Join(root, "shared")
	if err := os.Mkdir(untrusted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(untrusted, "must-not-exist", "agent.json")
	if _, err := OpenFileAgentState(path); !errors.Is(err, ErrAgentStateContinuity) || !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("open below writable non-sticky ancestor = %v, want insecure continuity failure", err)
	}
	if _, err := os.Lstat(filepath.Join(untrusted, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor mutated untrusted ancestor: %v", err)
	}
}

func TestPinnedAgentState_AncestorReplacementCannotSplitStateAndLock(t *testing.T) {
	root := secureAgentStateTestDir(t)
	ancestor := filepath.Join(root, "trusted")
	path := filepath.Join(ancestor, "state", "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	lock, err := store.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	displaced := ancestor + ".old"
	if err := os.Rename(ancestor, displaced); err != nil {
		t.Fatal(err)
	}
	replacementStateDir := filepath.Join(ancestor, "state")
	if err := os.MkdirAll(replacementStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replacementStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("continuity after ancestor replacement = %v", err)
	}
	if err := lock.Close(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("lock release after ancestor replacement = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace gained state or lock data: %v", err)
	}
}

func TestPinnedAgentState_RejectsNonRegularEntriesWithoutBlocking(t *testing.T) {
	root := secureAgentStateTestDir(t)
	statePath := filepath.Join(root, "agent.json")
	if err := unix.Mkfifo(statePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileAgentState(statePath); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("open FIFO state = %v, want continuity failure", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}

	store, err := OpenFileAgentState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := unix.Mkfifo(statePath+agentSetupLockSuffix, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.acquireSetupLock(context.Background()); !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("acquire FIFO lock = %v, want setup-lock and continuity failure", err)
	}
}

func TestPinnedAgentState_DirectoryReplacementFailsClosed(t *testing.T) {
	root := secureAgentStateTestDir(t)
	dir := filepath.Join(root, "state")
	path := filepath.Join(dir, "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	displaced := dir + ".old"
	if err := os.Rename(dir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("continuity after directory replacement = %v", err)
	}
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("save after directory replacement = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace was mutated: %v", err)
	}
}

func TestPinnedAgentState_ActiveSetupLockReplacementFailsBeforeContinuation(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	lock, err := store.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lockPath := path + agentSetupLockSuffix
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("replaced active lock continuity = %v", err)
	}
	if err := lock.Close(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("release replaced active lock = %v", err)
	}
}

func TestPinnedAgentState_ActiveSetupLockHardlinkFailsBeforeContinuation(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	lock, err := store.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path+agentSetupLockSuffix, path+agentSetupLockSuffix+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("hard-linked active lock continuity = %v", err)
	}
	if err := lock.Close(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("release hard-linked active lock = %v", err)
	}
}

func TestPinnedAgentState_RejectsStateAndTempLinkOrEntryReplacement(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	hardlink := path + ".hardlink"
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("hard-linked state load = %v, want continuity failure", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}

	tempName, tempFD, err := store.dir.impl.createExclusiveTemp(".qurl-agent-state-test-", "test state")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = unix.Close(tempFD)
		_ = unix.Unlinkat(store.dir.impl.fd, tempName, 0)
	}()
	tempLink := filepath.Join(filepath.Dir(path), tempName+".hardlink")
	if err := os.Link(filepath.Join(filepath.Dir(path), tempName), tempLink); err != nil {
		t.Fatal(err)
	}
	if err := store.dir.impl.validateOpenEntry(tempFD, tempName, "temp state"); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("hard-linked temp validation = %v", err)
	}
	if err := os.Remove(tempLink); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unlinkat(store.dir.impl.fd, tempName, 0); err != nil {
		t.Fatal(err)
	}
	replacementFD, err := unix.Openat(store.dir.impl.fd, tempName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(replacementFD)
	if err := store.dir.impl.validateOpenEntry(tempFD, tempName, "temp state"); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("replaced temp validation = %v", err)
	}
}

func TestPinnedAgentState_RejectsValidStateInodeReplacementWhileSetupLockHeld(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	state := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	lock, err := store.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if _, err := store.LoadAgentState(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("continuity after valid inode replacement = %v", err)
	}
	if err := store.SaveAgentState(context.Background(), state); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("save after valid inode replacement = %v", err)
	}
}

func TestPinnedAgentState_CloseErrorIsReportedOnce(t *testing.T) {
	store, err := OpenFileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("close failure")
	store.dir.impl.hooks.close = func(fd int) error {
		closeErr := unix.Close(fd)
		return errors.Join(sentinel, closeErr)
	}
	if err := store.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close = %v, want injected cleanup error", err)
	}
	if err := store.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("second Close = %v, want stable cleanup error", err)
	}
}

func TestPinnedAgentState_RuntimeCleanupClosesAbandonedStore(t *testing.T) {
	closed := make(chan struct{}, 1)
	func() {
		store, err := OpenFileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent.json"))
		if err != nil {
			t.Fatal(err)
		}
		store.dir.impl.hooks.close = func(fd int) error {
			select {
			case closed <- struct{}{}:
			default:
			}
			return unix.Close(fd)
		}
	}()
	waitForRuntimeCleanup(t, closed, "abandoned plaintext store")
}

func TestSealedAgentState_RuntimeCleanupClosesAbandonedStore(t *testing.T) {
	closed := make(chan struct{}, 1)
	func() {
		store, err := NewSealedFileAgentState(
			filepath.Join(secureAgentStateTestDir(t), "agent.sealed.json"),
			"test-wrapper",
			&testAgentStateKeyWrapper{},
		)
		if err != nil {
			t.Fatal(err)
		}
		store.dir.impl.hooks.close = func(fd int) error {
			select {
			case closed <- struct{}{}:
			default:
			}
			return unix.Close(fd)
		}
	}()
	waitForRuntimeCleanup(t, closed, "abandoned sealed store")
}

func TestSealedAgentState_ExplicitCloseStopsRuntimeCleanup(t *testing.T) {
	var closes atomic.Int32
	func() {
		store, err := NewSealedFileAgentState(
			filepath.Join(secureAgentStateTestDir(t), "agent.sealed.json"),
			"test-wrapper",
			&testAgentStateKeyWrapper{},
		)
		if err != nil {
			t.Fatal(err)
		}
		store.dir.impl.hooks.close = func(fd int) error {
			closes.Add(1)
			return unix.Close(fd)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	for range 3 {
		runtime.GC()
		runtime.Gosched()
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("sealed directory close calls = %d, want exactly one explicit close", got)
	}
}

func TestPinnedAgentState_RuntimeCleanupWaitsForRetainedOperation(t *testing.T) {
	closed := make(chan struct{}, 1)
	var retained AgentStateStore
	var release func() error
	func() {
		store, err := OpenFileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent.json"))
		if err != nil {
			t.Fatal(err)
		}
		store.dir.impl.hooks.close = func(fd int) error {
			select {
			case closed <- struct{}{}:
			default:
			}
			return unix.Close(fd)
		}
		retained, release, err = store.retainContinuity()
		if err != nil {
			t.Fatal(err)
		}
	}()
	for range 3 {
		runtime.GC()
		runtime.Gosched()
	}
	select {
	case <-closed:
		t.Fatal("runtime cleanup closed a store held by a retained operation")
	case <-time.After(50 * time.Millisecond):
	}
	runtime.KeepAlive(retained)
	if err := release(); err != nil {
		t.Fatal(err)
	}
	retained = nil
	waitForRuntimeCleanup(t, closed, "released retained plaintext store")
}

func TestSealedAgentState_RuntimeCleanupWaitsForRetainedOperation(t *testing.T) {
	closed := make(chan struct{}, 1)
	var retained AgentStateStore
	var release func() error
	func() {
		store, err := NewSealedFileAgentState(
			filepath.Join(secureAgentStateTestDir(t), "agent.sealed.json"),
			"test-wrapper",
			&testAgentStateKeyWrapper{},
		)
		if err != nil {
			t.Fatal(err)
		}
		store.dir.impl.hooks.close = func(fd int) error {
			select {
			case closed <- struct{}{}:
			default:
			}
			return unix.Close(fd)
		}
		retained, release, err = store.retainContinuity()
		if err != nil {
			t.Fatal(err)
		}
	}()
	for range 3 {
		runtime.GC()
		runtime.Gosched()
	}
	select {
	case <-closed:
		t.Fatal("runtime cleanup closed a sealed store held by a retained operation")
	case <-time.After(50 * time.Millisecond):
	}
	runtime.KeepAlive(retained)
	if err := release(); err != nil {
		t.Fatal(err)
	}
	retained = nil
	waitForRuntimeCleanup(t, closed, "released retained sealed store")
}

func waitForRuntimeCleanup(t *testing.T, closed <-chan struct{}, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		runtime.Gosched()
		select {
		case <-closed:
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime cleanup did not close %s", label)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPinnedAgentState_CloseWaitsForRetainedLifecycleReference(t *testing.T) {
	store, err := OpenFileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := store.retainContinuity()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- store.Close() }()
	go func() { closed <- store.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while lifecycle reference was retained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not finish after lifecycle release")
		}
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("closed store validation = %v", err)
	}
}

func TestPinnedAgentState_AtomicFailureReportsCleanupError(t *testing.T) {
	store, err := OpenFileAgentState(filepath.Join(secureAgentStateTestDir(t), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	operationErr := errors.New("rename failed")
	cleanupErr := errors.New("temp cleanup failed")
	cleanupSyncErr := errors.New("temp cleanup sync failed")
	store.dir.impl.hooks.rename = func(int, string, int, string) error {
		return operationErr
	}
	store.dir.impl.hooks.unlink = func(dirFD int, name string, flags int) error {
		err := unix.Unlinkat(dirFD, name, flags)
		return errors.Join(cleanupErr, err)
	}
	originalSync := store.dir.impl.hooks.syncFD
	syncCalls := 0
	store.dir.impl.hooks.syncFD = func(fd int) error {
		syncCalls++
		if syncCalls == 2 {
			return cleanupSyncErr
		}
		return originalSync(fd)
	}
	err = store.SaveAgentState(context.Background(), testAgentState(t))
	if !errors.Is(err, operationErr) || !errors.Is(err, cleanupErr) || !errors.Is(err, cleanupSyncErr) {
		t.Fatalf("SaveAgentState = %v, want operation and cleanup errors", err)
	}
	temps, globErr := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".qurl-agent-state-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(temps) != 0 {
		t.Fatalf("cleanup hook left temporary files: %v", temps)
	}
}

func TestPinnedAgentState_SetupLockSerializesIndependentHandles(t *testing.T) {
	path := filepath.Join(secureAgentStateTestDir(t), "agent.json")
	first, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	held, err := first.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if _, err := second.acquireSetupLock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended acquire = %v, want deadline", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := second.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAgentState_PlaintextAndSealedShareContinuityContract(t *testing.T) {
	type localStore interface {
		AgentStateStore
		AgentStateContinuity
	}
	tests := []struct {
		name string
		open func(*testing.T, string) localStore
	}{
		{"plaintext", func(t *testing.T, path string) localStore {
			store, err := OpenFileAgentState(path)
			if err != nil {
				t.Fatal(err)
			}
			return store
		}},
		{"sealed", func(t *testing.T, path string) localStore {
			store, err := NewSealedFileAgentState(path, "test", &testAgentStateKeyWrapper{})
			if err != nil {
				t.Fatal(err)
			}
			return store
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(secureAgentStateTestDir(t), "state")
			path := filepath.Join(dir, "agent.json")
			store := tt.open(t, path)
			defer func() { _ = store.Close() }()
			if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadAgentState(context.Background()); err != nil {
				t.Fatal(err)
			}
			old := dir + ".old"
			if err := os.Rename(dir, old); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
				t.Fatalf("continuity = %v", err)
			}
		})
	}
}

func TestWithAgentSetupLock_FinalContinuityFailureOverridesSuccess(t *testing.T) {
	dir := filepath.Join(secureAgentStateTestDir(t), "state")
	store, err := OpenFileAgentState(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	cleaned := false
	result, err := withAgentSetupLock(context.Background(), store, func(value *int) {
		if value != nil {
			cleaned = true
		}
	}, func(context.Context, AgentStateStore) (*int, error) {
		value := 42
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return &value, nil
	})
	if !errors.Is(err, ErrAgentStateContinuity) || result != nil || !cleaned {
		t.Fatalf("result/error/cleanup = %v / %v / %v, want nil continuity failure and cleanup", result, err, cleaned)
	}
}
