//go:build (linux && !android) || (darwin && !ios)

package qurl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// requireNonRootConfinement guards fixtures that simulate confinement with mode
// bits. root bypasses those, so the tree would not actually be confined and the
// test would assert the wrong thing. Skipping locally is right -- a real sandbox
// cannot be built in a unit test. Skipping in CI is not: it would drop the whole
// confined path from coverage and still report green.
func requireNonRootConfinement(t *testing.T) {
	t.Helper()
	if unix.Geteuid() != 0 {
		return
	}
	const reason = "confinement fixtures rely on DAC; root bypasses the mode bits they set"
	if os.Getenv("CI") != "" {
		t.Fatalf("%s -- running CI as root silently drops every confinement test", reason)
	}
	t.Skip(reason)
}

// confinedStateTree builds root/confined/container/state where confined is
// traversable but not openable. That is the shape macOS App Sandbox imposes: a
// process resolves paths *through* an ancestor it may not open as a directory
// handle, and the container below it opens normally.
func confinedStateTree(t *testing.T) (container, state string) {
	t.Helper()
	requireNonRootConfinement(t)
	root := secureAgentStateTestDir(t)
	confined := filepath.Join(root, "confined")
	container = filepath.Join(confined, "container")
	state = filepath.Join(container, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	// Restore before TempDir cleanup: RemoveAll cannot list a 0111 directory.
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })
	return canonicalPinnedStatePath(container), canonicalPinnedStatePath(state)
}

func TestPinnedStateDirOpensThroughAnUnopenableAncestor(t *testing.T) {
	_, state := confinedStateTree(t)

	dir, err := openPinnedStateDir(state, "agent state", pinnedStateDirWritable)
	if err != nil {
		t.Fatalf("openPinnedStateDir through a confined ancestor: %v", err)
	}
	defer func() { _ = dir.close() }()
	if dir.path != state {
		t.Fatalf("pinned path = %s, want %s", dir.path, state)
	}
}

// Continuity revalidation reopens by absolute path through its own walk. If
// that walk is not fixed too, a sandboxed process opens its state directory
// once and then fails every check afterwards.
func TestPinnedStateDirContinuityHoldsThroughAnUnopenableAncestor(t *testing.T) {
	_, state := confinedStateTree(t)

	dir, err := openPinnedStateDir(state, "agent state", pinnedStateDirWritable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.close() }()
	if err := dir.validateContinuity(); err != nil {
		t.Fatalf("validateContinuity through a confined ancestor: %v", err)
	}
}

func TestPinnedStateDirCreatesBeneathAnUnopenableAncestor(t *testing.T) {
	_, state := confinedStateTree(t)
	nested := filepath.Join(state, "a", "b")

	dir, err := openPinnedStateDir(nested, "agent state", pinnedStateDirWritable)
	if err != nil {
		t.Fatalf("openPinnedStateDir create through a confined ancestor: %v", err)
	}
	defer func() { _ = dir.close() }()
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("nested directory not created: %v", err)
	}
}

// The band between the denied ancestor and the anchor can never be opened with
// a handle, and the anchor is opened by absolute path. Without an explicit
// check a symlink planted there is followed rather than rejected.
func TestPinnedStateDirRejectsSymlinkInsideTheConfinedBand(t *testing.T) {
	requireNonRootConfinement(t)
	root := secureAgentStateTestDir(t)
	targetTree := filepath.Join(root, "real", "state")
	if err := os.MkdirAll(targetTree, 0o700); err != nil {
		t.Fatal(err)
	}
	confined := filepath.Join(root, "confined")
	if err := os.Mkdir(confined, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(confined, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })

	target := canonicalPinnedStatePath(filepath.Join(confined, "link", "state"))
	dir, err := openPinnedStateDir(target, "agent state", pinnedStateDirReadOnly)
	if err == nil {
		_ = dir.close()
		t.Fatal("openPinnedStateDir followed a symlink inside the confined band")
	}
}

// A band component can be unopenable and group/other-writable at once: mode
// 0333 is traversable, unreadable, and writable by anyone. Being unopenable is
// exactly what keeps it out of the walk, so it must be rejected by path.
func TestPinnedStateDirRejectsWritableComponentInTheConfinedBand(t *testing.T) {
	requireNonRootConfinement(t)
	root := secureAgentStateTestDir(t)
	confined := filepath.Join(root, "confined")
	evil := filepath.Join(confined, "evil")
	state := filepath.Join(evil, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(evil, 0o333); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(confined, 0o700)
		_ = os.Chmod(evil, 0o700)
	})

	dir, err := openPinnedStateDir(canonicalPinnedStatePath(state), "agent state", pinnedStateDirReadOnly)
	if err == nil {
		_ = dir.close()
		t.Fatal("openPinnedStateDir resumed below a world-writable band component")
	}
}

// The App Sandbox band is several components deep. Anchoring must skip the
// whole contiguous run, not stop at the first denied-or-openable boundary.
func TestPinnedStateDirSkipsAContiguousMultiComponentBand(t *testing.T) {
	requireNonRootConfinement(t)
	root := secureAgentStateTestDir(t)
	outer := filepath.Join(root, "outer")
	inner := filepath.Join(outer, "inner")
	state := filepath.Join(inner, "container", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inner, 0o111); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outer, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(outer, 0o700)
		_ = os.Chmod(inner, 0o700)
	})

	dir, err := openPinnedStateDir(canonicalPinnedStatePath(state), "agent state", pinnedStateDirWritable)
	if err != nil {
		t.Fatalf("openPinnedStateDir through a two-component band: %v", err)
	}
	_ = dir.close()
}

// A reachable tree must keep walking from the filesystem root. The fallback is
// only for ancestors this process genuinely cannot open.
func TestPinnedStateDirUnreachableTargetKeepsTheOriginalError(t *testing.T) {
	requireNonRootConfinement(t)
	root := secureAgentStateTestDir(t)
	confined := filepath.Join(root, "confined")
	state := filepath.Join(confined, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// 0000: neither openable nor traversable, so the target is unreachable too.
	if err := os.Chmod(confined, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })

	_, err := openPinnedStateDir(canonicalPinnedStatePath(state), "agent state", pinnedStateDirReadOnly)
	if err == nil {
		t.Fatal("openPinnedStateDir succeeded through a fully denied ancestor")
	}
	if !strings.Contains(err.Error(), "without following links") {
		t.Fatalf("error = %v, want the original component-open failure", err)
	}
}
