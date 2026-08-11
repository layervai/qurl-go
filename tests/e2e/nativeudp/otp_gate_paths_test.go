package nativeudp_test

// Fences the OTP gate's `paths:` filter against the code it actually compiles.
//
// The filter exists to conserve a small OTP issuance budget, but a filter that
// is too narrow is worse than none: the gate silently does not run on exactly
// the changes it was built to catch, while still reporting green everywhere
// else. That is a hole nobody notices, because nothing fails.
//
// It is easy to get wrong by reading names. `qurl` is only the public facade;
// registration executes in `internal/qv2`, `internal/udpfence` and `relayknock`
// -- all packages of the ROOT module, so touching them moves neither go.mod nor
// go.sum and matches no dependency path either. The first version of this
// filter listed `qurl/**` alone and missed nine of the eleven packages the gate
// compiles.
//
// So rather than restate the list by hand, this derives it: `go list` reports
// the real closure, and the filter must cover it.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gateWorkflowPath is relative to this package directory.
const gateWorkflowPath = "../../../.github/workflows/otp-registration-gate.yml"

// gatePackage is the package whose compile closure the gate must cover.
const gatePackage = "github.com/layervai/qurl-go/tests/e2e/nativeudp"

// modulePrefix is the root module path; in-repo packages carry it.
const modulePrefix = "github.com/layervai/qurl-go/"

// compiledPackageDirs reports every in-repo package directory the gate's test
// binary compiles, test files included, as repo-relative paths.
//
// -deps alone would be wrong here: it ignores _test.go files, and this package
// has no non-test source at all, so it would report a closure of one and the
// fence would pass vacuously. -test is what pulls in the real imports.
func compiledPackageDirs(t *testing.T) []string {
	t.Helper()

	out, err := exec.Command("go", "list", "-deps", "-test", gatePackage).Output()
	if err != nil {
		t.Fatalf("go list -deps -test %s: %v", gatePackage, err)
	}

	seen := map[string]bool{}
	var dirs []string
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if !strings.HasPrefix(pkg, modulePrefix) {
			continue // stdlib or an external module; not a repo path
		}
		// go list gives synthesized test packages three spellings, all of which
		// live in the real package's directory: "<pkg>.test" (the binary),
		// "<pkg> [<pkg>.test]" (the instrumented build) and "<pkg>_test" (the
		// external test package, which is what this file is in). Reduce all of
		// them to the directory, or the fence reports a path that does not
		// exist on disk and can never be covered by any glob.
		rel := strings.TrimPrefix(pkg, modulePrefix)
		if space := strings.IndexByte(rel, ' '); space >= 0 {
			rel = rel[:space]
		}
		rel = strings.TrimSuffix(strings.TrimSuffix(rel, ".test"), "_test")
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		dirs = append(dirs, rel)
	}
	if len(dirs) == 0 {
		t.Fatal("derived an empty compile closure; the fence would pass vacuously")
	}
	return dirs
}

// coveredByGlob reports whether a `paths:` entry matches everything under dir.
//
// Only the two shapes this filter uses are honoured -- a `X/**` subtree and an
// exact path. Anything cleverer would be this test reimplementing GitHub's
// matcher, which is a worse thing to be wrong about than an unrecognised glob.
func coveredByGlob(glob, dir string) bool {
	if subtree := strings.TrimSuffix(glob, "/**"); subtree != glob {
		return dir == subtree || strings.HasPrefix(dir, subtree+"/")
	}
	return glob == dir
}

// gateFilterPaths returns the globs listed under the workflow's `paths:` key.
//
// Scanned rather than YAML-parsed on purpose: the root module keeps a
// deliberately tiny dependency graph -- it is a public SDK -- and a test-only
// YAML library would still land in go.mod. The block is a fixed, flat list of
// quoted scalars, so scanning is sufficient and adds nothing to the graph.
func gateFilterPaths(t *testing.T) []string {
	t.Helper()

	raw, err := os.ReadFile(gateWorkflowPath)
	if err != nil {
		t.Fatalf("read gate workflow: %v", err)
	}

	var (
		paths   []string
		inBlock bool
		indent  int
	)
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !inBlock {
			if trimmed == "paths:" {
				inBlock = true
				indent = len(line) - len(strings.TrimLeft(line, " "))
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A line at or left of `paths:` own indentation ends the block.
		if len(line)-len(strings.TrimLeft(line, " ")) <= indent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		paths = append(paths, strings.Trim(strings.TrimPrefix(trimmed, "- "), `'"`))
	}

	if !inBlock {
		t.Fatalf("no `paths:` block in %s; the filter may have been removed, "+
			"which is safe for coverage but makes this fence meaningless", gateWorkflowPath)
	}
	if len(paths) == 0 {
		t.Fatal("found an empty `paths:` block; refusing to pass vacuously")
	}
	return paths
}

// TestGatePathsCoverTheCompiledClosure is the fence.
//
// Every top-level directory the gate compiles must be matched by some glob in
// the filter, so a new in-repo dependency cannot quietly fall outside the gate.
func TestGatePathsCoverTheCompiledClosure(t *testing.T) {
	filter := gateFilterPaths(t)

	for _, dir := range compiledPackageDirs(t) {
		covered := false
		for _, glob := range filter {
			if coveredByGlob(glob, dir) {
				covered = true
				break
			}
		}
		if !covered {
			top, _, _ := strings.Cut(dir, "/")
			t.Errorf("the gate compiles %s but the workflow's paths filter does not cover it.\n"+
				"A change there can break SDK registration and the gate will not run.\n"+
				"Add '%s/**' to paths: in %s.\nCurrent filter: %v",
				dir, top, gateWorkflowPath, filter)
		}
	}
}

// TestGatePathsCoverTheModuleGraph pins the non-source triggers separately.
// These carry no Go package, so the closure check above cannot see them, and a
// dependency bump genuinely can change registration behavior.
func TestGatePathsCoverTheModuleGraph(t *testing.T) {
	filter := map[string]bool{}
	for _, glob := range gateFilterPaths(t) {
		filter[glob] = true
	}

	for _, required := range []string{"go.mod", "go.sum", "go.work", "go.work.sum"} {
		if !filter[required] {
			t.Errorf("paths filter omits %s; a dependency bump could change registration "+
				"behavior without running the gate", required)
		}
	}

	// The workflow must retrigger on its own edits, or a change to the gate
	// itself ships unexercised.
	self := filepath.Base(gateWorkflowPath)
	found := false
	for glob := range filter {
		if strings.HasSuffix(glob, self) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("paths filter omits %s; edits to the gate would not run it", self)
	}
}
