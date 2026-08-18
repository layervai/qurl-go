// Package docscontract makes documentation drift a test failure.
//
// Nothing else reads the markdown: qurl/simplicity_test.go proves the Go
// examples that live in *_test.go files, but a README or guide fence can
// reference deleted functions, misspell an option, or teach a quickstart that
// cannot work, and no build turns red. That happened — shipped docs showed
// removed API. These tests read the markdown itself, so the drift fails CI.
//
// Four tiers, in separate test functions so a failure names its rule:
//
//   - TestDocGoFencesParse (tier 1): every ```go fence parses as real Go.
//   - TestDocFenceModuleSymbolsExist (tier 2): every pkg.Name reference whose
//     qualifier is one of this module's packages names an exported
//     package-level declaration that exists in today's sources.
//   - TestEmbeddedDeploymentStaysPreGAEmpty (tier 3): the guides are written
//     for the pre-GA posture (trust roots via QURL_DEPLOYMENT); embedding a
//     real deployment must fail the pin so the docs get rewritten.
//   - TestREADMEEnrollmentQuickstartAnchors (tier 4): the README enrollment
//     story keeps its minimal honest anchors.
//
// The gate is deliberately hermetic: pure go/parser over the working tree, no
// go toolchain exec, no network, no temp modules.
package docscontract

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"
)

// TestDocGoFencesParse is tier 1: every ```go fence in the guarded markdown
// must parse as real Go under the classification documented on classify. A
// fence that needs to elide code does it with `// …` comments; bare `...`
// pseudo-code is not valid Go anywhere outside its three legal uses, so the
// parser rejects it here.
func TestDocGoFencesParse(t *testing.T) {
	root := repoRoot(t)
	total := 0
	forms := map[string]int{}
	for _, path := range guardedMarkdownFiles(t, root) {
		fences := extractGoFences(t, root, path)
		total += len(fences)
		for i := range fences {
			f := &fences[i]
			res := parseFence(f)
			if res.err != nil {
				t.Errorf("go fence does not parse (as %s): %v\n"+
					"\tdoc fences must be real, parseable Go — a complete file, declarations, or statements;\n"+
					"\telide with `// …` comments, never a bare `...`", res.form, res.err)
				continue
			}
			forms[res.form]++
		}
		if rel, err := filepath.Rel(root, path); err == nil {
			t.Logf("%s: %d go fence(s)", filepath.ToSlash(rel), len(fences))
		}
	}
	if total == 0 {
		t.Fatal("no ```go fences found in any guarded markdown file; the fence extractor is broken")
	}
	for _, form := range slices.Sorted(maps.Keys(forms)) {
		t.Logf("classification %q: %d fence(s)", form, forms[form])
	}
	t.Logf("%d go fence(s) found in total", total)
}

// TestDocFenceModuleSymbolsExist is tier 2: every qualified identifier in a
// fence whose qualifier names one of this module's packages (see
// modulePackages) must be an exported package-level declaration in that
// package's non-test sources. This is the check that catches a doc still
// showing a deleted function.
//
// Shadowing heuristic: a qualifier that the fence itself declares as an
// identifier — or imports from a foreign path — is skipped; see fenceDeclared.
func TestDocFenceModuleSymbolsExist(t *testing.T) {
	root := repoRoot(t)
	symbols := moduleSymbolSets(t, root)
	for _, qualifier := range slices.Sorted(maps.Keys(symbols)) {
		t.Logf("package %s (%s/): %d exported package-level declarations",
			qualifier, modulePackages[qualifier].dir, len(symbols[qualifier]))
	}

	checked := 0
	for _, path := range guardedMarkdownFiles(t, root) {
		fences := extractGoFences(t, root, path)
		for i := range fences {
			f := &fences[i]
			res := parseFence(f)
			if res.err != nil {
				t.Errorf("cannot scan fence for symbol references — it does not parse (see TestDocGoFencesParse): %v", res.err)
				continue
			}
			declared := fenceDeclared(res.file)
			for _, ref := range fenceModuleRefs(res.file, res.fset, declared) {
				checked++
				if symbols[ref.qualifier][ref.name] {
					continue
				}
				t.Errorf("%s:%d: %s.%s is not an exported package-level declaration in %s/ — "+
					"the doc references API this module does not ship; fix the fence (or export the symbol)",
					f.relPath, res.docLineOf(ref.synLine), ref.qualifier, ref.name,
					modulePackages[ref.qualifier].dir)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no module-qualified references found in any go fence; the reference scan is broken")
	}
	t.Logf("checked %d module-qualified doc references", checked)
}
