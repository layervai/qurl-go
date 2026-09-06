package docscontract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Word-boundary patterns (\b) so identifier substrings never false-positive:
// ConnectAgentRuntime must not match the banned names, and a banned name
// embedded in a longer identifier is not a match either.
var (
	reConnectAgentRuntime = regexp.MustCompile(`\bqurl\.ConnectAgentRuntime\s*\(`)
	reDeploymentEnv       = regexp.MustCompile(`\bQURL_DEPLOYMENT\b`)
	reModuleSymbol        = regexp.MustCompile(`\b(qurl|crid|awsstore|relayknock|nativeudp)\.([A-Z][A-Za-z0-9_]*)\b`)
	readmeBannedSymbols   = []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: "RegisterAgentRuntime", re: regexp.MustCompile(`\bRegisterAgentRuntime\b`)},
		{name: "OpenRegisteredAgentRuntime", re: regexp.MustCompile(`\bOpenRegisteredAgentRuntime\b`)},
	}
)

var modulePackageDirs = map[string]string{
	"qurl":       "qurl",
	"crid":       "crid",
	"awsstore":   "awsstore",
	"relayknock": "relayknock",
	"nativeudp":  "relayknock/nativeudp",
}

// TestREADMEEnrollmentQuickstartAnchors keeps the minimal anchors of the
// README's honest enrollment story.
//
//   - The enrollment quickstart calls ConnectAgentRuntime — the single
//     call that enrolls, resumes, or reopens on every start.
//   - No fence in that story resurrects the deleted RegisterAgentRuntime or
//     OpenRegisteredAgentRuntime entry points (word-boundary matching, so
//     ConnectAgentRuntime itself never false-positives; the live
//     OpenRegisteredAgent / OpenRegisteredAgentWithIdentity names do not
//     contain the banned tokens).
//   - The README mentions QURL_DEPLOYMENT at least once: pre-GA, the trust
//     root enrollment authenticates against comes from that deployment file.
func TestREADMEEnrollmentQuickstartAnchors(t *testing.T) {
	root := repoRoot(t)
	readme := filepath.Join(root, "README.md")
	data, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	if !reConnectAgentRuntime.Match(data) {
		t.Errorf("README.md does not call ConnectAgentRuntime; the enrollment quickstart lost its one-call enrollment story")
	}

	for _, banned := range readmeBannedSymbols {
		if banned.re.Match(data) {
			t.Errorf("README.md references deleted entry point %s; use ConnectAgentRuntime", banned.name)
		}
	}

	if !reDeploymentEnv.Match(data) {
		t.Errorf("README.md never mentions QURL_DEPLOYMENT; pre-GA, native opens and agent enrollment need the deployment file from LayerV setup, and the README must say so")
	}
}

// TestDocumentedModuleSymbolsExist catches guides that name removed API. It
// scans all current docs, not Markdown syntax, so the check stays small and
// also covers API names in prose and tables.
func TestDocumentedModuleSymbolsExist(t *testing.T) {
	root := repoRoot(t)
	exports := make(map[string]map[string]bool, len(modulePackageDirs))
	for qualifier, dir := range modulePackageDirs {
		exports[qualifier] = exportedPackageNames(t, filepath.Join(root, dir), qualifier)
	}

	files := []string{filepath.Join(root, "README.md"), filepath.Join(root, "awsstore", "README.md")}
	docs := filepath.Join(root, "docs")
	err := filepath.WalkDir(docs, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == "decisions" {
			return fs.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, text := range strings.Split(string(data), "\n") {
			for _, match := range reModuleSymbol.FindAllStringSubmatch(text, -1) {
				checked++
				if !exports[match[1]][match[2]] {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s:%d: %s is not exported by this module", rel, line+1, match[0])
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no documented module symbols found")
	}
}

func exportedPackageNames(t *testing.T, dir, packageName string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if file.Name.Name != packageName {
			t.Fatalf("%s declares package %s, want %s", name, file.Name.Name, packageName)
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name.IsExported() {
					names[decl.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							names[spec.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								names[name.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return names
}
