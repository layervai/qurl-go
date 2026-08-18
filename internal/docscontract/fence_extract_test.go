package docscontract

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleRoot is the module path a go.mod must declare for a directory to be
// accepted as the repository root.
const moduleRoot = "github.com/layervai/qurl-go"

// modulePackages maps the package qualifiers that may appear in doc fences
// (`qurl.OpenClient`, `crid.Parse`, ...) to the repo-relative directory
// holding that package's non-test sources and to the import path a fence
// would use for it. awsstore is a separate Go module, but tier 2 only parses
// source files, so it participates like any other directory.
var modulePackages = map[string]struct {
	dir        string // repo-relative, slash-separated
	importPath string
}{
	"qurl":       {dir: "qurl", importPath: moduleRoot + "/qurl"},
	"crid":       {dir: "crid", importPath: moduleRoot + "/crid"},
	"awsstore":   {dir: "awsstore", importPath: moduleRoot + "/awsstore"},
	"relayknock": {dir: "relayknock", importPath: moduleRoot + "/relayknock"},
	"nativeudp":  {dir: "relayknock/nativeudp", importPath: moduleRoot + "/relayknock/nativeudp"},
}

// repoRoot walks up from the test's working directory to the directory whose
// go.mod declares moduleRoot. go test runs with the package directory as the
// working directory, but walking keeps the lookup robust to any harness that
// runs the binary elsewhere in the tree.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	start := dir
	for {
		if declaresRootModule(filepath.Join(dir, "go.mod")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod declaring module %s found walking up from %s", moduleRoot, start)
		}
		dir = parent
	}
}

func declaresRootModule(gomod string) bool {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest) == moduleRoot
		}
	}
	return false
}

// guardedMarkdownFiles returns every markdown file the contract covers:
// README.md, awsstore/README.md, and everything under docs/ except
// docs/decisions/ — ADRs quote historical and removed API by design.
func guardedMarkdownFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "awsstore", "README.md"),
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("guarded markdown file missing: %v", err)
		}
	}
	docs := filepath.Join(root, "docs")
	adrs := filepath.Join(docs, "decisions")
	err := filepath.WalkDir(docs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == adrs {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs/: %v", err)
	}
	if len(files) < 3 {
		t.Fatalf("markdown discovery found only %d file(s); the docs/ walk is broken", len(files))
	}
	return files
}

// goFence is one ```go fence extracted from a markdown file.
type goFence struct {
	path    string   // absolute path of the markdown file
	relPath string   // repo-relative, slash-separated, for messages
	line    int      // 1-based markdown line of the first fence content line
	lines   []string // fence content, without the fence marker lines
}

func (f *goFence) src() string { return strings.Join(f.lines, "\n") + "\n" }

// docLine converts a 1-based line inside the fence content to a line of the
// markdown file, clamping to the fence for wrapper-line artifacts.
func (f *goFence) docLine(contentLine int) int {
	contentLine = max(contentLine, 1)
	contentLine = min(contentLine, len(f.lines))
	return f.line + contentLine - 1
}

// extractGoFences returns the ```go fences of one markdown file.
//
// Fence markers are recognized at column 0 only, which is where every fence
// in this repository sits. An indented ```go fence fails loudly rather than
// being silently skipped, so a future doc cannot open a hole in the gate by
// nesting a fence in a list.
func extractGoFences(t *testing.T, root, path string) []goFence {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	rel := path
	if r, rerr := filepath.Rel(root, path); rerr == nil {
		rel = filepath.ToSlash(r)
	}

	var fences []goFence
	var cur *goFence
	inFence := false
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		atCol0 := strings.HasPrefix(line, "```")
		isMarker := strings.HasPrefix(trimmed, "```")
		if !inFence {
			if !isMarker {
				continue
			}
			info := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			if !atCol0 {
				if info == "go" {
					t.Fatalf("%s:%d: indented ```go fence; this extractor recognizes fences at column 0 only — unindent it so the drift gate can check it", rel, i+1)
				}
				continue // indented non-go fence: outside the contract
			}
			inFence = true
			if info == "go" {
				cur = &goFence{path: path, relPath: rel, line: i + 2}
			}
			continue
		}
		if atCol0 && strings.TrimSpace(strings.TrimPrefix(trimmed, "```")) == "" {
			inFence = false
			if cur != nil {
				fences = append(fences, *cur)
				cur = nil
			}
			continue
		}
		if cur != nil {
			cur.lines = append(cur.lines, line)
		}
	}
	if inFence {
		t.Fatalf("%s: unterminated code fence", rel)
	}
	return fences
}

// candidate is one synthetic-source form a fence may parse under.
type candidate struct {
	form string
	src  string
	// mapLine maps a 1-based synthetic-source line back to a 1-based fence
	// content line.
	mapLine func(int) int
}

// parsedFence is the parse result for a fence: the AST under the accepted
// form, or the primary form's error when no form parses.
type parsedFence struct {
	fence *goFence
	form  string
	file  *ast.File
	fset  *token.FileSet
	// docLineOf maps a synthetic-source line to a markdown line.
	docLineOf func(synLine int) int
	err       error // already formatted with markdown file:line
}

// classify picks the synthetic form a fence parses under.
//
// The rules, keyed on the fence's first token (skipping blank lines and
// //-comment lines):
//
//   - "package"  → a complete file; parse the fence as-is, no fallback.
//   - "func"     → declarations: parse "package p\n" + fence.
//   - "import"   → the leading import declaration(s) are located textually;
//     when the remainder starts with another declaration keyword the whole
//     fence is already a valid file body (declarations form), otherwise the
//     imports stay at file level and the remainder is wrapped in a function
//     body — the Go example style of imports shown above statements.
//   - anything else → statements: parse "package p\nfunc _() {\n" + fence +
//     "}". This includes fences starting with var/const/type, which are
//     valid statements too.
//
// If the primary form fails, the alternate wrap is tried before failing (a
// fence that opens with a type and then declares methods needs the
// declarations form, say); when both fail, the PRIMARY form's first error is
// reported, mapped back to the markdown file and line. go/parser accepts only
// real Go, so pseudo-code elision — a bare `...` outside its three legal uses
// — fails tier 1; docs elide with `// …` comments instead.
func classify(f *goFence) (primary, fallback *candidate) {
	switch first, _ := firstToken(f.lines, 0); first {
	case "package":
		return fileForm(f), nil
	case "func":
		return declForm(f), stmtForm(f)
	case "import":
		n := leadingImportLines(f.lines)
		switch next, _ := firstToken(f.lines, n); next {
		case "func", "type", "const", "var", "import", "":
			return declForm(f), importStmtForm(f, n)
		default:
			return importStmtForm(f, n), declForm(f)
		}
	default:
		return stmtForm(f), declForm(f)
	}
}

func fileForm(f *goFence) *candidate {
	return &candidate{form: "file", src: f.src(), mapLine: func(l int) int { return l }}
}

func declForm(f *goFence) *candidate {
	return &candidate{
		form:    "declarations",
		src:     "package p\n" + f.src(),
		mapLine: func(l int) int { return l - 1 },
	}
}

func stmtForm(f *goFence) *candidate {
	return &candidate{
		form:    "statements",
		src:     "package p\nfunc _() {\n" + f.src() + "}\n",
		mapLine: func(l int) int { return l - 2 },
	}
}

func importStmtForm(f *goFence, importLines int) *candidate {
	head := strings.Join(f.lines[:importLines], "\n")
	tail := strings.Join(f.lines[importLines:], "\n")
	return &candidate{
		form: "imports+statements",
		src:  "package p\n" + head + "\nfunc _() {\n" + tail + "\n}\n",
		mapLine: func(l int) int {
			if l <= 1+importLines {
				return l - 1 // "package p" prefix only
			}
			return l - 2 // plus the "func _() {" wrapper line
		},
	}
}

// firstToken returns the first whitespace-delimited token at or after fence
// content line index `from` (0-based), skipping blank lines and //-comments.
// A trailing "(" is cut so `import(` and `func(` classify by keyword. Doc
// fences open with line comments only; one opening with a block comment would
// classify as statements and still parse.
func firstToken(lines []string, from int) (string, int) {
	for i := from; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		tok := strings.Fields(trimmed)[0]
		if idx := strings.Index(tok, "("); idx > 0 {
			tok = tok[:idx]
		}
		return tok, i
	}
	return "", len(lines)
}

// leadingImportLines counts the fence content lines consumed by the import
// declaration(s) at the top of a fence, including blank and comment lines
// between two import declarations. The scan is textual and expects
// gofmt-shaped imports: single-line `import "path"` or a parenthesized block
// closed by a line containing ")". On a malformed block it returns what was
// consumed so far and go/parser reports the real error.
func leadingImportLines(lines []string) int {
	end := 0
	i := 0
	for {
		j := i
		for j < len(lines) {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				j++
				continue
			}
			break
		}
		if j >= len(lines) {
			return end
		}
		trimmed := strings.TrimSpace(lines[j])
		if trimmed != "import" && !strings.HasPrefix(trimmed, "import ") && !strings.HasPrefix(trimmed, "import(") {
			return end
		}
		open := strings.Index(trimmed, "(")
		switch {
		case open < 0 || strings.Contains(trimmed[open:], ")"):
			i = j + 1 // single-line import
		default:
			k := j + 1
			for k < len(lines) && !strings.Contains(lines[k], ")") {
				k++
			}
			if k >= len(lines) {
				return end // unterminated block: let the parser complain
			}
			i = k + 1
		}
		end = i
	}
}

// parseFence parses a fence under its classified form, falling back to the
// alternate wrap, and reports the primary form's error if neither parses.
func parseFence(f *goFence) *parsedFence {
	primary, fallback := classify(f)
	res := tryParse(f, primary)
	if res.err == nil || fallback == nil {
		return res
	}
	if alt := tryParse(f, fallback); alt.err == nil {
		return alt
	}
	return res
}

func tryParse(f *goFence, c *candidate) *parsedFence {
	fset := token.NewFileSet()
	res := &parsedFence{
		fence:     f,
		form:      c.form,
		fset:      fset,
		docLineOf: func(syn int) int { return f.docLine(c.mapLine(syn)) },
	}
	file, err := parser.ParseFile(fset, f.relPath, c.src, parser.SkipObjectResolution)
	if err != nil {
		line, msg := 1, err.Error()
		var list scanner.ErrorList
		if errors.As(err, &list) && len(list) > 0 {
			line, msg = list[0].Pos.Line, list[0].Msg
		}
		res.err = fmt.Errorf("%s:%d: %s", f.relPath, res.docLineOf(line), msg)
		return res
	}
	res.file = file
	return res
}

// fenceDeclared collects the identifiers a fence declares, plus import names
// that do NOT bind this module's own packages. Tier 2 skips a qualifier that
// appears here: `qurl` in a fence that declares (or foreign-imports) a `qurl`
// identifier is not a reference to this module's qurl package.
//
// The heuristic deliberately over-approximates — struct field names, function
// parameters, and receivers all count as declarations, and block scoping is
// ignored, so a shadowed qualifier is skipped everywhere in its fence. That
// can only make tier 2 more lenient on a pathological fence, never fail a
// correct one, and no guarded doc shadows a package qualifier today.
func fenceDeclared(file *ast.File) map[string]bool {
	declared := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						declared[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				declared[id.Name] = true
			}
		case *ast.TypeSpec:
			declared[n.Name.Name] = true
		case *ast.FuncDecl:
			declared[n.Name.Name] = true
		case *ast.Field:
			for _, id := range n.Names {
				declared[id.Name] = true
			}
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				if id, ok := n.Key.(*ast.Ident); ok {
					declared[id.Name] = true
				}
				if id, ok := n.Value.(*ast.Ident); ok {
					declared[id.Name] = true
				}
			}
		case *ast.LabeledStmt:
			declared[n.Label.Name] = true
		case *ast.ImportSpec:
			path := strings.Trim(n.Path.Value, `"`)
			name := path
			if idx := strings.LastIndex(path, "/"); idx >= 0 {
				name = path[idx+1:]
			}
			if n.Name != nil {
				name = n.Name.Name
			}
			// Importing the module package under its own name is exactly the
			// binding tier 2 checks; anything else shadows the qualifier.
			if pkg, ok := modulePackages[name]; !ok || pkg.importPath != path {
				declared[name] = true
			}
		}
		return true
	})
	return declared
}

// moduleRef is one pkg.Name selector in a fence whose qualifier names a
// module package.
type moduleRef struct {
	qualifier string
	name      string
	synLine   int
}

func fenceModuleRefs(file *ast.File, fset *token.FileSet, declared map[string]bool) []moduleRef {
	var refs []moduleRef
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, isModulePkg := modulePackages[id.Name]; !isModulePkg || declared[id.Name] {
			return true
		}
		refs = append(refs, moduleRef{
			qualifier: id.Name,
			name:      sel.Sel.Name,
			synLine:   fset.Position(sel.Pos()).Line,
		})
		return true
	})
	return refs
}

// moduleSymbolSets parses every non-test source file of each package in
// modulePackages and returns qualifier → set of exported package-level
// declarations (funcs, types, vars, consts). Files for every GOOS are parsed
// — build tags are ignored — so each set is the union across platforms, which
// is what an existence check wants.
func moduleSymbolSets(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	sets := make(map[string]map[string]bool, len(modulePackages))
	for qualifier, pkg := range modulePackages {
		dir := filepath.Join(root, filepath.FromSlash(pkg.dir))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("package directory for doc qualifier %q: %v (fix the modulePackages map if the package moved)", qualifier, err)
		}
		set := map[string]bool{}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parsing %s/%s: %v", pkg.dir, name, err)
			}
			if file.Name.Name != qualifier {
				t.Fatalf("%s/%s declares package %s, but the docs contract maps qualifier %q to that directory; fix the modulePackages map",
					pkg.dir, name, file.Name.Name, qualifier)
			}
			collectExported(file, set)
		}
		if len(set) == 0 {
			t.Fatalf("no exported declarations found under %s/ for doc qualifier %q; the symbol scan is broken or the package moved", pkg.dir, qualifier)
		}
		sets[qualifier] = set
	}
	return sets
}

func collectExported(file *ast.File, set map[string]bool) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.IsExported() {
				set[d.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, id := range s.Names {
						if id.IsExported() {
							set[id.Name] = true
						}
					}
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						set[s.Name.Name] = true
					}
				}
			}
		}
	}
}
