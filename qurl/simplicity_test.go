package qurl_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Friction budget for the basic scenarios.
//
// The SDK's central promise is that ordinary use takes a few lines. That promise
// decayed silently once: opening a link drifted to ~115 lines of trust wiring in
// every consumer while nobody was counting, because "a few lines" lived in the
// README instead of in CI. This test moves it into CI.
//
// The budget counts STATEMENTS in each example, excluding the `if err != nil`
// checks Go forces on every call — those are language tax, not product friction.
// What is counted is the work a customer must actually understand and write.
//
// Raising a budget is a product decision. If a change cannot fit, the correct
// fix is nearly always to move the work into the SDK, not to raise the number.
var frictionBudget = map[string]int{
	// Verify a link and get a reachable URL. One call. No setup, no trust
	// wiring, no transport selection — the SDK ships what it knows about the
	// deployment it talks to.
	"ExampleEnterPortal": 2,
	// Protect a URL and mint a link: open client, protect, create.
	"ExampleOpenClient": 3,
}

// countBudgetedStatements counts top-level statements in fn, skipping the
// `if err != nil { ... }` guards that Go requires after every call.
func countBudgetedStatements(fn *ast.FuncDecl) int {
	n := 0
	for _, stmt := range fn.Body.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			if binary, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
				if ident, ok := binary.X.(*ast.Ident); ok && ident.Name == "err" {
					continue
				}
			}
		}
		n++
	}
	return n
}

// TestBasicScenariosStayWithinFrictionBudget fails when a basic scenario grows.
// It reads the example files as the source of truth, so the examples cannot
// quietly diverge from what customers are told to write.
func TestBasicScenariosStayWithinFrictionBudget(t *testing.T) {
	fset := token.NewFileSet()
	// Scan the whole package rather than one file, so an example may live
	// wherever it fits and can never dodge the budget by moving.
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				budget, tracked := frictionBudget[fn.Name.Name]
				if !tracked {
					continue
				}
				seen[fn.Name.Name] = true
				if got := countBudgetedStatements(fn); got > budget {
					t.Errorf(
						"%s now takes %d statements, budget is %d.\n"+
							"A basic scenario got harder. Move the work into the SDK rather than raising the budget.",
						fn.Name.Name, got, budget,
					)
				}
			}
		}
	}

	// A budgeted example that vanished is the loudest possible regression: the
	// scenario stopped being demonstrated at all, so nothing was measuring it.
	for name := range frictionBudget {
		if !seen[name] {
			t.Errorf("budgeted example %s is missing; a basic scenario is no longer demonstrated", name)
		}
	}
}
