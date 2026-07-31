package qurl_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
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
// Every scenario a customer performs is budgeted. Leaving one untracked is how
// the opener silently grew to ~115 lines: nothing measured it, so nothing failed
// when it got worse. A new exported entry point that a customer is expected to
// call belongs here on the same commit that adds it.
var frictionBudget = map[string]int{
	// --- Opening -------------------------------------------------------------
	// Verify a link and get a reachable URL. One call. No setup, no trust
	// wiring, no transport selection — the SDK ships what it knows about the
	// deployment it talks to.
	"ExampleEnterPortal": 2,

	// --- Issuing -------------------------------------------------------------
	// Protect a URL and mint a link: open client, protect, create.
	"ExampleOpenClient":                     3,
	"ExampleClient_ProtectURL":              3,
	"ExampleClient_EnsureConnectorResource": 3,
	"ExampleClient_CreatePortal":            4,
	"ExampleNewClient":                      5,
	// The package overview: open a client, protect, create, print.
	"Example": 4,

	// --- Agent runtime -------------------------------------------------------
	// Registration is the highest-friction scenario in the SDK and the one an
	// integrator hits first. It was 12; removing the hand-assembled Hub trust
	// root (the SDK now ships it, exactly as it ships issuer keys and cells)
	// brought it to 11.
	//
	// 11 is the honest floor, not a concession. What remains is:
	//   open agent state / register / take the device key / ensure the resource
	//   / mint a cycle run ID / knock — plus the three defers that release the
	//   store, the binding, and the key material.
	//
	// Two of those look removable and are not:
	//   - The device static private key is taken and cleared explicitly. Hiding
	//     that inside the SDK would keep key material live longer than the
	//     caller can see or control.
	//   - The cycle RunID is caller-owned by frozen contract (issue #66): it is
	//     generated once per knock/service cycle and REUSED across every retry
	//     and reconnect. An SDK-generated ID would mint a fresh value per call
	//     and silently break retry correlation.
	// Lower this only by moving real work into the SDK, never by weakening
	// either of those.
	"ExampleRegisterAgentRuntime":    11,
	"ExampleRecoverAgentRuntime":     7,
	"ExampleNewSealedFileAgentState": 5,
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
	// Scan every test file rather than one, so an example may live wherever it
	// fits and can never dodge the budget by moving.
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("glob test files: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no test files found; the budget would vacuously pass")
	}

	seen := map[string]bool{}
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		{
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
