package qurl_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/layervai/qurl-go/qurl"
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
	"ExampleOpenClient":          3,
	"ExampleClient_ProtectURL":   3,
	"ExampleClient_CreatePortal": 4,
	// Kill one minted link before it expires: open client, mint, revoke.
	"ExampleClient_RevokePortal": 3,
	// Mint a fresh access link for a stored identifier (either form): open
	// client, resolve, print. The CRID trust story stays one optional call
	// (ResolvedAccess.VerifyCRID), not setup.
	"ExampleClient_ResolveResource": 3,
	"ExampleNewClient":              5,
	// Resolve a Connector binding through its already-registered assigned-cell
	// session: open state, reopen the binding, create one replayable request,
	// resolve, and print. The two defers are deterministic key/store cleanup.
	"ExampleResolveRegisteredAgentConnectorResource": 8,
	// Open a persisted registered device and use its narrow resource-only HTTP
	// bridge. The defers release the state pin and response body.
	"ExampleClient_RegisteredAgentResourceHTTPDoer": 8,
	// The package overview: open a client, protect, create, print.
	"Example": 4,

	// --- Agent runtime -------------------------------------------------------
	// Registration is the highest-friction scenario in the SDK and the one an
	// integrator hits first. It was 12; making the hand-assembled Hub trust
	// root an optional override — it now resolves from the deployment, via
	// QURL_DEPLOYMENT until GA builds embed it — brought it to 11.
	//
	// 12 is the honest floor, not a concession. What remains is:
	//   open agent state / register / create the replay request / resolve the
	//   resource / take the device key
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
	// ConnectAgentRuntime is the single entry point a service calls on every
	// start: the credential is an option rather than a positional argument, so
	// one call shape covers enrolling, resuming, and reopening.
	"ExampleConnectAgentRuntime":     12,
	"ExampleNewSealedFileAgentState": 5,
	// Resolve the platform-issued knock identity, prepare a source-fenced
	// operation from the binding's live assignment, serialize it, and retain the
	// exact recovery route before the knock. The cycle RunID is caller-owned and
	// unique, so generating it is required work.
	"ExamplePrepareLiveNativeSessionOperation": 14,

	// Headless enrollment is the escape hatch for a runtime with no mailbox, so
	// it must stay cheaper than the default OTP path it opts out of: open agent
	// state / register / two defers that close the store and the binding — plus
	// the ctx and the discard the example needs to compile.
	"ExampleWithAgentRuntimeHeadlessEnrollment": 6,

	// Recovery is one deliberate operator action, and the extra statement over
	// headless enrollment is the Hub trust root: RecoverAgentRuntime rejects a
	// call without WithAgentRuntimeRecoveryHub, so unlike registration it cannot
	// fall back to the deployment's hub. Teaching recovery that fallback is the
	// one honest way to get this to 6.
	"ExampleRecoverAgentRuntime": 7,
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

// The positive half of the closed-set rule, compile-enforced: the two
// resource-client options are accepted by every lifecycle entry point — plain
// client construction included — because the steady-state Client they configure
// is built on all of them. Losing one of these acceptances would strand a
// documented option, so pin the intent here next to the negative assertions.
var (
	_ qurl.ClientOption                   = qurl.WithAgentClientBaseURL("")
	_ qurl.AgentRuntimeRegistrationOption = qurl.WithAgentClientBaseURL("")
	_ qurl.AgentRuntimeRefreshOption      = qurl.WithAgentClientBaseURL("")
	_ qurl.AgentRuntimeRecoveryOption     = qurl.WithAgentClientBaseURL("")
	_ qurl.AgentRuntimeLifecycleOption    = qurl.WithAgentClientBaseURL("")
	_ qurl.ClientOption                   = qurl.WithAgentClientHTTPClient(nil)
	_ qurl.AgentRuntimeRegistrationOption = qurl.WithAgentClientHTTPClient(nil)
	_ qurl.AgentRuntimeRefreshOption      = qurl.WithAgentClientHTTPClient(nil)
	_ qurl.AgentRuntimeRecoveryOption     = qurl.WithAgentClientHTTPClient(nil)
	_ qurl.AgentRuntimeLifecycleOption    = qurl.WithAgentClientHTTPClient(nil)
)

// Option sets in this SDK are closed on purpose: each entry point accepts only
// the options that mean something to it, and the compiler is what enforces that.
// The rule is easy to erode one convenient interface embed at a time, so assert
// the boundaries rather than trusting review to catch it.
func TestOptionSetsStayClosed(t *testing.T) {
	// Compile-time proof of where the two renewal-policy options are accepted:
	// offline open belongs to ConnectAgentRuntime alone, pinned assignment to
	// both entry points that renew an assignment.
	openOnly := qurl.WithAgentRuntimeOfflineOpen()
	pinned := qurl.WithAgentRuntimePinnedAssignment()

	// The whole point of the closed sets: an option that means nothing to a
	// plain resource Client must not be silently accepted by one.
	if _, isClient := openOnly.(qurl.ClientOption); isClient {
		t.Error("WithAgentRuntimeOfflineOpen must not satisfy ClientOption; NewClient and OpenRegisteredAgent would accept and ignore it")
	}
	if _, isClient := pinned.(qurl.ClientOption); isClient {
		t.Error("WithAgentRuntimePinnedAssignment must not satisfy ClientOption; NewClient and OpenRegisteredAgent would accept and ignore it")
	}

	// Refresh and recovery exist to perform a network exchange, so the option
	// that forbids one must not reach them; recovery exists to adopt the Hub
	// placement, so the option that refuses adoption must not reach it either.
	if _, ok := any(openOnly).(qurl.AgentRuntimeRefreshOption); ok {
		t.Error("WithAgentRuntimeOfflineOpen must not satisfy AgentRuntimeRefreshOption; RefreshAgentRuntime is a network exchange")
	}
	if _, ok := any(openOnly).(qurl.AgentRuntimeRecoveryOption); ok {
		t.Error("WithAgentRuntimeOfflineOpen must not satisfy AgentRuntimeRecoveryOption; RecoverAgentRuntime is a network exchange")
	}
	if _, ok := any(pinned).(qurl.AgentRuntimeRecoveryOption); ok {
		t.Error("WithAgentRuntimePinnedAssignment must not satisfy AgentRuntimeRecoveryOption; recovery exists to adopt the Hub placement")
	}

	// Generic client options must not reach the lifecycle entry points.
	// Rejecting these at compile time is what replaced the old run-time
	// WithIssuerStatePath check.
	for name, opt := range map[string]any{
		"WithBaseURL":         qurl.WithBaseURL("https://example.test"),
		"WithHTTPClient":      qurl.WithHTTPClient(http.DefaultClient),
		"WithIssuerStatePath": qurl.WithIssuerStatePath("/tmp/x"),
	} {
		if _, ok := opt.(qurl.AgentRuntimeRegistrationOption); ok {
			t.Errorf("%s must not satisfy AgentRuntimeRegistrationOption", name)
		}
	}

	// The knock set stays the narrowest: no assignment or resource-client option
	// may alter a single UDP exchange.
	for name, opt := range map[string]any{
		"WithAgentClientBaseURL":       qurl.WithAgentClientBaseURL("https://example.test"),
		"WithAgentRuntimeOfflineOpen":  openOnly,
		"WithAgentRuntimePinnedAssign": pinned,
	} {
		if _, ok := opt.(qurl.AgentRuntimeUDPOption); ok {
			t.Errorf("%s must not satisfy AgentRuntimeUDPOption", name)
		}
	}
}
