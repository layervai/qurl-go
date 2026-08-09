module github.com/layervai/qurl-go

// This is a SECURITY floor, not a "track the newest toolchain" pin, and not a
// number to lower casually to widen compatibility.
//
// It names the oldest Go patch release free of the standard-library
// vulnerabilities this module's own code actually reaches. CI enforces that:
// setup-go takes its toolchain from this line, so govulncheck runs at exactly
// this version and fails the build if the floor drifts below a fix.
//
// 1.26.5 is the fix release for both vulnerabilities govulncheck reports as
// reachable from here:
//
//   - GO-2026-5856, crypto/tls Encrypted Client Hello privacy leak, reached via
//     qurl.HTTPFetcher.Fetch -> http.Client.Do -> tls.Conn.HandshakeContext
//   - GO-2026-4970, os root escape via symlink plus trailing slash, reached via
//     qurl.readPrivateStateFileBounded -> os.OpenInRoot
//
// Both are also fixed in 1.25.12, so a 1.25-line floor is legitimate and would
// widen reach considerably. It is blocked only by
// github.com/layervai/qurl-conformance declaring go 1.26.4: it is a TEST-ONLY
// dependency here (no package of it appears in any build graph — see
// `go list -deps ./qurl`), but `go mod tidy` folds a test dependency's
// directive into ours regardless. Moving to 1.25.12 therefore requires
// conformance to relax its own floor first, then a require bump here.
//
// Before changing this line, run `make vuln` at the candidate version.
go 1.26.5

require (
	github.com/layervai/qurl-conformance v0.12.2
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0
