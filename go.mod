module github.com/layervai/qurl-go

// This is a SECURITY floor, not a "track the newest toolchain" pin, and not a
// number to lower casually to widen compatibility.
//
// It names the oldest Go patch release free of the standard-library
// vulnerabilities this module's own code actually reaches. CI enforces that:
// setup-go takes its toolchain from this line, so govulncheck runs at exactly
// this version and fails the build if the floor drifts below a fix.
//
// 1.25.12 is the oldest release that qualifies. It is the fix release on the
// 1.25 line for both vulnerabilities govulncheck reports as reachable from
// here:
//
//   - GO-2026-5856, crypto/tls Encrypted Client Hello privacy leak, reached via
//     qurl.HTTPFetcher.Fetch -> http.Client.Do -> tls.Conn.HandshakeContext
//   - GO-2026-4970, os root escape via symlink plus trailing slash, reached via
//     qurl.readPrivateStateFileBounded -> os.OpenInRoot
//
// Both are fixed in 1.25.12 and 1.26.5. This line was 1.26.5 until
// qurl-conformance v0.12.3 relaxed its own directive to 1.25.12: conformance is
// a TEST-ONLY dependency here (no package of it appears in any build graph —
// see `go list -deps ./qurl`), but `go mod tidy` folds a test dependency's
// directive into ours regardless, so its floor was ours. Verified at 1.25.12
// before the change: build, vet, `go test -race ./...` and `make vuln` all
// clean, govulncheck reporting 0 reachable vulnerabilities.
//
// Anything below 1.25.12 reintroduces both CVEs. Before changing this line,
// run `make vuln` at the candidate version.
//
// ./awsstore and go.work sit at this same floor as of awsstore/v0.5.2, but do
// not read that as permanent. awsstore requires the PUBLISHED parent module, so
// it can only follow a root release, never lead one: the next time this line
// moves, awsstore is stranded on the old floor until a root tag ships and the
// lockstep bump lands. That window is why the root CI jobs set GOWORK=off — see
// .github/workflows/ci.yml. Keep it even while the floors agree; it is what
// makes the next reduction possible without breaking every root job.
go 1.25.12

require (
	github.com/layervai/qurl-conformance v0.12.5
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0
