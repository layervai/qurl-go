module github.com/layervai/qurl-go

// This is a SECURITY floor, not a "track the newest toolchain" pin, and not a
// number to lower casually to widen compatibility.
//
// It names the oldest Go patch release free of the standard-library
// vulnerabilities this module's own code actually reaches. CI enforces that:
// setup-go takes its toolchain from this line, so govulncheck runs at exactly
// this version and fails the build if the floor drifts below a fix.
//
// 1.25.13 is the oldest release that qualifies. It fixes the standard-library
// vulnerabilities govulncheck reports as reachable from here:
//
//   - GO-2026-6218, quadratic path resolution in net/url
//   - GO-2026-6090, unbounded post-handshake messages in crypto/tls
//   - GO-2026-5972, unbounded recursion in encoding/asn1
//   - GO-2026-5026, invalid Punycode-label acceptance through net/http
//
// The first three are reached through HTTP/TLS and certificate parsing; the
// fourth is reached through HTTP. 1.25.13 also retains the fixes that made
// 1.25.12 the previous floor (GO-2026-5856 and GO-2026-4970).
//
// Anything below 1.25.13 reintroduces a reachable vulnerability. Before
// changing this line, run `make vuln` at the candidate version.
//
// ./awsstore and go.work sit at this same floor, but do not read that as
// permanent. awsstore requires the PUBLISHED parent module, so a future floor
// reduction cannot reach awsstore until a root tag ships and its parent pin can
// follow. That window is why the root CI jobs set GOWORK=off — see
// .github/workflows/ci.yml. Keep it even while the floors agree; it makes a
// future reduction possible without breaking every root job.
go 1.25.13

require (
	github.com/layervai/qurl-conformance v0.12.7-0.20260822222830-7248e535c5e8
	golang.org/x/crypto v0.55.0
)

require golang.org/x/sys v0.47.0
