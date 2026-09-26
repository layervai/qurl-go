module github.com/layervai/qurl-go

// This is a SECURITY floor, not a "track the newest toolchain" pin, and not a
// number to lower casually to widen compatibility.
//
// It names the oldest Go patch release free of the standard-library
// vulnerabilities this module's own code actually reaches. CI enforces that:
// setup-go takes its toolchain from this line, so govulncheck runs at exactly
// this version and fails the build if the floor drifts below a fix.
//
// The floor is on the Go 1.26 line because golang.org/x/crypto v0.57.0 and
// golang.org/x/sys v0.48.0 declare go 1.26.0, and Go 1.25 is out of support
// since Go 1.27 shipped.
//
// 1.26.6 is the oldest 1.26 release that qualifies. It fixes the
// standard-library vulnerabilities govulncheck reports as reachable from here:
//
//   - GO-2026-6218, quadratic path resolution in net/url
//   - GO-2026-6090, unbounded post-handshake messages in crypto/tls
//   - GO-2026-5972, unbounded recursion in encoding/asn1
//   - GO-2026-5026, invalid Punycode-label acceptance through net/http
//
// The first three are reached through HTTP/TLS and certificate parsing; the
// fourth is reached through HTTP. 1.26.5 still reports all four, and 1.26.4
// additionally reports GO-2026-5856 and GO-2026-4970.
//
// Anything below 1.26.6 on the 1.26 line reintroduces a reachable
// vulnerability. The 1.25 line is excluded because it is out of support and
// below the go 1.26.0 that x/crypto and x/sys declare, not because 1.25.13 is
// itself vulnerable. Before changing this line, run `make vuln` at the
// candidate version.
//
// ./awsstore and go.work sit at this same floor, but do not read that as
// permanent. awsstore requires the PUBLISHED parent module, so a future floor
// reduction cannot reach awsstore until a root tag ships and its parent pin can
// follow. That window is why the root CI jobs set GOWORK=off — see
// .github/workflows/ci.yml. Keep it even while the floors agree; it makes a
// future reduction possible without breaking every root job.
go 1.26.6

require (
	github.com/layervai/qurl-conformance v0.17.0
	golang.org/x/crypto v0.57.0
)

require golang.org/x/sys v0.48.0
