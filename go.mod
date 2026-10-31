module github.com/layervai/qurl-go

// This is a security floor, not a request to track the newest toolchain.
// Go 1.26.10 matches the reviewed root security floor. CI govulncheck found
// eight reachable standard-library vulnerabilities at the previous 1.25.13
// floor. Keep CI on this directive and run `make vuln` before lowering it.

//
// ./awsstore and go.work sit at this same floor, but do not read that as
// permanent. awsstore requires the PUBLISHED parent module, so a future floor
// reduction cannot reach awsstore until a root tag ships and its parent pin can
// follow. That window is why the root CI jobs set GOWORK=off — see
// .github/workflows/ci.yml. Keep it even while the floors agree; it makes a
// future reduction possible without breaking every root job.
go 1.26.10

require (
	github.com/layervai/qurl-conformance v0.13.0
	golang.org/x/crypto v0.55.0
)

require golang.org/x/sys v0.47.0
