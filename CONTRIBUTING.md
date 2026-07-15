# Contributing to qurl-go

Thanks for helping improve the qURL Go SDK. This SDK is a security core, so the bar
is high — but the workflow is simple: one command runs everything CI runs.

> **Public surface vs. internals.** Integrators import the single public package,
> `qurl`. The cryptographic core lives in `internal/qv2` and the NHP transport in
> `relayknock`; `qurl` re-exports exactly the surface callers need (see
> [`qurl/facade.go`](qurl/facade.go)). New customer-facing API belongs on `qurl`.

## The one quality gate

```sh
make check   # tidy + format + lint + race tests + vuln scan
make help    # list all targets
```

`make check` is the single gate. A green local run means a green CI, because both run
the same pinned tools at the same versions. Run it before opening a PR.

> **Tip:** if `golangci-lint` reports issues in files outside this checkout (e.g. a
> sibling Git worktree), clear its cache with `./.tools/golangci-lint cache clean`
> and re-run — a stale analysis cache can leak results across worktrees.

### Individual targets

| Target       | What it runs                                                    |
| ------------ | -------------------------------------------------------------- |
| `make test`  | `go test -race ./...`                                          |
| `make cover` | race tests with a coverage profile + HTML report               |
| `make lint`  | `golangci-lint run` (lint **and** gofumpt/goimports formatting) |
| `make fmt`   | apply gofumpt + goimports formatting                           |
| `make vuln`  | `govulncheck ./...` — known-vuln scan of called code           |
| `make fuzz`  | run the parser fuzz targets (auto-discovered)                  |

Dev tools (`golangci-lint`, `govulncheck`) are version-pinned in the
[`Makefile`](Makefile) and installed on demand into a git-ignored `./.tools`.

## Runnable examples

The customer-facing documentation examples live as compile-checked `Example` functions
in [`qurl/example_test.go`](qurl/example_test.go); the cryptographic core has its own
tests under [`internal/qv2`](internal/qv2). The `qurl` examples run under `go test` and
appear on [pkg.go.dev](https://pkg.go.dev/github.com/layervai/qurl-go/qurl), so they
can never drift out of sync with the API. When you change public behavior, update (or
add) an example and keep its `// Output:` accurate.

## Static analysis

The linter set ([`.golangci.yml`](.golangci.yml)) is curated for a security core, not
maximal: error-handling and nil correctness (`errcheck`, `errorlint`, `nilerr`,
`nilnil`, `bodyclose`), security (`gosec`, `bidichk`, `forcetypeassert`), and
correctness footguns (`durationcheck`, `makezero`, `wastedassign`, …) on top of
`go vet` with nearly all analyzers enabled. The bar is **zero issues with no blanket
suppressions** — the crypto core passes `gosec` clean.

## Fuzzing

The internal strict link parser ([`internal/qv2`](internal/qv2)) is the SDK's
hostile-input surface, so it carries Go native fuzz targets
([`internal/qv2/fuzz_test.go`](internal/qv2/fuzz_test.go)) for the fragment parser,
the claims walker, and the canonical-base64url decoder. The committed seed corpus
under `internal/qv2/testdata/fuzz` includes regression crashers (e.g. the embedded-newline
base64 malleability case), which the normal `go test` run replays even without
`-fuzz` — this corpus replay is the deterministic regression gate. Live fuzzing runs
as a nightly soak ([`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)) rather
than a PR gate, so a newly-discovered (possibly unrelated) crasher never reds an
otherwise-good PR.

Run the fuzzers locally for longer than the CI smoke duration:

```sh
make fuzz FUZZTIME=2m
```

## Conformance vectors

The language-agnostic qURL vectors—including the registered-agent application
body/RunID contract—plus the packet and signature golden files come from the public
[`qurl-conformance`](https://github.com/layervai/qurl-conformance) module via
`go:embed` accessors. The bytes are pinned by the dependency version in `go.sum`, so
adopting an updated artifact is a dependency bump.

## Continuous integration

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs lint, race tests +
coverage (with corpus replay), and a blocking `govulncheck` on every PR and on `main`.

Because `govulncheck` is blocking, a newly published stdlib or dependency advisory can
turn CI red with no code change — resolve it by bumping the `go` directive in
[`go.mod`](go.mod) (the single source of the toolchain version) or the affected
dependency.

## Dependency policy

The verification core is deliberately dependency-light: the internal crypto core is
standard-library only, and `relayknock` adds only `golang.org/x/crypto`. Keep it that
way — the issuer signing key is reached through the `qurl.Signer` interface, never a
baked-in KMS client, so a KMS/HSM integration lives in your code, not in this module's
dependency graph.

## Pull requests

- Keep changes focused and reviewable; the crypto core lands in small, well-tested steps.
- Follow the [PR title convention](.github/PULL_REQUEST_TEMPLATE.md) (Conventional Commits).
- Include or update tests, and an `Example` when you touch public behavior.
- Make sure `make check` is green.
