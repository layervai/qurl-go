# Changelog

All notable changes to the `qurl` module. The `awsstore` module versions
independently under `awsstore/vX.Y.Z` tags.

Pre-1.0 semantic versioning: breaking changes land in minor versions (v0.N.0)
and are marked **Breaking** with what to change.

## v0.8.1 — 2026-08-25

- Fixed sealed agent state failing to initialize under the macOS App Sandbox.
  Both directory walks in the pinned state path opened a handle for every
  component starting at the filesystem root, which a sandboxed process can
  never do: the sandbox resolves paths *through* ancestors it refuses to open,
  so an app reaches its own container while `openat` on `/Users` is denied.
  A confined process now resumes the walk at the shallowest prefix it can open
  and validates the components in between by absolute path. Recovery engages
  only on a permission denial, so a walk that already succeeds is unchanged and
  no unconfined deployment is affected. Symlinks are still refused by
  `O_NOFOLLOW`, and the skipped region must still be root/euid-owned and closed
  to group and other. An unsafe region now reports itself rather than the
  generic denial that exposed it. (#202)

## v0.8.0 — 2026-08-23

- **Breaking:** registered-agent native knocks now require a positive,
  caller-owned `NativeKnockOptions.RunAttempt` in addition to `RunID`.
  Successful admissions return a nonzero durable `SessionID` and an opaque
  `NativeSessionReceipt` that is bound to the issuing cell, server key,
  issuance time, run id, and attempt. Keep the complete receipt in memory;
  field-only JSON serialization intentionally omits its private route and
  cannot be used for retirement.
- **Breaking:** retire a registered-agent admission with
  `RetireRegisteredAgentSession` only after its resource traffic has stopped
  and drained. Retry the same receipt on ambiguous transport failures until the
  server returns the same durable close event in `closing` or `closed` state,
  then wipe the device private key. The former resource/run-id exit contract is
  removed because it could not identify one admission without affecting a
  replacement or sibling session.
- Registered-agent ACKs now enforce the exact session-receipt success/denial
  union from qurl-conformance v0.13.0. Receipt, resource, address, error, and
  canonical-number drift is rejected before authority is retained; portal and
  generic knock envelopes remain unchanged.

## v0.7.0 — 2026-08-20

- **Breaking:** full qURL links now use the share-safe `qv2t1` fragment
  transport, which chunks all encoded qv2 fields at deterministic
  240-character boundaries. `VerifyLink` and `EnterPortal` reject the
  pre-release `#qv2.<claims>.<secret>.<signature>` full-link transport. The
  canonical qv2 cryptographic fragment and its exact signed claims bytes are
  unchanged. `IsCredentialLink` is the public shape classifier for callers
  that must route credential links to the fail-closed opener instead of a plain
  HTTP fetch. The SDK pins and runs the schema-v2 qURL conformance transport
  vectors at its real decoder boundary.

## v0.6.0 — 2026-08-19

- Added `WithAgentRuntimeEnrollmentCredentialProvider` for callers that mint a
  one-shot enrollment token lazily from the durable agent id. The callback runs
  exactly once under the setup lock only for fresh enrollment or pending-
  activation recovery; the SDK saves the agent id before calling it, requires
  exact-token replay for recovery, never retains the raw token in state, and
  clears the callback from the returned binding's renewal configuration.
  Completed state, pending completion, renewal, and offline open never invoke
  it. Combining it with an eager enrollment credential, an OTP provider, or
  offline open fails with `ErrInvalidRegisterConfig`. An explicitly empty eager
  credential is now treated as configured too, so it fails the same
  contradiction checks instead of being silently treated as absent. (#186)
- **Breaking:** the deprecated `RegisterAgentRuntime` and
  `OpenRegisteredAgentRuntime` entry points are gone, along with the no-op
  `WithAgentRuntimeReassignmentAdoption` and the `AgentRuntimeOpenOption` set
  that existed only for the removed open call. `ConnectAgentRuntime` is the
  single call on every start: pass the credential with
  `WithAgentRuntimeEnrollmentCredential` where you used to pass it
  positionally, and drop the adoption option — following a relocation has been
  the default since v0.3.0. Two error classes shift with the migration: a warm
  open's config faults now classify as `ErrInvalidRegisterConfig` where the
  removed open call used `ErrInvalidClientConfig`, and an option-free call on
  an empty store fails with an error wrapping `ErrAgentStateNotFound` and
  `ErrInvalidRegisterConfig` saying nothing is registered, naming the real
  remedies: enroll out of band (an installer) and reuse its store, or pass
  `WithAgentRuntimeEnrollmentCredential` — with `WithAgentRuntimeOTPProvider`
  for the default account one-time-code enrollment. Once a provider or
  credential is supplied, the usual enrollment-attempt classification applies
  instead. (#184)
- **Breaking:** `WithAgentRuntimeOfflineOpen` now returns
  `AgentRuntimeRegistrationOption` and belongs to `ConnectAgentRuntime` alone.
  Combining it with `WithAgentRuntimeEnrollmentCredential` or
  `WithAgentRuntimeOTPProvider` is a contradiction — enrollment needs the
  network an offline open forbids — and fails with
  `ErrInvalidRegisterConfig`. (#184)
- **Breaking:** `WithAgentRuntimePinnedAssignment` now returns the new
  `AgentRuntimeRenewalOption`, accepted by both entry points that renew an
  assignment — `ConnectAgentRuntime`, `RefreshAgentRuntime` — and a binding
  either returns applies the same policy to its own lease renewals. (#184)
- **Breaking:** `NewStaticProvider` takes a third argument: the cell entries
  the provider serves (pass `nil` to keep the relay-only shape).
  `StaticProvider` now implements `CellProvider`, and the transport rule is
  explicit: a provider without cells serves every open over the HTTPS relay;
  cells plus an allowlist knock catalog cells natively and fall back to the
  relay for the rest; cells alone is native-UDP-only, refusing a link outside
  the catalog with the new `ErrCellNotInCatalog` instead of silently
  downgrading. `DiscoveryProvider` remains relay-only — its manifest format
  carries no cells. **Breaking** reclassification on the pre-existing
  cells-without-allowlist paths too: `EnterPortalWith` with a `Config` carrying
  cells and no allowlist, and a deployment file with cells and no
  `relay_allowlist`, now refuse an out-of-catalog link with
  `ErrCellNotInCatalog` where they previously reported `ErrNotConfigured` —
  update any `errors.Is(err, ErrNotConfigured)` match there. (#184)
- **Breaking:** `ResolveResourceOptions.TTLSeconds int` is now
  `TTL time.Duration`, and `ResolvedAccess.QURL` is renamed `Link`. Zero still
  requests the server default lifetime. The wire carries whole seconds; a
  nonzero TTL with a sub-second remainder is rejected, not rounded. (#184)
- Added `Client.RevokePortal`: revoke one minted link immediately, with the
  same `qurl:write` credential that minted it. It is the single revoke entry
  point for every link the client mints — pass `Portal.ResourceID` and
  `Portal.QURLID` from a create, or the resource id you resolved and
  `ResolvedAccess.QURLID` from a `ResolveResource`. Only the named link dies;
  the resource and its other live links keep working. Revocation is
  deliberately not idempotent — a repeat revoke fails with the new
  `ErrPortalRevoked` sentinel while keeping the underlying `*APIError`
  matchable. (#184)
- Added `ResolvedAccess.QURLID`, the revocation handle for a resolve-minted
  link. Capture it alongside `Link`: neither is retrievable after the resolve
  response. It reads the `qurl_id` field the resolve endpoint now returns, so
  it is empty against a server predating that field — the one case where a
  resolve-minted link still has no individual revocation handle, and deleting
  the resource remains the lever. (#185)
- The Hub trust root is now resolved lazily, exactly where a Hub exchange
  becomes necessary. Opening completed state — warm or offline — no longer
  demands a trust root it would not use; enrollment and expired-lease renewal
  still require one, from `WithAgentRuntimeHub` or the deployment named by
  `QURL_DEPLOYMENT`, and fail with `ErrNoDeploymentHub` when neither is
  available. A fresh enrollment checks the trust root before persisting its
  minted identity, so a hub-less misconfiguration leaves the state store
  untouched. Only the no-hub class defers this way: a `QURL_DEPLOYMENT` file
  that cannot be read or parsed now fails every start at config time with
  `ErrInvalidRegisterConfig`, where a warm start previously succeeded silently
  and returned a binding that could never renew its own lease. (#184)
- `FileCredentials` — and with it `QURL_API_KEY_FILE`, explicit issuer-state
  paths, and `~/.config/qurl/token` — now accepts a file holding the raw
  bearer token, the form the Connector installer writes, alongside the
  existing JSON object with `"bearer_token"` or `"authorization"`. Empty or
  undecodable files now name the accepted formats instead of a bare decode
  error, every malformed credential-file shape — undecodable JSON included —
  now wraps `ErrInvalidClientConfig`, and a UTF-8 byte order mark ahead of a
  JSON envelope no longer misreads the file as a raw token. (#184)
- Tests are hermetic on contributor macOS machines: workflow-contract tests
  that need the GNU `timeout` binary skip with an install hint when it is not
  on PATH, and fixture repositories no longer read the contributor's global or
  system git config. (#184)
- Test renames follow the entry point: `TestRegisterAgentRuntime_*` and the
  runtime-open tests are now `TestConnectAgentRuntime_*`. (#184)
- CI maintenance: restored the credential-free review origin after the pinned
  review action runs, so the workflow's post-review trust guard remains
  meaningful instead of failing on the action's authenticated URL. (#187)

## v0.5.3 — 2026-08-14

- Raised the minimum Go version from 1.25.12 to 1.25.13. This is a security
  patch-floor update: Go 1.25.13 fixes four newly reported standard-library
  vulnerabilities reachable from the root module, including path-resolution,
  TLS post-handshake, ASN.1 recursion, and HTTP hostname-validation issues.
  Builders pinned to 1.25.12 must update their toolchain before upgrading. The
  root module, `awsstore`, and the development workspace remain aligned, and
  CI runs `govulncheck` at exactly the declared floor. (#175)
- Added the public `crid` package for Cryptographic Resource IDs. It provides
  strict `Parse` and `Validate` gates, a cheap `MatchesShape` dispatch check,
  typed rejection sentinels, version and environment reporting, and
  constant-time `KeyMatches` verification. The implementation is pinned to
  the released `qurl-crid-v1-vectors` conformance contract and fails closed
  when a delivered resource key does not match the CRID a caller already
  holds. (#174)
- `Resource` and `ConnectorResource` now carry the server-provided CRID when
  one exists. The field is optional, so older servers and keyless resources
  remain compatible. (#174)
- Added `Client.ResolveResource`, which exchanges either permanent identifier
  form for a fresh temporary access link, and `ResolvedAccess.VerifyCRID`,
  which binds that response to a caller-held resource key before use. A dark
  environment reports the new `ErrTemporaryAccessLinksDisabled` sentinel while
  preserving the underlying `*APIError` for inspection. (#174)
- qurl-conformance pinned at v0.12.5, up from v0.12.3, adopting the released
  `qurl-crid-v1-vectors` contract the new `crid` package is pinned to. (#174)
- Dependency and CI maintenance.

## v0.5.2 — 2026-08-10

- **The minimum Go version is now 1.25.12, down from 1.26.5.** This widens
  support to the whole Go 1.25 line, which matters most if you build on pinned
  or air-gapped CI (`GOTOOLCHAIN=local`) that cannot fetch a 1.26 toolchain.
  The floor remains a *security* floor rather than a preference for the newest
  release: 1.25.12 is the earliest version without the two standard-library
  vulnerabilities this SDK's code paths reach — GO-2026-5856 in `crypto/tls`
  and GO-2026-4970 in `os`, both fixed in 1.25.12 and 1.26.5 — and CI runs
  `govulncheck` at exactly the declared floor. Nothing that built against
  v0.5.1 stops building; this only removes a requirement that was stricter
  than anything in the module graph needed. (#162)
- `ErrInsecureAgentStatePermissions` now names the exact path and the exact
  command. Pointing a store at a path inside a directory that already exists at
  `0755` — a working directory, `$HOME`, anything `mkdir` made under the usual
  umask — failed with `state directory mode is 755, want 700` and left the
  operator to work out both which directory and what to run. It now ends
  `run: chmod 700 <dir>`, and the file-mode and writable-ancestor variants carry
  their own remedies; the ancestor case names the offending ancestor, which no
  `chmod` on the state directory could have fixed. Behavior is unchanged: the
  SDK still fails closed and still creates a missing state directory `0700`
  itself, rather than tightening a directory the caller already uses. (#159)
- An OTP enrollment that runs out its assignment ticket no longer blames the
  caller's callback. The assigned-cell OTP dispatch carries no acknowledgement,
  so "your provider was too slow" and "LayerV never sent the code" are the same
  observation at the client; the error now names both and says to check the
  credential's mailbox before debugging the callback. (#159)
- Corrected the headless enrollment guide, which listed the retired durable
  `agent` kind among the kinds `WithAgentRuntimeHeadlessEnrollment` accepts. It
  accepts `connector_bootstrap` and `bootstrap` only; a legacy `qurl:agent`
  key needs `WithAgentRuntimeAllowedRegistrationKeyKinds`. The option is also
  now documented as replacing the OTP provider and nothing else — every other
  option, `WithAgentRuntimeMetadata` included, stays. (#159)
- README overhaul: architecture diagram and glossary, credential setup via the
  [LayerV dashboard](https://layerv.ai/qurl/dashboard/keys), network
  requirements (outbound-only, NHP over UDP 443), and module/versioning notes.
  The changelog moved from the README to this file. (#150)
- qurl-conformance pinned at v0.12.3, up from v0.12.2. v0.12.3 relaxes its
  own Go directive to 1.25.12, which the floor change above required —
  conformance is test-only, but its directive folds into the root's. (#162)
- Dependency bumps and CI fixes for the JIT proof runner.

## v0.5.1 — 2026-08-05

- One-shot enrollment now names the remedy when the enrollment token was
  already consumed, instead of surfacing a bare deny. (#145)

## v0.5.0 — 2026-08-04

- **Breaking:** retired durable agent-kind enrollment; the default acceptance
  policy is account-only. Enrollments that relied on the durable agent kind
  must re-enroll under an account credential. (#139)
- Native knock denies are now classified and surfaced as `*ServerDenyError`
  instead of being rejected as malformed replies. (#140)
- qurl-conformance pinned at v0.12.2. (#141)

## v0.4.0 — 2026-08-04

- qurl-conformance pinned at v0.12.1, adopting the released conformance
  boundary for the 1.1 wire protocol. (#137)

## v0.3.0 — 2026-08-03

- **Breaking, and it requires action: you must upgrade to keep connecting.**
  The NHP wire protocol moves to 1.1, which authenticates the packet header
  inside the AEAD. 1.0 and 1.1 do not interoperate in either direction and
  there is no compatibility mode, so once LayerV's servers move to 1.1, an
  agent built against v0.2.0 or earlier fails every request with an explicit
  version error. Rebuild against this release and redeploy. Nothing about your
  code changes — no API moved — but a binary that is not rebuilt will not
  reconnect on its own.

  This closes a real defect rather than tidying the wire: under 1.0 the
  header's flag word was covered only by an unkeyed digest, so anyone who knew
  an agent's static public key and sat on the network path could alter how a
  reply was decoded and hand the caller bytes the server never sent.
  Authenticating the header is the fix, and it cannot be done compatibly.
  (#130)
- **Breaking:** enrollment now defaults to the emailed one-time code, for any
  runtime that can read a mailbox rather than humans specifically. A runtime
  with no address in reach opts out with the new
  `WithAgentRuntimeHeadlessEnrollment`; callers that previously enrolled with a
  pre-issued credential and no options must add it. Policy and provider must
  now agree in both directions: accepting the OTP kind without
  `WithAgentRuntimeOTPProvider` fails with `ErrAgentOTPRequired` before any
  network I/O, and installing a provider while excluding that kind is rejected
  as contradictory with `ErrInvalidRegisterConfig`.
- **Breaking:** `OpenRegisteredAgentRuntime` now takes the closed
  `AgentRuntimeOpenOption` set instead of `ClientOption`, matching the other
  lifecycle entry points. `WithAgentClientBaseURL` and
  `WithAgentClientHTTPClient` are unchanged there; generic `WithBaseURL`,
  `WithHTTPClient`, and `WithIssuerStatePath` are now rejected at compile time
  rather than at run time. The resource-only `OpenRegisteredAgent` still takes
  `ClientOption`.
- Added `ConnectAgentRuntime`, the single call a service makes on every start.
  It enrolls when nothing is registered yet (supply the credential with
  `WithAgentRuntimeEnrollmentCredential`), resumes an interrupted enrollment,
  and otherwise returns the existing registration. `RegisterAgentRuntime` and
  `OpenRegisteredAgentRuntime` are deprecated in its favor and unchanged.
- Added the native UDP connection lifecycle for services and agents:
  enrollment, emailed one-time codes, direct connections, strict conformance,
  and crash-safe activation/completion.
- Leases and relocation are now handled for you. Warm open renews an expired
  lease, a held binding renews itself as expiry approaches, re-running the
  connect call is safe on every start, and an authority-directed move is
  followed rather than surfaced. Placement is still only ever taken from an
  authenticated Hub result whose assignment generation advances.
  `WithAgentRuntimeReassignmentAdoption` is now a no-op and deprecated; opt out
  with `WithAgentRuntimeOfflineOpen` or `WithAgentRuntimePinnedAssignment`.
- `AgentRuntimeBinding`'s exported assignment fields are now written once, at
  construction, and never mutated by a renewal. They are safe to read from any
  goroutine; `binding.Assignment()` reports live placement.
- An interrupted registration now finishes at the placement its candidate is
  bound to before placement is reconciled, so a resume recovers a registration
  that was already recorded instead of losing it.
- Registration retries are budgeted per step, so a single call can span
  several of them before giving up. Use an outer context deadline when a
  smaller aggregate wall-clock ceiling is required.

## v0.2.0 — 2026-07-19

- Bounded native registration recovery to 90 days after the first
  authenticated assignment-ticket expiry, with a per-datagram deadline fence,
  immutable replacement anchor, and fail-closed pre-v6 pending-state
  migration.

## v0.1.1 — 2026-07-18

- Destroy the runtime result when setup unlock fails, so no key material
  outlives a failed open. (#88)

## v0.1.0 — 2026-07-17

- Initial tagged release.
- Removed the superseded public HTTP agent assignment/registration lifecycle.
  Everyday resource calls still use HTTPS, and browser behavior is unchanged.
- Added sealed full-`AgentState` storage and AWS-backed `AgentState` stores
  (the `awsstore` module).
