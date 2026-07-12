# qurl-go

**Use the LayerV qURL Platform from Go: protect a private URL once, then mint
short-lived access links for it.**

LayerV hosts qURL. Your Go app keeps a tiny surface area: protect the URL,
create a portal link for the returned resource, and share the link.

Portal recipients do not need LayerV credentials, API keys, keypairs, or SDK
state. They open the qURL link. Credentials are only for software that protects
URLs or creates portals.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/qurl.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why qURL

Agents and services increasingly need to reach private MCP servers, APIs, and
internal tools. The issue is visibility: every standing public endpoint becomes
inventory for scanners, fingerprinting, credential attacks, and AI-assisted
probing before a legitimate user or agent ever arrives.

Opening an inbound port, running a VPN, shipping a bastion, publishing a
Cloudflare Tunnel or ngrok URL, or passing around a long-lived key all leave
something durable to find, scan, or steal. qURL flips that model. It is an
invisibility primitive for authenticated access, not another externally visible
endpoint in front of the same service. The private resource is not public
inventory. A portal is cryptographic, just-in-time permission for one actor to
reach one private resource without turning that resource into public inventory.

## Install

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

Requires Go 1.26+. The SDK depends only on the standard library and
`golang.org/x/crypto`.

## Quickstart

```go
package main

import (
	"context"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

func issuePortal(ctx context.Context) (string, error) {
	client, err := qurl.OpenClient()
	if err != nil {
		return "", err
	}

	resource, err := client.ProtectURL(ctx, "https://internal.example.com/dashboard")
	if err != nil {
		return "", err
	}

	portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
	if err != nil {
		return "", err
	}

	return portal.Link, nil
}
```

That is the core flow:

| Step | Call | What you provide |
| --- | --- | --- |
| Protect a private URL | `client.ProtectURL` | The target URL you already know |
| Mint a short-lived access link | `resource.CreatePortal` | The returned resource handle |

If qURL Connector already protects the service, use its immutable qURL Connector
slug instead of calling `ProtectURL`:

```go
resource, err := client.GetConnectorResourceBySlug(ctx, "prod-dashboard")
if err != nil {
	return err
}

portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
```

If you persist the resource id, future calls do not need to recreate the handle:

```go
resource := client.ResourceByID("r_demo1234567")
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

For one-off scripts, `client.CreatePortalForURL` combines the two API calls and
returns both the portal and a resource handle you can reuse. That handle contains
the resource id and target URL; use `ProtectURL` when you need the full resource
metadata from LayerV.

## Connect to LayerV

Only software that protects URLs or creates portals needs LayerV credentials. A
user or agent that only receives and opens a qURL link does not set up anything.

Before deploying code that calls `OpenClient`, run the LayerV setup flow once
for that service identity. The setup flow consumes the temporary bootstrap key,
registers the service with your LayerV account, and stores the runtime issuer
credential in protected state for the process. After that, application code
starts with:

```go
client, err := qurl.OpenClient()
```

That is the normal application code. You do not paste bootstrap keys into your
app, read `LAYERV_API_KEY`, or ask portal recipients to hold credentials. LayerV
setup turns the one-time key into runtime issuer state; `OpenClient` uses that
state.

If your runtime stores LayerV credentials in KMS, a secret manager, or another
custom store, implement `qurl.CredentialProvider` and pass it to
`qurl.NewClient`. Otherwise use `OpenClient`.

## Register an Agent

For agents that enroll themselves at startup, `qurl.RegisterAgent` is a one-call
front door: hand it an API key and a place to persist state, and it returns a
ready-to-use `Client`.

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")

// error checks elided for brevity — see the guide below for the full pattern
client, err := qurl.RegisterAgent(ctx, apiKey, store)
resource, err := client.ProtectURL(ctx, "https://dashboard.internal.acme.com")
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

`RegisterAgent` is idempotent: the first call enrolls the agent and persists a
device credential; later calls load it and return a `Client` without qURL API
calls. A sealed or network-backed store may still call its key or storage
provider while loading. It picks the enrollment path from the key — a pre-issued
key completes in one headless call, while an account key uses an email one-time
code. The first call emails the code and returns `*qurl.OTPPendingError`; re-run with
`qurl.WithOTP`). Persist the state in a local file, AWS Secrets Manager or SSM
Parameter Store (`github.com/layervai/qurl-go/awsstore`), or any custom
`qurl.AgentStateStore`.

For a durable local file protected by KMS, HSM, or attested key release, use
`qurl.NewSealedFileAgentState`. The SDK encrypts the complete state with a fresh
AES-256-GCM DEK on every save; your provider adapter wraps exactly that 32-byte
DEK and must support both wrap and unwrap for every state-mutating workflow.
Scope provider decrypt permission to one installation when cross-agent envelope
substitution must be prevented; the store authenticates its persisted agent id
and supports an optional `qurl.WithExpectedSealedAgentID` pin for a separately
configured expected id.

REST-only warm starts can call `qurl.OpenRegisteredAgent` without an enrollment
key. qURL Connector runtimes should use `qurl.OpenRegisteredAgentRuntime` to
obtain the Client and validated knock binding from one store load; fresh
installs use `qurl.RegisterAgentRuntime` to receive the same pair without a
post-registration store/KMS reload.
`qurl.RefreshAgentRegistration` explicitly repairs missing/rotated NHP binding
metadata without touching or returning the device credential; its narrow
runtime binding exposes only the identity/NHP data and wipeable private-key
bytes needed for an immediate knock. Meanwhile,
`qurl.RecoverAgentCredential` performs operator-approved same-id credential
replacement after the owner revokes `agent:<device_id>`. Registration and
resource API origins are independent via `WithRegisterBaseURL` and
the dual-purpose `WithAgentClientBaseURL`/`WithAgentClientHTTPClient` options.
After recovery, discard all older clients immediately: they may cache the revoked
credential for one minute, while the returned client cuts over at once.

See [Register an agent](docs/register-an-agent.md) for **which key to use** (one
durable `qurl:agent` key fans out across a whole fleet), both enrollment paths, a
store-by-runtime table, the error table, and migrating from `BootstrapAgent`.

## Opening Links

Most recipients open qURL links directly and do not use this SDK at all. If you
are building a service or agent that opens received qURL links programmatically,
install opener trust config once at startup, then enter portals with one call:

```go
portal, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}
fmt.Println("resource URL:", portal.ResourceURL)
```

`EnterPortal` fails closed when no provider is installed. For tests or manual
configuration, see the opener guide.

## Guides

- [Protect a private service](docs/secure-a-private-service.md)
- [Register an agent](docs/register-an-agent.md)
- [Issue links](docs/issuing-links.md)
- [Open links](docs/opening-links.md)

## Error Handling

Match errors by type, not message text:

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidClientConfig` | Client credentials or options are missing or malformed |
| `qurl.ErrInvalidResourceRequest` | Resource input is invalid before an API request is sent |
| `qurl.ErrInvalidPortalRequest` | Portal input is invalid before an API request is sent |
| `*qurl.APIError` | LayerV returned a non-2xx API response |
| `qurl.ErrNotConfigured` | Opener config is missing |
| `qurl.ErrSignature` / `qurl.ErrUnknownKID` | A received signed link is forged, tampered, or untrusted |
| `*qurl.ServerDenyError` | qURL refused a programmatic open request |

## Security Notes

- Treat LayerV credentials and qURL links like credentials. Do not log them.
- Prefer short portal lifetimes such as `qurl.ValidFor(5*time.Minute)`.
- Keep issuer credentials in protected state, KMS, a secret manager, or another
  protected store.
- Do not ask portal recipients to handle issuer credentials. Recipients only
  need the link.
- Programmatic openers fail closed when trust or access configuration is absent.

## Changes

### Unreleased

- **Added: qURL Connector resource lifecycle** — device-authenticated
  clients can call `EnsureConnectorResource`, `GetConnectorResource`,
  `GetConnectorResourceBySlug`, and `DeleteConnectorResource` without falling back to
  an enrollment credential. The typed result keeps immutable `Slug` separate
  from mutable `Alias`, exposes `KnockResourceID`, and reports whether an ensure
  found an existing active resource. See [Manage qURL Connector
  resources](docs/connector-resources.md).

  **Minimum backend/deployment contract:** this release does not claim the
  backend is deployed or ready to flip. The qurl-service contract fenced by
  [layervai/qurl-service#1192](https://github.com/layervai/qurl-service/pull/1192)
  must be deployed first. Keep `QURL_AGENT_REGISTRATION_ENABLED=false` until
  that service ledger's completion-limiter, trusted-proxy, Redis, abuse-capacity,
  alarm, and cohort hard gates are proven; enable it only when enrollment may
  begin. Service startup with registration enabled also requires
  `QURL_AGENT_BOOTSTRAP_ENABLED=true` plus configured relay and NHP peer
  dependencies. `QURL_AGENT_OTP_ENABLED` is not required for qURL Connector's
  bootstrap-only default; enable it only for intentional account/OTP repair.
  qURL Connector resource ensure/create also requires the producer's existing
  `TUNNEL_AUTH_ENABLED=true` service gate. The resource collection/item routes
  have no new SDK-specific feature flag, but the private producer wire branch
  remains fail-closed behind that existing gate.

  The completion-minted device credential must retain the producer's exact
  URL and qURL Connector resource allow-list (GET/POST resource collection,
  GET/PATCH/DELETE resource item, and the two approved portal-creation writes)
  while denying transit and unclassified routes. `POST /v1/resources`
  find-or-create must preserve the exact `201` success envelope,
  `409 slug_in_use`, and `410 resource_tombstoned` contracts documented here.

- **Added: registered-agent lifecycle APIs** — `OpenRegisteredAgent` provides a
  store-backed reopen without qURL enrollment or resource API calls (a sealed
  store load may still call its key wrapper/KMS);
  `RegisterAgentRuntime` and `OpenRegisteredAgentRuntime` return a primed Client
  plus a validated one-shot runtime key binding without a duplicate store/KMS
  load;
  `RefreshAgentRegistration` forces a real
  REG/RAK binding refresh without completion; and `RecoverAgentCredential`
  performs explicit same-id replacement after owner revoke. Registration key
  kinds can be restricted before OTP/REG side effects, registration and resource
  origins are independent, and post-mint persistence/already-issued failures now
  carry typed recovery guidance. Ambiguous completion transport, unclassified
  5xx, and response failures never auto-retry, and completion cannot replace the
  peer that authenticated the successful RAK.

  **Fleet email-fan-out policy:** account-key OTP remains allowed by default for
  generic `RegisterAgent` compatibility. The repair-oriented
  `RefreshAgentRegistration` and `RecoverAgentCredential` default to
  bootstrap-only; interactive account repair requires explicit
  `WithAllowedRegistrationKeyKinds(RegistrationKeyKindAccount)`. Fleet callers
  should still set the bootstrap-only policy explicitly so routine lifecycle
  code documents and pins its intended trust model.

  This release requires qurl-service registration-info/completion support,
  idempotent same-key REG (including account recovery re-REG after an earlier
  authenticated RAK stopped before completion), device-key revoke that atomically
  clears the first-issue sentinel, and relay REG/RAK routing to be deployed with
  repeated-REG regression coverage before these lifecycle operations are
  enabled. During peer rotation, every qurl-service pod
  serving registration-info and completion must report the same peer key; a
  deployment-skew mismatch after mint fails recovery-required rather than
  silently replacing the RAK-authenticated peer. Registration-info/RAK must
  expose one routable peer deployment: the SDK persists that full host, port,
  and lease and uses completion only to corroborate its decoded public key;
  completion coordinates are ignored. Completion 401/403 responses must be
  emitted only when qurl-service can prove the atomic mint transaction made no
  device-key write, because the SDK classifies them as authoritative no-write
  authentication failures.

  qurl-service's persistent per-owner device cap must return structured HTTP 409
  `device_key_quota_exceeded` only when the atomic mint transaction rejects
  without writing. The SDK maps that exact response to
  `ErrDeviceKeyQuotaExceeded`; operators revoke an existing unused agent device
  key to free a slot, then safely retry.

  Completion HTTP 413 is likewise an authoritative pre-mint admission result and
  maps to `RegistrationRequestTooLargeError` /
  `ErrRegistrationRequestTooLarge` while preserving the underlying `APIError`.

  For `device_key_already_issued`, revoke the active `agent:<device_id>` key
  before `RecoverAgentCredential`. `WithTakeover` alone never clears the issuance
  sentinel; add it after revocation only for a changed-keypair/host rebind. A
  distinct new device id in a separate state store is the only no-revoke
  alternative and represents a separate identity.

  Completion must be excluded from qurl-service's global POST idempotency cache:
  its response reveals a one-time plaintext device secret and must never be
  persisted/replayed or reused across different request bodies. Deploy the
  qurl-service idempotency exclusion and regressions before enabling these SDK
  lifecycle APIs.

- **Added: sealed full-AgentState file storage** —
  `qurl.NewSealedFileAgentState` provides an SDK-owned AES-256-GCM envelope with
  pluggable exact-32-byte DEK wrapping, authenticated agent/provider binding,
  an optional expected-agent-id pin, strict bounded decoding, atomic `0600`
  persistence under a `0700` directory, and mandatory cross-process setup
  locking shared with `FileAgentState`.

- **Added: `qurl.RegisterAgent`** — a one-call, NHP-native front door that
  enrolls an agent and returns a ready-to-use `Client`. It covers both the
  pre-issued-key and email one-time-code paths and is idempotent. See
  [Register an agent](docs/register-an-agent.md).

#### Breaking changes

- **Removed the ambiguous `Client.ConnectorResource` projection.** Use
  `GetConnectorResourceBySlug`, which returns the dedicated
  `ConnectorResource` lifecycle type. The projection's generic
  `ErrResourceNotFound` and `ErrAmbiguousResource` sentinels are replaced by
  `ErrConnectorResourceNotFound` and `ErrConnectorResourceAmbiguous`.

- **`WithNHPPeer` can no longer be replaced by completion.** The override is the
  peer authenticated by REG/RAK and is preserved in durable state. Completion
  must report the same decoded public key; a differing key now fails
  recovery-required after a credential may have been minted. Custom/test
  deployments using a differing override must align their completion response
  before upgrading.

- **HTTP transport errors may carry an internal outcome wrapper.** Resource and
  registration callers should use `errors.Is`/`errors.As` to inspect underlying
  transport and context errors rather than direct concrete type assertions. The
  wrapper lets mutation paths distinguish an outcome that may have committed.

- **`ErrDeviceCredentialMissing` now also matches recovery ambiguity.** Both
  `CredentialPersistenceError` and `CredentialRecoveryRequiredError` preserve
  compatibility by matching that sentinel as well as
  `ErrCredentialRecoveryRequired`. Downstream code must replace any old
  clear/delete-state remediation with owner revoke plus explicit
  `RecoverAgentCredential`; deleting the durable identity is no longer safe.

- **Registration and resource-client overrides are now independent.**
  `WithRegisterBaseURL` and `WithRegisterHTTPClient` affect only
  registration-info, completion, and relay traffic. Callers that previously
  relied on either option to retarget the `Client` returned by `RegisterAgent`
  must also set `WithAgentClientBaseURL` and/or
  `WithAgentClientHTTPClient`.

- **Local AgentState directories and setup locks now fail closed.**
  `FileAgentState` requires its immediate state directory to be exactly `0700`.
  The requirement applies to load and save, so a completed registration under a
  looser directory also fails its read-only fast-path load until the mode is
  corrected. Read-only mounts remain supported only when directory metadata is
  still exactly `0700`; modes such as `0500` or `0555` are also rejected.
  Registration through either SDK local-file store now requires the mandatory
  cross-process sidecar lock to acquire and release successfully. The underlying
  `flock` is OS-advisory; "mandatory" means cooperating SDK setup refuses to run
  without it, not that the kernel blocks non-cooperating writers. Unsupported
  platforms or insecure lock paths return `ErrAgentSetupLock` instead of
  continuing without serialization. On Windows, Plan 9, and js/wasm the SDK has
  no local-file lock implementation, so fresh or incomplete `RegisterAgent` and
  `BootstrapAgent` setup with `FileAgentState` or `NewSealedFileAgentState` stops
  with that error; use a custom/network `AgentStateStore` (including `awsstore`
  where applicable) and serialize setup at the store boundary. A completed
  registration takes the lock-free read-only fast path, and direct local-store
  load/save is unaffected.
- **Agent enrollment moved to `api.layerv.ai`.** Enrollment is now NHP-native
  and its endpoints live on the main API origin. The default `BootstrapAgent`
  origin changed from the dedicated bootstrap host to `api.layerv.ai`; callers
  pinning `WithBootstrapBaseURL("https://bootstrap.layerv.ai")` must migrate
  (drop the override or point it at the current API origin).
- **The legacy `POST /v1/agent/bootstrap` HTTP path is removed.** Enrollment now
  runs over NHP, so the backend NHP endpoints must be deployed before this
  version of the SDK can register or bootstrap an agent. `BootstrapAgent` still
  works (now over NHP), but prefer `RegisterAgent` for new code.

  `AgentState` on disk is unaffected — the schema change is additive and
  backward compatible, so existing state files load without migration.

## License

[MIT](LICENSE) © LayerV AI
