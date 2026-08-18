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
[![Go 1.25.13+](https://img.shields.io/badge/go-1.25.13%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why qURL

Agents and services increasingly need to reach private MCP servers, APIs, and
internal tools. Every standing public endpoint becomes inventory for scanners,
fingerprinting, and credential attacks before a legitimate user or agent ever
arrives. VPNs and identity-aware proxies authenticate that inventory; they do
not remove it — the listener is still there to find, probe, and exploit.

qURL removes the inventory. A protected service holds only an outbound
connection, so there is no open port, no public DNS, and nothing for a scanner
to enumerate. A portal is cryptographic, just-in-time permission for one actor
to reach one private resource, and it expires on the schedule you set.

## How it fits together

```
┌─────────────┐  1. ProtectURL / CreatePortal (HTTPS)  ┌──────────────────┐
│ your Go app │ ──────────────────────────────────────▶│                  │
│ (this SDK)  │ ◀───────────── portal link ────────────│   LayerV qURL    │
└─────────────┘                                        │    Platform      │
┌─────────────┐  3. open the link                      │                  │
│  recipient  │ ──────────────────────────────────────▶│                  │
└─────────────┘  browser: HTTPS (qurl.link)            └────────▲─────────┘
                 program: EnterPortal (native UDP)              │
                                                                │ 2. outbound-only
                                                                │    NHP, UDP 443
┌───────────────────────────────────────────────┐               │
│ your private network                          │               │
│   private service ◀─── qURL Connector or ─────┼───────────────┘
│                        your own agent runtime │
└───────────────────────────────────────────────┘
```

Three roles, three sections of this README:

1. **Issue** — your app calls `ProtectURL` and `CreatePortal` over HTTPS and
   gets back a link. ([Quickstart](#quickstart))
2. **Serve** — the private service sits behind
   [qURL Connector](https://github.com/layervai/qurl-connector) or your own
   agent built with this SDK. Either way it dials *out* to LayerV and holds
   that connection; nothing listens. ([Connect a service or agent](#connect-a-service-or-agent))
3. **Open** — the recipient opens the link in a browser, or a program calls
   `EnterPortal`. LayerV verifies the portal and stitches recipient ↔ agent ↔
   service for the portal's lifetime. ([Opening links](#opening-links))

| Term | Meaning |
| --- | --- |
| **Resource** | A private URL LayerV protects. Identified by a stable resource id, never by a public address. |
| **Portal** | A short-lived signed link granting one actor access to one resource. |
| **Issuer** | Software holding LayerV credentials that protects URLs and creates portals. |
| **Connector** | LayerV's ready-made agent that publishes services from inside your network. |
| **Agent runtime** | Your own service enrolled directly with `ConnectAgentRuntime`. |

And every entry point in one place:

| Entry point | When to use it | Returns |
| --- | --- | --- |
| `OpenClient` / `OpenClientContext` | Issue links with the default credential chain ([Get a credential](#get-a-credential)); the context form bounds the eager startup check | `*Client` |
| `NewClient` | Issue links with your own `CredentialProvider` (KMS, a secret manager) | `*Client` |
| `ConnectAgentRuntime` | Run your own agent: one call on every start that enrolls, resumes, or reopens as needed | `*Client`, `*AgentRuntimeBinding` |
| `OpenRegisteredAgent` / `OpenRegisteredAgentWithIdentity` | Resource-only client from completed agent state — one store load, no lifecycle network I/O, no knockable binding | `*Client` (`WithIdentity` adds the agent id) |
| `RefreshAgentRuntime` | Renew a completed assignment through the Hub at a moment you choose | `*Client`, `*AgentRuntimeBinding` |
| `RecoverAgentRuntime` | Operator-driven replacement of a revoked or lost device credential | `*Client`, `*AgentRuntimeBinding` |
| `EnterPortal` | Open a received qURL link programmatically; needs no LayerV credentials | `*ResourceHandle` |

## Install

qurl-go is a library — there is no binary to `go install`. From inside your
module:

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

Requires Go 1.25.13+ — a security floor, not a preference for the newest
toolchain. It is the earliest patch release without the currently known
standard-library vulnerabilities this SDK's code paths reach; CI runs
`govulncheck` at exactly this version. Anything older reintroduces at least one
reachable vulnerability. See the comment above the `go` directive in
[go.mod](go.mod) for the advisory list and full rationale.

Not in a module yet? Run `go mod init example.com/myapp` first: `go get`
outside a module fails with `go.mod file not found`, and
`go install .../qurl@latest` fails with `is not a main package` because nothing
here builds a command.

| Module | Purpose |
| --- | --- |
| `github.com/layervai/qurl-go/qurl` | The SDK. Zero AWS dependencies. |
| `github.com/layervai/qurl-go/crid` | The Cryptographic Resource ID codec: strict local validation, environment reporting (`production`, `test`, or `unknown`), and the delivered-key match rule. No dependencies beyond the standard library. |
| `github.com/layervai/qurl-go/awsstore` | AWS-backed agent state (Secrets Manager, SSM, KMS sealing). A [separate module](awsstore/README.md) so the AWS SDK never leaks into `qurl`. |

## Get a credential

Create an API key in the [LayerV dashboard](https://layerv.ai/qurl/dashboard/keys)
with the `qurl:write` scope. No credit card — the free tier includes 500 qURLs
a month.

`OpenClient` resolves credentials in this order, most specific first:

1. An explicit `qurl.WithIssuerStatePath(...)` option
2. `QURL_API_KEY` — the key itself, for containers and CI
3. `QURL_API_KEY_FILE` — a path, for mounted secrets that should stay on disk
4. `~/.config/qurl/token` — what the qURL Connector installer already wrote
5. `/var/lib/layerv/qurl/issuer-state.json` — the machine-wide default

A credential file — whichever source names it — holds either the raw bearer
token itself (the form the Connector installer writes) or a JSON object with a
`"bearer_token"` or `"authorization"` field; both are accepted everywhere a
file is read.

For credentials held in KMS or a secret manager, implement
`qurl.CredentialProvider` and pass it to `qurl.NewClient` instead.

## Quickstart

```sh
export QURL_API_KEY="<key from https://layerv.ai/qurl/dashboard/keys>"
```

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

func main() {
	ctx := context.Background()

	client, err := qurl.OpenClient()
	if err != nil {
		log.Fatal(err)
	}

	resource, err := client.ProtectURL(ctx, "https://internal.example.com/dashboard")
	if err != nil {
		log.Fatal(err)
	}

	portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(portal.Link) // share this; it expires in 5 minutes
}
```

`ProtectURL` is idempotent: it returns the existing resource when the same URL
is already registered for your account.

If qURL Connector already protects the service, use its immutable connector
slug:

```go
resource, err := client.GetConnectorResourceBySlug(ctx, "prod-dashboard")
if err != nil {
	return err
}
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
```

If you persist the resource id, future calls can reconstruct the handle without
another lookup:

```go
resource := client.ResourceByID(resourceID)
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

`CreatePortal` and `Client.ResolveResource` both mint an access link.
`CreatePortal` is the portal-options path on a resource handle;
`ResolveResource` is the stored-identifier path — it accepts the resource id or
the resource's CRID and returns a `ResolvedAccess` whose CRID you can verify
against a key you already hold (`VerifyCRID`). Both leave the link lifetime to
the server default unless you ask (`ValidFor` on a portal,
`ResolveResourceOptions.TTL` on a resolve).

Next: [Protect a private service](docs/secure-a-private-service.md) ·
[Issue links](docs/issuing-links.md)

## Connect a service or agent

The easiest way to put a service behind qURL is
[qURL Connector](https://github.com/layervai/qurl-connector) — install it next
to the service and skip this section. Use this SDK's agent runtime when you
want the service itself to hold the connection, with no sidecar.

Your service registers once, then keeps serving. Registration happens over an
authenticated UDP channel — no inbound ports, no public endpoint, nothing for a
scanner to find.

Enrollment authenticates against the Hub trust root in your deployment file, so
point `QURL_DEPLOYMENT` at the file from LayerV setup (or pass
`WithAgentRuntimeHub`); GA builds will ship the trust root baked into the SDK,
at which point this step disappears. A completed registration whose lease is
live reopens without it.

```sh
export QURL_DEPLOYMENT=/etc/layerv/qurl/deployment.json
```

```go
store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
if err != nil {
	return err
}
defer store.Close()

client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
	qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredential),
	qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
	qurl.WithAgentRuntimeMetadata(hostname, version),
)
if err != nil {
	return err
}
defer binding.Destroy()
```

That — plus the deployment file — is the whole enrollment. Run it on every
start, under a supervisor, and stop thinking about the lifecycle:

- Restarts are safe — it enrolls only when nothing is registered yet.
- Crashes and dropped replies resume the same registration, for up to 90 days.
- Leases renew themselves, at startup and mid-run.
- Relocations are followed automatically, and only ever to a placement named in
  an authenticated LayerV reply — never a guessed or config-supplied address.

Keep the state file across restarts, and keep the metadata stable: the file is
what makes a resume possible, and the hostname and version become part of the
saved registration.

**The one-time code.** Enrollment defaults to emailing a code to the address on
your credential; `readOneTimeCode` is the callback you write to return it —
poll a mailbox, page an operator, your call. It should return exactly 8 decimal
digits and honor its context. Runtimes with no mailbox in reach (sealed
appliances, air-gapped builders) enroll with a pre-issued credential and swap
`WithAgentRuntimeOTPProvider` — that line only — for
`WithAgentRuntimeHeadlessEnrollment()`: an explicit opt-out, mutually exclusive
with an OTP provider, and not a shorter form of the call. Every other option
stays, `WithAgentRuntimeMetadata` included. Not sure which credential kind you
hold? Run the default and read the error; a wrong first guess costs nothing and
the retry reuses the same agent identity. The
[Connect a service or agent](docs/register-an-agent.md) guide has every path,
including renewing without holding an enrollment credential at runtime and
[taking manual control](docs/register-an-agent.md#taking-manual-control) of
renewal.

**Credentials are LayerV-minted tokens** of at least 32 characters. Passwords
and hand-picked strings are rejected before anything is saved or sent.

> **Network requirements.** Everything the SDK dials is outbound: HTTPS to
> `api.layerv.ai` for issuing, and NHP over **UDP 443** to LayerV hosts under
> `layerv.ai` for registration and native opens. No inbound ports, no
> listeners. If registration fails with `ErrEndpointNoReply`, the usual cause
> is an egress firewall silently dropping UDP 443 — the error names the exact
> host to allow. Two LayerV-internal names appear in those errors and in
> deployment files, and rarely in code you write — pinned openers
> (`CellEntry`) and self-hosted deployments (`HubBootstrap`) are the
> exceptions: the **hub** is where an agent registers, and it assigns the
> agent a **cell**, which carries its portal traffic from then on.

## Opening links

Most recipients open qURL links directly in a browser and do not use this SDK.
Programmatic recipients call:

```go
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}
resp, err := httpClient.Get(handle.ResourceURL) // httpClient is your own *http.Client
```

That is the whole integration, and it needs no LayerV credentials. `EnterPortal`
checks that the link was really issued by LayerV, then opens it over a direct
UDP connection. Browsers cannot send UDP, so links opened in a browser go
through an HTTPS path instead. In this SDK the resolved config decides the
transport: a link naming a cell the config lists is knocked directly over UDP,
anything else uses the HTTPS relay when a relay allowlist is configured — and a
cells-only config refuses such a link with `ErrCellNotInCatalog` rather than
silently downgrading (see
[docs/opening-links.md](docs/opening-links.md#pinning-the-opener-trust-config)).

The opener trust configuration — which issuer keys to verify links against and
which cells to reach — resolves most specific first: a `Provider` installed
with `SetDefaultProvider`, then a JSON file named by `QURL_DEPLOYMENT`, then
the deployment embedded in the build
([qurl/deployment.json](qurl/deployment.json)). The Hub trust root for agent
registration is not provider-supplied: it comes only from `QURL_DEPLOYMENT`,
the embedded deployment, or an explicit `WithAgentRuntimeHub`
(`RefreshAgentRuntime` takes a `HubBootstrap` argument) — an installed
`Provider` affects opener config only. Current releases embed an empty
deployment, so native opens and agent registration need a deployment file from
LayerV setup until a populated one ships in the SDK. The issuer HTTPS endpoint
is configured separately with `WithBaseURL`. A resolved deployment with no
issuer keys fails closed (`ErrNotConfigured`) rather than open a link it
cannot verify.

## Error handling

Match errors by type or sentinel, not message text. Grouped by the scenario
that raises them:

**Issuing — credentials and the HTTPS resource API**

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidClientConfig` | Resource-client credentials or options are malformed |
| `qurl.ErrInvalidPortalRequest` | A portal input is invalid; rejected before any API request is sent |
| `*qurl.APIError` | LayerV returned a non-2xx steady-state resource response |

**Opening links**

| Error | Meaning |
| --- | --- |
| `qurl.ErrNotConfigured` | A required piece of opener or deployment configuration is absent; the SDK fails closed rather than open a link it cannot verify |
| `qurl.ErrNoDeployment` | The resolved deployment carries no issuer keys — this build ships none and `QURL_DEPLOYMENT` is unset, or the named deployment file has empty `issuers`. Wraps `ErrNotConfigured` |
| `qurl.ErrSignature` | The link's issuer signature does not verify: forged, tampered, or signed by a key that is not the trust store's value for that kid |
| `qurl.ErrUnknownKID` | The link's kid is not in the trust store |
| `qurl.ErrCellNotInCatalog` | A verified link names a cell the cell catalog has no endpoint for, and no relay allowlist is configured. A cells-only opener refuses the open rather than silently downgrading to the HTTPS relay |
| `*qurl.ServerDenyError` | An authenticated platform deny: the reply verified, but access was refused — an expired, revoked, or consumed qURL, or a server-side access check. Also raised by the registered-agent knock path (`KnockRegisteredAgent`) when the assigned cell denies an admission |

**Agent lifecycle — `ConnectAgentRuntime`, refresh, recovery, knock**

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidRegisterConfig` | Native lifecycle inputs are malformed |
| `qurl.ErrNoDeploymentHub` | No Hub trust root is available: set `QURL_DEPLOYMENT` to a deployment file with a `"hub"`; `ConnectAgentRuntime` also accepts `WithAgentRuntimeHub`, and `RefreshAgentRuntime` takes a `HubBootstrap` argument. Wraps `ErrNotConfigured`; raised only by a start that actually needs a Hub exchange |
| `qurl.ErrAgentOTPRequired` | OTP enrollment — the default — was attempted without an OTP callback; install `WithAgentRuntimeOTPProvider`, or pass `WithAgentRuntimeHeadlessEnrollment` if this runtime cannot receive a code |
| `qurl.ErrInsecureAgentStatePermissions` | The state directory or file is readable beyond its owner. The message names the exact `chmod` to run; the SDK never widens or tightens a path you already own |
| `qurl.ErrAssignmentRecoveryRequired` | Registration ran out of retries; start recovery |
| `qurl.ErrEndpointNoReply` | The host resolved and every datagram was sent, but nothing answered: the server is down or the network path drops UDP to it silently. `*qurl.EndpointNoReplyError` carries the destination and attempt count |
| `qurl.ErrAgentBindingPersistence` | A state save failed or its acknowledgement was lost; reload before retry because the refreshed assignment may already be durable |
| `qurl.ErrCompletionRecoveryRequired` | Resume the exact persisted completion candidate |
| `qurl.ErrAgentRecoveryExpired` | This registration is older than 90 days and can no longer be resumed; enroll again |
| `qurl.ErrAgentRecoveryMigrationRequired` | Saved state predates the current format; keep the file and enroll again |
| `*qurl.NativeCredentialRecoveryRequiredError` | Completed native credential state is absent or malformed; explicit native recovery or reprovisioning is required |
| `*qurl.AgentAssignmentChangedError` | A renewal pinned with `WithAgentRuntimePinnedAssignment` — in `ConnectAgentRuntime` or `RefreshAgentRuntime`, or a binding either returned — found that LayerV moved your service; drop the option to follow the move |

**Resolve and CRID**

| Error | Meaning |
| --- | --- |
| `qurl.ErrTemporaryAccessLinksDisabled` | `ResolveResource` got a 503: the environment is not serving temporary access links. The underlying `*APIError` stays matchable |
| `qurl.ErrNoCRID` | `VerifyCRID` had no CRID to check against — the server omitted it (older server or keyless resource). Fails closed: absence is not a mismatch, but it is not a pass |
| `qurl.ErrCRIDMismatch` | The supplied resource key does not derive the held CRID — the substitution the identifier exists to detect. Do not use the key |

## Security notes

- Treat LayerV credentials, agent state, and qURL links like credentials. Do
  not log them.
- Never guess or construct LayerV addresses yourself; use what the SDK
  resolves from your deployment and from authenticated LayerV replies.
- Keep saved registration state across an unclear reply, and keep the exact
  pending completion candidate across ambiguous completion delivery.
- Call `binding.Destroy()` when done. If you took key ownership with
  `binding.TakeDeviceStaticPrivateKey()`, zero the returned slice yourself once
  the knocker no longer needs it.
- Keep issuer credentials in protected state, KMS, a secret manager, or another
  protected store — see [awsstore](awsstore/README.md) for AWS-backed options.
- Links opened in a browser (HTTPS) and services connected natively (UDP) are
  separate trust paths; neither configures the other.

Revocation today is asymmetric. `DeleteConnectorResource` revokes a connector
resource immediately (see
[Manage qURL Connector resources](docs/connector-resources.md)); portals and
qURLs have no SDK revoke call yet, so a minted link stays valid until it
expires. Pick lifetimes accordingly — `ValidFor` and `OneTimeUse` are the
controls you have at mint time.

## Guides

- [Protect a private service](docs/secure-a-private-service.md)
- [Connect a service or agent](docs/register-an-agent.md)
- [Manage qURL Connector resources](docs/connector-resources.md)
- [Issue links](docs/issuing-links.md)
- [Resolve a resource and verify its CRID](docs/resolve-and-crid.md)
- [Open links](docs/opening-links.md)
- [Testing against NHP](docs/testing-against-nhp.md) — loopback suites for most
  work, live sandbox for interop
  ([ADR 0001](docs/decisions/0001-sandbox-nhp-access.md))

Platform docs, the API reference, and the playground live at
[layerv.ai/start](https://layerv.ai/start).

## Versioning

Pre-1.0 semantic versioning: breaking changes land in minor versions (v0.N.0)
and are flagged in the [changelog](CHANGELOG.md) with what to change. Wire
compatibility is pinned by authenticated golden vectors from
[qurl-conformance](https://github.com/layervai/qurl-conformance); releases that
move the wire protocol say so loudly and name the flag day.

## License

[MIT](LICENSE) © LayerV AI
