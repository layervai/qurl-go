# qURL Go SDK for private service access

Use [qURL™ by LayerV](https://layerv.ai/qurl/) to share localhost web apps,
private APIs, and files through expiring access links. This
[Go SDK](https://layerv.ai/sdk/) creates access links, enrolls agents,
authorizes access, and opens received links from Go
applications. The `github.com/layervai/qurl-go/qurl` package supports the issuer,
agent, and recipient roles described below.

LayerV hosts qURL. To issue a link, your Go app protects a URL, creates a portal
for the returned resource, and shares the link. Serving a local app also needs
a running Connector to forward HTTP traffic; issuing the link does not start
the app or close an existing public route. The app's own sign-in requirements
still apply.

For a ready-made command to publish localhost, use the
[qURL CLI](https://github.com/layervai/qurl-integrations/tree/main/apps/cli).
The CLI embeds [qURL Connector](https://github.com/layervai/qurl-connector).
This SDK supplies link operations and agent enrollment and admission for Go software.

Start with [installation](#install), the [link quickstart](#quickstart),
[connecting a service or agent](#connect-a-service-or-agent),
[opening links](#opening-links), or the [guides](#guides).

Portal recipients do not need LayerV credentials, API keys, keypairs, or SDK
state. They open the qURL link. Credentials are only for software that protects
URLs or creates portals.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/qurl.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26.10+](https://img.shields.io/badge/go-1.26.10%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Local preview workflow](#share-a-localhost-preview-from-go) ·
[File access](#share-or-open-files-from-go) ·
[Sharing questions](#go-sharing-questions) · [Private links](https://qurl.link/)

## Share a localhost preview from Go

For a ready-made preview, publish the running app with the
[qURL CLI quickstart](https://github.com/layervai/qurl-integrations#share-a-localhost-web-app).
Use the Go SDK when you want your service to issue links, manage agent
enrollment and admission, or consume access programmatically:

| Use case | Go SDK role | Start here |
| --- | --- | --- |
| Issue a reviewer a short-lived link to a configured local preview | Issuer | Use a resource the issuer credential can manage, then create a portal. |
| Enroll an agent and request permission to serve a resource | Agent | Configure durable state and enroll or resume the [agent runtime](#connect-a-service-or-agent). HTTP forwarding requires the Connector runtime. |
| Let automation read a private API or download from a private file service | Recipient | Open and verify the received link, then authorize content requests as in [opening links](#opening-links). |

For an SDK-managed Connector resource that already exists, this helper looks
up its immutable slug and requests a five-minute access link. The caller
supplies an issuer client and context configured for its deployment:

```go
package preview

import (
	"context"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

func LinkForPreview(ctx context.Context, client *qurl.Client, connectorSlug string) (string, error) {
	resource, err := client.GetConnectorResourceBySlug(ctx, connectorSlug)
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

The slug and credential must identify a compatible, authorized Connector
resource. A CLI CRID is not a Connector slug and does not grant issuer
authority. For a resource published solely through the CLI, `qurl share` is
the direct link-issuing path; configure compatible SDK resource management
before using the helper above.

Keep the returned link private and keep the local service and runtime running.
Creating a portal does not start a server, enroll an agent, or close another
public route. See [quickstart](#quickstart) for client credentials and
[connecting a service](#connect-a-service-or-agent) for the required runtime.

## Share or open files from Go

To share files hosted on your machine, serve a dedicated directory through a
local HTTP app and publish its root address with the
[CLI file-sharing workflow](https://github.com/layervai/qurl-integrations#share-files-and-documents).
To upload supported documents or images, use the
[MCP upload tools](https://github.com/layervai/qurl-mcp#let-an-ai-agent-share-a-pdf-or-image)
or the [Gmail integration](https://github.com/layervai/qurl-integrations/tree/main/apps/chrome-extension).

This SDK can issue access for a compatible registered file-serving resource
and open received links. Its portal APIs do not upload a local file. An upload
service's identifiers and link-minting contract are not automatically the same
as a Connector resource's.

For a programmatic download, follow [opening links](#opening-links): verify the
qURL, authorize the HTTP request through the returned resource handle, and
apply its redirect checks. An HTTP GET of the browser share URL alone fetches
the opening page, not the protected file. Retain the documented session state
when one logical visit needs retries; opening a single-use link again can fail.

## Manage resources, links, and sessions

Use the same authenticated `Client` for management. `ProtectURL` creates or
reuses a URL resource, and `CreatePortal` mints a link. These additional methods
read or change resources you can manage:

| Task | Method |
| --- | --- |
| List resource metadata | `ListResources` |
| Read one resource and its bounded link preview | `GetResource` |
| Update metadata, tags, or alias | `UpdateResource` |
| Revoke the entire resource | `RevokeResource` |
| List all link summaries in pages | `ListPortals` |
| Read one page of sessions | `ListSessions` |
| Terminate one session | `TerminateSession` |
| Terminate one page of sessions | `TerminateSessions` |

Pass the response's `crid` as the resource identifier. Management methods also
accept a legacy resource public key. Page results keep the API's `meta`,
including `request_id` and the opaque `next_cursor`:

```go
page, err := client.ListPortals(ctx, resourceCRID, qurl.PageOptions{
    Limit: 20,
    Cursor: previousCursor,
})
if err != nil {
    return err
}
for _, link := range page.Data {
    fmt.Println(link.QURLID, link.Status)
}
```

Follow `NextCursor` even when a filtered page has no items. A nil `HasMore` or
`QURLCount` means the service did not report that value. `GetResource` returns
a bounded, unordered link preview; a missing link in that preview does not
prove revocation. Use `ListPortals` for complete paginated reads.

`ManagedResource` preserves omitted fields. Connector-owned upload responses
do not contain private content metadata; the SDK does not fill it with empty
or zero values. `ResourceUpdate` uses pointers to distinguish omitted fields
from explicit empty values. Set `ClearAlias: true` to send JSON null; do not
also set `Alias`. The service validates field bounds and policy combinations.

Session reads and bulk terminations always request bounded pagination.
`TerminateSessions` reports one page's count and cursor. It does not drain all
pages or retry mutations for you. A successful management request is not
independent evidence that a native connection has reached CLOSED.

## Connectivity, issuance, and opening from Go

Choose the Go API by the part of the sharing lifecycle your software owns:

- **Issuer:** resource and portal operations let an authorized service issue access to an existing resource. A returned link does not start the origin or enroll its serving agent. Use this role for a preview-review service or automation that grants access to a private API.
- **Agent:** this SDK manages enrollment, durable state, and NHP admission: permission to serve a resource. HTTP forwarding requires [qURL Connector](https://github.com/layervai/qurl-connector), embedded in the CLI; `ConnectAgentRuntime` alone does not carry application traffic. The [ngrok Go Agent SDK](https://github.com/ngrok/ngrok-go) provides a `net.Listener` that a Go HTTP server can serve directly. Choose based on the runtime and access workflow your application needs.
- **Recipient:** a qURL consumer opens and verifies a received link, then authorizes content requests through its returned resource handle. This differs from making a direct request to an [S3 presigned object URL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html). Follow [opening links](#opening-links) for target binding, redirect checks, and session state; fetching the browser opening page alone does not fetch the protected content.

For a ready-made localhost share, install the CLI. For an application already reached through Cloudflare Access or a Tailscale tailnet, evaluate its existing access workflow before adding another runtime. The [sharing comparison](https://github.com/layervai/qurl-integrations#choose-how-to-share-an-app-or-file) explains those deployment choices. Local app and file-serving paths still need an available origin; expiry, session lifetime, and app login remain separate concerns.

## Go sharing questions

### Should I install this SDK to share localhost from a terminal?

Install the [CLI](https://github.com/layervai/qurl-integrations/tree/main/apps/cli)
for that task. `qurl-go` is a Go library with issuer, agent, and opener
APIs; it is not a replacement CLI binary.

### Does an opener need my issuer API key?

`EnterPortal` verifies a received link using configured deployment trust and
the supported opening transport. It does not need the issuer's account key.
Do not hand out issuer credentials. Your private app's own authentication
still applies, and custom deployments need the appropriate opener settings.

### Does a link's expiry close an existing session?

Expiry limits new redemption. An admitted session has its own lifetime and
renewal rules. Choose the portal and session options for your resource; do not
assume that a five-minute link forces every session to end at the same deadline.

## Why qURL

qURL lets you issue temporary access to an individual resource while a
properly configured local origin remains on localhost or a private network.
The serving runtime provides the access path and the SDK lets your software
participate as an issuer, agent, or recipient. Restrict any independent public
route when qURL should be the only path to the app.

The resource still needs normal authentication, maintenance, and availability.
Treat links as access credentials rather than evidence that the holder is the
person named in a label.

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
                                                                │    access traffic
┌───────────────────────────────────────────────┐               │
│ your private network                          │               │
│   private service ◀─── qURL Connector ────────┼───────────────┘
│                        (embedded in the CLI)  │
└───────────────────────────────────────────────┘
```

Three roles, three sections of this README:

1. **Issue** — your app calls `ProtectURL` and `CreatePortal` over HTTPS and
   gets back a link. ([Quickstart](#quickstart))
2. **Serve** — the private service sits behind
   [qURL Connector](https://github.com/layervai/qurl-connector), embedded in
   the CLI. The Connector connects outward and forwards HTTP traffic to the
   service. This SDK handles agent enrollment and admission; it does not
   provide that forwarding connection. ([Connect a service or agent](#connect-a-service-or-agent))
3. **Open** — the recipient opens the link in a browser, or a program calls
   `EnterPortal`. LayerV verifies the portal and stitches recipient ↔ agent ↔
   service for the admitted session under the resource's policy. ([Opening links](#opening-links))

| Term | Meaning |
| --- | --- |
| **Resource** | A URL or service registered for qURL access and identified by a stable CRID. Its origin must be private or restricted when qURL should be the only access path. |
| **Portal** | A short-lived signed access link for one resource, subject to its use and session rules. Treat the link as a credential. |
| **Issuer** | Software holding LayerV credentials that protects URLs and creates portals. |
| **Connector** | LayerV's ready-made agent that publishes services from inside your network. |
| **Agent runtime** | SDK support for agent enrollment, durable state, and admission. HTTP forwarding runs separately through the Connector. |

And every entry point in one place:

| Entry point | When to use it | Returns |
| --- | --- | --- |
| `OpenClient` / `OpenClientContext` | Issue links with the default credential chain ([Get a credential](#get-a-credential)); the context form bounds the eager startup check | `*Client` |
| `NewClient` | Issue links with your own `CredentialProvider` (KMS, a secret manager) | `*Client` |
| `ConnectAgentRuntime` | Enroll, resume, or reopen an agent registration; does not start HTTP forwarding | `*Client`, `*AgentRuntimeBinding` |
| `OpenRegisteredAgent` / `OpenRegisteredAgentWithIdentity` | Resource-only client from completed agent state — one store load, no lifecycle network I/O, no knockable binding | `*Client` (`WithIdentity` adds the agent id) |
| `RefreshAgentRuntime` | Renew a completed assignment through the Hub at a moment you choose | `*Client`, `*AgentRuntimeBinding` |
| `RecoverAgentRuntime` | Operator-driven replacement of a revoked or lost device credential | `*Client`, `*AgentRuntimeBinding` |
| `RecoverAgentRuntimeWithCredentialProvider` | The same recovery with account authority resolved only after durable state and expiry validation | `*Client`, `*AgentRuntimeBinding` |
| `EnterPortal` | Open a received qURL link programmatically; needs no LayerV credentials | `*ResourceHandle` |
| `OpenCRID` | Open a resource from its CRID alone: asks for a link, checks it against the CRID, and opens it; needs no LayerV credentials ([Open by CRID](#open-by-crid)) | `*ResourceHandle` |
| `OpenCRIDAsDevice` | Open a resource by CRID as a registered device, which can open a private resource the owner allowed the device to open; takes the device key ([Open by CRID](#open-by-crid)) | `*ResourceHandle` |
| `OpenCRIDAsDeviceFromKeySource` | The same open for a device that does not hold its key in memory: takes a function that returns the key, and calls it only when the device key is needed ([Open by CRID](#open-by-crid)) | `*ResourceHandle` |
| `NewPortalOpener` | Keep one native-only received qURL ready for repeated service calls with proactive renewal and no request-path open | `*PortalOpener` |

## Install

qurl-go is a library — there is no binary to `go install`. From inside your
module:

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

Requires Go 1.26.10+ — a security floor, not a preference for the newest
toolchain. The floor is on the Go 1.26 line because `golang.org/x/crypto` and
`golang.org/x/sys` require it (and Go 1.25 is out of support); 1.26.10 is the
earliest 1.26 patch release without the currently known standard-library
vulnerabilities this SDK's code paths reach. CI runs `govulncheck` at exactly
this version. See the comment above the `go` directive in
[go.mod](go.mod) for the advisory list and full rationale.

Not in a module yet? Run `go mod init example.com/myapp` first: `go get`
outside a module fails with `go.mod file not found`, and
`go install .../qurl@latest` fails with `is not a main package` because nothing
here builds a command.

| Module | Purpose |
| --- | --- |
| `github.com/layervai/qurl-go/qurl` | The SDK. Zero AWS dependencies. |
| `github.com/layervai/qurl-go/qurl/qurltest` | Test doubles for code that calls `qurl`. For tests only. |
| `github.com/layervai/qurl-go/crid` | The Cryptographic Resource ID codec: strict local validation, environment reporting (`production`, `test`, or `unknown`), and the delivered-key match rule. No dependencies beyond the standard library. |
| `github.com/layervai/qurl-go/awsstore` | AWS-backed agent state (Secrets Manager, SSM, KMS sealing). A [separate module](awsstore/README.md) so the AWS SDK never leaks into `qurl`. |

## Get a credential

Create an API key in the [LayerV dashboard](https://layerv.ai/qurl/dashboard/keys)
with the `qurl:write` scope. Check the [current plans](https://layerv.ai/pricing/)
for service limits.

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

Production issuer keys, native cell endpoints, and the Hub trust root are embedded
in the SDK. Production needs no deployment file. For sandbox or a custom
deployment, set `QURL_DEPLOYMENT` to its deployment file.

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

A new resource is private or public. State which with `qurl.WithPrivate` when
the default must not decide, and read `Resource.Private` back; see
[Private and public resources](docs/issuing-links.md#private-and-public-resources).

Private consumer policies also support credential lists, publisher invitations,
verified email capture, reviewed requests and contract entitlements. See
[Consumer access](docs/consumer-access.md). These operations require a service
and NHP cell with consumer access enabled.

If qURL Connector already protects the service, use its immutable connector
slug:

```go
resource, err := client.GetConnectorResourceBySlug(ctx, "prod-dashboard")
if err != nil {
	return err
}
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
```

If you persist the CRID, future calls can reconstruct the handle without
another lookup:

```go
resource := client.ResourceByCRID(resourceCRID)
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

`CreatePortal` and `Client.ShareResource` both mint an access link.
`CreatePortal` is the portal-options path on a resource handle;
`ShareResource` is the stored-identifier path — it accepts the resource's CRID and returns a `ShareLink` whose CRID you can verify
against a key you already hold (`VerifyCRID`). Both leave the link lifetime to
the server default unless you ask (`ValidFor` on a portal,
`ShareResourceOptions.TTL` on a share).

**Publisher metadata.** A `ShareLink` also carries `ResourceCreatedAt` (when the
resource was created; `nil` if the service did not report it) and `Publisher`,
a `qurl.Publisher` with the owner's self-declared `Name` and a `Verified` flag.
Every publisher is unverified today, and anything missing decodes to
unverified. This metadata is asserted by the service and is not part of CRID
verification — `VerifyCRID` and `VerifyLinkForCRID` cover only the key and the
link. Treat `Name` as untrusted text: print it with `%q` so control characters
are escaped, and always show "unverified" clearly beside it. An owner manages
its own name with `Client.Publisher` and `Client.SetPublisherName`; see
[Publisher metadata](docs/share-and-crid.md#publisher-metadata).

Minted links use the share-safe `#qv2t1...` fragment transport. It keeps every
dot-separated component at 240 characters or fewer so messaging clients retain
the full click target, while preserving the exact signed qv2 bytes and keeping
the per-link private credential out of HTTP requests.

Next: [Protect a private service](docs/secure-a-private-service.md) ·
[Issue links](docs/issuing-links.md)

## Connect a service or agent

The ready-made local publishing path is the
[qURL CLI](https://github.com/layervai/qurl-integrations/tree/main/apps/cli),
which embeds [qURL Connector](https://github.com/layervai/qurl-connector)
to forward HTTP traffic to your running service. Keep the CLI's serving
runtime and the service available while recipients use it.

Use this SDK's agent APIs when building software that manages its own
enrollment, durable state, and NHP admission. Registration authenticates the
agent over outbound UDP. `ConnectAgentRuntime` returns its registration and
client; it does not start a listener or forward HTTP requests. Embedded HTTP
serving also needs the Connector runtime.

Enrollment uses the production Hub trust root embedded in the SDK. No deployment
file is needed for production. For sandbox or a custom deployment, set
`QURL_DEPLOYMENT` to its deployment file or pass `WithAgentRuntimeHub`. A
completed registration whose lease is live reopens without a Hub exchange.

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

That is the whole enrollment. Run it on every start, under a supervisor:

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
req, err := http.NewRequestWithContext(ctx, http.MethodGet, handle.ResourceURL, nil)
if err != nil {
	return err
}
if err := handle.AuthorizeContentRequest(req); err != nil {
	return err
}
httpClient := &http.Client{
	// Re-authorize same-origin redirects, refuse every other origin, and keep
	// the standard 10-request redirect limit.
	CheckRedirect: handle.CheckContentRedirect,
}
resp, err := httpClient.Do(req)
```

That is the whole integration, and it needs no LayerV credentials. `EnterPortal`
checks that the link was really issued by LayerV, then opens it over a direct
UDP connection. Browsers cannot send UDP, so links opened in a browser go
through an HTTPS path instead. In this SDK the resolved config decides the
transport: a configured cell catalog selects native UDP. Unknown cells fail with
`ErrCellNotInCatalog`, even when a relay allowlist is configured. Relay-only
operation requires a nil cell catalog and a relay allowlist (see
[docs/opening-links.md](docs/opening-links.md#pinning-the-opener-trust-config)).
Use an HTTP client without a cookie jar, or ensure its jar does not add the
reserved `qurl_vsession` cookie after `AuthorizeContentRequest` runs.

The opener trust configuration — which issuer keys to verify links against and
which cells to reach — resolves most specific first: a `Provider` installed
with `SetDefaultProvider`, then a JSON file named by `QURL_DEPLOYMENT`, then
the deployment embedded in the build
([qurl/deployment.json](qurl/deployment.json)). The Hub trust root for agent
registration is not provider-supplied: it comes only from `QURL_DEPLOYMENT`,
the embedded deployment, or an explicit `WithAgentRuntimeHub`
(`RefreshAgentRuntime` takes a `HubBootstrap` argument) — an installed
`Provider` affects opener config only. Releases embed the production issuer
keys, native cell endpoints, Hub trust root, and the production CRID link
endpoint (`https://relay.layerv.ai`, with link origin `https://qurl.link`).
`CRIDLinkOrigin()` reads the validated link origin without network I/O.
Production needs no deployment file. Set `QURL_DEPLOYMENT` only for sandbox or a custom deployment. The issuer
HTTPS endpoint is configured separately with `WithBaseURL`. A resolved deployment
with no issuer keys fails closed (`ErrNotConfigured`) rather than open a link it
cannot verify.

### Open by CRID

A program that holds only a CRID — no link — calls `OpenCRID`:

```go
handle, err := qurl.OpenCRID(ctx, resourceCRID)
if err != nil {
	return err
}
// handle is the same *ResourceHandle EnterPortal returns; use it the same way.
```

`OpenCRID` asks the server for a short-lived qURL link for that CRID, checks
the link, and opens it. It needs no LayerV credentials. The link comes from the
network, so it is used only after it passes every client check: it is on the
deployment's link origin, its issuer signature verifies under the trust store,
and its signed resource key derives the CRID you asked for. A link that fails a
check is never opened, returned, logged, or quoted in an error.

- **The request goes through the relay.** In this version the link request is
  always sent through the deployment's HTTPS relay, under a key minted for that
  one request — also when links themselves open over native UDP. The open that
  follows uses native UDP to the deployment's cell.
- **A registered device can open a private resource.** A private resource can
  be opened by CRID only by a registered device that the owner allowed, or by
  the owner's own device. Call `OpenCRIDAsDevice` with the device key, or
  `OpenCRIDAsDeviceWith` to pass the configuration yourself. The
  first request never carries the device key: it is sent under a random key
  and carries nothing derived from the device key. Only when
  that request is answered "not found" does the SDK send one second request,
  under the device key. The second request is a real request and counts
  against the server's per-source request limit. The source address can still
  connect a request to the device, and the relay can do more with the second
  request than with the first. See
  [Open a private resource](docs/opening-links.md#open-a-private-resource).
- **The device key can be read only when it is needed.** A device whose key
  costs something to read, for example a sealed key, calls
  `OpenCRIDAsDeviceFromKeySource` and passes a function that returns the key.
  The SDK calls the function once, and only when the first request was
  answered "not found". A public resource is opened without that call. The SDK
  overwrites the key the function returned before the call returns. See
  [Read the device key only when it is needed](docs/opening-links.md#read-the-device-key-only-when-it-is-needed).
- **Publisher data is display-only and unverified.** `RequestCRIDLink` returns
  the link together with what the server reports about it: a publisher name,
  when the resource was created, when the link expires. None of that is covered
  by the link's signature or by the CRID. The name is self-declared, and every
  publisher is unverified today. Show it quoted (`%q`), always next to
  "unverified", and never as a confirmed identity. To show it before opening,
  call `RequestCRIDLink`, then `EnterPortalForCRID` with the link and the same
  CRID.
- **It has to be configured.** The request needs a CRID link endpoint, which a
  deployment names in its `crid_link` object. The embedded deployment names
  the production endpoint. Custom
  deployments must name their endpoint in `QURL_DEPLOYMENT`, or pass it with
  `OpenCRIDWith`; an absent endpoint returns `ErrCRIDLinkNotConfigured`.
  `CheckCRIDLinkConfig` gives the same answer
  without a CRID and without sending anything. See
  [Open by CRID](docs/opening-links.md#open-by-crid) for the file format.
- **It can be tested without a server.** `qurltest.NewCRIDLinkServer` answers
  the link request in process, so a test runs the production call and the SDK
  still checks the link. See
  [Test without a server](docs/opening-links.md#test-without-a-server).

## Error handling

Match errors by type or sentinel, not message text. Grouped by the scenario
that raises them:

**Issuing — credentials and the HTTPS resource API**

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidClientConfig` | Resource-client credentials or options are malformed |
| `qurl.ErrInvalidPortalRequest` | A portal input is invalid; rejected before any API request is sent |
| `qurl.ErrPortalRevoked` | `RevokePortal` found the qURL no longer active: that link — created or shared — was already revoked, so a repeat revoke had nothing to do. The underlying `*APIError` stays matchable |
| `*qurl.APIError` | LayerV returned a non-2xx steady-state resource response |

**Opening links**

| Error | Meaning |
| --- | --- |
| `qurl.ErrNotConfigured` | A required piece of opener or deployment configuration is absent; the SDK fails closed rather than open a link it cannot verify |
| `qurl.ErrNoDeployment` | The resolved deployment carries no issuer keys — a custom build ships none and `QURL_DEPLOYMENT` is unset, or the named deployment file has empty `issuers`. Wraps `ErrNotConfigured` |
| `qurl.ErrSignature` | The link's issuer signature does not verify: forged, tampered, or signed by a key that is not the trust store's value for that kid |
| `qurl.ErrUnknownKID` | The link's kid is not in the trust store |
| `qurl.ErrCellNotInCatalog` | A verified link names a cell absent from the configured catalog. The opener refuses the open, even when a relay allowlist is configured |
| `qurl.ErrCellCatalogKeyMismatch` | A compact cell fingerprint selected a catalog entry whose full key differs from the signed link key. The SDK refuses before network I/O |
| `qurl.ErrQurlUserKeyMismatch` | The fragment private key does not derive the issuer-signed visitor public key. The SDK refuses before network I/O |
| `qurl.ErrPortalNativeOnly` | `PortalOpener` has no native cell catalog and will not use HTTPS relay |
| `qurl.ErrPortalOpenTimeout` | The configured `PortalOpener` NHP open timeout expired. A shorter caller deadline does not wrap this error |
| `qurl.ErrPortalOpenerNotStarted` | `PortalOpener.Do` ran before the first `Start` attempt completed, or after a caller-canceled or caller-deadlined first attempt |
| `qurl.ErrPortalOpenerNotReady` | The proactive opener has no unexpired cached handle. `Do` does not wait or open on the request path |
| `qurl.ErrPortalOpenerClosed` | `PortalOpener` was used after `Close` |
| `qurl.ErrPortalTargetChanged` | A proactive renewal authenticated a different target, so the opener kept the prior handle and failed closed |
| `qurl.ErrPortalRedirect` | A request configured with `RejectPortalRedirects` received a redirect, or a default-policy redirect changed origin |
| `*qurl.ServerDenyError` | An authenticated platform deny: the reply verified, but access was refused — an expired, revoked, or consumed qURL, or a server-side access check. Also raised by the registered-agent knock path (`KnockRegisteredAgent`) when the assigned cell denies an admission |

**Opening by CRID — `OpenCRID`, `RequestCRIDLink`, `OpenCRIDAsDevice`, `RequestCRIDLinkAsDevice`, their `With` forms, and the `FromKeySource` forms of the device calls**

The open that follows a successful link request can also return any error from
the table above.

| Error | Code | Meaning |
| --- | --- | --- |
| `qurl.ErrCRIDLinkNotFound` | `52602` | The CRID is unknown, retired, or malformed, or this client may not open it. The server gives one answer for all of these. Do not retry; check the CRID and your access |
| `qurl.ErrCRIDLinkUnavailable` | `52601` | A link cannot be issued right now. Try again later |
| `qurl.ErrCRIDLinkRateLimited` | `52603` | Too many requests from this client or for this CRID. Try again later |
| `qurl.ErrCRIDResourceOffline` | `52604` | The resource exists and this client may open it, but its publisher is offline. It may come back |
| `qurl.ErrCRIDResourceClosed` | `52605` | The resource exists and this client may open it, but it has been closed. Do not retry |
| `qurl.ErrInvalidCRIDLinkRequest` | `52606` | The server refused the request itself: malformed, not sent through the relay, or carrying something it does not support. Do not retry |
| `*qurl.ServerDenyError` | any other | The server answered with a decimal code outside this table: a server error, with the code in `ErrCode`. It matches none of the refusals above, `ErrCRIDLinkUnavailable` included, and it says nothing about the client's version. Each refusal above is also a `*ServerDenyError` carrying its code |
| `qurl.ErrServerOverloaded` | — | The server is busy and sent no answer. Try again later. For a call made as a device it is "no usable answer" and not proof that the server is busy: the relay can cause it on the request under the device key. The same holds there for `ErrCRIDLinkProtocol` and `ErrMalformedReply`. See [what the relay can and cannot do](docs/opening-links.md#what-the-relay-can-and-cannot-do-with-a-request-under-the-device-key) |
| `qurl.ErrCRIDLinkProtocol` | — | The reply is not a usable answer: its body is not one JSON object with unique member names, or it has no outcome code, a success code, or a code that is not a decimal number. A link request opens nothing, so a reply that claims success is not trusted with a link. Wraps `ErrMalformedReply` |
| `*qurl.CRIDLinkRejectedError` | — | The server issued a link and the link failed a client check; `Class` names the check (`missing_redirect`, `origin`, `path_or_query`, `transport`, `issuer_signature`, `crid_mismatch`, `info_crid_mismatch`). Matches `qurl.ErrCRIDLinkRejected`. The link is not returned |
| `qurl.ErrCRIDLinkNotConfigured` | — | The configuration cannot make the request: it names no CRID link endpoint, or it names one that cannot be used. Nothing was sent. Wraps `ErrNotConfigured` |
| `qurl.ErrCRIDLinkMisconfigured` | — | The configuration names a CRID link endpoint that cannot be used: a relay URL or link origin that is missing or wrong, or not exactly one usable cell. Nothing was sent. Wraps `ErrCRIDLinkNotConfigured`, so test for it first |
| `qurl.ErrInvalidResourceRequest` | — | The CRID failed the local validation gate — the `crid` package's sentinel matches too — or, with `qurl.ErrUnsupportedCRIDVersion`, has a version this SDK cannot verify a link against. Nothing was sent |
| `qurl.ErrInvalidDeviceKey` | — | A call made as a device was given a device key that is not 32 bytes, or that holds only zero bytes as a wiped key does, or was given a nil `DeviceKeySource`. Nothing was sent, no configuration was resolved, and the CRID was not looked at. It does not match `ErrInvalidResourceRequest`. A key that a `DeviceKeySource` returns is checked later; see the next row |
| `*qurl.DeviceKeySourceError` | — | A call that takes a `DeviceKeySource` needed the device key, and the source gave none that can be used. `Err` holds the error the source returned; it matches `ErrInvalidDeviceKey` when the source returned a key that is not 32 bytes or holds only zero bytes. The first request was sent and answered "not found", and `FirstAnswer` holds that answer. The request under the device key was not sent. The SDK puts nothing into it that matches `ErrCRIDLinkNotFound`; it matches only when the source's own error does. Its message never holds the text of `Err` |
| `*qurl.RelayError` | — | The relay could not be reached, answered with an HTTP error instead of a reply, or began a reply that could not be read to the end (`Status` is then 200). When the caller's context ended the request before a reply was read, the error also matches the context's error |
| `context.DeadlineExceeded` / `context.Canceled` | — | On its own, matching no other row: the caller's context ended between two steps of the call. For any open by CRID that is after the link was issued and before the open. For a call made as a device it can also be after "not found" and before the request with the device key. The error does not say which, so it does not say whether the device key was sent. Try again with more time |

A relay answer that does not authenticate as the server's reply is an error
that matches none of these rows, as it is for `EnterPortal`. It is never read
as an answer.

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

**Share and CRID**

| Error | Meaning |
| --- | --- |
| `qurl.ErrTemporaryAccessLinksDisabled` | `ShareResource` got a 503: the environment is not serving temporary access links. The underlying `*APIError` stays matchable |
| `qurl.ErrNoCRID` | The mint/share response or manually constructed link has no CRID. Fails closed. |
| `qurl.ErrCRIDMismatch` | The mint/share response changed the requested CRID, or the supplied key does not derive the held CRID. Do not use the returned link or mismatched key. |
| `qurl.ErrInvalidPublisherName` | `SetPublisherName` was given a name that can never be valid, or the service rejected it with a 400. A service rejection keeps its `*APIError` |

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

Revocation covers every minted link. `RevokePortal` revokes a single link
immediately, whichever call minted it: pass `Portal.CRID` and
`Portal.QURLID` from a create, or the CRID you shared and
`ShareLink.QURLID` from a `ShareResource`. Only that link dies — the
resource and its other live links keep working — and revoking a link that is
no longer active fails with `ErrPortalRevoked` rather than reporting success
it did not cause. Capture the qurl id when you mint: like the link itself, it
is not retrievable afterwards, and a server predating the field omits it. A
short `ShareResourceOptions.TTL` remains the complementary control at mint
time. `DeleteConnectorResource` revokes an entire connector resource (see
[Resolve and manage qURL Connector resources](docs/connector-resources.md)).

### Per-CRID preview metadata

Use `client.Preview(ctx, crid)` to read the public app name, preview text, media IDs and processing
state for a resource you own. To set optional text, pass the latest revision:

```go
name := "API guide"
text := "A guide to our API"
current, err := client.Preview(ctx, resourceCRID)
if err != nil {
    return err
}
_, err = client.UpdatePreview(ctx, resourceCRID, qurl.PreviewPatch{
    Revision: current.Revision, Name: &name, Description: &text,
})
```

`CreatePreviewUpload` returns an exact-size, five-minute HTTPS PUT request for
verified publishers. Upload the file bytes with the returned headers and exact Content-Length directly to
`URL`, without API credentials or redirects. Poll `Preview` until processing is
ready or failed. A replacement retains old media until ready. Send an empty
`MediaIDs` slice to remove all media and cancel pending work. A stale revision
returns 409; read current state before retrying. Descriptions are plain text, not
HTML, and are separate from private owner notes. Media URLs expire after five
minutes; load video only after explicit playback. The publisher cannot set its
verification status through these methods.

## Guides

- [Protect a private service](docs/secure-a-private-service.md)
- [Connect a service or agent](docs/register-an-agent.md)
- [Resolve and manage qURL Connector resources](docs/connector-resources.md)
- [Issue links](docs/issuing-links.md)
- [Share a resource and verify its CRID](docs/share-and-crid.md)
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
