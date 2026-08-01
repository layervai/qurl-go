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
internal tools. Every standing public endpoint becomes inventory for scanners,
fingerprinting, credential attacks, and AI-assisted probing before a legitimate
user or agent ever arrives.

qURL is an invisibility primitive for authenticated access. A portal is
cryptographic, just-in-time permission for one actor to reach one private
resource without turning that resource into public inventory.

## Install

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

Requires Go 1.26+.

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

## Connect to LayerV

Only software that protects URLs or creates portals needs LayerV credentials. A
user or agent that only receives and opens a qURL link does not set up anything.

Application issuers normally run the LayerV setup flow once, then use:

```go
client, err := qurl.OpenClient()
```

For protected external credential storage, implement `qurl.CredentialProvider`
and pass it to `qurl.NewClient`.

## Connect a service or agent

Your service registers once, then keeps serving. Registration happens over an
authenticated UDP channel — no inbound ports, no public endpoint, nothing for a
scanner to find.

```go
store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
if err != nil {
	return err
}
defer store.Close()

client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredential, store,
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
)
if err != nil {
	return err
}
defer binding.Destroy()
```

That is the whole enrollment. You supply the credential you were issued, a file
to keep state in, and a way to read the one-time code; the SDK already knows how
to reach LayerV.

`readOneTimeCode` is a function you write. That call **blocks** while LayerV
emails a code to the address on your credential and waits for your callback to
return it — [The one-time code](#the-one-time-code) below shows one.

**It survives restarts and bad networks.** State is saved before anything
irreversible happens, so a crash, a dropped reply, or a machine reboot resumes
the same registration rather than starting a new one — for up to 90 days. You do
not need to handle that; it is the default.

**Warm starts are free.** After the first successful registration, use
`OpenRegisteredAgentRuntime` — it loads saved state with no network calls at all.

**Keep the metadata stable.** The hostname and version you pass become part of
the saved registration. Change them only after registration has completed, or
recovery has nothing to match.

### The one-time code

Enrollment sends a one-time code to the address on your credential, and your
callback returns it. That is the default path.

It is not a "human" path. Agents increasingly have their own mailboxes, and a
service account or a shared operations alias works just as well. All that
matters is that *something* can read the address the code went to:

```go
func readOneTimeCode(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	return pollMailboxForCode(ctx) // your inbox, your operator, your call
}
```

Return exactly 8 decimal digits, and honor the `ctx` — it is already bounded by
the assignment ticket. The `challenge` is for logging and correlation only: it
carries no credential and nothing replayable. LayerV sends at most one code per
attempt, and the SDK never retries behind your back or writes the code to disk.

**If nothing can read a mailbox** — a sealed appliance, an air-gapped build
agent — enroll with a pre-issued credential and say so explicitly:

```go
client, binding, err := qurl.RegisterAgentRuntime(ctx, credential, store,
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeHeadlessEnrollment(),
)
```

That is the escape hatch, not the shortcut. Use it only when no address in reach
can receive the code — and note it cannot be combined with an OTP provider, since
one option says no code can be read and the other says how to read one.

**Not sure which you have?** The token will not tell you — credentials carry no
kind you can parse, and LayerV reports it on the first authenticated call. Go by
how you got it: issued against an address means the code path, pre-issued for a
machine means headless. Or just run the default and read the error, which names
the kind LayerV actually reported:

```
qurl: registration key kind "bootstrap" is disallowed; accepted kinds: account
```

Nothing is registered or written before that check, so a wrong first guess costs
you nothing. [Connect a service or agent](docs/register-an-agent.md) has the full
decision table.

### Credentials

Pass the credential LayerV issued you. Credentials must be LayerV-minted tokens
of at least 32 characters. Passwords and hand-picked strings are rejected before
anything is saved or sent.

### If LayerV moves your service

Occasionally LayerV relocates where your service is served from. The SDK will not
silently follow — it returns `*AgentAssignmentChangedError` so the move is your
decision. When you are ready:

```go
client, binding, err := qurl.RefreshAgentRuntime(ctx, qurl.HubBootstrap{}, store,
	qurl.WithAgentRuntimeReassignmentAdoption(),
)
```

The empty `HubBootstrap{}` means "use the trust root this build ships" — you only
fill it in if you run your own LayerV deployment. There is nothing to look up:
the option accepts only the move LayerV just told you about. Without it, the same
call keeps returning the error and changes nothing on disk.

## Opening Links

Most recipients open qURL links directly and do not use this SDK. Programmatic
recipients call:

```go
portal, err := qurl.EnterPortal(ctx, link)
```

That is the whole integration. The SDK ships the issuer keys it trusts and the
cells it can reach, so there is no trust configuration to assemble first.

`EnterPortal` checks that the link was really issued by LayerV, then opens it over
a direct UDP connection. Browsers cannot send UDP, so links opened in a browser
go through an HTTPS path instead; the SDK picks whichever works and you do not
configure either one.

To point the SDK at a different deployment (self-hosted, or a sandbox), set
`QURL_DEPLOYMENT` to a deployment JSON file; to take full programmatic control,
install a `Provider` with `SetDefaultProvider`. A build that ships no issuer keys
fails closed rather than opening a link it cannot verify.

## Guides

- [Protect a private service](docs/secure-a-private-service.md)
- [Register an agent](docs/register-an-agent.md)
- [Issue links](docs/issuing-links.md)
- [Open links](docs/opening-links.md)

## Error handling

Match errors by type or sentinel, not message text:

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidClientConfig` | Resource-client credentials or options are malformed |
| `qurl.ErrInvalidRegisterConfig` | Native lifecycle inputs are malformed |
| `qurl.ErrAssignmentRecoveryRequired` | Registration ran out of retries; start recovery |
| `qurl.ErrAgentBindingPersistence` | A state save failed or its acknowledgement was lost; reload before retry because the refreshed assignment may already be durable |
| `qurl.ErrCompletionRecoveryRequired` | Resume the exact persisted completion candidate |
| `qurl.ErrAgentRecoveryExpired` | This registration is older than 90 days and can no longer be resumed; enroll again |
| `qurl.ErrAgentRecoveryMigrationRequired` | Saved state predates the current format; keep the file and enroll again |
| `*qurl.NativeCredentialRecoveryRequiredError` | Completed native credential state is absent or malformed; explicit native recovery or reprovisioning is required |
| `*qurl.AgentAssignmentChangedError` | LayerV moved where your service is served from; opt in with `WithAgentRuntimeReassignmentAdoption` to accept a newer generation |
| `*qurl.APIError` | LayerV returned a non-2xx steady-state resource response |
| `*qurl.ServerDenyError` | LayerV refused the request |

## Security notes

- Treat LayerV credentials, agent state, and qURL links like credentials. Do not
  log them.
- Never guess or construct LayerV addresses yourself; use what the SDK ships.
- Keep saved registration state across an unclear reply, and keep the exact
  pending completion candidate across ambiguous completion delivery.
- Wipe the private-key bytes taken from `AgentRuntimeBinding` once you are done with them.
- Keep issuer credentials in protected state, KMS, a secret manager, or another
  protected store.
- Links opened in a browser and services connected over UDP are separate trust paths.

## Changes

### Unreleased

- **Breaking:** enrollment now defaults to the emailed one-time code, for any
  runtime that can read a mailbox rather than humans specifically. A runtime with
  no address in reach opts out with the new
  `WithAgentRuntimeHeadlessEnrollment`; callers that previously enrolled with a
  pre-issued credential and no options must add it. Policy and provider must now
  agree in both directions: accepting the OTP kind without
  `WithAgentRuntimeOTPProvider` fails with `ErrAgentOTPRequired` before any
  network I/O, and installing a provider while excluding that kind is rejected
  as contradictory with `ErrInvalidRegisterConfig`.
- Added the native UDP connection lifecycle for services and agents: enrollment,
  emailed one-time codes, direct connections, strict conformance, crash-safe
  activation/completion, and explicit opt-in assignment reassignment adoption.
- Bounded native registration recovery to 90 days after the first authenticated
  assignment-ticket expiry, with a per-datagram deadline fence, immutable
  replacement anchor, and fail-closed pre-v6 pending-state migration.
- Registration retries are budgeted per step, so a single call can span several
  of them before giving up. Use an outer
  context deadline when a smaller aggregate wall-clock ceiling is required.
- Removed the superseded public HTTP agent assignment/registration lifecycle.
  Everyday resource calls still use HTTPS, and browser behavior is
  unchanged.
- Added sealed full-AgentState storage and AWS-backed AgentState stores.

## License

[MIT](LICENSE) © LayerV AI
