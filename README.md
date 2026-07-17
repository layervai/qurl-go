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

## Native qURL Connector lifecycle

`RegisterAgentRuntime` is the only agent enrollment front door. Assignment,
optional account OTP, REG/RAK, and completion travel directly over authenticated
NHP UDP. There is no public HTTP assignment, registration, refresh, recovery, or
completion API in this SDK.

Trusted deployment configuration supplies one LayerV-owned Hub DNS name, UDP
port, and pinned server public key:

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
hub := qurl.HubBootstrap{
	Host:               "hub.nhp.layerv.ai",
	Port:               62206,
	ServerPublicKeyB64: configuredHubPublicKey,
}

client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredential, store,
	qurl.WithAgentRuntimeHub(hub),
	qurl.WithAgentRuntimeMetadata(hostname, version),
)
if err != nil {
	return err
}
defer binding.Destroy()
```

The Hub assigns the cell. Before REG, the SDK durably persists the exact ticket,
registration identity/metadata, authority-provided UDP endpoint and server
identity, and a one-way identity of the caller's enrollment credential. A lost
RAK therefore restarts by re-driving the same REG to the same pinned cell—even
after ticket expiry—before any new Hub assignment. Plaintext enrollment
credentials and OTP codes are never persisted. The SDK never calculates a cell
address or involves the browser relay in native discovery.

Recovery must use the identical persisted hostname and version because those
bytes are part of the exact REG replay. Change that metadata only after
activation completes. The v0.5 assignment lease must also expire strictly after
its ticket; pending-state validation enforces that producer invariant.

The default policy accepts unattended `connector_bootstrap`, `bootstrap`, and
durable `agent` credentials. Interactive account enrollment must explicitly add
both `WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount)`
and `WithAgentRuntimeOTPProvider`.

For account enrollment, the one-way OTP dispatch intentionally occurs before
the pending-activation save. A save failure cannot have sent REG; a later
explicit attempt may obtain a new ticket and dispatch that ticket's single OTP.

Every `RegisterAgentRuntime` enrollment credential must be a server-minted,
high-entropy token of at least 32 bytes. Shorter values and user-chosen
passwords are rejected before state mutation or network I/O. This requirement
is part of the initial pre-1.0 native-UDP contract for all credential kinds.
The SDK can enforce token syntax and byte length; the minting authority remains
responsible for supplying the required entropy.

Warm starts call `OpenRegisteredAgentRuntime`, which loads completed state
without network I/O. `RefreshAgentRuntime` refreshes an expiring assignment only
through the pinned Hub. It accepts endpoint revisions within the same cell and
assignment generation; a cell or generation move returns
`*AgentAssignmentChangedError` for explicit caller handling.

For each Connector cycle, take the private key once, create one `RunID`, and
knock with the resource's placement-neutral `KnockResourceID`:

```go
privateKey := binding.TakeDeviceStaticPrivateKey()
defer clear(privateKey)

connector, err := client.EnsureConnectorResource(ctx, "prod-dashboard")
if err != nil {
	return err
}
runID, err := qurl.NewCycleRunID()
if err != nil {
	return err
}
admission, err := qurl.KnockRegisteredAgent(ctx, binding, privateKey,
	connector.Resource.KnockResourceID,
	qurl.NativeKnockOptions{RunID: runID},
)
```

The returned `Client` uses HTTPS only for steady-state resource CRUD.
`WithAgentClientBaseURL` and `WithAgentClientHTTPClient` configure only that
resource client; they never affect Hub or cell UDP transport.

Agent state may be stored in a strict `0600` file under a `0700` directory, in a
sealed file using `NewSealedFileAgentState`, in AWS Secrets Manager or SSM via
`awsstore`, or in a custom `AgentStateStore`. The schema is native-only and
duplicate or unknown persisted fields fail closed. An older SDK therefore
cannot open state containing fields introduced by a newer SDK; treat a downgrade
as an explicit state-schema migration or reprovisioning operation rather than
deleting state.

See [Register an agent](docs/register-an-agent.md) for the complete lifecycle,
storage contract, recovery boundaries, and error table.

## Opening Links

Most recipients open qURL links directly and do not use this SDK. Programmatic
recipients install opener trust configuration and call:

```go
portal, err := qurl.EnterPortal(ctx, link)
```

`EnterPortal` fails closed when no provider is installed.

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
| `qurl.ErrAssignmentRecoveryRequired` | Hub assignment exhausted its bounded transaction |
| `qurl.ErrCompletionRecoveryRequired` | Resume the exact persisted completion candidate |
| `*qurl.NativeCredentialRecoveryRequiredError` | Completed native credential state is absent or malformed; explicit native recovery or reprovisioning is required |
| `*qurl.AgentAssignmentChangedError` | The Hub assigned a new cell or generation that needs explicit adoption |
| `*qurl.APIError` | LayerV returned a non-2xx steady-state resource response |
| `*qurl.ServerDenyError` | qURL denied an authenticated NHP operation |

## Security notes

- Treat LayerV credentials, agent state, and qURL links like credentials. Do not
  log them.
- Pin Hub and assigned-cell identities; do not derive or infer their addresses.
- Keep the exact pending activation across ambiguous RAK delivery and the exact
  pending completion candidate across ambiguous completion delivery.
- Wipe the private-key bytes taken from `AgentRuntimeBinding` after the knock.
- Keep issuer credentials in protected state, KMS, a secret manager, or another
  protected store.
- Browser relay traffic and native UDP agent traffic are separate trust paths.

## Changes

### Unreleased

- Added the qURL Connector native UDP lifecycle: Hub assignment, assigned-cell
  OTP/REG/completion, direct knock, strict golden-vector conformance, crash-safe
  activation/completion, and explicit assignment refresh/reassignment
  boundaries.
- Registration retry budgets are per phase, so one call can span initial Hub,
  first REG, replacement Hub, second REG, and completion budgets. Use an outer
  context deadline when a smaller aggregate wall-clock ceiling is required.
- Removed the superseded public HTTP agent assignment/registration lifecycle.
  Steady-state resource CRUD remains HTTPS, and browser relay behavior is
  unchanged.
- Added sealed full-AgentState storage and AWS-backed AgentState stores.

## License

[MIT](LICENSE) © LayerV AI
