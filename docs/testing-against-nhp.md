# Testing qurl-go against NHP

There are two ways to exercise the SDK, and they answer different questions:

- **Loopback suites** — fast, credential-free, and broader than the live
  deployment. Use these for most work; they are the public, documented testing
  path.
- **Live sandbox** — proves interoperability with the deployed server build.
  The sandbox estate is internal to LayerV and its connection settings are no
  longer documented in this repository; see
  [ADR 0002](decisions/0002-sandbox-docs-internal-only.md).

## Local testing

Everything below runs on loopback with no credentials, no AWS account, and no
network access.

Full test suite:

```bash
make test
```

The complete native UDP lifecycle — enrollment, hub assignment, assigned-cell
registration, knock, and extend — against an in-process hub and cell:

```bash
go test ./qurl/ -run TestConnectAgentRuntime_UDPOnlyGoldenLifecycle -v
```

The fault matrix — DNS failure, timeout, packet loss, delay, reorder, replay,
duplication, cancellation, malformed and oversize datagrams, wrong hub key,
wrong cell key, unknown message types, multi-address bounds, and the
authenticated-invalid-assignment matrix:

```bash
go test ./tests/e2e/nativeudp/ -run TestNativeUDPClientFaultPaths -v
```

That suite covers cases the live deployment cannot produce on demand, which is
why it stays the better tool for most work.

### Writing your own local test

The pattern is a real UDP socket on loopback plus a resolver and dialer that
keep the public hostname as the logical destination:

```go
transport := nativeudp.Options{
    DeviceStaticPriv: devicePriv,
    Resolver:         myResolver, // returns a public address
    Dialer:           myDialer,   // redirects the socket to your local server
    Timeout:          3 * time.Second,
}
```

Two things bite people here:

- The resolver must return a **public** address. The SDK rejects a hostname that
  resolves only to loopback or private space, so returning `127.0.0.1` fails
  with `nativeudp.ErrResolve` before any packet is sent. Return something like
  `8.8.8.8` and let the dialer do the redirection.
- The hub's `Port` must be `443`. Any other port is rejected as an invalid
  assignment config.

`qurl/agent_assignment_noreply_test.go` is a small, self-contained example.
`relayknock/relayknocktest` has helpers for building authenticated replies if
your test needs a responder rather than a blackhole.

## Live sandbox

Sandbox is LayerV's shared, best-effort pre-production estate: it carries no
customer data, holds no availability guarantee, and can be redeployed under
you. It is internal to LayerV, and its concrete connection values — hostnames,
the hub public key, API origins, SSM paths — are not documented here (see
[ADR 0002](decisions/0002-sandbox-docs-internal-only.md)). Internal engineers
obtain them from internal configuration as a deployment JSON file; everyone
else should use the loopback suites above.

### Point the SDK at a deployment

The supported path is `qurl.ConnectAgentRuntime` with a deployment file: set
`QURL_DEPLOYMENT` to the file's path and the SDK reads its trust roots —
including the hub — from there, so no estate value is hardcoded in your
program.

```bash
export QURL_DEPLOYMENT=$HOME/.config/layerv/deployment.json
```

The file looks like this. **Every value below is a placeholder**; internal
engineers obtain the real file from internal configuration:

```json
{
  "issuers": [
    {
      "kid": "issuer-key-id",
      "spki_der_b64": "BASE64_P256_SPKI_DER"
    }
  ],
  "cells": [
    {
      "cell_id": "cell0",
      "host": "cell0.nhp.example.internal",
      "port": 443,
      "server_public_key_b64": "BASE64_X25519_CELL_KEY"
    }
  ],
  "relay_allowlist": ["relay.example.internal"],
  "hub": {
    "host": "hub.nhp.example.internal",
    "port": 443,
    "server_public_key_b64": "BASE64_X25519_HUB_KEY"
  }
}
```

With that in place, registration is the same call a production service makes:

```go
store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
if err != nil {
    return err
}
defer store.Close()

client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
    qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredential),
    qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
)
if err != nil {
    return err
}
defer binding.Destroy()
```

`qurl.WithAgentRuntimeHub` still exists for a program that must carry its trust
root explicitly — it wins over the deployment file — but for sandbox work the
file is the right home for those values:

```go
hub := qurl.HubBootstrap{
    Host:               "hub.nhp.example.internal", // placeholder
    Port:               443,
    ServerPublicKeyB64: hubPublicKeyFromInternalConfig(),
}

client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
    qurl.WithAgentRuntimeHub(hub),
    qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredential),
    qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
)
```

A network path is not authentication: you still need a **server-minted
enrollment credential**, issued internally. The steady-state HTTPS resource
`Client` the call returns likewise needs the deployment's API settings; for
sandbox those come from internal configuration too, and this repository does
not name the origin.

For code that needs only the raw hub-assignment exchange — no store, no
registration — the low-level primitive still exists:

```go
assignment, err := qurl.FetchInitialAgentAssignment(
    ctx, hub, agentID, enrollmentCredential, transport)
```

It is an advanced seam; `ConnectAgentRuntime` is what services should call.

### Give the SDK enough time

The assignment budget defaults to 30 seconds with four attempts. If you pass a
context deadline at or below that, your deadline wins the race and ends the
exchange early. Give the context meaningfully more than the budget — or lower
the budget explicitly with `qurl.WithAgentRuntimeAssignmentRetryBudget` (on the
raw assignment call, `qurl.WithAssignmentRetryBudget`) — so you get the SDK's
own typed recovery error rather than a truncated attempt sequence.

## When nothing answers

If the hub or a cell goes silent — mid-deploy, redeployed, or blocked by your
own network's egress rules — the SDK now says so explicitly instead of hanging
opaquely. The example below uses a placeholder hostname; the shape is what
matters:

```
qurl: no reply from hub.nhp.example.internal:443 after 4 attempt(s) over 30s;
the host resolved and every datagram was sent, but nothing answered.
Either the server is not running or the network path drops UDP to it
silently (a source-fenced security group or egress firewall drops without
ICMP, which looks identical from here). Verify your source address is
permitted to reach hub.nhp.example.internal:443: nativeudp: udp exchange
failed: nativeudp: no reply before deadline: ... i/o timeout
```

Match it in code with either:

```go
errors.Is(err, qurl.ErrEndpointNoReply)
```

or, for the destination and attempt count:

```go
var silent *qurl.EndpointNoReplyError
if errors.As(err, &silent) {
    log.Printf("no reply from %s after %d attempts", silent.Endpoint, silent.Attempts)
}
```

**The SDK cannot tell you which cause applies.** A dropped packet generates no
ICMP and no RST, so "the server is down" and "something between us dropped it"
are identical from the client. The first things to check are your own network's
outbound UDP 443 policy and whether the deployment is mid-deploy.

Earlier releases returned a bare `context deadline exceeded` here, discarding
the destination, attempt count, and transport cause. That is fixed; when the
caller's context ended the wait, `context.DeadlineExceeded` remains in the chain
so existing cancellation handling keeps working.

## Release evidence

Interoperability evidence for a release used to come from the attended `Native
UDP sandbox proof` workflow, which ran a full authenticated lifecycle on a fresh
server-minted credential and published an evidence manifest. That proof was
retired in August 2026 along with the NHP-side controller that dispatched it.

There is now one narrower attended rollout canary:
[`otp-schema-v2-canary.yml`](../.github/workflows/otp-schema-v2-canary.yml)
registers exactly one SDK agent with a real emailed code and asserts warm-open
idempotency. It is main-only, protected by a dedicated reviewed Environment,
and ordered after a separately governed qurl-service reset/PASS receipt. It does
not grant qurl-go storage authority. Instead, after warm-open it emits one
short-lived linked binding commitment with no raw identifiers; a separately
protected qurl-service read-only verifier must authenticate the exact run,
match the complete server-side triple, and issue PASS. The canary is not a
replacement for the retired general proof and not an automated release gate.
See [OTP schema-v2 registration canary](otp-schema-v2-canary.md) for its exact
scope, verifier contract, blocker, and rollout order. Ad-hoc developer testing
against sandbox remains available, with the limits above still applying.

The loopback fault-path suite (`TestNativeUDPClientFaultPaths` in
`tests/e2e/nativeudp`) is unaffected and still runs in ordinary CI — it covers
the failure modes sandbox cannot produce on demand.
