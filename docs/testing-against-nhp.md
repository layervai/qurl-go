# Testing qurl-go against NHP

There are two ways to exercise the SDK, and they answer different questions:

- **Loopback suites** — fast, credential-free, and broader than the live
  deployment. Use these for most work.
- **Live sandbox** — proves interoperability with the deployed server build.
  Open to developers inside and outside the company on UDP 443; see
  [ADR 0001](decisions/0001-sandbox-nhp-access.md).

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
go test ./qurl/ -run TestRegisterAgentRuntime_UDPOnlyGoldenLifecycle -v
```

The fault matrix — DNS failure, timeout, packet loss, delay, reorder, replay,
duplication, cancellation, malformed and oversize datagrams, wrong hub key,
wrong cell key, unknown message types, multi-address bounds, and the
authenticated-invalid-assignment matrix:

```bash
go test ./tests/e2e/nativeudp/ -run TestNativeUDPClientFaultPaths -v
```

That suite covers cases the live deployment cannot produce on demand, which is
why it stays the better tool even though sandbox is reachable.

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

Sandbox accepts UDP 443 from any source. There is no allowlist, no VPN, and no
access request — if your network permits outbound UDP 443, it works.

| Setting | Value |
| --- | --- |
| Hub host | `hub.nhp.layerv.xyz` |
| UDP port | `443` (hub and cells alike) |
| Hub public key | `UhVQcrKoJ2LhQlRtuIItBjxXR2wA/VvZvTmqnzT+GS8=` |
| Cells | `cell0.nhp.layerv.xyz`, `cell1.nhp.layerv.xyz` |

```go
hub := qurl.HubBootstrap{
    Host:               "hub.nhp.layerv.xyz",
    Port:               443,
    ServerPublicKeyB64: "UhVQcrKoJ2LhQlRtuIItBjxXR2wA/VvZvTmqnzT+GS8=",
}

assignment, err := qurl.FetchInitialAgentAssignment(
    ctx, hub, agentID, enrollmentCredential, transport)
```

You still need a **server-minted enrollment credential**; opening the network
path did not remove authentication. Ask in the sandbox channel for one.

The hub public key is deployment configuration, not a constant to hardcode
permanently — read it from your deployment JSON via `QURL_DEPLOYMENT` if you are
writing something durable. It is published at SSM
`/sandbox/nhp/control/hub/identity/public-key`.

Sandbox is a shared, best-effort environment. It carries no customer data,
holds no availability guarantee, and can be redeployed under you.

### Give the SDK enough time

The assignment budget defaults to 30 seconds with four attempts. If you pass a
context deadline at or below that, your deadline wins the race and ends the
exchange early. Give the context meaningfully more than the budget — or lower
the budget explicitly with `qurl.WithAssignmentRetryBudget` — so you get the
SDK's own typed recovery error rather than a truncated attempt sequence.

## When nothing answers

If the hub or a cell goes silent — mid-deploy, redeployed, or blocked by your
own network's egress rules — the SDK now says so explicitly instead of hanging
opaquely:

```
qurl: no reply from hub.nhp.layerv.xyz:443 after 4 attempt(s) over 30s;
the host resolved and every datagram was sent, but nothing answered.
Either the server is not running or the network path drops UDP to it
silently (a source-fenced security group or egress firewall drops without
ICMP, which looks identical from here). Verify your source address is
permitted to reach hub.nhp.layerv.xyz:443: nativeudp: udp exchange failed:
nativeudp: no reply before deadline: ... i/o timeout
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
are identical from the client. Since sandbox no longer restricts sources, the
first things to check are your own outbound UDP 443 policy and whether sandbox
is mid-deploy.

Earlier releases returned a bare `context deadline exceeded` here, discarding
the destination, attempt count, and transport cause. That is fixed; when the
caller's context ended the wait, `context.DeadlineExceeded` remains in the chain
so existing cancellation handling keeps working.

## Release evidence

Interoperability evidence for a release comes from the attended `Native UDP
sandbox proof` workflow, which runs a full authenticated lifecycle on a fresh
server-minted credential and publishes an evidence manifest. Ad-hoc developer
testing against sandbox is not a substitute. See
[Native UDP sandbox proof](native-udp-sandbox-proof.md).
