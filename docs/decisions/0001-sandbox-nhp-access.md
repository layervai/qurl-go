# ADR 0001: Sandbox NHP is open to developers on UDP 443

- **Status:** Accepted
- **Date:** 2026-08-03
- **Applies to:** qurl-go v0.3.0 and later; the `nhp.layerv.xyz` sandbox estate
- **Decision owner:** qurl-go / NHP maintainers
- **Implementation:** `layervai/nhp` (Terraform); this repository carries the SDK
  and developer-facing side

## Context

Developers could not reach the sandbox NHP hub (`hub.nhp.layerv.xyz`) from
anywhere except the UDP proof runner. A probe built against the released v0.3.0
calling `qurl.FetchInitialAgentAssignment` from an ordinary network measured:

```
elapsed=30.001s
error=context deadline exceeded
errors.Is ErrResolve                 = false   (DNS resolved fine)
errors.Is ErrInvalidAssignmentConfig = false   (host/port/key were accepted)
errors.Is ErrServerUnauthenticated   = false   (nothing replied at all)
```

Connection settings were correct and verified live: host `hub.nhp.layerv.xyz`,
UDP port `443`, server public key
`UhVQcrKoJ2LhQlRtuIItBjxXR2wA/VvZvTmqnzT+GS8=`. This was purely network
reachability.

### What the fencing was

Verified live on 2026-08-03 in the sandbox account, `us-east-2`. All three
public UDP edges carried exactly one security group, every rule UDP 443:

| Edge | Permitted ingress |
| --- | --- |
| Hub | the proof runner's egress `/32` only |
| cell0 | the proof runner's egress `/32` + 7 managed AC EIPs |
| cell1 | the proof runner's egress `/32` only |

The single permitted source was the UDP proof runner's egress EIP. The seven
extra cell0 addresses are the managed AC EIP pool needed for registration —
infrastructure, not developer access.

(The account, NLB names, security-group ids, and addresses this section
originally quoted are deliberately not reproduced: this repository is public.
They are in `layervai/nhp`, which is not.)

Critically, **the cells were fenced identically to the hub**, so hub access
alone would have bought nothing: assignment would succeed and registration
against the assigned cell would hang one step later.

### Why the fence existed

It was a staged-rollout control for the sandbox measurement phase, not a
permanent architecture. The evidence is in the Terraform itself: the production
roots gate the same variables with `== null` and describe them as unset
"throughout sandbox measurement," while
`terraform/environments/prod/variables.tf` calls its own variable "optional
exact /32 sources for a **future reviewed production NHP public-edge
migration**." A public NHP edge was always the intended end state; the sandbox
fence was scaffolding around a measurement.

The rollout ledger
(`docs/runbooks/prod-rollout-ledger/2026-07-26-pr-3453-udp-source-fence.md`)
said any change here needs "a separate reviewed edge/source policy." This ADR is
that policy.

One clarification, because it was cited as evidence for the fence being
inviolable and does not say that: the validation in
`terraform/environments/sandbox-hub-dns/variables.tf` whose message reads
"Sandbox proof DNS must target exactly the source-fenced Hub NLB" only pins the
**NLB name** the DNS record aliases (an equality check on `var.hub_nlb_name`).
It prevents the record being repointed at a different load balancer; it does not
enforce the fencing. The ingress-CIDR validations did that.

## Decision

**The sandbox NHP hub and both sandbox cells accept UDP 443 from
`0.0.0.0/0`.** Developers inside and outside the company can run qurl-go against
sandbox from any network without requesting access.

Production is explicitly **not** in scope. Its `== null` validations are
untouched, so this change cannot open a production edge.

### Why not an allowlist

The requirement includes developers outside the company, whose source addresses
are unknown, unstable, and not ours to enumerate. A per-person or per-office
allowlist cannot satisfy it: laptop egress is dynamic, external contributors
have no stable address to register, and every add or stale-entry removal would
be a Terraform apply against a control-plane root. The list would be
permanently wrong in the permissive direction, which is the worst failure mode
for an allowlist — all the operational cost of a fence with none of the
assurance.

### Why this is defensible

NHP is a network-hiding knock protocol designed to sit on a public UDP port. It
does not respond to unauthenticated packets at all, authenticates via a Noise
handshake against a pinned server key, and implements cookie-based
return-routability for both the hub LST and assigned-cell reknock paths — the
standard defence against spoofed-source UDP amplification. Exposure to arbitrary
sources is the operating condition the protocol was built for, not an exception
to it. An unauthenticated scanner reaching the sandbox hub sees exactly what a
blocked developer saw: silence.

## Risks accepted

These are real and are being accepted deliberately, not overlooked:

- **Sandbox becomes internet-reachable.** It will be scanned and probed. NHP's
  silent-drop and cookie challenge are the mitigations; NLB and Fargate capacity
  are finite, so a determined flood can still degrade the sandbox estate.
  Sandbox carries no customer data and its availability is not a production
  concern.
- **The proof pipeline loses a negative control.** The post-rollout check
  "timeout from an unrelated public source" can no longer pass, because that is
  now a supported access path. The proof's positive assertions — that the proof
  runner completes a full authenticated lifecycle — are unaffected.
- **Source attribution weakens.** Sandbox traffic was previously attributable to
  one EIP. It no longer is. Sandbox evidence therefore cannot be used to argue
  anything about source provenance.
- **This does not set a production precedent.** Any production public-edge
  activation still requires its own reviewed policy, saved-plan sequence, and
  rollback contract, per the existing ledger.

## Consequences

- Developers point qurl-go at `hub.nhp.layerv.xyz:443` directly. See
  [Testing qurl-go against NHP](../testing-against-nhp.md).
- The loopback suites remain the faster and broader tool for most work; they
  cover fault paths sandbox cannot produce on demand. Live sandbox is for
  interop against the deployed server build.
- The attended `Native UDP sandbox proof` workflow continues unchanged for
  release evidence. See [Native UDP sandbox proof](../native-udp-sandbox-proof.md).
- The environment-level Terraform guards are **not deleted** — they are repinned
  to the new intended value, so accidental drift still fails a plan. The
  module-level rule still rejects every broad CIDR except the exact, greppable
  literal `["0.0.0.0/0"]`.

## The SDK failure mode was fixed independently

A blocked client used to hang to its context deadline and return a bare
`context deadline exceeded` — no destination, no attempt count, no transport
cause. That is bad under any access policy, and it stays fixed now that the
common cause is gone, because the same silence occurs whenever a sandbox
deployment is down, mid-deploy, or unreachable from a restrictive network:

- `nativeudp.ErrNoReply` marks the transport miss where the datagram was written
  and the socket deadline expired with nothing back. It accompanies
  `nativeudp.ErrTransport` and does not change retry classification.
- `qurl.ErrEndpointNoReply` and `*qurl.EndpointNoReplyError` report the logical
  destination, attempt count, elapsed time, and final cause when an entire
  bounded exchange was silence. When the caller's own context ended the wait,
  `context.DeadlineExceeded` stays in the chain, so existing cancellation
  handling is unaffected.

The SDK does not claim to distinguish "not permitted" from "server is down": a
DROP produces no ICMP and no RST, so the two are byte-for-byte identical at the
client. The error names the observation and states both candidate causes.

## Supersedes

Nothing. An earlier draft of this ADR recommended keeping sandbox
proof-pipeline-only; that recommendation was reviewed and not adopted, because
it did not meet the requirement that developers outside the company be able to
use the environment.
