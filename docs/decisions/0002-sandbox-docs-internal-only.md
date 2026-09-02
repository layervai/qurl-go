# ADR 0002: Sandbox estate documentation is internal-only

- **Status:** Accepted; amended 2026-09-01 (scope clarification, below)
- **Date:** 2026-08-17
- **Applies to:** this repository's public documentation of the NHP sandbox
  estate's connection details
- **Decision owner:** qurl-go maintainers
- **Implementation:** this repository, documentation only; the sandbox network
  fence lives in `layervai/nhp` and is not touched by this ADR

## Context

qurl-go is pre-GA and this repository is public. ADR 0001
([Sandbox NHP is open to developers on UDP 443](0001-sandbox-nhp-access.md))
opened the sandbox estate to developers inside and outside the company and, as
part of that, deliberately published the estate's concrete connection details
here: the hub hostname, the hub public key, the cell hostnames, and the SSM
path the key is published at.

The maintainers have since decided the LayerV sandbox estate is internal to
LayerV. Whatever the network permits, this public repository should not be
where readers obtain the estate's concrete coordinates.

## Decision

**This repository no longer documents concrete sandbox estate values** —
hostnames, API origins, public keys, or SSM paths. Internal engineers obtain
sandbox connection settings from internal configuration (a deployment JSON
supplied via `QURL_DEPLOYMENT`, and the matching HTTPS API settings), not from
these docs, which carry placeholder values only.

The loopback suites remain the public, documented testing path. They are
credential-free, cover fault paths the live estate cannot produce on demand,
and need no estate values at all.

## What this ADR does not change

Scope honesty, so nobody mistakes a documentation policy for a security
control:

- **The network fence.** What the sandbox estate accepts, and from where, is
  decided in `layervai/nhp` Terraform. This ADR changes what this repository
  documents; it does not alter any edge, security group, or validation there.
- **Functional code.** `qurl/agent_assignment.go` retains the release-gated
  trust allowlist suffix `.layerv.xyz` alongside `.layerv.ai`. That constant is
  functional trust configuration — which endpoint apexes the SDK will accept —
  not documentation, and it is deliberately retained. Test fixtures use
  placeholder hosts and locally generated keys.

## Amendment, 2026-09-01: component names, by suffix, are not estate coordinates

Raised by [#235](https://github.com/layervai/qurl-go/pull/235), which added
component names to the OTP registration gate's failure-diagnosis message and
asked whether this ADR wanted them gone. **It does not.** Recorded here so the
next change to name one does not re-argue it.

**Permitted:** names of estate components carried by SUFFIX only — the issuer
cells (`ca-iro-cell0`, `ca-iro-cell1`) and the assignment authority (`ca-ia`)
— and the authority's `AuthorityOperation` values (`IssueRegistrationOTP`,
`IssueAssignment`).

Two separate reasons, because these are two different kinds of string:

- **The component suffixes are not coordinates.** They are none of the four
  things the Decision enumerates: not a hostname, an API origin, a public key,
  or an SSM path. Nor do they function as coordinates in the sense the Context
  means — a reader holding them still cannot reach or locate anything, because
  the AWS account, the deployment prefix and credentials are each still
  required, and none of those three is committed anywhere in this repository.
  They are inert without internal access one already has.
- **The operation values are not estate values at all.** They are the
  authority's log schema — identifiers its consumers key on — not a
  description of where anything is deployed. `IssueRegistrationOTP` has been
  committed here since before this ADR without objection; `IssueAssignment` is
  the same class of string and is ruled the same way.

ADR 0001 is the qualifier on all of that, and it is worth being exact about
how far it reaches. Its ingress table names `cell0` and `cell1` — the bare
ordinals, as rows describing public UDP edges — and this ADR deliberately left
that body intact as a historical record. So the ORDINALS have been named here
since before this ADR existed and were never the part anyone treated as
sensitive. The `ca-iro-` component prefix is genuinely new, and is permitted
on the reasoning above rather than on this precedent, which does not cover it:
the precedent is corroboration, not the load-bearing support.

**Not ruled on:** the AWS profile name the same message already carries. It
was committed before #235 and is not what #235 asked, so it is left as it
was — untouched rather than settled.

**Still out, and not reopened by this:** VPC endpoint ids, EC2 instance ids,
account-scoped ARNs, and the deployment prefix. The AWS region is also out,
and is now out without qualification:
[#237](https://github.com/layervai/qurl-go/pull/237) removed the one literal
ADR 0001 still carried, so no region appears anywhere in this repository's
documentation. The mechanical reason it must stay that
way is worth stating so it is not "fixed" later: it is supplied as the
`OTP_E2E_MAILBOX_REGION` secret, and Actions masks a secret's value everywhere
it appears in a log, a test's own error string included. A committed literal
would render as `***` in the gate job log that is the only venue that message
exists for, destroying the diagnostic it was added to provide.

**Why the cost side was decisive.** The message uses the cell names to correct
an actively wrong reading: sandbox issuance is cell0-only, so `ca-iro-cell1`
has never been invoked and a reader who finds it empty must not take that as
the never-invoked fault branch. That correction cannot be stated about the
glob `ca-iro-cell*` this repository carried before — a glob cannot say which
member of itself is always empty — and the asymmetry it guards against had
already sent two investigations to the wrong conclusion. Redacting would have
cost a live diagnostic to remove strings that grant no access.

**If this is ever reversed,** the cost is bounded and known, because
`tests/e2e/nativeudp/otp_failure_diagnostics_test.go` requires none of the
three component suffixes: the `ca-iro-cell1` assertion is conditional, firing
only if the name is present and then demanding its "never been invoked"
qualifier nearby. Verified by probe rather than assumed, three of them, all
run over the whole package: redacting the three suffixes together leaves `go
test ./tests/e2e/nativeudp/` green; redacting the workstation profile on its
own leaves it green; and keeping the name while dropping the qualifier reds
it. Those probes run the whole
package rather than a `-run` subset, because the whole package is what the
REQUIRED check executes, and the narrower probe would not have covered the
source-level fences at the end of the same file. The `AuthorityOperation`
values are the exception: those two ARE pinned unconditionally, deliberately,
as log identifiers rather than coordinates, so removing one reds a REQUIRED
check.

The rest of the cost is edit surface, and it is THREE files rather than the
one an earlier version of this note claimed. The message carries the literals;
this document quotes all five in the Permitted list above; and the fence
carries them a third time — `ca-iro-cell1` in its conditional and its failure
string, and BOTH cells in the comment above them, which quotes the unqualified
phrasing it exists to forbid. The fence stays green under redaction — that is
the property verified above — but green is not the same as edited: a redactor
who stops short leaves it quoting a string that exists nowhere, with nothing
red to say so. Counting this document is intrinsic to reversing a recorded ruling
rather than a reason not to record it; counting the fence is simply the
correct count, and it is stated here because a future redactor arrives at this
ADR before they arrive at a comment in a test file.

## Consequences

- [Testing qurl-go against NHP](../testing-against-nhp.md) is rewritten: the
  live-sandbox section teaches the supported registration path with clearly
  marked placeholder values and points internal engineers at internal
  configuration for the real ones.
- ADR 0001 is annotated as superseded **in its publication aspect only** — the
  connection details quoted in its body are historical and no longer maintained
  here. Its body stays intact as the record of why access was opened.
- External developers no longer have a documented path to the sandbox estate.
  That is the accepted cost of this decision: ADR 0001 opened access precisely
  so that developers outside the company could use the environment, and this
  repository's docs no longer support that use.

## Supersedes

ADR 0001, in one aspect only: the choice to publish the sandbox estate's
connection details in this repository. The access decision recorded there —
what the sandbox network edge permits — was implemented in `layervai/nhp` and
is neither reversed nor reaffirmed by this ADR.
