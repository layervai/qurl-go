# ADR 0002: Sandbox estate documentation is internal-only

- **Status:** Accepted
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
- **Git history.** The removed values remain in this repository's history and
  released tags regardless of what the current docs say. This is a
  forward-looking publication policy, not a secret scrub — the values were
  never secrets.
- **Functional code.** `qurl/agent_assignment.go` retains the release-gated
  trust allowlist suffix `.layerv.xyz` alongside `.layerv.ai`. That constant is
  functional trust configuration — which endpoint apexes the SDK will accept —
  not documentation, and it is deliberately retained. Separately, one loopback
  test fixture (`qurl/agent_assignment_noreply_test.go`) still embeds the
  sandbox hub public key and cites its SSM path; that is code, not
  documentation, and is flagged for separate review rather than silently kept.
- **The sibling repo.** The public `qurl-connector` repository still carries
  estate values in non-markdown files (workflows, test fixtures,
  `tests/e2e/sandbox/sandbox-deployment.json`). Out of scope for this ADR;
  flagged for separate action.

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
