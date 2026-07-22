# Native UDP sandbox proof

The attended `Native UDP sandbox proof` workflow exercises the public Go SDK
against the real sandbox Hub and its authenticated assigned cell. It does not
use a browser relay, mock UDP transport, or HTTP lifecycle endpoint. The job is
manual because each fresh run consumes a server-minted enrollment credential.

Configure the protected GitHub `sandbox` environment before dispatching it:

- secret `QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL`: a fresh, server-minted
  `connector_bootstrap`, `bootstrap`, or `agent` enrollment credential;
- variables `QURL_GO_SANDBOX_HUB_HOST`, `QURL_GO_SANDBOX_HUB_PORT` (currently
  `62206`), and `QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64`: the atomic public
  Hub trust root;
- variable `QURL_GO_SANDBOX_KNOCK_RESOURCE_ID`: a live sandbox Connector knock
  resource;
- optional variable `QURL_GO_SANDBOX_EXPECTED_CELL_ID`: an operator assertion
  when a particular assignment is expected.

Strict mode fails when any required value is absent. It records the exact clean
Git build SHA, Hub trust root, and every authenticated assigned-cell tuple in a
30-day `go test -json` artifact. The workflow requires exactly one passing and
zero skipped events for every scenario marked `implemented` in
`tests/e2e/nativeudp/pre_retirement_scenarios.json`: provenance, fresh
registration, persisted warm open, Hub refresh with authenticated reassignment
adoption, assigned-cell KNK, assigned-cell EXT, and zero lifecycle HTTP calls.

The HTTP proof installs both the SDK's explicit resource-client trap and a
process-wide default-transport trap. Any lifecycle HTTP attempt is observable
and fails the run. UDP resolution and dialing remain the SDK's real public
defaults.

These seven SDK scenarios prove public API outcomes; they do not by themselves
attribute every NHP message visible on the wire. Exact LST/LRT/REG/RAK/
completion and KNK/ACK/EXT/ACK sequences remain separate blocking
`wire.*` inventory rows until the sandbox orchestrator supplies packet/log
evidence tied to the ephemeral agent and session.

The versioned inventory is the complete pre-retirement release gate. It also
tracks OTP behavior, two-cell reassignment and recovery, DNS/key/source
negatives, replay/duplicate/loss/reorder/delay/timeout/cancellation and malformed
packet faults, sealed cold/warm state, and the Connector's hardened-container,
FRP, backend, resource-versus-knock identity, journal, packet-capture, and exact
artifact evidence. SDK-owned work is `todo`; Connector and topology work is an
`external_dependency`. Both statuses are blocking. The workflow deliberately
ends red while any required row is not implemented and backed by an exact named
pass, so today's seven happy-path scenarios cannot authorize HTTP lifecycle
retirement. Add evidence only when the real Hub/Authority/cell prerequisites and
safe client-side fault injection exist; never convert an unavailable operation
into a skipped or simulated green result.
