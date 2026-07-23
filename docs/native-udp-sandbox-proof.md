# Native UDP sandbox proof

The attended `Native UDP sandbox proof` workflow exercises the public Go SDK
against the real sandbox Hub and its authenticated assigned cell. It does not
use a browser relay, mock UDP transport, or HTTP lifecycle endpoint. The job is
manual because each fresh run consumes a server-minted enrollment credential.
Every dispatch selects `pre_removal` or `post_removal` and supplies base64 of
the exact non-secret cross-repository sandbox deployment manifest plus the run
id of a successful, same-phase qURL Connector strict proof. The workflow
rejects duplicate keys, trailing input, non-finite numbers, and unknown or
missing fields before atomically publishing canonical JSON. It validates the
retirement state, the qurl-go SHA under test, and the exact existence of every
SHA in the fixed eleven-repository map at its explicitly mapped GitHub repository.
It also requires the tested SHA to be the current head of open, same-repository
qurl-go PR #93 targeting `main`, and requires GitHub to report that exact
commit as cryptographically verified.
It records all supplied image digests, validates the public Hub trust root, and
requires at least two cells with distinct endpoint names and server identities;
the blocking topology/retirement evidence must still prove those images are
actually deployed, while the Connector image is separately attested below. A
post-removal dispatch must also name a successful pre-removal run of the same
workflow.
The workflow resolves exactly one unexpired artifact for that run and exact
phase/SHA/attempt name through the Actions API, verifies the archive SHA-256,
rejects unsafe paths, symlinks, duplicate or extra files, and bounded declared
and actual expansion, then accepts only the four exact root files. It requires
canonical evidence, deployment manifest, inventory, and retired-lifecycle
surface bytes. The two runs must use the same executable proof-harness digest,
frozen full inventory mapping, retired-surface contract, Hub/cell topology,
FRP module/repository, and qRTS repository/image identities. The Connector's
module map is a
strict object containing only the Connector binary's embedded `frp` and
`qurl_go` module SHAs; its FRP SHA must equal `repositories.frp`, while its
qurl-go module SHA may intentionally differ from the qurl-go proof commit in
`repositories.qurl_go`. Connector provenance is checked against these embedded
module identities, not against the phase's qurl-go proof HEAD. Each qurl-go run
is bound to its own manifest SHA because qurl-go's HTTP cleanup is itself part
of the isolated cut; qurl-go is therefore in the explicit retirement set. The
qurl-go and Connector repository SHAs, Connector image, and Connector's
embedded qurl-go module may be repinned for the mechanically constrained cut;
website and the other generated-artifact owners are also retirement-set inputs.
At least one retirement repository, permitted module/image repin, or deployed
NHP/qurl-service image must actually differ. A phase label alone is not a
post-removal proof.
The post-removal Connector proof must also name the exact Connector
pre-removal run attested by the paired qurl-go pre-removal evidence; baselines
from two otherwise valid but unrelated Connector proof pairs cannot be mixed.

Configure the protected GitHub `sandbox` environment before dispatching it:

- secret `QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL`: a fresh, server-minted
  `connector_bootstrap`, `bootstrap`, or `agent` enrollment credential;
- secrets `OPS_ROUTINES_APP_ID` and `OPS_ROUTINES_APP_PRIVATE_KEY`: credentials
  for the organization App installed on exactly the repositories enumerated by
  the workflow. Its minted token has only `actions:read` and `contents:read` and
  lets the proof adapters verify the exact private-repository manifest,
  including Connector, NHP, qURL service, qRTS, FRP, and website, instead of
  trusting operator-entered digests;
- variables `QURL_GO_SANDBOX_HUB_HOST`, `QURL_GO_SANDBOX_HUB_PORT` (currently
  `62206`), and `QURL_GO_SANDBOX_HUB_SERVER_PUBLIC_KEY_B64`: the atomic public
  Hub trust root;
- variable `QURL_GO_SANDBOX_KNOCK_RESOURCE_ID`: a live sandbox Connector knock
  resource;
- optional variable `QURL_GO_SANDBOX_EXPECTED_CELL_ID`: an operator assertion
  when a particular assignment is expected.

The required `connector_proof_run_id` dispatch input is not trusted on its own.
A workflow-only App token resolves qURL Connector's exact
`.github/workflows/sandbox-smoke.yml` workflow id, then verifies the run was a
successful `workflow_dispatch` at the manifest's exact Connector SHA and
attempt. The manifest SHA must also be the current head of open,
same-repository qURL Connector PR #452 targeting `main`, and its exact commit
must be cryptographically verified by GitHub. It downloads only the exact
phase/SHA/attempt artifact, verifies the
GitHub artifact archive digest and safe three-file shape, rejects ambiguous
JSON, requires canonical Connector evidence and a byte-identical deployment
manifest, and recomputes the inventory and scenario-contract digests. The
Connector scenario contract uses the producer's exact algorithm: sort rows by
`name`, project only `name`, `status`, `test`, `requires_env`, and `reason`
(defaulting missing `test` to JSON `null` and missing `requires_env` to `[]`),
then hash ASCII, key-sorted, compact JSON. The App
token and raw Connector evidence are never placed in the `go test` environment.
The named Go adapter receives only a read-only allowlisted attestation and its
SHA-256 digest; that attestation carries no credential or raw packet evidence.

Strict mode fails when any required value is absent. It records the exact clean
Git build SHA, Hub trust root, deployment/inventory/proof-harness digests, and
every authenticated assigned-cell tuple in a 30-day allowlisted JSON evidence
manifest. The full normalized inventory mapping and checked-in exact retired
lifecycle surface have separately reviewed literal SHA-256 values
(`1dff59c8188ca1cb72847135b5e4a9e2c2bba4f737d788379c93a568152dc88d`
and `3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c`,
respectively); both are carried in evidence and must match across phases. The
latter enumerates the
public and internal HTTP method/path/operation identities, retired relay SDK
aliases, retained relay path, and forbidden lifecycle message types. The
manifest, inventory, and retired surface are snapshotted read-only and all input
digests are rechecked after the test process. Raw `go test -json` output is
redirected only to an ephemeral runner file: it is neither printed to the
Actions log nor uploaded, and it is deleted before artifact publication.
The test writes a separate strict non-secret provenance sidecar containing the
Hub host/port/key fingerprint and every authenticated assigned-cell
generation/revision/lease/host/port/key fingerprint observed by the public SDK.
The workflow requires the exact generated agent id, canonical bounded lease
timestamps, safe positive integer generation/revision counters no greater than
`9007199254740991`, and exactly four ordered observations: registration, warm
open, reassignment, and refresh. Registration and warm open must preserve the
entire assignment binding; reassignment must move to a different deployed cell
at a strictly newer generation; refresh must preserve the entire reassigned
binding. At least two distinct authenticated cell ids, hosts, and server
identities must come from the supplied deployment manifest. Every artifact
states `gate_passed`, the independent strict-test and inventory-enforcement
outcomes, input integrity, two-cell
provenance, and exact implemented/blocking/failure/skip/pass counts, so a
partial or one-cell run cannot be mistaken for proof.
The workflow requires exactly one passing and
zero skipped events for every scenario marked `implemented` in
`tests/e2e/nativeudp/pre_retirement_scenarios.json`: provenance, fail-closed Hub
DNS resolution, one-attempt real-socket UDP timeout, fresh registration,
persisted warm open, Hub refresh with authenticated reassignment adoption,
assigned-cell KNK, assigned-cell EXT, and zero lifecycle HTTP calls.
Any skip beneath a required scenario's nested subtest namespace also fails the
parent scenario, and every failing event is counted globally. A successful
inventory scan cannot mask a failed strict `go test` process: `strict_outcome`
is independently captured and must be `success` in current, paired pre-removal,
and final published evidence.
The attended job, Go process, and whole-lifecycle backstops are 75, 60, and 50
minutes respectively so the complete fault matrix remains runnable. Exact
per-operation deadlines, retry counts, and cancellation assertions remain the
actual behavioral bounds; the larger outer ceilings do not relax them.

The HTTP proof installs both the SDK's explicit resource-client trap and a
process-wide default-transport trap. Any lifecycle HTTP attempt is observable
and fails the run. Successful live Hub/cell exchanges retain the SDK's real
public resolver and dialer defaults. Registration, refresh, KNK, and EXT pass no
UDP-bound or retry-budget override, so the proof measures the shipped three-
second per-address timeout, three-address fan-out, and four-attempt/30-second
assignment budget. The DNS-failure case records the exact Hub
hostname requested before delegating to the OS resolver for a reserved failing
name; the timeout case records the exact public logical destination before a
test-only dialer redirects the real UDP socket to an ephemeral local no-reply
peer. Neither seam weakens the production endpoint validation path.

These nine SDK scenarios prove public API outcomes; they do not by themselves
attribute every NHP message visible on the wire. Exact Hub
LST/COK/cookie-bound proof-LST/LRT, assigned-cell REG/RAK and completion
LST/LRT, and KNK/ACK/EXT/ACK sequences remain separate blocking
`wire.*` inventory rows until the sandbox orchestrator supplies packet/log
evidence tied to the ephemeral agent and session.

The versioned 68-row inventory is the complete pre-removal and post-removal
release gate. It also tracks OTP behavior, authenticated-invalid-assignment and
multi-address matrices, two-cell reassignment and exact completion recovery,
DNS/key/source negatives, phase-complete replay/duplicate/loss/reorder/delay/
timeout/cancellation/malformed/oversize/unknown-message faults, independent
Go SDK real-KMS sealed cold enrollment and credentialless warm restart, SDK
packet-capture/legacy-route counters, producer-to-wire public resource versus
knock identity, and the Connector's hardened-container, FRP, backend,
resource-versus-knock identity, journal, packet-capture, and exact artifact
evidence. It includes a mandatory attestation binding the complete Connector
inventory and successful hardened run to the same proof phase and deployment
manifest. Five phase-aware retirement rows also require deployed HTTP/OpenAPI,
retained-relay rejection of OTP/REG/LST/LRT before waiter/plugin/Authority,
NHP registrar/interface, generated artifact, and Terraform saved-plan/live-state
proof; changing only a manifest label or commit is insufficient. SDK-owned work
is `todo`; Connector and topology work begins as an
`external_dependency` and may become `implemented` only when an exact named
adapter under `TestSandboxConnectorUDP`, `TestSandboxWireEvidence`, or
`TestSandboxTopology` verifies immutable repository SHA, run, inventory, and
artifact evidence. The attended command explicitly includes all four proof top
levels, so external rows are finishable without reassigning their owner. Both
non-implemented statuses are blocking. The workflow deliberately
ends red while any required row is not implemented and backed by an exact named
pass, so today's 10 implemented and 58 blocking scenarios cannot authorize any
retirement or removal. The DNS and timeout cases are inherently client-side failure paths,
run in ordinary CI as well as the attended runner through only the public SDK.
Add other evidence only when the real Hub/Authority/cell prerequisites and
safe client-side fault injection exist; never convert an unavailable operation
into a skipped or simulated green result.
