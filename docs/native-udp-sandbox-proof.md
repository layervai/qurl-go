# Native UDP sandbox proof

The attended `Native UDP sandbox proof` workflow exercises the public Go SDK
against the real sandbox Hub and its authenticated assigned cell. It does not
use a browser relay, mock UDP transport, or HTTP lifecycle endpoint. The job is
manual because each fresh run consumes a server-minted enrollment credential.
Every dispatch selects `pre_removal` or `post_removal` and supplies strict
canonical base64 of the exact non-secret cross-repository sandbox deployment
manifest and public Hub/cell runtime sidecar, the authenticated NHP producer
run/attempt/signed-main SHA/artifact ID/artifact digest. The workflow
rejects duplicate keys, trailing input, non-finite numbers, and unknown or
missing fields before atomically publishing canonical JSON. It validates the
retirement state, the qurl-go SHA under test, and the exact existence of every
directly consumed repository SHA at its explicitly mapped GitHub repository.
External deployment SHAs remain authenticated by the signed NHP producer
artifact and are joined by the final NHP controller.
It also requires the tested SHA to be the current head of open, same-repository
qurl-go PR #93 targeting `main`, and requires GitHub to report that exact
commit as cryptographically verified.
It records all supplied image digests, validates the public Hub trust root, and
requires exactly the ordered `cell0` and `cell1` endpoints with distinct names
and server identities;
the blocking topology/retirement evidence must still prove those images are
actually deployed. A
post-removal dispatch must also name a successful pre-removal run of the same
workflow.
The workflow resolves exactly one unexpired artifact for that run and exact
phase/SHA/attempt name through the Actions API, verifies the archive SHA-256,
rejects unsafe paths, symlinks, duplicate or extra files, and bounded declared
and actual expansion, then accepts only the five exact root files. It requires
canonical evidence, deployment manifest, public runtime sidecar, inventory,
and retired-lifecycle surface bytes. The two runs must use the same executable proof-harness digest,
frozen full inventory mapping, retired-surface contract, Hub/cell topology,
FRP module/repository, and qRTS repository/image identities. The deployment
manifest's Connector module map remains a strict producer-owned object whose
`frp` and `qurl_go` SHAs equal the corresponding repository SHAs; qurl-go does
not download or consume a Connector proof artifact. Each qurl-go run
is bound to its own manifest SHA because qurl-go's HTTP cleanup is itself part
of the isolated cut; qurl-go is therefore in the explicit retirement set. The
qurl-go and Connector repository SHAs, Connector image, and Connector's
embedded qurl-go module may be repinned for the mechanically constrained cut;
website and the other generated-artifact owners are also retirement-set inputs.
At least one retirement repository, permitted module/image repin, or deployed
NHP/qurl-service image must actually differ. A phase label alone is not a
post-removal proof.

Configure the protected GitHub `sandbox` environment before dispatching it:

- secret `QURL_GO_SANDBOX_ENROLLMENT_CREDENTIAL`: a fresh, server-minted
  `connector_bootstrap`, `bootstrap`, or `agent` enrollment credential;
- secrets `OPS_ROUTINES_APP_ID` and `OPS_ROUTINES_APP_PRIVATE_KEY`: credentials
  for the organization App installed on exactly the repositories enumerated by
  the workflow. Its minted token has only `actions:read`, `contents:read`, and
  `pull-requests:read` and lets the proof adapters verify the exact
  private-repository manifest,
  including NHP, qURL service, qRTS, FRP, and website, instead of
  trusting operator-entered digests;
- variable `QURL_GO_SANDBOX_KNOCK_RESOURCE_ID`: a live sandbox Connector knock
  resource;
- optional variable `QURL_GO_SANDBOX_EXPECTED_CELL_ID`: an operator assertion
  for the initial registration and credentialless warm-open cell. The explicit
  reassignment observation must move away from it.

The attended job derives the Hub endpoint and pinned X25519 key only from the
validated runtime sidecar. It rejects noncanonical bytes, verifies each
decoded 32-byte public key against the deployment manifest fingerprint, and
reauthenticates the exact successful NHP producer run, immutable artifact
identity/digest, and signed trusted-main producer commit. Mutable repository
variables never supply its Hub trust root.

The qurl-go proof is deliberately independent of the Connector proof. It
executes and publishes the complete 68-row inventory, but it only claims rows
whose checked-in status is `implemented`; every qurl-go-owned row must be
implemented and pass exactly once before this workflow is successful.
Connector-owned rows remain `external_dependency` here. The NHP controller
joins the successful qurl-go and Connector artifacts for the final pre-removal
and post-removal decision. A successful qurl-go artifact therefore proves the
SDK, authenticated deployment producer, Hub/cell trust, and phase pairing; it
does not by itself authorize lifecycle removal.

Strict mode fails when any required value is absent. It records the exact clean
Git build SHA, Hub trust root, deployment/inventory/proof-harness digests, and
every authenticated assigned-cell tuple in a 30-day allowlisted JSON evidence
manifest. The full normalized inventory mapping and checked-in exact retired
lifecycle surface have separately reviewed literal SHA-256 values
(`8c40e18b93f14a05aa383bfa6455cf896bf4ae899afdc1e5a57a14b1df44d4f9`
and `3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c`,
respectively); both are carried in evidence and must match across phases. The
latter enumerates the
public and internal HTTP method/path/operation identities, retired relay SDK
aliases, retained relay path, and forbidden lifecycle message types. The
manifest, inventory, and retired surface are snapshotted read-only and all input
digests are rechecked after the test process. Raw `go test -json` output is
redirected only to an ephemeral runner file: it is neither printed to the
Actions log nor uploaded, and it is deleted before artifact publication.
The test writes a separate strict non-secret schema-v2 provenance sidecar
containing the exact build SHA, generated agent id, deployment-manifest
SHA-256, typed-evidence-contract SHA-256, Hub host/port/key fingerprint, and
every authenticated assigned-cell
generation/revision/lease/host/port/key fingerprint observed by the public SDK.
The workflow requires the exact generated agent id, canonical bounded lease
timestamps, safe positive integer generation/revision counters no greater than
`9007199254740991`, and exactly four ordered observations: registration, warm
open, reassignment, and refresh. Registration and warm open must preserve the
entire assignment binding; reassignment must move to a different deployed cell
in the explicit cell0-to-cell1 fixture at a strictly newer generation; refresh
must preserve the reassigned
cell/generation/host/port/key tuple, may advance endpoint revision, and may
extend but never regress the parsed lease timestamp. The sidecar is published
with exclusive no-replace semantics, so an existing file or partial temporary
artifact fails closed instead of being overwritten. At least two distinct authenticated cell ids, hosts, and server
identities must come from the supplied deployment manifest. Every artifact
states `gate_passed`, the independent strict-test and inventory-enforcement
outcomes, input integrity, two-cell
provenance, and exact implemented/blocking/failure/skip/pass counts, so a
partial or one-cell run cannot be mistaken for proof.
The workflow requires exactly one passing and zero skipped events for every
scenario marked `implemented` in
`tests/e2e/nativeudp/pre_retirement_scenarios.json`. The live lifecycle source
path now performs provenance, fail-closed Hub DNS resolution, one-attempt
real-socket UDP timeout, fresh registration, persisted credentialless warm
open, an authenticated opt-in cell0-to-cell1 reassignment refresh, a following
ordinary same-cell Hub refresh, assigned-cell KNK, assigned-cell EXT, and zero
lifecycle HTTP calls.
The reassignment inventory row remains blocking until the deployed uniquely
tagged Authority fixture actually returns that real sequence; the client never
self-asserts or simulates the move.
Any skip beneath a required scenario's nested subtest namespace also fails the
parent scenario, and every failing event is counted globally. A successful
inventory scan cannot mask a failed strict `go test` process: `strict_outcome`
is independently captured and must be `success` in current, paired pre-removal,
and final published evidence.
The attended job, Go process, and whole-lifecycle backstops are 75, 60, and 50
minutes respectively so the complete fault matrix remains runnable. Exact
per-operation deadlines, retry counts, and cancellation assertions remain the
actual behavioral bounds; the larger outer ceilings do not relax them.

The UDP proof installs both the SDK's explicit resource-client trap and a
process-wide default-transport trap. Any lifecycle HTTP attempt is observable
and fails the run. Successful live Hub/cell exchanges retain the SDK's real
public resolver and dialer defaults. Registration, refresh, KNK, and EXT pass no
UDP-bound or retry-budget override, so the proof measures the shipped three-
second per-address timeout, three-address fan-out, and four-attempt/30-second
assignment budget. The DNS-failure case records the exact Hub
hostname requested before a test-only resolver returns a deterministic
`net.DNSError`; the timeout case records the exact public logical destination
before a test-only dialer redirects the real UDP socket to an ephemeral local
no-reply peer. Neither seam weakens the production endpoint validation path.

These thirteen SDK scenarios prove public API outcomes; they do not by themselves
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
evidence. The NHP controller later binds the complete Connector inventory and
successful hardened run to this proof's phase and deployment manifest. Five
phase-aware retirement rows also require deployed HTTP/OpenAPI,
retained-relay rejection of OTP/REG/LST/LRT before waiter/plugin/Authority,
NHP registrar/interface, generated artifact, and Terraform saved-plan/live-state
proof; changing only a manifest label or commit is insufficient. SDK-owned work
is `todo`; Connector and topology work remains `external_dependency` for the
final NHP-controller aggregation. Both non-implemented statuses remain blocking
for retirement, but only unfinished qurl-go-owned rows fail this producer
workflow. The artifact retains honest implemented/blocking counts for all 68
rows, so it cannot be mistaken for the final removal decision. The DNS and
timeout cases are inherently client-side failure paths,
run in ordinary CI as well as the attended runner through only the public SDK.
Add other evidence only when the real Hub/Authority/cell prerequisites and
safe client-side fault injection exist; never convert an unavailable operation
into a skipped or simulated green result.
