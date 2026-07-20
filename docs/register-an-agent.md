# Register a qURL Connector agent

`RegisterAgentRuntime` enrolls a qURL Connector and returns both:

- a `Client` authorized for steady-state qURL resource CRUD; and
- an `AgentRuntimeBinding` containing the authority-provided NHP UDP assignment
  needed for a direct knock.

The lifecycle is UDP-only. Hub assignment, optional account OTP, assigned-cell
REG/RAK, completion, refresh, and knock never use a public HTTP endpoint. The
resource `Client` returned after enrollment continues to use the qURL HTTPS API.
Browser relay is a separate browser path and is not used by this runtime.

## Basic flow

Trusted deployment configuration supplies one Hub endpoint and pinned X25519
server public key:

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
hub := qurl.HubBootstrap{
	Host:               "hub.nhp.layerv.ai",
	Port:               62206,
	ServerPublicKeyB64: configuredHubPublicKey,
}

client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredential, store,
	qurl.WithAgentRuntimeHub(hub),
	qurl.WithAgentRuntimeIdentity("connector-prod-1"),
	qurl.WithAgentRuntimeMetadata(hostname, version),
)
if err != nil {
	return err
}
defer binding.Destroy()
```

The SDK then:

1. loads or creates the persistent X25519 agent identity;
2. asks the pinned Hub for an assignment over authenticated NHP UDP;
3. obtains the optional account OTP, then durably persists one exact pending
   activation: current ticket and expiry, first-ticket recovery anchor, 90-day
   absolute recovery deadline, agent id/public key, registration key id/kind,
   metadata, complete assigned-cell binding, and a one-way identity of the
   caller-supplied enrollment credential;
4. sends REG directly to only that persisted assigned cell;
5. after an authenticated RAK, atomically replaces the pending activation with
   one exact completion candidate before sending completion;
6. completes directly with the assigned cell; and
7. returns the resource `Client` and a private-key-owning runtime binding.

The pending activation never contains the plaintext enrollment credential, OTP
code, or device credential. If RAK is lost after the authority commits REG, the
next call must supply the same enrollment credential. The SDK re-drives the
persisted REG to its pinned cell before asking the Hub for anything new. An
exact committed activation may replay after ticket expiry while its persisted
recovery deadline remains live; an authenticated `52111` marker-absent result
permits one replacement Hub ticket while the credential remains active. That
replacement changes the current ticket, never the first-ticket recovery anchor
or absolute deadline, including after a process restart.
Transport ambiguity never triggers Hub or cross-cell fallback.

Metadata is optional only when constructing a fresh REG. Once a
`PendingActivation` exists, its persisted `hostname` and `version` are exact
recovery-identity fields, so recovery must use the identical
`WithAgentRuntimeMetadata` values. Do not change the reported version or rename
the host until activation completes. A mismatch fails before network I/O and
does not authorize a replacement ticket; if the original values cannot be
restored, explicitly reprovision the agent rather than substituting new
metadata.

The v0.5 Hub contract requires the assignment lease to expire strictly after
the assignment ticket and caps a ticket at the qurl-conformance maximum of 900
seconds from the authenticated response clock. The SDK enforces both bounds
when it creates pending activation state and rechecks lease ordering on reload.

## Finite recovery horizon

`AgentRegistrationRecoveryHorizon` is exactly 90 days. A fresh pending
activation persists
`recovery_anchor_ticket_expires_at = assignment_ticket_expires_at` and
`recovery_expires_at = recovery_anchor_ticket_expires_at + 90 days`, where the
anchor is the first timestamp from the authenticated Hub LRT. A replacement
ticket keeps its own current expiry but copies that original anchor and deadline.
After RAK, the SDK copies the same immutable pair into `PendingCompletion`. RAK,
replacement, restart, assignment refresh, retries, SDK upgrade, and local save
time never reset it.

Credential-free assignment refresh carries no activation ticket and updates
only the assigned-cell binding and lease. It deliberately cannot re-anchor or
extend registration recovery. The 900-second lifetime cap therefore applies to
initial and replacement activation tickets, while a refreshed assignment has no
ticket-derived recovery authority to cap.

`RegisterAgentRuntime` clamps pending-recovery contexts to the deadline and
checks the same boundary before DNS and immediately before every Hub or cell UDP
datagram write, including OTP and each multi-address fallback. No recovery
datagram is dispatched at or after the deadline. It returns
`*AgentRecoveryExpiredError`, matchable with
`ErrAgentRecoveryExpired`, containing only the non-secret phase and deadline.
An invocation that began before the deadline may already have sent an earlier
datagram or completed a durable state transition. A save error therefore keeps
`ErrAgentBindingPersistence` (and, after RAK,
`ErrAgentCompletionCandidatePersistence`) even if the deadline expires at the
same time: reload before deciding which exact pending or completed state won.
Do not delete pending state to force reenrollment; use the explicit NHP-native
credential recovery or reprovisioning workflow.

The absolute deadline is authority-anchored, but the SDK compares it with the
host's UTC wall clock. Keep system time synchronized. Clock error can make the
local decision early or late, but it cannot extend server authority: an
authority whose replay evidence has retired still rejects mutation. The server
keeps an additional bounded in-flight/cleanup grace; that grace is not part of
the SDK's 90-day guarantee.

### Pre-v6 state

qurl-go v0.1.1 wrote schema-v5 pending records without a finite deadline. On
load, this SDK can migrate `PendingActivation` exactly because its authenticated
ticket expiry is present. It derives the finite registration-recovery fields
introduced by schema v6, then durably writes them in the current schema v7
before any UDP I/O. Schema v7 additionally carries explicit device-credential
recovery state. Schema-v5 records carrying any forward-populated recovery field
are rejected as corrupt rather than trusted as invented history. A schema-v5
`PendingCompletion` no longer retains that ticket anchor. Inventing
`upgrade time + 90 days` would make server
retention unbounded for installations that upgrade arbitrarily late, so the SDK
instead returns `*AgentRecoveryMigrationRequiredError`, matchable with
`ErrAgentRecoveryMigrationRequired`, and preserves the record without network
I/O. Use explicit recovery or reprovisioning; never hand-edit a deadline.

Negative schema versions and versions greater than the current schema are also
invalid. They fail closed before resolver, socket, or UDP activity; a newer
version requires an explicit compatible SDK upgrade or state migration.

## Explicit device-credential recovery

`RecoverAgentRuntime` replaces a lost or deliberately revoked native device API
key while preserving the existing agent id and X25519 identity. It is never
triggered by a resource API `401`; an operator must supply a live reusable
credential of exact kind `agent` with `qurl:agent` scope:

```go
client, binding, err := qurl.RecoverAgentRuntime(ctx, recoveryCredential, store,
	qurl.WithAgentRuntimeRecoveryHub(hub),
)
```

The recovery lifecycle has zero HTTP legs. First, the SDK sends
`IssueCredentialRecovery` to the pinned Hub over cookie-proven NHP UDP. The
authenticated result supplies the complete current cell id, generation, lease,
LayerV-owned UDP host/port, pinned server key, and a 15-minute opaque recovery
grant. The SDK never calculates or probes a cell and never uses the browser
relay. It then persists one replacement candidate and sends
`CompleteCredentialRecovery` directly to only that assigned cell.

Before the first Hub datagram, schema v7 persists the exact request nonce, a
domain-separated fingerprint of the recovery credential, and the exact Hub
host/port/server key. It never stores the raw recovery credential. A restart or
lost Hub reply requires the same credential and Hub trust root and replays the
byte-identical request only before its durable conservative `replay_not_after`
cutoff. That pre-anchor cutoff is locally derived to end before the released
Authority horizon; at or after it the SDK returns
`ErrCredentialRecoveryExpired` without DNS, socket, or UDP activity. After an
authenticated Issue response, the state clears
the revoked old device secret/id and persists the grant, assignment, candidate,
and first-grant recovery anchor before any cell datagram. Transport ambiguity,
completion-response loss, and save ambiguity always resume these exact durable
values; they never mint another logical request or candidate.

The first authenticated `recovery_grant_expires_at` anchors the immutable
90-day `AgentCredentialRecoveryHorizon`. A later grant in the same Authority
episode may replace an expired/rejected current grant but cannot move the
anchor or candidate. An exact Hub Issue replay that arrives with a stale grant
or assignment is persisted for its original anchor, then the same explicit SDK
call spends at most one new nonce to obtain live authority data before any cell
write. Exact committed completion may replay after grant expiry while the
horizon is live. An uncommitted expired grant is rejected. DNS, cookie proof,
retry, and cell writes are all fenced so no recovery datagram is written at or
after the exact horizon boundary.

Only authenticated Hub `52400`/`52404` and cell `52410` are retryable within the
caller's bounded operation. A terminal Hub denial clears its request intent so
the operator can correct revocation or credential state and start a new nonce;
transport ambiguity and malformed authenticated results retain the exact intent
because issuance is unknown. Cell `52411` retains the candidate and immutable
anchor but requires a later explicit call to obtain a fresh grant. Identity,
request, and candidate-conflict outcomes are terminal and never cause HTTP,
relay, cell-selection, takeover, or cross-cell fallback.

| Phase | Code | SDK action |
|---|---:|---|
| Hub | `52400` | Retry inside the current bounded operation after 5 seconds |
| Hub | `52401` | Stop: recovery credential rejected |
| Hub | `52402` | Stop: persisted agent identity rejected |
| Hub | `52403` | Stop: deliberately revoke the current device credential first |
| Hub | `52404` | Retry inside the current bounded operation after 60 seconds |
| Hub | `52405` | Stop: request contract rejected |
| Hub | `52406` | Stop: assignment requires operator recovery |
| Cell | `52410` | Retry inside the current bounded operation after 5 seconds |
| Cell | `52411` | Preserve the exact candidate; the next explicit call obtains a fresh grant |
| Cell | `52412` | Stop: persisted agent identity rejected |
| Cell | `52413` | Stop: a different replacement candidate already owns the episode |
| Cell | `52414` | Stop: request contract rejected |

After an authenticated cell success, the replacement credential is persisted
before the SDK materializes a runtime binding. If that assignment lease has
expired, the SDK immediately performs one credential-free Hub refresh. A
failure matches `ErrCredentialRecoveredAssignmentRefreshRequired` and unwraps
the underlying cause: the credential is already recovered, so call
`RefreshAgentRuntime`; do not start a second recovery episode.

### Authority rollout handoff

This finite contract is a greenfield, pre-enable cutoff. Before native
registration becomes reachable or replay cleanup starts, operators must prove
that Control contains zero legacy `registration_activation_v1`,
`registration_completion_v1`, and
`registration_completion_device_locator_v1` records and that every distributed
client includes the finite registration-recovery behavior introduced by schema
v6 or newer. The current state schema is v7 because it also adds explicit
device-credential recovery. If that proof is not zero, cleanup
must remain disabled until the records are explicitly reconciled; age alone is
not proof that a v0.1.1 recovery promise can be retired.

For records created after that gate, the authority must retain activation
outcomes through signed ticket expiry plus 90 days and its documented cleanup
grace. Completion does not receive the ticket expiry, so its replay metadata
must remain through `completed_at + 90 days + 15 minutes` (the current maximum
ticket lifetime) plus the same grace. Completion retirement must atomically
strip replay-only attributes from the device-key row and replace the detailed
owner/agent sentinel with a compact, non-replayable per-agent completion fence.
That fence remains for the registered agent's lifetime and denies every later
candidate; otherwise later device-key revocation/row deletion could let stale
completion state mint again. Deleting only one side, deleting the fence while
the agent still exists, or applying independent DynamoDB TTLs is invalid.

The SDK does not calculate a cell address. It resolves the exact host supplied
by the authenticated Hub response and authenticates the responding cell against
the supplied public key.

Placement rollout guard: this SDK release accepts assigned hosts only beneath
the LayerV DNS apexes encoded by its endpoint policy, and accepts IPv6 addresses
only from its release-gated IANA allocation allowlist. Provisioning a cell under
a new LayerV DNS apex or exclusively in a newly allocated IPv6 prefix therefore
requires an updated qurl-go release before the placement is enabled; older SDKs
intentionally fail resolution closed.

## Credential policy

`RegisterAgentRuntime` requires a server-minted encoded enrollment token whose
total string length is at least 32 bytes, including any prefix, and rejects
shorter values before any state mutation or network I/O. User-chosen passwords
are not enrollment credentials. This is part of the initial pre-1.0 native-UDP
contract for every key kind, including interactive account enrollment. The SDK
validates token syntax and this total-length floor; it does not measure decoded
random material or entropy. Hub operators must enforce cryptographically random
minting upstream; a low-entropy value violates this contract even if it passes
the SDK's length check.

By default the runtime accepts unattended credentials of these authenticated
Hub-reported kinds:

- `connector_bootstrap`
- `bootstrap`
- `agent`

The durable `agent` kind is appropriate when one owner-managed enrollment key
fans out across a controlled Connector fleet. Apply owner-side scope, rotation,
and revocation policy to that credential.

Account enrollment is interactive and opt-in:

```go
client, binding, err := qurl.RegisterAgentRuntime(ctx, accountCredential, store,
	qurl.WithAgentRuntimeHub(hub),
	qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(
		qurl.RegistrationKeyKindAccount,
	),
	qurl.WithAgentRuntimeOTPProvider(func(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
		if challenge.PendingActivationRecovery {
			return readPreviouslyIssuedEightDigitCode(ctx, challenge)
		}
		return readEightDigitCode(ctx, challenge)
	}),
)
```

The assigned cell receives a one-way OTP request before the callback runs. The
callback receives only bounded, non-secret challenge metadata. It must return
exactly eight ASCII digits. The code is never persisted or included in an
error. Each assignment ticket dispatches at most one NHP_OTP.

OTP dispatch intentionally precedes the pending-activation save: persisting a
"dispatched" record before the one-way send could strand the ticket if the
process exits between those operations. If the later state save fails, no REG
was sent; a new explicit attempt may obtain a new ticket and dispatch that
ticket's single OTP.

If REG has an ambiguous/lost RAK, recovery invokes the callback again with
`challenge.PendingActivationRecovery == true` so the caller can supply the
original code. Recovery does **not** dispatch another NHP_OTP and sends the exact
persisted REG body. Only an authenticated OTP-expired (`52101`) or ticket-expired
marker-absent (`52111`) result permits one fresh assignment ticket; that new
ticket may dispatch its own single OTP.

That authenticated-expiry path can invoke the provider twice in one call: first
with `PendingActivationRecovery == true` for the original code, then with
`false` for the replacement ticket's newly dispatched code. Separately, when a
fresh first REG receives account `52101`, the provider can also run twice in one
call, but both challenges have `PendingActivationRecovery == false`: each
follows the one OTP dispatch for its own distinct fresh ticket. Every path still
dispatches at most one OTP per ticket.

The recovery branch above must return the previously issued code. It must never
request, generate, or dispatch a new code; the SDK intentionally suppresses
NHP_OTP while replaying a pending activation.

Pending-activation recovery calls the provider with the caller's context
clamped to the persisted recovery deadline because an exact replay may occur
after the ticket window has expired. Set an earlier outer context deadline to
bound that operator or provider wait more tightly.

The SDK refuses to dispatch OTP unless the assignment ticket has at least the
conformance contract's inclusive 630 seconds remaining.

## Use the assignment

Take the private key exactly once. The binding owns and redacts it until then:

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
if err != nil {
	return err
}
```

Use one caller-owned `RunID` for the whole Connector cycle. Do not regenerate it
between knock and FRP login. `KnockResourceID` is placement-neutral; the
assigned cell returns the runtime resource host.

## Warm open and refresh

A completed warm start performs no enrollment or resource network call:

```go
client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store)
```

The store itself may perform I/O or call KMS. The open validates the native
identity, credential pair, assignment, server key, and live lease, and primes
the resource client's one-minute credential cache from that same state load.

If the assignment is expired or near expiry, refresh through the same pinned
Hub:

```go
client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store)
```

Refresh has no enrollment credential. A newer endpoint revision within the same
cell and assignment generation is accepted. A new cell or generation returns
`*qurl.AgentAssignmentChangedError`; the caller must explicitly adopt the
reassignment in the provisioned workflow. The SDK never infers an endpoint or
silently crosses that authority boundary.

Once that workflow has deliberately accepted the move, opt into exactly one
fresh authenticated Hub refresh:

```go
client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
	qurl.WithAgentRuntimeReassignmentAdoption(),
)
```

This option takes no cell or endpoint input. It accepts only a higher assignment
generation from that call's authenticated LRT and persists the full
authority-provided cell, endpoint, pinned server key, and lease in one store
save. Refresh does
not probe or contact either cell, and still sends no setup or device credential
and performs no HTTP request. A stale, regressed, expired, or identity-mismatched
target fails without changing durable state.

`OpenRegisteredAgent` is available when a process needs only the steady-state
resource `Client` and will not knock. It still accepts native completed state
only; assignment expiry does not block resource CRUD.

## Resource-client options

These options configure only the returned HTTPS resource client:

```go
qurl.WithAgentClientBaseURL("https://api.layerv.ai")
qurl.WithAgentClientHTTPClient(customHTTPClient)
```

They do not configure Hub, cell, assignment, registration, completion, or knock
transport. Native UDP uses the closed `AgentRuntime*Option` sets, so an option
cannot accidentally retarget both trust paths.

## State storage

`AgentState` contains the X25519 private key, completed device credential, Hub
assignment, and possibly a crash-recovery activation record or completion
candidate. It is a credential file: never log it or attach it to support
bundles. `FileAgentState` is permission-protected plaintext; use a sealed or
secret-manager store when the complete state must be encrypted at rest.

### Plaintext local file

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
```

The parent directory must be exactly `0700`; the file is atomically written
`0600`. Symlinks, oversized files, insecure permissions, corrupt JSON, duplicate
or unknown fields, and inconsistent assignments fail closed. Local stores use a
sidecar setup lock so two processes cannot mint competing identities against one
path.
Because unknown fields fail closed, an SDK downgrade may not be able to open
state written by a newer SDK. Treat that as an explicit state-schema migration
or reprovisioning operation; never delete credential state merely to bypass the
decode failure.

### Sealed local file

```go
store, err := qurl.NewSealedFileAgentState(
	"/var/lib/layerv/qurl/agent-state.sealed.json",
	"aws-kms",
	wrapper,
	qurl.WithExpectedSealedAgentID("connector-prod-1"),
)
```

The SDK encrypts the full state with a fresh AES-256-GCM data-encryption key on
every save. The adapter wraps exactly that 32-byte key and must implement both
wrap and unwrap. The authenticated envelope binds provider id, agent id, wrapped
key metadata, nonce, and ciphertext. Scope unwrap permission to the intended
installation.

### AWS stores

`github.com/layervai/qurl-go/awsstore` provides Secrets Manager and SSM
Parameter Store implementations. See [the AWS store guide](../awsstore/README.md)
for IAM and consistency requirements.

### Custom stores

An `AgentStateStore` must:

- return `ErrAgentStateNotFound` only when no state exists;
- return `ErrInvalidAgentState` for present but unreadable/corrupt state;
- return a fresh caller-owned snapshot on every load;
- encode or clone synchronously during save rather than retaining the pointer;
- propagate context cancellation; and
- serialize setup externally if it does not implement the SDK local-file lock.

Save can commit and still return an acknowledgement error. Callers must reload
before deciding whether a pending activation, completion candidate, refreshed
assignment, or completed credential exists. Concurrent context cancellation or
recovery expiry does not remove this reload-first requirement.

## Crash and retry boundaries

The lifecycle separates retryable transport from security-sensitive mutation:

A single call can consume independent bounded budgets for the initial Hub
assignment, first REG, replacement Hub assignment, second REG, and completion.
Callers that need a smaller aggregate ceiling must set an outer context
deadline.

- Hub assignment uses one bounded logical-operation budget. Authenticated rate-limit
  advice may delay and retry within that budget. The SDK draws one fresh
  32-byte request nonce and serializes the LST body once per logical operation;
  DNS/address fallback and every bounded retry reuse that exact body while each
  new UDP exchange gets fresh NHP packet randomness. A later public assignment
  call draws a new nonce. The nonce is never returned or persisted.
- The exact pending activation is durable before the first REG. Resolution and
  transport faults retry only that body and pinned cell within the configured
  attempt/elapsed budget. Exhaustion returns
  `*RegistrationRecoveryRequiredError`; restart with the same enrollment
  credential before its persisted 90-day deadline.
- An authenticated assigned-cell REG rate limit is terminal for that call. The
  SDK automatically retries only network ambiguity. RAK has no retry-after field
  in this wire contract; after any authority- or operator-required delay, callers
  may re-invoke the exact pinned activation, but must never seek a new Hub
  assignment or cross-cell fallback for that verdict.
- An authenticated `52111`, or account `52101`, proves the pending first use did
  not activate. Only then may the SDK seek one replacement ticket. The old
  record remains durable until its replacement saves successfully; a consumed
  credential/new-ticket denial therefore cannot erase the recovery evidence.
- Completion retries only resolution/transport faults and authenticated `52300`
  unavailable responses.
- The exact candidate is durable before the first completion packet. Lost or
  ambiguous completion resumes that candidate before the same unchanged
  90-day deadline; it never generates another.
- A save error immediately after RAK may have committed. Reload first. If the
  pending activation remains, resume its exact REG with the same enrollment
  credential. If the pending completion exists, resume with an empty enrollment
  credential. Never request a replacement from save ambiguity alone: only an
  authenticated `52111` or account `52101` from the exact pending-activation
  replay may authorize the one bounded replacement above.

## Errors

Use `errors.Is` and `errors.As`:

| Error | Meaning and action |
| --- | --- |
| `ErrInvalidRegisterConfig` | Correct Hub, identity, metadata, credential, or option input before retrying. |
| `ErrRegistrationKeyKindDisallowed` / `*RegistrationKeyKindDisallowedError` | The authenticated Hub reported a valid kind outside caller policy. |
| `ErrAgentOTPRequired` | Account enrollment lacks the explicit OTP provider. |
| `ErrOTPIncorrect` | Obtain the correct code and start a new explicit attempt as appropriate. |
| `ErrOTPExpired` | Start a new explicit assignment/OTP attempt. |
| `ErrAssignmentRecoveryRequired` / `*AssignmentRecoveryRequiredError` | The bounded logical Hub operation was exhausted; inspect the matchable cause. |
| `ErrAgentBindingPersistence` | A state save failed or its acknowledgement was lost. Reload before retry; a refreshed or reassigned binding may already be durable. |
| `ErrRegistrationRecoveryRequired` / `*RegistrationRecoveryRequiredError` | The bounded assigned-cell REG transaction was ambiguous; re-run with the same store, Hub trust root, metadata, and enrollment credential so the exact pending activation is replayed first. |
| `ErrAssignmentTicketInvalid` / `ErrAssignmentTicketExpired` | The assigned cell rejected the Hub ticket. Do not invent or retarget an endpoint. |
| `ErrAgentIdentityConflict` | Stop and use explicit owner-controlled native reprovisioning. |
| `ErrDeviceKeyQuotaExceeded` | Revoke an unused device credential, then resume according to authority guidance. |
| `ErrAgentCompletionCandidatePersistence` / `*AgentCompletionCandidatePersistenceError` | Reload state before any retry; resume the exact pending activation with the same enrollment credential or the exact pending completion with an empty credential. Save ambiguity alone never authorizes replacement; only an exact pending-activation replay authenticated as `52111` or account `52101` permits the one bounded replacement. |
| `ErrCompletionRecoveryRequired` / `*CompletionRecoveryRequiredError` | Re-run `RegisterAgentRuntime` with the same store and empty enrollment credential to resume the exact pending candidate. |
| `ErrCredentialRecoveryRetryRequired` / `*CredentialRecoveryRetryRequiredError` | Re-run `RecoverAgentRuntime` with the same store, Hub trust root, and recovery credential when a Hub issue is pending; a pending cell completion needs no credential unless its authenticated grant was rejected. |
| `ErrCredentialRecoveryCandidatePersistence` / `*CredentialRecoveryCandidatePersistenceError` | The recovery candidate save failed before durability could be reconciled. Reload and retry the same explicit recovery; never mint a replacement after ambiguity. Also matches `ErrAgentBindingPersistence`. |
| `ErrCredentialRecoveryExpired` / `*CredentialRecoveryExpiredError` | The explicit device-credential recovery episode reached its immutable first-grant-plus-90-day deadline. No recovery datagram is sent at or after it. |
| `ErrRecoveryCredentialRejected` | Correct or replace the reusable `qurl:agent` credential, then make a new explicit recovery attempt. |
| `ErrCredentialRecoveryRevokeRequired` | Deliberately revoke the current device credential, then make a new explicit recovery attempt. |
| `ErrCredentialRecoveryGrantRejected` | The cell rejected the grant or its live credential fences. Re-run explicitly with the recovery credential; the SDK retains the exact candidate and original horizon. |
| `ErrCredentialRecoveryCandidateConflict` | A different candidate was already committed. Stop; never delete durable pending state or rotate the candidate locally. |
| `ErrAgentRecoveryExpired` / `*AgentRecoveryExpiredError` | The pending phase is at or beyond its authority-anchored 90-day deadline. No datagram is sent at or after that boundary, but the invocation may have sent earlier traffic. A concurrent save ambiguity is reported with the reload-first persistence errors instead. |
| `ErrAgentRecoveryMigrationRequired` / `*AgentRecoveryMigrationRequiredError` | A legacy schema-v5 pending completion has no authenticated deadline anchor. No recovery UDP was sent; preserve it and use explicit NHP-native recovery or reprovisioning. |
| `ErrCompletionCredentialConflict` / `*CompletionError` | The authority already committed a different candidate. Stop and use explicit NHP-native credential recovery or reprovisioning; never delete the persisted candidate or mint a replacement locally. |
| `*NativeCredentialRecoveryRequiredError` | Native completed credential state is absent or malformed; explicit native recovery/reprovisioning is required. |
| `*AgentAssignmentChangedError` | A new cell or generation was refused by default; deliberately re-run refresh with `WithAgentRuntimeReassignmentAdoption` to accept a newer generation. |
| `ErrAgentSetupLock` | Repair state-path locking/permissions. Reload before retry because release can fail after a committed save. |

Producer-controlled diagnostic strings are not reflected into native lifecycle
errors. Unknown or malformed authenticated responses fail closed under the
appropriate strict response sentinel.

## Transport boundary

The native lifecycle exposes no HTTP assignment or registration route. Its only
network destinations are:

- the configured Hub over NHP UDP;
- the Hub-assigned cell over NHP UDP; and
- the qURL API over HTTPS after enrollment, for resource CRUD performed by the
  returned `Client`.

The browser relay remains separate: browsers address a relay route using the
assigned cell public-key fingerprint, while the relay uses its provisioned
lookup table. Native SDKs do not call the relay or use it for discovery.
