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
   activation: ticket and expiry, agent id/public key, registration key id/kind,
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
exact committed activation may replay after ticket expiry; an authenticated
`52111` marker-absent result permits one replacement Hub ticket while the
credential remains active. Transport ambiguity never triggers Hub or cross-cell
fallback.

Metadata is optional only when constructing a fresh REG. Once a
`PendingActivation` exists, its persisted `hostname` and `version` are exact
recovery-identity fields, so recovery must use the identical
`WithAgentRuntimeMetadata` values. Do not change the reported version or rename
the host until activation completes. A mismatch fails before network I/O and
does not authorize a replacement ticket; if the original values cannot be
restored, explicitly reprovision the agent rather than substituting new
metadata.

The v0.5 Hub contract requires the assignment lease to expire strictly after
the assignment ticket. The SDK enforces that ordering when it creates and
reloads pending activation state.

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
`false` for the replacement ticket's newly dispatched code.

The recovery branch above must return the previously issued code. It must never
request, generate, or dispatch a new code; the SDK intentionally suppresses
NHP_OTP while replaying a pending activation.

Pending-activation recovery calls the provider with the caller's context because
an exact replay may occur after the ticket window has expired. Set an outer
context deadline to bound that operator or provider wait.

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
before deciding whether a pending activation or completion candidate exists.

## Crash and retry boundaries

The lifecycle separates retryable transport from security-sensitive mutation:

A single call can consume independent bounded budgets for the initial Hub
assignment, first REG, replacement Hub assignment, second REG, and completion.
Callers that need a smaller aggregate ceiling must set an outer context
deadline.

- Hub assignment uses one bounded transaction budget. Authenticated rate-limit
  advice may delay and retry within that budget.
- The exact pending activation is durable before the first REG. Resolution and
  transport faults retry only that body and pinned cell within the configured
  attempt/elapsed budget. Exhaustion returns
  `*RegistrationRecoveryRequiredError`; restart with the same enrollment
  credential.
- An authenticated `52111`, or account `52101`, proves the pending first use did
  not activate. Only then may the SDK seek one replacement ticket. The old
  record remains durable until its replacement saves successfully; a consumed
  credential/new-ticket denial therefore cannot erase the recovery evidence.
- Completion retries only resolution/transport faults and authenticated `52300`
  unavailable responses.
- The exact candidate is durable before the first completion packet. Lost or
  ambiguous completion resumes that candidate; it never generates another.
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
| `ErrAssignmentRecoveryRequired` / `*AssignmentRecoveryRequiredError` | The bounded Hub transaction was exhausted; inspect the matchable cause. |
| `ErrRegistrationRecoveryRequired` / `*RegistrationRecoveryRequiredError` | The bounded assigned-cell REG transaction was ambiguous; re-run with the same store, Hub trust root, metadata, and enrollment credential so the exact pending activation is replayed first. |
| `ErrAssignmentTicketInvalid` / `ErrAssignmentTicketExpired` | The assigned cell rejected the Hub ticket. Do not invent or retarget an endpoint. |
| `ErrAgentIdentityConflict` | Stop and use explicit owner-controlled native reprovisioning. |
| `ErrDeviceKeyQuotaExceeded` | Revoke an unused device credential, then resume according to authority guidance. |
| `ErrAgentCompletionCandidatePersistence` / `*AgentCompletionCandidatePersistenceError` | Reload state before any retry; resume the exact pending activation with the same enrollment credential or the exact pending completion with an empty credential. Save ambiguity alone never authorizes replacement; only an exact pending-activation replay authenticated as `52111` or account `52101` permits the one bounded replacement. |
| `ErrCompletionRecoveryRequired` / `*CompletionRecoveryRequiredError` | Re-run `RegisterAgentRuntime` with the same store and empty enrollment credential to resume the exact pending candidate. |
| `ErrCompletionCredentialConflict` / `*CompletionError` | The authority already committed a different candidate. Stop and use explicit NHP-native credential recovery or reprovisioning; never delete the persisted candidate or mint a replacement locally. |
| `*NativeCredentialRecoveryRequiredError` | Native completed credential state is absent or malformed; explicit native recovery/reprovisioning is required. |
| `*AgentAssignmentChangedError` | A new cell or generation requires explicit reassignment adoption. |
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
