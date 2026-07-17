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
3. persists the Hub-provided cell id, generation, endpoint revision, lease,
   LayerV-owned DNS host, UDP port, and assigned-cell server public key;
4. sends optional account OTP and REG directly to that assigned cell;
5. persists one exact completion candidate before sending completion;
6. completes directly with the assigned cell; and
7. returns the resource `Client` and a private-key-owning runtime binding.

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
		return readEightDigitCode(ctx, challenge)
	}),
)
```

The assigned cell receives a one-way OTP request before the callback runs. The
callback receives only bounded, non-secret challenge metadata. It must return
exactly eight ASCII digits. The code is never persisted or included in an
error. One invocation never silently requests a second OTP; ticket expiry
requires a new explicit call.

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
assignment, and possibly a crash-recovery completion candidate. It is a
credential file: never log it or attach it to support bundles.

### Plaintext local file

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
```

The parent directory must be exactly `0700`; the file is atomically written
`0600`. Symlinks, oversized files, insecure permissions, corrupt JSON, unknown
fields, and inconsistent assignments fail closed. Local stores use a sidecar
setup lock so two processes cannot mint competing identities against one path.
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
before deciding whether a completion candidate exists.

## Crash and retry boundaries

The lifecycle separates retryable transport from security-sensitive mutation:

- Hub assignment uses one bounded transaction budget. Authenticated rate-limit
  advice may delay and retry within that budget.
- Assigned-cell REG may reassign once for an expired bootstrap ticket. Account
  OTP never performs a hidden second assignment/OTP attempt.
- Completion retries only resolution/transport faults and authenticated `52300`
  unavailable responses.
- The exact candidate is durable before the first completion packet. Lost or
  ambiguous completion resumes that candidate; it never generates another.
- A save error immediately after RAK may have committed. Reload first. If the
  exact pending candidate exists, resume with an empty enrollment credential.
  If it does not, use explicit native owner recovery/reprovisioning; never replay
  a possibly consumed enrollment credential.

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
| `ErrAssignmentTicketInvalid` / `ErrAssignmentTicketExpired` | The assigned cell rejected the Hub ticket. Do not invent or retarget an endpoint. |
| `ErrAgentIdentityConflict` | Stop and use explicit owner-controlled native reprovisioning. |
| `ErrDeviceKeyQuotaExceeded` | Revoke an unused device credential, then resume according to authority guidance. |
| `ErrAgentCompletionCandidatePersistence` / `*AgentCompletionCandidatePersistenceError` | Reload state before any retry; never replay the enrollment credential. |
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
