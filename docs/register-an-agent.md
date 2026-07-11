# Register an Agent

`RegisterAgent` is the one-call front door for enrolling an agent and getting a
ready-to-use `Client`. Hand it your API key and a place to persist state; it
returns a `Client` you immediately use to protect URLs and mint portals:

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")

client, err := qurl.RegisterAgent(ctx, apiKey, store)
if err != nil {
	return err
}

resource, err := client.ProtectURL(ctx, "https://dashboard.internal.acme.com")
if err != nil {
	return err
}

portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
if err != nil {
	return err
}

fmt.Println(portal.Link)
```

That is the whole target flow: `RegisterAgent` → `ProtectURL` → `CreatePortal`
→ the qURL link.

`RegisterAgent` is idempotent. The first call enrolls the agent and persists a
device credential into `store`. Every later call loads that credential and
returns a `Client` with **no qURL API calls** — so calling it unconditionally on
startup is the intended pattern, not a thing to guard against. A sealed or
network-backed store may still call its key or storage provider while loading.

The `key` argument is used only during first enrollment. Once `store` holds a
completed registration, the fast path serves the `Client` entirely from it and
never re-validates the key. Rotating or mistyping the key against an
already-registered `store` is therefore not detected; the persisted device
credential is authoritative from then on.

For an explicit zero-network reopen, use `OpenRegisteredAgent`. It takes normal
`ClientOption` values, so the resource API origin is independent of the
registration origin:

```go
client, err := qurl.OpenRegisteredAgent(ctx, store,
	qurl.WithBaseURL(resourceAPIURL),
)
```

The returned client caches the store-backed Authorization value for up to one
minute. After credential recovery, use the new client returned by
`RecoverAgentCredential` for immediate cutover; an older client observes the
replacement only after its cache expires.

`WithRegisterBaseURL` targets only registration-info and completion;
`WithAgentClientBaseURL` targets the `Client` returned by `RegisterAgent` or
`RecoverAgentCredential`. This prevents a dedicated registration origin from
silently retargeting later `/v1/resources` calls:

```go
client, err := qurl.RegisterAgent(ctx, enrollmentKey, store,
	qurl.WithRegisterBaseURL(registrationURL),
	qurl.WithAgentClientBaseURL(resourceAPIURL),
)
```

Headless callers that refuse account-key/OTP enrollment can enforce that policy
before any OTP email or NHP registration side effect:

```go
qurl.WithAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindBootstrap)
```

## Which key do I use?

You pass one key at enrollment. After that the agent runs entirely off the
device credential in its `store` and never uses the key again — the key is
**enrollment-only material**, so mount it as a secret or env var for the first
run. Pick it by how the agent is deployed:

| Deployment | Key | Lifetime & blast radius |
| --- | --- | --- |
| **A fleet** of headless agents (containers, CI, autoscalers) | one **durable `qurl:agent`-scoped** key, shared by all | long-lived until revoked; revoking it cuts off the whole fleet at once |
| **One** headless agent, provisioned on its own | a **one-shot** enrollment key, minted per agent | single-use and short-lived under LayerV key policy — LayerV consumes it on first enrollment, so a leaked key can't enroll a second device |
| An agent acting **as a person's account** | that account's existing **API key** | long-lived; enrollment needs an emailed one-time code (see below) |

Create the key from your LayerV account's key management, scoping it to
`qurl:agent` for the durable/fleet case. Lifetime and single-use-vs-reusable are
**LayerV key policy**, set when you mint the key — the SDK treats every
pre-issued (bootstrap-kind) key identically and does not itself expire or consume
keys.

**Fleets — one key, many agents.** Mint a single durable `qurl:agent` key, give
every agent the same secret, and give each agent its **own** `store` (its own
file path or secret id). Each agent generates its own device keypair and id and
enrolls idempotently; under LayerV key policy the durable key is hash-matched
and **not consumed**, so it survives any number of enrollments. Don't point two
agents at one `store` — that is a single shared identity, not a fleet.

## Two enrollment paths

`RegisterAgent` picks the enrollment path automatically from the kind of key you
pass. You call the same function either way.

### Pre-issued (bootstrap) key — one call, headless

A pre-issued key **is** the enrollment credential. `RegisterAgent` completes in
a single call with no email and no prompt — the right fit for headless agents
and CI:

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")

client, err := qurl.RegisterAgent(ctx, preIssuedKey, store)
if err != nil {
	return err
}
// client is ready.
```

### Account key + email one-time code

An account key enrolls with an email one-time code (OTP). This path is
**two-phase and re-entrant**: the first call asks LayerV to email a code and
returns `*OTPPendingError` (which unwraps to `ErrOTPPending`); you re-run
`RegisterAgent` with the code once it arrives.

This is a pause point, not a failure. Match `*OTPPendingError` with
`errors.As`, read `MaskedEmail` so you can tell the operator which inbox to
check, obtain the code, and re-run with `WithOTP`:

```go
client, err := qurl.RegisterAgent(ctx, accountKey, store)

var pending *qurl.OTPPendingError
switch {
case errors.As(err, &pending):
	// LayerV emailed a code to pending.MaskedEmail (e.g. "j***@acme.com").
	// Obtain it out of band, then resume.
	code := readOneTimeCode(pending.MaskedEmail)

	client, err = qurl.RegisterAgent(ctx, accountKey, store, qurl.WithOTP(code))
	if err != nil {
		return err
	}
	use(client)
case err != nil:
	return err
default:
	// Already registered on a prior run — client returned with no code needed.
	use(client)
}
```

`errors.Is(err, qurl.ErrOTPPending)` matches the same pause if you only need the
boolean and not the masked destination.

The re-entrancy is durable across process restarts. `store` records that a code
was requested, so a crashed-and-restarted process resumes the **same enrollment
identity** (the same device keypair and `agent_id`) rather than starting over —
and, within the resend cooldown, keeps waiting on the already-emailed code rather
than sending a new one. Re-running with **no** code only re-sends a fresh code
once that short cooldown has elapsed (so a long-idle restart refreshes an expired
code), then pauses again.

#### Single-call variant with `WithOTPProvider`

If the agent can fetch its own code — for example by reading a mailbox API —
`WithOTPProvider` supplies it from a callback so one `RegisterAgent` call both
requests and consumes the code:

```go
client, err := qurl.RegisterAgent(ctx, accountKey, store,
	qurl.WithOTPProvider(func(ctx context.Context) (string, error) {
		return fetchLatestOneTimeCode(ctx) // polls until the code arrives
	}),
)
```

**Caveat (from the `WithOTPProvider` godoc):** on a fresh store the code is
dispatched and *then* the provider is invoked within the same call, so the
provider must **await delivery** — poll or block until the code is actually in
the mailbox. A provider that returns early hands back a stale or empty value: an
empty (whitespace-only) return fails fast with `ErrInvalidRegisterConfig` before
any registration round trip, while a non-empty but wrong code reaches the
enrollment service and fails with `ErrOTPIncorrect`. Set at most one of `WithOTP`
or `WithOTPProvider`.

## Credential storage

Registration writes an `AgentState`. Once enrollment completes, that state is a
**credential file**: it holds `DeviceAPIKey`, the bearer token the returned
`Client` authorizes with. From then on the `Client` authenticates purely from
persisted state — the API key you passed at enrollment is not needed again.

Treat the state as secret. Keep it out of logs, crash dumps, and support
bundles.

Pick a store by runtime. They all satisfy the same two-method
`AgentStateStore` interface (`LoadAgentState` / `SaveAgentState`), so the rest of
your code is identical whichever you choose:

| Runtime | Store |
| --- | --- |
| Single host / VM / container with a durable disk | `qurl.FileAgentState(path)` |
| Local disk with a KMS/HSM/attested release boundary | `qurl.NewSealedFileAgentState(path, providerID, wrapper)` |
| Shared POSIX / EFS across tasks | `qurl.FileAgentState(mountPath)` — **not** the AWS stores |
| Ephemeral / autoscaling / Lambda / Fargate (no durable disk) | `awsstore.NewSecretsManagerStore(...)` |
| Cost-sensitive AWS fleets | `awsstore.NewParameterStore(...)` (KMS SecureString) |
| Custom backend / tests | implement `AgentStateStore`; return `qurl.ErrAgentStateNotFound` when empty |

### File storage (`FileAgentState`)

`qurl.FileAgentState(path)` writes plaintext JSON protected by filesystem
permissions: the file is `0600` under a `0700` directory, written atomically
(temp file + rename). It is the right store for a single host — or for shared
POSIX storage such as EFS (see below):

```go
store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
```

On a shared or multi-tenant host where filesystem permissions are not a
sufficient boundary, use the sealed file store below or back the state with a
secret manager.

### Sealed file storage (`NewSealedFileAgentState`)

`NewSealedFileAgentState` encrypts the complete `AgentState`—including the
device API credential and X25519 private key—under an SDK-owned AES-256-GCM
envelope. Every save generates a fresh 32-byte data-encryption key (DEK) and
nonce. Your `AgentStateKeyWrapper` integrates the chosen KMS, HSM, or attested
key-release provider and sees only that exact 32-byte DEK, never AgentState JSON.
Both full-AgentState file stores cap encoded state at 1 MiB so plaintext and
sealed deployments have the same schema-growth budget. `FileCredentials` keeps
its historical 64 KiB issuer-credential cap; the sealed envelope, wrapped key,
and provider metadata are independently bounded.

```go
store, err := qurl.NewSealedFileAgentState(
	"/var/lib/layerv/qurl/agent_state.sealed.json",
	"aws-kms",
	myKMSWrapper,
)
if err != nil {
	return err
}
client, err := qurl.RegisterAgent(ctx, enrollmentKey, store)
```

The wrapper must authenticate every field in `AgentStateKeyBinding` as its KMS
encryption context (or equivalent): purpose, envelope version, provider id, and
agent id. It owns the version and optional JSON metadata in
`WrappedAgentStateKey`. The SDK may compact, indent, or otherwise reserialize
that metadata between wrap and unwrap, so treat it as JSON semantics rather than
byte-identical whitespace or object-member ordering. Return
`qurl.ErrInvalidWrappedAgentStateKey` when a persisted wrapper record fails
authentication; ordinary KMS/network failures remain operational
`qurl.ErrAgentStateKeyWrapper` errors rather than being misreported as corrupt
state. If the provider cannot distinguish authentication failure from another
decrypt failure, return the invalid-record sentinel and fail closed. The SDK
includes wrapper metadata in its AES-GCM AAD; wrappers that use metadata to
choose or configure unwrap must cryptographically authenticate a
provider-defined canonical or semantic representation in their wrapped-key
record or provider encryption context too, because unwrap necessarily runs
before the SDK can verify that AAD.

Every successful state mutation performs `WrapKey` and a verification
`UnwrapKey` before the atomic commit—two provider operations per save. This is a
deliberate fail-before-commit check. The runtime identity therefore needs both
wrap/encrypt and unwrap/decrypt permission during initial enrollment and any
later workflow that mutates state. Decrypt-only permission is insufficient. A
fresh pre-issued-key enrollment persists three transitions (typically six
provider operations); an account enrollment that requests and completes OTP
persists four (typically eight). Restarts, retries, or OTP re-sends can add more,
and resumed incomplete setup unwraps once before and again after acquiring the
lock. These paths compound during retry storms and OTP redispatch, so size
KMS/HSM quotas and latency budgets for degraded workflows, not only the happy
path's six or eight calls. The second incomplete-state read ensures only the
locked snapshot can drive mutation if another process completed setup between
the two loads.

The wrapper binding authenticates the agent id stored in the envelope; the
store does not accept a separately configured expected agent id. A principal
that can unwrap state for multiple agents could therefore substitute another
valid envelope within that principal's decrypt scope. Scope each runtime's KMS
key or decrypt policy to one installation when cross-agent substitution must be
prevented, and authenticate every binding field in the provider encryption
context. When the agent id is known in configuration, also pass
`qurl.WithExpectedSealedAgentID(id)` to the store and the same id through
`qurl.WithDeviceID(id)` (or `qurl.WithAgentID(id)` for `BootstrapAgent`); the
store then rejects a different envelope before it calls the key wrapper. Sealed
store agent ids must be valid UTF-8, at most 256 bytes, and contain neither
surrounding whitespace nor control characters.

This identity binding assumes `agent_id` is generated by the SDK or supplied by
the caller and registration completion echoes it unchanged. If the service ever
introduces an independently server-minted id, update the plaintext and sealed
AgentState validation contracts together; do not relax only the sealed decoder.

Sealing authenticates each envelope but does not provide freshness or
anti-rollback protection. An attacker who can replace the file with an older
valid envelope for the same provider and agent id will not be detected by this
store alone; deployments requiring rollback detection must keep a monotonic
version in an external trusted store and enforce it around `AgentStateStore`.

The SDK wipes its temporary plaintext and DEK byte buffers after use. Go's JSON
decoder copies credential fields into `AgentState` strings, which are immutable
and cannot be explicitly wiped; buffer wiping is best-effort defense in depth,
not a guarantee that no plaintext copies remain in process memory.

Both SDK local-file stores require an immediate `0700` state directory, write a
`0600` state file atomically, and take the same mandatory setup lock. Lock
failures stop registration; custom/network stores remain caller-serialized.
"Mandatory" means the SDK refuses to proceed unless it acquires the OS advisory
`flock`; it does not turn advisory locking into kernel-enforced exclusion for a
non-cooperating writer.
The exact directory mode is enforced on load as well as save, including a
completed registration's read-only fast path; correct a pre-existing `0750` or
`0755` directory to `0700` before upgrading. A read-only filesystem mount is
supported when the directory metadata remains exactly `0700`; changing the mode
to `0500`, `0555`, or another "stricter" value is rejected by policy.
If lock release fails after enrollment was atomically persisted, the call still
returns `ErrAgentSetupLock` and no client because ownership is ambiguous. Retry
normally: the completed state then recovers through the pre-lock fast path
without enrolling a second identity.
Windows, Plan 9, and js/wasm do not currently have an SDK local-file lock
implementation, so fresh or incomplete local-file enrollment fails closed with
`ErrAgentSetupLock` there. Use a custom/network store (including `awsstore` where
applicable) that serializes setup itself. A completed registration reopens on a
lock-free read-only fast path; direct `LoadAgentState` and `SaveAgentState` calls
are also unaffected.

### AWS storage (`awsstore`)

The `awsstore` submodule provides `AgentStateStore` implementations backed by
AWS Secrets Manager and SSM Parameter Store. It is a **separate Go module**, so
the AWS SDK dependency never leaks into the root `qurl` module — programs using
the file store pull in no AWS code.

```sh
go get github.com/layervai/qurl-go/awsstore@latest
```

**Secrets Manager** — reach for it when the identity is a first-class secret you
want rotation hooks, resource policies, and CloudTrail data events on:

```go
import (
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/layervai/qurl-go/awsstore"
	"github.com/layervai/qurl-go/qurl"
)

cfg, err := config.LoadDefaultConfig(ctx)
if err != nil {
	return err
}
store := awsstore.NewSecretsManagerStore(
	secretsmanager.NewFromConfig(cfg),
	"qurl/agent-state",                        // secret name or ARN
	awsstore.WithKMSKeyID("alias/qurl-agent"), // customer-managed CMK (recommended)
)

client, err := qurl.RegisterAgent(ctx, apiKey, store)
```

**Parameter Store** — a lighter-weight, lower-cost option that is still
KMS-encrypted at rest:

```go
import (
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/layervai/qurl-go/awsstore"
)

store := awsstore.NewParameterStore(
	ssm.NewFromConfig(cfg),
	"/qurl/agent-state",                       // parameter name
	awsstore.WithKMSKeyID("alias/qurl-agent"),
)
```

Because the stored value is a credential, encrypt it with a customer-managed KMS
key via `WithKMSKeyID` and scope IAM to the single resource. The
[`awsstore` README](../awsstore/README.md) has the least-privilege IAM policies
for each store, the KMS-binding note (on Secrets Manager the CMK is bound at
`CreateSecret` time), and the store contract.

**EFS = `FileAgentState`.** For EFS-backed or other shared POSIX storage, do
**not** use the AWS stores — point the root module's file store at the mounted
path:

```go
store := qurl.FileAgentState("/mnt/efs/qurl/agent-state.json")
```

`FileAgentState` writes atomically with the same `0600`/`0700` posture across
the shared mount and pulls in no AWS SDK. Encrypt the file system at rest and
restrict the access point's POSIX uid/gid to the agent. See the
[EFS recipe](../awsstore/README.md#efs-recipe-shared-storage--no-aws-store-needed).

For `FileAgentState` and `NewSealedFileAgentState`, the SDK serializes concurrent
setup across processes with a mandatory sidecar lock. Run enrollment from **one
process at a time** for custom/network stores; the SDK cannot derive a shared
lock for them, and concurrent account-path setup can dispatch multiple OTPs.

## Binding refresh and credential recovery

These are deliberately separate operations:

- `RefreshAgentRegistration` always fetches current registration-info, validates
  the relay `server_id` against the NHP peer key, sends a real `NHP_REG`, and
  requires a successful `NHP_RAK`. It then saves the authoritative relay/peer
  metadata while preserving `DeviceAPIKey` and `RegisteredAt`. It never calls
  completion, even when the old peer is expired or missing. `WithTakeover()` is
  honored only when explicitly supplied.
- `RecoverAgentCredential` is the operator-controlled path for a revoked or
  locally lost device credential. It preserves the persisted device id and
  X25519 keypair, sends REG, calls completion exactly once, and persists the
  replacement before returning a `Client`. It is never triggered automatically
  by a 401 or by ordinary binding refresh.

```go
state, err := qurl.RefreshAgentRegistration(ctx, enrollmentKey, store,
	qurl.WithAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindBootstrap),
	qurl.WithRegisterBaseURL(registrationURL),
)

client, err := qurl.RecoverAgentCredential(ctx, enrollmentKey, store,
	qurl.WithDeviceID(state.AgentID),
	qurl.WithRegisterBaseURL(registrationURL),
	qurl.WithAgentClientBaseURL(resourceAPIURL),
)
```

Credential recovery has an intentional owner step: first revoke
`agent:<device_id>` with an owner credential. qurl-service atomically revokes
the prior device key and clears its first-issue sentinel; only then can explicit
same-id recovery mint one replacement. If the sentinel is still present,
completion returns `device_key_already_issued`, mapped to
`*CredentialRecoveryRequiredError`. Use an active durable `qurl:agent` or
account enrollment key for recovery; a consumed one-shot bootstrap key cannot
perform a later registration-info refresh.

Completion and local persistence are a distributed transaction. If completion
returns a plaintext key but the final `SaveAgentState` fails, the SDK returns
`*CredentialPersistenceError` carrying the device id. It never retries
completion in that call. Revoke `agent:<device_id>`, then invoke
`RecoverAgentCredential`; do not delete the state or choose a new identity.

The same recovery-required class covers every ambiguous post-completion result:
a transport failure after dispatch, an unclassified 5xx, malformed/invalid 2xx
response, response agent-id mismatch, or a completion peer key that differs from
the peer that authenticated the RAK. Completion is first-issue-only, so none of
those conditions is safe to retry automatically. The sole 5xx exception is
qurl-service's structured `503 service_unavailable`, emitted by completion's
pre-auth admission layer before the mint handler runs; that maps to
`ErrRegistrationRetryLater`. The SDK preserves the RAK-authenticated peer and
requires qurl-service's completion response to report the same key; the response
cannot silently rotate binding state after the handshake.

## Errors

Match errors by type, not message text: use `errors.Is` against a sentinel for a
broad outcome, and `errors.As` against a typed error to read structured detail.
Every message names the next concrete step.

| Error | When it happens | Handle it by |
| --- | --- | --- |
| `*qurl.OTPPendingError` (unwraps `ErrOTPPending`) | Account path emailed a code and is waiting for it. Not a failure — the pause point. | `errors.As` to read `MaskedEmail`; re-run with `WithOTP(code)`. |
| `qurl.ErrOTPIncorrect` | Supplied one-time code was wrong. | Re-run with the correct `WithOTP` code. |
| `qurl.ErrOTPExpired` | Code was valid but expired. | Re-run with **no** code to request a fresh one, then supply it. |
| `qurl.ErrRegistrationRateLimited` | Too many attempts, or the service is rate limiting. | Back off and retry later. |
| `qurl.ErrRegistrationRetryLater` | The relay returned an overload cookie, or completion's pre-auth admission layer returned structured `service_unavailable` before minting. | Back off briefly and re-run. |
| `qurl.ErrKeyRejected` | The API key (or a pre-issued key used as the credential) was rejected. | Check the key and re-run. |
| `qurl.ErrBootstrapSetupKeyConsumed` | A pre-issued **one-shot** setup key was already consumed by an earlier enrollment (RAK code 52108, or reported by the completion call). | Mint a fresh setup key, or restore the completed agent state from the run that consumed it. |
| `qurl.ErrAgentIdentityConflict` | This device id is already enrolled to a different key or agent. | Re-run with `WithTakeover()` to re-bind, or pick a different `WithDeviceID`. |
| `qurl.ErrNoAccountEmail` | Account key has no email on file for the code. | Add an email to the account, or use a pre-issued key. |
| `*qurl.RegistrationKeyKindDisallowedError` (unwraps `ErrRegistrationKeyKindDisallowed`) | Registration-info returned a valid key kind rejected by caller policy. No OTP/REG side effect occurred. | Supply an allowed enrollment key or deliberately widen `WithAllowedRegistrationKeyKinds`. |
| `*qurl.CredentialPersistenceError` (unwraps `ErrCredentialRecoveryRequired` and `ErrDeviceCredentialMissing`) | Completion may have minted a key, but transport/5xx/response validation or the final state save left no provably durable credential. | Revoke `agent:<DeviceID>`, then call `RecoverAgentCredential` with the same store. Never loop ordinary registration. |
| `*qurl.CredentialRecoveryRequiredError` (unwraps `ErrCredentialRecoveryRequired` and `ErrDeviceCredentialMissing`) | The device key was already issued or completed state lacks its local credential. | Revoke `agent:<DeviceID>`, then call `RecoverAgentCredential` with the same store and enrollment key. |
| `qurl.ErrRegistrationInvalidInput` | The service rejected a registration input as malformed (e.g. a bad device id). | Fix the input (use a valid `WithDeviceID`) and re-run. |
| `qurl.ErrRegistrationDisabled` | Agent registration is disabled for the account. | Contact the account owner to enable it. |
| `qurl.ErrInvalidRegisterConfig` | Inputs or options were invalid before any network call (empty key, nil store, conflicting options). | Fix the call. |
| `qurl.ErrInvalidAgentState` | Persisted state exists but is corrupt/unreadable — surfaced wrapped in the front-door config error. (`ErrAgentStateNotFound` is **not** caller-facing: it is the store-contract sentinel a custom `AgentStateStore` returns when empty, which the engine converts into a fresh enrollment.) | Clear or replace the corrupt state. |
| `qurl.ErrAgentStateKeyWrapper` | A sealed store's KMS/HSM wrapper is unavailable or violated its 32-byte DEK contract. | Restore provider access/configuration; do not delete otherwise valid state for an operational outage. |
| `qurl.ErrAgentSetupLock` | The mandatory local-file setup lock could not be acquired or released. | Fix state-directory/sidecar permissions or platform support; do not run setup unlocked. |
| `*qurl.RegistrationDenyError` | An authenticated enrollment denial carrying a wire code newer than this SDK. | Read `ErrCode` / `ErrMsg`; `errors.Is` still matches the typed sentinel for known codes. |

A worked pattern:

```go
client, err := qurl.RegisterAgent(ctx, apiKey, store)

var pending *qurl.OTPPendingError
switch {
case err == nil:
	use(client)
case errors.As(err, &pending):
	resumeWithCode(pending.MaskedEmail) // re-run with WithOTP
case errors.Is(err, qurl.ErrAgentIdentityConflict):
	// deliberate re-bind, replaces the prior binding
	client, err = qurl.RegisterAgent(ctx, apiKey, store, qurl.WithTakeover())
	// ...
case errors.Is(err, qurl.ErrRegistrationRetryLater),
	errors.Is(err, qurl.ErrRegistrationRateLimited):
	backOffAndRetry()
default:
	return err
}
```

## Troubleshooting

**No email arrives on the account path.** If registration returns
`ErrNoAccountEmail`, the account key has no usable email on file — the code can
never be delivered. Add an email to the account, or enroll with a pre-issued key
(which needs no email). If a code *was* sent but has not arrived, re-running
`RegisterAgent` with no code re-sends a fresh one after a short cooldown.

**Lost device credential.** Match `ErrCredentialRecoveryRequired` and use
`errors.As` to read `DeviceID` from `CredentialPersistenceError` or
`CredentialRecoveryRequiredError`. Do not clear the state or rotate the device
id: an owner first revokes `agent:<device_id>`, then the agent calls
`RecoverAgentCredential` with the same store and enrollment key.

**Setup key already consumed.** `ErrBootstrapSetupKeyConsumed` means a pre-issued
one-shot setup key was accepted by an earlier enrollment and cannot enroll again.
Mint a fresh setup key from LayerV, or restore the completed `AgentState` from the
run that consumed the key.

**Identity conflict / takeover.** `ErrAgentIdentityConflict` means the device id
is already enrolled to a different key or agent. Re-run with `WithTakeover()` to
deliberately re-bind it — this **replaces** the prior binding, so use it
knowingly — or choose a different id with `WithDeviceID`.

**Rate limiting / retry.** `ErrRegistrationRateLimited` (too many attempts) and
`ErrRegistrationRetryLater` (relay overload or a pre-mint admission outage) are
both back-off signals. Wait and re-run; `RegisterAgent` resumes the same
enrollment.

## Migrating from BootstrapAgent

`BootstrapAgent` still works — it now runs the same NHP enrollment engine as
`RegisterAgent`'s pre-issued-key path — but **prefer `RegisterAgent` for new
code**. `RegisterAgent` returns a ready-to-use `Client` and covers both the
pre-issued-key and email-OTP paths; `BootstrapAgent` is the pre-issued path
specialized to return the raw `AgentState`, kept for callers that build the
`Client` separately.

`BootstrapAgent`:

```go
state, err := qurl.BootstrapAgent(ctx, setupKey, store, qurl.WithAgentID("prod-us-east-1"))
```

The equivalent with `RegisterAgent`, which additionally hands back a `Client`:

```go
client, err := qurl.RegisterAgent(ctx, setupKey, store, qurl.WithDeviceID("prod-us-east-1"))
```

**Breaking change — the bootstrap origin moved.** Agent enrollment is now
NHP-native, and the endpoints live on the main API origin, `api.layerv.ai`. Two
consequences:

- The default bootstrap origin changed to `api.layerv.ai`. Anyone pinning
  `WithBootstrapBaseURL("https://bootstrap.layerv.ai")` (the old dedicated
  bootstrap host) **must migrate** — drop the override to use the default, or
  point it at the current API origin.
- The legacy `POST /v1/agent/bootstrap` HTTP path is **gone**. Enrollment now
  runs over NHP, so the backend NHP endpoints must be deployed before this
  version of the SDK can register or bootstrap an agent.

Existing state files are unaffected: the `AgentState` schema is additive and
backward compatible, so a state written by an older `BootstrapAgent` loads and
validates without migration, and a state written by `RegisterAgent` is still
readable by older code that ignores the new fields.

## How enrollment works

Enrollment is agent-initiated and travels over a relay, in the shape described
by the Cloud Security Alliance's Software-Defined Perimeter (SDP) / NHP
specification: the agent knocks to request an OTP, then sends a registration
(REG) and receives the server's registration acknowledgement (RAK). Those
OTP/REG/RAK messages ride the relay as encrypted NHP packets rather than hitting
a standing public endpoint — but the RAK is only an acknowledgement (an
`errCode`/`errMsg` status, **not** a credential). The device credential is minted
separately, by the authenticated HTTPS completion call
(`POST /v1/agent/registration/complete`), and the path-selecting discovery
pre-flight (`GET /v1/agent/registration-info`) is likewise a standing,
authenticated HTTPS call to the LayerV API. `RegisterAgent` proves the agent's
X25519 device key through the handshake, so the same keypair is reused across
resumes, and the enrollment service never becomes public inventory. You do not
configure any of this: the side-effect-free pre-flight tells the SDK which path
the key takes and where to knock.

The `WithRelayURL` and `WithNHPPeer` options exist for advanced routing (pinned
or test endpoints) and are not needed in normal use; an overridden peer bypasses
the pre-flight's integrity check, so pin only a peer you trust. The completion
response must still report that same peer key: the SDK preserves the peer that
authenticated the RAK and rejects any post-handshake replacement.

## Next

- [Issue links](issuing-links.md)
- [Open links](opening-links.md)
- [Protect a private service](secure-a-private-service.md)
- [`awsstore` README](../awsstore/README.md) — AWS-backed state stores
