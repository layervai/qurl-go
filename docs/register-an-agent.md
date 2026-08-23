# Connect a service or agent

Your software registers with LayerV once, then serves traffic. Nothing listens on
a public port, so there is no endpoint for a scanner to find.

## The whole thing

This is a complete service: enroll, publish a resource, accept a connection.

```go
store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
if err != nil {
	return err
}
defer store.Close()

_, binding, err := qurl.ConnectAgentRuntime(ctx, store,
	qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredential),
	qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
	qurl.WithAgentRuntimeMetadata(hostname, version),
)
if err != nil {
	return err
}
defer binding.Destroy()

request, err := qurl.NewNativeConnectorResourceRequest("prod-dashboard", "")
if err != nil {
	return err
}
connector, err := qurl.ResolveRegisteredAgentConnectorResource(ctx, binding, request)
if err != nil {
	return err
}

privateKey := binding.TakeDeviceStaticPrivateKey()
defer clear(privateKey)

runID, err := qurl.NewCycleRunID()
if err != nil {
	return err
}

admission, err := qurl.KnockRegisteredAgent(ctx, binding, privateKey,
	connector.Resource.KnockResourceID,
	qurl.NativeKnockOptions{RunID: runID, RunAttempt: 1},
)
if err != nil {
	return err
}

// After the corresponding serving session has stopped and drained:
_, err = qurl.RetireRegisteredAgentSession(ctx, binding, privateKey,
	admission.SessionReceipt,
)
if err != nil {
	return err
}
```

You supply the credential LayerV issued you, a file to keep state in, and a way
to read the one-time code. The SDK already knows how to reach LayerV.

`readOneTimeCode` is a function you write. On a first enrollment that call
**blocks** while LayerV emails a code to the address on your credential and waits
for your callback, so give the context a deadline if nothing may be watching the
mailbox. [The one-time code](#the-one-time-code) shows one. Later starts never
call it.

Two things come back from registration:

- **`client`** — performs explicit management actions such as removing a
  resource. Resource setup for the running Connector does not use it.
- **`binding`** — proof of who this machine is. Hold it for the life of the
  process and `Destroy()` it on the way out.

Resource setup is a registered-agent `NHP_LST`/`NHP_LRT` exchange sent directly
to the assigned cell. It does not call the qURL HTTPS API. In production,
persist `request.RequestNonce` before the first exchange and reuse the exact
request after an uncertain response; changing any request field under the same
nonce is rejected. Once a resource is known, pass its exact `ResourceID` as the
second argument to `NewNativeConnectorResourceRequest` on later starts. That is
a read-only continuity assertion: LayerV returns that exact active resource or
fails instead of creating or adopting a replacement.

And two rules for the serving loop:

- **One run ID and positive attempt number per cycle attempt.** Do not change
  either between retries. Increment the attempt only when starting a new
  serving attempt under the same run.
- **Retire before wiping the key.** After the serving session has stopped and
  drained, call `qurl.RetireRegisteredAgentSession` with the exact
  `SessionReceipt` returned by admission. Retry an ambiguous result with that
  same receipt, then wipe the device key when the lifecycle operation ends.
  Retirement closes only that admission; it cannot retire a sibling or
  replacement.
- **Keep the receipt opaque and in memory.** Copying the complete Go value is
  safe, but do not JSON-marshal or reconstruct it from its exported fields: its
  private routing snapshot returns retirement to the original cell and is not
  serialized. Server-side recovery closes sessions left behind by a process
  crash.

## Which enrollment path?

There are two, and the credential LayerV issued you decides which — not
anything you configure:

| How you got the credential | Path | What you pass |
|---|---|---|
| Issued against an address — your account, a service account, a team alias | One-time code | `WithAgentRuntimeOTPProvider` (the default) |
| Pre-issued one-shot for a machine — a connector bootstrap or bootstrap key baked into an image or installer | No code | `WithAgentRuntimeHeadlessEnrollment` |
| A retired durable agent key — a legacy `qurl:agent`-scoped credential | No code | `WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAgent)` — the headless option does not admit this kind |

**The token itself will not tell you.** Credentials carry no kind you can parse;
the SDK checks only shape and length, and LayerV reports the kind on the first
authenticated call. Go by how you obtained it.

**If you are not sure, run the call at the top of this page.** With a provider
installed the default assumes the one-time code, and when that is wrong the
error names the kind LayerV actually reported:

```
qurl: registration key kind "bootstrap" is disallowed; accepted kinds: account (this is a one-shot enrollment token that carries its own proof, so it does not use the OTP path; pass WithAgentRuntimeHeadlessEnrollment)
```

That is a `*qurl.RegistrationKeyKindDisallowedError`, and its `Kind` field
carries the same value. Add `qurl.WithAgentRuntimeHeadlessEnrollment()` and the
call goes through. A wrong first guess costs you nothing: the check happens
before any registration, and the retry reuses the same agent identity the first
attempt saved to your state file rather than enrolling a second one.

Do this with the provider installed. A call with *no* provider stops earlier
still, with `qurl.ErrAgentOTPRequired` — that check runs before the Hub is
contacted, so there is no reported kind for it to name.

Either way, the credential must be a LayerV-minted token of at least 32
characters. Passwords and hand-picked strings are rejected before anything is
written to disk or sent over the network.

## The one-time code

Enrollment sends a one-time code to the address on the credential, and your
callback returns it. This is the default and it is what you should use.

Nothing about it assumes a human is at a keyboard. Agents increasingly have
their own mailboxes, and a service account or a shared operations alias is just
as valid. The only question the SDK cares about is whether *something* can read
the address the code went to and hand the code back:

```go
func readOneTimeCode(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	// However this runtime reaches its mailbox: an IMAP poll, your inbox API,
	// a prompt an operator answers. Return the code as exactly 8 decimal digits.
	return pollMailboxForCode(ctx)
}
```

Return **exactly 8 decimal digits**; anything else is rejected as a
configuration error. Honor the `ctx` you are handed — it is already bounded by
the assignment ticket, so returning late is the same as not returning at all.

The `challenge` argument is for logging and correlation, not for fetching
anything: it carries the agent id, credential key id, cell id, and ticket
expiry, and deliberately excludes the credential and the ticket itself. There is
nothing replayable in it.

LayerV sends at most one code per attempt, the SDK never retries behind your
back, and the code is never written to disk. If the code never arrives or comes
back wrong, nothing is registered.

Without a callback, enrollment stops with `qurl.ErrAgentOTPRequired` before any
network call.

### If nothing can read a mailbox

Some runtimes genuinely have no address anywhere in reach — a sealed appliance,
an air-gapped build agent, a container with no path to any inbox. Those enroll
with a pre-issued credential and no code, and they have to say so:

```go
client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
	qurl.WithAgentRuntimeEnrollmentCredential(credential),
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeHeadlessEnrollment(),
)
```

This is the escape hatch, not the shortcut. It accepts exactly the two one-shot
enrollment token kinds that carry their own proof (`connector_bootstrap` and
`bootstrap`) and refuses an OTP credential, since honoring one would need the
code this runtime just said it cannot get. The retired durable `agent` kind is
not admitted here either; a legacy `qurl:agent`-scoped key needs the explicit
[`WithAgentRuntimeAllowedRegistrationKeyKinds`](#accepting-either-kind). Reach
for this only when no address — the runtime's own, an operator's, or a shared
alias — can receive the code.

If the one-shot token must be minted for the agent identity at first use, supply
it lazily instead of minting it before `ConnectAgentRuntime` knows that identity:

```go
credentialProvider := func(ctx context.Context, request qurl.AgentEnrollmentCredentialRequest) (string, error) {
	return mintOrReplayEnrollmentToken(ctx, request.AgentID, request.PendingActivationRecovery)
}

client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
	qurl.WithAgentRuntimeEnrollmentCredentialProvider(credentialProvider),
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeHeadlessEnrollment(),
)
```

The SDK generates and saves `request.AgentID` before calling the provider, and
holds the setup lock across the callback and enrollment. A concurrent start
therefore waits, reloads the completed state, and does not mint again. Before
contacting the mint authority, persist or deterministically derive a non-secret
idempotency transaction identity from the stable agent id, then replay that
transaction on every callback until enrollment is known complete.
`PendingActivationRecovery == false` means only that qurl has no pending REG; a
prior provider mint may still have committed before its result reached the SDK.
If the field is true, replay must return the exact same token: qurl stores only
its fingerprint and rejects a new token. Never persist the raw token. The
callback is not called for completed state, pending completion, lease renewal,
or offline open, and it is not retained by the returned binding.

The lazy provider cannot be combined with an eager enrollment credential, an
OTP provider, or offline open; each contradiction fails with
`qurl.ErrInvalidRegisterConfig` before the callback or network is reached.

**`WithAgentRuntimeHeadlessEnrollment` replaces the OTP provider and nothing
else.** Keep every other option, `WithAgentRuntimeMetadata` included — it is not
a shorter form of the call. If registration comes back rejecting the input, the
error names the options to look at:

```
qurl: native assigned-cell registration input rejected (errCode="52109");
correct WithAgentRuntimeIdentity, WithAgentRuntimeMetadata, or the producer
contract before retrying
```

Match it with `errors.Is(err, qurl.ErrRegistrationInvalidInput)`.

**It cannot be combined with an OTP provider.** One option says no code can be
read; the other says how to read one. Passing both is a contradiction, not a
harmless dead callback, and it fails with `qurl.ErrInvalidRegisterConfig` when
the options are parsed.

### Accepting either kind

You need this only if one binary ships to both kinds of deployment and cannot
know at build time which credential it will get. Keep the provider and widen the
policy rather than reaching for the escape hatch:

```go
client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
	qurl.WithAgentRuntimeEnrollmentCredential(credential),
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(
		qurl.RegistrationKeyKindAccount,
		qurl.RegistrationKeyKindBootstrap,
	),
	qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
)
```

Whichever kind LayerV reports, this call takes it: the code path runs only for
the account kind, and the pre-issued kind never touches your callback.

## Running in production

**Enrollment is durable, and staying connected is automatic.** In practice that
means you can write the code above, run it under a supervisor, and stop thinking
about the lifecycle. Specifically:

- **Restart as often as you like.** `ConnectAgentRuntime` is the only call you
  need, on every start. It enrolls when nothing is registered yet, and otherwise
  returns your existing registration — without contacting LayerV or touching
  your OTP callback while its lease is live; an expired lease renews through
  the Hub first. Your process never has to work out whether this is the first
  boot.
- **Crashes and dropped replies resume.** State is saved before anything
  irreversible happens, so an interrupted enrollment continues rather than
  starting a second one — for up to 90 days. Past that,
  `qurl.ErrAgentRecoveryExpired` tells you to enroll again.
- **Leases renew themselves.** A registration holds a lease lasting hours. The
  SDK renews it at startup if it lapsed while you were down, and mid-run as it
  approaches expiry. You never track `LeaseExpiresAt` or catch an expiry error.
- **Relocations are followed.** LayerV occasionally moves where your service is
  served from. That is absorbed by the same renewal, so a move looks exactly like
  an ordinary day.

A process that restarts after a weekend outage, or one whose service was
relocated overnight, runs the same code as one restarting after thirty seconds.

If LayerV moved the agent *during* an interrupted enrollment, the resume returns
the original registration when that attempt had already been recorded, and
otherwise reports `ErrCompletionIdentityRejected` so you enroll again. Nothing
was committed in the second case, so a fresh enrollment cannot leave a stray
credential behind. Both outcomes are decided by LayerV, not guessed at locally.

### If you have no enrollment credential at runtime

Many services deliberately keep the enrollment credential out of the running
process — an installer enrolls, and the service only ever starts. Drop the
credential and OTP options:

```go
client, binding, err := qurl.ConnectAgentRuntime(ctx, store)
```

Same call, same behavior for an already-registered agent, including renewal and
relocation. Without a credential it simply cannot create a registration, which is
the property a service holding no enrollment secret wants.

### Two things you still own

- **Keep the state file.** It is the only thing that makes a resume possible.
  Losing it means enrolling again.
- **Keep the metadata stable.** The hostname and version you pass become part of
  the saved registration. Change them only after enrollment completes, or a
  resumed attempt has nothing to match.

### Details worth knowing, none of which need code

- Renewal happens about once per lease, not once per knock. A knock comfortably
  inside the lease makes no extra network call.
- Renewing early is best effort. If LayerV is briefly unreachable while your
  lease is still valid, the knock proceeds on that lease. Only a lease that has
  actually run out turns a failed renewal into a failed knock.
- Sharing one binding across goroutines is safe; concurrent knocks collapse into
  a single renewal. `binding.Assignment()` reports live placement; the exported
  fields are a fixed record of where the binding started and never change, so
  either is safe to read from anywhere.
- Retries are budgeted per step, so one call can spend several budgets. Set a
  deadline on the context you pass if you want a smaller overall ceiling.

## Where state is stored

| Store | Use it when |
|---|---|
| `qurl.OpenFileAgentState(path)` | The host filesystem is already trusted. Use this for anything long-running: it reports construction errors and you own `Close`. |
| `qurl.FileAgentState(path)` | Compatibility only. Returns a store instead of an error, so a bad path surfaces later. |
| `qurl.NewSealedFileAgentState(...)` | You want the file encrypted at rest with a key you control. |
| `awsstore` | You want that key held in AWS KMS. See [`awsstore`](../awsstore/README.md). |
| Your own | Implement `qurl.AgentStateStore` for anything else. |

Whichever you choose, the file must survive restarts. Losing it means losing the
ability to resume, and you will need to enroll again.

### Point it at a directory the SDK can create

State is a credential file, so the SDK requires its directory to be `0700` and
the file itself `0600`, and it refuses to run rather than widen anything.

When the directory does **not** exist yet the SDK creates it `0700` and you
never think about this — which is why the `/var/lib/layerv/qurl/` paths above
just work. The failure everyone hits is pointing it at a directory that already
exists: `mkdir` under the usual `umask 022` leaves `0755`, and so do most
working directories and `$HOME`.

```go
// The parent already exists at 0755, so this fails closed.
store, err := qurl.OpenFileAgentState("./agent-state.json")
```

```
qurl: agent state namespace continuity lost: qurl: insecure agent state
permissions: state directory mode is 755, want 700; run: chmod 700 /srv/myapp
```

Run the `chmod` the error names, or give the SDK a subdirectory it can create
itself (`./state/agent-state.json`). The SDK will not tighten a directory you
already use for other things, and it never loosens one.

Match it with `errors.Is(err, qurl.ErrInsecureAgentStatePermissions)`. The same
error covers a state file left readable (`chmod 600`) and an ancestor directory
that is group- or world-writable — that last one names the offending ancestor,
because no `chmod` on the state directory can fix it.

## Taking manual control

Rarely needed. The defaults above suit almost every deployment.

**Renew at a moment you choose** rather than on the next start or knock:

```go
client, binding, err := qurl.RefreshAgentRuntime(ctx, qurl.HubBootstrap{}, store)
```

The empty `qurl.HubBootstrap{}` means "use the deployment's trust root" — the
file named by `QURL_DEPLOYMENT` today, embedded in GA builds later; you only
fill it in if you run your own LayerV deployment and want to pin the Hub in
code. Renewal everywhere else resolves the trust root the same way, so a
self-hosted deployment usually just points `QURL_DEPLOYMENT` at its deployment
file.

**Turn off automatic behavior:**

| Option | Effect |
|---|---|
| `qurl.WithAgentRuntimeOfflineOpen()` | `ConnectAgentRuntime` makes no network call: it serves only an existing completed registration, an expired lease returns `ErrAssignmentLeaseExpired` instead of renewing, and the binding it returns does not renew itself either. For a process that must start without reaching LayerV, or that renews on its own schedule — recover with an explicit `RefreshAgentRuntime`. Enrollment needs the network this option forbids, so combining it with `WithAgentRuntimeEnrollmentCredential`, `WithAgentRuntimeEnrollmentCredentialProvider`, or `WithAgentRuntimeOTPProvider` fails with `ErrInvalidRegisterConfig`. |
| `qurl.WithAgentRuntimePinnedAssignment()` | `ConnectAgentRuntime` and `RefreshAgentRuntime` refuse to follow a relocation, returning `*qurl.AgentAssignmentChangedError` and changing nothing on disk; a binding either call returns applies the same policy when renewing its own lease. For placement that feeds an egress allowlist or a change-control process. |

## When something goes wrong

**Fix the call:**

| Error | What to do |
|---|---|
| `ErrAgentOTPRequired` | The account kind is accepted but no OTP callback was installed. Add `WithAgentRuntimeOTPProvider`, or use `WithAgentRuntimeHeadlessEnrollment` for a pre-issued credential. |
| `*RegistrationKeyKindDisallowedError` | LayerV reported a credential kind your policy does not accept; `Kind` names it. Add `WithAgentRuntimeHeadlessEnrollment`, or widen with `WithAgentRuntimeAllowedRegistrationKeyKinds`. |
| `ErrAssignmentKeyRejected` | LayerV did not accept this credential. Check you passed the right one and that it is not revoked. |
| `*AgentAssignmentChangedError` | You pinned placement and LayerV moved your service. Drop `WithAgentRuntimePinnedAssignment` to follow the move. |
| `ErrAssignmentLeaseExpired` | LayerV could not be reached to renew, or you passed `WithAgentRuntimeOfflineOpen`. Check connectivity; drop the option if you did not mean to manage renewal yourself. |

**Wait and retry:**

| Error | What to do |
|---|---|
| `ErrAssignmentRateLimited` | Too many attempts too quickly. Back off. |
| `ErrAssignmentReassignmentRequired` | A move was in progress and the SDK's own retries did not outlast it. Retry later; if it persists, contact LayerV. |

**Enroll again:**

| Error | What to do |
|---|---|
| `ErrAgentRecoveryExpired` | Older than the 90-day resume window. |
| `ErrAgentRecoveryMigrationRequired` | Saved state predates the current format. Keep the file and enroll again. |
| `ErrCompletionIdentityRejected` | LayerV declined to finish an interrupted enrollment, usually because the agent moved before that attempt was recorded. Nothing was committed, so enrolling again cannot orphan a credential. |

**Ask LayerV:**

| Error | What to do |
|---|---|
| `ErrAssignmentQuotaExceeded` | Your account is at its limit. Raise it or retire an unused registration. |
| `*ServerDenyError` | LayerV refused the request; the error carries the reason. |

## How this stays safe

Automatic does not mean unchecked. The guarantees behind the behavior above:

- **Placement is never guessed.** Following a relocation means going where LayerV
  said to go in an authenticated reply, and only when it advances the assignment
  generation. A replayed or rolled-back placement is rejected. The SDK never
  derives an address, reads one from config, or takes one from an unauthenticated
  packet.
- **One agent, one credential.** An interrupted enrollment resumes the exact
  saved attempt rather than minting a second credential, and LayerV — not the
  SDK — decides whether that attempt already counted.
- **Enrollment and connections travel over an authenticated UDP channel.** No
  part of it uses a public HTTP endpoint.
- **Credentials and one-time codes are never written to disk.** Wipe private-key
  bytes taken from the binding as soon as the cycle ends.
- **Links and services are separate trust paths.** A link opened in a browser and
  a service connected this way do not stand in for each other.

## See also

- [Secure a private service](secure-a-private-service.md)
- [Issue links](issuing-links.md)
- [Manage connector resources](connector-resources.md)
