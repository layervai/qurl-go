# Connect a service or agent

Your software registers with LayerV once, then serves traffic. Nothing listens on
a public port, so there is no endpoint for a scanner to find.

## Connect

```go
store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
if err != nil {
	return err
}
defer store.Close()

client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredential, store,
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeOTPProvider(readOneTimeCode),
)
if err != nil {
	return err
}
defer binding.Destroy()
```

That is the whole enrollment. You supply the credential LayerV issued you, a
file to keep state in, and a way to read the one-time code; the SDK already
knows how to reach LayerV.

`readOneTimeCode` is a function you write. That call **blocks** while LayerV
emails a code to the address on your credential and waits for your callback to
return it, so give the context a deadline if nothing may be watching the
mailbox. [The one-time code](#the-one-time-code) below shows one.

You get back two things:

- **`client`** — use it to create and manage protected resources, like any other
  qURL client.
- **`binding`** — proof of who this machine is. Keep it for the life of the
  process and `Destroy()` it on the way out.

## Which enrollment path?

There are two, and the credential LayerV issued you decides which — not
anything you configure:

| How you got the credential | Path | What you pass |
|---|---|---|
| Issued against an address — your account, a service account, a team alias | One-time code | `WithAgentRuntimeOTPProvider` (the default) |
| Pre-issued for a machine — a connector bootstrap key, an agent key baked into an image or installer | No code | `WithAgentRuntimeHeadlessEnrollment` |

**The token itself will not tell you.** Credentials carry no kind you can parse;
the SDK checks only shape and length, and LayerV reports the kind on the first
authenticated call. Go by how you obtained it.

**If you are not sure, run the call at the top of this page.** With a provider
installed the default assumes the one-time code, and when that is wrong the
error names the kind LayerV actually reported:

```
qurl: registration key kind "bootstrap" is disallowed; accepted kinds: account
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
client, binding, err := qurl.RegisterAgentRuntime(ctx, credential, store,
	qurl.WithAgentRuntimeMetadata(hostname, version),
	qurl.WithAgentRuntimeHeadlessEnrollment(),
)
```

This is the escape hatch, not the shortcut. It accepts exactly the pre-issued
kinds that carry their own proof (`connector_bootstrap`, `bootstrap`, `agent`)
and refuses an OTP credential, since honoring one would need the code this
runtime just said it cannot get. Reach for it only when no address — the
runtime's own, an operator's, or a shared alias — can receive the code.

**It cannot be combined with an OTP provider.** One option says no code can be
read; the other says how to read one. Passing both is a contradiction, not a
harmless dead callback, and it fails with `qurl.ErrInvalidRegisterConfig` when
the options are parsed.

### Accepting either kind

You need this only if one binary ships to both kinds of deployment and cannot
know at build time which credential it will get. Keep the provider and widen the
policy rather than reaching for the escape hatch:

```go
client, binding, err := qurl.RegisterAgentRuntime(ctx, credential, store,
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

## Restarts, crashes, and flaky networks

**This is handled for you.** State is saved before anything irreversible happens,
so a crash, a dropped reply, or a reboot resumes the *same* registration instead
of starting a new one.

That resume window is **90 days**. Within it, retrying is always safe — the SDK
replays the identical registration rather than creating a second one. Past it,
`qurl.ErrAgentRecoveryExpired` tells you to enroll again.

Three things you control:

- **Keep the metadata stable.** The hostname and version you pass become part of
  the saved registration. Change them only after registration completes, or a
  resumed attempt has nothing to match.
- **Keep the state file.** It is the only thing that makes a resume possible.
- **Keep the enrollment options stable.** Resuming re-checks your policy before
  it reads the interrupted registration, so an enrollment started with
  `WithAgentRuntimeHeadlessEnrollment()` must be resumed with it still passed.
  Dropping it fails with `qurl.ErrAgentOTPRequired`. Resuming with the same
  options you started with is always correct.

Retries are budgeted per step, so one call can spend several budgets before giving
up. If you want a smaller overall ceiling, set a deadline on the context you pass.

## Starting up again later

After the first successful registration, warm starts need no network at all:

```go
client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store)
```

Use this on every normal start. Reserve `RegisterAgentRuntime` for first-time
enrollment.

## If LayerV moves your service

Occasionally LayerV relocates where your service is served from. The SDK does not
silently follow — it returns `*qurl.AgentAssignmentChangedError` so the move stays
your decision. When you are ready to accept it:

```go
client, binding, err := qurl.RefreshAgentRuntime(ctx, qurl.HubBootstrap{}, store,
	qurl.WithAgentRuntimeReassignmentAdoption(),
)
```

The empty `qurl.HubBootstrap{}` means "use the trust root this build ships"; you
only fill it in if you run your own LayerV deployment. There is nothing to look
up — the option accepts only the move LayerV just told you about, and without it
the call keeps returning the error and changes nothing on disk.

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

## Serving traffic

Each connection cycle takes the private key once and reuses one run ID for every
retry in that cycle:

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

Use **one** run ID for the whole cycle — do not regenerate it between steps. That
single ID is what lets LayerV correlate every retry with the attempt that started
it; a fresh one per retry breaks the correlation.

Wipe the key bytes when the cycle ends (`clear()` above) and call
`qurl.ExitRegisteredAgentSession` to close out cleanly.

## When something goes wrong

| Error | What it means | What to do |
|---|---|---|
| `ErrAgentOTPRequired` | OTP enrollment — the default — with no OTP callback | Add `WithAgentRuntimeOTPProvider`, or `WithAgentRuntimeHeadlessEnrollment` if nothing can read the code |
| `*RegistrationKeyKindDisallowedError` | The credential's kind is outside your enrollment policy | A pre-issued credential needs `WithAgentRuntimeHeadlessEnrollment` |
| `ErrInvalidRegisterConfig` | Among other causes: an OTP provider passed alongside `WithAgentRuntimeHeadlessEnrollment` | Drop one of the two — they contradict each other |
| `ErrAssignmentKeyRejected` | LayerV did not accept this credential | Check you passed the right one and that it is not revoked |
| `ErrAssignmentRateLimited` | Too many attempts too quickly | Back off and retry |
| `ErrAssignmentQuotaExceeded` | Your account is at its limit | Raise the limit or retire an unused registration |
| `ErrAssignmentLeaseExpired` | This registration went stale | Call `RefreshAgentRuntime` |
| `*AgentAssignmentChangedError` | LayerV moved your service | Opt in with `WithAgentRuntimeReassignmentAdoption` |
| `ErrAgentRecoveryExpired` | Older than the 90-day resume window | Enroll again |
| `ErrAgentRecoveryMigrationRequired` | Saved state predates the current format | Keep the file, enroll again |
| `*ServerDenyError` | LayerV refused the request | The error carries the reason |

## Security notes

- Registration and connections travel over an authenticated UDP channel. No part
  of it uses a public HTTP endpoint.
- Never construct LayerV addresses yourself; the SDK ships what it needs.
- Wipe private-key bytes taken from the binding as soon as the cycle ends.
- Credentials and one-time codes are never written to disk.
- Links opened in a browser and services connected this way are separate trust
  paths; neither stands in for the other.

## See also

- [Secure a private service](secure-a-private-service.md)
- [Issue links](issuing-links.md)
- [Manage connector resources](connector-resources.md)
