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
)
if err != nil {
	return err
}
defer binding.Destroy()
```

That is the whole enrollment. You supply the credential LayerV issued you and a
file to keep state in; the SDK already knows how to reach LayerV.

You get back two things:

- **`client`** — use it to create and manage protected resources, like any other
  qURL client.
- **`binding`** — proof of who this machine is. Keep it for the life of the
  process and `Destroy()` it on the way out.

## Credentials

Pass the credential LayerV issued you. Credentials minted for unattended software
work with no extra options.

Credentials must be LayerV-minted tokens of at least 32 characters. Passwords and
hand-picked strings are rejected before anything is written to disk or sent over
the network. The check is on shape and length, so the token still has to come from
LayerV to be accepted.

### Enrolling as a person

If a human is enrolling and should receive a one-time code by email, opt in
explicitly:

```go
client, binding, err := qurl.RegisterAgentRuntime(ctx, credential, store,
	qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAccount),
	qurl.WithAgentRuntimeOTPProvider(promptForEmailedCode),
)
```

Both options are required together. That is deliberate: software enrolling on its
own should never be able to trigger an email challenge by accident. Without the
callback, a person-type credential is refused before any network call with
`qurl.ErrAgentOTPRequired`.

Your callback receives only what it needs to prompt someone — never the
credential, and never anything replayable. LayerV sends at most one code per
attempt, the SDK never retries behind your back, and the code is never written to
disk. If the person cancels or mistypes, nothing is registered.

## Restarts, crashes, and flaky networks

**This is handled for you.** State is saved before anything irreversible happens,
so a crash, a dropped reply, or a reboot resumes the *same* registration instead
of starting a new one.

That resume window is **90 days**. Within it, retrying is always safe — the SDK
replays the identical registration rather than creating a second one. Past it,
`qurl.ErrAgentRecoveryExpired` tells you to enroll again.

Two things you control:

- **Keep the metadata stable.** The hostname and version you pass become part of
  the saved registration. Change them only after registration completes, or a
  resumed attempt has nothing to match.
- **Keep the state file.** It is the only thing that makes a resume possible.

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
| `ErrAgentOTPRequired` | A person-type credential with no OTP callback | Add `WithAgentRuntimeOTPProvider`, or use a credential minted for software |
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
