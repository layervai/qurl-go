# Discovery trust policy

Native opens use the deployment bundle shipped with the SDK, or the explicit
deployment file selected by `QURL_DEPLOYMENT`. The bundle supplies trusted
issuer keys and native cell identities. It does not fetch a discovery manifest
for each open. Use this path for new native deployments. `PortalOpener` also
reuses an admitted handle for requests in one logical visit.

An application can install a `Provider` explicitly. `DiscoveryProvider` is an
optional HTTPS-relay provider: its manifest has no native cells or CRID-link
configuration. Installing it overrides the normal deployment selection. Do not
install it as a way to configure native CRID opens.

## Signed discovery

For an application that requires dynamic relay discovery, use:

- `ManifestKeys` loaded from trusted deployment configuration;
- `RequireSignature: true`;
- an explicit `ExpectedProfile`;
- an approved `MinVersion` greater than zero;
- no `PinSHA256`.

The constructor rejects a provider with no trust anchor. Every configured
anchor that applies must validate. A configured pin must match the exact
manifest bytes; a present signature under configured signing keys must verify.
A valid pin cannot rescue a bad signature. `RequireSignature` also rejects a
pin-matching document whose signature was removed.

Keep manifest-signing keys separate from the qURL issuer keys carried inside
the manifest. Never learn a manifest's signing key from that same untrusted
manifest or its unauthenticated envelope.

Pin-only mode remains available for an explicitly approved fixed document.
A pin plus a required signature is an intentional freeze of one exact signed
document, useful during a controlled rollout or incident. It is not a fallback
between independent anchors. Remove an old pin as part of a reviewed migration
to signed discovery, before publishing a different manifest.

## Rotate keys and revisions

1. Distribute the new manifest signing key under a new `kid` through trusted
   reader configuration. Keep the old key during overlap.
2. Confirm readers have that overlap set, then publish a higher-version
   manifest signed by the new key. Do not reuse a `kid` for a different key.
3. Advance the approved `MinVersion` in reader deployment configuration.
4. Retire the old manifest key after its outstanding manifests expire. An
   urgent compromise can require earlier retirement and rejection of those
   manifests. Do not silently fall back to the retired key.

Rotating a manifest-signing key does not itself retire the qURL issuer keys
inside the manifest. Their overlap must cover outstanding signed links.

`Resolve` advances its revision floor for the lifetime of that provider.
It rejects older revisions even if their signatures are valid. That runtime
floor is not durable: a restart starts at the configured `MinVersion`.
Deploy the approved floor again after a restart. Applications that require
more durable rollback state must supply it through their deployment process;
the SDK does not claim to persist it.

## No discovery cache

The SDK does not cache this optional discovery provider. Each `Resolve` fetches,
authenticates, checks the validity window, and checks the revision floor.
An endpoint failure fails the open. There is no TTL window or stale-on-error
fallback. This preserves the existing revocation/freshness behavior and adds
no cache or refresh state to a path that is not the native production default.

For high-volume native access, use the pinned deployment/cell configuration
and reuse a `PortalOpener` handle for a logical visit. A high-volume application
that specifically needs dynamic relay discovery must account for one manifest
fetch per open. Any application-owned cache must enforce both its own expiry
and the authenticated manifest's `not_after`; it must not turn a fetch failure
into permission to use expired trust material.

The signed accept path, configured-anchor precedence, unknown keys, expiry,
signing-key overlap/retirement, downgrade rejection, and race-clean concurrent
resolves have executable
coverage in `qurl/discovery_test.go`. Global-mutating test fixtures reject
parallel use through Go testing's own guard. The rest of the package can keep
parallel tests; a package-wide ban is not needed.
