# Opening links

This guide covers the **opener side**: turning a qURL link into a reachable resource
with `EnterPortal`, wiring up trust, handling errors, and the one operational rule
that trips people up (egress IP). To *mint* links instead, see
[Issuing links](issuing-links.md).

- [`EnterPortal` vs `EnterPortalWith`](#enterportal-vs-enterportalwith)
- [Trust providers](#trust-providers)
  - [Static provider](#static-provider)
  - [Discovery provider](#discovery-provider)
  - [The discovery manifest](#the-discovery-manifest)
- [The relay allowlist](#the-relay-allowlist)
- [The result: `ResourceHandle`](#the-result-resourcehandle)
- [The same-egress-IP rule](#the-same-egress-ip-rule)
- [Error handling](#error-handling)
- [Current status](#current-status)

## `EnterPortal` vs `EnterPortalWith`

There are two ways to open a link. They do the **same** verification and knock; they
differ only in where the trust config comes from.

**`EnterPortal(ctx, link)`** — the locked, one-argument verb. A deployment installs
its trust anchors once at startup, then opens any link with no per-call config:

```go
// once, at startup:
provider, _ := qurl.NewStaticProvider(trust, allowlist)
qurl.SetDefaultProvider(provider)

// anywhere, afterwards:
handle, err := qurl.EnterPortal(ctx, link)
```

With no provider installed, `EnterPortal` fails closed with `qurl.ErrNotConfigured`.

**`EnterPortalWith(ctx, link, cfg)`** — the explicit-config seam. Pass the trust
store and allowlist directly. Use it in tests, in code that builds config per call, or
when you need to pin a custom HTTP client (see [egress IP](#the-same-egress-ip-rule)):

```go
handle, err := qurl.EnterPortalWith(ctx, link, qurl.Config{
	TrustStore:     trust,      // *qv2.TrustStore — REQUIRED
	RelayAllowlist: allowlist,  // *qv2.RelayAllowlist — REQUIRED
	HTTPClient:     myClient,   // optional; nil uses the default client
})
```

Both `TrustStore` and `RelayAllowlist` are **required** and fail closed when missing:
an empty trust store rejects every signature, an empty allowlist rejects every link.

## Trust providers

A `Provider` resolves the two pieces of deployment config `EnterPortal` needs — the
issuer **trust anchors** (which issuer keys to trust) and the **relay allowlist**.
Neither is a per-link secret; the per-link credential rides inside the link itself.

```go
type Provider interface {
	Resolve(ctx context.Context) (*qv2.TrustStore, *qv2.RelayAllowlist, error)
}
```

A provider only *supplies* trust material — it can't weaken the gate. `EnterPortal`
feeds whatever it resolves into the same verify + post-verify allowlist check. At
worst a provider supplies an empty store/allowlist, which fails closed.

### Static provider

The simplest provider: fixed, in-process anchors. Good for pinned deployments, tests,
and embedded defaults.

```go
// Trust store: kid -> issuer public key (DER SPKI, e.g. from KMS GetPublicKey).
trust, _ := qv2.NewTrustStoreFromDER(map[string][]byte{
	"issuer-key-2026": issuerPubDER,
})

// Relay allowlist: the relays your deployment permits.
allowlist := qv2.NewRelayAllowlist([]string{"relay.example.com"})

provider, _ := qurl.NewStaticProvider(trust, allowlist)
qurl.SetDefaultProvider(provider)
```

This is a runnable example — see
[`ExampleNewStaticProvider`](../qurl/example_test.go).

To rotate keys with a static provider, build a new one whose trust store carries the
overlap set (old + new kid) and swap it in with `SetDefaultProvider`.

### Discovery provider

For deployments that publish trust anchors centrally, a `DiscoveryProvider` fetches an
**authenticated** manifest and turns it into the trust store and allowlist. The
manifest is non-secret but never blindly trusted: it's authenticated by a **pin**
(sha256 of the exact bytes) and/or a **detached issuer signature**, and it fails
closed on every doubt — unverifiable, expired, downgraded, or malformed.

```go
fetcher, _ := qurl.NewHTTPFetcher("https://trust.example.com/qurl/manifest.json", nil)

provider, err := qurl.NewDiscoveryProvider(qurl.DiscoveryConfig{
	Fetcher:   fetcher,
	PinSHA256: pin, // 32-byte sha256 of the exact manifest bytes
	// …or ManifestKeys for the signed path; see below
})
if err != nil {
	// ErrDiscoveryConfig: a provider must be pinned or signed, never blindly trusting
}
qurl.SetDefaultProvider(provider)
```

`DiscoveryConfig` knobs:

| Field              | Purpose                                                                          |
| ------------------ | ------------------------------------------------------------------------------- |
| `Fetcher`          | Fetches the raw envelope bytes (`NewHTTPFetcher`, or your own). **Required.**    |
| `PinSHA256`        | 32-byte sha256 pin of the exact manifest bytes (the pinned trust mode).          |
| `ManifestKeys`     | `kid -> *ecdsa.PublicKey` manifest-signing keys (the signed trust mode).         |
| `RequireSignature` | Make a valid signature mandatory (default: any one configured anchor suffices).  |
| `MinVersion`       | Downgrade floor — reject manifests older than this; the floor advances on accept. |
| `ExpectedProfile`  | Require the manifest's `profile` to match.                                       |
| `Now`              | Clock override (tests). Production leaves it nil.                                |

You must configure a pin and/or signing keys — a provider that authenticates nothing
is rejected at construction.

> **No caching.** A `DiscoveryProvider` re-fetches and re-verifies on **every** open,
> so a slow or down manifest endpoint fails every open. This is a deliberate
> fail-closed-over-availability stance for the mechanism. High-volume deployments
> should wrap it in a TTL cache that itself fails closed once the manifest's
> `not_after` (or the TTL) elapses.

### The discovery manifest

The fetcher returns an **envelope** that carries the manifest as opaque base64url (so
the bytes that are pinned/signed are exactly the bytes that are parsed):

```json
{
  "manifest_b64": "<unpadded-base64url of the manifest JSON below>",
  "sig_b64": "<detached issuer signature over the manifest bytes>",
  "kid": "<which ManifestKeys entry signed it>"
}
```

`sig_b64` and `kid` are present only on the signed path. The decoded manifest is:

```json
{
  "profile": "qurl-v2-trust",
  "version": 7,
  "issued_at": 1700000000,
  "not_after": 1700604800,
  "issuers": [
    { "kid": "issuer-key-2026", "spki_der_b64": "<P-256 public key, DER SPKI, base64url>" }
  ],
  "relay_allowlist": ["relay.example.com", "relay-eu.example.com:8443"]
}
```

> The manifest schema is a documented assumption today; the final discovery trust
> policy (signed vs. pinned default, rotation, downgrade window) is being finalized and
> may evolve. Manifest-signing-key rotation is separate from issuer-anchor rotation:
> overlap-publish the new `kid` into every client's `ManifestKeys` *before* cutting the
> published manifest over to sign under it.

## The relay allowlist

`relay_url` is attacker-controlled until the issuer signature verifies, so it's checked
**only afterward**, against an allowlist of host (or `host:port`) origins from your
deployment config:

```go
allow := qv2.NewRelayAllowlist([]string{
	"relay.example.com",       // matches any port on this host
	"relay-eu.example.com:8443", // matches only this exact host:port
})
```

- Comparison is case-insensitive on host.
- A bare host matches any port; a `host:port` entry matches only that exact pair.
- An empty allowlist rejects every link (fail closed) — enumerate your relays.

A `relay_url` that isn't HTTPS, or whose host isn't on the list, fails with
`qv2.ErrRelayURL`.

## The result: `ResourceHandle`

A successful open returns a `ResourceHandle`:

```go
type ResourceHandle struct {
	RedirectURL string // the now-reachable resource URL the server returned
	OpenSeconds uint32 // how long access stays open, if reported
}
```

Make your request to `RedirectURL` promptly — and from the right IP (next section).

## The same-egress-IP rule

This is the one operational rule that catches people:

> The NHP server opens access for the **source IP of your relay knock**. Any
> request you then make to `RedirectURL` **must leave from that same IP**, or it will
> arrive at a server that opened access for a different address — and be dropped.

On a single host with one network interface this is automatic. It breaks when your
knock and your resource request can take **different** egress paths — a rotating-egress
NAT, a proxy pool, or separate services. The fix is to pin both to the same exit by
giving `EnterPortalWith` an `HTTPClient` bound to that egress, and using a matching
client for the resource request:

```go
pinned := &http.Client{Transport: transportBoundToEgress(exitIP)}

handle, err := qurl.EnterPortalWith(ctx, link, qurl.Config{
	TrustStore:     trust,
	RelayAllowlist: allowlist,
	HTTPClient:     pinned, // knock leaves from exitIP …
})
// … and the resource request must leave from exitIP too:
resp, err := pinned.Get(handle.RedirectURL)
```

## Error handling

Every failure is a typed error. Match with `errors.Is` / `errors.As`, never on message
text.

| Error                          | Meaning                                          | Retryable?            |
| ------------------------------ | ------------------------------------------------ | --------------------- |
| `qurl.ErrNotConfigured`        | No provider / missing trust store or allowlist   | No — fix config       |
| `qv2.ErrSignature`             | Issuer signature didn't verify (forged/tampered) | No — reject           |
| `qv2.ErrUnknownKID`            | Signed by an issuer key you don't trust          | No — reject           |
| `qv2.ErrRelayURL`              | `relay_url` not HTTPS or not on the allowlist    | No — reject           |
| `qv2.ErrStrictParse` / `ErrFragment` / `ErrEncoding` / `ErrKeyLength` | Malformed link | No — reject |
| `qurl.ErrServerOverloaded`     | Relay returned an overload cookie-challenge      | **Yes** — backoff     |
| `*relayknock.RelayError`       | Transport fault talking to the relay             | Maybe — depends on cause |
| `*qurl.ServerDenyError`        | Authenticated deny (expired/revoked/consumed)    | No — inspect `.ErrCode` |
| `qurl.ErrMalformedReply`       | Reply unusable (e.g. success ACK with no URL)    | No — server-side fault |

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	resp, _ := http.Get(handle.RedirectURL) // mind the egress IP

case errors.Is(err, qv2.ErrSignature),
	errors.Is(err, qv2.ErrUnknownKID),
	errors.Is(err, qv2.ErrRelayURL):
	// untrusted, forged, or malformed — reject, do not retry

case errors.Is(err, qurl.ErrServerOverloaded):
	// relay is shedding load — retry later with backoff

case errors.Is(err, qurl.ErrNotConfigured):
	// no provider installed — a startup/config bug

default:
	var deny *qurl.ServerDenyError
	if errors.As(err, &deny) {
		// authenticated refusal; deny.ErrCode tells you why (e.g. expired)
	}
	// else: transport or other fault
}
```

When matching the discovery path, these additional sentinels pinpoint why a manifest
was rejected: `ErrManifestUnverified`, `ErrManifestPinMismatch`, `ErrManifestExpired`,
`ErrManifestNotYetValid`, `ErrManifestDowngrade`, `ErrManifestSchema`,
`ErrDiscoveryConfig`.

## Current status

Opening a link performs a **live network knock** to the relay. The qURL v2
server-side admission contract is still being deployed, so a live end-to-end open
can't complete yet — the parse, verify, relay-validation, and knock-construction steps
are implemented and tested offline against conformance vectors, and the live path
lights up when the server contract ships (no SDK change needed). See
[Status & limitations](../README.md#status--limitations).
