# Manage qURL Connector resources

qURL Connector enrolls once, persists its per-device API credential, and uses
that credential for steady-state qURL Connector resource management. The
enrollment key is not a resource CRUD credential and should not remain in this
path.

This lifecycle is tracked under
[`layervai/qurl-connector#421`](https://github.com/layervai/qurl-connector/issues/421).

## Ensure a qURL Connector resource

```go
result, err := client.EnsureConnectorResource(ctx, "prod-dashboard")
if err != nil {
	return err
}

fmt.Println(result.Resource.ResourceID)
fmt.Println(result.Resource.ConnectorRoutingID)
fmt.Println(result.Resource.KnockResourceID)
fmt.Println(result.FoundExisting)
```

The exported API uses qURL Connector terminology. The SDK supplies and validates
qurl-service's private resource discriminator internally; it is neither
configurable nor exposed on `ConnectorResource`.

The owner-scoped `Slug` is immutable and identifies qURL Connector across
restarts. `Alias` is an independent, mutable display handle; the SDK returns it
but never compares it with the slug. `EnsureConnectorResourceResult.FoundExisting`
comes from `meta.found_existing`: `true` means the resource was already active
and `false` means the service created a fresh resource, including after explicit
revocation released an old slug claim. This ensure-only metadata is deliberately
not stored on the reusable `ConnectorResource` entity.

Alias and slug have different lifecycle meaning, but qurl-service's current
OpenAPI intentionally constrains both to the exact same
`^[a-z][a-z0-9-]{1,62}[a-z0-9]$` grammar. Alias validation here is therefore
producer-contract validation, not an attempt to use display metadata as qURL
Connector identity.

The current producer rejects a nonconforming alias on create and patch, so
observing one in a successful response is contract drift or corrupt stored data;
the SDK rejects that row rather than returning a resource with invalid metadata.
If the producer ever loosens the alias grammar independently, update and release
the SDK contract with it.

`EnsureConnectorResource` requires the response to contain a valid
`resource_id`, `connector_routing_id`, `knock_resource_id`, `status: "active"`,
the exact requested slug, and the producer's private resource discriminator.
Missing, malformed, contradictory, or cross-wired fields fail closed with
`ErrInvalidConnectorResourceResponse`.

Management API `ConnectorResource.ResourceID` is the producer-issued protected
resource P-256 public key in canonical unpadded-base64url DER SPKI form. The SDK
validates canonical wire encoding, DER structure, ECDSA key type, P-256 curve,
a valid non-identity point, and the byte-exact canonical SPKI re-marshalling.
The value is distinct from both `ConnectorRoutingID`, the opaque
reverse-connection routing label, and `KnockResourceID`, the placement-neutral
NHP admission target. The SDK requires all three values to be present and
mutually distinct: the public-key and routing grammars cannot overlap, while
explicit comparisons reject an opaque knock id equal to either one.
The immutable, customer-chosen slug is not one of those three control-plane
values and may legitimately equal a syntactically valid routing or admission
value. The knock id otherwise keeps its producer-owned opaque grammar, but the
SDK rejects surrounding whitespace and control characters before forwarding
the value to the NHP admission path.

A cycle `RunID` is not a fourth resource identity and is intentionally absent
from `ConnectorResource` and the resource CRUD wire contract. qURL Connector
generates it separately with `NewCycleRunID` once per outer knock/service cycle
and reuses the exact value for that cycle's retries and reconnects. Never derive
`RunID` from `ResourceID`, `ConnectorRoutingID`, `KnockResourceID`, or `Slug`, and
never derive any of those durable control-plane values from `RunID`.

`ConnectorRoutingID` has the exact producer-owned shape
`^c-[a-z2-7]{52}$`. The SDK consumes that value verbatim; it never derives a
routing label from the public key, slug, cell id, `qurl_site`, or any hostname.

The SDK strictly decodes base64url, parses a valid P-256 DER SPKI public key, and
requires byte-exact canonical re-marshalling. Legacy `r_` storage identifiers
and non-key blobs are not public REST IDs and are rejected before dispatch.
Update the producer fence and SDK together if any identity, routing, or
admission contract changes.

`KnockResourceID` is an opaque, producer-owned NHP admission target. The SDK
requires it to be present and rejects surrounding whitespace or control
characters, but does not impose an identifier grammar on its interior bytes;
for example, internal spaces are preserved verbatim. This deliberately keeps
the client from deriving or normalizing a value that NHP must match exactly.

The fenced qURL Connector resource status schema contains only `active` and
`revoked`; any other status is invalid producer drift rather than a transitional
state qURL Connector may use. qurl-service's shared resource serializer returns
the full identity, routing, admission, type, and slug field set for active and
revoked detail/list rows. The SDK therefore validates a complete revoked row
before returning `ErrConnectorResourceRevoked`; missing fields are contract
drift, not evidence that deletion completed.

The SDK does not automatically retry `ErrConnectorResourceSlugConflict`. The
service contract permits the caller to retry that error once to resolve a
transient create race. If the retry conflicts again, stop: the slug is bound to
a resource the owner must revoke before trying again. Do not replay an ensure
whose error indicates an unknown request outcome; it may already have committed.

## Recover cached state

Use the immutable resource id when it is available:

```go
resource, err := client.GetConnectorResource(ctx, cachedResourceID)
```

If a local identity cache was lost but the qURL Connector slug is known, recover
the active resource with:

```go
resource, err := client.GetConnectorResourceBySlug(ctx, "prod-dashboard")
```

The id lookup accepts the resource-detail envelope
`data.resource`; the slug lookup accepts the resource-list envelope `data[]`.
The create/ensure path accepts the flat resource envelope `data`. Keeping these
shapes separate prevents a valid HTTP response from silently decoding to an
empty resource.

The producer defines slug lookup as a server-side active-only 0-or-1 result and
forbids combining `slug` with `status` or `type`. The SDK therefore sends only
`?slug=...`; it does not add a status filter or filter returned rows locally.
Only an explicit `data: []` is not-found; missing or `null` data is contract
drift and fails closed, so intermediaries must preserve the producer's empty
array rather than normalizing it to `null`.
More than one row is an invalid, ambiguous producer response even when only one
row appears active; the error matches both `ErrConnectorResourceAmbiguous` and
the broader `ErrInvalidConnectorResourceResponse` sentinel.

## Revoke a resource

```go
err := client.DeleteConnectorResource(ctx, resource.ResourceID)
```

Delete expects the API's `204 No Content` response. Other SDK methods still
require a non-empty JSON response, so supporting delete does not weaken the
generic JSON decoder.

## Error handling

The lifecycle methods provide matchable qURL Connector resource errors while
preserving the underlying `*qurl.APIError` for status, problem code, and request
diagnostics:

| Error | Meaning |
| --- | --- |
| `qurl.ErrConnectorResourceNotFound` | Resource id or owner-scoped slug was not found |
| `qurl.ErrConnectorResourceRevoked` | A resource detail row has status revoked; its slug may be reusable after ordinary delete |
| `qurl.ErrConnectorResourceTombstoned` | An exact `410 resource_tombstoned` closed the resource lifecycle; do not retry the slug as ordinary reuse |
| `qurl.ErrConnectorResourceSlugConflict` | Find-or-create could not resolve a slug collision to an active resource |
| `qurl.ErrConnectorResourceAmbiguous` | A slug lookup returned more than one resource |
| `qurl.ErrConnectorResourceOutcomeUnknown` | An ensure or delete was dispatched, but the SDK cannot prove whether it committed |
| `qurl.ErrInvalidConnectorResourceResponse` | A 2xx response violated the qURL Connector resource contract; also matches `qurl.ErrInvalidAPIResponse` |

`ErrInvalidAPIResponse` classifies a bad successful response; it is not a retry
signal. Check the Connector-specific errors first. In particular,
`ErrConnectorResourceAmbiguous` also matches both invalid-response sentinels and
must not be retried as a generic transient failure. Only the bounded slug
conflict and outcome-reconciliation procedures below permit another mutation.

The endpoint mappings are intentionally operation-specific:

| Operation | Typed lifecycle mapping |
| --- | --- |
| Ensure | Only `409 slug_in_use` maps to `ErrConnectorResourceSlugConflict`; only `410 resource_tombstoned` maps to `ErrConnectorResourceTombstoned` |
| Get by resource id | `404` maps to `ErrConnectorResourceNotFound`; `410 resource_tombstoned` maps to `ErrConnectorResourceTombstoned`; a valid `200` detail row with `status: "revoked"` maps to `ErrConnectorResourceRevoked` |
| Get by slug | Only an empty `200 data: []` maps to `ErrConnectorResourceNotFound`; route-level 404/409/410 remain raw `*APIError` values |
| Delete | Only `404` maps to `ErrConnectorResourceNotFound` |

An error code such as `resource_revoked` never maps by code alone. In
particular, ordinary DELETE-revoked slugs may be reused while an exact
`410 resource_tombstoned` response is lifecycle-closed.

For example, a `409 slug_in_use` matches both
`ErrConnectorResourceSlugConflict` and `*qurl.APIError`. A device credential `401`
remains an `*qurl.APIError`; the SDK does not silently retry resource CRUD with
the enrollment key.

If ensure matches `ErrConnectorResourceOutcomeUnknown`, reconcile with
`GetConnectorResourceBySlug` before deciding whether another ensure is safe. If
delete matches it, reconcile with `GetConnectorResource` before deciding whether
to delete again. Pre-dispatch validation and authorization failures do not match
this sentinel. A nominal `201` or `204` whose body violates the endpoint
contract also matches it: the SDK does not treat a protocol-invalid response as
proof that the mutation committed. A surfaced non-4xx status on ensure or
delete also matches it: an unexpected 1xx/3xx or a 5xx cannot prove whether the
mutation committed. The underlying `*qurl.APIError` remains available through
`errors.As`; an authoritative 4xx remains the producer's rejection result.

## API origin and transport

These methods use the `Client` resource origin and HTTP transport. Agent
registration can use a separate origin, but changing the registration origin
must not retarget qURL Connector resource CRUD. The default client refuses
redirects so a bearer credential is not forwarded to a different origin.

Read transport failures deliberately preserve their standard underlying cause
instead of matching the mutation-only `ErrConnectorResourceOutcomeUnknown`.
Use `errors.Is` for context cancellation/deadline causes and `errors.As` for
standard transport types such as `net.Error`; reads are side-effect-free, so a
caller may retry them under its normal bounded read policy. A response that
arrives with a successful status but cannot be consumed or validated instead
matches `ErrInvalidConnectorResourceResponse`. Check the more specific
`ErrConnectorResourceAmbiguous` before a generic invalid-response branch.

The wire shapes are fenced against qurl-service's `/v1/resources` and
`/v1/resources/{id}` OpenAPI contracts, including the explicit
`connector_routing_id` producer in
[`layervai/qurl-service#1225`](https://github.com/layervai/qurl-service/pull/1225),
and the existing qURL Connector resource/bootstrap test fixtures. This SDK
change does not claim that the backend is deployed or that a qurl-go release
has been tagged. Mutable rollout state and cross-repository handoff gates live
in issue 421 rather than this SDK contract reference.
