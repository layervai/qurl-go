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
validates canonical wire encoding and the producer's decoded-byte structural
window; qurl-service remains authoritative for DER parsing and curve validation.
The value is distinct from both `ConnectorRoutingID`, the opaque
reverse-connection routing label, and `KnockResourceID`, the placement-neutral
NHP admission target. The SDK requires all three values to be present and
pairwise distinct.

A cycle `RunID` is not a fourth resource identity and is intentionally absent
from `ConnectorResource` and the resource CRUD wire contract. qURL Connector
generates it separately with `NewCycleRunID` once per outer knock/service cycle
and reuses the exact value for that cycle's retries and reconnects. Never derive
`RunID` from `ResourceID`, `ConnectorRoutingID`, `KnockResourceID`, or `Slug`, and
never derive any of those durable control-plane values from `RunID`.

`ConnectorRoutingID` has the exact producer-owned shape
`^c-[a-z2-7]{52}$`. The SDK consumes that value verbatim; it never derives a
routing label from the public key, slug, cell id, `qurl_site`, or any hostname.

The SDK mirrors qurl-service's strict base64url decoding and 80-160 decoded-byte
structural window; legacy `r_` storage identifiers are not public REST IDs and
are rejected before dispatch. Update the producer fence and SDK together if any
identity, routing, or admission contract changes.

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
| `qurl.ErrConnectorResourceRevoked` | Resource is revoked or tombstoned |
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
| Ensure | Only `409 slug_in_use` maps to `ErrConnectorResourceSlugConflict`; only `410 resource_tombstoned` maps to `ErrConnectorResourceRevoked` |
| Get by resource id | `404` maps to `ErrConnectorResourceNotFound`; `410 resource_tombstoned` and a valid `200` detail row with `status: "revoked"` map to `ErrConnectorResourceRevoked` |
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
proof that the mutation committed. A 5xx response on ensure or delete also
matches it because a gateway or service can fail after the mutation committed;
the underlying `*qurl.APIError` remains available through `errors.As`.

## API origin and transport

These methods use the `Client` resource origin and HTTP transport. Agent
registration can use a separate origin, but changing the registration origin
must not retarget qURL Connector resource CRUD. The default client refuses
redirects so a bearer credential is not forwarded to a different origin.

The wire shapes are fenced against qurl-service's `/v1/resources` and
`/v1/resources/{id}` OpenAPI contracts, including the explicit
`connector_routing_id` producer in
[`layervai/qurl-service#1225`](https://github.com/layervai/qurl-service/pull/1225),
and the existing qURL Connector resource/bootstrap test fixtures. This SDK
change does not claim that the backend is deployed or that a qurl-go release
has been tagged. Mutable rollout state and cross-repository handoff gates live
in issue 421 rather than this SDK contract reference.
