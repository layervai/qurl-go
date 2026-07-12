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
OpenAPI intentionally constrains both to the exact same lowercase 3-64
character grammar. Alias validation here is therefore producer-contract
validation, not an attempt to use display metadata as qURL Connector identity.

`EnsureConnectorResource` requires the response to contain a valid
`resource_id`, `knock_resource_id`, `status: "active"`, the exact requested
slug, and the producer's private resource discriminator. Missing or
contradictory fields fail closed with `ErrInvalidConnectorResourceResponse`.

Management API `ConnectorResource.ResourceID` values intentionally follow the
producer's exact current contract: `r_` plus 11 lowercase alphanumeric,
underscore, or hyphen characters. They are distinct from the NHP public key and
the `KnockResourceID`. This is a fail-closed OpenAPI coupling, not a
forward-compatible length range; update the producer fence and SDK together if
the service ever changes the id shape. Before a future producer emits a new
shape, ship an SDK transition that safely accepts both the legacy and new
formats so already-cached ids remain usable. This greenfield cutover has no
prior production qURL Connector ids to migrate, but later format changes must
not make that assumption.

The fenced qURL Connector resource status schema contains only `active` and
`revoked`; any other status is invalid producer drift rather than a transitional
state qURL Connector may use.

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
row appears active.

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
| `qurl.ErrInvalidConnectorResourceResponse` | A 2xx response violated the qURL Connector resource contract |

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
this sentinel. A 5xx response on ensure or delete also matches it because a
gateway or service can fail after the mutation committed; the underlying
`*qurl.APIError` remains available through `errors.As`.

## API origin and transport

These methods use the `Client` resource origin and HTTP transport. Agent
registration can use a separate origin, but changing the registration origin
must not retarget qURL Connector resource CRUD. The default client refuses
redirects so a bearer credential is not forwarded to a different origin.

The wire shapes are fenced against qurl-service's `/v1/resources` and
`/v1/resources/{id}` OpenAPI contracts and the existing qURL Connector
resource/bootstrap test fixtures. This SDK change does not claim that the
backend is deployed or that a qurl-go release has been tagged; those are
separate cross-repository handoff gates in issue 421.
