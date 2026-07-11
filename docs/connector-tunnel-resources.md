# Manage qURL Connector tunnel resources

qURL Connector enrolls once, persists its per-device API credential, and uses
that credential for steady-state tunnel-resource management. The enrollment key
is not a resource CRUD credential and should not remain in this path.

This lifecycle is tracked under
[`layervai/qurl-connector#421`](https://github.com/layervai/qurl-connector/issues/421).

## Ensure a tunnel resource

```go
result, err := client.EnsureTunnelResource(ctx, "prod-dashboard")
if err != nil {
	return err
}

fmt.Println(result.Resource.ResourceID)
fmt.Println(result.Resource.KnockResourceID)
fmt.Println(result.FoundExisting)
```

The method sends exactly:

```json
{"type":"tunnel","slug":"prod-dashboard","find_or_create":true}
```

The owner-scoped `Slug` is immutable and identifies the connector across
restarts. `Alias` is an independent, mutable display handle; the SDK returns it
but never compares it with the slug. `EnsureTunnelResourceResult.FoundExisting`
comes from `meta.found_existing`: `true` means the resource was already active
and `false` means the service created a fresh resource, including after explicit
revocation released an old slug claim. This ensure-only metadata is deliberately
not stored on the reusable `TunnelResource` entity.

Alias and slug have different lifecycle meaning, but qurl-service's current
OpenAPI intentionally constrains both to the exact same lowercase 3-64
character grammar. Alias validation here is therefore producer-contract
validation, not an attempt to use display metadata as tunnel identity.

`EnsureTunnelResource` requires the response to contain a valid
`resource_id`, `knock_resource_id`, `type: "tunnel"`, `status: "active"`, and
the exact requested slug. Missing or contradictory fields fail closed with
`ErrInvalidTunnelResourceResponse`.

Resource ids intentionally follow the producer's exact current contract:
`r_` plus 11 lowercase alphanumeric, underscore, or hyphen characters. This is
a fail-closed OpenAPI coupling, not a forward-compatible length range; update
the producer fence and SDK together if the service ever changes the id shape.
Before a future producer emits a new shape, ship an SDK transition that safely
accepts both the legacy and new formats so already-cached ids remain usable.
This greenfield cutover has no prior production connector ids to migrate, but
later format changes must not make that assumption.
The fenced tunnel status schema contains only `active` and `revoked`; any other
status is invalid producer drift rather than a transitional state the connector
may use.

The SDK does not automatically retry `ErrTunnelResourceSlugConflict`. The
service contract permits the caller to retry that error once to resolve a
transient create race. If the retry conflicts again, stop: the slug is bound to
a resource the owner must revoke before trying again. Do not replay an ensure
whose error indicates an unknown request outcome; it may already have committed.

## Recover cached state

Use the immutable resource id when it is available:

```go
resource, err := client.GetTunnelResource(ctx, cachedResourceID)
```

If a local identity cache was lost but the connector slug is known, recover the
active resource with:

```go
resource, err := client.GetTunnelResourceBySlug(ctx, "prod-dashboard")
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
err := client.DeleteTunnelResource(ctx, resource.ResourceID)
```

Delete expects the API's `204 No Content` response. Other SDK methods still
require a non-empty JSON response, so supporting delete does not weaken the
generic JSON decoder.

## Error handling

The lifecycle methods provide matchable connector errors while preserving the
underlying `*qurl.APIError` for status, problem code, and request diagnostics:

| Error | Meaning |
| --- | --- |
| `qurl.ErrTunnelResourceNotFound` | Resource id or owner-scoped slug was not found |
| `qurl.ErrTunnelResourceRevoked` | Resource is revoked or tombstoned |
| `qurl.ErrTunnelResourceSlugConflict` | Find-or-create could not resolve a slug collision to an active resource |
| `qurl.ErrTunnelResourceOutcomeUnknown` | An ensure or delete was dispatched, but the SDK cannot prove whether it committed |
| `qurl.ErrInvalidTunnelResourceResponse` | A 2xx response violated the tunnel-resource contract |

The endpoint mappings are intentionally operation-specific:

| Operation | Typed lifecycle mapping |
| --- | --- |
| Ensure | Only `409 slug_in_use` maps to `ErrTunnelResourceSlugConflict`; only `410 resource_tombstoned` maps to `ErrTunnelResourceRevoked` |
| Get by resource id | `404` maps to `ErrTunnelResourceNotFound`; `410 resource_tombstoned` and a valid `200` detail row with `status: "revoked"` map to `ErrTunnelResourceRevoked` |
| Get by slug | Only an empty `200 data: []` maps to `ErrTunnelResourceNotFound`; route-level 404/409/410 remain raw `*APIError` values |
| Delete | Only `404` maps to `ErrTunnelResourceNotFound` |

An error code such as `resource_revoked` never maps by code alone. In
particular, ordinary DELETE-revoked slugs may be reused while an exact
`410 resource_tombstoned` response is lifecycle-closed.

For example, a `409 slug_in_use` matches both
`ErrTunnelResourceSlugConflict` and `*qurl.APIError`. A device credential `401`
remains an `*qurl.APIError`; the SDK does not silently retry resource CRUD with
the enrollment key.

If ensure matches `ErrTunnelResourceOutcomeUnknown`, reconcile with
`GetTunnelResourceBySlug` before deciding whether another ensure is safe. If
delete matches it, reconcile with `GetTunnelResource` before deciding whether
to delete again. Pre-dispatch validation and authorization failures do not match
this sentinel. A 5xx response on ensure or delete also matches it because a
gateway or service can fail after the mutation committed; the underlying
`*qurl.APIError` remains available through `errors.As`.

## API origin and transport

These methods use the `Client` resource origin and HTTP transport. Agent
registration can use a separate origin, but changing the registration origin
must not retarget tunnel CRUD. The default client refuses redirects so a bearer
credential is not forwarded to a different origin.

The wire shapes are fenced against qurl-service's `/v1/resources` and
`/v1/resources/{id}` OpenAPI contracts and the existing qURL Connector
resource/bootstrap test fixtures. This SDK change does not claim that the
backend is deployed or that a qurl-go release has been tagged; those are
separate cross-repository handoff gates in issue 421.
