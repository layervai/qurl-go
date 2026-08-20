# Resolve qURL Connector resources

The running Connector resolves or creates its resource over the registered
agent's assigned-cell NHP session. This path sends one authenticated `NHP_LST`
and accepts only the matching `NHP_LRT`; it has no HTTP, Hub, generic-plugin, or
cross-cell fallback.

```go
request, err := qurl.NewNativeConnectorResourceRequest("prod-dashboard", cachedResourceID)
if err != nil {
	return err
}
result, err := qurl.ResolveRegisteredAgentConnectorResource(ctx, binding, request)
if err != nil {
	return err
}

fmt.Println(result.Resource.ResourceID)
fmt.Println(result.Resource.ConnectorRoutingID)
fmt.Println(result.Resource.KnockResourceID)
fmt.Println(result.FoundExisting)
```

Use an empty `cachedResourceID` only for the first request. Once a binding is
known, supply its exact public resource ID on every later start. That value
becomes `expected_resource_id`, a read-only continuity assertion: the assigned
cell returns that exact active resource or an identity-conflict error. It never
creates, reclaims, or substitutes a resource while the assertion is present.

`RequestNonce` identifies one logical operation. Persist the request before its
first exchange and reuse every field exactly after an uncertain response. The
Authority stores the original successful result, including
`FoundExisting=false`, so a lost response can be replayed without changing its
meaning. Reusing a nonce with changed Connector or continuity fields is a
terminal invalid request. A fresh nonce for an existing binding returns
`FoundExisting=true`.

The binding keeps ownership of its device key during resource discovery. Call
`TakeDeviceStaticPrivateKey` only after every resource exchange is complete,
then use the returned `KnockResourceID` for `KnockRegisteredAgent`.

`ConnectorResource.ResourceID` is the protected resource's P-256 public key in
canonical unpadded-base64url DER SPKI form. It is distinct from both
`ConnectorRoutingID`, the opaque reverse-connection routing label, and
`KnockResourceID`, the placement-neutral admission target. The SDK requires all
three values to be present and mutually distinct. A present CRID must also
cryptographically match the delivered resource key.

`ConnectorRoutingID` has the exact producer-owned shape
`^c-[a-z2-7]{52}$`; the SDK consumes it verbatim and never derives it from the
resource key, Connector id, location, or a hostname. `KnockResourceID` remains
opaque, but must be non-empty exact UTF-8 without surrounding whitespace or
control characters and must fit the NHP application bound.

The immutable, customer-chosen Connector id is not one of those three
control-plane values. A cycle `RunID` is not a fourth identity either: generate
it separately with `NewCycleRunID` once per admission cycle and reuse that exact
value for the cycle's retries and reconnects.

The native success is accepted only when the agent id, Connector id, public
resource id, routing id, knock id, optional CRID, and continuity assertion form
one internally consistent binding. Missing, malformed, contradictory, or
cross-wired values fail closed with
`ErrInvalidNativeConnectorResourceResponse`.

## Explicit management reads

The HTTPS client retains exact read and delete operations for management tools.
They are not a recovery fallback for Connector startup: if native continuity
state is missing or the NHP exchange fails, stop and repair that state instead
of adopting an HTTPS lookup result.

Use the immutable resource id when it is available:

```go
resource, err := client.GetConnectorResource(ctx, cachedResourceID)
```

An attended management tool can also look up the active owner-scoped Connector
id:

```go
resource, err := client.GetConnectorResourceBySlug(ctx, "prod-dashboard")
```

The id lookup accepts the resource-detail envelope
`data.resource`; the slug lookup accepts the resource-list envelope `data[]`.
Keeping the id and slug response shapes separate prevents a valid HTTP response
from silently decoding to an empty resource. Detail-envelope siblings such as
`data.qurls` are intentionally ignored; only `data.resource` supplies the
Connector entity.

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

Delete operates on the whole resource. To revoke a single minted portal and
leave the resource active, use `Client.RevokePortal` with the portal's
resource and qURL ids instead — see
[Issue links](issuing-links.md#revoke-a-portal).

## Error handling

Native discovery returns one closed, authenticated error taxonomy:

| Error | Meaning |
| --- | --- |
| `qurl.ErrConnectorResourceUnavailable` | Retryable platform result; reuse the exact request nonce |
| `qurl.ErrConnectorResourceIdentityRejected` | The registered identity or assigned-cell binding is no longer exact |
| `qurl.ErrConnectorResourceEntitlementDenied` | The enrolled identity cannot use this Connector id |
| `qurl.ErrConnectorResourceIdentityConflict` | The continuity assertion did not name the exact active resource |
| `qurl.ErrConnectorResourceQuotaExceeded` | The account's Connector resource quota denied the request |
| `qurl.ErrConnectorResourceRateLimited` | Retryable rate limit; honor `ConnectorResourceDiscoveryError.RetryAfter` and reuse the exact request |
| `qurl.ErrConnectorResourceRequestRejected` | The exact application request is invalid; unchanged retry cannot succeed |
| `qurl.ErrInvalidNativeConnectorResourceResponse` | The authenticated LRT violated the native contract; do not fall back |

`ConnectorResourceDiscoveryError` exposes only the sanctioned code and bounded
retry delay. Producer diagnostics, credentials, peer keys, and the request
nonce are never reflected in its public text.

The explicit HTTPS management methods have their own typed errors and preserve
the underlying `*qurl.APIError` for status, problem code, and request diagnostics:

| Error | Meaning |
| --- | --- |
| `qurl.ErrConnectorResourceNotFound` | Resource id or owner-scoped slug was not found |
| `qurl.ErrConnectorResourceRevoked` | A resource detail row has status revoked; its slug may be reusable after ordinary delete |
| `qurl.ErrConnectorResourceTombstoned` | An exact `410 resource_tombstoned` closed the resource lifecycle; do not retry the slug as ordinary reuse |
| `qurl.ErrConnectorResourceAmbiguous` | A slug lookup returned more than one resource |
| `qurl.ErrConnectorResourceOutcomeUnknown` | A delete was dispatched, but the SDK cannot prove whether it committed |
| `qurl.ErrInvalidConnectorResourceResponse` | A 2xx response violated the qURL Connector resource contract; also matches `qurl.ErrInvalidAPIResponse` |

`ErrInvalidAPIResponse` classifies a bad successful response; it is not a retry
signal. Check the Connector-specific errors first. In particular,
`ErrConnectorResourceAmbiguous` also matches both invalid-response sentinels and
must not be retried as a generic transient failure.

The endpoint mappings are intentionally operation-specific:

| Operation | Typed lifecycle mapping |
| --- | --- |
| Get by resource id | `404` maps to `ErrConnectorResourceNotFound`; `410 resource_tombstoned` maps to `ErrConnectorResourceTombstoned`; a valid `200` detail row with `status: "revoked"` maps to `ErrConnectorResourceRevoked` |
| Get by slug | Only an empty `200 data: []` maps to `ErrConnectorResourceNotFound`; route-level 404/409/410 remain raw `*APIError` values |
| Delete | Only `404` maps to `ErrConnectorResourceNotFound` |

An error code such as `resource_revoked` never maps by code alone. In
particular, ordinary DELETE-revoked slugs may be reused while an exact
`410 resource_tombstoned` response is lifecycle-closed.

If delete matches `ErrConnectorResourceOutcomeUnknown`, reconcile with
`GetConnectorResource` before deciding whether to delete again. Pre-dispatch
validation and authorization failures do not match this sentinel. A nominal
`204` with body content or a surfaced non-4xx status also matches
outcome-unknown: neither proves whether the deletion committed. The underlying
`*qurl.APIError` remains available through `errors.As`; an authoritative 4xx
remains the producer's rejection result.

## API origin and transport

The management read/delete methods use the `Client` resource origin and HTTP
transport. Native resource discovery uses the assigned cell and the registered
agent key instead. Neither path falls back to the other. The default HTTP client
refuses redirects so a bearer credential is not forwarded to a different
origin.

Read transport failures deliberately preserve their standard underlying cause
instead of matching the mutation-only `ErrConnectorResourceOutcomeUnknown`.
Use `errors.Is` for context cancellation/deadline causes and `errors.As` for
standard transport types such as `net.Error`; reads are side-effect-free, so a
caller may retry them under its normal bounded read policy. A response that
arrives with a successful status but cannot be consumed or validated instead
matches `ErrInvalidConnectorResourceResponse`. Check the more specific
`ErrConnectorResourceAmbiguous` before a generic invalid-response branch.

The native bodies are fenced against the Connector-resource LST/LRT conformance
artifact. The management shapes remain fenced against qurl-service's
`/v1/resources` and `/v1/resources/{id}` OpenAPI contracts.
