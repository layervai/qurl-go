# Resolve a resource and verify its CRID

`ResolveResource` asks LayerV to mint a fresh access link for a resource that
already exists. It is the counterpart of `CreatePortal`: both mint access
links, but `CreatePortal` is the issuing flow on a `Resource` handle you
protected or looked up, while `ResolveResource` is addressed by identifier —
the public-key resource id or the resource's CRID — and its response can be
tied to a resource key you already hold with `VerifyCRID`.

## Resolve an access link

```go
access, err := client.ResolveResource(ctx, resourceID, nil)
if err != nil {
	return err
}

fmt.Println(access.Link)
```

`resourceID` accepts either identifier form the platform serves: the
public-key resource id (the `Resource.ID` you stored after `ProtectURL`) or
the resource's CRID. The SDK validates presence only; the server is
authoritative for which identifiers resolve.

### Link lifetime

`opts` may be nil. If `TTL` is omitted (zero), the field is not sent and the
API applies its default lifetime; the LayerV API remains the source of truth
for account limits. The wire carries whole integer seconds, so a nonzero
`TTL` must be whole seconds — negative and sub-second durations are rejected
with `ErrInvalidResourceRequest` rather than rounded.

```go
access, err := client.ResolveResource(ctx, resourceID, &qurl.ResolveResourceOptions{
	TTL: 90 * time.Second,
})
if err != nil {
	return err
}

fmt.Println(access.ExpiresAt, access.ExpiresInSeconds, access.SingleUse)
```

The lifetime fields on the response report the server's grant, never an echo
of the request: `ExpiresAt` is zero when the API omits it, and `SingleUse`
reports whether the link expires on first successful use.

## Resolve, verify, open

`ResolveResource` deliberately does not parse, verify, or open the link.
When the link is qv2-shaped — `access.Type` reports `"qv2"` — the
composition is resolve → verify → `EnterPortal`:

```go
access, err := client.ResolveResource(ctx, resourceID, nil)
if err != nil {
	return err
}

if err := access.VerifyCRID(resourceKeyDER); err != nil {
	return err
}

handle, err := qurl.EnterPortal(ctx, access.Link)
if err != nil {
	return err
}

fmt.Println(handle.ResourceURL)
```

`resourceKeyDER` is the resource public key you already hold, as DER
SubjectPublicKeyInfo bytes exactly as delivered. `VerifyCRID` re-derives the
CRID from those bytes and compares it to `access.CRID` in constant time: nil
means the key is the one the CRID commits to, and any non-nil error is a
fail-closed "do not use this key on the strength of this response".

`EnterPortal` is the verifying opener. It needs opener trust config installed
once at startup; see [Open links](opening-links.md).

## Errors

```go
access, err := client.ResolveResource(ctx, resourceID, nil)
if err == nil {
	err = access.VerifyCRID(resourceKeyDER)
}

switch {
case err == nil:
	// Resolved, and the response is bound to the held key.
case errors.Is(err, qurl.ErrTemporaryAccessLinksDisabled):
	// The LayerV API answered 503: the environment is not currently
	// serving temporary access links. Service posture, not a bad request —
	// callers that treat resolve as optional can fall back here.
	return err
case errors.Is(err, qurl.ErrNoCRID):
	// The response carried no CRID to verify against (older server or
	// keyless resource). Verification fails closed: absence is not a
	// mismatch, but it is not a pass either.
	return err
case errors.Is(err, qurl.ErrCRIDMismatch):
	// The supplied resource key does not derive the held CRID — the
	// substitution the identifier exists to detect. Do not use the key.
	return err
default:
	return err
}
```

| Error | Meaning |
| --- | --- |
| `qurl.ErrTemporaryAccessLinksDisabled` | The API answered 503: the environment is not currently serving temporary access links — the surface is dark or administratively disabled. A service posture, not anything wrong with the request; the underlying `*qurl.APIError` remains matchable with `errors.As`. |
| `qurl.ErrNoCRID` | `VerifyCRID` had no CRID to verify against: the server omitted the field (older server or keyless resource). Fails closed — absence is not a mismatch, but it is not a pass either. |
| `qurl.ErrCRIDMismatch` | The supplied resource key does not derive the held CRID. This is the substitution the identifier exists to detect: fail closed and do not use the key. |

Other API failures surface as `*qurl.APIError` exactly like the rest of the
client. When the held CRID itself fails the local validation gate,
`VerifyCRID` wraps the `crid` package's typed sentinels (`crid.ErrCharset`,
`crid.ErrLength`, `crid.ErrChecksum`, `crid.ErrNonCanonical`,
`crid.ErrForbiddenVersion`) instead of reporting a mismatch.

## What a CRID is

A CRID — Cryptographic Resource ID — is a fingerprint of a resource public
key. It commits to the exact DER SubjectPublicKeyInfo bytes of that key:

```
digest  = SHA-256("NHP-QURL-CRID-V1" || 0x00 || der_spki_bytes)
payload = version_byte || digest[:digest_length]
crid    = base32(payload || crc32c(payload))
```

encoded with the RFC 4648 base32 alphabet in lowercase, unpadded. Because the
identifier commits to the key bytes, any party that later receives the key
can re-derive the identifier and detect substitution without trusting the
channel that delivered the key. The trailing CRC32C is typo detection, not
security. A CRID is a commitment, never an address: routing labels and
placement identifiers are separate, server-issued values, and a client must
not derive them from a CRID or from the key behind it.

The codec lives in `github.com/layervai/qurl-go/crid` and has no dependencies
beyond the standard library.

### The KeyMatches rule

`crid.KeyMatches` is the one rule every CRID consumer MUST apply: a delivered
resource key is used only if it hashes to the CRID already held. On a
mismatch the consumer fails closed — no fallback to the delivered key, no
partial trust.

In the flow above the rule is applied for you: `VerifyCRID` is `KeyMatches`
against `access.CRID`, wrapped in the client's sentinels. Apply `KeyMatches`
directly when you hold a bare CRID — for example the `Resource.CRID` stored
from a `ProtectURL` response — and a resource key arrives over any other
channel:

```go
ok, err := crid.KeyMatches(heldCRID, deliveredKeyDER)
if err != nil {
	return err // the held CRID failed the local validation gate
}
if !ok {
	return fmt.Errorf("delivered key does not derive the held crid")
}
```

`(false, nil)` is the fail-closed outcome for a valid CRID and a foreign key;
the error reports a held CRID that fails the local gate itself.

### Local validation is a gate, not an oracle

`crid.Parse` and `crid.Validate` reject only permanently invalid values, each
with one of the five typed sentinels above. Everything else is the server's
decision: a value that parses may still name a resource that does not exist,
and a structurally valid CRID with an unregistered version byte parses with
`Known` reporting false rather than failing. Forward such values to the
platform; the server is authoritative.

### Environments

The first character of a CRID encodes the top five bits of its version byte,
so production full CRIDs start with `a` and test ones with `q`. That property
is for humans scanning logs. Programs use `CRID.Environment`, which reports
production, test, or unknown — unknown for unregistered version bytes, rather
than guessing from the environment bit:

```go
c, err := crid.Parse(access.CRID)
if err != nil {
	return err
}

switch c.Environment() {
case crid.EnvironmentProduction:
	// version byte registered for production
case crid.EnvironmentTest:
	// version byte registered for test environments
case crid.EnvironmentUnknown:
	// unregistered version: forward it to the server, never reject locally
}
```

## Next

- [Open links](opening-links.md)
- [Issue links](issuing-links.md)
