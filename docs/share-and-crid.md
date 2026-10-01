# Share a resource and verify its CRID

`ShareResource` asks LayerV to mint a fresh share link — a short-lived qURL
access link — for a resource that already exists. It is the counterpart of
`CreatePortal`: both mint access links, but `CreatePortal` is the issuing flow
on a `Resource` handle you protected or looked up, while `ShareResource` is
addressed by CRID and its response can be tied to a resource key you already hold with
`VerifyCRID`.

A CRID is safe to share: paste it anywhere. The share link is the secret, and
`ShareResource` is what turns the identifier into access. Each share link
expires on its own; share again whenever you need a fresh one.

## Mint a share link

```go
share, err := client.ShareResource(ctx, resourceCRID, nil)
if err != nil {
	return err
}

fmt.Println(share.Link)
```

`resourceCRID` must be the CRID returned by the service. Public keys are verification data and are rejected as resource locators.

### Link lifetime

`opts` may be nil. If `TTL` is omitted (zero), the field is not sent and the
API applies its default lifetime; the LayerV API remains the source of truth
for account limits. The wire carries whole integer seconds, so a nonzero
`TTL` must be whole seconds — negative and sub-second durations are rejected
with `ErrInvalidResourceRequest` rather than rounded.

```go
share, err := client.ShareResource(ctx, resourceCRID, &qurl.ShareResourceOptions{
	TTL: 90 * time.Second,
})
if err != nil {
	return err
}

fmt.Println(share.ExpiresAt, share.ExpiresInSeconds, share.SingleUse)
```

The lifetime fields on the response report the server's grant, never an echo
of the request: `ExpiresAt` is zero when the API omits it, and `SingleUse`
reports whether the link expires on first successful use.

### Revoke one minted link

Every share mints a new link, and each one is revocable on its own.
`ShareLink.QURLID` is the handle; `RevokePortal` is the call, taking the same
`resourceCRID` you shared:

```go
share, err := client.ShareResource(ctx, resourceCRID, nil)
if err != nil {
	return err
}

// … hand share.Link to the recipient, then withdraw it …

if err := client.RevokePortal(ctx, resourceCRID, share.QURLID); err != nil {
	return err
}
```

Only that link stops working; the resource and any other links minted from it
are untouched. Capture `QURLID` when you share — like `Link`, it is not
retrievable afterwards, and it is empty when the API omits it (a server
predating the field), which is the one case where a share link has no
individual revocation handle.

Revocation is not idempotent: the second call fails with
`qurl.ErrPortalRevoked` because the qURL is no longer active. A caller that
only needs the link dead can treat that as settled.

```go
err := client.RevokePortal(ctx, resourceCRID, share.QURLID)
switch {
case err == nil:
	// The link is dead.
case errors.Is(err, qurl.ErrPortalRevoked):
	// Already revoked — the outcome the caller wanted, reached earlier.
default:
	return err
}
```

`RevokePortal` needs the `qurl:write` scope, and it is the same call that
revokes a `CreatePortal` link — the platform mints one kind of qURL however
you ask for it. See [Issue links](issuing-links.md) for the create side.

## Share, verify, open

`ShareResource` returns an unverified link. Keep the advertised CRID from an
independent source and pass it to the opener:

```go
share, err := client.ShareResource(ctx, resourceCRID, nil)
if err != nil {
    return err
}
handle, err := qurl.EnterPortalForCRID(ctx, share.Link, resourceCRID)
if err != nil {
    return err
}
fmt.Println(handle.ResourceURL)
```

`EnterPortalForCRID` verifies the issuer signature over the exact received
claims, then hashes the signed resource key and compares it with the held CRID.
A missing, malformed, unsupported, or mismatched CRID fails before access.
For explicit deployment settings, use `Config.ExpectedCRID` with
`EnterPortalWith`. Omit it only for link-only access without an independently
held resource identity.

To verify without requesting access, call
`VerifyLinkForCRID(link, expectedCRID, trustStore)` or
`VerifyPortalLink(ctx, link, expectedCRID)` with configured deployment trust.
These checks establish the signed resource identity, not content integrity,
link liveness, or the trustworthiness of the outer browser URL. Do not obtain
`expectedCRID` from the same response as the link. Open browser links only with
a trusted frontend. See [Open links](opening-links.md) for deployment settings.

`ShareLink.VerifyCRID(resourceKeyDER)` remains a key-fingerprint helper. It does
not inspect the link or bind its signed resource key; use the APIs above for
that purpose.

## Publisher metadata

A share response also reports when the resource was created and who published
it — the resource's owner:

```go
share, err := client.ShareResource(ctx, resourceCRID, nil)
if err != nil {
	return err
}

status := "UNVERIFIED (self-declared name)"
if share.Publisher.Verified {
	status = "verified"
}
fmt.Printf("Publisher: %q - %s\n", share.Publisher.Name, status)
if share.CreatedAt != nil {
	fmt.Println("Created:", share.CreatedAt.Format(time.DateOnly))
}
```

| Field | Meaning |
| --- | --- |
| `ShareLink.CreatedAt` | When the resource behind the CRID was created. `nil` when the service did not report it. |
| `ShareLink.Publisher.Name` | The name the owner chose for itself. Empty when the owner has not set one. |
| `ShareLink.Publisher.Verified` | Whether LayerV has verified that owner. `false` for every publisher today. |

Read these fields with three rules in mind:

- **Every publisher is unverified today.** No verification mechanism exists
  yet, so `Verified` is always `false`. It also fails closed: a service that
  predates the fields, a missing `publisher` object, and a missing or null
  `verified` flag all decode to the zero `qurl.Publisher` — no name,
  unverified. Only an explicit `true` from the service reports `true`.
- **It is not part of CRID verification.** Publisher metadata is asserted by
  the service and rides beside the CRID, not inside it. `VerifyCRID`,
  `VerifyLinkForCRID`, `VerifyPortalLink`, and `EnterPortalForCRID` bind the
  resource key and the signed link — nothing else. A CRID or link that verifies
  says nothing about the publisher or the creation date.
- **The name is untrusted text.** It is self-declared: whoever owns the
  resource picked it. Display it quoted with control and other non-printing
  characters escaped — `%q` and `strconv.Quote` both do this — and never
  interpolate it raw into a terminal, a log line, or markup. Always show the
  verification status next to it, and make "unverified" obvious: a
  self-declared name must never read as a confirmed identity.

The owner reads and changes its own profile with `Publisher` and
`SetPublisherName`:

```go
publisher, err := client.Publisher(ctx)
if err != nil {
	return err
}
fmt.Printf("%q verified=%t\n", publisher.Name, publisher.Verified)

// Set the name; pass "" to remove it.
if _, err := client.SetPublisherName(ctx, "Acme Docs"); err != nil {
	return err
}
```

`Publisher` needs the `qurl:read` scope and `SetPublisherName` needs
`qurl:write`; a registered agent's device credential can call both. Setting a
name does not verify the publisher, and nothing in the request can. The service
decides which names are acceptable: a name it refuses fails with
`qurl.ErrInvalidPublisherName`, with the reason on the underlying
`*qurl.APIError`.

## Errors

```go
share, err := client.ShareResource(ctx, resourceCRID, nil)
if err == nil {
	err = share.VerifyCRID(resourceKeyDER)
}

switch {
case err == nil:
	// Shared, and the response is bound to the held key.
case errors.Is(err, qurl.ErrTemporaryAccessLinksDisabled):
	// The LayerV API answered 503: the environment is not currently
	// serving temporary access links. Service posture, not a bad request —
	// callers that treat sharing as optional can fall back here.
	return err
case errors.Is(err, qurl.ErrNoCRID):
	// A manually constructed ShareLink has no CRID.
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
| `qurl.ErrNoCRID` | The mint/share response or manually constructed link has no CRID. Fails closed. |
| `qurl.ErrCRIDMismatch` | The mint/share response changed the requested CRID, or the supplied key does not derive the held CRID. Do not use the returned link or mismatched key. |
| `qurl.ErrPortalRevoked` | `RevokePortal` found the qURL no longer active: this link was already revoked, so a repeat revoke had nothing to do. The underlying `*qurl.APIError` stays matchable. |
| `qurl.ErrInvalidPublisherName` | `SetPublisherName` was given a name that is not valid UTF-8 or is far too long (rejected before any request), or the service answered 400 because the name breaks its naming rules. A service rejection keeps its `*qurl.APIError`. |

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
security. A CRID is a commitment, never a network address: routing labels and
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
against `share.CRID`, wrapped in the client's sentinels. Apply `KeyMatches`
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
c, err := crid.Parse(share.CRID)
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
