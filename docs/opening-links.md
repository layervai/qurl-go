# Open qURL Links

Most recipients do not need this SDK. They open the qURL link directly.

Opening a portal does not require LayerV credentials or issuer setup.

## Link Transport

Full qURL links use the share-safe `qv2t1` fragment transport. It splits each
encoded qv2 field into deterministic chunks no longer than 240 characters, so
messaging clients can recognize the entire capability as one link:

```text
#qv2t1.<claims-count>.<secret-count>.<signature-count>.<claims-chunks...>.<secret-chunks...>.<signature-chunks...>
```

The SDK reconstructs the exact signed qv2 bytes before verification; it never
decodes and reserializes claims. The fragment still carries the private
credential and is not included in HTTP requests to the link origin. Full links
using the pre-release `#qv2.<claims>.<secret>.<signature>` transport are rejected.

Use `qurl.IsCredentialLink(link)` only when deciding whether a URL must go
through the qURL opener instead of a plain HTTP fetch. It intentionally returns
true for malformed links that declare `qv2t1`, so they fail closed in
`VerifyLink` or `EnterPortal` rather than falling through to an unsafe fetch.

## Programmatic Opening

Use this SDK only when your Go service or agent needs to open received qURL links
in code. Call `EnterPortal` anywhere you receive a link:

```go
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}

req, err := http.NewRequestWithContext(ctx, http.MethodGet, handle.ResourceURL, nil)
if err != nil {
	return err
}
if err := handle.AuthorizeContentRequest(req); err != nil {
	return err
}
client := &http.Client{
	// Re-authorize same-origin redirects, refuse every other origin, and keep
	// the standard 10-request redirect limit.
	CheckRedirect: handle.CheckContentRedirect,
}
resp, err := client.Do(req)
```

`AuthorizeContentRequest` adds the short-lived application-session cookie only
to the exact granted HTTPS origin. Call it again from `CheckRedirect` so it can
approve a same-origin redirect and refuse a different origin. Use a client
without a cookie jar, or ensure its jar does not append the reserved
`qurl_vsession` cookie after this method runs.

Opener trust config is not an issuer credential. It cannot protect URLs or
create portals; it only tells the SDK which LayerV-issued qURL links and
platform access endpoints this process should trust. With no provider installed
— the common case — `EnterPortal` resolves that config from the JSON deployment
file named by `QURL_DEPLOYMENT`, falling back to the deployment embedded in the
build. Production issuer keys and native cell endpoints are embedded, so
production needs no deployment file. Set `QURL_DEPLOYMENT` for sandbox or a
custom deployment.

Before any transport work, every opening path derives the X25519 public key
from the fragment private key with the standard clamped X25519 basepoint
operation. It requires that key to equal the public key in the signed qURL
claims. Every qURL minter must create that public claim from the matching
fragment private key. A mismatch fails closed with
`ErrQurlUserKeyMismatch`; there is no compatibility fallback.

After the open returns, the SDK wipes the decoded fragment private-key buffer
that it owns. Go's cryptography APIs can make runtime-managed working copies
and do not provide a supported operation to erase those copies explicitly.

## Long-Lived Service Opener

Use `PortalOpener` when a service repeatedly calls one protected target. It is
native-UDP-only and is bound to the exact target URL in the first authenticated
NHP ACK. `Start` opens the visitor session and starts proactive renewal. `Do`
uses only the cached handle. It does not open a portal, read deployment data,
resolve a qURL, mint, list, retry, or sleep on the request path.

```go
opener, err := qurl.NewPortalOpener(link)
if err != nil {
	return err
}
if err := opener.Start(ctx); err != nil {
	return err
}
defer opener.Close()

resp, err := opener.Do(ctx, func(target *url.URL) (*http.Request, error) {
	// Sign the method, target authority, and exact target path here. target is
	// the authenticated ACK URL, not caller input.
	return http.NewRequest(http.MethodPost, target.String(), body)
}, qurl.RejectPortalRedirects())
if err != nil {
	return err
}
defer resp.Body.Close()
```

Each native NHP open has a 15-second default deadline, including the open made
by the synchronous first `Start`. Use `WithPortalOpenerOpenTimeout` to select a
positive deadline of at most 60 seconds for slower private networks. When
`Start` must resolve provider or deployment config first, that separate step is
bounded by the caller context and the provider's I/O deadline. An SDK open
deadline returns `ErrPortalOpenTimeout`; a shorter caller deadline returns only
the caller's context error and does not record a platform failure.

The resolved configuration — embedded production defaults, `QURL_DEPLOYMENT`,
or an installed provider — must include the link's issuer and cell. A missing
cell returns `ErrPortalNativeOnly` or `ErrCellNotInCatalog`; the opener never
falls back to the HTTPS relay. A renewal that authenticates a different target
does not replace the active handle. `Health` reports
`LastFailureClass == PortalOpenerFailureTargetChanged`. A later explicit
recovery `Start` returns `ErrPortalTargetChanged` if the target is still wrong.

By default, `Do` follows only same-origin redirects and reauthorizes each one.
An off-origin redirect fails with `ErrPortalRedirect` before the redirected
request is sent.
Use `RejectPortalRedirects` for signed POST or PATCH operations because a
redirect can change the method or invalidate a signature. The first request URL
and wire Host are always the exact authenticated target. The builder cannot add
a path, query, or alternate authority.

Renewal starts before expiry and runs in one background goroutine. Each attempt
has the configured I/O timeout. Failed attempts use capped backoff for the full
remaining lifetime of the old handle. The retry window is time-bounded: it
stops at the reported expiry and does not create a permanent background retry
loop. After each successful open, another renewal cannot start for five seconds.
If less time remains, the opener stops at expiry instead of reopening
continuously. After that, `Do` returns `ErrPortalOpenerNotReady` immediately.
`Health` returns readiness, UTC times, a failure count, and a secret-free
failure class.
It does not return the qURL, target, session ID, cookie, or raw transport error.
Lifecycle code can call `Start` again after expiry to run one
single-flight recovery open. This explicit recovery stays off the request path,
because concurrent callers share the first caller's context and cancellation,
and it must authenticate the same target as the first open. A caller-canceled
first `Start` leaves the opener in `new`; a platform failure leaves it
`degraded`. `Close` cancels renewal, active request and redirect legs, and
response-body reads, then releases the SDK's references to the qURL and session
material. It cannot retract bytes that a transport already sent, but no later
redirect leg can start. A body read interrupted by `Close` returns its native
request-context error, typically `context.Canceled`, not
`ErrPortalOpenerClosed`. Callers must close every response body. Until it is
closed, the body retains the request cancellation hook that lets `Close` abort
body reads. If shutdown needs a strict guarantee that no new protected request
can leave after the shutdown point, stop and drain request handlers before
calling `Close`.
The opener pins the trust and cell config resolved by `Start` for all background
renewals. `Close` also cancels an in-progress provider or deployment resolution.
Call `Start` after a bounded cycle ends if deployment trust or cell routing
changed.

## Retry a Visit

Each ordinary `EnterPortal` or `EnterPortalWith` call starts an independent
visit. For retries after a lost reply or later renewal, build explicit trust
and transport config and retain one `PortalSession`. Obtain the issuer's public
DER key, its key ID, and the relay host from your trusted deployment config:

```go
trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{
	issuerKID: issuerPublicKeyDER,
})
if err != nil {
	return err
}
visitCfg := qurl.Config{
	TrustStore:     trust,
	RelayAllowlist: qurl.NewRelayAllowlist([]string{relayHost}),
	PortalSession:  &qurl.PortalSession{},
}
handle, err := qurl.EnterPortalWith(ctx, link, visitCfg)
if err != nil {
	return err
}
fmt.Println(handle.ResourceURL)
// A later retry of this visit uses the same visitCfg and link.
```

For an already configured explicit opener, copy its `Config` per visit and set
a fresh `PortalSession` on the copy. The default provider/deployment resolution
belongs to `EnterPortal`; `EnterPortalWith` requires these inputs explicitly.
This example uses HTTPS relay only. For native UDP, supply `Cells` instead of
`RelayAllowlist`, as described below. Retaining a session adds no HTTP request
on either transport.

The zero-value session creates a private random capability only after the link
passes verification. It binds to that link and stays in memory. Reuse the same
pointer for retries; use a separate session for each link and each visitor. The
SDK rejects a session reused for another verified link before it sends a
request. Nil `Config.PortalSession` starts a new visitor on every call. When
server enforcement is enabled, a single-use link cannot give that new visitor
the first visitor's live session through the verifier.
`EnterPortal` always starts an independent visit. Its default-provider path has
no retained session. Under server enforcement, a second open of a consumed
single-use link is denied. Use the explicit config above when lost-reply
recovery is required. No config or session is stored in a process-wide cache.

The capability travels in the encrypted qURL ASP payload as
`usrData.qurl_session_secret`: canonical unpadded base64url for 32 random bytes.
NHP hashes the decoded bytes as a separate renewal proof. It does not bind or
replace the application-session cookie, and does not grant NHP renewal from a
new IP without the existing session's required identity. This is a qURL ASP
extension, not a new NHP header field. It follows the ASP verification-data
model in the CSA NHP specification, Appendix 2, NHP-KNK (pages 48–49), and its
separate application token/cookie guidance for NAT (page 50). NHP packet types,
Noise authentication, request counters, numeric session IDs, and overload
cookies retain their existing meanings. The capability never enters the shared
link or the application-session cookie. The `qv2t1` link structure, inner qv2
fragment, signed claims, signature, CRID, and query parameters do not change.

After server enforcement is enabled, an old IP-bound single-use session that
was opened without a renewal proof cannot renew. Open a fresh link with a
current client. A new client cannot recover a previous visitor's session from
the shared link alone.

Older servers can ignore the additional ASP field. A successful open against
such a server does not confirm renewal-proof enforcement; deploy the companion
service and NHP verifier changes before relying on that guarantee.

## Pinning the Opener Trust Config

To pin the trust config in code instead, install a `StaticProvider` during
startup. What you hand `NewStaticProvider` decides the transport every open
uses:

- **Cells, with or without an allowlist** — native UDP only. The allowlist is
  ignored. A cell in the catalog is knocked directly over UDP; a verified link naming a cell outside the catalog fails
  with `qurl.ErrCellNotInCatalog` rather than quietly downgrading to the HTTPS
  relay.
- **Allowlist, no cells** — every open uses the HTTPS relay.

The strict pinned form supplies issuer keys and cells, and no allowlist:

```go
func installPinnedOpener(issuerKID string, issuerPublicKeyDER []byte, cells []qurl.CellEntry) error {
	trustStore, err := qurl.NewTrustStoreFromDER(map[string][]byte{
		issuerKID: issuerPublicKeyDER,
	})
	if err != nil {
		return err
	}

	// A nil allowlist declares native UDP the only transport this opener uses.
	provider, err := qurl.NewStaticProvider(trustStore, nil, cells)
	if err != nil {
		return err
	}

	qurl.SetDefaultProvider(provider)
	return nil
}
```

Each `CellEntry` mirrors one row of your deployment catalog: the cell's label,
its LayerV-owned DNS name, the standard NHP UDP port, and its 32-byte X25519
server key in base64:

```go
cells := []qurl.CellEntry{{
	CellID:             "cell-1",
	Host:               cellHost, // from your deployment catalog
	Port:               443,
	ServerPublicKeyB64: cellServerKeyB64,
}}
```

To configure an explicit relay-only provider, supply an allowlist and no cells:

```go
provider, err := qurl.NewStaticProvider(
	trustStore,
	qurl.NewRelayAllowlist(platformHosts),
	nil,
)
```

Production defaults already supply these values. For sandbox or a custom
deployment, obtain the issuer key id, issuer public key, cell catalog entries,
and allowed platform hosts from that deployment operator.

## Open by CRID

`EnterPortal` opens a link. A program that holds only a CRID has no link, and a
link is what turns the identifier into access. `OpenCRID` covers that case in
one call, and it needs no LayerV credentials:

```go
handle, err := qurl.OpenCRID(ctx, resourceCRID)
if err != nil {
	return err
}
// handle is the *ResourceHandle EnterPortal returns. Authorize the content
// request with it exactly as shown under Programmatic Opening.
```

It runs two steps:

1. **Request a link.** The SDK sends a request that names the CRID. The server
   answers with a short-lived qURL link, or with the reason there is none. This
   step opens nothing.
2. **Open the link.** The SDK opens the link bound to the CRID, exactly as
   `EnterPortalForCRID` does.

Whether a CRID can be opened this way is the server's decision. A client that
may not open it gets `ErrCRIDLinkNotFound`, the same answer as for a CRID that
does not exist.

### What is checked

The link in step 1 arrives from the network, so the SDK uses it only after
checking it against things it already holds. The checks run in this order, and
the first one that fails ends the call with a `*qurl.CRIDLinkRejectedError`
whose `Class` names it:

| `Class` | Check |
| --- | --- |
| `missing_redirect` | The reply carries a link, as a non-empty string |
| `origin` | The link is on the deployment's link origin: same scheme, host, and port, and no userinfo |
| `path_or_query` | The link has no path other than `/` and no query |
| `transport` | The link's fragment is the `qv2t1` transport |
| `issuer_signature` | The link's signed content parses and verifies under the trust store |
| `crid_mismatch` | The signed resource key derives the CRID that was requested |
| `info_crid_mismatch` | If the reply's metadata names a CRID, it is the one that was requested |

The origin check compares text: the link must begin with the configured link
origin exactly as it is written. Another spelling of the same origin, such as
an upper-case host or an explicit default port, is rejected as `origin`.

A rejected link is not opened and is not returned, and nothing else from that
reply is either. The error text names the failed check and never contains the
link. Where a check corresponds to an existing sentinel, that sentinel matches
too: `ErrCRIDMismatch` for the two CRID classes, `ErrFragment` for
`transport`, and `ErrSignature` or `ErrUnknownKID` for `issuer_signature`.
`ErrUnknownKID` usually means the configured trust does not belong to the
deployment that issued the link.

Before any of this, the CRID itself must pass the local validation gate and
carry a version this SDK can verify a link against. A CRID that does not is
refused before any configuration is resolved or request sent, with
`ErrInvalidResourceRequest`.

### Show the publisher before opening

`OpenCRID` returns only the handle. To tell a user who published a resource
before opening it, take the two steps apart:

```go
issued, err := qurl.RequestCRIDLink(ctx, resourceCRID)
if err != nil {
	return err
}

status := "UNVERIFIED (self-declared name)"
if issued.Publisher.Verified {
	status = "verified"
}
fmt.Printf("Publisher: %q - %s\n", issued.Publisher.Name, status)
if issued.ResourceCreatedAt != nil {
	fmt.Println("Created:", issued.ResourceCreatedAt.Format(time.DateOnly))
}

handle, err := qurl.EnterPortalForCRID(ctx, issued.Link, resourceCRID)
if err != nil {
	return err
}
```

| Field | Meaning |
| --- | --- |
| `CRIDLink.Link` | The access link. It is a credential: use it, do not log it. Printing a `CRIDLink` with `%v`, `%+v`, `%#v`, or `%s` redacts it. Encoding one as JSON does not, and some structured loggers encode what they are given as JSON |
| `CRIDLink.Publisher` | The publisher's self-declared `Name` and its `Verified` flag. `false` for every publisher today |
| `CRIDLink.ResourceCreatedAt` | When the resource was created. `nil` when the server did not report a time the SDK can read |
| `CRIDLink.ExpiresAt` | When the server says the link stops working. Zero when not reported. The server enforces the expiry inside the signed link |
| `CRIDLink.QURLID` | Identifies this one issued link. Empty when not reported |

The fields have the names and the absence rules of the same fields on
`ShareLink`, so `ResourceCreatedAt` is a pointer and `ExpiresAt` is not.

Everything except `Link` is **display-only and unverified**. It is reported by
the server next to the link and is covered by neither the link's signature nor
the CRID: a link that verifies says nothing about the publisher or the dates.
The three rules under
[Publisher metadata](share-and-crid.md#publisher-metadata) apply unchanged —
every publisher is unverified, the metadata is not part of CRID verification,
and the name is untrusted text to quote with `%q`. Malformed metadata never
fails the call; what the SDK cannot use is simply absent. A text value longer
than 128 Unicode code points is dropped, not shortened.

### Transport

In this version the link request always goes through the deployment's HTTPS
relay, under a key minted for that one request, also when the configuration
opens links over native UDP. The relay is not trusted with the answer: the
reply is authenticated to the cell's key, so a relay can delay or drop a
request but cannot forge a link. An answer that does not authenticate is an
error and is never read. The open in step 2 uses native UDP to the
deployment's cell.

A busy server answers with a cookie instead of a link. The SDK reports that as
`ErrServerOverloaded` and does not answer the cookie; try again later.

### Configuration

The request needs three facts: the relay to send through, the server key to
seal the request to, and the origin issued links are on, which the answer is
checked against. An ordinary open reads the relay and the key from the link's
signed claims; a client that holds only a CRID has no claims yet. A deployment
supplies the relay and the origin in one optional object, `crid_link`. The key
is the key of the deployment's one cell:

```json
{
  "issuers": [
    { "kid": "issuer-key-id", "spki_der_b64": "BASE64_P256_SPKI_DER" }
  ],
  "cells": [
    {
      "cell_id": "cell0",
      "host": "cell0.example.com",
      "port": 443,
      "server_public_key_b64": "BASE64_X25519_CELL_KEY"
    }
  ],
  "relay_allowlist": ["relay.example.com"],
  "crid_link": {
    "relay_url": "https://relay.example.com",
    "link_origin": "https://links.example.com"
  }
}
```

Every value above is a placeholder.

- `relay_url` must be HTTPS and its host must be in `relay_allowlist`. With
  `cells` present the allowlist gates only this request; links still open over
  native UDP and never fall back to the relay.
- `link_origin` must be a bare HTTPS origin in its one canonical spelling:
  `https://`, a lowercase host, a port only when it is not 443, and no path,
  query, fragment, userinfo, or trailing slash. The SDK compares it with an
  issued link as text.
- `cells` must name exactly one cell. With none or several, the request is
  refused: the SDK does not choose a cell for a CRID.

A deployment that cannot carry the request fails with
`ErrCRIDLinkNotConfigured`, which matches `ErrNotConfigured`, before anything
is sent. There are two cases, and the error says which:

| The deployment | `ErrCRIDLinkNotConfigured` | `ErrCRIDLinkMisconfigured` |
| --- | --- | --- |
| names no `crid_link` | matches | does not match |
| names a `crid_link` that cannot be used | matches | matches |

The first case means this deployment does not offer the request. The second is
a fault to report: a relay that is not on the allowlist, an origin with a
trailing slash, a missing value, or `cells` that does not name exactly one
usable cell. `ErrCRIDLinkMisconfigured` matches both sentinels, so test for it
first. A wrong value inside `crid_link` affects only this request; links keep
opening.

**The deployment embedded in this release names no `crid_link`.** Against it,
`OpenCRID` and `RequestCRIDLink` return `ErrCRIDLinkNotConfigured` until
`QURL_DEPLOYMENT` names a file that has one.

**Deployment decoding is strict.** A release that predates `crid_link` rejects
the whole file as carrying an unknown field, and then opens nothing. Add
`crid_link` only to deployment files read by releases that know it. The same
strictness applies inside the object: a misspelled or unknown member, or a
member of the wrong type, makes the file malformed, and a malformed file opens
nothing either. Its error is the one for a file that does not decode, and it
matches neither of the two sentinels above.

An installed `Provider` supplies trust and transport, not the CRID link
endpoint. With one installed, pass the endpoint explicitly:

```go
cfg := qurl.Config{
	TrustStore:     trustStore,
	Cells:          cells, // exactly one cell
	RelayAllowlist: qurl.NewRelayAllowlist([]string{relayHost}),
	CRIDLink: &qurl.CRIDLinkConfig{
		RelayURL:   "https://" + relayHost,
		LinkOrigin: linkOrigin,
		UserAgent:  "example-tool/1.2", // optional; names your program to the server
	},
}
handle, err := qurl.OpenCRIDWith(ctx, resourceCRID, cfg)
```

`UserAgent` is optional and travels inside the encrypted request. `OpenCRID`
and `RequestCRIDLink` send none. Two rules decide what is sent, in this order:

1. A value that holds a control character (U+0000 to U+001F, or U+007F),
   U+2028 or U+2029 anywhere is left out. The request is still made, without a
   user agent.
2. Any other value longer than 256 bytes of UTF-8 is cut at a character
   boundary.

The first rule looks at the whole value, so a control character past the 256th
byte leaves the user agent out too.

Each `OpenCRID` call requests a fresh link and starts an independent visit, so
a `Config.PortalSession` cannot carry a visit across two `OpenCRIDWith` calls.
To retry one visit, request the link once with `RequestCRIDLinkWith` and retry
`EnterPortalWith` with that link and the retained session, as described under
[Retry a Visit](#retry-a-visit).

### Ask whether the request is offered

`CheckCRIDLinkConfig` answers that question before there is a CRID to open:

```go
err := qurl.CheckCRIDLinkConfig()
switch {
case err == nil:
	// A request can be sent. Whether a link is issued is the server's answer.
case errors.Is(err, qurl.ErrCRIDLinkMisconfigured):
	// The deployment names an endpoint that cannot be used.
	report(err)
case errors.Is(err, qurl.ErrCRIDLinkNotConfigured):
	// The deployment names no endpoint. Opening by CRID is not offered here.
default:
	// The deployment itself could not be read.
	report(err)
}
```

It reads the deployment and checks it. It sends nothing and creates nothing.
The error is the one `RequestCRIDLink` returns for the same deployment before
it sends anything.

Use it when the answer must not depend on the CRID. `RequestCRIDLink` checks
the CRID first, so for a CRID it cannot request it returns
`ErrInvalidResourceRequest` and says nothing about the deployment.

With a `Provider` installed the answer is always `ErrCRIDLinkNotConfigured`,
and the `Provider` is not asked. `CheckCRIDLinkConfigWith` checks an explicit
`Config`.

### Errors from an open by CRID

```go
handle, err := qurl.OpenCRID(ctx, resourceCRID)
var rejected *qurl.CRIDLinkRejectedError
switch {
case err == nil:
	use(handle.ResourceURL)
case errors.Is(err, qurl.ErrCRIDLinkNotFound):
	// Unknown CRID, or this client may not open it. Do not retry.
	reject()
case errors.Is(err, qurl.ErrCRIDResourceOffline):
	// The publisher is offline. It may come back.
	retryLater()
case errors.Is(err, qurl.ErrCRIDLinkUnavailable),
	errors.Is(err, qurl.ErrCRIDLinkRateLimited),
	errors.Is(err, qurl.ErrServerOverloaded):
	retryLater()
case errors.Is(err, qurl.ErrCRIDResourceClosed):
	reject()
case errors.As(err, &rejected):
	// The server issued a link that failed a check. rejected.Class says which.
	reject()
case errors.Is(err, qurl.ErrCRIDLinkMisconfigured):
	// Tested before ErrCRIDLinkNotConfigured, which it also matches.
	reportUnusableCRIDLinkEndpoint(err)
case errors.Is(err, qurl.ErrCRIDLinkNotConfigured):
	reportMissingCRIDLinkEndpoint()
case errors.Is(err, qurl.ErrInvalidResourceRequest):
	// Not a CRID this SDK can request a link for. Nothing was sent.
	reject()
default:
	report(err)
}
```

The full table is in the
[README](../README.md#error-handling). Every refusal in it is also a
`*qurl.ServerDenyError` carrying the server's code, so code that already
handles an authenticated deny from `EnterPortal` handles these without change.

The six refusal codes are a closed set. When the link request is answered with
any other decimal code, the error is a `*qurl.ServerDenyError` that matches
none of the six sentinels. Treat it as a server error:

- It is not `ErrCRIDLinkUnavailable`. Only the server's own "unavailable"
  answer is.
- It does not say that the client is out of date. A server that does not know
  this request cannot answer with one of the six codes, so it answers with a
  general one.
- `ErrCode` carries the code for a caller that wants it.

`RequestCRIDLink` returns such an error only for the link request. From
`OpenCRID` it can also come from the open that follows.

## Errors

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(handle.ResourceURL)
case errors.Is(err, qurl.ErrNotConfigured):
	reportMissingOpenerTrustConfig()
case errors.Is(err, qurl.ErrCellNotInCatalog):
	// The verified link names a cell outside the configured native catalog.
	reject()
case errors.Is(err, qurl.ErrSignature), errors.Is(err, qurl.ErrUnknownKID):
	reject()
default:
	var deny *qurl.ServerDenyError
	if errors.As(err, &deny) {
		reject()
		return
	}
	report(err)
}
```

Handle request-authorization errors at the protected-content request, not at
`EnterPortal`:

```go
if err := handle.AuthorizeContentRequest(req); err != nil {
	if errors.Is(err, qurl.ErrInvalidContentRequest) {
		reject()
	}
	return err
}
resp, err := client.Do(req)
if errors.Is(err, qurl.ErrInvalidContentRequest) {
	// CheckContentRedirect refused a cross-origin redirect.
	reject()
}
if errors.Is(err, qurl.ErrTooManyContentRedirects) {
	// CheckContentRedirect stopped after the standard 10-request limit.
	reject()
}
```

`errors.Is` also finds both redirect sentinels when `http.Client` wraps a
redirect-policy error in `*url.Error`.

`EnterPortal` fails closed when the resolved deployment carries no issuer keys
— a build that ships an empty deployment and has no `QURL_DEPLOYMENT` override
or installed provider, and equally a `QURL_DEPLOYMENT` file whose `issuers`
list is empty, returns `qurl.ErrNoDeployment`, which matches
`errors.Is(err, qurl.ErrNotConfigured)` — and when the link cannot be verified.

### Updating production defaults

This release includes production cell0 at `cell0.nhp.layerv.ai:443`. Default
opens use native UDP. Before a new cell or cell identity serves links, release
its catalog entry and update consumers. Older builds reject an unknown cell.
An operator-supplied `QURL_DEPLOYMENT` file can update the catalog before a
consumer upgrade. Networks that block outbound UDP need an explicit relay-only
configuration; the native catalog does not enable relay fallback.

Before changing the issuer signing key, publish the incoming public key alongside
the outgoing key and update consumers. Keep both keys through the overlap period;
remove the outgoing key only after its links have expired and consumers have
updated. Older builds reject an unknown issuer with `ErrUnknownKID`. A trusted
`QURL_DEPLOYMENT` file can supply the updated issuer set while a build is upgraded.

An override replaces the full embedded deployment; it does not merge with it.
Include every required issuer and cell entry, plus the Hub trust root when
enrollment uses the deployment Hub. A file containing only the new key or cell
does not retain any of the other embedded defaults.

The initial production values were verified against the production deployment
on 2026-09-15.
