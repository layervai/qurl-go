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
build.

## Retry a Visit

Each ordinary `EnterPortal` or `EnterPortalWith` call starts an independent
visit. For an explicit opener config, retain one `PortalSession` when a caller
must retry the same visit after a lost reply or renew its access:

```go
cfg.PortalSession = &qurl.PortalSession{}
handle, err := qurl.EnterPortalWith(ctx, link, cfg)
// A later retry of this visit uses the same cfg and link.
```

The zero-value session creates a private random capability only after the link
passes verification. It binds to that link and stays in memory. Reuse the same
pointer for retries; use a separate session for each link and each visitor. The
SDK rejects a session reused for another verified link before it sends a
request. Nil `Config.PortalSession` starts a new visitor on every call. A
single-use link cannot give that new visitor the first visitor's live session.

The capability travels in the encrypted qURL ASP payload as
`usrData.qurl_session_secret`: canonical unpadded base64url for 32 random bytes.
NHP hashes the decoded bytes to identify the visitor. This is a qURL ASP
extension, not a new NHP header field. It follows the ASP verification-data
model in the CSA NHP specification, Appendix 2, NHP-KNK (pages 48–49), and its
separate application token/cookie guidance for NAT (page 50). NHP packet types,
Noise authentication, request counters, numeric session IDs, and overload
cookies retain their existing meanings. The capability never enters the shared
link or the application-session cookie. The `qv2t1` link structure, inner qv2
fragment, signed claims, signature, CRID, and query parameters do not change.

After server enforcement is enabled, an old single-use session that was opened
without this visitor binding cannot renew. Open a fresh link with a current
client. A new client cannot recover a previous visitor's session from the
shared link alone.

## Pinning the Opener Trust Config

To pin the trust config in code instead, install a `StaticProvider` during
startup. What you hand `NewStaticProvider` decides the transport every open
uses:

- **Cells, no allowlist** — native UDP only. A cell in the catalog is knocked
  directly over UDP; a verified link naming a cell outside the catalog fails
  with `qurl.ErrCellNotInCatalog` rather than quietly downgrading to the HTTPS
  relay.
- **Cells and an allowlist** — native UDP for cataloged cells, HTTPS relay
  fallback for any other cell, gated by the allowlist.
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

To keep the relay as a fallback for cells outside the catalog, pass an
allowlist as well:

```go
provider, err := qurl.NewStaticProvider(
	trustStore,
	qurl.NewRelayAllowlist(platformHosts),
	cells,
)
```

LayerV opener setup gives you the issuer key id, issuer public key, cell
catalog entries, and allowed platform hosts for the links this process is
allowed to open.

## Errors

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(handle.ResourceURL)
case errors.Is(err, qurl.ErrNotConfigured):
	reportMissingOpenerTrustConfig()
case errors.Is(err, qurl.ErrCellNotInCatalog):
	// Native-UDP-only opener; the verified link names a cell outside its catalog.
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
