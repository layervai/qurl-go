# Protect a Private Service with qURL

Use LayerV qURL Platform to make a private service reachable only through signed,
expiring qURL links. LayerV hosts the platform; your application uses this SDK to
issue and open links with LayerV-provided config.

## 1. Enable the Service in LayerV

In LayerV, register the private service you want agents or clients to reach.
LayerV returns two sets of Go-facing config:

- **Issuer config**: values the resource owner uses with `CreatePortal`.
- **Opener config**: issuer keys and allowed qURL platform access endpoints for
  clients that call `EnterPortal`.

Some SDK field names are compatibility names. Treat values such as
`CellPublicKey` and `RelayURL` as opaque LayerV config values that your app
passes to the SDK.

## 2. Issue a Link

The resource owner signs a short-lived link with `CreatePortal`:

```go
link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
	CellPublicKey:     resource.AccessPublicKey,
	RelayURL:          resource.AccessURL,
	ResourcePublicKey: resource.ResourceIdentity,
	JTI:               "ticket_01",
	IssuedAt:          now,
	NotBefore:         now,
	Expiry:            now + 300,
})
if err != nil {
	return err
}
```

Use a KMS-backed `qurl.Signer` for production issuer keys. `LocalSigner` is
handy for demos and tests.

## 3. Open a Link

The client installs opener config once, then opens any qURL link with one call:

```go
qurl.SetDefaultProvider(provider)

handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}

resp, err := http.Get(handle.RedirectURL)
```

`EnterPortal` verifies the link before asking the qURL platform for access. If
the opener has no provider, it fails closed with `qurl.ErrNotConfigured`.

## 4. Handle Errors

Use `errors.Is` and `errors.As`:

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(handle.RedirectURL)
case errors.Is(err, qurl.ErrSignature), errors.Is(err, qurl.ErrUnknownKID):
	reject()
case errors.Is(err, qurl.ErrNotConfigured):
	fixConfig()
default:
	retryOrReport(err)
}
```

## Next

- [Issue links](issuing-links.md)
- [Open links](opening-links.md)
