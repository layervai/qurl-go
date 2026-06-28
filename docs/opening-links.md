# Open qURL Links

`EnterPortal` is the client-side verb. It verifies a qURL link and asks the
LayerV qURL Platform for access, returning a `ResourceHandle` with the reachable
URL.

## Configure Once

Install opener config once at startup:

```go
qurl.SetDefaultProvider(provider)
```

The provider supplies issuer keys and allowed qURL platform access endpoints.
LayerV provides those values when your service is enabled for qURL.

For tests or manual configuration:

```go
trust, err := qurl.NewTrustStoreFromDER(issuerKeys)
if err != nil {
	return err
}
allow := qurl.NewRelayAllowlist(platformAccessHosts)

provider, err := qurl.NewStaticProvider(trust, allow)
if err != nil {
	return err
}
qurl.SetDefaultProvider(provider)
```

`NewRelayAllowlist` keeps its wire-format name, but in normal integrations the
entries are simply qURL platform access hosts from LayerV config.

## Open

```go
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}

fmt.Println(handle.RedirectURL)
```

`EnterPortal` fails closed when no provider is installed.

Use `EnterPortalWith` when tests or advanced clients need to pass config
explicitly:

```go
handle, err := qurl.EnterPortalWith(ctx, link, qurl.Config{
	TrustStore:      trust,
	RelayAllowlist:  allow,
	HTTPClient:      client,
})
```

## Errors

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(handle.RedirectURL)
case errors.Is(err, qurl.ErrNotConfigured):
	fixConfig()
case errors.Is(err, qurl.ErrSignature), errors.Is(err, qurl.ErrUnknownKID):
	reject()
case errors.Is(err, qurl.ErrServerOverloaded):
	retryLater()
default:
	var deny *qurl.ServerDenyError
	var network *qurl.RelayError
	switch {
	case errors.As(err, &deny):
		reject()
	case errors.As(err, &network):
		retryLater()
	default:
		report(err)
	}
}
```

`ErrRelayURL` means the link points at a qURL access endpoint that is not in the
opener config. Treat it as a rejected link.
