# Open qURL Links

Most recipients do not need this SDK. They open the qURL link directly.

Opening a portal does not require LayerV credentials or issuer setup.

## Programmatic Opening

Use this SDK only when your Go service or agent needs to open received qURL links
in code. Install opener trust config once at startup, then call `EnterPortal`
anywhere you receive a link:

```go
portal, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}

fmt.Println(portal.ResourceURL)
```

The opener trust config is not an issuer credential. It cannot protect URLs or
create portals; it only tells the SDK which LayerV-issued qURL links and
platform access endpoints this process should trust.

For pinned opener trust config, install a `StaticProvider` during startup:

```go
func installPinnedOpener(issuerKID string, issuerPublicKeyDER []byte, platformHosts []string) error {
	trustStore, err := qurl.NewTrustStoreFromDER(map[string][]byte{
		issuerKID: issuerPublicKeyDER,
	})
	if err != nil {
		return err
	}

	provider, err := qurl.NewStaticProvider(
		trustStore,
		qurl.NewRelayAllowlist(platformHosts),
	)
	if err != nil {
		return err
	}

	qurl.SetDefaultProvider(provider)
	return nil
}
```

LayerV opener setup gives you the issuer key id, issuer public key, and allowed
platform hosts for the links this process is allowed to open.

## Errors

```go
portal, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(portal.ResourceURL)
case errors.Is(err, qurl.ErrNotConfigured):
	reportMissingOpenerTrustConfig()
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

`EnterPortal` fails closed when no provider is installed or the link cannot be
verified.
