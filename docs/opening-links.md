# Open qURL Links

Most recipients do not need this SDK. They open the qURL link directly.

Opening a portal does not require a LayerV credential, bootstrap key, local
keypair, or resource state.

## Programmatic Opening

Use this SDK only when your Go service or agent needs to open received qURL links
in code. Install the opener provider once at startup, then call `EnterPortal`:

```go
qurl.SetDefaultProvider(provider)

handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}

fmt.Println(handle.RedirectURL)
```

The provider is opener policy, not an issuer credential. It cannot protect URLs
or create portals.

## Errors

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case err == nil:
	use(handle.RedirectURL)
case errors.Is(err, qurl.ErrNotConfigured):
	installProvider()
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
