# Protect a Private Service with qURL

Use the LayerV qURL Platform to make a private service reachable only through
short-lived qURL links. The app that protects URLs and creates portals has LayerV
credentials; the person or agent opening a portal link does not. LayerV handles
the platform work.

## 1. Connect to LayerV

First, connect the service that creates portals to your LayerV account. This
happens outside the Go code during setup or deploy. After that, application code
starts with:

```go
client, err := qurl.OpenClient()
if err != nil {
	return err
}
```

That is the normal application code. You do not paste keys into your app;
LayerV setup handles the connection.

## 2. Protect the URL

A resource is the private URL LayerV protects:

```go
resource, err := client.ProtectURL(ctx, "https://internal.example.com/dashboard")
if err != nil {
	return err
}
```

`ProtectURL` returns the existing resource when the same target URL is
already registered for your account.

## 3. Create a Portal

A portal is the short-lived link you share:

```go
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
if err != nil {
	return err
}

fmt.Println(portal.Link)
```

You can create many portals for one resource, each with its own lifetime, label,
and session policy.

## 4. Open a Link Programmatically

Most users can open the qURL link directly and need no keypair state. If you are
building an agent or service that opens received qURL links in code, install
opener config once and call `EnterPortal`:

```go
qurl.SetDefaultProvider(provider)

handle, err := qurl.EnterPortal(ctx, portal.Link)
if err != nil {
	return err
}

resp, err := http.Get(handle.RedirectURL)
```

`EnterPortal` verifies the link before asking qURL for access. If no opener
provider is installed, it fails closed with `qurl.ErrNotConfigured`.

## Errors

Use `errors.Is` and `errors.As`:

```go
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
switch {
case err == nil:
	share(portal.Link)
case errors.Is(err, qurl.ErrInvalidPortalRequest):
	fixInput()
default:
	var apiErr *qurl.APIError
	if errors.As(err, &apiErr) {
		reportAPIError(apiErr)
		return
	}
	return err
}
```

## Next

- [Issue links](issuing-links.md)
- [Open links](opening-links.md)
