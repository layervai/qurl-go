# Protect a Private Service with qURL

Use the LayerV qURL Platform to keep a private service off public inventory and
make it reachable only through short-lived portal links. The app that protects
URLs and creates portals has LayerV credentials; the person or agent opening a
portal link does not. LayerV turns the private URL into an invisible,
authenticated resource and turns each portal into just-in-time access to that
resource.

## 1. Connect to LayerV

Before this service creates portals, run the LayerV setup flow once for this
service identity. The setup flow consumes the temporary bootstrap key, registers
the service with your LayerV account, and stores the runtime issuer credential in
protected state for the process. After that, application code starts with:

```go
client, err := qurl.OpenClient()
if err != nil {
	return err
}
```

That is the normal application code. You do not paste bootstrap keys into your
app, read `LAYERV_API_KEY`, or ask portal recipients to hold credentials. LayerV
setup turns the one-time key into runtime issuer state; `OpenClient` uses that
state.

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
opener policy once during startup, then call `EnterPortal`:

```go
opened, err := qurl.EnterPortal(ctx, portal.Link)
if err != nil {
	return err
}

resp, err := http.Get(opened.ResourceURL)
```

`EnterPortal` verifies the link before asking qURL for access. If no opener
provider is installed, it fails closed with `qurl.ErrNotConfigured`. See
[Open links](opening-links.md) for a complete pinned-provider setup example.

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
