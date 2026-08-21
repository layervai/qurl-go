# Protect a Private Service with qURL

Use the LayerV qURL Platform to keep a private service off public inventory and
make it reachable only through short-lived portal links. The app that protects
URLs and creates portals has LayerV credentials; the person or agent opening a
portal link does not. LayerV turns the private URL into an invisible,
authenticated resource and turns each portal into just-in-time access to that
resource.

## 1. Connect to LayerV

Only this issuing service needs a credential; the person or agent opening a
portal link never holds one. Create an API key with the `qurl:write` scope in
the [LayerV dashboard](https://layerv.ai/qurl/dashboard/keys), hand it to the
process the way you deploy any secret, and start with:

```go
client, err := qurl.OpenClient()
if err != nil {
	return err
}
```

`OpenClient` resolves the credential most specific first: an explicit
`qurl.WithIssuerStatePath(...)` option, then `QURL_API_KEY` (the key itself,
for containers and CI), then `QURL_API_KEY_FILE` (a path, for mounted secrets
that should stay on disk), then `~/.config/qurl/token` — what the qURL
Connector installer already wrote — then the machine-wide
`/var/lib/layerv/qurl/issuer-state.json`. A key file holds either the raw
bearer token or a JSON envelope with a `bearer_token` or `authorization`
field.

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
and session controls.

## 4. Open a Link Programmatically

Most users can open the qURL link directly and need no keypair state. If you are
building an agent or service that opens received qURL links in code, call
`EnterPortal`:

```go
handle, err := qurl.EnterPortal(ctx, portal.Link)
if err != nil {
	return err
}

resp, err := httpClient.Get(handle.ResourceURL) // httpClient is your own *http.Client
if err != nil {
	return err
}
defer resp.Body.Close()
```

`handle.OpenSeconds` reports how long access stays open, as reported by qURL
(0 when not provided). `EnterPortal` verifies the link before asking qURL for
access, and it fails closed when no issuer keys are configured
(`qurl.ErrNoDeployment`, which matches `errors.Is(err, qurl.ErrNotConfigured)`)
rather than open a link it cannot verify. The trust config comes from the
deployment embedded in the build, a JSON file named by `QURL_DEPLOYMENT`, or a
provider installed with `qurl.SetDefaultProvider`; see
[Open links](opening-links.md) for a complete pinned-provider setup example.

## 5. Revoke a Portal

Portals expire on their own. To kill one sooner, revoke it with the ids the
create call returned:

```go
if err := client.RevokePortal(ctx, portal.ResourceID, portal.QURLID); err != nil {
	return err
}
```

Revocation is immediate and not idempotent: revoking the same portal again
fails with `qurl.ErrPortalRevoked`, which a caller that only needs the link
dead can treat as settled. See
[Issue links](issuing-links.md#revoke-a-portal) for the details, including
the one link kind this cannot revoke.

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
