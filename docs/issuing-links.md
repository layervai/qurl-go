# Issue qURL Links

Issuing a qURL link is a two-step platform flow:

1. Protect the private URL.
2. Create a portal link for that resource.

There is nothing to copy from a separate setup page. The input is the URL you
want LayerV to protect.

Only the issuer needs credentials. A customer, user, or agent that only opens a
portal link does not need an API key, keypair, or local qURL state.

## Protect the URL

```go
client, err := qurl.OpenClient()
if err != nil {
	return err
}

resource, err := client.ProtectURL(ctx, "https://internal.example.com/dashboard")
if err != nil {
	return err
}
```

`ProtectURL` is idempotent for the same account and target URL. If the resource
already exists, LayerV returns the existing resource.

You can attach resource-level metadata when it helps operators recognize the
protected service:

```go
resource, err := client.ProtectURL(ctx,
	"https://internal.example.com/dashboard",
	qurl.WithAlias("dev-dashboard"),
	qurl.WithDescription("Admin dashboard"),
)
```

## Create a Portal

```go
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
if err != nil {
	return err
}

fmt.Println(portal.Link)
```

Portal options apply to the link you are minting now:

```go
portal, err := resource.CreatePortal(ctx,
	qurl.ValidFor(5*time.Minute),
	qurl.WithLabel("Alice from Acme"),
	qurl.OneTimeUse(),
	qurl.MaxSessions(1),
)
```

## Reuse a Stored Resource ID

Most production apps protect the URL once, store the resource id, and mint
portals as needed:

```go
resource := client.ResourceByID("r_demo1234567")

portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

## One-Call Convenience

For a script or prototype where you want one API call, use:

```go
portal, resource, err := client.CreatePortalForURL(ctx,
	"https://internal.example.com/dashboard",
	qurl.ValidFor(5*time.Minute),
)
fmt.Println(resource.ID, portal.Link)
```

That asks LayerV to protect the URL and mint the portal in one API call. Use the
explicit `ProtectURL` then `resource.CreatePortal` flow when the resource
identity matters to your application.

## Credentials

Credentials are for software that protects URLs or creates portals. If your code
only opens received portal links, skip this section.

LayerV bootstrap creates issuer state once. Application code reads that state:

```go
client, err := qurl.OpenClient()
```

`OpenClient` reads `/var/lib/layerv/qurl/issuer-state.json`
(`qurl.DefaultIssuerStatePath`). Do not keep the temporary bootstrap key as
the application's credential, and do not pass it to `NewClient`.

If your app keeps issuer state in KMS, a secret manager, or a platform-specific
store, implement `qurl.CredentialProvider` and pass it to `qurl.NewClient`.
