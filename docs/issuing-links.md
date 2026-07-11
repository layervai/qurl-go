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

## Connector-Protected Services

If qURL Connector already protects the service, skip `ProtectURL`. Use the
immutable connector slug for that service:

```go
resource, err := client.GetTunnelResourceBySlug(ctx, "prod-dashboard")
if err != nil {
	return err
}

portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
if err != nil {
	return err
}
```

The connector install/startup flow creates or finds the LayerV resource for that
immutable slug. Your app only resolves it and mints portals. A resource alias is
a separate, mutable display handle and is never used as connector identity.

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

## Connect to LayerV

Credentials are for software that protects URLs or creates portals. If your code
only opens received portal links, skip this section.

Before deploying code that creates portals, run the LayerV setup flow once for
that service identity. The setup flow consumes the temporary bootstrap key,
registers the service with your LayerV account, and stores the runtime issuer
credential in protected state for the process. After that, application code
starts with:

```go
client, err := qurl.OpenClient()
```

That is the normal application code. You do not paste bootstrap keys into your
app, read `LAYERV_API_KEY`, or ask portal recipients to hold credentials. LayerV
setup turns the one-time key into runtime issuer state; `OpenClient` uses that
state.

If your runtime stores LayerV credentials in KMS, a secret manager, or another
custom store, implement `qurl.CredentialProvider` and pass it to
`qurl.NewClient`. Otherwise use `OpenClient`.
