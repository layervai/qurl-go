# Issue qURL Links

`CreatePortal` signs a short-lived qURL link for a private service configured in
the LayerV qURL Platform.

## Inputs

Most values come from two places:

- The `qurl.Resource` config LayerV provides for the private service.
- Your issuer signing key.

```go
resource := qurl.Resource{
	AccessPublicKey:  accessPublicKey,  // from LayerV resource config
	AccessURL:        accessURL,        // from LayerV resource config
	ResourceIdentity: resourceIdentity, // from LayerV resource config
}

link, err := qurl.CreatePortal(ctx, signer, resource, qurl.ValidFor(5*time.Minute))
```

LayerV gives you the resource values when you enable the private service for
qURL. `CreatePortal` generates the per-link credential and link id. Your
application chooses the lifetime.

| Field | Source | Required |
| --- | --- | --- |
| `resource` | LayerV resource config | Yes |
| `signer` | Your issuer signing key | Yes |
| `qurl.ValidFor(...)` | Link lifetime | Yes |

Use options only when you need them:

```go
link, err := qurl.CreatePortal(ctx, signer, resource,
	qurl.ValidFor(5*time.Minute),
	qurl.WithLinkID("ticket_01"),
)
```

For conformance tests or advanced issuers that need to set every signed claim
explicitly, use `CreatePortalWithParams`.

## Signer

`CreatePortal` uses the `qurl.Signer` interface. Production issuers usually back
that interface with KMS or another managed key service:

```go
type Signer interface {
	KID() string
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}
```

`qurl.GenerateLocalSigner` is useful for tests and demos.

## Verify Before Sending

You can verify a freshly minted link offline:

```go
pubDER, err := signer.PublicKeyDER()
if err != nil {
	return err
}
trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
if err != nil {
	return err
}
_, err = qurl.VerifyLink(link, trust)
```

Verification catches malformed or unverifiable links before they leave your
issuer path.
