# Issue qURL Links

`CreatePortal` signs a short-lived qURL link for a private service configured in
the LayerV qURL Platform.

## Inputs

Most values come from two places:

- The LayerV qURL Platform resource config for the private service.
- Your issuer signing key.

```go
link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
	CellPublicKey:     resource.AccessPublicKey,
	RelayURL:          resource.AccessURL,
	ResourcePublicKey: resource.ResourceIdentity,
	CellID:            resource.Label,
	JTI:               "ticket_01",
	IssuedAt:          now,
	NotBefore:         now,
	Expiry:            now + 300,
})
```

`CellPublicKey`, `RelayURL`, and `ResourcePublicKey` are wire-format field names.
In normal integrations, copy the corresponding values from LayerV's resource
config; you do not need to understand the lower-level pieces behind them.

| Field | Source | Required |
| --- | --- | --- |
| `CellPublicKey` | LayerV resource config: access public key | Yes |
| `RelayURL` | LayerV resource config: qURL access URL | Yes |
| `ResourcePublicKey` | LayerV resource config: resource identity | Yes |
| `CellID` | Optional LayerV resource label | No |
| `JTI` | Unique link id chosen by your issuer | Yes |
| `IssuedAt`, `NotBefore`, `Expiry` | Link validity window, Unix seconds | Yes |

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
