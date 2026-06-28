# Issuing links

This guide covers the **issuer side**: minting qURL links with `CreatePortal`,
managing signing keys safely, and rotating them. Everything uses the single `qurl`
package. If you want to *open* links instead, see [Opening links](opening-links.md).

- [The one call](#the-one-call)
- [`CreateParams` reference](#createparams-reference)
- [Validity windows](#validity-windows)
- [Signing keys: the `Signer` seam](#signing-keys-the-signer-seam)
- [Self-verification at mint time](#self-verification-at-mint-time)
- [Key rotation](#key-rotation)
- [Verifying your own links](#verifying-your-own-links)
- [Error handling](#error-handling)

## The one call

`CreatePortal` does everything needed to produce a link:

1. generates a fresh per-link X25519 keypair (the private half becomes the fragment
   secret, the public half is bound into the signed claims),
2. assembles the claims,
3. signs them through your `Signer`,
4. returns the full `https://qurl.link/#…` link.

```go
signer, _ := qurl.GenerateLocalSigner("issuer-key-2026") // dev key; see "Signing keys"

link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
	CellPublicKey:     cellPub,     // raw 32-byte X25519 NHP cell key
	RelayURL:          "https://relay.example.com",
	ResourcePublicKey: resourceDER, // DER SPKI P-256 resource key
	JTI:               "qurl_01J…", // unique per link
	IssuedAt:          iat,
	NotBefore:         nbf,
	Expiry:            exp,
})
```

You never choose the version, issuer, `kid`, signature, or per-link keypair —
`CreatePortal` and the signer own those. You supply only the bindings and the
validity window.

## `CreateParams` reference

| Field               | Type     | Required | Description                                                              |
| ------------------- | -------- | :------: | ------------------------------------------------------------------------ |
| `CellPublicKey`     | `[]byte` |    ✅    | Raw 32-byte X25519 NHP cell (server) public key. Defines the relay route. |
| `RelayURL`          | `string` |    ✅    | HTTPS relay origin the opener knocks. Signed, but acted on only after verify. |
| `ResourcePublicKey` | `[]byte` |    ✅    | Protected-resource public key, DER SPKI form (e.g. a P-256 KMS key, ~91 bytes). |
| `JTI`               | `string` |    ✅    | Unique qURL id — the per-link identifier and part of the anti-tamper envelope. |
| `IssuedAt`          | `int64`  |    ✅    | `iat` claim, Unix seconds.                                                |
| `NotBefore`         | `int64`  |    ✅    | `nbf` claim, Unix seconds.                                                |
| `Expiry`            | `int64`  |    ✅    | `exp` claim, Unix seconds.                                                |
| `CellID`            | `string` |    —     | Optional human/config label for the cell. Empty omits it from the claims. |

`CellPublicKey` and `ResourcePublicKey` are raw bytes, not base64 — `CreatePortal`
encodes them for the wire. To turn a P-256 public key into the DER SPKI bytes
`ResourcePublicKey` wants:

```go
resourceDER, _ := x509.MarshalPKIXPublicKey(&resourcePriv.PublicKey)
```

## Validity windows

The three time fields are **Unix seconds** and must satisfy the clock-free ordering
bounds the verifier enforces:

- `IssuedAt <= Expiry`
- `NotBefore <= Expiry`

A window that violates these fails the mint (as `qurl.ErrStrictParse`) rather than
producing a link no verifier would accept.

```go
now := time.Now().Unix()
params := qurl.CreateParams{
	// …bindings…
	IssuedAt:  now,
	NotBefore: now,
	Expiry:    now + 300, // a 5-minute link
}
```

> **Liveness is the admission layer's job, not the mint's.** `CreatePortal` has no
> trusted clock; it only checks the ordering bounds above. Whether a link is
> *currently* live (vs. expired or not-yet-valid against the wall clock) is enforced
> when the resource admits traffic. Keep windows short.

## Signing keys: the `Signer` seam

The issuer signing key is never held by `CreatePortal` directly. Signing goes through
a tiny interface, so where the key lives is your choice:

```go
type Signer interface {
	KID() string                                              // published key id
	SignDigest(ctx context.Context, digest []byte) ([]byte, error) // returns ASN.1 DER
}
```

The SDK owns the domain-separated digest and the DER → raw `r‖s` low-S normalization,
so **no signer can drift** on those details — it just signs the 32 digest bytes it's
handed.

| Where the key lives        | How                                                                 |
| -------------------------- | ------------------------------------------------------------------- |
| **Production** (KMS / HSM) | Implement `qurl.Signer` over your KMS client (`MessageType=DIGEST`). Recommended — a leaked process must not yield the issuer key. |
| **Self-custody / files**   | Implement `qurl.Signer` over a file- or HSM-resident key.           |
| **Tests & local dev**      | `qurl.NewLocalSigner(priv, kid)` or `qurl.GenerateLocalSigner(kid)`. |

A minimal KMS signer looks like this (sketch — wire it to your SDK):

```go
type kmsSigner struct {
	kid    string
	client *kms.Client
	keyID  string
	pubDER []byte // cache GetPublicKey output so self-verify is free
}

func (s *kmsSigner) KID() string { return s.kid }

func (s *kmsSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil // ASN.1 DER; the SDK normalizes to low-S
}

// Optional but recommended — enables mint-time self-verify (see below).
func (s *kmsSigner) PublicKeyDER() ([]byte, error) { return s.pubDER, nil }
```

> The `Signer` interface keeps AWS (or any HSM SDK) out of this module's dependency
> graph — the SDK stays standard-library-only. A KMS-backed signer ships with the
> credential-provider follow-up; until then, implement the two methods yourself.

## Self-verification at mint time

If your `Signer` also implements `PublicKeyDER() ([]byte, error)`, `CreatePortal`
verifies the freshly minted signature against that public key *before returning*. This
catches a custody misconfiguration — a signer whose signing key disagrees with its
reported public key (wrong, rotated, or region-mismatched) — at mint time, instead of
producing a link that only fails downstream.

`LocalSigner` implements it. A production KMS signer should cache its `GetPublicKey`
output (as in the sketch above) so self-verify doesn't cost an API call per mint.

## Key rotation

Rotation is **overlap-publish**, expressed entirely through the contents of the
verifiers' trust store — there is no per-key TTL or "retired" flag in the library.

1. **Add** the new key. Start signing new links with the new `kid`, and publish the
   new public key into every verifier's trust store *alongside* the old one. Links
   signed under either kid now verify.
2. **Overlap.** Outstanding links signed under the old kid keep working for as long as
   the old key remains in the published trust store. Size this window to your longest
   link lifetime.
3. **Retire** the old key by removing it from the published trust store. From then on,
   verifiers return `qurl.ErrUnknownKID` for links signed under it.

On the verifier side this is just publishing an updated trust store (or manifest) — see
[Opening links → Trust providers](opening-links.md#trust-providers).

## Verifying your own links

A link from `CreatePortal` is guaranteed to parse and verify against a trust store
holding the signer's public key — `CreatePortal` runs the same strict checks the
verifier uses *before* signing, so a mint that wouldn't verify fails at mint instead.
The round trip is the basis of the [Quickstart](../README.md#quickstart):

```go
pubDER, _ := signer.PublicKeyDER()
trust, _ := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})

frag, err := qurl.VerifyLink(link, trust)
// err == nil; frag.Claims holds the verified claim set
```

This exact flow is a runnable example — see [`qurl/example_test.go`](../qurl/example_test.go).

## Error handling

| Error                         | Cause                                                             |
| ----------------------------- | ---------------------------------------------------------------- |
| `qurl.ErrInvalidCreateParams` | A required binding is missing (nil key, empty `JTI`, zero time). |
| `qurl.ErrStrictParse`         | A deep value rule failed (bad key length, time ordering, …).     |
| `qurl.ErrKeyLength`           | A key field decoded to the wrong size.                           |

Match the exact cause with `errors.Is`:

```go
link, err := qurl.CreatePortal(ctx, signer, params)
switch {
case errors.Is(err, qurl.ErrInvalidCreateParams):
	// a required field was missing
case errors.Is(err, qurl.ErrStrictParse):
	// a value was present but invalid (e.g. nbf > exp)
case err != nil:
	// signer error, keygen failure, etc.
}
```
