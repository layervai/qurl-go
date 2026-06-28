# qurl-go

**Use the LayerV qURL Platform from Go: issue short-lived access links and open
them from agents or services without exposing a private endpoint.**

LayerV hosts the qURL Platform. This SDK gives your Go app the small surface it
needs: mint a link with `CreatePortal`, open a link with `EnterPortal`, and
match typed errors.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/qurl.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why qURL

Agents and services increasingly need to reach private MCP servers, APIs, and
internal tools. The old choices are painful: open an inbound port, run a VPN,
ship a bastion, or pass around a long-lived key.

qURL flips that model. A private service stays private. Access is granted with a
signed, expiring qURL link. The SDK verifies the link before acting on it, and
the LayerV qURL Platform handles the access path.

## Install

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

One import is all you need:

```go
import "github.com/layervai/qurl-go/qurl"
```

Requires Go 1.26+. The SDK depends only on the standard library and
`golang.org/x/crypto`.

## The Two Verbs

| Job | Function | What it does |
| --- | --- | --- |
| Issue an access link | `qurl.CreatePortal` | Signs a short-lived qURL link for a private service configured in LayerV. |
| Open an access link | `qurl.EnterPortal` | Verifies the link, asks the qURL platform for access, and returns the reachable URL. |

## Quickstart

This example mints and verifies a qURL link entirely offline. In production, the
resource config values come from the LayerV qURL Platform when you protect a
service. The helper functions below generate throwaway values so the example can
run as pasted.

```go
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

func main() {
	ctx := context.Background()

	// Local-only signer for the demo. Production issuers usually implement
	// qurl.Signer with KMS or another managed key.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// In production, LayerV provides this resource config when you protect a
	// private service. The demo generates throwaway values so it runs as pasted.
	resource := qurl.Resource{
		AccessPublicKey:  newX25519PublicKey(),
		AccessURL:        "https://access.qurl.link",
		ResourceIdentity: newP256SPKI(),
	}

	link, err := qurl.CreatePortal(ctx, signer, resource, qurl.ValidFor(5*time.Minute))
	if err != nil {
		panic(err)
	}

	pubDER, err := signer.PublicKeyDER()
	if err != nil {
		panic(err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})
	if err != nil {
		panic(err)
	}

	frag, err := qurl.VerifyLink(link, trust)
	if err != nil {
		panic(err)
	}
	fmt.Println("verified qURL:", frag.Claims.Jti)
}

func newX25519PublicKey() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

func newP256SPKI() []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}
```

The package examples in [`qurl/example_test.go`](qurl/example_test.go) are
compile-checked with `go test ./qurl`.

## Opening Links

To open live links, configure the opener once with the issuer keys and qURL
platform access endpoints LayerV gives you, then call `EnterPortal` for each
link:

```go
qurl.SetDefaultProvider(provider)

handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}
fmt.Println("resource URL:", handle.RedirectURL)
```

`EnterPortal` fails closed when no provider is installed. For tests or manual
configuration, use `NewStaticProvider` or `EnterPortalWith`.

## Platform Setup

Live access has two pieces:

1. Enable the private service in the LayerV qURL Platform.
2. Use the resource config and opener config LayerV provides in this SDK.

LayerV hosts the qURL Platform. Your application only needs the SDK calls:
sign links locally, verify received links locally, and ask LayerV for access.

See the guides:

- [Protect a private service](docs/secure-a-private-service.md)
- [Issue links](docs/issuing-links.md)
- [Open links](docs/opening-links.md)

## Error Handling

Match errors by type, not message text:

| Error | Meaning | Usual action |
| --- | --- | --- |
| `qurl.ErrNotConfigured` | Opener config is missing | Install the provider from LayerV config |
| `qurl.ErrSignature` | Link is forged or tampered | Reject |
| `qurl.ErrUnknownKID` | Issuer key is not trusted | Reject |
| `qurl.ErrRelayURL` | Link points at an untrusted qURL access endpoint | Reject |
| `qurl.ErrServerOverloaded` | qURL platform is asking the client to retry later | Retry with backoff |
| `*qurl.ServerDenyError` | qURL platform refused this link | Treat as denied or expired |
| `*qurl.RelayError` | Network fault reaching qURL platform | Retry depending on cause |
| `qurl.ErrMalformedReply` | qURL platform returned an unusable response | Treat as service fault |

## Security Notes

- Treat a qURL link like an expiring bearer credential. Share it only with the
  intended caller and do not log it.
- Keep issuer signing keys in managed custody for production. `LocalSigner` is
  for tests, demos, and self-custody use cases.
- The SDK verifies the issuer signature before it acts on link contents.
- Empty or missing opener config fails closed.

## License

[MIT](LICENSE) © LayerV AI
