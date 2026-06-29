# qurl-go

**Use the LayerV qURL Platform from Go: protect a private URL once, then mint
short-lived access links for it.**

LayerV hosts qURL. Your Go app keeps a tiny surface area: protect the URL,
create a portal link for the returned resource, and share the link.

Portal recipients do not need LayerV credentials, API keys, keypairs, or SDK
state. They open the qURL link. Credentials are only for software that protects
URLs or creates portals.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/qurl.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why qURL

Agents and services increasingly need to reach private MCP servers, APIs, and
internal tools. The issue is visibility: every standing public endpoint becomes
inventory for scanners, fingerprinting, credential attacks, and AI-assisted
probing before a legitimate user or agent ever arrives.

Opening an inbound port, running a VPN, shipping a bastion, publishing a
Cloudflare Tunnel or ngrok URL, or passing around a long-lived key all leave
something durable to find, scan, or steal. qURL flips that model. It is an
invisibility primitive for authenticated access, not another externally visible
endpoint in front of the same service. The private resource is not public
inventory. A portal is cryptographic, just-in-time permission for one actor to
reach one private resource without turning that resource into public inventory.

## Install

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

Requires Go 1.26+. The SDK depends only on the standard library and
`golang.org/x/crypto`.

## Quickstart

```go
package main

import (
	"context"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

func issuePortal(ctx context.Context) (string, error) {
	client, err := qurl.OpenClient()
	if err != nil {
		return "", err
	}

	resource, err := client.ProtectURL(ctx, "https://internal.example.com/dashboard")
	if err != nil {
		return "", err
	}

	portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
	if err != nil {
		return "", err
	}

	return portal.Link, nil
}
```

That is the core flow:

| Step | Call | What you provide |
| --- | --- | --- |
| Protect a private URL | `client.ProtectURL` | The target URL you already know |
| Mint a short-lived access link | `resource.CreatePortal` | The returned resource handle |

If qURL Connector already protects the service, use the connector id instead of
calling `ProtectURL`:

```go
resource, err := client.ConnectorResource(ctx, "prod-dashboard")
if err != nil {
	return err
}

portal, err := resource.CreatePortal(ctx, qurl.ValidFor(5*time.Minute))
```

If you persist the resource id, future calls do not need to recreate the handle:

```go
resource := client.ResourceByID("r_demo1234567")
portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
```

For one-off scripts, `client.CreatePortalForURL` combines the two API calls and
returns both the portal and a resource handle you can reuse. That handle contains
the resource id and target URL; use `ProtectURL` when you need the full resource
metadata from LayerV.

## Connect to LayerV

Only software that protects URLs or creates portals needs LayerV credentials. A
user or agent that only receives and opens a qURL link does not set up anything.

Before deploying code that calls `OpenClient`, run the LayerV setup flow once
for that service identity. The setup flow consumes the temporary bootstrap key,
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

## Opening Links

Most recipients open qURL links directly and do not use this SDK at all. If you
are building a service or agent that opens received qURL links programmatically,
install opener trust config once at startup, then enter portals with one call:

```go
portal, err := qurl.EnterPortal(ctx, link)
if err != nil {
	return err
}
fmt.Println("resource URL:", portal.ResourceURL)
```

`EnterPortal` fails closed when no provider is installed. For tests or manual
configuration, see the opener guide.

## Guides

- [Protect a private service](docs/secure-a-private-service.md)
- [Issue links](docs/issuing-links.md)
- [Open links](docs/opening-links.md)

## Error Handling

Match errors by type, not message text:

| Error | Meaning |
| --- | --- |
| `qurl.ErrInvalidClientConfig` | Client credentials or options are missing or malformed |
| `qurl.ErrInvalidResourceRequest` | Resource input is invalid before an API request is sent |
| `qurl.ErrInvalidPortalRequest` | Portal input is invalid before an API request is sent |
| `*qurl.APIError` | LayerV returned a non-2xx API response |
| `qurl.ErrNotConfigured` | Opener config is missing |
| `qurl.ErrSignature` / `qurl.ErrUnknownKID` | A received signed link is forged, tampered, or untrusted |
| `*qurl.ServerDenyError` | qURL refused a programmatic open request |

## Security Notes

- Treat LayerV credentials and qURL links like credentials. Do not log them.
- Prefer short portal lifetimes such as `qurl.ValidFor(5*time.Minute)`.
- Keep issuer credentials in protected state, KMS, a secret manager, or another
  protected store.
- Do not ask portal recipients to handle issuer credentials. Recipients only
  need the link.
- Programmatic openers fail closed when trust or access configuration is absent.

## License

[MIT](LICENSE) © LayerV AI
