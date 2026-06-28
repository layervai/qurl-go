# qurl-go

**Give an AI agent — or any client — authenticated, time-bound access to a private
MCP server, API, or service, without opening a port, running a VPN, or sharing a
key.** The service stays invisible to the internet; only a caller holding a signed,
expiring **qURL link** can reach it, and only after it proves who it is.

qURL is the access layer for the agentic internet — *authenticate-before-connect*,
built on the open **OpenNHP** standard. This is the Go SDK.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go/qurl.svg)](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **The internet has a hidden layer. This is how you enter.**

---

## The problem

Your agent (or service) needs to reach something private — an MCP server, an internal
API, a database. Today that usually means one of:

- an **open inbound port** — now anyone on the internet can find and probe it,
- a **VPN or bastion** you have to stand up and operate,
- an **ngrok-style tunnel**, or
- a **shared API key** copied around and rarely rotated.

Every one of those exposes the thing you're trying to protect. The resource is
reachable first and secured afterward — the same assumption behind most breaches that
start with "an exposed endpoint."

## How qURL is different

With qURL the resource is **invisible by default**: it sits behind [NHP](#glossary)
and ignores every packet until a caller proves it's authorized. Access is handed out
as a **qURL link** — a short-lived, cryptographically signed ticket.

- **No inbound port.** The caller makes an *outbound* knock; nothing is ever exposed.
- **No shared secret.** Each link carries its own one-time credential and an expiry.
- **Authenticated and governed.** The issuer signature, the relay, and the validity
  window are all verified before any connection is attempted.

Two roles, one package:

| Role | What you do | Verb |
| ---- | ----------- | ---- |
| **Resource owner** — hand out access to your private service | mint a signed, expiring access link | `CreatePortal` |
| **Client / agent** — reach the service | open the link, get the reachable URL | `EnterPortal` |

## What runs today

Straight talk about the surface, so nothing surprises you:

- ✅ **Issue and verify access links — fully offline, right now.** Mint a signed link
  and verify it with nothing but this library. That's the [Quickstart](#quickstart)
  below, and it's compile-checked.
- 🚧 **The live "client reaches the resource" round trip** needs your deployment's
  qURL admission service and a trust provider installed (or the hosted onramp).
  `EnterPortal` parses, verifies, validates the relay, and builds the knock today; the
  final hop lights up once that's in place. See
  [Status — what runs today](#status--what-runs-today).

## Install

```sh
go get github.com/layervai/qurl-go/qurl@latest
```

One import (`github.com/layervai/qurl-go/qurl`) is all you need. Requires Go 1.26+.
The library depends only on the standard library and `golang.org/x/crypto` — no AWS
SDK, no KMS client baked in.

## Quickstart

Issue an access link for your service and verify it — the whole thing runs **offline**,
no deployment required. (In a real setup the resource owner mints the link and hands it
to the client; here one program does both so you can see it work end to end.)

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
	now := time.Now().Unix()

	// 1. Your issuer signing key. In production this is a KMS-resident key reached
	//    through the qurl.Signer seam; locally, a software key needs no AWS.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// 2. Mint an access link. cellPub / resourceDER identify the NHP cell in front of
	//    your service and the resource itself; here we generate throwaway keys so the
	//    example runs exactly as pasted. The per-link credential is generated for you.
	cellPub := newX25519PublicKey() // raw 32-byte X25519 NHP cell key
	resourceDER := newP256SPKI()    // DER SPKI P-256 resource key

	link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
		CellPublicKey:     cellPub,
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: resourceDER,
		JTI:               "qurl_demo_0001",
		IssuedAt:          now,
		NotBefore:         now,
		Expiry:            now + 300, // a 5-minute link
	})
	if err != nil {
		panic(err)
	}

	// 3. The client verifies the link before trusting it. Build a trust store from the
	//    issuer's public key; a tampered or untrusted link fails closed here.
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
	fmt.Println("verified access link for relay:", frag.Claims.RelayURL)
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

This flow is compile-checked in [`qurl/example_test.go`](qurl/example_test.go)
(`go test ./qurl/`) — the example there uses fixed timestamps and asserts its output,
so it's representative rather than a byte-for-byte copy of the snippet above.

## Secure a private service, end to end

The Quickstart above is the issue + verify half. The full job — *put qURL in front of a
private service and let a client or agent reach it* — is the
**[golden-path guide](docs/secure-a-private-service.md)**. It walks the whole path and
marks each step **runs today** or **needs your qURL deployment**, so you always know
what's live and what's operator setup.

## Open a link (client / agent side)

`EnterPortal` is the client/agent verb. It parses the fragment, verifies the issuer
signature, validates the relay, and performs the NHP knock — returning a
`ResourceHandle` with the now-reachable URL.

```go
// Once, at startup: install the trust anchors your deployment publishes.
qurl.SetDefaultProvider(provider) // e.g. qurl.NewStaticProvider(trust, allowlist)

// Then open any link with no per-call config:
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	// see "Error handling" for the failure taxonomy
}
fmt.Println("resource URL:", handle.RedirectURL)
```

A live open succeeds only when your deployment has qURL admission deployed and a trust
provider installed; without a provider it fails closed with `ErrNotConfigured`. Prefer
explicit config (tests, or pinning a fixed egress)? Use
`EnterPortalWith(ctx, link, qurl.Config{…})`.

→ **[Opening links guide](docs/opening-links.md)** — providers (static & discovery),
the relay allowlist, the same-egress-IP rule, error handling, and retries.

## Why now

The number of things asking to connect is exploding on two axes at once: anyone with an
AI can ship infrastructure now, and agents spin up without any ceiling on their count.
Almost none of them can be onboarded the old way — a machine can't click through an MFA
prompt, and a builder who shipped something with AI may not know what an inbound port
is. They can authenticate programmatically, or be denied. *Authenticate-before-connect*
is the access model that still works when the caller brings no networking expertise at
all — which is exactly who (and what) is doing the integrating now.

## How it works

`EnterPortal` runs the steps in the order the protocol requires — signature first, then
(and only then) act on anything the link claims:

```
qurl.EnterPortal(link)
  │
  ├─ 1. Verify the issuer signature over the exact claim bytes   ← untrusted links stop here
  ├─ 2. Validate the relay against your allowlist                ← only after the signature verifies
  └─ 3. Knock the relay to open access for your egress IP
        → ResourceHandle{RedirectURL, OpenSeconds}
```

You import **one package** — everything else is internal:

| Package | Role |
| ------- | ---- |
| [`qurl`](https://pkg.go.dev/github.com/layervai/qurl-go/qurl) | Everything: issue/open links, trust providers, the `Signer` seam, and the typed errors to match on. |

The cryptographic core and the NHP knock transport are internal. (The generic
relay-knock layer is separately importable as `github.com/layervai/qurl-go/relayknock`
for non-qURL NHP use; qURL integrations don't need it.)

### Anatomy of a qURL link

```
https://qurl.link/#<version>.<claims>.<secret>.<signature>
                    │         │        │         └─ issuer signature over the claims bytes
                    │         │        └─────────── per-link private key (the one-time credential)
                    │         └──────────────────── signed claims: relay, keys, expiry, id
                    └────────────────────────────── protocol version tag (no secrets here)
```

Everything sensitive rides in the fragment after `#`, which browsers never send to
`qurl.link`. The signature covers the **exact claims bytes on the wire**, so the claims
can't be altered without breaking it. The secret needs no signature: swapping it for an
attacker's key makes proof-of-possession fail, because the signed public key no longer
matches. Treat a link like an expiring bearer credential and share it only with the
intended caller.

### Glossary

| Term | Meaning |
| ---- | ------- |
| **NHP** | Network Hiding Protocol (OpenNHP) — keeps a resource invisible; ignores all traffic until an authorized knock. |
| **Knock** | An authenticated, outbound packet that asks the NHP server to open access for you. |
| **Relay** | The public endpoint that forwards your knock to the (private) NHP server. |
| **Cell** | The NHP server instance guarding a resource; identified by its X25519 key. |
| **Issuer** | The party that mints and signs qURL links (your service). |

## Error handling

Every failure is a typed error you match with `errors.Is` / `errors.As` — never on
message text:

| Error | Meaning | What to do |
| ----- | ------- | ---------- |
| `qurl.ErrNotConfigured` | No trust anchors / relay allowlist installed | Install a provider; check config |
| `qurl.ErrSignature` | Issuer signature didn't verify (forged/tampered) | Reject — do not retry |
| `qurl.ErrUnknownKID` | Link signed by an issuer key you don't trust | Reject — do not retry |
| `qurl.ErrRelayURL` | Relay isn't HTTPS or not on the allowlist | Reject — do not retry |
| `qurl.ErrServerOverloaded` | Relay returned an overload cookie-challenge | Retry later (backoff) |
| `*qurl.ServerDenyError` | Authenticated server refused (expired/revoked) | Inspect `.ErrCode`; usually give up |
| `*qurl.RelayError` | Transport fault talking to the relay | Retry depending on cause |
| `qurl.ErrMalformedReply` | Reply was unusable (e.g. no resource URL) | Treat as a server-side fault |

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case errors.Is(err, qurl.ErrSignature), errors.Is(err, qurl.ErrUnknownKID):
	// untrusted or tampered link — reject
case errors.Is(err, qurl.ErrServerOverloaded):
	// retry with backoff
case err != nil:
	// other failure
default:
	use(handle.RedirectURL)
}
```

See the [opening links guide](docs/opening-links.md#error-handling) for the complete
taxonomy and retry guidance.

## Security model (for the security team)

When adoption crosses from one engineer to the team, this is the section your security
reviewers will want. qURL is built around a deliberately small, standard-library-only
cryptographic core:

- **Verify before you act.** The issuer signature is checked first; the relay and
  everything else are attacker-controlled until it verifies, so they're only used
  afterward.
- **Sign exactly what's transmitted.** Signatures cover the exact base64url claim bytes
  on the wire, never a re-serialization — closing a classic signature-bypass hole. Mint
  and verify share one preimage by construction.
- **Fail closed.** An empty trust store rejects every signature; an empty relay
  allowlist rejects every link; an unconfigured opener refuses rather than trusting
  anything.
- **Strict parsing.** Duplicate keys, unknown fields, nulls, wrong types, non-canonical
  base64url, and out-of-range times are all rejected. This surface is continuously
  fuzzed.
- **Conformance-tested.** Verification runs against the language-agnostic
  [`qurl-conformance`](https://github.com/layervai/qurl-conformance) vectors, so the Go
  SDK agrees byte-for-byte with other implementations of the standard.

⚠️ **Same-egress-IP rule.** The NHP server opens access for the **source IP of your
knock**. Any request you then make to the resource must leave from that same IP. Behind
a rotating-egress NAT or proxy pool, pin the knock and the resource request to the same
exit — see the
[opening links guide](docs/opening-links.md#the-same-egress-ip-rule).

## Status — what runs today

The foundation is complete and tested: minting, strict parsing, issuer verification,
relay validation, and knock construction. The external rollout pieces are explicit:

- **Live opens need deployed qURL admission.** `EnterPortal` builds and posts the knock,
  but the server-side admission path must be deployed before a live end-to-end open can
  complete.
- **One-argument open needs trust config.** Until your process installs a provider via
  `SetDefaultProvider`, `EnterPortal(ctx, link)` fails closed with `ErrNotConfigured`.
  Use `NewStaticProvider` for fixed anchors, or `EnterPortalWith` to pass config per
  call.
- **Discovery is advanced configuration.** `NewDiscoveryProvider` is available for
  deployments that already publish signed or pinned manifests. Start with static trust
  unless you own that publishing pipeline.

## Roadmap

- **Production KMS signer** — a KMS-backed `qurl.Signer` for `CreatePortal`.
- **REST client** — a typed client for the qurl-service control-plane API.

## Documentation

- 🚀 [Secure a private service](docs/secure-a-private-service.md) — the end-to-end golden path
- 📘 [Issuing links](docs/issuing-links.md) — mint links, signing custody, rotation
- 📗 [Opening links](docs/opening-links.md) — providers, trust, errors, egress IP
- 📚 [API reference on pkg.go.dev](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)
- 🛠️ [Contributing](CONTRIBUTING.md) — dev workflow, the `make check` gate, fuzzing

## License

[MIT](LICENSE) © LayerV AI
