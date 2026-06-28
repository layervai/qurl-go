# qurl-go

The official Go SDK for **qURL** — short-lived, cryptographically signed links that
open a path to resources that are otherwise invisible on the network.

[![Go Reference](https://pkg.go.dev/badge/github.com/layervai/qurl-go.svg)](https://pkg.go.dev/github.com/layervai/qurl-go)
[![CI](https://github.com/layervai/qurl-go/actions/workflows/ci.yml/badge.svg)](https://github.com/layervai/qurl-go/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Quantum URL (qURL)** · The internet has a hidden layer. This is how you enter.

---

## What is this?

Some resources shouldn't be reachable by just anyone who finds the address — they
should be **invisible until you prove you're allowed in**. qURL makes that possible.
A protected resource sits behind [NHP](#glossary): it is invisible on the network,
ignoring every packet by default. A **qURL link** is a signed, expiring ticket that opens a path to it.

This SDK gives you the two verbs you need, plus the cryptographic core underneath:

| You want to…                                  | Use            |
| --------------------------------------------- | -------------- |
| **Open** a qURL link and reach the resource   | `EnterPortal`  |
| **Issue** (mint) a qURL link for someone else | `CreatePortal` |

A qURL link looks like an ordinary URL:

```
https://qurl.link/#qv2.<claims>.<secret>.<sig>
```

Everything sensitive rides in the fragment after `#`, which browsers never send to a
server. The link carries its own one-time credential, an issuer signature, and an
expiry — so it's safe to put in an email, a QR code, or a chat message.

## Install

```sh
go get github.com/layervai/qurl-go@latest
```

Requires Go 1.26 or newer. The verification core depends only on the standard
library and `golang.org/x/crypto` — no AWS SDK, no KMS client baked in.

## Quickstart

The fastest way to see the SDK work end to end **today**: mint a signed link with a
local key, then verify it. Both steps run completely offline.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/qv2"
)

func main() {
	ctx := context.Background()
	now := time.Now().Unix()

	// 1. An issuer signing key. In production this is a KMS-resident key reached
	//    through the qv2.Signer seam; locally, a software key needs no AWS.
	signer, _ := qv2.GenerateLocalSigner("issuer-key-2026")

	// 2. Mint a link. cellPub / resourceDER come from your deployment (the NHP cell
	//    key and the resource's DER key); the per-link credential is generated for
	//    you and tucked into the fragment.
	link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
		CellPublicKey:     cellPub,     // raw 32-byte X25519 NHP cell key
		RelayURL:          "https://relay.example.com",
		ResourcePublicKey: resourceDER, // DER SPKI P-256 resource key
		JTI:               "qurl_demo_0001",
		IssuedAt:          now,
		NotBefore:         now,
		Expiry:            now + 300, // a 5-minute link
	})
	if err != nil {
		panic(err)
	}

	// 3. Build a trust store from the issuer's public key and verify the link.
	pubDER, _ := signer.PublicKeyDER()
	trust, _ := qv2.NewTrustStoreFromDER(map[string][]byte{signer.KID(): pubDER})

	frag, err := qv2.FragmentFromLinkAndVerify(link, trust)
	if err != nil {
		panic(err) // tampered or untrusted links fail closed here
	}
	fmt.Println("verified qURL for relay:", frag.Claims.RelayURL)
}
```

> This exact flow is a compile-checked, runnable example —
> see [`qurl/example_test.go`](qurl/example_test.go) (`go test ./qurl/`). Runnable
> versions of every flow live in the packages' `example_test.go` files; the shorter
> snippets elsewhere in these docs are abbreviated for readability, with
> deployment-specific values (keys, times) shown as placeholders.

## Issue a link

`CreatePortal` is the issuer side. It generates the fresh per-link keypair, assembles
and signs the claims, and returns the full `https://qurl.link/#qv2.…` link. The
issuer key never lives in your process directly — signing goes through the
`qv2.Signer` seam, so you can drop in KMS, an HSM, or a file-backed key without
changing this call.

```go
signer, _ := qv2.GenerateLocalSigner("issuer-key-2026") // dev; use KMS in prod

link, _ := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
	CellPublicKey:     cellPub,
	RelayURL:          "https://relay.example.com",
	ResourcePublicKey: resourceDER,
	JTI:               "qurl_01J…",
	IssuedAt:          iat, NotBefore: nbf, Expiry: exp,
})
```

→ **[Issuing links guide](docs/issuing-links.md)** — production signing custody (KMS),
validity windows, key rotation, and the full `CreateParams` reference.

## Open a link

`EnterPortal` is the opener side and the headline verb. It does everything in one
call: parse the fragment, verify the issuer signature, validate the relay, and knock
to open access — returning a `ResourceHandle` with the now-reachable URL.

```go
// One-argument form. A deployment installs its trust anchors once at startup…
qurl.SetDefaultProvider(provider) // e.g. qurl.NewStaticProvider(trust, allowlist)

// …then opens any link with no per-call config:
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	// see "Error handling" for the failure taxonomy
}
fmt.Println("reachable at:", handle.RedirectURL)
```

Prefer to pass config explicitly (e.g. in tests, or to pin a fixed egress)? Use
`EnterPortalWith(ctx, link, qurl.Config{…})`.

> **Status:** opening a link performs a live network knock to the relay. The qURL v2
> server-side admission contract is still being deployed, so a *live* open cannot
> complete end to end yet — but parsing, signature verification, relay validation,
> and knock construction are all implemented and tested offline. Until your
> deployment installs a provider, the one-argument `EnterPortal` fails closed with
> `ErrNotConfigured`. See [Status & limitations](#status--limitations).

→ **[Opening links guide](docs/opening-links.md)** — providers (static & discovery),
the relay allowlist, the same-egress-IP rule, error handling, and retries.

## How it works

`EnterPortal` stitches two lower layers together in the exact order the protocol
requires — signature first, then (and only then) act on anything the link claims:

```
EnterPortal(link)                                ← open the locked link
  │
  ├─ qv2.ParseAndVerify(fragment, trustStore)    ← strict parse + verify issuer signature
  │     → Claims{relay_url, cell_public_key, resource_public_key, exp, …}
  │     → Secret{per-link private key}
  │
  ├─ qv2.ValidateRelayURL(relay_url, allowlist)  ← ONLY after the signature verifies
  │
  └─ relayknock.Knock(relay_url, cell_key, body) ← open access for your egress IP
        → ResourceHandle{RedirectURL, OpenSeconds}
```

Three packages, each independently usable and tested:

| Package                                    | Role                                                                 |
| ------------------------------------------ | -------------------------------------------------------------------- |
| [`qurl`](https://pkg.go.dev/github.com/layervai/qurl-go/qurl)             | Top-level verbs: `EnterPortal`, `CreatePortal`, trust providers.       |
| [`qv2`](https://pkg.go.dev/github.com/layervai/qurl-go/qv2)               | The security core: strict parser, issuer sign/verify, trust store.    |
| [`relayknock`](https://pkg.go.dev/github.com/layervai/qurl-go/relayknock) | The low-level NHP relay-knock wire profile (Noise handshake).         |

### Anatomy of a qURL link

```
https://qurl.link/#qv2.<claims>.<secret>.<sig>
                   │    │        │        └─ issuer signature over the claims bytes
                   │    │        └────────── per-link private key (the one-time credential)
                   │    └─────────────────── signed claims: relay, keys, expiry, id
                   └──────────────────────── version tag (always "qv2")
```

The signature covers the **exact claims bytes on the wire**, so the claims can't be
altered without breaking it. The secret needs no signature: swapping it for an
attacker's key makes the proof-of-possession step fail, because the signed public key
no longer matches.

### Glossary

| Term       | Meaning                                                                       |
| ---------- | ----------------------------------------------------------------------------- |
| **NHP**    | Network Hiding Protocol — keeps a resource invisible; ignores all traffic until a knock. |
| **Knock**  | An authenticated packet that asks the NHP server to open access for you.       |
| **Relay**  | The public endpoint that forwards your knock to the (private) NHP server.      |
| **Cell**   | The NHP server instance guarding a resource; identified by its X25519 key.     |
| **Issuer** | The party that mints and signs qURL links (e.g. your qurl-service).            |

## Error handling

Every failure mode is a typed error you can match with `errors.Is` / `errors.As`.
Match on these, not on message text:

| Error                         | Meaning                                          | What to do                          |
| ----------------------------- | ------------------------------------------------ | ----------------------------------- |
| `qurl.ErrNotConfigured`       | No trust anchors / relay allowlist installed     | Install a provider; check config    |
| `qv2.ErrSignature`            | Issuer signature didn't verify (forged/tampered) | Reject — do not retry               |
| `qv2.ErrUnknownKID`           | Link signed by an issuer key you don't trust     | Reject — do not retry               |
| `qv2.ErrRelayURL`             | `relay_url` isn't HTTPS or not on the allowlist  | Reject — do not retry               |
| `qurl.ErrServerOverloaded`    | Relay returned an overload cookie-challenge      | Retry later (backoff)               |
| `*qurl.ServerDenyError`       | Authenticated server refused (expired/revoked)   | Inspect `.ErrCode`; usually give up |
| `*relayknock.RelayError`      | Transport fault talking to the relay             | Retry depending on cause            |
| `qurl.ErrMalformedReply`      | Reply was unusable (e.g. no resource URL)        | Treat as a server-side fault        |

```go
handle, err := qurl.EnterPortal(ctx, link)
switch {
case errors.Is(err, qv2.ErrSignature), errors.Is(err, qv2.ErrUnknownKID):
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

## Status & limitations

This is the **foundation** release: the cryptographic core and both verbs are
complete and tested. A few things are intentionally provisional:

- **Live opens need a deployed relay.** The qURL v2 server-side admission contract is
  being rolled out. Parsing, verification, relay validation, and knock construction
  are implemented and unit-tested offline against conformance vectors; the live
  end-to-end open lights up when the server contract is deployed — no SDK change
  needed.
- **Production trust anchors aren't published yet.** Until your deployment installs a
  provider via `SetDefaultProvider`, the one-argument `EnterPortal` fails closed with
  `ErrNotConfigured`. Inject anchors today with `NewStaticProvider` /
  `NewDiscoveryProvider`, or call `EnterPortalWith`.
- **Conformance vectors are provisional.** `qv2/testdata` vendors the language-agnostic
  qURL v2 conformance artifact; the current copy tracks an in-flight upstream branch
  and is re-vendored verbatim on merge.

## Security model

The `qv2` package is a deliberately small, standard-library-only security core. Its
guarantees:

- **Verify before you act.** The issuer signature is checked first; `relay_url` and
  everything else are attacker-controlled until it verifies, so they're only used
  afterward.
- **Sign exactly what's transmitted.** Signatures cover the exact base64url claims
  bytes on the wire, never a re-serialization — closing a classic signature-bypass
  hole. Mint and verify share one preimage by construction.
- **Fail closed.** An empty trust store rejects every signature; an empty relay
  allowlist rejects every link; an unconfigured opener refuses rather than trusting
  anything.
- **Strict parsing.** Duplicate keys, unknown fields, nulls, wrong types,
  non-canonical base64url, and out-of-range times are all rejected. This surface is
  continuously fuzzed.
- **Conformance-tested.** Verification is exercised against language-agnostic vectors
  so the Go SDK agrees byte-for-byte with other qURL implementations.

⚠️ **Same-egress-IP rule.** The NHP server opens access for the **source IP of
your knock**. Any request you then make to the resource must leave from that same IP.
Behind a rotating-egress NAT or proxy pool, pin the knock and the resource request to
the same exit — see the [opening links guide](docs/opening-links.md#the-same-egress-ip-rule).

## Roadmap

The foundation lands the verify/knock core and both verbs, plus the trust/relay
credential provider (`StaticProvider`, `DiscoveryProvider`). Remaining follow-ups,
tracked as issues:

- **Production KMS signer** — a KMS-backed `qv2.Signer` for `CreatePortal`.
- **REST client** — a typed client for the qurl-service control-plane API.

## Documentation

- 📘 [Issuing links](docs/issuing-links.md) — mint links, signing custody, rotation
- 📗 [Opening links](docs/opening-links.md) — providers, trust, errors, egress IP
- 📚 [API reference on pkg.go.dev](https://pkg.go.dev/github.com/layervai/qurl-go)
- 🛠️ [Contributing](CONTRIBUTING.md) — dev workflow, the `make check` gate, fuzzing

## License

[MIT](LICENSE) © LayerV AI
