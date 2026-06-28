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
ignoring every packet by default. A **qURL link** is a signed, expiring ticket that
opens a path to it.

This SDK gives you the issuer path that works completely offline today, plus the
opener path that lights up when your deployment has the qURL v2 admission service
and trust provider configured:

| You want to...                                | Use                                  | Status |
| --------------------------------------------- | ------------------------------------ | ------ |
| **Issue** (mint) a qURL link for someone else | `CreatePortal`                       | Works today |
| **Verify** a link before acting on it         | `qurl.VerifyLink`      | Works today |
| **Open** a link and reach the resource        | `EnterPortal` / `EnterPortalWith`    | SDK-ready; requires deployed qURL v2 admission and configured trust |

A qURL link looks like an ordinary URL:

```
https://qurl.link/#<claims>.<secret>.<sig>
```

Everything sensitive rides in the fragment after `#`, which browsers never send to
`qurl.link`. The full link still carries a short-lived credential, so treat it like
an expiring bearer link and share it only with the intended opener.

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

	// 1. An issuer signing key. In production this is a KMS-resident key reached
	//    through the qurl.Signer seam; locally, a software key needs no AWS.
	signer, err := qurl.GenerateLocalSigner("issuer-key-2026")
	if err != nil {
		panic(err)
	}

	// 2. Mint a link. In production these keys come from your NHP cell and
	//    protected resource; here we generate throwaway keys so the example runs
	//    exactly as pasted.
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

	// 3. Build a trust store from the issuer's public key and verify the link.
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
		panic(err) // tampered or untrusted links fail closed here
	}
	fmt.Println("verified qURL for relay:", frag.Claims.RelayURL)
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

This exact flow is compile-checked in [`qurl/example_test.go`](qurl/example_test.go)
and runs with `go test ./qurl/`. Shorter snippets later in the docs focus on the
API shape and use deployment-specific placeholders.

## Issue a link

`CreatePortal` is the issuer side. It generates the fresh per-link keypair, assembles
and signs the claims, and returns the full `https://qurl.link/#…` link. The
issuer key never lives in your process directly — signing goes through the
`qurl.Signer` seam, so you can drop in KMS, an HSM, or a file-backed key without
changing this call.

```go
signer, _ := qurl.GenerateLocalSigner("issuer-key-2026") // dev; use KMS in prod

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

`EnterPortal` is the opener side. It parses the fragment, verifies the issuer
signature, validates the relay, and performs the NHP knock. A live open succeeds only
when your deployment has qURL v2 admission deployed and a trust provider installed;
without that provider it fails closed with `ErrNotConfigured`.

```go
// One-argument form. A deployment installs its trust anchors once at startup…
qurl.SetDefaultProvider(provider) // e.g. qurl.NewStaticProvider(trust, allowlist)

// ...then opens links with no per-call trust config:
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	// see "Error handling" for the failure taxonomy
}
fmt.Println("resource URL:", handle.RedirectURL)
```

Prefer to pass config explicitly (e.g. in tests, or to pin a fixed egress)? Use
`EnterPortalWith(ctx, link, qurl.Config{…})`.

> **Status:** `EnterPortal` is implemented and tested through parse, signature
> verification, relay validation, and knock construction. The final live round trip
> depends on your deployment's qURL v2 admission rollout and trust-provider
> configuration. See [Status & limitations](#status--limitations).

→ **[Opening links guide](docs/opening-links.md)** — providers (static & discovery),
the relay allowlist, the same-egress-IP rule, error handling, and retries.

## How it works

`EnterPortal` stitches two lower layers together in the exact order the protocol
requires — signature first, then (and only then) act on anything the link claims:

```
EnterPortal(link)                                ← open the locked link
  │
  ├─ qurl.VerifyLink(fragment, trustStore)    ← strict parse + verify issuer signature
  │     → Claims{relay_url, cell_public_key, resource_public_key, exp, …}
  │     → Secret{per-link private key}
  │
  ├─ qurl.ValidateRelayURL(relay_url, allowlist)  ← ONLY after the signature verifies
  │
  └─ relayknock.Knock(relay_url, cell_key, body) ← open access for your egress IP
        → ResourceHandle{RedirectURL, OpenSeconds}
```

You import **one package** — everything else is internal:

| Package                                                      | Role                                                                          |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`qurl`](https://pkg.go.dev/github.com/layervai/qurl-go/qurl) | Everything: open/issue links, trust providers, the `Signer` seam, and the typed errors to match on. |

The cryptographic core and the NHP knock transport are internal. (The generic
relay-knock layer is separately importable as `github.com/layervai/qurl-go/relayknock`
for non-qURL NHP use; qURL integrations don't need it.)

### Anatomy of a qURL link

```
https://qurl.link/#<claims>.<secret>.<signature>
                    │        │        └─ issuer signature over the claims bytes
                    │        └────────── per-link private key (the one-time credential)
                    └─────────────────── signed claims: relay, keys, expiry, id
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
| `qurl.ErrSignature`            | Issuer signature didn't verify (forged/tampered) | Reject — do not retry               |
| `qurl.ErrUnknownKID`           | Link signed by an issuer key you don't trust     | Reject — do not retry               |
| `qurl.ErrRelayURL`             | `relay_url` isn't HTTPS or not on the allowlist  | Reject — do not retry               |
| `qurl.ErrServerOverloaded`    | Relay returned an overload cookie-challenge      | Retry later (backoff)               |
| `*qurl.ServerDenyError`       | Authenticated server refused (expired/revoked)   | Inspect `.ErrCode`; usually give up |
| `*relayknock.RelayError`      | Transport fault talking to the relay             | Retry depending on cause            |
| `qurl.ErrMalformedReply`      | Reply was unusable (e.g. no resource URL)        | Treat as a server-side fault        |

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

## Status & limitations

This is the **foundation** release: minting, strict parsing, issuer verification,
relay validation, and knock construction are implemented and tested. The external
rollout pieces are explicit:

- **Live opens need deployed qURL v2 admission.** `EnterPortal` builds and posts the
  qURL knock, but the server-side admission path must be deployed before a live
  end-to-end open can complete.
- **One-argument open needs trust config.** Until your process installs a provider via
  `SetDefaultProvider`, `EnterPortal(ctx, link)` fails closed with
  `ErrNotConfigured`. Use `NewStaticProvider` for fixed anchors, or call
  `EnterPortalWith` when you want to pass trust and relay config per call.
- **Discovery is advanced configuration.** `NewDiscoveryProvider` is available for
  deployments that already publish signed or pinned manifests. Its manifest policy is
  still being finalized, so start with static trust unless you own that publishing
  pipeline.

## Security model

The SDK is built around a deliberately small, standard-library-only cryptographic
core. Its guarantees:

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

## Conformance vectors

The language-agnostic qURL conformance vectors and the composed issuer-signature
golden file are consumed from the public
[`qurl-conformance`](https://github.com/layervai/qurl-conformance) package via its
`go:embed` accessors, so the Go SDK is verified against the same fixtures as other
qURL implementations.
The bytes are pinned by the dependency version in `go.sum`, so adopting an updated
artifact is a **dependency bump**.

## Roadmap

The foundation lands the verify/knock core and both verbs, plus the trust/relay
credential provider (`StaticProvider`, `DiscoveryProvider`). Remaining follow-ups,
tracked as issues:

- **Production KMS signer** — a KMS-backed `qurl.Signer` for `CreatePortal`.
- **REST client** — a typed client for the qurl-service control-plane API.

## Documentation

- 📘 [Issuing links](docs/issuing-links.md) — mint links, signing custody, rotation
- 📗 [Opening links](docs/opening-links.md) — providers, trust, errors, egress IP
- 📚 [API reference on pkg.go.dev](https://pkg.go.dev/github.com/layervai/qurl-go)
- 🛠️ [Contributing](CONTRIBUTING.md) — dev workflow, the `make check` gate, fuzzing

## License

[MIT](LICENSE) © LayerV AI
