# qurl-go

The canonical **Go SDK for qURL** — short-lived, policy-bound, cryptographically
protected links into NHP-protected resources.

> **Quantum URL (qURL)** · The internet has a hidden layer. This is how you enter.

A qURL resource is invisible by default and becomes reachable only after an
authorized NHP knock opens the access-control firewall for your egress IP. This
SDK performs that knock and the qURL v2 parse/verify in dependency-light,
clean-room Go.

## Status

**PR-1: foundation.** This package proves the core knock + qv2 parse path:

- `relayknock` — the generic NHP relay-knock wire profile.
- `qv2` — the strict qURL v2 keyed-identity fragment parser + issuer-signature verify/sign.
- `EnterPortal` — the one-shot "open this qURL link" verb.
- `CreatePortal` — the issuer-side mint verb (the inverse of `EnterPortal`), behind
  a KMS/local/file signer seam.

The credential provider and the REST client are **stacked follow-up PRs**, tracked
as issues — see [Roadmap](#roadmap). They are deliberately out of the foundation so
the cryptographic core lands reviewable on its own.

## Layered design

```
EnterPortal(qurlLink)                         ← the locked entry verb
  │
  ├─ qv2.ParseAndVerify(fragment, trustStore) ← strict parse + issuer-sig verify
  │     → Claims{cell_public_key, relay_url, resource_public_key, qurl_user_public_key, exp, …}
  │     → Secret{qurl_user_private_key}
  │
  ├─ qv2.ValidateRelayURL(relay_url, allowlist)  ← ONLY after the signature verifies
  │
  └─ relayknock.Knock(ctx, relay_url, cell_public_key, knockBody, opts)
        serverId = PubKeyFingerprint(cell_public_key)
        device identity = qurl_user_private_key (from the link's secret)
        POST {relay_url}/relay/{serverId}  →  decrypt + authenticate the NHP_ACK
```

Each layer is independently usable and independently tested:

- **`relayknock`** knows packet framing and the NHP Noise handshake (X25519 /
  AES-256-GCM / BLAKE2s) and nothing about qURL body shapes. Its wire format is
  fenced **byte-for-byte** by golden vectors copied from the nhp js-agent's
  cross-language fixtures. Only dependency: `golang.org/x/crypto`. It never imports
  `nhp/core`.
- **`qv2`** is a pure security core: a strict allowlist parser (rejects duplicate
  keys, unknown fields, nulls, wrong types, non-canonical base64url, out-of-range
  times) and a P-256 raw-`r‖s` low-S issuer-signature verifier over the **exact
  received claims bytes** (never a re-serialization). The matching mint side
  (`SignClaims` + the `Signer` seam) signs those same exact bytes, so sign and
  verify share one preimage by construction. Still standard-library only — no KMS,
  no AWS: the signer is an interface, not a baked-in client. It is exercised against
  nhp-owned **conformance vectors** vendored verbatim into `qv2/testdata`.

## `EnterPortal` usage

```go
import "github.com/layervai/qurl-go/qurl"

// One-shot: parse the qURL link, verify the issuer signature, derive the relay
// route from the verified cell key, and knock using the per-qURL key carried in
// the link. No external key is needed — the credential rides in the fragment.
//
// NOTE: until the qv2 issuer trust anchors ship (see "Provisional" below), the
// one-argument form fails closed with ErrNotConfigured. Today you supply the
// trust anchors + relay allowlist explicitly via EnterPortalWith:
cfg := qurl.Config{TrustStore: trustStore, RelayAllowlist: allowlist}
handle, err := qurl.EnterPortalWith(ctx, "https://qurl.link/#qv2.<claims>.<secret>.<sig>", cfg)
if err != nil {
    // errors.Is(err, qurl.ErrNotConfigured) — no trust anchors / allowlist;
    // qv2.ErrSignature / qv2.ErrUnknownKID — bad/unknown issuer signature;
    // qv2.ErrRelayURL — relay_url not HTTPS or off the allowlist;
    // *relayknock.RelayError — relay transport fault;
    // *qurl.ServerDenyError — authenticated server deny (carries ErrCode);
    // qurl.ErrServerOverloaded / qurl.ErrMalformedReply — retry / unusable reply.
}
// handle carries the reachable resource (the redirect URL) the server returned.

// Once the anchors ship, qurl.EnterPortal(ctx, link) works with no config.
```

## `CreatePortal` usage (issuer side)

`CreatePortal` is the inverse of `EnterPortal`: it mints the qURL link. It
generates the fresh per-qURL X25519 keypair (the secret rides in the fragment),
assembles and signs the claims, and returns the
`https://qurl.link/#qv2.<claims>.<secret>.<sig>` link. The issuer signing key never
lives in this process directly — signing goes through the `qv2.Signer` seam.

```go
import (
    "github.com/layervai/qurl-go/qurl"
    "github.com/layervai/qurl-go/qv2"
)

// The signer seam: KMS in production (credential-provider follow-up), or a
// software-resident local key for tests / self-custody. Production custody belongs
// in KMS — a leaked process must not yield the issuer key.
signer, _ := qv2.GenerateLocalSigner("qurl-issuer-key-2026-06") // or qv2.NewLocalSigner(priv, kid)

link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
    CellPublicKey:     cellPub,      // raw 32-byte X25519 NHP cell key
    RelayURL:          "https://relay.example.com",
    ResourcePublicKey: resourceDER,  // DER SPKI protected-resource key
    JTI:               "qurl_01J...",
    IssuedAt:          iat, NotBefore: nbf, Expiry: exp, // Unix seconds
})
// link verifies under qurl.EnterPortalWith / qv2.FragmentFromLinkAndVerify against
// a trust store holding the signer's public key (signer.PublicKeyDER()).
```

The signer interface is just two methods — `KID()` and
`SignDigest(ctx, digest) (derSig, err)` — so a KMS, file, or HSM signer drops in
without touching `qurl`/`qv2`. `qv2` owns the domain-separated digest and the
DER → raw r||s low-S conversion, so no signer can drift on those.

### Same-egress-IP invariant

The NHP server opens its firewall for the **source IP of the relay POST**. The
knock and any subsequent request to the resource MUST share an egress IP. Behind a
rotating-egress NAT/proxy pool, pin the knock and the request to the same exit, or
the request will arrive at a firewall opened for a different address.

### Provisional: live qv2 admission

The qURL v2 server-side admission contract (`/internal/v2/qurl/admissions/*`) is
**Proposed** in the nhp design and not yet deployed. `EnterPortal` therefore builds
and posts a structurally correct qv2 knock, and the pure steps (parse → verify →
derive serverId → assemble packet) are unit-tested offline against the vectors, but
a **live** end-to-end qv2 resolve cannot round-trip until the qv2 NHP server
contract ships. This is called out in the `EnterPortal` godoc and tracked in the
roadmap; the verb and wire construction are ready so the live path is a server-side
turn-up, not an SDK change.

## Conformance vectors

`qv2/testdata` vendors the nhp-owned, language-agnostic qURL v2 conformance
artifact (`qv2_conformance_vectors.json`) plus the composed issuer-signature golden
file (`issuer_signature_vectors.json`). The loader is structured so adopting an
updated artifact is a **file swap**. The current copies are vendored from an
in-flight nhp branch and are marked **provisional** pending the merged full-class
artifact; re-vendor verbatim on merge.

## Development

```sh
go vet ./...
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs exactly this on every PR and on `main`.

## Roadmap

The foundation lands the verify/knock core; `CreatePortal` (issuer-side mint) lands
on top of it. The following are the remaining stacked follow-ups, filed as issues:

- **Credential provider** — pluggable trust-anchor / relay-allowlist resolution,
  including the production KMS-backed `qv2.Signer` for `CreatePortal`.
- **REST client** — typed client for the qurl-service control-plane API.
