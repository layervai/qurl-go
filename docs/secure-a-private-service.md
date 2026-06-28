# Secure a private service

The golden path: give a client or AI agent **authenticated, time-bound access to a
private MCP server (or any service) without exposing it** — no inbound port, no VPN, no
shared key. This guide walks the whole thing end to end and marks each step **✅ runs
today** (works with this SDK alone) or **🚧 needs your qURL deployment** (the admission
service + relay, which you operate or the hosted onramp provides).

If you just want to see signing and verification work offline, start with the
[Quickstart](../README.md#quickstart). This guide is the full picture.

## The shape

```
 resource owner                              client / agent
 ──────────────                              ──────────────
 CreatePortal ──► qURL link  ──(you share)──►  EnterPortal
                                                   │  outbound knock
                                                   ▼
                                  relay ──► NHP cell ──► your private service
                                  (opens access for the caller's egress IP)
```

Three pieces are in play:

- your **private service** — the MCP server, API, or resource you don't want exposed,
- an **NHP cell** in front of it — default-deny; it ignores all traffic until an
  authorized knock,
- a **relay** — the public endpoint the client posts its knock to.

The SDK gives you the two verbs (`CreatePortal`, `EnterPortal`); the cell + relay are
your qURL deployment.

## 1. Put your service behind NHP · 🚧 needs your qURL deployment

Your service runs with **no inbound ports open**. In front of it sits an NHP cell that
drops every packet until it sees an authorized knock. Standing up the cell + relay is a
deployment/infra step (or handled by the hosted onramp) — not something the SDK does.

What you get out of this step, to use below:

- the cell's **X25519 public key** (`CellPublicKey`),
- the relay's **HTTPS URL** (`RelayURL`),
- your resource's **P-256 public key** in DER SPKI form (`ResourcePublicKey`).

> Until you have a deployed cell + relay (or the hosted onramp), you can still mint and
> verify links offline — only the live *open* in step 3 requires this piece.

## 2. Mint an access link · ✅ runs today

The resource owner mints a short-lived link with `CreatePortal` and hands it to the
client (email, QR, chat, an API response — anything; the credential rides in the URL
fragment and is single-use + expiring).

```go
signer, _ := qurl.GenerateLocalSigner("issuer-key-2026") // dev; use KMS in prod
now := time.Now().Unix()

link, err := qurl.CreatePortal(ctx, signer, qurl.CreateParams{
	CellPublicKey:     cellPub,     // from step 1
	RelayURL:          "https://relay.example.com",
	ResourcePublicKey: resourceDER, // from step 1
	JTI:               "qurl_01J…", // unique per link
	IssuedAt:          now,
	NotBefore:         now,
	Expiry:            now + 300,   // keep it short
})
```

Keep windows short — minutes, not days. Production signing belongs in KMS/HSM behind the
`qurl.Signer` seam; see the **[issuing links guide](issuing-links.md)** for custody,
rotation, and the full `CreateParams` reference.

## 3. Open the link from the client / agent · 🚧 needs deployed admission + trust config

The client verifies the issuer signature, then knocks the relay to open access. Install
your deployment's trust anchors once at startup, then open any link:

```go
// once, at startup — the issuer keys + relays your deployment trusts:
provider, _ := qurl.NewStaticProvider(trust, allowlist)
qurl.SetDefaultProvider(provider)

// per link:
handle, err := qurl.EnterPortal(ctx, link)
if err != nil {
	// errors.Is(err, qurl.ErrNotConfigured) → no provider installed
	// errors.Is(err, qurl.ErrSignature)     → forged/tampered link
	// see the opening-links guide for the full taxonomy
}
fmt.Println("reachable at:", handle.RedirectURL)
```

Without a provider installed this fails closed with `qurl.ErrNotConfigured`. The live
knock completes once your deployment's qURL admission is in place. Building the trust
store and allowlist is covered in the **[opening links guide](opening-links.md)**.

## 4. Reach the resource — mind the egress IP · 🚧 with the live open

The NHP server opened access for the **source IP of your knock**. Make your request to
`handle.RedirectURL` **from that same IP** — on a single host it's automatic; behind a
rotating-egress NAT or proxy pool, pin the knock and the request to the same exit (see
[the same-egress-IP rule](opening-links.md#the-same-egress-ip-rule)).

```go
resp, err := http.Get(handle.RedirectURL) // same egress IP as the knock
```

## Built for agents

This path is designed so a non-expert builder — or an AI agent acting for one — can wire
it in with **zero NHP knowledge**: one import (`qurl`), two verbs, typed errors an agent
can branch on, and a credential that lives in the link rather than in side-channel
config. Steps 2 and the verification half run from this SDK alone today; the live open
(steps 1, 3, 4) lights up with your qURL deployment or the hosted onramp.

## Where to go next

- **[Issuing links](issuing-links.md)** — signing custody (KMS), validity windows, key rotation
- **[Opening links](opening-links.md)** — providers, the relay allowlist, error handling, retries
- **[Status — what runs today](../README.md#status--what-runs-today)**
