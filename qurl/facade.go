package qurl

// Single public front door. Everything a qURL integration needs is reachable from
// this one package: minting links (CreatePortal), opening them (EnterPortal), the
// issuer signing seam, the trust store and relay allowlist, link verification, and
// the typed errors to match on. The cryptographic core lives in an internal package;
// these aliases and wrappers re-export exactly the surface callers need, so you never
// import anything but qurl.

import (
	"context"
	"crypto/ecdsa"

	// Aliased to `core` so the re-exported type aliases and error vars below render
	// as `= core.X` on pkg.go.dev rather than surfacing the internal package name.
	core "github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
)

// --- core types ---

// Signer is the issuer signing seam used by CreatePortal. Production binds it to a
// KMS- or HSM-resident P-256 key; LocalSigner is the software-key implementation for
// tests and self-custody. Implementations sign the digest they are handed and must
// not recompute it.
type Signer = core.Signer

// LocalSigner is an in-process Signer backed by a software-resident P-256 key. Use it
// for local development and tests; production custody belongs in a KMS/HSM Signer.
type LocalSigner = core.LocalSigner

// TrustStore resolves a link's key id (kid) to the issuer public key used to verify
// its signature. Build one with NewTrustStore or NewTrustStoreFromDER.
type TrustStore = core.TrustStore

// RelayAllowlist is the set of relay host[:port] origins a verified link may target.
// Build one with NewRelayAllowlist. An empty allowlist rejects every link.
type RelayAllowlist = core.RelayAllowlist

// Claims is the verified claim set carried by a qURL link (relay, keys, validity
// window, id). Read it from the Fragment returned by VerifyLink.
type Claims = core.Claims

// Secret is the one-time per-link credential carried by a qURL link. It is the type of
// Fragment.Secret; most callers never construct it (CreatePortal mints it and
// EnterPortal consumes it), but it is re-exported so Fragment.Secret has a nameable type.
type Secret = core.Secret

// Fragment is a parsed, verified qURL link: its Claims and Secret plus the exact
// signed bytes. VerifyLink returns one.
type Fragment = core.Fragment

// RelayError is a transport fault talking to the relay (before any authenticated
// server decision). Match it with errors.As to distinguish transport faults from an
// authenticated ServerDenyError.
type RelayError = relayknock.RelayError

// --- signing (issuer side) ---

// GenerateLocalSigner mints a fresh random P-256 issuer key under kid. It is a
// convenience for tests and local development; a generated key is ephemeral and is
// not a production custody model.
func GenerateLocalSigner(kid string) (*LocalSigner, error) {
	return core.GenerateLocalSigner(kid)
}

// NewLocalSigner builds a LocalSigner from an existing P-256 private key and the kid
// verifiers resolve to its public half. It rejects a nil key, a non-P-256 curve, and
// an empty kid.
func NewLocalSigner(priv *ecdsa.PrivateKey, kid string) (*LocalSigner, error) {
	return core.NewLocalSigner(priv, kid)
}

// --- trust anchors (opener side) ---

// NewTrustStore builds a trust store from a kid -> P-256 public key map. The map is
// copied; every key must be a non-nil P-256 public key.
func NewTrustStore(keys map[string]*ecdsa.PublicKey) (*TrustStore, error) {
	return core.NewTrustStore(keys)
}

// NewTrustStoreFromDER builds a trust store from kid -> DER SPKI public-key bytes —
// the form AWS KMS GetPublicKey returns and the form persisted in config. This is the
// usual way to load issuer anchors.
func NewTrustStoreFromDER(derByKID map[string][]byte) (*TrustStore, error) {
	return core.NewTrustStoreFromDER(derByKID)
}

// ParseP256PublicKeyDER parses a DER SPKI public key and asserts it is on the P-256
// curve. Handy for turning a single issuer key blob into a *ecdsa.PublicKey for
// NewTrustStore.
func ParseP256PublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	return core.ParseP256PublicKeyDER(der)
}

// NewRelayAllowlist builds a relay allowlist from host or host:port entries. A bare
// host matches any port; a host:port entry matches only that exact pair. An empty
// allowlist rejects every link (fail closed).
func NewRelayAllowlist(entries []string) *RelayAllowlist {
	return core.NewRelayAllowlist(entries)
}

// --- verification ---

// VerifyLink parses a qURL link and verifies its issuer signature against the trust
// store, returning the verified Fragment. It is the one-call way to validate a link
// without opening it; EnterPortal performs this same check as its first step. A
// tampered, forged, or untrusted link fails closed here (see ErrSignature /
// ErrUnknownKID). Validate the relay separately with ValidateRelayURL before acting
// on it.
func VerifyLink(link string, trust *TrustStore) (*Fragment, error) {
	return core.FragmentFromLinkAndVerify(link, trust)
}

// ValidateRelayURL checks a verified link's relay against the HTTPS requirement and
// the allowlist. Call it only after VerifyLink succeeds (the relay is
// attacker-controlled until the signature verifies).
func ValidateRelayURL(relayURL string, allow *RelayAllowlist) error {
	return core.ValidateRelayURL(relayURL, allow)
}

// VerifyRawIssuerSignature verifies a raw 64-byte r||s low-S issuer signature over the
// exact base64url claims bytes under pub. Advanced: this is the low-level primitive
// behind VerifyLink, exposed for cross-language conformance tooling. Most callers want
// VerifyLink instead.
func VerifyRawIssuerSignature(pub *ecdsa.PublicKey, claimsB64 string, rawSig []byte) error {
	return core.VerifyRawIssuerSignature(pub, claimsB64, rawSig)
}

// --- discovery manifests (publishing side) ---

// ManifestDigest returns the SHA-256 of the exact manifest bytes — the value to set as
// DiscoveryConfig.PinSHA256 when pinning a published trust manifest. Hash the decoded
// manifest the publisher signs and serves, not the envelope.
func ManifestDigest(manifest []byte) [32]byte {
	return core.ManifestDigest(manifest)
}

// SignManifest signs a discovery trust manifest with an issuer Signer, returning the
// detached raw r||s signature to place in the envelope's sig_b64. It is the
// publishing-side counterpart to the signed-manifest path NewDiscoveryProvider
// verifies; manifest signing uses a separate signing domain from qURL link claims.
func SignManifest(ctx context.Context, signer Signer, manifestBytes []byte) ([]byte, error) {
	return core.SignManifest(ctx, signer, manifestBytes)
}

// VerifyManifestSignature verifies a detached manifest signature (the envelope's
// sig_b64) over the exact manifest bytes under pub, in the manifest signing domain.
// NewDiscoveryProvider does this for you when consuming a signed manifest; it's
// exposed so a publisher can self-check a manifest it just signed.
func VerifyManifestSignature(pub *ecdsa.PublicKey, manifest, rawSig []byte) error {
	return core.VerifyManifestSignature(pub, manifest, rawSig)
}

// --- error sentinels (match with errors.Is) ---

var (
	// ErrSignature is returned when a link's issuer signature does not verify
	// (forged or tampered, or signed by a key not in your trust store's value for
	// that kid).
	ErrSignature = core.ErrSignature
	// ErrUnknownKID is returned when a link's kid is not in the trust store.
	ErrUnknownKID = core.ErrUnknownKID
	// ErrRelayURL is returned when a link's relay is not HTTPS or not on the allowlist.
	ErrRelayURL = core.ErrRelayURL
	// ErrStrictParse is returned for any strict-schema violation in a link's claims
	// (duplicate key, unknown field, null, wrong type, out-of-range time, ...).
	ErrStrictParse = core.ErrStrictParse
	// ErrFragment is returned when a link's shape is invalid (wrong prefix, wrong part
	// count, empty part).
	ErrFragment = core.ErrFragment
	// ErrEncoding is returned when a part of a link is not valid unpadded base64url.
	ErrEncoding = core.ErrEncoding
	// ErrKeyLength is returned when a decoded key field in a link is not its expected
	// size.
	ErrKeyLength = core.ErrKeyLength
)
