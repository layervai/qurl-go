package qurl

// Single public front door. Everything a qURL integration needs is reachable
// from this one package: platform resource and portal creation, programmatic
// opening, advanced signed-fragment helpers, and the typed errors to match on.
// The cryptographic core lives in an internal package; these wrappers expose
// exactly the surface callers need, so you never import anything but qurl.

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/layervai/qurl-go/internal/qv2"
)

// --- core types ---

// Signer is the issuer signing seam used by CreatePortalWithParams. Production
// protocol integrations bind it to a KMS- or HSM-resident P-256 key;
// LocalSigner is the software-key implementation for tests and self-custody.
// Implementations sign the digest they are handed and must not recompute it.
type Signer interface {
	// KID returns the published trust-store key id this signer stamps into claims.
	KID() string
	// SignDigest signs the 32-byte SHA-256 signing digest and returns an ASN.1 DER
	// ECDSA signature over P-256.
	SignDigest(ctx context.Context, digest []byte) (derSig []byte, err error)
}

// LocalSigner is an in-process Signer backed by a software-resident P-256 key. Use it
// for local development and tests; production custody belongs in a KMS/HSM Signer.
type LocalSigner struct {
	inner *qv2.LocalSigner
}

// KID returns the issuer key id this signer stamps into claims.
func (s *LocalSigner) KID() string {
	if s == nil || s.inner == nil {
		return ""
	}
	return s.inner.KID()
}

// SignDigest signs the digest with the local key and returns ASN.1 DER.
func (s *LocalSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if s == nil || s.inner == nil {
		return nil, errors.New("qurl: nil local signer")
	}
	return s.inner.SignDigest(ctx, digest)
}

// PublicKeyDER returns the signer's issuer public key in DER SPKI form, the shape
// accepted by NewTrustStoreFromDER.
func (s *LocalSigner) PublicKeyDER() ([]byte, error) {
	if s == nil || s.inner == nil {
		return nil, errors.New("qurl: nil local signer")
	}
	return s.inner.PublicKeyDER()
}

// TrustStore resolves a link's key id (kid) to the issuer public key used to verify
// its signature. LayerV opener config provides these keys; build one manually with
// NewTrustStore or NewTrustStoreFromDER for tests and pinned applications.
type TrustStore struct {
	inner *qv2.TrustStore
}

// RelayAllowlist is the set of qURL platform access hosts a verified link may
// target. The name matches the qURL wire format. Build one with NewRelayAllowlist.
// An empty allowlist rejects every link.
type RelayAllowlist struct {
	inner *qv2.RelayAllowlist
}

// Claims is the verified claim set carried by a qURL link. Read it from the
// Fragment returned by VerifyLink.
type Claims struct {
	V   int    `json:"v"`
	Iss string `json:"iss"`
	Kid string `json:"kid"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`

	CellPublicKeyB64 string `json:"cell_public_key_b64"`
	CellID           string `json:"cell_id,omitempty"`
	RelayURL         string `json:"relay_url"`

	ResourcePublicKeyB64 string `json:"resource_public_key_b64"`
	QurlUserPublicKeyB64 string `json:"qurl_user_public_key_b64"`
}

// Secret is the one-time per-link credential carried by a signed qURL fragment.
// It is the type of Fragment.Secret; most callers never construct it, but it is
// exported so Fragment.Secret has a nameable type.
type Secret struct {
	QurlUserPrivateKeyB64 string `json:"qurl_user_private_key_b64"`
}

// Fragment is a parsed, verified qURL link: its Claims and Secret plus the exact
// signed bytes. VerifyLink returns one.
type Fragment struct {
	// ClaimsB64 is the exact unpadded-base64url claims string as it appeared in the
	// fragment. Signature verification uses this, not a re-serialization of Claims.
	ClaimsB64 string
	// SecretB64 is the exact unpadded-base64url secret string as it appeared in the
	// fragment.
	SecretB64 string
	// SigB64 is the exact unpadded-base64url issuer signature as it appeared in the
	// fragment.
	SigB64 string
	// Claims is the strict-parsed, verified claim set.
	Claims *Claims
	// Secret is the strict-parsed per-link credential.
	Secret *Secret
}

// RelayError is a network fault reaching the qURL platform before any
// authenticated platform decision. Match it with errors.As to distinguish network
// faults from an authenticated ServerDenyError. The name matches the qURL wire
// format.
type RelayError struct {
	Status int
	Msg    string
}

func (e *RelayError) Error() string {
	if e == nil {
		return "qurl: platform access error"
	}
	return e.Msg
}

// --- signing (issuer side) ---

// GenerateLocalSigner mints a fresh random P-256 issuer key under kid. It is a
// convenience for tests and local development; a generated key is ephemeral and is
// not a production custody model.
func GenerateLocalSigner(kid string) (*LocalSigner, error) {
	signer, err := qv2.GenerateLocalSigner(kid)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{inner: signer}, nil
}

// NewLocalSigner builds a LocalSigner from an existing P-256 private key and the kid
// verifiers resolve to its public half. It rejects a nil key, a non-P-256 curve, and
// an empty kid.
func NewLocalSigner(priv *ecdsa.PrivateKey, kid string) (*LocalSigner, error) {
	signer, err := qv2.NewLocalSigner(priv, kid)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{inner: signer}, nil
}

// --- opener config ---

// NewTrustStore builds a trust store from a kid -> P-256 public key map. The map
// is copied; every key must be a non-nil P-256 public key.
func NewTrustStore(keys map[string]*ecdsa.PublicKey) (*TrustStore, error) {
	trust, err := qv2.NewTrustStore(keys)
	if err != nil {
		return nil, err
	}
	return wrapTrustStore(trust), nil
}

// NewTrustStoreFromDER builds a trust store from kid -> DER SPKI public-key
// bytes, the usual form for persisted opener config.
func NewTrustStoreFromDER(derByKID map[string][]byte) (*TrustStore, error) {
	trust, err := qv2.NewTrustStoreFromDER(derByKID)
	if err != nil {
		return nil, err
	}
	return wrapTrustStore(trust), nil
}

// ParseP256PublicKeyDER parses a DER SPKI public key and asserts it is on the P-256
// curve. Handy for turning a single issuer key blob into a *ecdsa.PublicKey for
// NewTrustStore.
func ParseP256PublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	return qv2.ParseP256PublicKeyDER(der)
}

// NewRelayAllowlist builds a qURL platform endpoint allowlist from host or
// host:port entries. A bare host matches any port; a host:port entry matches only
// that exact pair. An empty allowlist rejects every link (fail closed).
func NewRelayAllowlist(entries []string) *RelayAllowlist {
	return wrapRelayAllowlist(qv2.NewRelayAllowlist(entries))
}

// --- verification ---

// VerifyLink parses a qURL link and verifies its issuer signature against the trust
// store, returning the verified Fragment. It is the one-call way to validate a link
// without opening it; EnterPortal performs this same check as its first step. A
// tampered, forged, or untrusted link fails closed here (see ErrSignature /
// ErrUnknownKID).
func VerifyLink(link string, trust *TrustStore) (*Fragment, error) {
	fragment, err := qv2.FragmentFromLinkAndVerify(link, trust.core())
	if err != nil {
		return nil, err
	}
	return wrapFragment(fragment), nil
}

// ValidateRelayURL checks a verified link's qURL platform access URL against the
// HTTPS requirement and the allowlist. Call it only after VerifyLink succeeds.
func ValidateRelayURL(relayURL string, allow *RelayAllowlist) error {
	return qv2.ValidateRelayURL(relayURL, allow.core())
}

// VerifyRawIssuerSignature verifies a raw 64-byte r||s low-S issuer signature over the
// exact base64url claims bytes under pub. Advanced: this is the low-level primitive
// behind VerifyLink, exposed for cross-language conformance tooling. Most callers want
// VerifyLink instead.
func VerifyRawIssuerSignature(pub *ecdsa.PublicKey, claimsB64 string, rawSig []byte) error {
	return qv2.VerifyRawIssuerSignature(pub, claimsB64, rawSig)
}

// --- discovery manifests (publishing side) ---

// ManifestDigest returns the SHA-256 of the exact manifest bytes, the value to set
// as DiscoveryConfig.PinSHA256 when pinning a published opener-config manifest.
func ManifestDigest(manifest []byte) [32]byte {
	return qv2.ManifestDigest(manifest)
}

// SignManifest signs a discovery trust manifest with an issuer Signer, returning the
// detached raw r||s signature to place in the envelope's sig_b64. It is the
// publishing-side counterpart to the signed-manifest path NewDiscoveryProvider
// verifies; manifest signing uses a separate signing domain from qURL link claims.
func SignManifest(ctx context.Context, signer Signer, manifestBytes []byte) ([]byte, error) {
	return qv2.SignManifest(ctx, signer, manifestBytes)
}

// VerifyManifestSignature verifies a detached manifest signature (the envelope's
// sig_b64) over the exact manifest bytes under pub, in the manifest signing domain.
// NewDiscoveryProvider does this for you when consuming a signed manifest; it's
// exposed so a publisher can self-check a manifest it just signed.
func VerifyManifestSignature(pub *ecdsa.PublicKey, manifest, rawSig []byte) error {
	return qv2.VerifyManifestSignature(pub, manifest, rawSig)
}

func wrapTrustStore(trust *qv2.TrustStore) *TrustStore {
	if trust == nil {
		return nil
	}
	return &TrustStore{inner: trust}
}

func (ts *TrustStore) core() *qv2.TrustStore {
	if ts == nil {
		return nil
	}
	return ts.inner
}

func wrapRelayAllowlist(allow *qv2.RelayAllowlist) *RelayAllowlist {
	if allow == nil {
		return nil
	}
	return &RelayAllowlist{inner: allow}
}

func (allow *RelayAllowlist) core() *qv2.RelayAllowlist {
	if allow == nil {
		return nil
	}
	return allow.inner
}

func wrapFragment(fragment *qv2.Fragment) *Fragment {
	if fragment == nil {
		return nil
	}
	return &Fragment{
		ClaimsB64: fragment.ClaimsB64,
		SecretB64: fragment.SecretB64,
		SigB64:    fragment.SigB64,
		Claims:    wrapClaims(fragment.Claims),
		Secret:    wrapSecret(fragment.Secret),
	}
}

func wrapClaims(claims *qv2.Claims) *Claims {
	if claims == nil {
		return nil
	}
	return &Claims{
		V:                    claims.V,
		Iss:                  claims.Iss,
		Kid:                  claims.Kid,
		Iat:                  claims.Iat,
		Nbf:                  claims.Nbf,
		Exp:                  claims.Exp,
		Jti:                  claims.Jti,
		CellPublicKeyB64:     claims.CellPublicKeyB64,
		CellID:               claims.CellID,
		RelayURL:             claims.RelayURL,
		ResourcePublicKeyB64: claims.ResourcePublicKeyB64,
		QurlUserPublicKeyB64: claims.QurlUserPublicKeyB64,
	}
}

func wrapSecret(secret *qv2.Secret) *Secret {
	if secret == nil {
		return nil
	}
	return &Secret{QurlUserPrivateKeyB64: secret.QurlUserPrivateKeyB64}
}

// Compile-time guards: the public Claims/Secret structs must stay field-identical to
// the internal core structs (a struct conversion only compiles when fields match —
// names, types, order; tags aside), so a core field change forces a matching change
// here rather than a silent shape mismatch. That wrapClaims/wrapSecret/wrapFragment
// actually populate every field is covered by TestVerifyLinkSurfacesAllClaimFields;
// Fragment's exported-field shape is guarded by TestFragmentExportedFieldsMirrorCore.
var (
	_ = qv2.Claims(Claims{})
	_ = qv2.Secret(Secret{})
)

// --- error sentinels (match with errors.Is) ---

var (
	// ErrSignature is returned when a link's issuer signature does not verify
	// (forged or tampered, or signed by a key not in your trust store's value for
	// that kid).
	ErrSignature error
	// ErrUnknownKID is returned when a link's kid is not in the trust store.
	ErrUnknownKID error
	// ErrRelayURL is returned when a link's qURL platform access URL is not HTTPS or
	// not on the allowlist.
	ErrRelayURL error
	// ErrStrictParse is returned for any strict-schema violation in a link's claims
	// (duplicate key, unknown field, null, wrong type, out-of-range time, ...).
	ErrStrictParse error
	// ErrFragment is returned when a link's shape is invalid (wrong prefix, wrong part
	// count, empty part).
	ErrFragment error
	// ErrEncoding is returned when a part of a link is not valid unpadded base64url.
	ErrEncoding error
	// ErrKeyLength is returned when a decoded key field in a link is not its expected
	// size.
	ErrKeyLength error
)

func init() {
	ErrSignature = qv2.ErrSignature
	ErrUnknownKID = qv2.ErrUnknownKID
	ErrRelayURL = qv2.ErrRelayURL
	ErrStrictParse = qv2.ErrStrictParse
	ErrFragment = qv2.ErrFragment
	ErrEncoding = qv2.ErrEncoding
	ErrKeyLength = qv2.ErrKeyLength
}
