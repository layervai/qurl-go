package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/layervai/qurl-go/qv2"
)

// CreatePortal is the issuer-side mint verb: the inverse of EnterPortal. Where
// EnterPortal opens an existing qURL link, CreatePortal produces one — it
// assembles and signs the qURL v2 claims, generates the fresh per-qURL keypair
// whose secret rides in the fragment, and returns the
// https://qurl.link/#qv2.<claims>.<secret>.<sig> link. (The package doc lives in
// portal.go; this is the mint half of the same qurl entry surface.)
//
// The issuer signing key is never held here directly: signing goes through the
// qv2.Signer seam (KMS in production, qv2.LocalSigner for tests / self-custody
// integrations), so this verb has no AWS dependency and the credential-provider
// follow-up can supply a real KMS signer without touching this code. The signed
// claims bytes are handed verbatim to qv2.BuildFragment, so the bytes the issuer
// signs are exactly the bytes a verifier (qv2.ParseAndVerify / EnterPortal)
// checks — mint and enter are symmetric by construction.

// LinkBaseURL is the canonical qURL link origin CreatePortal prepends to the
// fragment. The credential, claims, and signature all live in the fragment after
// '#', which browser semantics keep out of the HTTP request to this origin.
const LinkBaseURL = "https://qurl.link/"

// b64url is the single pinned qURL wire encoding (unpadded base64url). The secret
// part (Part 2) is assembled here with the stdlib encoder rather than widening the
// qv2 public surface; RawURLEncoding's output is byte-identical to qv2's internal
// encoder. BuildFragment validates only the OUTER Part-2 envelope (it decodes the
// base64url blob; it does not re-run the secret schema), so the inner
// qurl_user_private_key_b64 field is kept symmetric with the verify side by the
// shared qv2.Secret struct (the field name cannot drift without a compile break)
// and by the create→verify round-trip test, not by a BuildFragment re-check.
// Owning the Part-2 codec in one qv2 place (mirroring parseSecret) is deferred —
// see qurl-go#6.
var b64url = base64.RawURLEncoding

// CreateParams are the issuer-supplied inputs to a mint. The verb owns everything
// a caller must NOT choose: the version and issuer (pinned by qv2), the kid
// (stamped from the signer), the issuer signature, and the per-qURL keypair
// (freshly generated each call). A caller supplies only the bindings and the
// signed validity window.
type CreateParams struct {
	// CellPublicKey is the raw 32-byte X25519 NHP cell (server static) public key.
	// It defines the relay routing target and the Noise server identity. REQUIRED.
	CellPublicKey []byte
	// RelayURL is the HTTPS relay origin the viewer knocks. It is part of the
	// signed envelope but is acted on by a verifier only after the signature
	// verifies. REQUIRED.
	RelayURL string
	// ResourcePublicKey is the protected-resource public key in DER SPKI form (the
	// NHP knock resource identity / AC routing key, e.g. a P-256 KMS key).
	// REQUIRED.
	ResourcePublicKey []byte
	// CellID is the one optional claim: a human/config label for the cell. Empty
	// omits it from the signed claims (absent, not "").
	CellID string
	// JTI is the unique qURL id stamped into the claims (the jti claim). REQUIRED:
	// it is part of the signed anti-tamper envelope and the per-link identifier.
	JTI string

	// IssuedAt, NotBefore, Expiry are the signed validity window as Unix seconds
	// (the iat / nbf / exp claims). All three are REQUIRED and must satisfy the
	// clock-free ordering bounds iat<=exp and nbf<=exp (the strict parser enforces
	// them at sign time, so a nonsensical window fails the mint rather than
	// producing an artifact no verifier accepts). Liveness vs the wall clock is the
	// admission layer's concern, not the mint's.
	IssuedAt  int64
	NotBefore int64
	Expiry    int64
}

// ErrInvalidCreateParams is returned when CreateParams is missing a required
// binding before any signing is attempted. Claim-shape faults (key length, time
// ordering, ...) surface from qv2.SignClaims as wrapped qv2.ErrStrictParse, so a
// caller can match the strict-parse contract directly.
var ErrInvalidCreateParams = errors.New("qurl: invalid CreatePortal params")

// CreatePortal mints a qURL v2 link. It generates a fresh per-qURL X25519 keypair
// (the private half becomes the fragment secret, the public half is bound into
// the signed claims), assembles the claims, signs them through the issuer Signer
// seam, and returns the full https://qurl.link/#qv2.<claims>.<secret>.<sig> link.
//
// Symmetry guarantee: the returned link parses and verifies under
// qv2.ParseAndVerify / qv2.FragmentFromLinkAndVerify / EnterPortalWith against a
// trust store holding the signer's public key. CreatePortal validates the claims
// through the same strict parser those verifiers use BEFORE signing, so a mint
// that would not verify fails here instead of emitting a bad link.
func CreatePortal(ctx context.Context, signer qv2.Signer, p CreateParams) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("%w: signer must not be nil", ErrInvalidCreateParams)
	}
	if err := p.validate(); err != nil {
		return "", err
	}

	// Generate the fresh per-qURL X25519 identity. crypto/ecdh clamps the scalar
	// and gives both raw halves: the private 32 bytes ride in the secret, the
	// public 32 bytes are bound into the signed claims as the qURL agent identity.
	userKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("qurl: generate per-qURL key: %w", err)
	}

	claims := &qv2.Claims{
		V:                    qv2.Version,
		Iss:                  qv2.Issuer,
		Iat:                  p.IssuedAt,
		Nbf:                  p.NotBefore,
		Exp:                  p.Expiry,
		Jti:                  p.JTI,
		CellPublicKeyB64:     b64url.EncodeToString(p.CellPublicKey),
		CellID:               p.CellID,
		RelayURL:             p.RelayURL,
		ResourcePublicKeyB64: b64url.EncodeToString(p.ResourcePublicKey),
		QurlUserPublicKeyB64: b64url.EncodeToString(userKey.PublicKey().Bytes()),
	}

	// Sign the EXACT marshaled claims bytes through the seam. SignClaims stamps the
	// signer kid, strict-validates the bytes, and returns the canonical Part-1
	// string alongside the raw 64-byte low-S signature.
	//
	// qv2 errors from SignClaims and BuildFragment below are returned VERBATIM (no
	// qurl: wrap) so callers keep matching the qv2 sentinels directly —
	// errors.Is(err, qv2.ErrStrictParse) for an invalid claim window/shape, etc. The
	// keygen/secret errors above carry no such sentinel, so those are qurl:-wrapped.
	claimsB64, rawSig, err := qv2.SignClaims(ctx, signer, claims)
	if err != nil {
		return "", err
	}

	secretB64, err := buildSecretB64(userKey.Bytes())
	if err != nil {
		return "", err
	}

	// BuildFragment takes claimsB64 verbatim as Part 1, so the transmitted bytes
	// equal the signed bytes. It re-decodes the parts and re-validates the raw
	// signature, so it can never emit a body ParseFragment would reject.
	body, err := qv2.BuildFragment(claimsB64, secretB64, rawSig)
	if err != nil {
		return "", err
	}
	return LinkBaseURL + "#" + body, nil
}

// validate checks the issuer-supplied bindings are PRESENT before any keygen or
// signing, so every missing-required-input fault is one error class
// (ErrInvalidCreateParams) a caller can match with a single errors.Is. The
// presence checks cover all required inputs, including the three time fields
// (a zero Unix second is treated as "omitted"). The DEEP value rules — key
// lengths, version pin, the iat<=exp / nbf<=exp ordering bounds — are left to
// qv2.SignClaims's strict-parse-before-sign, which surfaces them as
// qv2.ErrStrictParse; validate deliberately does not duplicate them.
func (p CreateParams) validate() error {
	if len(p.CellPublicKey) == 0 {
		return fmt.Errorf("%w: CellPublicKey is required", ErrInvalidCreateParams)
	}
	if p.RelayURL == "" {
		return fmt.Errorf("%w: RelayURL is required", ErrInvalidCreateParams)
	}
	if len(p.ResourcePublicKey) == 0 {
		return fmt.Errorf("%w: ResourcePublicKey is required", ErrInvalidCreateParams)
	}
	if p.JTI == "" {
		return fmt.Errorf("%w: JTI is required", ErrInvalidCreateParams)
	}
	// Time fields: a zero value means the caller omitted them (Unix second 0 is not
	// a usable qURL window). Catch them here as a missing-input fault rather than
	// letting the strict parser's required-and-non-zero rule surface them as a
	// different error class. Ordering (iat<=exp, nbf<=exp) stays in the parser.
	if p.IssuedAt == 0 {
		return fmt.Errorf("%w: IssuedAt is required", ErrInvalidCreateParams)
	}
	if p.NotBefore == 0 {
		return fmt.Errorf("%w: NotBefore is required", ErrInvalidCreateParams)
	}
	if p.Expiry == 0 {
		return fmt.Errorf("%w: Expiry is required", ErrInvalidCreateParams)
	}
	return nil
}

// buildSecretB64 assembles fragment Part 2: base64url of the JSON
// {"qurl_user_private_key_b64":"<32-byte key>"}. Part 2 is base64url-encoded JSON,
// not the raw key bytes, mirroring exactly what the verify path's secret parser
// (qv2 parseSecret) consumes.
func buildSecretB64(privateKey []byte) (string, error) {
	raw, err := json.Marshal(qv2.Secret{QurlUserPrivateKeyB64: b64url.EncodeToString(privateKey)})
	if err != nil {
		return "", fmt.Errorf("qurl: marshal secret: %w", err)
	}
	return b64url.EncodeToString(raw), nil
}
