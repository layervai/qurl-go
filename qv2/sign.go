package qv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

// Issuer-side signing for qURL v2: the signer seam plus SignClaims, the mint
// counterpart to the verify path in fragment.go / signature.go.
//
// The two security-critical primitives stay private to this package and are
// applied in exactly one place each: signingDigest (the domain-separated SHA-256
// preimage every verifier shares) and derToRawLowS (the DER -> fixed-width raw
// r||s low-S conversion verifiers require). The Signer seam therefore sits at the
// DIGEST boundary — it signs 32 opaque digest bytes and returns ASN.1 DER, the
// native output of both AWS KMS Sign (MessageType=DIGEST) and ecdsa.SignASN1.
// SignClaims, not the signer, computes the digest and normalizes to low-S, so a
// KMS, local, or file signer physically cannot drift on the domain tag or emit a
// non-low-S wire signature. This mirrors the qurl-service reference
// (internal/qurlv2/issuer.go) with the KMS client swapped for the interface, and
// keeps AWS out of qv2 — the SDK core stays standard-library only.

// Signer signs the qURL v2 issuer-signature digest. It is the credential seam:
// production binds it to a KMS-resident ECC_NIST_P256 key (filled in by the
// credential-provider follow-up), tests and simple integrations use LocalSigner,
// and a file/HSM signer can implement the same two methods. Implementations sign
// the digest they are handed and MUST NOT recompute it or wrap it — qv2 owns the
// domain-separated preimage so every signer and verifier provably agree on it.
type Signer interface {
	// KID returns the published trust-store key id this signer stamps into claims.
	// Verifiers resolve it to the public half and reject unknown kids.
	KID() string
	// SignDigest signs the 32-byte SHA-256 signing digest and returns an ASN.1 DER
	// ECDSA signature over the pinned P-256 curve. The signature need NOT be low-S
	// normalized: SignClaims applies derToRawLowS to the result. The digest is the
	// only message the signer sees, so it cannot influence the preimage.
	SignDigest(ctx context.Context, digest []byte) (derSig []byte, err error)
}

// SignClaims is the issuance entry point: it serializes claims to the canonical
// qURL v2 wire encoding, signs the exact bytes that will appear as fragment Part
// 1, and returns both the encoded claims part and the pinned 64-byte raw r||s
// low-S signature. The returned claimsB64 MUST be the value embedded as Part 1 so
// the signed bytes and the transmitted bytes are identical — pass it straight to
// BuildFragment.
//
// It stamps signer.KID() onto a COPY of claims (the caller's struct is never
// mutated) so the signature and the kid that resolves the verifying key always
// agree. The marshaled bytes are run through the SAME strict parser verifiers use
// BEFORE signing, so the issuer never emits — or burns a KMS Sign on — an artifact
// a verifier would reject (wrong v/iss, zero/out-of-range times, empty/wrong-length
// keys, nbf>exp, ...). That validation is fail-closed, not a signature bypass: it
// is one shared definition of "valid claims" for signer and verifier.
//
// CANONICAL ENCODING: the qURL v2 wire encoding of claims is, by definition,
// whatever this function emits — currently json.Marshal, which HTML-escapes '<',
// '>', and '&'. This is safe precisely because the signature is over the
// transmitted bytes and every verifier checks those received bytes WITHOUT
// re-serializing (see fragment.go Verify). A verifier that re-marshals claims and
// verifies the re-encoding would diverge from the bytes signed here and silently
// break — do not add one.
func SignClaims(ctx context.Context, signer Signer, claims *Claims) (claimsB64 string, rawSig []byte, err error) {
	if signer == nil {
		return "", nil, errors.New("qv2: signer must not be nil")
	}
	if claims == nil {
		return "", nil, errors.New("qv2: claims must not be nil")
	}
	kid := signer.KID()
	if kid == "" {
		return "", nil, errors.New("qv2: signer kid must not be empty")
	}

	stamped := *claims
	stamped.Kid = kid
	encoded, err := json.Marshal(stamped)
	if err != nil {
		return "", nil, fmt.Errorf("qv2: marshal claims: %w", err)
	}
	// Validate the EXACT bytes about to be signed through the verifier's strict
	// parser. Runs before SignDigest so invalid claims never reach the signer.
	if _, err := parseClaims(encoded); err != nil {
		return "", nil, fmt.Errorf("qv2: refusing to sign invalid claims: %w", err)
	}

	claimsB64 = encodeB64(encoded)
	digest := signingDigest(claimsB64)
	der, err := signer.SignDigest(ctx, digest[:])
	if err != nil {
		return "", nil, fmt.Errorf("qv2: signer SignDigest: %w", err)
	}
	if len(der) == 0 {
		return "", nil, errors.New("qv2: signer returned an empty signature")
	}
	// KMS (and ecdsa.SignASN1) return ASN.1 DER and do not low-S normalize. Convert
	// to the pinned fixed-width raw r||s low-S wire form here, in one place.
	rawSig, err = derToRawLowS(der)
	if err != nil {
		return "", nil, fmt.Errorf("qv2: convert signature to wire format: %w", err)
	}
	return claimsB64, rawSig, nil
}

// LocalSigner is an in-process Signer backed by a software-resident P-256 private
// key. It is the KMS-free signer named in the design (KMS / local / file): it
// makes SignClaims and CreatePortal usable in tests, examples, and integrations
// that hold their own issuer key, without an AWS dependency. Production custody
// belongs in KMS — a leaked process must not yield the issuer key — so prefer a
// KMS-backed Signer (credential-provider follow-up) for real issuance.
type LocalSigner struct {
	priv *ecdsa.PrivateKey
	kid  string
}

// NewLocalSigner builds a LocalSigner from an existing P-256 private key and the
// kid verifiers resolve to its public half. It rejects a nil key, a non-P-256
// curve, and an empty kid so a misconfigured signer fails at construction rather
// than emitting unverifiable artifacts.
func NewLocalSigner(priv *ecdsa.PrivateKey, kid string) (*LocalSigner, error) {
	if priv == nil {
		return nil, errors.New("qv2: local signer private key must not be nil")
	}
	if priv.Curve != curve {
		return nil, errors.New("qv2: local signer key is not on the P-256 curve")
	}
	if kid == "" {
		return nil, errors.New("qv2: local signer kid must not be empty")
	}
	return &LocalSigner{priv: priv, kid: kid}, nil
}

// GenerateLocalSigner mints a fresh random P-256 issuer key under kid. It is a
// convenience for tests and local development; a generated key is ephemeral and
// is NOT a production custody model.
func GenerateLocalSigner(kid string) (*LocalSigner, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("qv2: generate local signer key: %w", err)
	}
	return NewLocalSigner(priv, kid)
}

// KID returns the issuer key id this signer stamps into claims.
func (s *LocalSigner) KID() string { return s.kid }

// SignDigest signs the digest with the local key and returns ASN.1 DER, matching
// the seam contract (KMS-shaped output). Low-S normalization is SignClaims's job.
func (s *LocalSigner) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, digest)
}

// PublicKeyDER returns the signer's issuer public key in DER SPKI form — the
// trust-store load form (NewTrustStoreFromDER) and the shape AWS KMS GetPublicKey
// returns. Use it to build the verifier trust store for keys minted by this
// signer.
func (s *LocalSigner) PublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
}
