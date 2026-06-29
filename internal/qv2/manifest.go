package qv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Discovery-manifest signature primitive.
//
// The credential-provider discovery path (qurl/discovery.go) can authenticate a
// non-secret published trust manifest in two ways: a PINNED sha256 of the exact
// manifest bytes, or a detached ISSUER SIGNATURE over those bytes. This file owns
// the SIGNED path's preimage so it can never collide with the qURL issuer-claims
// preimage.
//
// CRITICAL — separate domain. A manifest signature and a qURL claims signature are
// produced by the same kind of key (a P-256 issuer key) and verified with the same
// raw r||s / low-S machinery, so the ONLY thing keeping them non-interchangeable is
// the domain-separation prefix. manifestSigningInput uses its OWN prefix
// (ManifestDomainSeparationPrefix) and is computed by manifestSigningDigest, which
// is deliberately NOT signingDigest. A claims signature therefore can never verify
// as a manifest signature, and vice versa, even under the same kid. Do not route a
// manifest through signingDigest or a claim through manifestSigningDigest.

// ManifestDomainSeparationPrefix is the fixed signing-input prefix for the discovery
// manifest signature. It is distinct from domainSeparationPrefix (the qURL issuer
// claims prefix) so the two signature domains can never overlap. The signing input
// is this prefix + a single 0x00 byte + the exact manifest bytes.
const ManifestDomainSeparationPrefix = "NHP-QURL-V2-DISCOVERY-MANIFEST"

// manifestSigningInput builds the exact bytes a manifest signer signs and a
// verifier verifies: ManifestDomainSeparationPrefix + 0x00 + the exact manifest
// bytes (verbatim, never re-serialized). It mirrors signingInput's construction but
// in the manifest domain.
func manifestSigningInput(manifest []byte) []byte {
	prefix := []byte(ManifestDomainSeparationPrefix)
	out := make([]byte, 0, len(prefix)+1+len(manifest))
	out = append(out, prefix...)
	out = append(out, domainSeparator) // the same single 0x00 separator byte
	out = append(out, manifest...)
	return out
}

// manifestSigningDigest is the SHA-256 of the manifest signing input. It is the
// manifest-domain counterpart to signingDigest and MUST stay separate from it.
func manifestSigningDigest(manifest []byte) [32]byte {
	return sha256.Sum256(manifestSigningInput(manifest))
}

// VerifyManifestSignature verifies a detached issuer signature over the EXACT
// manifest bytes using pub, under the manifest signing domain. The signature must
// be the pinned wire form (64-byte raw r||s, low-S normalized, scalars in range) —
// the same wire contract as a qURL issuer signature, just over a different
// preimage. It returns nil on success or a wrapped ErrSignature.
//
// The manifest bytes MUST be the verbatim bytes that were fetched/pinned, never a
// re-serialization: re-canonicalizing a JSON manifest before verifying is the same
// signature-bypass vector the claims path guards against.
func VerifyManifestSignature(pub *ecdsa.PublicKey, manifest, rawSig []byte) error {
	if pub == nil {
		return fmt.Errorf("%w: nil manifest public key", ErrSignature)
	}
	if len(manifest) == 0 {
		return fmt.Errorf("%w: empty manifest bytes", ErrSignature)
	}
	r, s, err := rawToScalars(rawSig)
	if err != nil {
		return err
	}
	digest := manifestSigningDigest(manifest)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrSignature
	}
	return nil
}

// SignManifest is the manifest-domain counterpart to SignClaims: it signs the EXACT
// manifest bytes through the Signer seam and returns the pinned 64-byte raw r||s low-S
// wire signature that VerifyManifestSignature accepts. It is the supported way to
// produce a manifest signature, so a signer (KMS / local / file) cannot drift on the
// domain tag or the wire form — this function owns the manifest signing domain
// (manifestSigningDigest) and the DER->raw low-S normalization (derToRawLowS), exactly
// as SignClaims owns them for the claims domain.
//
// CRITICAL — separate domain. SignManifest signs manifestSigningDigest, NEVER
// signingDigest, so a signature it produces can only ever verify as a MANIFEST
// signature (VerifyManifestSignature) and never as a qURL claims signature, even under
// the same key. That separation is the load-bearing guard tested in both directions by
// TestManifestSignature_DomainSeparation; routing a manifest through SignClaims (or a
// claim through SignManifest) would break it.
//
// The manifestBytes MUST be the verbatim bytes that will be published/pinned, never a
// re-serialization — the verifier checks the received bytes without re-encoding, so a
// signature over canonicalized JSON would not verify against the transmitted bytes.
func SignManifest(ctx context.Context, signer Signer, manifestBytes []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("qurl: manifest signer must not be nil")
	}
	if len(manifestBytes) == 0 {
		return nil, errors.New("qurl: manifest bytes must not be empty")
	}
	digest := manifestSigningDigest(manifestBytes)
	der, err := signer.SignDigest(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("qurl: manifest signer SignDigest: %w", err)
	}
	if len(der) == 0 {
		return nil, errors.New("qurl: manifest signer returned an empty signature")
	}
	// KMS (and ecdsa.SignASN1) return ASN.1 DER and do not low-S normalize; convert to
	// the pinned fixed-width raw r||s low-S wire form here, in one place.
	rawSig, err := derToRawLowS(der)
	if err != nil {
		return nil, fmt.Errorf("qurl: convert manifest signature to wire format: %w", err)
	}
	return rawSig, nil
}

// ManifestDigest returns the sha256 of the EXACT manifest bytes — the value the
// PINNED discovery path compares against a configured pin. It is a plain content
// hash (no domain prefix): a pin authenticates "these exact bytes" by identity, so
// it needs no domain separation the way a signature does. Returned as a 32-byte
// array so callers compare in constant time without hex round-tripping.
func ManifestDigest(manifest []byte) [32]byte {
	return sha256.Sum256(manifest)
}
