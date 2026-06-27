package qv2

import (
	"fmt"
	"strings"
)

// Fragment is a parsed qURL v2 fragment. It retains ClaimsB64 — the EXACT
// base64url claims bytes from the wire — because the issuer signature MUST be
// verified over those received bytes, never over a re-serialization of Claims.
type Fragment struct {
	// ClaimsB64 is Part 1 verbatim: the exact unpadded-base64url claims string as
	// it appeared in the fragment. Signature verification uses this, not Claims.
	ClaimsB64 string
	// SecretB64 is Part 2 verbatim.
	SecretB64 string
	// SigB64 is Part 3 verbatim (the base64url raw r||s issuer signature).
	SigB64 string

	// Claims is the strict-parsed claim set. Present after a successful Parse.
	Claims *Claims
	// Secret is the strict-parsed secret. Present after a successful Parse.
	Secret *Secret
	// sig is the decoded 64-byte raw signature, cached for Verify.
	sig []byte
}

// fragmentParts is the exact number of dot-separated tokens in a qURL v2
// fragment: the literal "qv2" prefix plus three base64url parts.
const fragmentParts = 4

// ParseFragment parses the fragment body (everything after "#") into a Fragment.
// It enforces the wire shape — literal "qv2" prefix, exactly three non-empty
// base64url parts — and strict-parses the claims and secret JSON. It does NOT
// verify the issuer signature (call Verify) and does NOT validate relay_url
// (call ValidateRelayURL after Verify), matching the design's ordering: relay_url
// is acted on only after signature verification succeeds.
//
// The input may include a leading "#"; it is stripped. The input must NOT include
// the scheme/host (pass the fragment only). To accept a full qURL link, use
// FragmentFromLink first.
func ParseFragment(fragment string) (*Fragment, error) {
	body := strings.TrimPrefix(fragment, "#")

	parts := strings.Split(body, ".")
	if len(parts) != fragmentParts {
		return nil, fmt.Errorf("%w: expected %d dot-separated parts (qv2.<claims>.<secret>.<sig>), got %d",
			ErrFragment, fragmentParts, len(parts))
	}
	prefix, claimsB64, secretB64, sigB64 := parts[0], parts[1], parts[2], parts[3]

	if prefix != FragmentPrefix {
		return nil, fmt.Errorf("%w: prefix must be %q, got %q", ErrFragment, FragmentPrefix, prefix)
	}
	if claimsB64 == "" || secretB64 == "" || sigB64 == "" {
		return nil, fmt.Errorf("%w: claims/secret/sig parts must all be non-empty", ErrFragment)
	}

	frag := &Fragment{ClaimsB64: claimsB64, SecretB64: secretB64, SigB64: sigB64}

	claimsRaw, err := decodeB64(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("claims part: %w", err)
	}
	claims, err := parseClaims(claimsRaw)
	if err != nil {
		return nil, err
	}
	frag.Claims = claims

	secretRaw, err := decodeB64(secretB64)
	if err != nil {
		return nil, fmt.Errorf("secret part: %w", err)
	}
	secret, err := parseSecret(secretRaw)
	if err != nil {
		return nil, err
	}
	frag.Secret = secret

	sig, err := decodeB64(sigB64)
	if err != nil {
		return nil, fmt.Errorf("sig part: %w", err)
	}
	frag.sig = sig

	return frag, nil
}

// FragmentFromLink extracts the fragment body from a full qURL link
// (https://qurl.link/#qv2.<claims>.<secret>.<sig>) and parses it. It splits on
// the first "#" so a URL with query parameters before the fragment is handled
// correctly; a link with no "#" is rejected as a fragment-shape error. The
// signature is NOT verified here — call Verify / ParseAndVerify.
func FragmentFromLink(qurlLink string) (*Fragment, error) {
	hash := strings.IndexByte(qurlLink, '#')
	if hash < 0 {
		return nil, fmt.Errorf("%w: qURL link has no '#qv2.…' fragment", ErrFragment)
	}
	return ParseFragment(qurlLink[hash+1:])
}

// Verify checks the issuer signature against the trust store. It resolves the
// public key for the parsed claims' kid, then verifies the signature over the
// EXACT received claims bytes (ClaimsB64), enforcing the 64-byte / low-S /
// in-range wire contract. It must be called on a Fragment returned by
// ParseFragment.
func (f *Fragment) Verify(ts *TrustStore) error {
	if ts == nil {
		return fmt.Errorf("%w: nil trust store", ErrSignature)
	}
	if f.Claims == nil {
		return fmt.Errorf("%w: fragment not parsed", ErrSignature)
	}
	pub, err := ts.publicKeyForKID(f.Claims.Kid)
	if err != nil {
		return err
	}
	return verifyRawSignature(pub, f.ClaimsB64, f.sig)
}

// FragmentFromLinkAndVerify extracts the fragment from a full qURL link and
// verifies the issuer signature in one call — the convenience path for the SDK
// entry verb. relay_url validation remains a separate post-verify step
// (ValidateRelayURL), matching the design ordering.
func FragmentFromLinkAndVerify(qurlLink string, ts *TrustStore) (*Fragment, error) {
	frag, err := FragmentFromLink(qurlLink)
	if err != nil {
		return nil, err
	}
	if err := frag.Verify(ts); err != nil {
		return nil, err
	}
	return frag, nil
}

// DecodeCellPublicKey returns the raw 32-byte X25519 cell public key from VERIFIED
// claims, for deriving the relay serverId and as the Noise server static key. Call
// only on claims from a Fragment that has been verified.
func DecodeCellPublicKey(c *Claims) ([]byte, error) {
	return decodeX25519PublicKey(fieldCellPublicKeyB64, c.CellPublicKeyB64)
}

// DecodeQurlUserPrivateKey returns the raw 32-byte X25519 per-qURL private key
// from the secret block, used as the Noise agent static identity for the knock.
func DecodeQurlUserPrivateKey(s *Secret) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil secret", ErrStrictParse)
	}
	return decodeX25519PrivateKey(fieldQurlUserPrivateKeyB64, s.QurlUserPrivateKeyB64)
}

// ParseAndVerify is the convenience path: parse the fragment then verify the
// issuer signature. relay_url validation still remains a separate post-verify
// step the caller performs with ValidateRelayURL.
//
// IMPORTANT — this is NOT a full admission gate. It establishes only that the
// issuer signed these exact claim bytes; it does NOT enforce LIVENESS. A returned
// Fragment can carry a claim whose exp is already in the past or whose nbf is still
// in the future: the strict parser only checks the clock-free iat<=exp / nbf<=exp
// ordering bounds (this package has no trusted clock). The admission caller MUST
// itself reject expired/not-yet-valid claims (exp/nbf vs current time, with the
// agreed clock-skew allowance) and validate the resource key structurally before
// use. See the package doc and validateClaimValues in parse.go.
func ParseAndVerify(fragment string, ts *TrustStore) (*Fragment, error) {
	frag, err := ParseFragment(fragment)
	if err != nil {
		return nil, err
	}
	if err := frag.Verify(ts); err != nil {
		return nil, err
	}
	return frag, nil
}

// BuildFragment assembles a fragment body from the exact claims bytes, secret
// bytes, and raw 64-byte signature. claimsB64 is taken verbatim as Part 1 so the
// signed bytes and the transmitted bytes are identical. It returns the body
// WITHOUT a leading "#"; callers prepend "#"/the URL.
//
// Callers MUST pass encodeB64 output for claimsB64 and secretB64. BuildFragment
// enforces that contract rather than trusting it: it re-decodes both parts with
// decodeB64 (the same strict, unpadded base64url the parser uses), which rejects
// a stray "." (the field separator — not in the base64url alphabet), padding, and
// non-canonical encodings. With the signature validated to the pinned 64-byte
// low-S form, BuildFragment can never emit a body that ParseFragment would reject.
func BuildFragment(claimsB64, secretB64 string, rawSig []byte) (string, error) {
	if claimsB64 == "" || secretB64 == "" {
		return "", fmt.Errorf("%w: claims and secret parts must be non-empty", ErrFragment)
	}
	// Guard the parts are well-formed base64url (dot-free, unpadded, canonical).
	// A guard failure means a caller passed a non-encodeB64 string; wrap ErrFragment
	// while preserving the underlying ErrEncoding for callers that match on it.
	if _, err := decodeB64(claimsB64); err != nil {
		return "", fmt.Errorf("%w: claims part is not valid base64url: %w", ErrFragment, err)
	}
	if _, err := decodeB64(secretB64); err != nil {
		return "", fmt.Errorf("%w: secret part is not valid base64url: %w", ErrFragment, err)
	}
	if _, _, err := rawToScalars(rawSig); err != nil {
		return "", err
	}
	return strings.Join([]string{FragmentPrefix, claimsB64, secretB64, encodeB64(rawSig)}, "."), nil
}
