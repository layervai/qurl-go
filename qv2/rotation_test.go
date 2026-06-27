package qv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

// Trust-anchor overlap (kid rotation) is verified HERE, in qv2, because the
// verify path and the local test signer both live in this package — the
// qurl-layer provider only passes a *TrustStore through, so the rotation
// PROPERTY is a qv2 concern. qURL v2 issuer-key rotation is overlap-publish: the
// trust store carries BOTH the outgoing and incoming kid for a window, so a link
// signed under EITHER kid keeps verifying until the old kid is retired. This
// re-mints under two distinct kids rather than reusing the single-kid vendored
// vector, which cannot exercise an overlap.

// newTestSignerWithKID generates a fresh local P-256 issuer key under an explicit
// kid, so a test can build a multi-kid (overlap) trust store. It mirrors
// newTestSigner, which is pinned to testIssuerKID.
func newTestSignerWithKID(t *testing.T, kid string) *testSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	return &testSigner{priv: priv, kid: kid}
}

// mintLink signs baselineClaims under this signer's kid and assembles a full qURL
// fragment string, returning the link. The secret is a valid Part-2 block; the
// claims carry the signer's kid (signClaims stamps it).
func (s *testSigner) mintLink(t *testing.T) string {
	t.Helper()
	claimsB64, rawSig := s.signClaims(t, baselineClaims(t))
	body, err := BuildFragment(claimsB64, mintSecretB64(t), rawSig)
	if err != nil {
		t.Fatalf("BuildFragment: %v", err)
	}
	return "https://qurl.link/#" + body
}

// TestTrustAnchorRotation_OverlapVerifies covers the rotation done-criterion from
// issue #2: during an overlap publish the trust store carries BOTH the old and the
// new kid, so a link signed under EITHER kid verifies against that one store.
func TestTrustAnchorRotation_OverlapVerifies(t *testing.T) {
	oldS := newTestSignerWithKID(t, "qurl-issuer-old")
	newS := newTestSignerWithKID(t, "qurl-issuer-new")

	// Overlap trust store: both kids published together (the superset map a signer
	// re-publishes on rotation).
	overlap, err := NewTrustStore(map[string]*ecdsa.PublicKey{
		oldS.kid: &oldS.priv.PublicKey,
		newS.kid: &newS.priv.PublicKey,
	})
	if err != nil {
		t.Fatalf("overlap trust store: %v", err)
	}

	for _, tc := range []struct {
		name   string
		signer *testSigner
	}{
		{"old kid still verifies during overlap", oldS},
		{"new kid verifies during overlap", newS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := tc.signer.mintLink(t)
			if _, err := FragmentFromLinkAndVerify(link, overlap); err != nil {
				t.Fatalf("link signed under %q must verify against the overlap store: %v", tc.signer.kid, err)
			}
		})
	}
}

// TestTrustAnchorRotation_RetiredKidRejected is the other half: once a kid is
// retired (dropped from the published store), a link still signed under it no
// longer verifies — the store is the single source of which kids are trusted.
func TestTrustAnchorRotation_RetiredKidRejected(t *testing.T) {
	oldS := newTestSignerWithKID(t, "qurl-issuer-old")
	newS := newTestSignerWithKID(t, "qurl-issuer-new")

	// Post-rotation store: only the new kid remains published.
	postRotation, err := NewTrustStore(map[string]*ecdsa.PublicKey{
		newS.kid: &newS.priv.PublicKey,
	})
	if err != nil {
		t.Fatalf("post-rotation trust store: %v", err)
	}

	link := oldS.mintLink(t)
	_, err = FragmentFromLinkAndVerify(link, postRotation)
	if !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("retired kid: want ErrUnknownKID, got %v", err)
	}
}
