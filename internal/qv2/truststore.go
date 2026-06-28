package qv2

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// TrustStore resolves a claim's `kid` to the issuer public key used to verify the
// signature. Verifiers resolve the public key for a claim's kid from this small
// published store; unknown or retired kids are rejected. The store is deliberately
// KMS-independent so verification has no AWS dependency and the golden vectors
// verify offline.
//
// Rotation is overlap-publish and is expressed ENTIRELY through the contents of
// this map — there is no per-kid TTL or "retired" flag in the library. During
// overlap, the published map contains both the current kid and any
// recently-retired kids, so outstanding qURLs signed under an old kid keep
// verifying. Retiring a kid means removing it from the published map; from that
// point publicKeyForKID returns ErrUnknownKID for it.
type TrustStore struct {
	keys map[string]*ecdsa.PublicKey
}

// NewTrustStore builds a trust store from a kid -> public key map. The map is
// copied so later caller mutations cannot change verification behavior. Every key
// must be a non-nil P-256 public key.
func NewTrustStore(keys map[string]*ecdsa.PublicKey) (*TrustStore, error) {
	if len(keys) == 0 {
		return nil, errors.New("qurl: trust store must contain at least one issuer key")
	}
	copied := make(map[string]*ecdsa.PublicKey, len(keys))
	for kid, pub := range keys {
		if kid == "" {
			return nil, errors.New("qurl: trust store kid must not be empty")
		}
		if err := validateP256PublicKey(pub); err != nil {
			return nil, fmt.Errorf("qurl: trust store key %q: %w", kid, err)
		}
		copied[kid] = pub
	}
	return &TrustStore{keys: copied}, nil
}

// NewTrustStoreFromDER builds a trust store from kid -> DER SPKI public-key bytes
// (the form AWS KMS GetPublicKey returns and the form persisted on disk/config).
// It parses and type-asserts each entry to a P-256 public key.
func NewTrustStoreFromDER(derByKID map[string][]byte) (*TrustStore, error) {
	keys := make(map[string]*ecdsa.PublicKey, len(derByKID))
	for kid, der := range derByKID {
		pub, err := ParseP256PublicKeyDER(der)
		if err != nil {
			return nil, fmt.Errorf("qurl: trust store key %q: %w", kid, err)
		}
		keys[kid] = pub
	}
	return NewTrustStore(keys)
}

// publicKeyForKID returns the issuer public key for kid, or ErrUnknownKID.
func (ts *TrustStore) publicKeyForKID(kid string) (*ecdsa.PublicKey, error) {
	pub, ok := ts.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	return pub, nil
}

// ParseP256PublicKeyDER parses a DER SPKI public key and asserts it is on the
// P-256 curve. Used to load issuer keys from KMS GetPublicKey output or config.
func ParseP256PublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 {
		return nil, errors.New("qurl: empty public-key DER")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("qurl: parse SPKI public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("qurl: issuer key is %T, want *ecdsa.PublicKey", parsed)
	}
	if err := validateP256PublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// validateP256PublicKey rejects nil and non-P-256 public keys. It validates the
// point is well-formed by round-tripping through crypto/ecdh, which performs the
// modern on-curve / not-identity check without touching the deprecated raw
// ecdsa.PublicKey coordinate fields.
func validateP256PublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil {
		return errors.New("qurl: nil public key")
	}
	if pub.Curve != curve {
		return errors.New("qurl: issuer key is not on the P-256 curve")
	}
	// ECDH() returns an error for a nil/zero/off-curve point and never touches
	// the deprecated coordinate accessors.
	if _, err := pub.ECDH(); err != nil {
		return fmt.Errorf("qurl: issuer public key is not a valid P-256 point: %w", err)
	}
	return nil
}
