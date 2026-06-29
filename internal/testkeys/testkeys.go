// Package testkeys generates throwaway public keys for the SDK's runnable examples
// and tests, so the example files don't each re-implement the same key-gen helpers.
// The keys are random and ephemeral — never a production custody model.
package testkeys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

// X25519Public returns a fresh raw 32-byte X25519 public key — the shape of an NHP
// cell key (CreateParams.CellPublicKey). It panics on failure, which is acceptable in
// example/test code.
func X25519Public() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// P256SPKI returns a fresh P-256 public key in DER SPKI form — the shape of a resource
// key (CreateParams.ResourcePublicKey), and what AWS KMS GetPublicKey returns. It
// panics on failure, which is acceptable in example/test code.
func P256SPKI() []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}
