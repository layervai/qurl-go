package qv2

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Golden-vector fixture schema for qURL v2 issuer signatures.
//
// These vectors are the cross-language CONTRACT proving that KMS-sign output, Go
// verification, and WebCrypto verification agree byte-for-byte on the pinned P-256
// raw r||s low-S wire encoding — plus a high-S rejection and a wrong-length
// rejection vector. They are VERIFY fixtures, not sign-determinism fixtures:
// ECDSA's nonce is random, so a signature cannot be reproduced. The fixture is
// generated once and consumers re-verify the committed bytes.
//
// The fixture bytes are consumed from the public qurl-conformance package
// (github.com/layervai/qurl-conformance), whose go:embed accessor returns the
// canonical issuer-signature vectors; the dependency version pins the bytes.

// VectorFile is the top-level committed fixture document.
type VectorFile struct {
	// Description documents the contract for a human reader of the JSON.
	Description string `json:"description"`
	// Algorithm pins the signing profile (informational; verifiers do not
	// negotiate).
	Algorithm string `json:"algorithm"`
	// DomainSeparationPrefix is the ASCII prefix; the 0x00 separator follows it.
	DomainSeparationPrefix string `json:"domain_separation_prefix"`
	// Issuer is the shared issuer key all vectors are signed/verified under.
	Issuer IssuerKeyMaterial `json:"issuer"`
	// Vectors is the ordered list of accept/reject cases.
	Vectors []SignatureVector `json:"vectors"`
}

// IssuerKeyMaterial is the issuer public key in both import forms.
type IssuerKeyMaterial struct {
	KID string `json:"kid"`
	// SPKIDERB64 is the DER SPKI public key, base64url (KMS GetPublicKey form).
	SPKIDERB64 string `json:"spki_der_b64"`
	// JWK is the same public key as a P-256 JWK (crv/x/y), for WebCrypto "jwk".
	JWK ECPublicJWK `json:"jwk"`
}

// ECPublicJWK is a minimal P-256 public-key JWK. x and y are fixed-width 32-byte
// base64url (leading zeros preserved) so a strict importer accepts them.
type ECPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// SignatureVector is one accept-or-reject case.
type SignatureVector struct {
	Name string `json:"name"`
	// Expect is "accept" or "reject".
	Expect string `json:"expect"`
	// Reason documents why (and, for rejects, names the failure class).
	Reason string `json:"reason"`
	// ClaimsB64 is the exact base64url claims string (primary verify input).
	ClaimsB64 string `json:"claims_b64"`
	// SigB64Raw is the signature as base64url. For accept/high-S it is 64-byte
	// raw r||s; for the wrong-length case it is the DER form.
	SigB64Raw string `json:"sig_b64"`
	// SigEncoding documents the signature's byte form ("raw_r_s" or "der").
	SigEncoding string `json:"sig_encoding"`
	// SigningInputB64 is the cross-check value: a verifier reconstructs
	// prefix + 0x00 + ClaimsB64 itself and asserts its base64url equals this.
	SigningInputB64 string `json:"signing_input_b64"`
}

// Expectation constants for the cross-language vocabulary. Shared by the signature
// vectors and the conformance artifact so a consumer in any language switches on
// the same closed set.
const (
	ExpectAccept = "accept"
	ExpectReject = "reject"
)

// VectorRejectClass enumerates the named signature rejection classes, so consumers
// can map a vector to the exact sentinel error it must trigger.
const (
	RejectClassHighS       = "high_s"
	RejectClassWrongLength = "wrong_length"
)

// LoadVectorBytes parses a committed vector file's bytes. It returns an error
// (never an empty/zero document) if the bytes are empty or malformed, so a
// consumer test FAILS rather than silently skipping the contract.
func LoadVectorBytes(data []byte) (*VectorFile, error) {
	var vf VectorFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		return nil, fmt.Errorf("qv2: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, fmt.Errorf("qv2: vector file has no vectors")
	}
	return &vf, nil
}
