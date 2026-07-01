package qv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// RejectClass is the machine-readable rejection class. It is present on reject
	// vectors and absent on accept vectors. The pointer carries valid string values;
	// rejectClassNull keeps explicit JSON null distinct from absence during
	// validation.
	// The tag keeps any future marshal path aligned with the wire name;
	// UnmarshalJSON handles reads so it can fail closed on null.
	// This absent/null distinction only matters while parsing raw JSON signature
	// fixtures.
	RejectClass     *string `json:"reject_class,omitempty"`
	rejectClassNull bool    // Parser-only; validation rejects null before any marshal path.
	// Reason documents why in human-readable prose. It is mandatory contract
	// metadata even though reject_class drives machine-readable control flow.
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

// Signature encoding constants for SignatureVector.SigEncoding.
const (
	SignatureEncodingRawRS = "raw_r_s"
	SignatureEncodingDER   = "der"
)

// RejectClassHighS and RejectClassWrongLength enumerate the named signature
// rejection classes, so consumers can map a vector to the exact sentinel error it
// must trigger. Keep this closed taxonomy in lockstep with qurl-conformance's
// issuer-signature reject_class values and assertConformanceSignatureReject.
const (
	RejectClassHighS       = "high_s"
	RejectClassWrongLength = "wrong_length"
)

type signatureRejectClassSpec struct {
	err         error
	sigEncoding string
}

// signatureRejectClasses maps each valid signature reject_class to the sentinel
// verifier error it must produce and the concrete fixture encoding that exercises
// it. The loader uses the keys as the closed taxonomy, so assertion, encoding
// shape, and schema validation move together. A qurl-conformance reject-class or
// encoding change is a coordinated code change here, not just a dependency bump.
var (
	signatureRejectClasses = map[string]signatureRejectClassSpec{
		RejectClassHighS: {
			err:         ErrSignatureHighS,
			sigEncoding: SignatureEncodingRawRS,
		},
		RejectClassWrongLength: {
			err:         ErrSignatureLength,
			sigEncoding: SignatureEncodingDER,
		},
	}
	signatureRejectClassNames = sortedSignatureRejectClassNames()
)

// UnmarshalJSON records reject_class null so validation can reject it as a
// non-canonical fixture shape instead of silently treating it as absence.
func (v *SignatureVector) UnmarshalJSON(data []byte) error {
	type signatureVectorAlias SignatureVector
	var decoded signatureVectorAlias
	// The alias carries the normal field set; the shallower raw reject_class field
	// wins over the alias's promoted field and preserves explicit null through the
	// validation path.
	raw := struct {
		*signatureVectorAlias
		RejectClass json.RawMessage `json:"reject_class"`
	}{
		signatureVectorAlias: &decoded,
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*v = SignatureVector(decoded)
	// Name is the display/dedupe key, so normalize it at the decode boundary;
	// payload fields stay byte-faithful and are validated separately.
	v.Name = strings.TrimSpace(v.Name)
	// The RawMessage shadow should prevent alias RejectClass population; reset
	// defensively so a future refactor cannot carry a stale pointer into validation.
	v.RejectClass = nil
	v.rejectClassNull = bytes.Equal(raw.RejectClass, []byte("null"))
	if raw.RejectClass == nil || v.rejectClassNull {
		return nil
	}
	var rejectClass string
	if err := json.Unmarshal(raw.RejectClass, &rejectClass); err != nil {
		return fmt.Errorf("reject_class: %w", err)
	}
	v.RejectClass = &rejectClass
	return nil
}

func sortedSignatureRejectClassNames() string {
	names := make([]string, 0, len(signatureRejectClasses))
	for name := range signatureRejectClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func signatureRejectClassSpecFor(rejectClass string) (signatureRejectClassSpec, bool) {
	spec, ok := signatureRejectClasses[rejectClass]
	return spec, ok
}

// LoadVectorBytes parses a committed vector file's bytes. It returns an error
// (never an empty/zero document) if the bytes are empty or malformed, so a
// consumer test FAILS rather than silently skipping the contract. New upstream
// schema fields intentionally require code changes because unknown fields fail
// closed instead of being dropped.
func LoadVectorBytes(data []byte) (*VectorFile, error) {
	var vf VectorFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		return nil, fmt.Errorf("qurl: parse vector file: %w", err)
	}
	if len(vf.Vectors) == 0 {
		return nil, errors.New("qurl: vector file has no vectors")
	}
	if err := validateVectorFileShape(&vf); err != nil {
		return nil, err
	}
	seenNames := make(map[string]struct{}, len(vf.Vectors))
	for i := range vf.Vectors {
		if err := validateSignatureVector(i, &vf.Vectors[i], seenNames); err != nil {
			return nil, err
		}
	}
	return &vf, nil
}

func validateVectorFileShape(vf *VectorFile) error {
	if strings.TrimSpace(vf.Algorithm) == "" {
		return errors.New("qurl: vector file has empty algorithm")
	}
	if vf.DomainSeparationPrefix != domainSeparationPrefix {
		return fmt.Errorf("qurl: vector file has domain_separation_prefix %q, want %q", vf.DomainSeparationPrefix, domainSeparationPrefix)
	}
	if strings.TrimSpace(vf.Issuer.KID) == "" {
		return errors.New("qurl: vector file issuer has empty kid")
	}
	if strings.TrimSpace(vf.Issuer.SPKIDERB64) == "" {
		return errors.New("qurl: vector file issuer has empty spki_der_b64")
	}
	if vf.Issuer.JWK.Kty != "EC" {
		return fmt.Errorf("qurl: vector file issuer jwk has kty %q, want EC", vf.Issuer.JWK.Kty)
	}
	if vf.Issuer.JWK.Crv != "P-256" {
		return fmt.Errorf("qurl: vector file issuer jwk has crv %q, want P-256", vf.Issuer.JWK.Crv)
	}
	if strings.TrimSpace(vf.Issuer.JWK.X) == "" {
		return errors.New("qurl: vector file issuer jwk has empty x")
	}
	if strings.TrimSpace(vf.Issuer.JWK.Y) == "" {
		return errors.New("qurl: vector file issuer jwk has empty y")
	}
	return nil
}

func validateSignatureVector(i int, v *SignatureVector, seenNames map[string]struct{}) error {
	// Re-trim here because package tests/generators can construct SignatureVector
	// directly and bypass UnmarshalJSON's decode-boundary normalization.
	name := strings.TrimSpace(v.Name)
	if name == "" {
		return fmt.Errorf("qurl: signature vector at index %d has empty name", i)
	}
	v.Name = name
	if _, ok := seenNames[name]; ok {
		return fmt.Errorf("qurl: duplicate signature vector name %q", name)
	}
	seenNames[name] = struct{}{}
	// Reason is prose-only, but every vector must carry it so fixture diffs stay
	// reviewable and self-explanatory.
	if strings.TrimSpace(v.Reason) == "" {
		return fmt.Errorf("qurl: signature vector %q has empty reason", name)
	}
	if err := validateSignaturePayloadFields(name, v); err != nil {
		return err
	}
	// Keep the empty-field diagnostic distinct from the closed enum diagnostic.
	if v.SigEncoding != SignatureEncodingRawRS && v.SigEncoding != SignatureEncodingDER {
		return fmt.Errorf("qurl: signature vector %q has sig_encoding %q, want %s|%s", name, v.SigEncoding, SignatureEncodingRawRS, SignatureEncodingDER)
	}
	switch v.Expect {
	case ExpectAccept:
		return validateAcceptSignatureVector(name, v)
	case ExpectReject:
		return validateRejectSignatureVector(name, v)
	default:
		return fmt.Errorf("qurl: signature vector %q has expect %q, want accept|reject", name, v.Expect)
	}
}

func validateSignaturePayloadFields(name string, v *SignatureVector) error {
	if strings.TrimSpace(v.ClaimsB64) == "" {
		return fmt.Errorf("qurl: signature vector %q has empty claims_b64", name)
	}
	if strings.TrimSpace(v.SigB64Raw) == "" {
		return fmt.Errorf("qurl: signature vector %q has empty sig_b64", name)
	}
	if strings.TrimSpace(v.SigEncoding) == "" {
		return fmt.Errorf("qurl: signature vector %q has empty sig_encoding", name)
	}
	if strings.TrimSpace(v.SigningInputB64) == "" {
		return fmt.Errorf("qurl: signature vector %q has empty signing_input_b64", name)
	}
	return nil
}

func validateAcceptSignatureVector(name string, v *SignatureVector) error {
	if v.SigEncoding != SignatureEncodingRawRS {
		return fmt.Errorf("qurl: accept signature vector %q has sig_encoding %q, want %s", name, v.SigEncoding, SignatureEncodingRawRS)
	}
	present, isNull, value := rejectClassState(v)
	if present {
		if isNull {
			return fmt.Errorf("qurl: accept signature vector %q has reject_class null", name)
		}
		return fmt.Errorf("qurl: accept signature vector %q has reject_class %q", name, value)
	}
	return nil
}

func validateRejectSignatureVector(name string, v *SignatureVector) error {
	present, isNull, value := rejectClassState(v)
	if !present {
		return fmt.Errorf("qurl: reject signature vector %q is missing reject_class", name)
	}
	if isNull {
		return fmt.Errorf("qurl: reject signature vector %q has reject_class null", name)
	}
	if value == "" {
		return fmt.Errorf("qurl: reject signature vector %q has reject_class \"\"", name)
	}
	spec, ok := signatureRejectClassSpecFor(value)
	if !ok {
		return fmt.Errorf("qurl: reject signature vector %q has reject_class %q, want one of %s", name, value, signatureRejectClassNames)
	}
	if v.SigEncoding != spec.sigEncoding {
		return fmt.Errorf("qurl: reject signature vector %q with reject_class %q has sig_encoding %q, want %s", name, value, v.SigEncoding, spec.sigEncoding)
	}
	return nil
}

func rejectClassState(v *SignatureVector) (present, isNull bool, value string) {
	if v.RejectClass != nil {
		return true, false, *v.RejectClass
	}
	return v.rejectClassNull, v.rejectClassNull, ""
}
