package qv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Strict JSON parsing for qURL v2.
//
// Go's encoding/json does the WRONG thing by default in several ways that are
// signature/admission-bypass hazards, so this file hand-rolls the guards the
// design requires:
//
//   - Duplicate keys: encoding/json silently collapses to last-wins, and
//     DisallowUnknownFields does NOT catch duplicates. We detect them with a
//     json.Decoder.Token() walk over the original bytes.
//   - null in a scalar field: unmarshals to the zero value with no error. The
//     token walk rejects any null value and records presence.
//   - Unknown fields: rejected against an explicit allowlist during the walk
//     (independent of struct tags, so the policy is visible in one place).
//
// After the structural walk, a typed json.Unmarshal enforces value types
// (int64 time fields reject floats/exponents/strings; string key fields reject
// arrays/objects/numbers). Finally range and per-field key-length checks run.

// parseClaims strict-parses the decoded claims JSON bytes (the bytes produced by
// base64url-decoding Part 1) into a Claims value. It rejects every strict-schema
// violation in the design's "Parsing rules" before returning.
func parseClaims(raw []byte) (*Claims, error) {
	present, err := strictObjectWalk(raw, allowedClaimKeys)
	if err != nil {
		return nil, err
	}
	if err := requireKeys(present, requiredClaimKeys); err != nil {
		return nil, err
	}

	var c Claims
	if err := strictUnmarshal(raw, &c); err != nil {
		return nil, err
	}
	if err := validateClaimValues(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// parseSecret strict-parses the decoded secret JSON bytes (Part 2) into a Secret
// value with the same strict profile as the claims parser.
func parseSecret(raw []byte) (*Secret, error) {
	present, err := strictObjectWalk(raw, allowedSecretKeys)
	if err != nil {
		return nil, err
	}
	if err := requireKeys(present, requiredSecretKeys); err != nil {
		return nil, err
	}

	var s Secret
	if err := strictUnmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.QurlUserPrivateKeyB64 == "" {
		return nil, fmt.Errorf("%w: %s is empty", ErrStrictParse, fieldQurlUserPrivateKeyB64)
	}
	// Decode AND length-check the per-qURL private key (the PoP credential), the
	// same shape discipline the claims path applies to the public keys. The error
	// keeps both ErrStrictParse (parser contract) and the underlying
	// ErrKeyLength/ErrEncoding so callers can match either.
	if _, err := decodeX25519PrivateKey(fieldQurlUserPrivateKeyB64, s.QurlUserPrivateKeyB64); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	return &s, nil
}

// strictObjectWalk walks a JSON object token-by-token over the ORIGINAL bytes and
// enforces the structural rules that encoding/json hides:
//   - the top-level value must be a single object (not an array/scalar);
//   - every key must be in allowed;
//   - no key may repeat (duplicate-key rejection);
//   - no value may be JSON null.
//
// It returns the set of keys that were present (with a non-null value) so the
// caller can enforce required-field presence. It deliberately does not interpret
// value types beyond null — type enforcement is the typed-unmarshal pass's job.
func strictObjectWalk(raw []byte, allowed map[string]struct{}) (map[string]struct{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exact during the walk; no float coercion

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("%w: top-level value must be a JSON object", ErrStrictParse)
	}

	present := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStrictParse, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			// json guarantees object keys are strings; defensive only.
			return nil, fmt.Errorf("%w: non-string object key", ErrStrictParse)
		}
		if _, allow := allowed[key]; !allow {
			return nil, fmt.Errorf("%w: unknown field %q", ErrStrictParse, key)
		}
		if _, dup := present[key]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrStrictParse, key)
		}
		present[key] = struct{}{}

		if err := rejectNullValue(dec, key); err != nil {
			return nil, err
		}
	}

	// Consume the closing '}' and assert there is no trailing data (e.g. a second
	// concatenated JSON value), which a lenient parser would ignore.
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after JSON object", ErrStrictParse)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: unexpected trailing content", ErrStrictParse)
	}

	return present, nil
}

// rejectNullValue reads the next value for a key and rejects an explicit JSON
// null, fully consuming nested arrays/objects so the decoder stays aligned for
// the next key. Non-null values are accepted here and type-checked later.
func rejectNullValue(dec *json.Decoder, key string) error {
	valTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if delim, ok := valTok.(json.Delim); ok && (delim == '[' || delim == '{') {
		// Drain the nested container so the cursor lands on this key's sibling.
		// A scalar-typed field carrying an array/object is rejected later by the
		// typed unmarshal; the drain only keeps the walk well-formed.
		return drainContainer(dec)
	}
	if valTok == nil {
		return fmt.Errorf("%w: field %q is null", ErrStrictParse, key)
	}
	return nil
}

// drainContainer consumes tokens until the currently-open array/object is
// balanced. The opening delimiter has already been read by the caller.
func drainContainer(dec *json.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrStrictParse, err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
		}
	}
	return nil
}

// requireKeys returns ErrStrictParse if any required key is missing from present.
func requireKeys(present map[string]struct{}, required []string) error {
	for _, k := range required {
		if _, ok := present[k]; !ok {
			return fmt.Errorf("%w: missing required field %q", ErrStrictParse, k)
		}
	}
	return nil
}

// strictUnmarshal decodes raw into v with DisallowUnknownFields and integer-only
// number parsing. The structural walk already caught unknown/duplicate/null;
// this pass enforces value TYPES (so a string-where-int or array-where-scalar
// is rejected). It uses a single Decode and asserts no trailing tokens remain.
//
// Integer-only time parsing comes from the TARGET fields being typed int64, not
// from UseNumber(): encoding/json rejects a fractional/exponent/string number
// when the destination is an integer, so 1.5, 1e9, and "5" all fail to decode
// into Claims.{Iat,Nbf,Exp}.
func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after JSON object", ErrStrictParse)
	}
	return nil
}

// validateClaimValues enforces the value-level rules that survive type decoding:
// version pin, issuer, integer time-field ranges, the clock-free iat<=exp and
// nbf<=exp ordering bounds, and per-field key lengths. Liveness (exp/nbf vs now)
// is intentionally NOT checked here — it is the admission caller's job (see the
// package doc); this library has no trusted clock.
func validateClaimValues(c *Claims) error {
	if c.V != Version {
		return fmt.Errorf("%w: v must be %d, got %d", ErrStrictParse, Version, c.V)
	}
	if c.Iss != Issuer {
		return fmt.Errorf("%w: iss must be %q, got %q", ErrStrictParse, Issuer, c.Iss)
	}
	if c.Kid == "" {
		return fmt.Errorf("%w: kid is empty", ErrStrictParse)
	}
	if c.Jti == "" {
		return fmt.Errorf("%w: jti is empty", ErrStrictParse)
	}

	for _, f := range []struct {
		name string
		val  int64
	}{{fieldIat, c.Iat}, {fieldNbf, c.Nbf}, {fieldExp, c.Exp}} {
		if f.val < 0 {
			return fmt.Errorf("%w: %s must be a non-negative Unix second, got %d", ErrStrictParse, f.name, f.val)
		}
		if f.val == 0 {
			return fmt.Errorf("%w: %s is required and must be non-zero", ErrStrictParse, f.name)
		}
		if f.val > maxUnixSeconds {
			return fmt.Errorf("%w: %s=%d exceeds max allowed Unix second %d", ErrStrictParse, f.name, f.val, maxUnixSeconds)
		}
	}
	// iat<=exp and nbf<=exp are CLOCK-FREE sanity bounds on the signed window: they
	// catch a structurally-incoherent claim (issued-after-it-expires, or
	// not-valid-before-after-it-expires) at parse time rather than letting the
	// crypto core vouch for nonsensical bytes. LIVENESS — exp-vs-now, nbf-vs-now,
	// and clock skew — is the admission layer's job, NOT this library's. We do not
	// enforce nbf>=iat (a backdated nbf is harmless given the nbf/exp-vs-now checks
	// admission owns).
	if c.Iat > c.Exp {
		return fmt.Errorf("%w: iat (%d) must be <= exp (%d)", ErrStrictParse, c.Iat, c.Exp)
	}
	if c.Nbf > c.Exp {
		return fmt.Errorf("%w: nbf (%d) must be <= exp (%d)", ErrStrictParse, c.Nbf, c.Exp)
	}

	if _, err := decodeX25519PublicKey(fieldCellPublicKeyB64, c.CellPublicKeyB64); err != nil {
		return fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if _, err := decodeX25519PublicKey(fieldQurlUserPublicKeyB64, c.QurlUserPublicKeyB64); err != nil {
		return fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	if _, err := decodeResourcePublicKey(c.ResourcePublicKeyB64); err != nil {
		return fmt.Errorf("%w: %w", ErrStrictParse, err)
	}
	// relay_url must be present (required field), but HTTPS + allowlist checks are
	// a post-verify step (ValidateRelayURL), NOT part of the parser, because the
	// design says relay_url is used only AFTER signature verification succeeds.
	if c.RelayURL == "" {
		return fmt.Errorf("%w: relay_url is empty", ErrStrictParse)
	}
	// cell_id is deliberately the ONE present-string claim allowed to be empty:
	// it is the single OPTIONAL claim, so absent and present-empty are treated as
	// equivalent "no cell" and both accepted.
	return nil
}
