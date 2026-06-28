package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/layervai/qurl-go/internal/qv2"
)

// CreatePortal is the issuer-side mint verb. It signs a short-lived qURL link
// for a private service configured in LayerV and returns the
// https://qurl.link/#<version>.<claims>.<secret>.<sig> link.
//
// The issuer signing key is never held here directly: signing goes through the
// qurl.Signer seam (KMS in production, qurl.LocalSigner for tests / self-custody
// integrations), so this verb has no AWS dependency. The signed claims bytes are
// handed verbatim to the fragment builder, so the bytes the issuer signs are
// exactly the bytes a verifier (qurl.VerifyLink / EnterPortal) checks.

// LinkBaseURL is the canonical qURL link origin CreatePortal prepends to the
// fragment. The credential, claims, and signature all live in the fragment after
// '#', which browser semantics keep out of the HTTP request to this origin.
const LinkBaseURL = "https://qurl.link/"

// b64url is the single pinned qURL wire encoding (unpadded base64url). The secret
// part (Part 2) is assembled here with the stdlib encoder rather than widening the
// public surface; RawURLEncoding's output is byte-identical to the core's internal
// encoder. BuildFragment validates only the OUTER Part-2 envelope (it decodes the
// base64url blob; it does not re-run the secret schema), so the inner
// qurl_user_private_key_b64 field is kept symmetric with the verify side by the
// shared Secret struct (the field name cannot drift without a compile break)
// and by the create→verify round-trip test, not by a BuildFragment re-check.
// Owning the Part-2 codec in one core place (mirroring parseSecret) is deferred —
// see qurl-go#6.
var b64url = base64.RawURLEncoding

// Resource is the LayerV-provided config for a private service protected by
// qURL. Treat it as opaque application config: pass it to CreatePortal when you
// issue a link.
type Resource struct {
	// AccessPublicKey is the qURL platform access key for this private service.
	// LayerV provides it as part of resource config.
	AccessPublicKey []byte
	// AccessURL is the qURL platform access URL for this private service. LayerV
	// provides it as part of resource config.
	AccessURL string
	// ResourceIdentity is the private service identity key in DER SPKI form.
	// LayerV provides it as part of resource config.
	ResourceIdentity []byte
	// Label is an optional LayerV resource label. Empty omits the label from the
	// signed link.
	Label string
}

// CreateOption customizes CreatePortal. Most callers only need ValidFor; the
// other options are for stable audit ids, tests, or schedulers that need a
// precise validity window.
type CreateOption interface {
	applyCreateOption(*createOptions) error
}

type createOptionFunc func(*createOptions) error

func (f createOptionFunc) applyCreateOption(o *createOptions) error {
	return f(o)
}

type createOptions struct {
	jti string

	issuedAt    time.Time
	hasIssuedAt bool

	notBefore    time.Time
	hasNotBefore bool

	validFor    time.Duration
	hasValidFor bool

	expiresAt    time.Time
	hasExpiresAt bool
}

// ValidFor makes the link expire after d, measured from the issued-at time. This
// is the usual way to set link lifetime.
func ValidFor(d time.Duration) CreateOption {
	return createOptionFunc(func(o *createOptions) error {
		if d <= 0 {
			return fmt.Errorf("%w: ValidFor duration must be positive", ErrInvalidCreateParams)
		}
		o.validFor = d
		o.hasValidFor = true
		return nil
	})
}

// ExpiresAt sets the absolute expiration time for the link. Use either
// ExpiresAt or ValidFor, not both.
func ExpiresAt(t time.Time) CreateOption {
	return createOptionFunc(func(o *createOptions) error {
		if t.IsZero() {
			return fmt.Errorf("%w: ExpiresAt time must not be zero", ErrInvalidCreateParams)
		}
		o.expiresAt = t
		o.hasExpiresAt = true
		return nil
	})
}

// NotBefore sets the earliest time the link should be accepted. By default, the
// link is valid immediately at its issued-at time.
func NotBefore(t time.Time) CreateOption {
	return createOptionFunc(func(o *createOptions) error {
		if t.IsZero() {
			return fmt.Errorf("%w: NotBefore time must not be zero", ErrInvalidCreateParams)
		}
		o.notBefore = t
		o.hasNotBefore = true
		return nil
	})
}

// WithIssuedAt sets the signed issued-at time. It is mainly useful for tests and
// deterministic issuers; normal callers use the current time.
func WithIssuedAt(t time.Time) CreateOption {
	return createOptionFunc(func(o *createOptions) error {
		if t.IsZero() {
			return fmt.Errorf("%w: issued-at time must not be zero", ErrInvalidCreateParams)
		}
		o.issuedAt = t
		o.hasIssuedAt = true
		return nil
	})
}

// WithLinkID sets the signed per-link id. By default CreatePortal generates a
// random id.
func WithLinkID(id string) CreateOption {
	return createOptionFunc(func(o *createOptions) error {
		if id == "" {
			return fmt.Errorf("%w: link id must not be empty", ErrInvalidCreateParams)
		}
		o.jti = id
		return nil
	})
}

// CreateParams are the low-level inputs to a mint. Most callers should use
// CreatePortal with a Resource and options instead; CreateParams exists for tests,
// conformance, and integrations that need to set every signed claim explicitly.
type CreateParams struct {
	// CellPublicKey is the access public key from LayerV resource config. The name
	// matches the qURL wire format. REQUIRED.
	CellPublicKey []byte
	// RelayURL is the qURL platform access URL from LayerV resource config. The
	// name matches the qURL wire format. REQUIRED.
	RelayURL string
	// ResourcePublicKey is the resource identity key from LayerV resource config,
	// in DER SPKI form. REQUIRED.
	ResourcePublicKey []byte
	// CellID is an optional LayerV resource label. Empty omits it from the signed
	// claims.
	CellID string
	// JTI is the unique qURL id stamped into the claims (the jti claim). REQUIRED:
	// it is part of the signed anti-tamper envelope and the per-link identifier.
	JTI string

	// IssuedAt, NotBefore, Expiry are the signed validity window as Unix seconds
	// (the iat / nbf / exp claims). All three are REQUIRED and must satisfy the
	// clock-free ordering bounds iat<=exp and nbf<=exp. A nonsensical window fails
	// the mint rather than producing an artifact no verifier accepts.
	IssuedAt  int64
	NotBefore int64
	Expiry    int64
}

// ErrInvalidCreateParams is returned when CreatePortal inputs are missing or
// internally inconsistent before any signing is attempted. Claim-shape faults
// (key length, time ordering, ...) surface from the signer as wrapped
// qurl.ErrStrictParse, so a caller can match the strict-parse contract directly.
var ErrInvalidCreateParams = errors.New("qurl: invalid CreatePortal params")

// CreatePortal mints a qURL link for a LayerV resource. It generates the
// per-link credential and link id, assembles the signed claims, signs them
// through the issuer Signer seam, and returns the full
// https://qurl.link/#<version>.<claims>.<secret>.<sig> link.
//
// A typical issuer passes the LayerV-provided Resource and a lifetime:
//
//	resource := qurl.Resource{
//		AccessPublicKey:  accessPublicKey,
//		AccessURL:        accessURL,
//		ResourceIdentity: resourceIdentity,
//	}
//	link, err := qurl.CreatePortal(ctx, signer, resource, qurl.ValidFor(5*time.Minute))
//
// Use CreatePortalWithParams when tests or conformance code need to set every
// signed claim explicitly.
func CreatePortal(ctx context.Context, signer Signer, resource Resource, opts ...CreateOption) (string, error) {
	params, err := createParamsFromResource(resource, opts)
	if err != nil {
		return "", err
	}
	return CreatePortalWithParams(ctx, signer, params)
}

// CreatePortalWithParams mints a qURL link from explicit signed-claim inputs. It
// is the advanced seam behind CreatePortal; most integrations should pass a
// Resource to CreatePortal instead of constructing CreateParams.
//
// Symmetry guarantee: the returned link parses and verifies under
// qurl.VerifyLink / EnterPortalWith against a trust store holding the signer's
// public key. CreatePortalWithParams validates the claims through the same strict
// parser those verifiers use BEFORE signing, so a mint that would not verify
// fails here instead of emitting a bad link.
func CreatePortalWithParams(ctx context.Context, signer Signer, p CreateParams) (string, error) {
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
	// core errors from SignClaims and BuildFragment below are returned VERBATIM (no
	// qurl: wrap) so callers keep matching the error sentinels directly —
	// errors.Is(err, qurl.ErrStrictParse) for an invalid claim window/shape, etc. The
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

func createParamsFromResource(resource Resource, opts []CreateOption) (CreateParams, error) {
	create, err := resolveCreateOptions(opts)
	if err != nil {
		return CreateParams{}, err
	}
	jti := create.jti
	if jti == "" {
		jti, err = randomJTI()
		if err != nil {
			return CreateParams{}, err
		}
	}

	return CreateParams{
		CellPublicKey:     resource.AccessPublicKey,
		RelayURL:          resource.AccessURL,
		ResourcePublicKey: resource.ResourceIdentity,
		CellID:            resource.Label,
		JTI:               jti,
		IssuedAt:          create.issuedAt.Unix(),
		NotBefore:         create.notBefore.Unix(),
		Expiry:            create.expiresAt.Unix(),
	}, nil
}

func resolveCreateOptions(opts []CreateOption) (createOptions, error) {
	var out createOptions
	for _, opt := range opts {
		if opt == nil {
			return out, fmt.Errorf("%w: nil CreateOption", ErrInvalidCreateParams)
		}
		if err := opt.applyCreateOption(&out); err != nil {
			return out, err
		}
	}
	if out.hasValidFor && out.hasExpiresAt {
		return out, fmt.Errorf("%w: use either ValidFor or ExpiresAt, not both", ErrInvalidCreateParams)
	}
	if !out.hasValidFor && !out.hasExpiresAt {
		return out, fmt.Errorf("%w: link lifetime is required; use ValidFor or ExpiresAt", ErrInvalidCreateParams)
	}

	now := time.Now().UTC()
	if !out.hasIssuedAt {
		out.issuedAt = now
	}
	if !out.hasNotBefore {
		out.notBefore = out.issuedAt
	}
	if out.hasValidFor {
		out.expiresAt = out.issuedAt.Add(out.validFor)
	} else {
		out.expiresAt = out.expiresAt.UTC()
	}
	out.issuedAt = out.issuedAt.UTC()
	out.notBefore = out.notBefore.UTC()
	return out, nil
}

func randomJTI() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("qurl: generate link id: %w", err)
	}
	return "qurl_" + b64url.EncodeToString(raw[:]), nil
}

// validate checks the issuer-supplied bindings are PRESENT before any keygen or
// signing, so every missing-required-input fault is one error class
// (ErrInvalidCreateParams) a caller can match with a single errors.Is. The
// presence checks cover all required inputs, including the three time fields
// (a zero Unix second is treated as "omitted"). The DEEP value rules — key
// lengths, version pin, the iat<=exp / nbf<=exp ordering bounds — are left to
// the signer's strict-parse-before-sign, which surfaces them as
// qurl.ErrStrictParse; validate deliberately does not duplicate them.
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
// (the secret parser) consumes.
func buildSecretB64(privateKey []byte) (string, error) {
	raw, err := json.Marshal(qv2.Secret{QurlUserPrivateKeyB64: b64url.EncodeToString(privateKey)})
	if err != nil {
		return "", fmt.Errorf("qurl: marshal secret: %w", err)
	}
	return b64url.EncodeToString(raw), nil
}
