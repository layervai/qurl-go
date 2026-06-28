package qurl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/layervai/qurl-go/internal/qv2"
)

// Discovery-manifest credential provider.
//
// A DiscoveryProvider fetches a NON-SECRET published trust manifest carrying the
// issuer trust anchors (kid -> P-256 public key), the relay allowlist, an expiry,
// and a monotonic version, then turns it into the *qurl.TrustStore / *qurl.RelayAllowlist
// EnterPortal needs. "Non-secret" does NOT mean "blindly trusted": a manifest is
// authenticated before use by a configured PIN (sha256 of the exact bytes) or a
// detached ISSUER SIGNATURE (the manifest-signature verifier, a SEPARATE signing domain
// from qURL claims). It FAILS CLOSED on every doubt — unverifiable, expired,
// downgraded (older version than last accepted), missing a trust mode, or carrying an
// empty/invalid anchor set or allowlist all return an error, never a partial result.
//
// OPEN DECISION #13 (tracked in qurl-go issue #24): the FINAL discovery trust policy
// (signed vs pinned as the production default, kid-rotation procedure, downgrade-window
// specifics) is Open Decision #13 in the qURL v2 plan and is not yet frozen. This file
// implements the MECHANISM with safe fail-closed defaults and makes the policy
// configurable (DiscoveryConfig). When #13 lands, it selects/clamps these knobs; it must
// not loosen the fail-closed posture without an explicit threat-model decision recorded
// there. The manifest JSON schema here is a documented assumption (no published schema
// exists in the org yet) and may change to match #13.

// ManifestEnvelope is the fetched discovery document. The signed/pinned MANIFEST
// itself is carried as opaque base64url (ManifestB64) — exactly like a qURL link fragment
// keeps ClaimsB64 verbatim — so the bytes that are pinned/verified are the bytes that
// are parsed, with zero re-serialization in between. SigB64 / Kid are present only on
// the SIGNED path and are NOT covered by the signature (a detached signature over the
// manifest bytes), so an attacker stripping them just turns a signed manifest into an
// unauthenticated one, which fails closed when a trust mode is required.
type ManifestEnvelope struct {
	// ManifestB64 is the unpadded-base64url of the exact Manifest JSON bytes. It is
	// the signature/pin preimage; it is decoded and parsed verbatim.
	ManifestB64 string `json:"manifest_b64"`
	// SigB64 is the unpadded-base64url detached issuer signature (64-byte raw r||s,
	// low-S) over the decoded manifest bytes, in the manifest signing domain. Empty
	// on a pin-only manifest.
	SigB64 string `json:"sig_b64,omitempty"`
	// Kid selects which configured manifest-signing public key verifies SigB64. Empty
	// on a pin-only manifest.
	Kid string `json:"kid,omitempty"`
}

// Manifest is the decoded, authenticated trust manifest. Field semantics:
//   - Profile/Version identify the manifest class and its monotonic revision; a
//     Version below the provider's last-accepted floor is a DOWNGRADE and is rejected.
//   - NotAfter is the manifest expiry as Unix seconds; now > NotAfter fails closed.
//   - Issuers becomes the trust store (kid -> DER SPKI P-256 key).
//   - RelayAllowlist becomes the relay allowlist (host or host:port entries).
type Manifest struct {
	Profile        string           `json:"profile"`
	Version        int64            `json:"version"`
	IssuedAt       int64            `json:"issued_at"`
	NotAfter       int64            `json:"not_after"`
	Issuers        []ManifestIssuer `json:"issuers"`
	RelayAllowlist []string         `json:"relay_allowlist"`
}

// ManifestIssuer is one issuer trust anchor: a kid and its P-256 public key in DER
// SPKI form (the AWS KMS GetPublicKey shape, base64url-encoded for JSON transport).
type ManifestIssuer struct {
	Kid        string `json:"kid"`
	SPKIDERB64 string `json:"spki_der_b64"`
}

// ManifestFetcher fetches the raw discovery-envelope bytes. It is the network seam:
// production binds it to an HTTPS GET of the published manifest URL (NewHTTPFetcher),
// tests inject a static byte slice so no real network is touched under -race. A
// fetcher returns the exact response body; all authentication happens after fetch.
type ManifestFetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// FetcherFunc adapts a plain function to ManifestFetcher.
type FetcherFunc func(ctx context.Context) ([]byte, error)

// Fetch calls the wrapped function.
func (f FetcherFunc) Fetch(ctx context.Context) ([]byte, error) { return f(ctx) }

// DiscoveryConfig configures a DiscoveryProvider's fetch source and TRUST POLICY.
// The trust policy is fail-closed by construction: a provider that authenticates no
// way (no pin, no signing keys) is rejected at construction, and a manifest that
// satisfies no configured mode is rejected at resolve.
type DiscoveryConfig struct {
	// Fetcher fetches the raw envelope bytes. REQUIRED.
	Fetcher ManifestFetcher

	// PinSHA256 is the expected sha256 of the EXACT manifest bytes (the PINNED trust
	// mode). When set (32 bytes), a fetched manifest whose ManifestDigest does not
	// equal this pin is rejected. A pin structurally prevents downgrade and substitution
	// (it authenticates one exact byte string), so it is the smallest correct trust
	// anchor. Leave nil to disable the pinned mode.
	PinSHA256 []byte

	// ManifestKeys are the manifest-signing public keys (kid -> P-256 public key) for
	// the SIGNED trust mode. When non-empty, a manifest carrying a SigB64/Kid is
	// verified with the manifest-signature verifier against the key for that kid. Leave nil
	// to disable the signed mode.
	ManifestKeys map[string]*ecdsa.PublicKey

	// RequireSignature, when true, makes a valid issuer signature MANDATORY — the signed
	// path is the stronger anchor (it survives a benign republish, supports rotation, and
	// binds to a kid). Default false: a manifest authenticates as long as at least one
	// configured anchor validates it. To migrate pin-only -> signed you must DROP the pin
	// when adding signing keys: a still-configured pin authenticates one exact byte string,
	// so a pin+keys combo is "pin-pinned" — the keys cannot admit a different/newer manifest
	// until the pin is removed. Note the per-anchor rule is still strict in either case:
	// authenticate requires EVERY configured anchor that is present to validate (a pin,
	// once configured, must match; a signature, once present and keyed, must verify), so
	// "default false" relaxes which anchor is REQUIRED, never whether a present anchor may
	// fail. #13 may flip this default for production.
	RequireSignature bool

	// MinVersion is the initial downgrade floor: a manifest with Version < MinVersion is
	// rejected as a downgrade before it is ever accepted. After the provider accepts a
	// manifest, the floor advances to that manifest's Version, so a later fetch can never
	// roll back to an older revision FOR THE LIFETIME OF THIS PROVIDER. Zero means "no
	// initial floor" (the first accepted manifest sets it).
	//
	// The advanced floor is IN-MEMORY only: a process restart resets it to MinVersion, so
	// rollback protection across restarts is bounded by MinVersion and the manifest's
	// not_after, not by the highest version a previous process accepted. Durable
	// rollback state is Open Decision #13 (tracked in qurl-go issue #24); pin a high
	// MinVersion if cross-restart anti-rollback matters before #13 lands.
	MinVersion int64

	// ExpectedProfile, when non-empty, requires the manifest's Profile to equal it. A
	// mismatch fails closed (a manifest minted for a different profile/class must not be
	// accepted as this one). Empty disables the profile check.
	ExpectedProfile string

	// Now overrides the clock for expiry checks. Tests inject a fixed clock for
	// determinism; production leaves it nil (time.Now). The crypto core is
	// deliberately clock-free, but staleness/expiry is THIS layer's job, so the clock
	// lives here, not in the core.
	Now func() time.Time
}

// manifestClockSkewLeeway is the tolerance applied to the manifest's lower validity
// bound (issued_at). A manifest whose issued_at is in the FUTURE relative to the local
// clock is rejected as not-yet-valid — but only once it is more than this leeway ahead,
// so a manifest published a few seconds early or a client whose clock lags slightly is
// still accepted. Without the leeway a bare now < issued_at check would strand
// legitimate viewers on benign clock skew between the issuer and the client. The value
// mirrors a conservative NTP-grade skew budget; it is intentionally small relative to a
// manifest's lifetime, so it tightens the freshness window without being a real attack
// lever (the manifest is still pin/signature-authenticated and upper-bounded by
// not_after and the monotonic version floor).
const manifestClockSkewLeeway = 2 * time.Minute

// manifestClockSkewLeewaySec is manifestClockSkewLeeway in whole seconds, the unit the
// manifest's issued_at/not_after use (Unix seconds). Derived once here rather than
// recomputed per Resolve.
const manifestClockSkewLeewaySec = int64(manifestClockSkewLeeway / time.Second)

// Discovery-path sentinel errors. Each failure mode has its OWN sentinel so a caller
// (and a test) can assert the specific cause with errors.Is, and so removing any one
// guard makes exactly that test go red. All are fail-closed outcomes.
var (
	// ErrManifestUnverified is returned when a fetched manifest satisfies no configured
	// trust mode (no matching pin and no valid signature, or the only mode required is
	// not satisfied). It wraps the more specific cause where one applies.
	ErrManifestUnverified = errors.New("qurl: discovery manifest failed trust verification")
	// ErrManifestPinMismatch is returned when the manifest bytes' sha256 does not equal
	// the configured pin.
	ErrManifestPinMismatch = errors.New("qurl: discovery manifest pin mismatch")
	// ErrManifestExpired is returned when now > manifest.not_after.
	ErrManifestExpired = errors.New("qurl: discovery manifest expired")
	// ErrManifestNotYetValid is returned when manifest.issued_at is in the future by more
	// than manifestClockSkewLeeway — the lower-bound freshness guard, symmetric with
	// ErrManifestExpired. A manifest within the leeway is accepted (benign clock skew).
	ErrManifestNotYetValid = errors.New("qurl: discovery manifest not yet valid")
	// ErrManifestDowngrade is returned when manifest.version is below the provider's
	// downgrade floor (an attempted rollback to an older revision).
	ErrManifestDowngrade = errors.New("qurl: discovery manifest version downgrade")
	// ErrManifestSchema is returned when the envelope/manifest is structurally invalid
	// (unparseable, missing required fields, bad encoding, wrong profile, empty anchor
	// set or allowlist).
	ErrManifestSchema = errors.New("qurl: discovery manifest schema invalid")
	// ErrDiscoveryConfig is returned when DiscoveryConfig itself authenticates nothing
	// or is missing a fetcher (a misconfiguration that would otherwise trust blindly).
	ErrDiscoveryConfig = errors.New("qurl: discovery provider misconfigured")
)

// DiscoveryProvider is a Provider that resolves trust anchors and the relay
// allowlist from an authenticated discovery manifest. It re-fetches and re-verifies on
// every Resolve and returns the freshly built trust material; a fetch/verify failure
// returns the error (fail closed) rather than ever serving stale anchors. Concurrent
// Resolve calls are safe.
//
// NO CACHING — operational cost. Because every Resolve does a fresh HTTPS GET +
// authenticate, EnterPortal pays a network round-trip to the manifest endpoint on
// EVERY link open, and a down/slow manifest endpoint fails every open even while a
// recently-authenticated, still-in-window manifest exists. This is a deliberate
// fail-closed-over-availability stance for the mechanism. A deployment expecting high
// open volume should wrap this in a TTL cache that itself fails closed once not_after
// (or the TTL) elapses; whether prod ships such a cache (and its window) is Open
// Decision #13, tracked in qurl-go issue #24.
type DiscoveryProvider struct {
	cfg DiscoveryConfig

	mu sync.Mutex
	// floor is the downgrade floor: max(cfg.MinVersion, highest accepted Version). A
	// manifest with Version < floor is rejected, so an accepted revision can never be
	// rolled back while this provider lives. It is in-memory only and resets to
	// cfg.MinVersion on restart — see MinVersion for the cross-restart caveat (#13). Guarded by mu.
	floor int64
}

// NewDiscoveryProvider builds a DiscoveryProvider. It rejects a config that
// authenticates nothing — no fetcher, or NEITHER a pin NOR any manifest signing key —
// because such a provider could only "trust" a manifest blindly, which violates the
// pin-or-sign rule. This is the construction-time half of the fail-closed posture.
func NewDiscoveryProvider(cfg DiscoveryConfig) (*DiscoveryProvider, error) {
	if cfg.Fetcher == nil {
		return nil, fmt.Errorf("%w: a manifest fetcher is required", ErrDiscoveryConfig)
	}
	if len(cfg.PinSHA256) == 0 && len(cfg.ManifestKeys) == 0 {
		return nil, fmt.Errorf("%w: configure a pin (PinSHA256) and/or manifest signing keys (ManifestKeys) — a manifest must be pinned or signed, never blindly trusted", ErrDiscoveryConfig)
	}
	if len(cfg.PinSHA256) != 0 && len(cfg.PinSHA256) != 32 {
		return nil, fmt.Errorf("%w: PinSHA256 must be a 32-byte sha256 (got %d bytes)", ErrDiscoveryConfig, len(cfg.PinSHA256))
	}
	if cfg.RequireSignature && len(cfg.ManifestKeys) == 0 {
		return nil, fmt.Errorf("%w: RequireSignature set but no ManifestKeys configured", ErrDiscoveryConfig)
	}
	// Validate the manifest-signing keys at construction so a nil or non-P-256 entry
	// surfaces here, not on the first signed-manifest fetch. NewTrustStore is the same
	// validator the trust-anchor path uses (non-empty kid, non-nil P-256 point). It is
	// guarded on a non-empty map because pin-only mode (no ManifestKeys) is legal and
	// NewTrustStore rejects an empty map; the throwaway store is only used to validate.
	if len(cfg.ManifestKeys) != 0 {
		if _, err := qv2.NewTrustStore(cfg.ManifestKeys); err != nil {
			return nil, fmt.Errorf("%w: invalid ManifestKeys: %w", ErrDiscoveryConfig, err)
		}
	}
	// Defensively copy the trust-critical reference types so a caller mutating the
	// backing array/map AFTER construction cannot silently change the trust anchor
	// authenticate/verifyManifestSig read on every Resolve. cfg is otherwise stored by
	// value; PinSHA256 (slice) and ManifestKeys (map) are the reference fields that would
	// otherwise alias the caller's data. The map copy is shallow — the values are
	// *ecdsa.PublicKey for keys never mutated in place (qurl.NewTrustStore copies its map
	// the same way), so copying the map structure is the right depth and makes the
	// provider's documented immutability real rather than conventional. Both helpers map
	// nil to nil, preserving "no pin"/"no signing keys".
	cfg.PinSHA256 = bytes.Clone(cfg.PinSHA256)
	cfg.ManifestKeys = maps.Clone(cfg.ManifestKeys)
	return &DiscoveryProvider{cfg: cfg, floor: cfg.MinVersion}, nil
}

// Resolve fetches, authenticates, and decodes the discovery manifest into a trust
// store and relay allowlist. It fails closed on any verification, freshness, or schema
// fault. On success it advances the monotonic downgrade floor and returns the freshly
// built trust material.
//
// A nil receiver (a caller that ignored NewDiscoveryProvider's construction error and
// installed the nil *DiscoveryProvider) fails closed with ErrNotConfigured rather than
// panicking on the p.cfg field read — the same fail-closed footgun guard StaticProvider
// has.
func (p *DiscoveryProvider) Resolve(ctx context.Context) (*TrustStore, *RelayAllowlist, error) {
	if p == nil {
		return nil, nil, ErrNotConfigured
	}
	raw, err := p.cfg.Fetcher.Fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("qurl: fetch discovery manifest: %w", err)
	}

	env, manifestBytes, err := decodeEnvelope(raw)
	if err != nil {
		return nil, nil, err
	}

	// Authenticate the EXACT manifest bytes BEFORE parsing them for trust material.
	if err := p.authenticate(env, manifestBytes); err != nil {
		return nil, nil, err
	}

	manifest, err := parseManifest(manifestBytes)
	if err != nil {
		return nil, nil, err
	}
	if p.cfg.ExpectedProfile != "" && manifest.Profile != p.cfg.ExpectedProfile {
		return nil, nil, fmt.Errorf("%w: profile %q, want %q", ErrManifestSchema, manifest.Profile, p.cfg.ExpectedProfile)
	}

	// Freshness: not-yet-valid then expiry (clock), then downgrade (monotonic version).
	// All fail closed. Read the clock once so the compared and reported values agree.
	//
	// Lower bound (not-yet-valid): a manifest whose issued_at is in the future is rejected
	// once it is more than manifestClockSkewLeeway ahead of now, so a benignly skewed clock
	// or a slightly-early publish is still accepted while a clearly future-dated manifest
	// fails closed. This makes "in window" mean BOTH ends, symmetric with the expiry check.
	//
	// Upper bound (expiry): the boundary is inclusive — now == not_after is still valid;
	// the manifest expires the second AFTER not_after (a one-second grace at the exact
	// boundary, immaterial against the manifest's lifetime and matching "valid through
	// not_after").
	now := p.now().Unix()
	if now+manifestClockSkewLeewaySec < manifest.IssuedAt {
		return nil, nil, fmt.Errorf("%w: issued_at=%d, now=%d, leeway=%ds", ErrManifestNotYetValid, manifest.IssuedAt, now, manifestClockSkewLeewaySec)
	}
	if now > manifest.NotAfter {
		return nil, nil, fmt.Errorf("%w: not_after=%d, now=%d", ErrManifestExpired, manifest.NotAfter, now)
	}

	// Downgrade check + floor advance are one atomic step under the lock so concurrent
	// resolves see a monotonic floor and never roll back. The check stays BELT-AND-LOCK:
	// reading the floor and writing it must not straddle two acquisitions, or a racing
	// resolve could move the floor backward (a monotonicity TOCTOU). buildTrustMaterial
	// runs only after the floor check passes — so a downgrade/replay fails before the
	// issuer-DER parsing is spent, and it touches no provider state, so holding the lock
	// across it adds no contention (the expensive fetch already happened outside it).
	p.mu.Lock()
	defer p.mu.Unlock()
	if manifest.Version < p.floor {
		return nil, nil, fmt.Errorf("%w: version=%d < floor=%d", ErrManifestDowngrade, manifest.Version, p.floor)
	}
	ts, allow, err := buildTrustMaterial(manifest)
	if err != nil {
		return nil, nil, err
	}
	p.floor = manifest.Version
	return ts, allow, nil
}

// authenticate enforces the configured trust mode(s) over the exact manifest bytes.
// It is STRICTLY fail-closed: the manifest is accepted iff ALL of these hold —
//   - if a pin is configured, the bytes' digest MATCHES it (a mismatch fails closed);
//   - if signing keys are configured AND the envelope carries a signature, that
//     signature VERIFIES under the named kid (a present-but-bad signature fails closed,
//     even when a pin also matched — every configured, present anchor must validate);
//   - at least ONE anchor authenticated the bytes (pinned or signed);
//   - additionally, with RequireSignature, a valid signature is MANDATORY.
//
// So a manifest that is unpinned-or-pin-mismatched, or that carries a signature that
// does not verify, or that satisfies no anchor at all, is rejected. This is the
// safe-default MECHANISM; whether the production policy is pin-only, signed-only, or
// pin-AND-signed (and the exact precedence between them) is Open Decision #13, which
// selects/clamps these knobs — it must not loosen this posture without a threat-model
// decision recorded there. SigB64/Kid ride OUTSIDE the pinned/signed preimage, so an
// attacker who cannot alter the manifest bytes also cannot forge acceptance; corrupting
// a present signature only makes an otherwise-good manifest fail closed (deny), never
// admits a bad one.
func (p *DiscoveryProvider) authenticate(env *ManifestEnvelope, manifestBytes []byte) error {
	pinned := false
	if len(p.cfg.PinSHA256) != 0 {
		got := qv2.ManifestDigest(manifestBytes)
		// Both operands are non-secret public values (a content hash vs a configured
		// pin), so there is no timing oracle to defend here; the constant-time compare
		// is used purely for uniformity with the secret-comparison style elsewhere, not
		// because this comparison is sensitive.
		if subtle.ConstantTimeCompare(got[:], p.cfg.PinSHA256) != 1 {
			return ErrManifestPinMismatch
		}
		pinned = true
	}

	signed := false
	if len(p.cfg.ManifestKeys) != 0 && env.SigB64 != "" {
		if err := p.verifyManifestSig(env, manifestBytes); err != nil {
			return err
		}
		signed = true
	}

	if p.cfg.RequireSignature && !signed {
		return fmt.Errorf("%w: a valid issuer signature is required but the manifest carried none", ErrManifestUnverified)
	}
	if !pinned && !signed {
		return fmt.Errorf("%w: manifest matched no configured trust mode (pin or signature)", ErrManifestUnverified)
	}
	return nil
}

// verifyManifestSig resolves the manifest signing key for env.Kid and verifies the
// detached signature over the exact manifest bytes in the manifest signing domain.
//
// MANIFEST-SIGNING-KEY ROTATION (distinct from issuer-anchor rotation): the kid here
// names a MANIFEST-signing key in DiscoveryConfig.ManifestKeys, NOT an issuer trust
// anchor inside the manifest. An unknown kid fails closed (ErrManifestUnverified), so
// rotating the manifest signing key requires OVERLAP-PUBLISHING the new kid into every
// client's ManifestKeys BEFORE cutting the published manifest over to sign under it —
// otherwise a pin-valid, freshly-signed manifest under a not-yet-distributed kid is
// rejected here. This is a separate rotation from issuer-anchor (claims-signing) kid
// rotation, which lives inside the manifest's issuer set and is covered by
// the core/rotation_test.go.
func (p *DiscoveryProvider) verifyManifestSig(env *ManifestEnvelope, manifestBytes []byte) error {
	if env.Kid == "" {
		return fmt.Errorf("%w: signed manifest is missing its kid", ErrManifestSchema)
	}
	pub, ok := p.cfg.ManifestKeys[env.Kid]
	if !ok {
		return fmt.Errorf("%w: %w for manifest kid %q", ErrManifestUnverified, qv2.ErrUnknownKID, env.Kid)
	}
	sig, err := b64url.DecodeString(env.SigB64)
	if err != nil {
		return fmt.Errorf("%w: manifest sig is not valid base64url: %w", ErrManifestSchema, err)
	}
	if err := qv2.VerifyManifestSignature(pub, manifestBytes, sig); err != nil {
		return fmt.Errorf("%w: %w", ErrManifestUnverified, err)
	}
	return nil
}

func (p *DiscoveryProvider) now() time.Time {
	if p.cfg.Now != nil {
		return p.cfg.Now()
	}
	return time.Now()
}

// strictDecodeJSON decodes raw into v rejecting unknown fields AND trailing data after
// the top-level JSON object (a second concatenated value a lenient parser would ignore).
// It is the same strictness the core's typed-unmarshal pass applies (the parser
// strictUnmarshal): DisallowUnknownFields + a dec.More() trailing-data check. It does
// NOT do the core's full token-walk (duplicate-key / null rejection) — that heavier guard
// stays in the core because the manifest bytes here are already authenticated by the
// pin/signature, so only the legitimate signer can produce the bytes being parsed.
func strictDecodeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after JSON object")
	}
	return nil
}

// decodeEnvelope parses the fetched bytes into a ManifestEnvelope and decodes the
// inner manifest bytes (the pin/signature preimage), returning both.
func decodeEnvelope(raw []byte) (*ManifestEnvelope, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("%w: empty discovery response", ErrManifestSchema)
	}
	var env ManifestEnvelope
	if err := strictDecodeJSON(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("%w: parse envelope: %w", ErrManifestSchema, err)
	}
	if env.ManifestB64 == "" {
		return nil, nil, fmt.Errorf("%w: envelope is missing manifest_b64", ErrManifestSchema)
	}
	manifestBytes, err := b64url.DecodeString(env.ManifestB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: manifest_b64 is not valid base64url: %w", ErrManifestSchema, err)
	}
	if len(manifestBytes) == 0 {
		return nil, nil, fmt.Errorf("%w: manifest_b64 decoded to empty", ErrManifestSchema)
	}
	return &env, manifestBytes, nil
}

// parseManifest strict-parses the decoded manifest bytes via strictDecodeJSON: an
// unknown field or trailing data after the object fails closed rather than being
// silently ignored. (Duplicate-key/null rejection — the core's heavier token-walk — is left
// to the core since these bytes are already pin/signature-authenticated; see strictDecodeJSON.)
func parseManifest(manifestBytes []byte) (*Manifest, error) {
	var m Manifest
	if err := strictDecodeJSON(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("%w: parse manifest: %w", ErrManifestSchema, err)
	}
	if m.Version <= 0 {
		return nil, fmt.Errorf("%w: version must be a positive integer", ErrManifestSchema)
	}
	if m.IssuedAt <= 0 {
		return nil, fmt.Errorf("%w: issued_at must be a positive Unix timestamp", ErrManifestSchema)
	}
	if m.NotAfter <= 0 {
		return nil, fmt.Errorf("%w: not_after must be a positive Unix timestamp", ErrManifestSchema)
	}
	// A validity window that ends before it starts is internally contradictory; reject
	// it as a schema fault rather than letting the absolute expiry clock be the only gate.
	if m.NotAfter <= m.IssuedAt {
		return nil, fmt.Errorf("%w: not_after (%d) must be after issued_at (%d)", ErrManifestSchema, m.NotAfter, m.IssuedAt)
	}
	if len(m.Issuers) == 0 {
		return nil, fmt.Errorf("%w: manifest has no issuer trust anchors", ErrManifestSchema)
	}
	// Require at least one USABLE relay entry, not merely a non-empty slice.
	// NewRelayAllowlist trims and drops blank/whitespace entries, so a slice of only
	// blanks (e.g. ["", "  "]) is length-non-empty yet builds an allowlist that rejects
	// every relay — a schema-valid-but-unusable manifest. Reject it here so "schema
	// valid" implies "has a usable relay anchor". A real host alongside a stray blank is
	// still accepted (the blank is dropped downstream); only an all-blank list fails.
	hasUsableRelay := false
	for _, e := range m.RelayAllowlist {
		if strings.TrimSpace(e) != "" {
			hasUsableRelay = true
			break
		}
	}
	if !hasUsableRelay {
		return nil, fmt.Errorf("%w: manifest has no usable relay allowlist entries", ErrManifestSchema)
	}
	return &m, nil
}

// buildTrustMaterial turns an authenticated, in-window manifest into the the trust
// store and relay allowlist. It defers issuer-key parsing (and the empty-anchor-set
// rejection) to qurl.NewTrustStoreFromDER, reusing its fail-closed construction rather
// than re-validating here. The relay allowlist's emptiness is already gated upstream in
// parseManifest (an empty relay_allowlist is a schema fault), so qurl.NewRelayAllowlist
// only needs to index the entries.
func buildTrustMaterial(m *Manifest) (*qv2.TrustStore, *qv2.RelayAllowlist, error) {
	derByKID := make(map[string][]byte, len(m.Issuers))
	for _, iss := range m.Issuers {
		if iss.Kid == "" {
			return nil, nil, fmt.Errorf("%w: an issuer entry is missing its kid", ErrManifestSchema)
		}
		if _, dup := derByKID[iss.Kid]; dup {
			return nil, nil, fmt.Errorf("%w: duplicate issuer kid %q", ErrManifestSchema, iss.Kid)
		}
		der, err := b64url.DecodeString(iss.SPKIDERB64)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: issuer %q spki_der_b64 is not valid base64url: %w", ErrManifestSchema, iss.Kid, err)
		}
		derByKID[iss.Kid] = der
	}
	ts, err := qv2.NewTrustStoreFromDER(derByKID)
	if err != nil {
		// A bad key blob (wrong curve, unparseable DER) is a schema fault from the
		// provider's view: the manifest carried an unusable anchor.
		return nil, nil, fmt.Errorf("%w: %w", ErrManifestSchema, err)
	}
	allow := qv2.NewRelayAllowlist(m.RelayAllowlist)
	return ts, allow, nil
}
