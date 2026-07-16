package qurl

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Wire shapes for NHP-native agent registration: the opaque JSON bodies carried
// inside relayknock NHP messages (OTP / REG) and returned inside the NHP_RAK
// reply, plus the two qurl-service HTTPS response envelopes (registration-info
// pre-flight and registration/complete). relayknock is body-shape agnostic — it
// seals and opens these bytes without interpreting them — so the request/reply
// JSON contract lives here.
//
// The RAK errCode → typed-error mapping is the load-bearing part: it turns the
// enrollment service's coded denial into the actionable sentinels in
// register_errors.go.

// agentAspID is the NHP authorization-service-provider id for the agent
// registration path (the qURL resolve path uses qurlAspID = "qurl").
const agentAspID = "agent"

// --- NHP message bodies (sealed into relayknock OTP / REG) ---

// otpRequestBody is the one-way NHP_OTP body: it asks the enrollment service to
// email a one-time code for an account key. usrId is the key id, pass is the API
// key secret. There is no reply — a conforming relay acknowledges dispatch with
// HTTP 202.
type otpRequestBody struct {
	UsrID string `json:"usrId"`
	DevID string `json:"devId"`
	AspID string `json:"aspId"`
	Pass  string `json:"pass"`
}

// registerRequestBody is the round-trip NHP_REG body. otp is the enrollment
// credential: for a pre-issued (bootstrap) key it is the key secret itself; for
// an account key it is the emailed one-time code. usrData carries audit metadata
// and the takeover intent. The device X25519 public key is NOT in the body — the
// server learns it as the authenticated Noise initiator static key and binds it.
type registerRequestBody struct {
	UsrID   string           `json:"usrId"`
	DevID   string           `json:"devId"`
	AspID   string           `json:"aspId"`
	OTP     string           `json:"otp"`
	UsrData registerUserData `json:"usrData"`
}

// registerUserData is the usrData sub-object of a registration body.
type registerUserData struct {
	Hostname string `json:"hostname,omitempty"`
	Version  string `json:"version,omitempty"`
	Takeover bool   `json:"takeover,omitempty"`
}

// --- NHP_RAK reply body ---

// registerAckBody is the decrypted NHP_RAK body. errCode "0" (or empty) is
// success; a "521xx" code is a typed denial mapped by mapRAKError.
type registerAckBody struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
	AspID   string `json:"aspId"`
}

// rakSuccess is the NHP_RAK success errCode. errCode is a string field; "" and
// "0" both mean success. It aliases reply.go's errSuccess so the single "0"
// success literal has one source across the resolve and enrollment reply paths.
const rakSuccess = errSuccess

func (b registerAckBody) isSuccess() bool {
	// Trim to match mapRAKError, which trims before matching: a whitespace-padded
	// code (e.g. " 0 ") must not slip past success here only to miss every mapping
	// after mapRAKError trims it and surface as a spurious RegistrationDenyError.
	code := strings.TrimSpace(b.ErrCode)
	return code == "" || code == rakSuccess
}

// parseRegisterAck decodes the decrypted NHP_RAK body. An empty body decodes to a
// zero-value ack whose empty errCode reads as success (isSuccess), so the run
// proceeds to the completion fetch. That is safe not because the body is empty but
// because the RAK was already authenticated by the Noise handshake and the
// completion endpoint re-verifies server-side enrollment — a spurious empty RAK
// simply fails there. The integrity guard is that authenticated-then-completion-
// verified tail, not the emptiness. A non-empty body that is not valid JSON is a
// hard error.
func parseRegisterAck(body []byte) (*registerAckBody, error) {
	var ack registerAckBody
	if len(body) == 0 {
		return &ack, nil
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, fmt.Errorf("%w: parse registration reply body: %w", ErrRegisterReplyMalformed, err)
	}
	// Defense-in-depth on the echoed aspId: the RAK is Noise-authenticated, but
	// every other wire field gets a consistency check, so a reply carrying a
	// mismatched aspId (a RAK for a different authorization service) is treated as
	// malformed rather than acted on. An absent aspId is tolerated (empty body ⇒
	// success is handled above; a server may omit it).
	if ack.AspID != "" && ack.AspID != agentAspID {
		return nil, fmt.Errorf("%w: registration reply aspId %q, want %q", ErrRegisterReplyMalformed, ack.AspID, agentAspID)
	}
	return &ack, nil
}

// NHP_RAK error codes (the enrollment wire contract). These map to the typed
// sentinels in register_errors.go; an unrecognized code falls through to
// RegistrationDenyError so a caller still sees the raw code.
const (
	rakCredentialInvalid = "52100" // OTP/credential wrong
	rakCredentialExpired = "52101" // OTP expired
	rakAttemptsExceeded  = "52102" // too many attempts (lockout)
	rakIdentityConflict  = "52103" // device identity already enrolled elsewhere
	rakRateLimited       = "52104" // rate limited
	rakEmailUnavailable  = "52105" // no account email for the code
	rakInvalidAPIKey     = "52106" // API key invalid
	rakRegistrationOff   = "52107" // registration disabled
	rakBootstrapConsumed = "52108" // pre-issued setup key already consumed
	rakInvalidInput      = "52109" // malformed registration input (e.g. device id)
)

// pathKind distinguishes the two enrollment paths for the error mapping. The one
// code whose meaning depends on the path is 52100: on the account path it is a
// wrong emailed OTP (ErrOTPIncorrect); on the bootstrap path the credential IS
// the key, so a rejected credential is a rejected key (ErrKeyRejected).
type pathKind int

const (
	// pathUnknown is the zero value returned when path selection itself fails.
	// Lifecycle callers must not pass it to the RAK mapper, whose defensive
	// fallback preserves a raw denial rather than guessing a credential meaning.
	pathUnknown pathKind = iota
	pathAccount
	pathBootstrap
)

// bootstrapConsumedGuidance is the operator-facing next step when a one-shot
// setup key appears already consumed. It is shared verbatim by the RAK 52108
// mapping (rakMappings) and the completion-path mapper (mapCompletionHTTPError),
// which can both report the consumed-setup-key condition, so the guidance has a
// single source.
const bootstrapConsumedGuidance = "rerun LayerV setup for a fresh key or restore the completed agent state"

// rakMapping is one row of rakMappings: the typed sentinel a known RAK code maps
// to, plus the actionable guidance detail that leads the mapped error message
// (the service-provided errMsg is appended after it by detailSuffix).
type rakMapping struct {
	sentinel error
	detail   string
}

// rakMappings is the single source for both the RAK code → sentinel resolution
// (sentinelForRAKCode) and the RAK code → actionable error (mapRAKError), so the
// two can no longer drift as codes are added. Every known, path-INDEPENDENT code
// lives here; the one path-dependent code (rakCredentialInvalid / 52100) is
// deliberately ABSENT — its meaning splits by enrollment path, so mapRAKError
// resolves it ahead of the table and sentinelForRAKCode returns nil for it.
var rakMappings = map[string]rakMapping{
	rakCredentialExpired: {ErrOTPExpired, "request a fresh code by re-running the same operation with no WithOTP, then re-run it with the new code"},
	rakAttemptsExceeded:  {ErrRegistrationRateLimited, "too many attempts; wait before retrying registration"},
	rakRateLimited:       {ErrRegistrationRateLimited, "back off and retry registration later"},
	rakIdentityConflict:  {ErrAgentIdentityConflict, "this device id is already enrolled; re-run with qurl.WithTakeover to re-bind it, or pick a different qurl.WithDeviceID"},
	rakEmailUnavailable:  {ErrNoAccountEmail, "add an email to the account or register with a pre-issued key"},
	rakInvalidAPIKey:     {ErrKeyRejected, "check the API key and re-run registration"},
	rakRegistrationOff:   {ErrRegistrationDisabled, "agent registration is disabled for this account"},
	rakBootstrapConsumed: {ErrBootstrapSetupKeyConsumed, bootstrapConsumedGuidance},
	rakInvalidInput:      {ErrRegistrationInvalidInput, "the device id or registration input was malformed; use a valid identifier with qurl.WithDeviceID"},
}

// sentinelForRAKCode returns the path-independent sentinel a known RAK code maps
// to, or nil for an unknown code (or 52100, which is path-dependent — see
// mapRAKError). It backs RegistrationDenyError.Is so a raw deny still matches the
// typed sentinel for its code.
func sentinelForRAKCode(code string) error {
	if m, ok := rakMappings[strings.TrimSpace(code)]; ok {
		return m.sentinel
	}
	return nil
}

// mapRAKError turns a non-success NHP_RAK body into a typed error. Known codes
// become the actionable sentinels (from rakMappings); 52100 is resolved by path;
// anything else becomes a RegistrationDenyError carrying the raw code and message
// so a caller can act on a code newer than this SDK.
func mapRAKError(ack *registerAckBody, path pathKind) error {
	code := strings.TrimSpace(ack.ErrCode)
	msg := strings.TrimSpace(ack.ErrMsg)

	// 52100 is path-dependent (see pathKind), so it is resolved ahead of the
	// table, which deliberately omits it: on the bootstrap path the credential IS
	// the key (a rejected key), on the account path it is a wrong emailed OTP.
	if code == rakCredentialInvalid {
		switch path {
		case pathBootstrap:
			return fmt.Errorf("%w: pre-issued key was rejected by the enrollment service%s", ErrKeyRejected, detailSuffix(msg))
		case pathAccount:
			return fmt.Errorf("%w: the one-time code was rejected; re-run the same operation with the correct qurl.WithOTP code%s", ErrOTPIncorrect, detailSuffix(msg))
		default:
			// Do not guess the credential meaning when an internal caller has not
			// selected a path. Preserve the raw denial for diagnosis instead.
			return &RegistrationDenyError{ErrCode: ack.ErrCode, ErrMsg: ack.ErrMsg}
		}
	}
	if m, ok := rakMappings[code]; ok {
		return fmt.Errorf("%w: %s%s", m.sentinel, m.detail, detailSuffix(msg))
	}
	// Unknown code: surface the raw deny so a caller can act on a code newer than
	// this SDK.
	return &RegistrationDenyError{ErrCode: ack.ErrCode, ErrMsg: ack.ErrMsg}
}

// detailSuffix appends the service-provided message to a mapped error when
// present, so the actionable SDK guidance leads and the raw detail trails.
func detailSuffix(msg string) string {
	if msg == "" {
		return ""
	}
	return " (service said: " + msg + ")"
}

// --- qurl-service HTTPS response envelopes ---

// registrationInfoResponse is the data payload of GET /v1/agent/registration-info,
// the side-effect-free pre-flight. key_kind selects the enrollment path.
type registrationInfoResponse struct {
	KeyKind       string            `json:"key_kind"` // "bootstrap" | "account"
	KeyID         string            `json:"key_id"`
	NHPServerPeer NHPServerPeerInfo `json:"nhp_server_peer"`
	Relay         registrationRelay `json:"relay"`
	MaskedEmail   string            `json:"masked_email"`
}

// registrationRelay is the relay coordinates the pre-flight returns: the relay
// base URL to POST NHP packets to, and the server id used in the /relay/{id}
// path. server_id must equal relayknock.PubKeyFingerprint(nhp_server_peer key).
type registrationRelay struct {
	BaseURL  string `json:"base_url"`
	ServerID string `json:"server_id"`
}

// Key-kind values returned by registration-info.
const (
	keyKindBootstrap = "bootstrap"
	keyKindAccount   = "account"
)

// validate checks the pre-flight response. errKind is the caller's front-door
// config-error class (ErrInvalidRegisterConfig / ErrInvalidBootstrapConfig),
// threaded so a malformed response surfaces the class of the front door that was
// called — the same invariant the load-path validators preserve.
func (r registrationInfoResponse) validate(now time.Time, errKind error) error {
	switch strings.TrimSpace(r.KeyKind) {
	case keyKindBootstrap, keyKindAccount:
	default:
		return fmt.Errorf("%w: registration-info returned unknown key_kind %q", errKind, r.KeyKind)
	}
	if strings.TrimSpace(r.KeyID) == "" {
		return fmt.Errorf("%w: registration-info missing key_id", errKind)
	}
	if strings.TrimSpace(r.Relay.BaseURL) == "" {
		return fmt.Errorf("%w: registration-info missing relay base_url", errKind)
	}
	if err := validateHTTPSOrLoopbackURL(r.Relay.BaseURL, "relay base_url", errKind); err != nil {
		return err
	}
	if strings.TrimSpace(r.Relay.ServerID) == "" {
		return fmt.Errorf("%w: registration-info missing relay server_id", errKind)
	}
	return validateNHPServerPeerInfo(r.NHPServerPeer, now, true, "registration-info", errKind)
}

// completionResponse is the data payload of POST /v1/agent/registration/complete.
// It mints the device REST credential and corroborates the durable agent
// identity + NHP peer key. The response cannot replace the peer that
// authenticated the RAK; registration orchestration asserts the public keys
// agree and retains the RAK peer's coordinates and lease.
type completionResponse struct {
	AgentID       string            `json:"agent_id"`
	RegisteredAt  *time.Time        `json:"registered_at"`
	NHPServerPeer NHPServerPeerInfo `json:"nhp_server_peer"`
	DeviceAPIKey  string            `json:"device_api_key"`
}

// validate checks the completion response. errKind is the caller's front-door
// config-error class, threaded like registrationInfoResponse.validate so a
// malformed completion surfaces the calling front door's class.
func (r completionResponse) validate(_ time.Time, errKind error) error {
	if strings.TrimSpace(r.AgentID) == "" {
		return fmt.Errorf("%w: completion response missing agent_id", errKind)
	}
	if r.RegisteredAt == nil {
		return fmt.Errorf("%w: completion response missing registered_at", errKind)
	}
	if r.DeviceAPIKey == "" {
		return fmt.Errorf("%w: completion response missing device_api_key", errKind)
	}
	if err := validateExactBearerToken(r.DeviceAPIKey, "completion response device_api_key", errKind); err != nil {
		return err
	}
	// Completion only corroborates the RAK-authenticated public key. Its host,
	// port, and lease are never persisted, so irrelevant coordinate defects must
	// not turn a successfully minted credential into recovery-required ambiguity.
	// The public key is identity, not a coordinate: require its canonical, usable
	// X25519 representation before comparing it with the RAK peer. A malformed or
	// ambiguous identity correctly makes the minted response recovery-required.
	// Do not replace this with validateNHPServerPeerInfo: registration-info plus
	// the authenticated RAK are the sole coordinate/lease authority.
	return validateNHPServerPublicKey(r.NHPServerPeer.PublicKeyB64, "completion response", errKind)
}

// completeRequestBody is the POST /v1/agent/registration/complete request.
type completeRequestBody struct {
	DeviceID        string `json:"device_id"`
	DevicePubKeyB64 string `json:"device_pubkey_b64"`
}
