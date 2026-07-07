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
// "0" both mean success, matching the qURL resolve path's isSuccess convention.
const rakSuccess = "0"

func (b registerAckBody) isSuccess() bool { return b.ErrCode == "" || b.ErrCode == rakSuccess }

// parseRegisterAck decodes the decrypted NHP_RAK body. An empty body is treated
// as a zero-value ack (no errCode) so a malformed empty reply surfaces as a
// missing-success failure rather than a JSON error, mirroring parseAck.
func parseRegisterAck(body []byte) (*registerAckBody, error) {
	var ack registerAckBody
	if len(body) == 0 {
		return &ack, nil
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, fmt.Errorf("qurl: parse registration reply body: %w", err)
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
	pathAccount pathKind = iota
	pathBootstrap
)

// sentinelForRAKCode returns the path-independent sentinel a known RAK code maps
// to, or nil for an unknown code (or 52100, which is path-dependent — see
// mapRAKError). It backs RegistrationDenyError.Is so a raw deny still matches the
// typed sentinel for its code.
func sentinelForRAKCode(code string) error {
	switch strings.TrimSpace(code) {
	case rakCredentialExpired:
		return ErrOTPExpired
	case rakAttemptsExceeded, rakRateLimited:
		return ErrRegistrationRateLimited
	case rakIdentityConflict:
		return ErrAgentIdentityConflict
	case rakEmailUnavailable:
		return ErrNoAccountEmail
	case rakInvalidAPIKey:
		return ErrKeyRejected
	case rakRegistrationOff:
		return ErrRegistrationDisabled
	case rakBootstrapConsumed:
		return ErrBootstrapSetupKeyConsumed
	case rakInvalidInput:
		return ErrRegistrationInvalidInput
	default:
		return nil
	}
}

// mapRAKError turns a non-success NHP_RAK body into a typed error. Known codes
// become the actionable sentinels; 52100 is resolved by path; anything else
// becomes a RegistrationDenyError carrying the raw code and message so a caller
// can act on a code newer than this SDK.
func mapRAKError(ack *registerAckBody, path pathKind) error {
	code := strings.TrimSpace(ack.ErrCode)
	msg := strings.TrimSpace(ack.ErrMsg)

	switch code {
	case rakCredentialInvalid:
		if path == pathBootstrap {
			return fmt.Errorf("%w: pre-issued key was rejected by the enrollment service%s", ErrKeyRejected, detailSuffix(msg))
		}
		return fmt.Errorf("%w: the one-time code was rejected; re-run qurl.RegisterAgent with the correct qurl.WithOTP code%s", ErrOTPIncorrect, detailSuffix(msg))
	case rakCredentialExpired:
		return fmt.Errorf("%w: request a fresh code by re-running qurl.RegisterAgent with no WithOTP, then supply the new code%s", ErrOTPExpired, detailSuffix(msg))
	case rakAttemptsExceeded:
		return fmt.Errorf("%w: too many attempts; wait before retrying registration%s", ErrRegistrationRateLimited, detailSuffix(msg))
	case rakRateLimited:
		return fmt.Errorf("%w: back off and retry registration later%s", ErrRegistrationRateLimited, detailSuffix(msg))
	case rakIdentityConflict:
		return fmt.Errorf("%w: this device id is already enrolled; re-run with qurl.WithTakeover to re-bind it, or pick a different qurl.WithDeviceID%s", ErrAgentIdentityConflict, detailSuffix(msg))
	case rakEmailUnavailable:
		return fmt.Errorf("%w: add an email to the account or register with a pre-issued key%s", ErrNoAccountEmail, detailSuffix(msg))
	case rakInvalidAPIKey:
		return fmt.Errorf("%w: check the API key and re-run registration%s", ErrKeyRejected, detailSuffix(msg))
	case rakRegistrationOff:
		return fmt.Errorf("%w: agent registration is disabled for this account%s", ErrRegistrationDisabled, detailSuffix(msg))
	case rakBootstrapConsumed:
		return fmt.Errorf("%w: rerun LayerV setup for a fresh key or restore the completed agent state%s", ErrBootstrapSetupKeyConsumed, detailSuffix(msg))
	case rakInvalidInput:
		return fmt.Errorf("%w: the device id or registration input was malformed; use a valid identifier with qurl.WithDeviceID%s", ErrRegistrationInvalidInput, detailSuffix(msg))
	default:
		// Only the unknown-code path returns the raw deny, so build it here rather
		// than on every call.
		return &RegistrationDenyError{ErrCode: ack.ErrCode, ErrMsg: ack.ErrMsg}
	}
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

func (r registrationInfoResponse) validate(now time.Time) error {
	switch strings.TrimSpace(r.KeyKind) {
	case keyKindBootstrap, keyKindAccount:
	default:
		return fmt.Errorf("%w: registration-info returned unknown key_kind %q", ErrInvalidRegisterConfig, r.KeyKind)
	}
	if strings.TrimSpace(r.KeyID) == "" {
		return fmt.Errorf("%w: registration-info missing key_id", ErrInvalidRegisterConfig)
	}
	if strings.TrimSpace(r.Relay.BaseURL) == "" {
		return fmt.Errorf("%w: registration-info missing relay base_url", ErrInvalidRegisterConfig)
	}
	if err := validateHTTPSOrLoopbackURL(r.Relay.BaseURL, "relay base_url", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	if strings.TrimSpace(r.Relay.ServerID) == "" {
		return fmt.Errorf("%w: registration-info missing relay server_id", ErrInvalidRegisterConfig)
	}
	return validateNHPServerPeerInfo(r.NHPServerPeer, now, "registration-info", ErrInvalidRegisterConfig)
}

// completionResponse is the data payload of POST /v1/agent/registration/complete.
// It mints (or returns) the device REST credential and confirms the durable
// agent identity + NHP peer.
type completionResponse struct {
	AgentID       string            `json:"agent_id"`
	RegisteredAt  *time.Time        `json:"registered_at"`
	NHPServerPeer NHPServerPeerInfo `json:"nhp_server_peer"`
	DeviceAPIKey  string            `json:"device_api_key"`
}

func (r completionResponse) validate(now time.Time) error {
	if strings.TrimSpace(r.AgentID) == "" {
		return fmt.Errorf("%w: completion response missing agent_id", ErrInvalidRegisterConfig)
	}
	if r.RegisteredAt == nil {
		return fmt.Errorf("%w: completion response missing registered_at", ErrInvalidRegisterConfig)
	}
	if strings.TrimSpace(r.DeviceAPIKey) == "" {
		return fmt.Errorf("%w: completion response missing device_api_key", ErrInvalidRegisterConfig)
	}
	return validateNHPServerPeerInfo(r.NHPServerPeer, now, "completion response", ErrInvalidRegisterConfig)
}

// completeRequestBody is the POST /v1/agent/registration/complete request.
type completeRequestBody struct {
	DeviceID        string `json:"device_id"`
	DevicePubKeyB64 string `json:"device_pubkey_b64"`
}
