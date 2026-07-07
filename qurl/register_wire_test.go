package qurl

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Pure wire-mapping tests: the NHP_RAK errCode → typed-error table (including the
// path-dependent 52100), the response envelope validation, and the JSON body
// shapes. These are exhaustive and fast; the end-to-end flow tests in
// register_test.go cover the orchestration that reaches them.

func TestMapRAKError_Table(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		path    pathKind
		want    error
		wantMsg string // substring the actionable message must contain
	}{
		{name: "52100 account = otp incorrect", code: rakCredentialInvalid, path: pathAccount, want: ErrOTPIncorrect, wantMsg: "WithOTP"},
		{name: "52100 bootstrap = key rejected", code: rakCredentialInvalid, path: pathBootstrap, want: ErrKeyRejected, wantMsg: "pre-issued key"},
		{name: "52101 expired", code: rakCredentialExpired, path: pathAccount, want: ErrOTPExpired, wantMsg: "fresh"},
		{name: "52102 attempts exceeded", code: rakAttemptsExceeded, path: pathAccount, want: ErrRegistrationRateLimited, wantMsg: "too many attempts"},
		{name: "52103 identity conflict", code: rakIdentityConflict, path: pathAccount, want: ErrAgentIdentityConflict, wantMsg: "WithTakeover"},
		{name: "52104 rate limited", code: rakRateLimited, path: pathAccount, want: ErrRegistrationRateLimited, wantMsg: "back off"},
		{name: "52105 no email", code: rakEmailUnavailable, path: pathAccount, want: ErrNoAccountEmail, wantMsg: "email"},
		{name: "52106 invalid api key", code: rakInvalidAPIKey, path: pathAccount, want: ErrKeyRejected, wantMsg: "API key"},
		{name: "52107 registration disabled", code: rakRegistrationOff, path: pathAccount, want: ErrRegistrationDisabled, wantMsg: "disabled"},
		{name: "52108 bootstrap consumed", code: rakBootstrapConsumed, path: pathBootstrap, want: ErrBootstrapSetupKeyConsumed, wantMsg: "rerun LayerV setup"},
		{name: "52109 invalid input", code: rakInvalidInput, path: pathAccount, want: ErrRegistrationInvalidInput, wantMsg: "device id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapRAKError(&registerAckBody{ErrCode: tt.code, ErrMsg: "svc detail"}, tt.path)
			if !errors.Is(err, tt.want) {
				t.Fatalf("code %s path %d: want %v, got %v", tt.code, tt.path, tt.want, err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("code %s: message %q lacks actionable %q", tt.code, err.Error(), tt.wantMsg)
			}
			// The service-provided detail is carried through.
			if !strings.Contains(err.Error(), "svc detail") {
				t.Errorf("code %s: message %q dropped the service detail", tt.code, err.Error())
			}
		})
	}
}

func TestMapRAKError_UnknownCodeIsRegistrationDeny(t *testing.T) {
	err := mapRAKError(&registerAckBody{ErrCode: "52199", ErrMsg: "future failure"}, pathAccount)
	var deny *RegistrationDenyError
	if !errors.As(err, &deny) {
		t.Fatalf("unknown code: want *RegistrationDenyError, got %v", err)
	}
	if deny.ErrCode != "52199" || deny.ErrMsg != "future failure" {
		t.Fatalf("deny = %#v", deny)
	}
	if !strings.Contains(err.Error(), "52199") || !strings.Contains(err.Error(), "future failure") {
		t.Errorf("deny message %q missing raw code/msg", err.Error())
	}
}

func TestRegistrationDenyError_IsBridgesKnownCode(t *testing.T) {
	// A RegistrationDenyError carrying a KNOWN code still matches the typed
	// sentinel via Is(), so a caller that only kept the deny path is not stranded.
	deny := &RegistrationDenyError{ErrCode: rakIdentityConflict}
	if !errors.Is(deny, ErrAgentIdentityConflict) {
		t.Fatal("RegistrationDenyError with 52103 should match ErrAgentIdentityConflict")
	}
	// The path-dependent 52100 is NOT bridged (its meaning needs the path), so a
	// raw deny for it matches neither credential sentinel.
	deny100 := &RegistrationDenyError{ErrCode: rakCredentialInvalid}
	if errors.Is(deny100, ErrOTPIncorrect) || errors.Is(deny100, ErrKeyRejected) {
		t.Fatal("52100 must not bridge to a path-specific sentinel via Is()")
	}
	// A truly unknown code matches nothing.
	if errors.Is(&RegistrationDenyError{ErrCode: "50000"}, ErrKeyRejected) {
		t.Fatal("unknown code should not match any sentinel")
	}
}

func TestRegisterAckBody_IsSuccess(t *testing.T) {
	for _, code := range []string{"", "0"} {
		if !(registerAckBody{ErrCode: code}).isSuccess() {
			t.Errorf("errCode %q should be success", code)
		}
	}
	if (registerAckBody{ErrCode: "52100"}).isSuccess() {
		t.Error("errCode 52100 should not be success")
	}
}

func TestParseRegisterAck_EmptyBodyIsZeroValue(t *testing.T) {
	ack, err := parseRegisterAck(nil)
	if err != nil {
		t.Fatalf("parseRegisterAck(nil): %v", err)
	}
	// An empty body decodes to a zero-value ack: no errCode. Per the qURL
	// convention (errCode "" == success, mirroring parseAck), that reads as
	// success, and the caller proceeds to the completion fetch — a malformed
	// empty reply cannot mint a credential on its own.
	if ack.ErrCode != "" {
		t.Errorf("empty body ErrCode = %q, want empty", ack.ErrCode)
	}
	if !ack.isSuccess() {
		t.Error("empty body should read as success (errCode empty), matching parseAck")
	}
}

func TestParseRegisterAck_MalformedBodyErrors(t *testing.T) {
	if _, err := parseRegisterAck([]byte("{not json")); err == nil {
		t.Fatal("malformed RAK body should error")
	}
}

func TestRegistrationInfoResponse_Validate(t *testing.T) {
	goodPeer := NHPServerPeerInfo{
		PublicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Host:         "nhp.example.test",
		Port:         62206,
	}
	base := registrationInfoResponse{
		KeyKind:       keyKindBootstrap,
		KeyID:         "key_x",
		NHPServerPeer: goodPeer,
		Relay:         registrationRelay{BaseURL: "https://relay.example.test", ServerID: "abcdefghijk"},
	}
	if err := base.validate(time.Now(), ErrInvalidRegisterConfig); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*registrationInfoResponse)
		want string
	}{
		{"unknown key kind", func(r *registrationInfoResponse) { r.KeyKind = "mystery" }, "unknown key_kind"},
		{"missing key id", func(r *registrationInfoResponse) { r.KeyID = "" }, "missing key_id"},
		{"missing relay base", func(r *registrationInfoResponse) { r.Relay.BaseURL = "" }, "missing relay base_url"},
		{"non-https relay base", func(r *registrationInfoResponse) { r.Relay.BaseURL = "ftp://x" }, "must use http"},
		{"missing server id", func(r *registrationInfoResponse) { r.Relay.ServerID = "" }, "missing relay server_id"},
		{"bad peer key", func(r *registrationInfoResponse) { r.NHPServerPeer.PublicKeyB64 = "not-base64" }, "not standard base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			tt.edit(&r)
			err := r.validate(time.Now(), ErrInvalidRegisterConfig)
			if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want ErrInvalidRegisterConfig containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestRegistrationInfoResponse_AllowsLoopbackRelay(t *testing.T) {
	// The fakes use loopback http relays; validate must permit them like the rest
	// of the SDK's HTTPS-or-loopback rule.
	r := registrationInfoResponse{
		KeyKind:       keyKindAccount,
		KeyID:         "key_x",
		NHPServerPeer: NHPServerPeerInfo{PublicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Host: "h", Port: 1},
		Relay:         registrationRelay{BaseURL: "http://127.0.0.1:8080", ServerID: "abcdefghijk"},
	}
	if err := r.validate(time.Now(), ErrInvalidRegisterConfig); err != nil {
		t.Fatalf("loopback relay rejected: %v", err)
	}
}

func TestCompletionResponse_Validate(t *testing.T) {
	now := time.Now().UTC()
	goodPeer := NHPServerPeerInfo{PublicKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Host: "h", Port: 1}
	base := completionResponse{
		AgentID:       "agent-x",
		RegisteredAt:  &now,
		NHPServerPeer: goodPeer,
		DeviceAPIKey:  "lv_device_secret",
	}
	if err := base.validate(time.Now(), ErrInvalidRegisterConfig); err != nil {
		t.Fatalf("valid completion rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*completionResponse)
		want string
	}{
		{"missing agent id", func(r *completionResponse) { r.AgentID = "" }, "missing agent_id"},
		{"missing registered_at", func(r *completionResponse) { r.RegisteredAt = nil }, "missing registered_at"},
		{"missing device key", func(r *completionResponse) { r.DeviceAPIKey = "" }, "missing device_api_key"},
		{"bad peer", func(r *completionResponse) { r.NHPServerPeer.Port = 0 }, "missing NHP peer port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			tt.edit(&r)
			err := r.validate(time.Now(), ErrInvalidRegisterConfig)
			if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want ErrInvalidRegisterConfig containing %q, got %v", tt.want, err)
			}
		})
	}
}

// TestNHPBodyShapes pins the JSON field names of the OTP and REG bodies (the
// opaque bytes relayknock seals), so a rename that would break server interop is
// caught here.
func TestNHPBodyShapes(t *testing.T) {
	otpRaw, err := json.Marshal(otpRequestBody{UsrID: "key_x", DevID: "agent-1", AspID: agentAspID, Pass: "secret"})
	if err != nil {
		t.Fatalf("marshal otp body: %v", err)
	}
	var otpMap map[string]any
	if err := json.Unmarshal(otpRaw, &otpMap); err != nil {
		t.Fatalf("unmarshal otp body: %v", err)
	}
	for _, k := range []string{"usrId", "devId", "aspId", "pass"} {
		if _, ok := otpMap[k]; !ok {
			t.Errorf("otp body missing key %q (got %v)", k, otpMap)
		}
	}
	if otpMap["aspId"] != "agent" {
		t.Errorf("otp aspId = %v, want agent", otpMap["aspId"])
	}

	regRaw, err := json.Marshal(registerRequestBody{
		UsrID: "key_x", DevID: "agent-1", AspID: agentAspID, OTP: "123456",
		UsrData: registerUserData{Hostname: "host", Version: "1.2.3", Takeover: true},
	})
	if err != nil {
		t.Fatalf("marshal reg body: %v", err)
	}
	var regMap map[string]any
	if err := json.Unmarshal(regRaw, &regMap); err != nil {
		t.Fatalf("unmarshal reg body: %v", err)
	}
	for _, k := range []string{"usrId", "devId", "aspId", "otp", "usrData"} {
		if _, ok := regMap[k]; !ok {
			t.Errorf("reg body missing key %q (got %v)", k, regMap)
		}
	}
	usrData, ok := regMap["usrData"].(map[string]any)
	if !ok {
		t.Fatalf("reg usrData is not an object: %v", regMap["usrData"])
	}
	if usrData["hostname"] != "host" || usrData["version"] != "1.2.3" || usrData["takeover"] != true {
		t.Errorf("reg usrData = %v", usrData)
	}
}

// TestSentinelForRAKCode covers the path-independent sentinel lookup that backs
// RegistrationDenyError.Is (52100 is path-dependent, so it maps to nil here).
func TestSentinelForRAKCode(t *testing.T) {
	if sentinelForRAKCode(rakCredentialInvalid) != nil {
		t.Error("52100 is path-dependent and must not have a path-independent sentinel")
	}
	if !errors.Is(sentinelForRAKCode(rakBootstrapConsumed), ErrBootstrapSetupKeyConsumed) {
		t.Error("52108 should map to ErrBootstrapSetupKeyConsumed")
	}
	if sentinelForRAKCode("00000") != nil {
		t.Error("unknown code should map to nil")
	}
}
