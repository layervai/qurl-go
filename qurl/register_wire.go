package qurl

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Wire shapes for the assigned-cell NHP_REG/NHP_RAK exchange. Native OTP and
// completion LST/LRT bodies live beside their lifecycle implementations. No
// public HTTP registration-info or completion envelope is supported.

// agentAspID is the NHP authorization-service-provider id for registered agents.
const agentAspID = "agent"

const (
	keyKindBootstrap = "bootstrap"
	keyKindAccount   = "account"
)

// registerRequestBody is the round-trip NHP_REG body. OTP carries either the
// enrollment credential or the assigned-cell OTP. The authenticated Noise
// initiator static key supplies the device public key.
type registerRequestBody struct {
	UsrID   string           `json:"usrId"`
	DevID   string           `json:"devId"`
	AspID   string           `json:"aspId"`
	OTP     string           `json:"otp"`
	UsrData registerUserData `json:"usrData"`
}

type registerUserData struct {
	Hostname         string `json:"hostname,omitempty"`
	Version          string `json:"version,omitempty"`
	AssignmentTicket string `json:"assignment_ticket"`
}

func marshalRegisterRequestBody(keyID, deviceID, credential string, userData registerUserData) ([]byte, error) {
	body, err := json.Marshal(registerRequestBody{
		UsrID: keyID, DevID: deviceID, AspID: agentAspID,
		OTP: credential, UsrData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("qurl: encode registration body: %w", err)
	}
	return body, nil
}

type registerAckBody struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
	AspID   string `json:"aspId"`
}

const rakSuccess = errSuccess

func (b registerAckBody) isSuccess() bool {
	return b.ErrCode == rakSuccess
}

// parseNativeRegisterAck enforces the released assigned-cell RAK contract. A
// success or denial is an exact JSON object with a canonical nonempty errCode
// and aspId "agent". Empty bodies, unknown/duplicate fields, trailing values,
// null, and whitespace-normalized codes fail closed.
func parseNativeRegisterAck(body []byte) (*registerAckBody, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: native registration reply body must not be empty", ErrRegisterReplyMalformed)
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return nil, invalidNativeProducerReply(ErrRegisterReplyMalformed, "assigned-cell registration reply")
	}
	var ack *registerAckBody
	if err := strictDecodeJSON(body, &ack); err != nil {
		return nil, invalidNativeProducerReply(ErrRegisterReplyMalformed, "assigned-cell registration reply")
	}
	if ack == nil {
		return nil, fmt.Errorf("%w: native registration reply must be a JSON object", ErrRegisterReplyMalformed)
	}
	if ack.ErrCode == "" || ack.ErrCode != strings.TrimSpace(ack.ErrCode) {
		return nil, fmt.Errorf("%w: native registration reply must contain an exact non-empty errCode", ErrRegisterReplyMalformed)
	}
	if ack.AspID != agentAspID {
		return nil, fmt.Errorf("%w: native registration reply aspId is invalid", ErrRegisterReplyMalformed)
	}
	return ack, nil
}

// NHP_RAK error codes owned by the assigned-cell registration contract.
const (
	rakCredentialInvalid = "52100"
	rakCredentialExpired = "52101"
	rakAttemptsExceeded  = "52102"
	rakIdentityConflict  = "52103"
	rakRateLimited       = "52104"
	rakEmailUnavailable  = "52105"
	rakInvalidAPIKey     = "52106"
	rakRegistrationOff   = "52107"
	rakBootstrapConsumed = "52108"
	rakInvalidInput      = "52109"
)
