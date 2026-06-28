package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
)

// qURL platform reply interpretation. The lower transport authenticates the reply
// packet but is body-shape agnostic; the qURL success/deny semantics live here.

// ErrServerOverloaded is returned when the qURL platform asks the client to retry
// later instead of opening access immediately.
var ErrServerOverloaded = errors.New("qurl: platform busy; retry later")

// ErrMalformedReply is returned when an authenticated reply is structurally
// unusable: an unexpected platform reply, or a success reply that carries no
// reachable resource (empty redirectUrl). It is distinct from a ServerDenyError
// (an authenticated deny) and a RelayError (a transport fault).
var ErrMalformedReply = errors.New("qurl: malformed platform reply")

// ServerDenyError is an authenticated qURL platform deny: the platform vouched
// for the reply, but access was refused (expired/revoked/consumed qURL, policy
// mismatch). It is distinct from a RelayError, which is a transport fault before
// any authenticated platform decision.
type ServerDenyError struct {
	// ErrCode is the qURL platform error code string. "" / "0" are success and
	// never produce this error.
	ErrCode string
}

func (e *ServerDenyError) Error() string {
	return fmt.Sprintf("qurl: platform denied access (errCode=%q)", e.ErrCode)
}

// serverKnockAckMsg is the subset of the qURL platform reply the resolve path reads.
type serverKnockAckMsg struct {
	ErrCode     string `json:"errCode"`
	OpenTime    uint32 `json:"opnTime"`
	RedirectURL string `json:"redirectUrl"`
}

// qURL success error codes. errCode is a string field; "" and "0" both mean
// success (common.IsSuccessErrCode).
const errSuccess = "0"

func (m *serverKnockAckMsg) isSuccess() bool { return m.ErrCode == "" || m.ErrCode == errSuccess }

// parseAck decodes the decrypted ACK body. An empty body is treated as a
// zero-value ACK (no errCode, no redirect) so the caller surfaces "no redirectUrl"
// rather than a JSON error.
func parseAck(body []byte) (*serverKnockAckMsg, error) {
	var ack serverKnockAckMsg
	if len(body) == 0 {
		return &ack, nil
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, fmt.Errorf("qurl: parse server ACK body: %w", err)
	}
	return &ack, nil
}
