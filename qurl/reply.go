package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
)

// qURL knock-reply interpretation. relayknock decrypts and authenticates the NHP
// packet but is body-shape agnostic; the qURL ACK body shape and its success/deny
// semantics live here.

// ErrServerOverloaded is returned when the relay knock got an NHP_COK overload
// cookie-challenge instead of an admission reply. The NHP_RKN cookie-answer path
// is out of scope for a one-shot EnterPortal, so the caller should retry later.
var ErrServerOverloaded = errors.New("qurl: NHP server overloaded (cookie-challenge); retry later")

// ErrMalformedReply is returned when an authenticated reply is structurally
// unusable — an unexpected NHP type, or a success ACK that carries no reachable
// resource (empty redirectUrl). It is distinct from a ServerDenyError (an
// authenticated deny) and a relayknock.RelayError (a transport fault).
var ErrMalformedReply = errors.New("qurl: malformed server reply")

// ServerDenyError is an authenticated server DENY: the knock decrypted and the
// server vouched for it, but admission was refused (expired/revoked/consumed
// qURL, policy mismatch). It is distinct from a relayknock.RelayError, which is a
// transport fault before any authenticated server decision.
type ServerDenyError struct {
	// ErrCode is the server's NHP error code string (e.g. "52024" for a qURL
	// session-expired deny). "" / "0" are success and never produce this error.
	ErrCode string
}

func (e *ServerDenyError) Error() string {
	return fmt.Sprintf("qurl: server denied admission (errCode=%q)", e.ErrCode)
}

// serverKnockAckMsg is the subset of the NHP server's ServerKnockAckMsg the
// resolve path reads.
type serverKnockAckMsg struct {
	ErrCode     string `json:"errCode"`
	OpenTime    uint32 `json:"opnTime"`
	RedirectURL string `json:"redirectUrl"`
}

// NHP success error codes. errCode is a string field; "" and "0" both mean
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
