package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// qURL platform reply interpretation. The lower transport authenticates the reply
// packet but is body-shape agnostic; the qURL success/deny semantics live here.

// ErrServerOverloaded is returned when the qURL platform asks the client to retry
// later instead of opening access immediately.
var ErrServerOverloaded = errors.New("qurl: platform busy; retry later")

// ErrMalformedReply is returned when an authenticated reply is structurally
// unusable: an unexpected platform reply, or a success reply that carries no
// reachable resource URL. It is distinct from a ServerDenyError (an
// authenticated deny) and a RelayError (a transport fault).
var ErrMalformedReply = errors.New("qurl: malformed platform reply")

// ServerDenyError is an authenticated qURL platform deny: the platform vouched
// for the reply, but access was refused (expired/revoked/consumed qURL or a
// server-side access check). It is distinct from a RelayError, which is a
// transport fault before any authenticated platform decision.
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
	ErrCode     string           `json:"errCode"`
	SessionID   nhpSessionIDJSON `json:"sessId"`
	OpenTime    nhpOpenTimeJSON  `json:"opnTime"`
	RedirectURL string           `json:"redirectUrl"`
}

// nhpSessionIDJSON preserves field presence while accepting only the base NHP
// Session ID wire shape: an unsigned decimal JSON integer that fits uint64.
// Keeping this strict at decode time makes success and denial symmetric: a
// successful ACK requires one nonzero value, while a denied ACK must omit the
// field entirely.
type nhpSessionIDJSON struct {
	Value   uint64
	Present bool
}

func (v *nhpSessionIDJSON) UnmarshalJSON(data []byte) error {
	v.Present = true
	if len(data) == 0 {
		return errors.New("NHP session id must be an unsigned decimal JSON integer")
	}
	for _, b := range data {
		if b < '0' || b > '9' {
			return errors.New("NHP session id must be an unsigned decimal JSON integer")
		}
	}
	value, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil {
		return fmt.Errorf("NHP session id: %w", err)
	}
	v.Value = value
	return nil
}

// nhpOpenTimeJSON preserves presence and accepts only the canonical NHP wire
// shape: an unsigned decimal JSON integer that fits uint32. A success ACK must
// carry a positive lifetime; a denied ACK must carry the explicit value zero.
type nhpOpenTimeJSON struct {
	Value   uint32
	Present bool
}

func (v *nhpOpenTimeJSON) UnmarshalJSON(data []byte) error {
	v.Present = true
	if len(data) == 0 {
		return errors.New("NHP open time must be an unsigned decimal JSON integer")
	}
	for _, b := range data {
		if b < '0' || b > '9' {
			return errors.New("NHP open time must be an unsigned decimal JSON integer")
		}
	}
	value, err := strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		return fmt.Errorf("NHP open time: %w", err)
	}
	v.Value = uint32(value)
	return nil
}

// qURL success error codes. errCode is a string field; "" and "0" both mean
// success (common.IsSuccessErrCode).
const errSuccess = "0"

// isSuccessErrCode is the knock-ACK success predicate shared by the portal and
// native reply interpreters. Every other canonical errCode on a knock ACK is an
// authenticated server deny, never a malformed reply. (The registration RAK
// contract is deliberately stricter and requires a nonempty errCode; it does
// not use this predicate.)
func isSuccessErrCode(code string) bool { return code == "" || code == errSuccess }

func (m *serverKnockAckMsg) isSuccess() bool { return isSuccessErrCode(m.ErrCode) }

// parseAck decodes the decrypted ACK body. An empty body is treated as a
// zero-value ACK (no errCode, no resource URL) so the caller surfaces the
// missing resource URL rather than a JSON error.
func parseAck(body []byte) (*serverKnockAckMsg, error) {
	var ack serverKnockAckMsg
	if len(body) == 0 {
		return &ack, nil
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return nil, fmt.Errorf("%w: invalid server ACK body", ErrMalformedReply)
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, fmt.Errorf("%w: invalid server ACK body", ErrMalformedReply)
	}
	return &ack, nil
}
