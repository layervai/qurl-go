// Package sessioncookie parses the strict shared NHP cookie-challenge body.
package sessioncookie

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// RejectBodyParse and the other Reject constants are stable internal
// rejection classes shared by the UDP and HTTPS session transports.
const (
	RejectBodyParse = "body_parse"
	RejectEncoding  = "cookie_encoding"
	RejectLength    = "cookie_length"
	RejectCanonical = "cookie_canonical"
	RejectCounter   = "counter"
)

// Error classifies one strict cookie-challenge rejection without retaining the
// cookie bytes or the original JSON.
type Error struct {
	Class  string
	Detail string
}

func (e *Error) Error() string { return "malformed cookie challenge (" + e.Class + "): " + e.Detail }

// Unwrap keeps the shared malformed-reply taxonomy attached to the classified
// error so a future transport cannot accidentally lose it.
func (e *Error) Unwrap() error { return nhpwire.ErrMalformedReply }

func reject(class, detail string) error { return &Error{Class: class, Detail: detail} }

type challenge struct {
	transactionID uint64
	cookie        []byte
}

// Parse accepts exactly the shared NHP COK body contract and correlates its
// transaction id to the initiating KNK counter.
func Parse(body []byte, requestCounter uint64) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, reject(RejectBodyParse, "body must be one JSON object")
	}
	var parsed challenge
	defer func() { cryptoutil.Wipe(parsed.cookie) }()
	seen := make(map[string]struct{}, 2)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, reject(RejectBodyParse, "invalid object key")
		}
		key, ok := token.(string)
		if !ok {
			return nil, reject(RejectBodyParse, "object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, reject(RejectBodyParse, "duplicate field")
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) {
			return nil, reject(RejectBodyParse, "field has an invalid value")
		}
		switch key {
		case "trxId":
			if err := json.Unmarshal(raw, &parsed.transactionID); err != nil {
				return nil, reject(RejectBodyParse, "trxId has an invalid type")
			}
		case "cookie":
			parsed.cookie, err = decode(raw)
			cryptoutil.Wipe(raw)
			if err != nil {
				return nil, err
			}
		default:
			return nil, reject(RejectBodyParse, "unknown field")
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, reject(RejectBodyParse, "object is incomplete")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, reject(RejectBodyParse, "trailing JSON")
	}
	if len(seen) != 2 {
		return nil, reject(RejectBodyParse, "missing required field")
	}
	if parsed.transactionID != requestCounter {
		return nil, reject(RejectCounter, "transaction does not match the request")
	}
	cookie := parsed.cookie
	parsed.cookie = nil
	return cookie, nil
}

func decode(raw []byte) ([]byte, error) {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, reject(RejectBodyParse, "cookie has an invalid type")
	}
	encoded := raw[1 : len(raw)-1]
	if bytes.IndexByte(encoded, '\\') >= 0 || bytes.ContainsAny(encoded, " \t\r\n") {
		return nil, reject(RejectEncoding, "cookie is not strict base64")
	}
	cookie := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(cookie, encoded)
	if err != nil {
		cryptoutil.Wipe(cookie)
		rawCookie := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
		defer cryptoutil.Wipe(rawCookie)
		rawN, rawErr := base64.RawStdEncoding.Strict().Decode(rawCookie, encoded)
		if rawErr == nil && rawN == nhpwire.CookieSize {
			return nil, reject(RejectCanonical, "cookie is not canonical padded base64")
		}
		return nil, reject(RejectEncoding, "cookie is not strict base64")
	}
	cookie = cookie[:n]
	if len(cookie) != nhpwire.CookieSize {
		cryptoutil.Wipe(cookie)
		return nil, reject(RejectLength, "cookie has the wrong decoded length")
	}
	return cookie, nil
}
