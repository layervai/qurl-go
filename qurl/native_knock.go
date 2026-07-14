package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidNativeKnockOptions marks a native registered-agent knock that is
// invalid before any DNS lookup, socket creation, or packet construction.
var ErrInvalidNativeKnockOptions = errors.New("qurl: invalid native knock options")

// NativeKnockOptions carries the caller-owned state for one native UDP knock.
//
// RunID is mandatory. qURL Connector generates it once with NewCycleRunID for
// each outer knock/service cycle and reuses the exact value for every retry and
// reconnect in that cycle. The native knock runtime validates and carries the
// value but never generates or normalizes one implicitly.
type NativeKnockOptions struct {
	RunID string
}

// nativeAgentKnockBody is the AEAD-protected NHP_KNK application body for a
// registered agent. Field order is wire-significant for the byte-exact
// cross-language conformance fence even though JSON object semantics do not
// otherwise depend on it.
type nativeAgentKnockBody struct {
	HeaderType      int    `json:"headerType"`
	UserID          string `json:"usrId"`
	DeviceID        string `json:"devId"`
	AuthServiceID   string `json:"aspId"`
	KnockResourceID string `json:"resId"`
	RunID           string `json:"runId"`
}

// marshalNativeKnockApplicationBody is the single producer for the registered-
// agent NHP_KNK body. The eventual UDP exchange calls this before resolving the
// assignment host or constructing any packet, preserving the mandatory
// caller-owned RunID boundary independently of transport retries.
func marshalNativeKnockApplicationBody(agentID, knockResourceID string, opts NativeKnockOptions) ([]byte, error) {
	// Keep this first: an invalid or missing cycle identity must fail before any
	// other native-knock work and the rejected value must never appear in an
	// error. ValidateCycleRunID reports only the violated shape.
	if err := ValidateCycleRunID(opts.RunID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidNativeKnockOptions, err)
	}
	if err := validateNativeKnockIdentity("agent id", agentID); err != nil {
		return nil, err
	}
	if err := validateNativeKnockIdentity("knock resource id", knockResourceID); err != nil {
		return nil, err
	}

	return json.Marshal(nativeAgentKnockBody{
		HeaderType:      nhpKNKHeaderType,
		UserID:          agentID,
		DeviceID:        agentID,
		AuthServiceID:   agentAspID,
		KnockResourceID: knockResourceID,
		RunID:           opts.RunID,
	})
}

func validateNativeKnockIdentity(kind, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%w: %s must not be blank", ErrInvalidNativeKnockOptions, kind)
	}
	if trimmed != value {
		return fmt.Errorf("%w: %s must not have surrounding whitespace", ErrInvalidNativeKnockOptions, kind)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidNativeKnockOptions, kind)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidNativeKnockOptions, kind)
	}
	return nil
}
