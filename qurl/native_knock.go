package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	agentIDTrimmed := strings.TrimSpace(agentID)
	if agentIDTrimmed == "" {
		return nil, fmt.Errorf("%w: agent id must not be blank", ErrInvalidNativeKnockOptions)
	}
	if agentIDTrimmed != agentID {
		return nil, fmt.Errorf("%w: agent id must not have surrounding whitespace", ErrInvalidNativeKnockOptions)
	}
	knockResourceIDTrimmed := strings.TrimSpace(knockResourceID)
	if knockResourceIDTrimmed == "" {
		return nil, fmt.Errorf("%w: knock resource id must not be blank", ErrInvalidNativeKnockOptions)
	}
	if knockResourceIDTrimmed != knockResourceID {
		return nil, fmt.Errorf("%w: knock resource id must not have surrounding whitespace", ErrInvalidNativeKnockOptions)
	}

	body, err := json.Marshal(nativeAgentKnockBody{
		HeaderType:      nhpKNKHeaderType,
		UserID:          agentID,
		DeviceID:        agentID,
		AuthServiceID:   agentAspID,
		KnockResourceID: knockResourceID,
		RunID:           opts.RunID,
	})
	if err != nil {
		return nil, fmt.Errorf("qurl: encode native knock body: %w", err)
	}
	return body, nil
}
