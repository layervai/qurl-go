package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/layervai/qurl-go/internal/nhpcontract"
)

// ErrInvalidNativeKnockOptions marks a native registered-agent knock that is
// invalid before any DNS lookup, socket creation, or packet construction.
// Invalid identities expose only this sentinel. An invalid RunID also preserves
// ErrInvalidCycleRunID so callers of the existing RunID validator retain its
// more specific error classification.
var ErrInvalidNativeKnockOptions = errors.New("qurl: invalid native knock options")

// NativeKnockOptions carries the caller-owned state for one native UDP knock.
//
// The type and RunID field intentionally land with this producer boundary
// before the exported UDP transport: issue #66 freezes this caller contract so
// qURL Connector integration does not depend on an implicit SDK-generated ID.
//
// RunID is mandatory. qURL Connector generates it once with NewCycleRunID for
// each outer knock/service cycle and reuses the exact value for every retry and
// reconnect in that cycle. The native knock runtime validates and carries the
// value but never generates or normalizes one implicitly.
type NativeKnockOptions struct {
	RunID string
}

// nativeAgentKnockBody is the AEAD-protected NHP_KNK application body for a
// registered agent. This is deliberately separate from buildKnockBody's
// provisional qURL keyed-identity contract: that path uses a signed resource
// public key, while this path uses the assignment's placement-neutral
// knock_resource_id. Field order is wire-significant for the byte-exact
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

	// This scalar-only struct cannot currently make json.Marshal fail. Keep the
	// error path explicit so adding a fallible field cannot silently weaken it.
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
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return nil, fmt.Errorf("%w: encoded body exceeds NHP maximum of %d bytes", ErrInvalidNativeKnockOptions, nhpcontract.MaxApplicationBodySize)
	}
	return body, nil
}

func validateNativeKnockIdentity(kind, value string) error {
	// Current registration/assignment contracts treat these as opaque protocol
	// identities, not user-facing slugs. Match AgentState validation by preserving
	// printable internal whitespace exactly while rejecting ambiguous edge
	// whitespace and control characters. Size is not checked here: any field long
	// enough to matter is caught by the aggregate encoded-body check in
	// marshalNativeKnockApplicationBody, which is the binding NHP wire limit.
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
