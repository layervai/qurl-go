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

// ErrInvalidNativeKnockInput marks a native registered-agent knock that is
// invalid before any DNS lookup, socket creation, or packet construction.
// Invalid identities expose only this sentinel. An invalid RunID also preserves
// ErrInvalidCycleRunID so callers of the existing RunID validator retain its
// more specific error classification.
var ErrInvalidNativeKnockInput = errors.New("qurl: invalid native knock input")

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
	RunID      string
	RunAttempt uint64
	// ProtectedResourceID is the canonical public CRID resource. It is
	// authenticated separately from the placement-neutral knock resource ID.
	ProtectedResourceID string
	// Operation is a prepared durable session operation. The caller must persist
	// its exact JSON before this knock. Nil selects an operation-free knock; it
	// does not make ProtectedResourceID optional.
	Operation *NativeSessionOperation

	// recovery selects the durable-operation recovery action inside the
	// encrypted KNK body. It is package-private so ordinary callers cannot turn
	// an admission API into a control operation.
	recovery bool
}

// nativeAgentKnockBody is the AEAD-protected NHP_KNK application body for a
// registered agent. This is deliberately separate from buildKnockBody's
// qURL keyed-identity contract: that path uses a signed resource public key,
// while this path uses the assignment's placement-neutral knock_resource_id.
// Field order is wire-significant for the released
// byte-exact conformance vector. Outside that canonical vector, opaque identity
// values use normal JSON semantics: encoders may escape equivalent characters
// differently without changing the identity the server parses.
type nativeAgentKnockBody struct {
	HeaderType          int               `json:"headerType"`
	UserID              string            `json:"usrId"`
	DeviceID            string            `json:"devId"`
	AuthServiceID       string            `json:"aspId"`
	KnockResourceID     string            `json:"resId"`
	RunID               string            `json:"runId"`
	RunAttempt          uint64            `json:"runAttempt"`
	ProtectedResourceID string            `json:"protected_resource_id,omitempty"`
	OperationID         string            `json:"operation_id,omitempty"`
	BindingSHA256       string            `json:"binding_sha256,omitempty"`
	OwnerID             string            `json:"owner_id,omitempty"`
	PreparedAtMS        int64             `json:"prepared_at_ms,omitempty"`
	ExpiresAtMS         int64             `json:"expires_at_ms,omitempty"`
	UserData            map[string]string `json:"usrData,omitempty"`
}

type nativeExactSessionCloseBody struct {
	HeaderType            int    `json:"headerType"`
	AuthServiceID         string `json:"aspId"`
	CellID                string `json:"cellId"`
	SessionID             uint64 `json:"sessId"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis"`
	RunID                 string `json:"runId"`
	RunAttempt            uint64 `json:"runAttempt"`
}

// marshalNativeKnockApplicationBody is the single producer for the registered-
// agent NHP_KNK body. The eventual UDP exchange calls this before resolving the
// assignment host or constructing any packet, preserving the mandatory
// caller-owned RunID boundary independently of transport retries.
// KnockRegisteredAgent requires ProtectedResourceID before calling this helper;
// the empty internal form remains only for historical packet-vector decoding.
func marshalNativeKnockApplicationBody(agentID, knockResourceID string, opts NativeKnockOptions) ([]byte, error) {
	return marshalNativeSessionApplicationBody(agentID, knockResourceID, opts, nhpKNKHeaderType)
}

// marshalNativeSessionApplicationBody produces the protected application body
// for exactly one registered-agent session-control packet. Its headerType is
// part of the peer-authentication contract, not a cosmetic duplicate of the
// outer packet type: a server rejects an RKN or EXT whose body says KNK. The
// narrow allowlist means an internal caller cannot accidentally emit a body for
// an unsupported initiator message.
func marshalNativeSessionApplicationBody(agentID, knockResourceID string, opts NativeKnockOptions, headerType int) ([]byte, error) {
	switch headerType {
	case nhpKNKHeaderType, nhpRKNHeaderType:
	default:
		return nil, fmt.Errorf("%w: unsupported native session header type", ErrInvalidNativeKnockInput)
	}
	// Keep this first: an invalid or missing cycle identity must fail before any
	// other native-knock work and the rejected value must never appear in an
	// error. ValidateCycleRunID reports only the violated shape.
	if err := ValidateCycleRunID(opts.RunID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidNativeKnockInput, err)
	}
	if opts.RunAttempt == 0 {
		return nil, fmt.Errorf("%w: run attempt must be positive", ErrInvalidNativeKnockInput)
	}
	if err := validateNativeKnockIdentity("agent id", agentID); err != nil {
		return nil, err
	}
	if err := validateNativeKnockIdentity("knock resource id", knockResourceID); err != nil {
		return nil, err
	}

	// This scalar-only struct cannot currently make json.Marshal fail. Keep the
	// error path explicit so adding a fallible field cannot silently weaken it.
	wire := nativeAgentKnockBody{
		HeaderType:          headerType,
		UserID:              agentID,
		DeviceID:            agentID,
		AuthServiceID:       agentAspID,
		KnockResourceID:     knockResourceID,
		RunID:               opts.RunID,
		RunAttempt:          opts.RunAttempt,
		ProtectedResourceID: opts.ProtectedResourceID,
	}
	if opts.Operation != nil {
		operation := *opts.Operation
		if validateNativeSessionOperation(operation) != nil || operation.AgentID != agentID ||
			operation.ResourceID != knockResourceID || operation.RunID != opts.RunID ||
			operation.RunAttempt != opts.RunAttempt || operation.ProtectedResourceID != opts.ProtectedResourceID {
			return nil, ErrInvalidNativeSessionOperation
		}
		wire.OperationID = operation.OperationID
		wire.BindingSHA256 = operation.BindingSHA256
		wire.OwnerID = operation.OwnerID
		wire.PreparedAtMS = operation.PreparedAtMillis
		wire.ExpiresAtMS = operation.ExpiresAtMillis
		if opts.recovery {
			wire.UserData = map[string]string{
				nativeSessionOperationRecoveryUserDataKey: nativeSessionOperationRecoveryAction,
			}
		}
	} else if opts.recovery {
		return nil, ErrInvalidNativeSessionOperation
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("qurl: encode native knock body: %w", err)
	}
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return nil, fmt.Errorf("%w: encoded body exceeds NHP maximum of %d bytes", ErrInvalidNativeKnockInput, nhpcontract.MaxApplicationBodySize)
	}
	return body, nil
}

func marshalNativeExactSessionCloseBody(receipt NativeSessionReceipt) ([]byte, error) {
	if err := validateNativeSessionReceipt(receipt); err != nil {
		return nil, err
	}
	body, err := json.Marshal(nativeExactSessionCloseBody{
		HeaderType: nhpEXTHeaderType, AuthServiceID: agentAspID,
		CellID: receipt.CellID, SessionID: receipt.SessionID,
		SessionIssuedAtMillis: receipt.SessionIssuedAtMillis,
		RunID:                 receipt.RunID, RunAttempt: receipt.RunAttempt,
	})
	if err != nil {
		return nil, fmt.Errorf("qurl: encode exact native session close body: %w", err)
	}
	if len(body) > nhpcontract.MaxApplicationBodySize {
		return nil, fmt.Errorf("%w: encoded body exceeds NHP maximum of %d bytes", ErrInvalidNativeKnockInput, nhpcontract.MaxApplicationBodySize)
	}
	return body, nil
}

func validateNativeKnockIdentity(kind, value string) error {
	// Current registration/assignment contracts treat these as opaque protocol
	// identities, not user-facing slugs. Match AgentState validation by preserving
	// printable internal whitespace exactly while rejecting ambiguous edge
	// whitespace and control characters. Size belongs to the aggregate encoded-body
	// check in marshalNativeKnockApplicationBody, the binding NHP wire limit.
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%w: %s must not be blank", ErrInvalidNativeKnockInput, kind)
	}
	if trimmed != value {
		return fmt.Errorf("%w: %s must not have surrounding whitespace", ErrInvalidNativeKnockInput, kind)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidNativeKnockInput, kind)
	}
	if strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidNativeKnockInput, kind)
	}
	return nil
}
