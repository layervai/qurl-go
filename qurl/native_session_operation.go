package qurl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	nativeSessionOperationSchema                = 1
	nativeSessionOperationBindingSchema         = 1
	nativeSessionOperationAgentKeySchema        = 2
	nativeSessionOperationCredentialKind        = "account"
	nativeSessionOperationConnectorIDClaim      = ""
	nativeSessionOperationSelectorDomain        = "layerv/native-session-operation/v1\x00"
	nativeSessionOperationMaxCreationWindow     = 30 * time.Minute
	nativeSessionOperationMaxClockSkew          = 30 * time.Second
	nativeSessionOperationResumeHorizon         = 24 * time.Hour
	nativeSessionOperationPacketMargin          = 125 * time.Second
	nativeSessionOperationRecoveryStateCanceled = "CANCELED"
	nativeSessionOperationRecoveryStateClosing  = "CLOSING"
	nativeSessionOperationRecoveryStateClosed   = "CLOSED"
	nativeSessionOperationRecoveryRequiredCode  = "52029"
)

// ErrInvalidNativeSessionOperation marks an operation that fails before DNS,
// socket, or packet work. Error text never includes an operation identity or
// owner value.
var ErrInvalidNativeSessionOperation = errors.New("qurl: invalid native session operation")

// NativeSessionOperationInput is the caller-owned, non-secret authority used
// to prepare one durable session operation before any network request. CellID
// must match the exact completed AgentRuntimeBinding snapshot. The two table
// names and AWS identity are signed deployment authority, not wire fields.
type NativeSessionOperationInput struct {
	AWSAccountID        string
	AWSRegion           string
	CellID              string
	ExpiresAtMillis     int64
	OwnerID             string
	PreparedAtMillis    int64
	QURLAgentKeysTable  string
	ResourceID          string
	RunAttempt          uint64
	RunID               string
	SessionControlTable string
}

// NativeSessionOperation is a complete, strict, serializable operation intent.
// Persist its exact JSON before any KnockRegisteredAgent call that references
// it. It contains no bearer credential or private key. The field order is the
// sorted canonical order used by the fixed-identity orchestration authority.
type NativeSessionOperation struct {
	AgentID             string `json:"agent_id"`
	AgentKeySchema      int    `json:"agent_key_schema_version"`
	AgentPublicKeyB64   string `json:"agent_public_key_b64"`
	AuthServiceID       string `json:"auth_service_id"`
	AWSAccountID        string `json:"aws_account_id"`
	AWSRegion           string `json:"aws_region"`
	BindingSchema       int    `json:"binding_schema"`
	BindingSHA256       string `json:"binding_sha256"`
	CellID              string `json:"cell_id"`
	ConnectorIDClaim    string `json:"connector_id_claim"`
	CredentialKind      string `json:"enrollment_credential_kind"`
	ExpiresAtMillis     int64  `json:"expires_at_ms"`
	OperationID         string `json:"operation_id"`
	OwnerID             string `json:"owner_id"`
	PreparedAtMillis    int64  `json:"prepared_at_ms"`
	QURLAgentKeysTable  string `json:"qurl_agent_keys_table"`
	ResourceID          string `json:"resource_id"`
	RunAttempt          uint64 `json:"run_attempt"`
	RunID               string `json:"run_id"`
	Schema              int    `json:"schema"`
	SessionControlTable string `json:"session_control_table"`
}

type nativeSessionOperationCanonicalBinding struct {
	AgentID             string `json:"agent_id"`
	AgentKeySchema      int    `json:"agent_key_schema_version"`
	AgentPublicKeyB64   string `json:"agent_public_key_b64"`
	AuthServiceID       string `json:"auth_service_id"`
	AWSAccountID        string `json:"aws_account_id"`
	AWSRegion           string `json:"aws_region"`
	BindingSchema       int    `json:"binding_schema"`
	CellID              string `json:"cell_id"`
	ConnectorIDClaim    string `json:"connector_id_claim"`
	CredentialKind      string `json:"enrollment_credential_kind"`
	ExpiresAtMillis     int64  `json:"expires_at_ms"`
	OperationID         string `json:"operation_id"`
	OwnerID             string `json:"owner_id"`
	PreparedAtMillis    int64  `json:"prepared_at_ms"`
	QURLAgentKeysTable  string `json:"qurl_agent_keys_table"`
	ResourceID          string `json:"resource_id"`
	RunAttempt          uint64 `json:"run_attempt"`
	RunID               string `json:"run_id"`
	SessionControlTable string `json:"session_control_table"`
}

// NativeSessionOperationRecovery is the authenticated result of recovery. A
// CANCELED or CLOSED state is terminal. CLOSING is durable but not terminal;
// the caller must replay the same operation until CLOSED before it moves the
// source-fenced recovery route or starts a replacement operation.
type NativeSessionOperationRecovery struct {
	BindingSHA256         string
	CellID                string
	CloseEventID          string
	OperationID           string
	RunAttempt            uint64
	RunID                 string
	SessionID             uint64
	SessionIssuedAtMillis int64
	State                 string
}

// UnmarshalJSON rejects every unknown, duplicate, missing, or noncanonical
// operation field. This keeps independently restored encrypted bundles on the
// same closed schema as freshly prepared operations.
func (o *NativeSessionOperation) UnmarshalJSON(raw []byte) error {
	if o == nil {
		return ErrInvalidNativeSessionOperation
	}
	fields, err := exactObjectFields(raw)
	if err != nil || !exactNativeSessionOperationKeys(fields) {
		return ErrInvalidNativeSessionOperation
	}
	type operationAlias NativeSessionOperation
	var decoded operationAlias
	if err := strictDecodeJSON(raw, &decoded); err != nil {
		return ErrInvalidNativeSessionOperation
	}
	operation := NativeSessionOperation(decoded)
	if err := validateNativeSessionOperation(operation); err != nil {
		return err
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalidNativeSessionOperation
	}
	*o = operation
	return nil
}

func exactNativeSessionOperationKeys(fields map[string]json.RawMessage) bool {
	if len(fields) != 21 {
		return false
	}
	for _, key := range []string{
		"agent_id", "agent_key_schema_version", "agent_public_key_b64", "auth_service_id",
		"aws_account_id", "aws_region", "binding_schema", "binding_sha256", "cell_id",
		"connector_id_claim", "enrollment_credential_kind", "expires_at_ms", "operation_id",
		"owner_id", "prepared_at_ms", "qurl_agent_keys_table", "resource_id", "run_attempt",
		"run_id", "schema", "session_control_table",
	} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}

// PrepareNativeSessionOperation constructs and validates one operation without
// DNS, socket, Hub, HTTP, or state-store I/O. The caller must durably bind its
// exact serialized bytes before it invokes the network-facing APIs.
func PrepareNativeSessionOperation(binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	input NativeSessionOperationInput,
) (*NativeSessionOperation, error) {
	if binding == nil || validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey) != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	assignment := binding.Assignment()
	if assignment.CellID == "" || assignment.CellID != input.CellID {
		return nil, ErrInvalidNativeSessionOperation
	}
	operation := NativeSessionOperation{
		AgentID: binding.authoritativeAgentID, AgentKeySchema: nativeSessionOperationAgentKeySchema,
		AgentPublicKeyB64: binding.authoritativePublicKeyB64, AuthServiceID: agentAspID,
		AWSAccountID: input.AWSAccountID, AWSRegion: input.AWSRegion,
		BindingSchema: nativeSessionOperationBindingSchema, CellID: input.CellID,
		ConnectorIDClaim: nativeSessionOperationConnectorIDClaim,
		CredentialKind:   nativeSessionOperationCredentialKind, ExpiresAtMillis: input.ExpiresAtMillis,
		OwnerID: input.OwnerID, PreparedAtMillis: input.PreparedAtMillis,
		QURLAgentKeysTable: input.QURLAgentKeysTable, ResourceID: input.ResourceID,
		RunAttempt: input.RunAttempt, RunID: input.RunID, Schema: nativeSessionOperationSchema,
		SessionControlTable: input.SessionControlTable,
	}
	operationID, err := nativeSessionOperationID(operation.AgentPublicKeyB64, operation.RunID, operation.RunAttempt)
	if err != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	operation.OperationID = operationID
	bindingDigest, err := nativeSessionOperationBindingSHA256(operation)
	if err != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	operation.BindingSHA256 = bindingDigest
	if err := validateNativeSessionOperation(operation); err != nil {
		return nil, err
	}
	return &operation, nil
}

func nativeSessionOperationID(publicKeyB64, runID string, runAttempt uint64) (string, error) {
	publicKey, err := base64.StdEncoding.Strict().DecodeString(publicKeyB64)
	if err != nil || len(publicKey) != x25519key.Size || base64.StdEncoding.EncodeToString(publicKey) != publicKeyB64 ||
		ValidateCycleRunID(runID) != nil || runAttempt == 0 {
		return "", ErrInvalidNativeSessionOperation
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(nativeSessionOperationSelectorDomain))
	_, _ = hash.Write(publicKey)
	_, _ = hash.Write([]byte(runID))
	var attempt [8]byte
	binary.BigEndian.PutUint64(attempt[:], runAttempt)
	_, _ = hash.Write(attempt[:])
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func nativeSessionOperationBindingSHA256(operation NativeSessionOperation) (string, error) {
	operationID, err := nativeSessionOperationID(operation.AgentPublicKeyB64, operation.RunID, operation.RunAttempt)
	if err != nil || operation.OperationID != operationID {
		return "", ErrInvalidNativeSessionOperation
	}
	canonical := nativeSessionOperationCanonicalBinding{
		AgentID: operation.AgentID, AgentKeySchema: operation.AgentKeySchema,
		AgentPublicKeyB64: operation.AgentPublicKeyB64, AuthServiceID: operation.AuthServiceID,
		AWSAccountID: operation.AWSAccountID, AWSRegion: operation.AWSRegion,
		BindingSchema: operation.BindingSchema, CellID: operation.CellID,
		ConnectorIDClaim: operation.ConnectorIDClaim, CredentialKind: operation.CredentialKind,
		ExpiresAtMillis: operation.ExpiresAtMillis, OperationID: operation.OperationID,
		OwnerID: operation.OwnerID, PreparedAtMillis: operation.PreparedAtMillis,
		QURLAgentKeysTable: operation.QURLAgentKeysTable, ResourceID: operation.ResourceID,
		RunAttempt: operation.RunAttempt, RunID: operation.RunID,
		SessionControlTable: operation.SessionControlTable,
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return "", ErrInvalidNativeSessionOperation
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func validateNativeSessionOperation(operation NativeSessionOperation) error {
	if operation.Schema != nativeSessionOperationSchema ||
		operation.BindingSchema != nativeSessionOperationBindingSchema ||
		operation.AgentKeySchema != nativeSessionOperationAgentKeySchema ||
		operation.CredentialKind != nativeSessionOperationCredentialKind ||
		operation.ConnectorIDClaim != nativeSessionOperationConnectorIDClaim ||
		operation.AuthServiceID != agentAspID || !validNativeSessionOperationIdentity(operation.AgentID) ||
		!validNativeSessionOperationIdentity(operation.OwnerID) ||
		!validNativeSessionOperationIdentity(operation.ResourceID) ||
		!validNativeSessionOperationIdentity(operation.CellID) ||
		!validNativeSessionOperationTable(operation.SessionControlTable) ||
		!validNativeSessionOperationTable(operation.QURLAgentKeysTable) ||
		!validNativeSessionOperationAWS(operation.AWSAccountID, operation.AWSRegion) ||
		operation.PreparedAtMillis <= 0 || operation.ExpiresAtMillis <= operation.PreparedAtMillis ||
		operation.ExpiresAtMillis-operation.PreparedAtMillis > nativeSessionOperationMaxCreationWindow.Milliseconds() ||
		!validLowerHex(operation.OperationID, sha256.Size*2) ||
		!validLowerHex(operation.BindingSHA256, sha256.Size*2) {
		return ErrInvalidNativeSessionOperation
	}
	want, err := nativeSessionOperationBindingSHA256(operation)
	if err != nil || want != operation.BindingSHA256 {
		return ErrInvalidNativeSessionOperation
	}
	return nil
}

func validateNativeSessionOperationAdmission(operation NativeSessionOperation, binding *AgentRuntimeBinding,
	assignment *AgentAssignment, now time.Time,
) error {
	if err := validateNativeSessionOperationBinding(operation, binding); err != nil || assignment == nil ||
		operation.CellID != assignment.CellID {
		return ErrInvalidNativeSessionOperation
	}
	nowMillis := now.UTC().UnixMilli()
	if nowMillis <= 0 || operation.PreparedAtMillis > nowMillis+nativeSessionOperationMaxClockSkew.Milliseconds() ||
		nowMillis >= operation.ExpiresAtMillis {
		return ErrInvalidNativeSessionOperation
	}
	return nil
}

func validateNativeSessionOperationBinding(operation NativeSessionOperation, binding *AgentRuntimeBinding) error {
	if err := validateNativeSessionOperation(operation); err != nil || binding == nil ||
		operation.AgentID != binding.authoritativeAgentID ||
		operation.AgentPublicKeyB64 != binding.authoritativePublicKeyB64 {
		return ErrInvalidNativeSessionOperation
	}
	return nil
}

func validNativeSessionOperationIdentity(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validNativeSessionOperationTable(value string) bool {
	if len(value) < 3 || len(value) > 255 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if strings.IndexByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.", value[i]) < 0 {
			return false
		}
	}
	return true
}

func validNativeSessionOperationAWS(accountID, region string) bool {
	if len(accountID) != 12 || !validNativeSessionOperationAWSRegion(region) {
		return false
	}
	for i := 0; i < len(accountID); i++ {
		if accountID[i] < '0' || accountID[i] > '9' {
			return false
		}
	}
	return true
}

func validNativeSessionOperationAWSRegion(region string) bool {
	parts := strings.Split(region, "-")
	if len(parts) != 3 || len(parts[0]) != 2 || parts[1] == "" || parts[2] == "" || parts[2][0] == '0' {
		return false
	}
	for _, value := range parts[:2] {
		for index := 0; index < len(value); index++ {
			if value[index] < 'a' || value[index] > 'z' {
				return false
			}
		}
	}
	for index := 0; index < len(parts[2]); index++ {
		if parts[2][index] < '0' || parts[2][index] > '9' {
			return false
		}
	}
	return true
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func nativeSessionOperationAbsentRecoveryDeadline(operation NativeSessionOperation) (int64, error) {
	if err := validateNativeSessionOperation(operation); err != nil {
		return 0, err
	}
	resumeMillis := nativeSessionOperationResumeHorizon.Milliseconds()
	marginMillis := nativeSessionOperationPacketMargin.Milliseconds()
	if operation.PreparedAtMillis > math.MaxInt64-resumeMillis || operation.ExpiresAtMillis > math.MaxInt64-marginMillis {
		return 0, ErrInvalidNativeSessionOperation
	}
	preparedDeadline := operation.PreparedAtMillis + resumeMillis
	expiresDeadline := operation.ExpiresAtMillis + marginMillis
	if expiresDeadline > preparedDeadline {
		return expiresDeadline, nil
	}
	return preparedDeadline, nil
}

type nativeSessionOperationRecoveryBody struct {
	HeaderType    int    `json:"headerType"`
	UserID        string `json:"usrId"`
	DeviceID      string `json:"devId"`
	AuthServiceID string `json:"aspId"`
	ResourceID    string `json:"resId"`
	RunID         string `json:"runId"`
	RunAttempt    uint64 `json:"runAttempt"`
	OperationID   string `json:"operation_id"`
	BindingSHA256 string `json:"binding_sha256"`
	OwnerID       string `json:"owner_id"`
	PreparedAtMS  int64  `json:"prepared_at_ms"`
	ExpiresAtMS   int64  `json:"expires_at_ms"`
}

type nativeSessionOperationRecoveryACK struct {
	ErrCode               nativeJSONValue[string] `json:"errCode"`
	ErrMsg                nativeJSONValue[string] `json:"errMsg"`
	OperationID           nativeJSONValue[string] `json:"operation_id"`
	BindingSHA256         nativeJSONValue[string] `json:"binding_sha256"`
	State                 nativeJSONValue[string] `json:"state"`
	CellID                nativeJSONValue[string] `json:"cellId"`
	SessionID             nhpSessionIDJSON        `json:"sessId"`
	SessionIssuedAtMillis nativeJSONValue[int64]  `json:"sessIssuedAtMillis"`
	RunID                 nativeJSONValue[string] `json:"runId"`
	RunAttempt            nhpSessionIDJSON        `json:"runAttempt"`
	CloseEventID          nativeJSONValue[string] `json:"closeEventId"`
}

// RecoverNativeSessionOperation sends the strict authenticated recovery EXT to
// the separately persisted source-fenced endpoint. It never follows the
// binding's current assignment and never opens a replacement admission.
func RecoverNativeSessionOperation(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	operation NativeSessionOperation, recoveryEndpoint NHPUDPEndpoint, transportOpts ...AgentRuntimeUDPOption,
) (*NativeSessionOperationRecovery, error) {
	if binding == nil || validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey) != nil ||
		validateNativeSessionOperationBinding(operation, binding) != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	if validateAssignmentEndpointHost(recoveryEndpoint.Host, "recovery endpoint", ErrInvalidNativeSessionOperation) != nil ||
		recoveryEndpoint.Port != standardNHPUDPPort {
		return nil, ErrInvalidNativeSessionOperation
	}
	endpointKey, err := decodeAssignmentServerPublicKey(recoveryEndpoint.ServerPublicKeyB64)
	if err != nil || len(endpointKey) != x25519key.Size {
		return nil, ErrInvalidNativeSessionOperation
	}
	endpoint := nativeudp.Endpoint{Host: recoveryEndpoint.Host, Port: recoveryEndpoint.Port, ServerStaticPub: endpointKey}
	cfg := defaultNativeAgentRuntimeConfig()
	for _, option := range transportOpts {
		if option == nil || option.applyAgentRuntimeOption(cfg) != nil {
			return nil, ErrInvalidNativeSessionOperation
		}
	}
	body, err := json.Marshal(nativeSessionOperationRecoveryBody{
		HeaderType: nhpEXTHeaderType, UserID: operation.AgentID, DeviceID: operation.AgentID,
		AuthServiceID: operation.AuthServiceID, ResourceID: operation.ResourceID,
		RunID: operation.RunID, RunAttempt: operation.RunAttempt, OperationID: operation.OperationID,
		BindingSHA256: operation.BindingSHA256, OwnerID: operation.OwnerID,
		PreparedAtMS: operation.PreparedAtMillis, ExpiresAtMS: operation.ExpiresAtMillis,
	})
	if err != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	defer wipeBytes(body)
	reply, err := nativeudp.Exit(ctx, endpoint, body, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	return consumeNativeSessionOperationRecoveryReply(reply, operation)
}

func consumeNativeSessionOperationRecoveryReply(reply *relayknock.Reply,
	operation NativeSessionOperation,
) (*NativeSessionOperationRecovery, error) {
	if reply != nil {
		defer wipeBytes(reply.Body)
	}
	if reply == nil || !reply.IsACK() || rejectDuplicateJSONFields(reply.Body) != nil {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation recovery ACK")
	}
	var ack *nativeSessionOperationRecoveryACK
	if strictDecodeJSON(reply.Body, &ack) != nil || ack == nil || !ack.ErrCode.Present ||
		ack.ErrCode.Value != strings.TrimSpace(ack.ErrCode.Value) {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation recovery ACK")
	}
	if ack.ErrCode.Value != errSuccess {
		if !ack.ErrMsg.Present || ack.ErrMsg.Value == "" || ack.ErrMsg.Value != strings.TrimSpace(ack.ErrMsg.Value) ||
			!isCanonicalKnockDenyCode(ack.ErrCode.Value) || nativeSessionOperationRecoveryACKHasAuthority(ack) {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation recovery deny ACK")
		}
		return nil, &ServerDenyError{ErrCode: ack.ErrCode.Value}
	}
	if (ack.ErrMsg.Present && ack.ErrMsg.Value != "") || !ack.OperationID.Present || !ack.BindingSHA256.Present || !ack.State.Present ||
		ack.OperationID.Value != operation.OperationID || ack.BindingSHA256.Value != operation.BindingSHA256 {
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation recovery success ACK")
	}
	result := &NativeSessionOperationRecovery{
		OperationID: ack.OperationID.Value, BindingSHA256: ack.BindingSHA256.Value, State: ack.State.Value,
	}
	switch ack.State.Value {
	case nativeSessionOperationRecoveryStateCanceled:
		if nativeSessionOperationRecoveryACKHasSession(ack) {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation canceled ACK")
		}
	case nativeSessionOperationRecoveryStateClosing, nativeSessionOperationRecoveryStateClosed:
		if !ack.CellID.Present || !ack.SessionID.Present || !ack.SessionIssuedAtMillis.Present ||
			!ack.RunID.Present || !ack.RunAttempt.Present || !ack.CloseEventID.Present ||
			ack.CellID.Value != operation.CellID || ack.CellID.Value == "" || ack.SessionID.Value == 0 ||
			ack.SessionIssuedAtMillis.Value <= 0 || ack.RunID.Value != operation.RunID ||
			ack.RunAttempt.Value != operation.RunAttempt || !validNativeCloseEventID(ack.CloseEventID.Value) {
			return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation terminal ACK")
		}
		result.CellID = ack.CellID.Value
		result.SessionID = ack.SessionID.Value
		result.SessionIssuedAtMillis = ack.SessionIssuedAtMillis.Value
		result.RunID = ack.RunID.Value
		result.RunAttempt = ack.RunAttempt.Value
		result.CloseEventID = ack.CloseEventID.Value
	default:
		return nil, invalidNativeProducerReply(ErrMalformedReply, "native session operation recovery state")
	}
	return result, nil
}

func nativeSessionOperationRecoveryACKHasSession(ack *nativeSessionOperationRecoveryACK) bool {
	return ack.CellID.Present || ack.SessionID.Present || ack.SessionIssuedAtMillis.Present || ack.RunID.Present ||
		ack.RunAttempt.Present || ack.CloseEventID.Present
}

func nativeSessionOperationRecoveryACKHasAuthority(ack *nativeSessionOperationRecoveryACK) bool {
	return ack.OperationID.Present || ack.BindingSHA256.Present || ack.State.Present ||
		nativeSessionOperationRecoveryACKHasSession(ack)
}

// NativeSessionOperationAbsentRecoveryDeadline returns the exclusive time at
// which an absent operation may no longer create a CANCELED tombstone. Existing
// MAPPED/CLOSING/terminal authority remains recoverable while the server row is
// retained; this timestamp is not a client-side deletion signal.
func NativeSessionOperationAbsentRecoveryDeadline(operation NativeSessionOperation) (time.Time, error) {
	millis, err := nativeSessionOperationAbsentRecoveryDeadline(operation)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(millis).UTC(), nil
}

// NativeSessionOperationRecoveryRequired reports the exact authenticated
// server denial that tells the caller to recover this operation before it makes
// a replacement admission attempt.
func NativeSessionOperationRecoveryRequired(err error) bool {
	var denied *ServerDenyError
	return errors.As(err, &denied) && denied.ErrCode == nativeSessionOperationRecoveryRequiredCode
}
