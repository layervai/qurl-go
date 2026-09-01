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
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// NativeSessionOperationJournalMargin is the maximum time a caller may spend
// durably committing a prepared live operation before it sends the related
// KnockRegisteredAgent request. The preparation, commit, and knock must remain
// one serialized critical section for a shared binding.
const NativeSessionOperationJournalMargin = 125 * time.Second

const (
	nativeSessionOperationSchema = 2
	// The binding schema remains 2 because this contract has not been released.
	// This coordinated v2 cutover replaces the earlier v2 canonical field set;
	// no compatibility decoder is retained.
	nativeSessionOperationBindingSchema        = 2
	nativeSessionOperationAgentKeySchema       = 2
	nativeSessionOperationConnectorIDClaim     = ""
	nativeSessionOperationSelectorDomain       = "layerv/native-session-operation/v1\x00"
	nativeSessionOperationMaxCreationWindow    = 30 * time.Minute
	nativeSessionOperationMaxClockSkew         = 30 * time.Second
	nativeSessionOperationResumeHorizon        = 24 * time.Hour
	nativeSessionOperationAbsentRecoveryMargin = NativeSessionOperationJournalMargin
	nativeSessionOperationRecoveryRequiredCode = "52029"
	nativeSessionOperationRecoveryCompleteCode = "52030"
	nativeSessionOperationRecoveryUserDataKey  = "native_session_operation_action"
	nativeSessionOperationRecoveryAction       = "recover"
)

// ErrInvalidNativeSessionOperation marks an operation that fails before DNS,
// socket, or packet work. Error text never includes an operation identity or
// owner value.
var ErrInvalidNativeSessionOperation = errors.New("qurl: invalid native session operation")

// ErrNativeSessionOperationLeaseMargin means no operation was created because
// the binding could not establish enough live lease for the caller to commit a
// durable journal record and send the following admission packet. The error
// keeps any Hub renewal cause in its chain. It does not mean the current lease
// has already expired.
var ErrNativeSessionOperationLeaseMargin = errors.New("qurl: native session operation lease margin unavailable")

// NativeSessionOperationUnexpectedAdmissionError reports a server contract
// violation in which a recovery KNK admitted a session instead of returning a
// recovery denial ACK. SessionReceipt lets the durable caller record that
// exact admission as MAPPED and recover it through the same operation authority;
// it must not retry the recovery KNK or start a replacement operation first.
type NativeSessionOperationUnexpectedAdmissionError struct {
	SessionReceipt NativeSessionReceipt
}

func (e *NativeSessionOperationUnexpectedAdmissionError) Error() string {
	return "qurl: native session operation recovery returned admission authority"
}

func (e *NativeSessionOperationUnexpectedAdmissionError) Unwrap() error { return ErrMalformedReply }

// NativeSessionOperationInput contains only the authenticated resource and run
// facts required to prepare one durable session operation before any network
// request. CellID must match the exact completed AgentRuntimeBinding snapshot.
// ResourceID is the placement-neutral knock/catalog key; ProtectedResourceID
// is the distinct canonical CRID public-resource identity. AWS accounts,
// regions, and storage names are private server configuration and never enter
// this public contract.
type NativeSessionOperationInput struct {
	// CellID is required by PrepareNativeSessionOperation and must be empty for
	// PrepareLiveNativeSessionOperation, which derives placement from the binding.
	CellID              string
	ExpiresAtMillis     int64
	OwnerID             string
	PreparedAtMillis    int64
	ProtectedResourceID string
	ResourceID          string
	RunAttempt          uint64
	RunID               string
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
	BindingSchema       int    `json:"binding_schema"`
	BindingSHA256       string `json:"binding_sha256"`
	CellID              string `json:"cell_id"`
	ConnectorIDClaim    string `json:"connector_id_claim"`
	CredentialKind      string `json:"enrollment_credential_kind"`
	ExpiresAtMillis     int64  `json:"expires_at_ms"`
	OperationID         string `json:"operation_id"`
	OwnerID             string `json:"owner_id"`
	PreparedAtMillis    int64  `json:"prepared_at_ms"`
	ProtectedResourceID string `json:"protected_resource_id"`
	ResourceID          string `json:"resource_id"`
	RunAttempt          uint64 `json:"run_attempt"`
	RunID               string `json:"run_id"`
	Schema              int    `json:"schema"`
}

type nativeSessionOperationCanonicalBinding struct {
	AgentID             string `json:"agent_id"`
	AgentKeySchema      int    `json:"agent_key_schema_version"`
	AgentPublicKeyB64   string `json:"agent_public_key_b64"`
	AuthServiceID       string `json:"auth_service_id"`
	BindingSchema       int    `json:"binding_schema"`
	CellID              string `json:"cell_id"`
	ConnectorIDClaim    string `json:"connector_id_claim"`
	CredentialKind      string `json:"enrollment_credential_kind"`
	ExpiresAtMillis     int64  `json:"expires_at_ms"`
	OperationID         string `json:"operation_id"`
	OwnerID             string `json:"owner_id"`
	PreparedAtMillis    int64  `json:"prepared_at_ms"`
	ProtectedResourceID string `json:"protected_resource_id"`
	ResourceID          string `json:"resource_id"`
	RunAttempt          uint64 `json:"run_attempt"`
	RunID               string `json:"run_id"`
}

// NativeSessionOperationRecovery is the authenticated result of recovery.
// Complete is true only after the server reports the exact operation terminal.
// UnexpectedAdmission is set only when an incompatible server admits the
// recovery packet. The caller must durably record that receipt as MAPPED before
// any retry. No bearer material is replayed on this control path.
type NativeSessionOperationRecovery struct {
	Complete            bool
	UnexpectedAdmission *NativeSessionReceipt
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
	if len(fields) != 18 {
		return false
	}
	for _, key := range []string{
		"agent_id", "agent_key_schema_version", "agent_public_key_b64", "auth_service_id",
		"binding_schema", "binding_sha256", "cell_id",
		"connector_id_claim", "enrollment_credential_kind", "expires_at_ms", "operation_id",
		"owner_id", "prepared_at_ms", "protected_resource_id", "resource_id", "run_attempt",
		"run_id", "schema",
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
	return prepareNativeSessionOperationForAssignment(binding, deviceStaticPrivateKey, assignment, input)
}

func prepareNativeSessionOperationForAssignment(binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	assignment AgentAssignment, input NativeSessionOperationInput,
) (*NativeSessionOperation, error) {
	if binding == nil || validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey) != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	if assignment.CellID == "" || assignment.CellID != input.CellID ||
		validateNativeSessionOperationInput(input, true) != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	operation := NativeSessionOperation{
		AgentID: binding.authoritativeAgentID, AgentKeySchema: nativeSessionOperationAgentKeySchema,
		AgentPublicKeyB64: binding.authoritativePublicKeyB64, AuthServiceID: agentAspID,
		BindingSchema: nativeSessionOperationBindingSchema, CellID: input.CellID,
		ConnectorIDClaim: nativeSessionOperationConnectorIDClaim,
		CredentialKind:   binding.enrollmentCredentialKind, ExpiresAtMillis: input.ExpiresAtMillis,
		OwnerID: input.OwnerID, PreparedAtMillis: input.PreparedAtMillis,
		ProtectedResourceID: input.ProtectedResourceID,
		ResourceID:          input.ResourceID,
		RunAttempt:          input.RunAttempt, RunID: input.RunID, Schema: nativeSessionOperationSchema,
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

// PrepareLiveNativeSessionOperation renews the held binding only when its lease
// is close enough that the following durable journal commit could cross the
// ordinary session-renewal boundary. It then prepares an operation against the
// exact live assignment and returns that source endpoint for recovery.
//
// Unlike PrepareNativeSessionOperation, this function may contact the pinned
// Hub when renewal is due. It never contacts the assigned cell. CellID must be
// empty because the live binding, not the caller, owns placement. Callers must
// durably persist both returned values and send the knock within
// NativeSessionOperationJournalMargin (currently 125 seconds) of this function
// returning. Callers that share one binding must serialize this preparation,
// its durable commit, and KnockRegisteredAgent as one critical section because
// a concurrent renewal can move the binding before admission.
func PrepareLiveNativeSessionOperation(ctx context.Context, binding *AgentRuntimeBinding,
	deviceStaticPrivateKey []byte, input NativeSessionOperationInput,
) (*NativeSessionOperation, NHPUDPEndpoint, error) {
	if binding == nil || len(deviceStaticPrivateKey) != x25519key.Size || input.CellID != "" ||
		validateRuntimeBindingIdentity(binding, deviceStaticPrivateKey) != nil {
		return nil, NHPUDPEndpoint{}, ErrInvalidNativeSessionOperation
	}
	if _, err := binding.checkedAssignment(binding.authoritativeAssignment); err != nil {
		return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: runtime binding assignment: %w", ErrInvalidNativeSessionOperation, err)
	}
	if err := validateContext(ctx, ErrInvalidNativeSessionOperation); err != nil {
		return nil, NHPUDPEndpoint{}, err
	}
	if err := validateNativeSessionOperationInput(input, false); err != nil {
		return nil, NHPUDPEndpoint{}, err
	}
	decisionAt := time.Now().UTC()
	liveAtDecision := binding.Assignment()
	expiredAtDecision := liveAtDecision.LeaseExpired(decisionAt)
	// The packet margin is longer than one bounded native exchange and gives
	// the caller time to fsync the operation before KnockRegisteredAgent samples
	// the lease. This operation does not exist yet; the exported contract requires
	// callers to exclude sibling preparation and knock work on the same binding.
	assignment, err := binding.liveSessionAssignmentStrict(ctx, deviceStaticPrivateKey, decisionAt.Add(NativeSessionOperationJournalMargin))
	if err != nil {
		// On an online binding this private sentinel means the Hub exchange
		// succeeded but returned a lease that is still too short. Do not relabel
		// that successful renewal as an expired pre-renewal assignment.
		if errors.Is(err, errAgentRuntimeRenewalUnavailable) {
			if binding.renewal != nil {
				return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: renewed assignment has insufficient journal margin: %w",
					ErrNativeSessionOperationLeaseMargin, err)
			}
			if !expiredAtDecision {
				return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: assignment has insufficient journal margin: %w",
					ErrNativeSessionOperationLeaseMargin, err)
			}
		}
		if expiredAtDecision {
			return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: live assignment expired before Hub renewal: %w: %w",
				ErrInvalidNativeSessionOperation, ErrAssignmentLeaseExpired, err)
		}
		return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: Hub renewal could not establish journal margin: %w",
			ErrNativeSessionOperationLeaseMargin, err)
	}
	// Re-sample after the Hub exchange. The returned margin starts when this
	// function delivers the operation, not when a possibly slow renewal began.
	preparedAt := time.Now().UTC()
	if err := assignment.Validate(preparedAt); err != nil {
		return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: live assignment: %w", ErrInvalidNativeSessionOperation, err)
	}
	if !preparedAt.Add(NativeSessionOperationJournalMargin + sessionLeaseRenewalLead).Before(assignment.LeaseExpiresAt) {
		return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: renewed assignment has insufficient journal margin",
			ErrNativeSessionOperationLeaseMargin)
	}
	if _, err := assignmentNativeEndpoint(assignment); err != nil {
		return nil, NHPUDPEndpoint{}, fmt.Errorf("%w: live assignment endpoint: %w", ErrInvalidNativeSessionOperation, err)
	}
	input.CellID = assignment.CellID
	operation, err := prepareNativeSessionOperationForAssignment(binding, deviceStaticPrivateKey, *assignment, input)
	if err != nil {
		return nil, NHPUDPEndpoint{}, err
	}
	return operation, assignment.Endpoint, nil
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
		BindingSchema: operation.BindingSchema, CellID: operation.CellID,
		ConnectorIDClaim: operation.ConnectorIDClaim, CredentialKind: operation.CredentialKind,
		ExpiresAtMillis: operation.ExpiresAtMillis, OperationID: operation.OperationID,
		OwnerID: operation.OwnerID, PreparedAtMillis: operation.PreparedAtMillis,
		ProtectedResourceID: operation.ProtectedResourceID,
		ResourceID:          operation.ResourceID,
		RunAttempt:          operation.RunAttempt, RunID: operation.RunID,
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
		!validNativeSessionOperationCredentialKind(operation.CredentialKind) ||
		operation.ConnectorIDClaim != nativeSessionOperationConnectorIDClaim ||
		operation.AuthServiceID != agentAspID || !validNativeSessionOperationIdentity(operation.AgentID) ||
		validateNativeSessionOperationInput(NativeSessionOperationInput{
			CellID:          operation.CellID,
			ExpiresAtMillis: operation.ExpiresAtMillis, OwnerID: operation.OwnerID,
			PreparedAtMillis: operation.PreparedAtMillis, ProtectedResourceID: operation.ProtectedResourceID,
			ResourceID: operation.ResourceID, RunAttempt: operation.RunAttempt, RunID: operation.RunID,
		}, true) != nil ||
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

func validateNativeSessionOperationInput(input NativeSessionOperationInput, requireCell bool) error {
	cellValid := input.CellID == ""
	if requireCell {
		cellValid = validNativeSessionOperationIdentity(input.CellID)
	}
	if !cellValid || !validNativeSessionOperationIdentity(input.OwnerID) ||
		!validNativeSessionOperationIdentity(input.ResourceID) ||
		validateConnectorResourceID(input.ProtectedResourceID) != nil ||
		input.ProtectedResourceID == input.ResourceID ||
		input.PreparedAtMillis <= 0 || input.ExpiresAtMillis <= input.PreparedAtMillis ||
		input.ExpiresAtMillis-input.PreparedAtMillis > nativeSessionOperationMaxCreationWindow.Milliseconds() ||
		ValidateCycleRunID(input.RunID) != nil || input.RunAttempt == 0 {
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
		operation.AgentPublicKeyB64 != binding.authoritativePublicKeyB64 ||
		operation.CredentialKind != binding.enrollmentCredentialKind {
		return ErrInvalidNativeSessionOperation
	}
	return nil
}

func validNativeSessionOperationCredentialKind(kind string) bool {
	return kind == keyKindAccount || kind == keyKindBootstrap
}

func validNativeSessionOperationIdentity(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
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
	marginMillis := nativeSessionOperationAbsentRecoveryMargin.Milliseconds()
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

// RecoverNativeSessionOperation sends the recovery action through the standard
// NHP_KNK to NHP_ACK exchange at the separately persisted source-fenced
// endpoint. It never follows the binding's current assignment or intentionally
// opens a replacement admission. A normal strict denial ACK carries only
// whether the durable operation is terminal or still closing. An incompatible
// server admission returns NativeSessionOperationUnexpectedAdmissionError; the
// caller must persist its exact receipt as MAPPED before recovery and must not
// retry this packet directly. WithAgentRuntimeSessionRelay carries this recovery
// KNK and its one possible RKN over HTTPS; this is the relay-capable durable
// close/reconciliation path and is separate from UDP-only exact-session EXT.
func RecoverNativeSessionOperation(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte,
	operation NativeSessionOperation, recoveryEndpoint NHPUDPEndpoint, transportOpts ...AgentRuntimeSessionOption,
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
	opts := NativeKnockOptions{
		RunID: operation.RunID, RunAttempt: operation.RunAttempt,
		ProtectedResourceID: operation.ProtectedResourceID, Operation: &operation, recovery: true,
	}
	body, err := marshalNativeSessionApplicationBody(operation.AgentID, operation.ResourceID, opts, nhpKNKHeaderType)
	if err != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	defer wipeBytes(body)
	reknockBody, err := marshalNativeSessionApplicationBody(operation.AgentID, operation.ResourceID, opts, nhpRKNHeaderType)
	if err != nil {
		return nil, ErrInvalidNativeSessionOperation
	}
	defer wipeBytes(reknockBody)
	var reply *relayknock.Reply
	if cfg.sessionRelay != nil {
		reply, err = cfg.sessionRelay.KnockWithReknock(ctx, endpoint.ServerStaticPub, deviceStaticPrivateKey, body, reknockBody)
	} else {
		reply, err = nativeudp.KnockWithReknock(ctx, endpoint, body, reknockBody, cfg.udpOptions(deviceStaticPrivateKey))
	}
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	recovery, err := consumeNativeSessionOperationRecoveryReply(reply, operation)
	var unexpected *NativeSessionOperationUnexpectedAdmissionError
	if errors.As(err, &unexpected) {
		unexpected.SessionReceipt.agentID = binding.authoritativeAgentID
		unexpected.SessionReceipt.endpoint = cloneNativeUDPEndpoint(endpoint)
		if recovery != nil && recovery.UnexpectedAdmission != nil {
			receipt := unexpected.SessionReceipt
			recovery.UnexpectedAdmission = &receipt
		}
	}
	return recovery, err
}

func consumeNativeSessionOperationRecoveryReply(reply *relayknock.Reply,
	operation NativeSessionOperation,
) (*NativeSessionOperationRecovery, error) {
	result, err := consumeNativeAgentKnockReply(reply, operation.ResourceID, nativeAgentKnockExpectation{
		CellID: operation.CellID, RunID: operation.RunID, RunAttempt: operation.RunAttempt,
		OperationID: operation.OperationID, BindingSHA256: operation.BindingSHA256,
		AllowSuccessOperationEcho: true,
	})
	var denied *ServerDenyError
	if !errors.As(err, &denied) {
		if err == nil {
			receipt := result.SessionReceipt
			return &NativeSessionOperationRecovery{UnexpectedAdmission: &receipt},
				&NativeSessionOperationUnexpectedAdmissionError{SessionReceipt: receipt}
		}
		return nil, err
	}
	switch denied.ErrCode {
	case nativeSessionOperationRecoveryCompleteCode:
		return &NativeSessionOperationRecovery{Complete: true}, nil
	case nativeSessionOperationRecoveryRequiredCode:
		return &NativeSessionOperationRecovery{}, nil
	default:
		return nil, denied
	}
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

// NativeSessionOperationRecoveryRequired reports the exact authenticated,
// operation-bound denial returned by KnockRegisteredAgent that tells the
// caller to recover the supplied operation before it makes a replacement
// admission attempt. An operation-free knock cannot receive this result under
// the v2 contract. Recovery itself returns a non-complete
// NativeSessionOperationRecovery with a nil error while the server is still
// closing the operation.
func NativeSessionOperationRecoveryRequired(err error) bool {
	var denied *ServerDenyError
	return errors.As(err, &denied) && denied.ErrCode == nativeSessionOperationRecoveryRequiredCode
}
