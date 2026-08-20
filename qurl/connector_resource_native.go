package qurl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	connectorResourceLSTQuery       = "connector_resource"
	connectorResourceLSTVersion     = 1
	connectorResourceLSTNonceBytes  = 32
	connectorResourceLSTMaxBody     = 976
	connectorResourceLSTMaxKnockID  = 64
	connectorResourceLSTMaxRetrySec = 3600

	connectorResourceUnavailableCode      = "52500"
	connectorResourceIdentityRejectedCode = "52501"
	connectorResourceEntitlementCode      = "52502"
	connectorResourceIdentityConflictCode = "52503"
	connectorResourceQuotaCode            = "52504"
	connectorResourceRateLimitedCode      = "52505"
	connectorResourceInvalidRequestCode   = "52506"
)

var (
	// ErrInvalidNativeConnectorResourceRequest reports a request rejected before
	// DNS, socket creation, or packet construction.
	ErrInvalidNativeConnectorResourceRequest = errors.New("qurl: invalid native Connector resource request")
	// ErrConnectorResourceUnavailable is an authenticated, retryable platform
	// result. A caller must reuse the same RequestNonce for the retry.
	ErrConnectorResourceUnavailable = errors.New("qurl: Connector resource temporarily unavailable")
	// ErrConnectorResourceIdentityRejected means the registered agent binding is
	// absent, expired, or no longer exact.
	ErrConnectorResourceIdentityRejected = errors.New("qurl: Connector resource identity rejected")
	// ErrConnectorResourceEntitlementDenied means the registered agent is not
	// entitled to the requested Connector ID.
	ErrConnectorResourceEntitlementDenied = errors.New("qurl: Connector resource entitlement denied")
	// ErrConnectorResourceIdentityConflict means expected_resource_id did not
	// name the exact active resource. The SDK never adopts a replacement.
	ErrConnectorResourceIdentityConflict = errors.New("qurl: Connector resource identity conflict")
	// ErrConnectorResourceQuotaExceeded is an authenticated account quota denial.
	ErrConnectorResourceQuotaExceeded = errors.New("qurl: Connector resource quota exceeded")
	// ErrConnectorResourceRateLimited is an authenticated retry-after result.
	ErrConnectorResourceRateLimited = errors.New("qurl: Connector resource rate limited")
	// ErrConnectorResourceRequestRejected means the assigned cell rejected the
	// exact application request. Retrying unchanged cannot succeed.
	ErrConnectorResourceRequestRejected = errors.New("qurl: Connector resource request rejected")
	// ErrInvalidNativeConnectorResourceResponse reports an authenticated LRT
	// that does not satisfy the native Connector-resource contract. It remains
	// distinct from the legacy HTTPS resource-response classification.
	ErrInvalidNativeConnectorResourceResponse = errors.New("qurl: invalid native Connector resource response")
)

// NativeConnectorResourceRequest is one durable logical NHP_LST operation.
// Persist RequestNonce before the first exchange when exact lost-response
// replay must survive a process restart. Reusing the nonce with changed fields
// is a terminal server-side conflict.
type NativeConnectorResourceRequest struct {
	ConnectorID        string
	ExpectedResourceID string
	RequestNonce       string
}

// NewNativeConnectorResourceRequest validates the customer Connector ID and
// optional continuity assertion, then generates a canonical 32-byte request
// nonce. It performs no network or state I/O.
func NewNativeConnectorResourceRequest(connectorID, expectedResourceID string) (*NativeConnectorResourceRequest, error) {
	request := &NativeConnectorResourceRequest{
		ConnectorID:        connectorID,
		ExpectedResourceID: expectedResourceID,
	}
	if err := validateNativeConnectorResourceRequest(request, false); err != nil {
		return nil, err
	}
	raw := make([]byte, connectorResourceLSTNonceBytes)
	defer wipeBytes(raw)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("%w: generate request nonce: %w", ErrInvalidNativeConnectorResourceRequest, err)
	}
	request.RequestNonce = base64.RawURLEncoding.EncodeToString(raw)
	return request, nil
}

// ConnectorResourceResolution is the complete binding selected by one native
// Connector-resource exchange and its creation provenance.
type ConnectorResourceResolution struct {
	Resource      *ConnectorResource
	FoundExisting bool
}

// ConnectorResourceDiscoveryError is one authenticated closed-taxonomy LRT
// denial. Code and RetryAfter are safe to inspect; the error never contains a
// peer key, request nonce, or credential.
type ConnectorResourceDiscoveryError struct {
	Code       string
	RetryAfter time.Duration
	kind       error
}

func (e *ConnectorResourceDiscoveryError) Error() string {
	if e == nil {
		return "qurl: Connector resource discovery error"
	}
	return fmt.Sprintf("qurl: Connector resource discovery error %s", e.Code)
}

func (e *ConnectorResourceDiscoveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// ResolveRegisteredAgentConnectorResource sends one authenticated NHP_LST to
// the binding's assigned cell and consumes only the corresponding NHP_LRT.
// There is no HTTP, Hub, generic-plugin, or cross-cell fallback. The binding
// retains key ownership; TakeDeviceStaticPrivateKey may transfer it after this
// call for the subsequent KNK runtime.
func ResolveRegisteredAgentConnectorResource(
	ctx context.Context,
	binding *AgentRuntimeBinding,
	request *NativeConnectorResourceRequest,
	transportOpts ...AgentRuntimeUDPOption,
) (*ConnectorResourceResolution, error) {
	if err := validateContext(ctx, ErrInvalidNativeConnectorResourceRequest); err != nil {
		return nil, err
	}
	if err := validateNativeConnectorResourceRequest(request, true); err != nil {
		return nil, err
	}
	if binding == nil || binding.deviceStaticPrivateKey == nil {
		return nil, fmt.Errorf("%w: runtime binding must own a device key", ErrInvalidNativeConnectorResourceRequest)
	}
	body, err := marshalNativeConnectorResourceRequest(binding.AgentID, request)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)

	var resolution *ConnectorResourceResolution
	err = binding.deviceStaticPrivateKey.withBorrow(ErrInvalidNativeConnectorResourceRequest, func(privateKey []byte) error {
		cfg, endpoint, endpointErr := registeredAgentSessionEndpoint(ctx, binding, privateKey, transportOpts)
		if endpointErr != nil {
			return endpointErr
		}
		reply, exchangeErr := nativeudp.List(ctx, endpoint, body, cfg.udpOptions(privateKey))
		if exchangeErr != nil {
			return normalizeRelayError(exchangeErr, ErrInvalidNativeConnectorResourceResponse)
		}
		if reply == nil || !reply.IsListResult() {
			return invalidNativeConnectorResourceResponse("missing or unexpected reply type")
		}
		var parseErr error
		resolution, parseErr = parseNativeConnectorResourceResponse(reply.Body, binding.AgentID, request)
		return parseErr
	})
	if err != nil {
		return nil, err
	}
	return resolution, nil
}

type nativeConnectorResourceRequestEnvelope struct {
	UsrID   string                                 `json:"usrId"`
	DevID   string                                 `json:"devId"`
	AspID   string                                 `json:"aspId"`
	UsrData nativeConnectorResourceRequestUserData `json:"usrData"`
}

type nativeConnectorResourceRequestUserData struct {
	Query              string  `json:"query"`
	Version            int     `json:"version"`
	RequestNonce       string  `json:"request_nonce"`
	ConnectorID        string  `json:"connector_id"`
	ExpectedResourceID *string `json:"expected_resource_id,omitempty"`
}

func marshalNativeConnectorResourceRequest(agentID string, request *NativeConnectorResourceRequest) ([]byte, error) {
	userData := nativeConnectorResourceRequestUserData{
		Query: connectorResourceLSTQuery, Version: connectorResourceLSTVersion,
		RequestNonce: request.RequestNonce, ConnectorID: request.ConnectorID,
	}
	if request.ExpectedResourceID != "" {
		expected := request.ExpectedResourceID
		userData.ExpectedResourceID = &expected
	}
	body, err := json.Marshal(nativeConnectorResourceRequestEnvelope{
		UsrID: agentID, DevID: agentID, AspID: agentAspID, UsrData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", ErrInvalidNativeConnectorResourceRequest, err)
	}
	if len(body) > connectorResourceLSTMaxBody {
		size := len(body)
		wipeBytes(body)
		return nil, fmt.Errorf("%w: encoded request is %d bytes, maximum is %d", ErrInvalidNativeConnectorResourceRequest, size, connectorResourceLSTMaxBody)
	}
	return body, nil
}

func validateNativeConnectorResourceRequest(request *NativeConnectorResourceRequest, requireNonce bool) error {
	if request == nil {
		return fmt.Errorf("%w: request must not be nil", ErrInvalidNativeConnectorResourceRequest)
	}
	if err := validateConnectorSlug(request.ConnectorID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidNativeConnectorResourceRequest, err)
	}
	if request.ExpectedResourceID != "" {
		if err := validateConnectorResourceID(request.ExpectedResourceID); err != nil {
			return fmt.Errorf("%w: expected resource identity: %w", ErrInvalidNativeConnectorResourceRequest, err)
		}
	}
	if !requireNonce && request.RequestNonce == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(request.RequestNonce)
	defer wipeBytes(raw)
	if err != nil || len(raw) != connectorResourceLSTNonceBytes || base64.RawURLEncoding.EncodeToString(raw) != request.RequestNonce {
		return fmt.Errorf("%w: request nonce must be canonical unpadded base64url of %d bytes", ErrInvalidNativeConnectorResourceRequest, connectorResourceLSTNonceBytes)
	}
	return nil
}

type nativeConnectorResourceList struct {
	Query              string  `json:"query"`
	Version            int     `json:"version"`
	AgentID            string  `json:"agent_id"`
	ConnectorID        string  `json:"connector_id"`
	ResourceID         string  `json:"resource_id"`
	ConnectorRoutingID string  `json:"connector_routing_id"`
	KnockResourceID    string  `json:"knock_resource_id"`
	CRID               *string `json:"crid,omitempty"`
	FoundExisting      *bool   `json:"found_existing"`
}

func parseNativeConnectorResourceResponse(body []byte, agentID string, request *NativeConnectorResourceRequest) (*ConnectorResourceResolution, error) {
	if len(body) == 0 || len(body) > connectorResourceLSTMaxBody || !utf8.Valid(body) {
		return nil, invalidNativeConnectorResourceResponse("body size or UTF-8")
	}
	fields, err := exactObjectFields(body)
	if err != nil {
		return nil, invalidNativeConnectorResourceResponse("envelope framing")
	}
	var envelope assignmentEnvelope
	if err := strictDecodeJSON(body, &envelope); err != nil {
		return nil, invalidNativeConnectorResourceResponse("envelope schema")
	}
	if envelope.ErrCode == errSuccess {
		if !exactFieldNames(fields, []string{"errCode", "list"}) || isJSONNull(envelope.List) {
			return nil, invalidNativeConnectorResourceResponse("success envelope fields")
		}
		return parseNativeConnectorResourceSuccess(envelope.List, agentID, request)
	}
	return nil, parseNativeConnectorResourceError(fields, envelope)
}

func parseNativeConnectorResourceSuccess(raw json.RawMessage, agentID string, request *NativeConnectorResourceRequest) (*ConnectorResourceResolution, error) {
	fields, err := exactObjectFields(raw)
	if err != nil || !exactRequiredOptionalFields(fields,
		[]string{"query", "version", "agent_id", "connector_id", "resource_id", "connector_routing_id", "knock_resource_id", "found_existing"},
		[]string{"crid"}) {
		return nil, invalidNativeConnectorResourceResponse("success list fields")
	}
	if rawCRID, ok := fields["crid"]; ok && isJSONNull(rawCRID) {
		return nil, invalidNativeConnectorResourceResponse("null crid")
	}
	var list nativeConnectorResourceList
	if err := strictDecodeJSON(raw, &list); err != nil || list.FoundExisting == nil {
		return nil, invalidNativeConnectorResourceResponse("success list schema")
	}
	if list.Query != connectorResourceLSTQuery || list.Version != connectorResourceLSTVersion ||
		list.AgentID != agentID || list.ConnectorID != request.ConnectorID {
		return nil, invalidNativeConnectorResourceResponse("success request binding")
	}
	if request.ExpectedResourceID != "" && list.ResourceID != request.ExpectedResourceID {
		return nil, invalidNativeConnectorResourceResponse("success continuity binding")
	}
	if !validateNativeConnectorKnockID(list.KnockResourceID) {
		return nil, invalidNativeConnectorResourceResponse("knock resource identity")
	}
	wire := connectorResourceWire{
		ResourceID: list.ResourceID, ConnectorRoutingID: list.ConnectorRoutingID,
		KnockResourceID: list.KnockResourceID, Type: producerConnectorResourceType,
		Status: "active", Slug: list.ConnectorID,
	}
	if list.CRID != nil {
		wire.CRID = *list.CRID
		if wire.CRID == "" || !nativeConnectorCRIDMatches(wire.CRID, wire.ResourceID) {
			return nil, invalidNativeConnectorResourceResponse("crid binding")
		}
	}
	resource, err := wire.connectorResource(nil, connectorResourceExpectation{slug: request.ConnectorID})
	if err != nil {
		return nil, invalidNativeConnectorResourceResponse("resource binding")
	}
	return &ConnectorResourceResolution{Resource: resource, FoundExisting: *list.FoundExisting}, nil
}

func parseNativeConnectorResourceError(fields map[string]json.RawMessage, envelope assignmentEnvelope) error {
	if envelope.ErrCode == "" || isJSONNull(fields["errCode"]) || isJSONNull(fields["errMsg"]) {
		return invalidNativeConnectorResourceResponse("error envelope required fields")
	}
	var kind error
	var wantMessage string
	retryPermitted, retryRequired := false, false
	switch envelope.ErrCode {
	case connectorResourceUnavailableCode:
		kind, wantMessage, retryPermitted = ErrConnectorResourceUnavailable, "connector resource temporarily unavailable", true
	case connectorResourceIdentityRejectedCode:
		kind, wantMessage = ErrConnectorResourceIdentityRejected, "connector resource identity rejected"
	case connectorResourceEntitlementCode:
		kind, wantMessage = ErrConnectorResourceEntitlementDenied, "connector resource entitlement denied"
	case connectorResourceIdentityConflictCode:
		kind, wantMessage = ErrConnectorResourceIdentityConflict, "connector resource identity conflict"
	case connectorResourceQuotaCode:
		kind, wantMessage = ErrConnectorResourceQuotaExceeded, "connector resource quota exceeded"
	case connectorResourceRateLimitedCode:
		kind, wantMessage, retryPermitted, retryRequired = ErrConnectorResourceRateLimited, "connector resource rate limited", true, true
	case connectorResourceInvalidRequestCode:
		kind, wantMessage = ErrConnectorResourceRequestRejected, "invalid connector resource request"
	default:
		return invalidNativeConnectorResourceResponse("unknown error code")
	}
	wantFields := []string{"errCode", "errMsg"}
	if _, ok := fields["retryAfterSeconds"]; ok {
		wantFields = append(wantFields, "retryAfterSeconds")
	}
	if !exactFieldNames(fields, wantFields) || envelope.ErrMsg != wantMessage {
		return invalidNativeConnectorResourceResponse("error envelope fields")
	}
	retryAfter, err := parseEnvelopeRetryAfter(envelope, fields, retryPermitted, retryRequired)
	if err != nil || retryAfter > connectorResourceLSTMaxRetrySec*time.Second {
		return invalidNativeConnectorResourceResponse("retry-after policy")
	}
	return &ConnectorResourceDiscoveryError{Code: envelope.ErrCode, RetryAfter: retryAfter, kind: kind}
}

func nativeConnectorCRIDMatches(value, resourceID string) bool {
	der, err := base64.RawURLEncoding.Strict().DecodeString(resourceID)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != resourceID {
		return false
	}
	matched, err := crid.KeyMatches(value, der)
	return err == nil && matched
}

func invalidNativeConnectorResourceResponse(reason string) error {
	return fmt.Errorf("%w: native Connector resource LRT %s", ErrInvalidNativeConnectorResourceResponse, reason)
}

func exactRequiredOptionalFields(fields map[string]json.RawMessage, required, optional []string) bool {
	if len(fields) < len(required) || len(fields) > len(required)+len(optional) {
		return false
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	for name := range fields {
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	return true
}

func exactFieldNames(fields map[string]json.RawMessage, names []string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func validateNativeConnectorKnockID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		len(value) <= connectorResourceLSTMaxKnockID && strings.IndexFunc(value, unicode.IsControl) < 0
}
