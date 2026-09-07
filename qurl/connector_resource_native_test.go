package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
)

const testNativeConnectorNonce = "ERERERERERERERERERERERERERERERERERERERERERE"

func TestNativeConnectorResourceConformance(t *testing.T) {
	t.Parallel()

	var fixture struct {
		Fixtures struct {
			AgentID              string `json:"agent_id"`
			ConnectorID          string `json:"connector_id"`
			ResourcePublicKey    string `json:"resource_public_key"`
			CRID                 string `json:"crid"`
			ConnectorRoutingID   string `json:"connector_routing_id"`
			KnockResourceID      string `json:"knock_resource_id"`
			ExistingRequestNonce string `json:"existing_request_nonce"`
		} `json:"fixtures"`
		SuccessExchanges  []conformance.ConnectorResourceLSTV1Exchange  `json:"success_exchanges"`
		ResultRejectCases []conformance.ConnectorResourceLSTV1BodyCase  `json:"result_reject_cases"`
		ErrorCases        []conformance.ConnectorResourceLSTV1ErrorCase `json:"error_cases"`
		ErrorRejectCases  []conformance.ConnectorResourceLSTV1BodyCase  `json:"error_reject_cases"`
		SizeCases         []conformance.ConnectorResourceLSTV1SizeCase  `json:"size_cases"`
	}
	// CI compares these bytes with the released v0.17.0 public artifact.
	raw, err := os.ReadFile("testdata/connector_resource_crid_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}

	if connectorResourceLSTQuery != conformance.ConnectorResourceLSTV1Query ||
		connectorResourceLSTVersion != conformance.ConnectorResourceLSTV1Version ||
		agentAspID != conformance.ConnectorResourceLSTV1AspID ||
		connectorResourceLSTNonceBytes != conformance.ConnectorResourceLSTV1NonceBytes ||
		connectorResourceLSTMaxBody != conformance.ConnectorResourceLSTV1MaxPlaintextBodyBytes ||
		connectorResourceLSTMaxKnockID != conformance.ConnectorResourceLSTV1KnockResourceIDMax ||
		connectorResourceLSTMaxRetrySec != conformance.ConnectorResourceLSTV1MaxRetryAfterSeconds {
		t.Fatal("native Connector-resource constants drifted from public conformance")
	}
	wantCodes := []string{
		conformance.ConnectorResourceLSTV1ErrorUnavailable,
		conformance.ConnectorResourceLSTV1ErrorIdentityRejected,
		conformance.ConnectorResourceLSTV1ErrorEntitlement,
		conformance.ConnectorResourceLSTV1ErrorIdentityConflict,
		conformance.ConnectorResourceLSTV1ErrorQuota,
		conformance.ConnectorResourceLSTV1ErrorRateLimited,
		conformance.ConnectorResourceLSTV1ErrorInvalidRequest,
	}
	gotCodes := []string{
		connectorResourceUnavailableCode,
		connectorResourceIdentityRejectedCode,
		connectorResourceEntitlementCode,
		connectorResourceIdentityConflictCode,
		connectorResourceQuotaCode,
		connectorResourceRateLimitedCode,
		connectorResourceInvalidRequestCode,
	}
	if !slices.Equal(gotCodes, wantCodes) {
		t.Fatalf("native error codes = %v, public conformance = %v", gotCodes, wantCodes)
	}

	for _, exchange := range fixture.SuccessExchanges {
		exchange := exchange
		t.Run("success/"+exchange.Name, func(t *testing.T) {
			t.Parallel()
			var publicRequest nativeConnectorResourceRequestEnvelope
			if err := json.Unmarshal([]byte(exchange.Request.BodyJSON), &publicRequest); err != nil {
				t.Fatal(err)
			}
			request := nativeRequestFromConformance(&publicRequest)
			body, err := marshalNativeConnectorResourceRequest(fixture.Fixtures.AgentID, request)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != exchange.Request.BodyJSON {
				t.Fatalf("generated request = %s\npublic vector     = %s", body, exchange.Request.BodyJSON)
			}
			resolution, err := parseNativeConnectorResourceResponse([]byte(exchange.Result.BodyJSON), fixture.Fixtures.AgentID, request)
			if err != nil {
				t.Fatal(err)
			}
			if resolution == nil || resolution.Resource == nil ||
				resolution.FoundExisting != exchange.ExpectedFoundExisting ||
				resolution.Resource.ResourcePublicKey != fixture.Fixtures.ResourcePublicKey ||
				resolution.Resource.ConnectorRoutingID != fixture.Fixtures.ConnectorRoutingID ||
				resolution.Resource.KnockResourceID != fixture.Fixtures.KnockResourceID {
				t.Fatalf("resolution = %#v", resolution)
			}
			if publicRequest.UsrData.ExpectedCRID != nil && resolution.Resource.CRID != *publicRequest.UsrData.ExpectedCRID {
				t.Fatal("continuity result did not retain the exact expected resource")
			}
		})
	}

	for _, testCase := range fixture.SizeCases {
		if testCase.Direction != "result" {
			continue
		} // The SDK only receives result bodies.
		t.Run("size/"+testCase.Name, func(t *testing.T) {
			var envelope struct {
				List struct {
					AgentID     string `json:"agent_id"`
					ConnectorID string `json:"connector_id"`
				} `json:"list"`
			}
			if err := json.Unmarshal([]byte(testCase.BodyJSON), &envelope); err != nil {
				t.Fatal(err)
			}
			request := &NativeConnectorResourceRequest{ConnectorID: envelope.List.ConnectorID, RequestNonce: testNativeConnectorNonce}
			result, err := parseNativeConnectorResourceResponse([]byte(testCase.BodyJSON), envelope.List.AgentID, request)
			if err != nil || result == nil {
				t.Fatalf("maximum result rejected: %v", err)
			}
		})
	}

	continuityRequest := &NativeConnectorResourceRequest{
		ConnectorID: fixture.Fixtures.ConnectorID, ExpectedCRID: fixture.Fixtures.CRID,
		RequestNonce: fixture.Fixtures.ExistingRequestNonce,
	}
	for _, testCase := range fixture.ResultRejectCases {
		testCase := testCase
		t.Run("reject-success/"+testCase.Name, func(t *testing.T) {
			t.Parallel()
			if result, err := parseNativeConnectorResourceResponse([]byte(testCase.BodyJSON), fixture.Fixtures.AgentID, continuityRequest); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
				t.Fatalf("result, error = %#v, %v; want native response rejection", result, err)
			}
		})
	}
	for _, testCase := range fixture.ErrorCases {
		testCase := testCase
		t.Run("error/"+testCase.Name, func(t *testing.T) {
			t.Parallel()
			result, err := parseNativeConnectorResourceResponse([]byte(testCase.BodyJSON), fixture.Fixtures.AgentID, continuityRequest)
			if result != nil || err == nil {
				t.Fatalf("result, error = %#v, %v; want typed denial", result, err)
			}
			var discovery *ConnectorResourceDiscoveryError
			if !errors.As(err, &discovery) || discovery.Code != testCase.ErrorCode || discovery.RetryAfter != time.Duration(testCase.RetryAfterSeconds)*time.Second {
				t.Fatalf("typed error = %#v, want code %s retry %ds", discovery, testCase.ErrorCode, testCase.RetryAfterSeconds)
			}
		})
	}
	for _, testCase := range fixture.ErrorRejectCases {
		testCase := testCase
		t.Run("reject-error/"+testCase.Name, func(t *testing.T) {
			t.Parallel()
			if result, err := parseNativeConnectorResourceResponse([]byte(testCase.BodyJSON), fixture.Fixtures.AgentID, continuityRequest); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
				t.Fatalf("result, error = %#v, %v; want native response rejection", result, err)
			}
		})
	}
}

func nativeRequestFromConformance(request *nativeConnectorResourceRequestEnvelope) *NativeConnectorResourceRequest {
	native := &NativeConnectorResourceRequest{
		ConnectorID: request.UsrData.ConnectorID, RequestNonce: request.UsrData.RequestNonce,
	}
	if request.UsrData.ExpectedCRID != nil {
		native.ExpectedCRID = *request.UsrData.ExpectedCRID
	}
	return native
}

func TestNewNativeConnectorResourceRequest(t *testing.T) {
	t.Parallel()

	first, err := NewNativeConnectorResourceRequest(testConnectorSlug, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNativeConnectorResourceRequest(testConnectorSlug, testConnectorCRID)
	if err != nil {
		t.Fatal(err)
	}
	for i, request := range []*NativeConnectorResourceRequest{first, second} {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(request.RequestNonce)
		if err != nil || len(raw) != connectorResourceLSTNonceBytes {
			t.Fatalf("request %d nonce = %q: decoded length %d, err %v", i, request.RequestNonce, len(raw), err)
		}
	}
	if first.RequestNonce == second.RequestNonce {
		t.Fatal("independent Connector-resource requests reused a nonce")
	}
	if second.ExpectedCRID != testConnectorCRID {
		t.Fatalf("expected resource id = %q", second.ExpectedCRID)
	}
}

func TestNativeConnectorResourceRequestValidation(t *testing.T) {
	t.Parallel()

	valid := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	cases := []struct {
		name    string
		request *NativeConnectorResourceRequest
	}{
		{name: "nil", request: nil},
		{name: "invalid Connector ID", request: &NativeConnectorResourceRequest{ConnectorID: "Bad ID", RequestNonce: testNativeConnectorNonce}},
		{name: "missing nonce", request: &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug}},
		{name: "padded nonce", request: &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce + "="}},
		{name: "short nonce", request: &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))}},
		{name: "invalid expected id", request: &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce, ExpectedCRID: "r_private"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := validateNativeConnectorResourceRequest(tc.request, true); !errors.Is(err, ErrInvalidNativeConnectorResourceRequest) {
				t.Fatalf("error = %v, want ErrInvalidNativeConnectorResourceRequest", err)
			}
		})
	}
	if err := validateNativeConnectorResourceRequest(valid, true); err != nil {
		t.Fatalf("valid request: %v", err)
	}
}

func TestResolveRegisteredAgentConnectorResource_EncryptedAssignedCellExchange(t *testing.T) {
	t.Parallel()

	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	reply := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, false)
	binding, server, resolver, dialer := newNativeConnectorResourceTestRuntime(t, reply)
	defer binding.Destroy()

	result, err := ResolveRegisteredAgentConnectorResource(context.Background(), binding, request,
		WithAgentRuntimeUDPResolver(resolver),
		WithAgentRuntimeUDPDialer(dialer),
		WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Resource == nil || result.FoundExisting {
		t.Fatalf("result = %#v, want newly-created complete binding", result)
	}
	resource := result.Resource
	if resource.ResourcePublicKey != testConnectorID || resource.ConnectorRoutingID != testConnectorRoutingID ||
		resource.KnockResourceID != testKnockID || resource.Slug != testConnectorSlug || resource.CRID != testConnectorCRID {
		t.Fatalf("resource = %#v", resource)
	}
	if _, err := resource.CreatePortal(context.Background()); !errors.Is(err, ErrInvalidPortalRequest) {
		t.Fatalf("native resource unexpectedly retained an HTTP client: %v", err)
	}

	requests := waitRuntimeUDPRequests(t, server, 1)
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeListRequest {
		t.Fatalf("requests = %#v, want one NHP_LST", requests)
	}
	wantBody := `{"usrId":"agent-conform","devId":"agent-conform","aspId":"agent","usrData":{"query":"connector_resource","version":1,"request_nonce":"` + testNativeConnectorNonce + `","connector_id":"prod-dashboard"}}`
	if got := string(requests[0].body); got != wantBody {
		t.Fatalf("LST body = %s\nwant     = %s", got, wantBody)
	}

	key := binding.TakeDeviceStaticPrivateKey()
	if len(key) != 32 {
		t.Fatalf("post-discovery key transfer length = %d, want 32", len(key))
	}
	wipeBytes(key)
}

func TestResolveRegisteredAgentConnectorResource_ExpectedIdentityIsSentAndPinned(t *testing.T) {
	t.Parallel()

	request := &NativeConnectorResourceRequest{
		ConnectorID: testConnectorSlug, ExpectedCRID: testConnectorCRID, RequestNonce: testNativeConnectorNonce,
	}
	reply := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, true)
	binding, server, resolver, dialer := newNativeConnectorResourceTestRuntime(t, reply)
	defer binding.Destroy()
	result, err := ResolveRegisteredAgentConnectorResource(context.Background(), binding, request,
		WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer), WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.FoundExisting || result.Resource.ResourcePublicKey != testConnectorID {
		t.Fatalf("result = %#v", result)
	}
	requests := waitRuntimeUDPRequests(t, server, 1)
	wantExpected := `"expected_crid":"` + testConnectorCRID + `"`
	if !strings.Contains(string(requests[0].body), wantExpected) {
		t.Fatalf("LST omitted continuity assertion: %s", requests[0].body)
	}
}

func TestResolveRegisteredAgentConnectorResource_ContextCancellationRemainsTransportError(t *testing.T) {
	t.Parallel()

	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	binding, server, resolver, dialer := newNativeConnectorResourceTestRuntimeStep(t, runtimeUDPStep{
		requestType: relayknock.TypeListRequest,
		noReply:     true,
	})
	defer binding.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := make(chan struct{})
	go func() {
		defer close(cancelled)
		deadline := time.Now().Add(runtimeReplyTimeout)
		for len(server.snapshot()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	result, err := ResolveRegisteredAgentConnectorResource(ctx, binding, request,
		WithAgentRuntimeUDPResolver(resolver),
		WithAgentRuntimeUDPDialer(dialer),
		WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1),
	)
	<-cancelled
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("result, error = %#v, %v; want context cancellation", result, err)
	}
	if errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
		t.Fatalf("transport cancellation was misclassified as an invalid LRT: %v", err)
	}
	requests := waitRuntimeUDPRequests(t, server, 1)
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeListRequest {
		t.Fatalf("requests = %#v, want one NHP_LST", requests)
	}
}

func TestResolveRegisteredAgentConnectorResource_InvalidInputsPrecedeIO(t *testing.T) {
	t.Parallel()

	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	binding, server, _, _ := newNativeConnectorResourceTestRuntime(t,
		nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, true))
	defer binding.Destroy()
	resolver := new(noIONativeResolver)
	dialer := new(noIONativeDialer)
	options := []AgentRuntimeUDPOption{WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer)}

	//nolint:staticcheck // Nil is intentional: the public API must reject it before I/O.
	if result, err := ResolveRegisteredAgentConnectorResource(nil, binding, request, options...); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceRequest) {
		t.Fatalf("nil context = %#v, %v", result, err)
	}
	if result, err := ResolveRegisteredAgentConnectorResource(context.Background(), nil, request, options...); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceRequest) {
		t.Fatalf("nil binding = %#v, %v", result, err)
	}
	key := binding.TakeDeviceStaticPrivateKey()
	defer wipeBytes(key)
	if result, err := ResolveRegisteredAgentConnectorResource(context.Background(), binding, request, options...); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceRequest) {
		t.Fatalf("transferred key = %#v, %v", result, err)
	}
	if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(server.snapshot()) != 0 {
		t.Fatalf("invalid inputs reached I/O: resolver=%d dialer=%d packets=%d", resolver.calls.Load(), dialer.calls.Load(), len(server.snapshot()))
	}
}

func TestParseNativeConnectorResourceErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		body      string
		want      error
		wantCode  string
		wantRetry time.Duration
	}{
		{name: "unavailable", body: `{"errCode":"52500","errMsg":"connector resource temporarily unavailable"}`, want: ErrConnectorResourceUnavailable, wantCode: "52500"},
		{name: "unavailable retry", body: `{"errCode":"52500","errMsg":"connector resource temporarily unavailable","retryAfterSeconds":7}`, want: ErrConnectorResourceUnavailable, wantCode: "52500", wantRetry: 7 * time.Second},
		{name: "identity", body: `{"errCode":"52501","errMsg":"connector resource identity rejected"}`, want: ErrConnectorResourceIdentityRejected, wantCode: "52501"},
		{name: "entitlement", body: `{"errCode":"52502","errMsg":"connector resource entitlement denied"}`, want: ErrConnectorResourceEntitlementDenied, wantCode: "52502"},
		{name: "continuity", body: `{"errCode":"52503","errMsg":"connector resource identity conflict"}`, want: ErrConnectorResourceIdentityConflict, wantCode: "52503"},
		{name: "quota", body: `{"errCode":"52504","errMsg":"connector resource quota exceeded"}`, want: ErrConnectorResourceQuotaExceeded, wantCode: "52504"},
		{name: "rate limit", body: `{"errCode":"52505","errMsg":"connector resource rate limited","retryAfterSeconds":9}`, want: ErrConnectorResourceRateLimited, wantCode: "52505", wantRetry: 9 * time.Second},
		{name: "invalid", body: `{"errCode":"52506","errMsg":"invalid connector resource request"}`, want: ErrConnectorResourceRequestRejected, wantCode: "52506"},
	}
	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseNativeConnectorResourceResponse([]byte(tc.body), "agent-conform", request)
			if result != nil || !errors.Is(err, tc.want) {
				t.Fatalf("result, error = %#v, %v; want nil and %v", result, err, tc.want)
			}
			var discovery *ConnectorResourceDiscoveryError
			if !errors.As(err, &discovery) || discovery.Code != tc.wantCode || discovery.RetryAfter != tc.wantRetry {
				t.Fatalf("typed error = %#v, want code %s retry %v", discovery, tc.wantCode, tc.wantRetry)
			}
		})
	}
}

func TestParseNativeConnectorResourceRejectsContractDrift(t *testing.T) {
	t.Parallel()

	valid := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, false)
	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	cases := []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "invalid JSON", body: `{"errCode":`},
		{name: "duplicate nested", body: strings.Replace(valid, `"query":"connector_resource"`, `"query":"connector_resource","query":"connector_resource"`, 1)},
		{name: "unknown success field", body: strings.Replace(valid, `"found_existing":false`, `"found_existing":false,"revision":1`, 1)},
		{name: "missing found existing", body: strings.Replace(valid, `,"found_existing":false`, "", 1)},
		{name: "null found existing", body: strings.Replace(valid, `"found_existing":false`, `"found_existing":null`, 1)},
		{name: "wrong query", body: strings.Replace(valid, connectorResourceLSTQuery, "resources", 1)},
		{name: "wrong version", body: strings.Replace(valid, `"version":1`, `"version":2`, 1)},
		{name: "wrong agent", body: strings.Replace(valid, `"agent_id":"agent-conform"`, `"agent_id":"other-agent"`, 1)},
		{name: "wrong Connector", body: strings.Replace(valid, `"connector_id":"prod-dashboard"`, `"connector_id":"other-dashboard"`, 1)},
		{name: "private resource id", body: strings.Replace(valid, testConnectorID, "r_private", 1)},
		{name: "missing routing id", body: strings.Replace(valid, `"connector_routing_id":"`+testConnectorRoutingID+`",`, "", 1)},
		{name: "empty knock id", body: strings.Replace(valid, testKnockID, "", 1)},
		{name: "oversize knock id", body: strings.Replace(valid, testKnockID, strings.Repeat("k", connectorResourceLSTMaxKnockID+1), 1)},
		{name: "resource used as knock id", body: strings.Replace(valid, testKnockID, testConnectorID, 1)},
		{name: "list on error", body: `{"errCode":"52501","errMsg":"connector resource identity rejected","list":{}}`},
		{name: "unknown error code", body: `{"errCode":"52999","errMsg":"connector resource identity rejected"}`},
		{name: "wrong error message", body: `{"errCode":"52501","errMsg":"details from producer"}`},
		{name: "rate limit missing retry", body: `{"errCode":"52505","errMsg":"connector resource rate limited"}`},
		{name: "retry on terminal", body: `{"errCode":"52501","errMsg":"connector resource identity rejected","retryAfterSeconds":1}`},
		{name: "zero retry", body: `{"errCode":"52500","errMsg":"connector resource temporarily unavailable","retryAfterSeconds":0}`},
		{name: "excessive retry", body: `{"errCode":"52500","errMsg":"connector resource temporarily unavailable","retryAfterSeconds":3601}`},
		{name: "body over maximum", body: strings.Repeat("x", connectorResourceLSTMaxBody+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseNativeConnectorResourceResponse([]byte(tc.body), "agent-conform", request)
			if result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
				t.Fatalf("result, error = %#v, %v; want native response rejection", result, err)
			}
			if errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatalf("native response error was misclassified as HTTP API drift: %v", err)
			}
		})
	}
}

func TestParseNativeConnectorResourcePinsExpectedIdentityAndCRID(t *testing.T) {
	t.Parallel()

	request := &NativeConnectorResourceRequest{
		ConnectorID: testConnectorSlug, ExpectedCRID: testConnectorCRID, RequestNonce: testNativeConnectorNonce,
	}
	wrongResource := nativeConnectorSuccessBody(testOtherConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, true)
	if result, err := parseNativeConnectorResourceResponse([]byte(wrongResource), "agent-conform", request); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
		t.Fatalf("continuity mismatch = %#v, %v", result, err)
	}

	// The response is key-bound, but belongs to a different resource.
	otherCRID := "aeqq3ixwrzh6k32picwqxzdkc4dkzenxwozcpcw2fstb5uug22dn3akqpppq"
	otherKey := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpDu9mdM6E96ncBm5qjKn16Rjv6sWoHRQQz2ElwKSg5YQDLCvofuEb7gmId2YBKv3YXcrdc3tmBaiRzYCH9Hp6Q"
	if !nativeConnectorCRIDMatches(otherCRID, otherKey) {
		t.Fatal("invalid test identity")
	}
	other := nativeConnectorSuccessBody(otherKey, testConnectorRoutingID, testKnockID, otherCRID, true)
	if result, err := parseNativeConnectorResourceResponse([]byte(other), "agent-conform", request); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
		t.Fatalf("changed CRID = %#v, %v", result, err)
	}

	emptyCRID := ""
	empty := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, emptyCRID, true)
	if result, err := parseNativeConnectorResourceResponse([]byte(empty), "agent-conform", request); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
		t.Fatalf("empty CRID = %#v, %v", result, err)
	}
	foreignCRID := "a"
	foreign := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, foreignCRID, true)
	if result, err := parseNativeConnectorResourceResponse([]byte(foreign), "agent-conform", request); result != nil || !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
		t.Fatalf("foreign CRID = %#v, %v", result, err)
	}
}

func TestAgentRuntimePrivateKeyBorrowSerializesTransfer(t *testing.T) {
	t.Parallel()

	owner := newAgentRuntimePrivateKey(bytes.Repeat([]byte{0x23}, 32))
	borrowed := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- owner.withBorrow(ErrInvalidNativeConnectorResourceRequest, func(key []byte) error {
			if len(key) != 32 || key[0] != 0x23 {
				return fmt.Errorf("borrowed key changed")
			}
			close(borrowed)
			<-release
			return nil
		})
	}()
	<-borrowed

	var wg sync.WaitGroup
	wg.Add(1)
	taken := make(chan []byte, 1)
	go func() {
		defer wg.Done()
		taken <- owner.take()
	}()
	select {
	case <-taken:
		t.Fatal("key transfer did not wait for the native exchange")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	key := <-taken
	if len(key) != 32 || key[0] != 0x23 {
		t.Fatalf("transferred key = %x", key)
	}
	wipeBytes(key)
	if err := owner.withBorrow(ErrInvalidNativeConnectorResourceRequest, func([]byte) error { return nil }); !errors.Is(err, ErrInvalidNativeConnectorResourceRequest) {
		t.Fatalf("borrow after transfer = %v", err)
	}
}

func nativeConnectorSuccessBody(resourceID, routingID, knockID string, resourceCRID string, foundExisting bool) string {
	cridField := fmt.Sprintf(`,"crid":%q`, resourceCRID)
	return fmt.Sprintf(`{"errCode":"0","list":{"query":"connector_resource","version":1,"agent_id":"agent-conform","connector_id":"prod-dashboard","resource_public_key":%q,"connector_routing_id":%q,"knock_resource_id":%q%s,"found_existing":%t}}`,
		resourceID, routingID, knockID, cridField, foundExisting)
}

func newNativeConnectorResourceTestRuntime(t *testing.T, replyBody string) (*AgentRuntimeBinding, *runtimeUDPServer, runtimeRouteResolver, runtimeRouteDialer) {
	t.Helper()
	return newNativeConnectorResourceTestRuntimeStep(t, runtimeUDPStep{
		requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: replyBody,
	})
}

func newNativeConnectorResourceTestRuntimeStep(t *testing.T, step runtimeUDPStep) (*AgentRuntimeBinding, *runtimeUDPServer, runtimeRouteResolver, runtimeRouteDialer) {
	t.Helper()
	contract := loadAssignmentFixture(t)
	agentPrivate := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	agentPublic := assignmentHex(t, contract.Keys.Agent.StaticPubHex)
	cellPrivate := assignmentHex(t, contract.Keys.AssignedCell.StaticPrivHex)
	cellPublic := assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)
	server := newRuntimeUDPServer(t, cellPrivate, agentPublic, step)
	cellIP := netip.MustParseAddr("9.9.9.9")
	endpoint := NHPUDPEndpoint{
		Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: base64.StdEncoding.EncodeToString(cellPublic),
	}
	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1,
		LeaseExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Endpoint: endpoint,
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(agentPublic)
	binding := &AgentRuntimeBinding{
		AgentID: "agent-conform", PublicKeyB64: publicKeyB64, RegisteredAt: time.Now().Add(-time.Hour),
		CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt, NHPUDPEndpoint: endpoint,
		authoritativeAgentID: "agent-conform", authoritativePublicKeyB64: publicKeyB64,
		authoritativeAssignment: assignment.clone(), deviceStaticPrivateKey: newAgentRuntimePrivateKey(agentPrivate),
	}
	resolver := runtimeRouteResolver{hosts: map[string]netip.Addr{endpoint.Host: cellIP}}
	dialer := runtimeRouteDialer{targets: map[string]string{cellIP.String(): server.conn.LocalAddr().String()}}
	return binding, server, resolver, dialer
}

func TestNativeConnectorRejectsResourceIDCompatibility(t *testing.T) {
	request := &NativeConnectorResourceRequest{ConnectorID: testConnectorSlug, RequestNonce: testNativeConnectorNonce}
	good := nativeConnectorSuccessBody(testConnectorID, testConnectorRoutingID, testKnockID, testConnectorCRID, true)
	for _, body := range []string{strings.Replace(good, `"resource_public_key":`, `"resource_id":`, 1), strings.Replace(good, `,"crid":"`+testConnectorCRID+`"`, "", 1)} {
		if _, err := parseNativeConnectorResourceResponse([]byte(body), "agent-conform", request); !errors.Is(err, ErrInvalidNativeConnectorResourceResponse) {
			t.Fatalf("old response accepted: %v", err)
		}
	}
}
