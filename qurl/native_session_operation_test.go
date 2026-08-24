package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
)

func testNativeSessionOperationBinding(t *testing.T) (*AgentRuntimeBinding, []byte, NativeSessionOperationInput) {
	t.Helper()
	contract := loadAssignmentFixture(t)
	privateBytes := assignmentHex(t, contract.Keys.Agent.StaticPrivHex)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicB64 := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	assignment := &AgentAssignment{
		CellID: "cell-01", AssignmentGeneration: 7, EndpointRevision: 3,
		LeaseExpiresAt: time.Now().Add(time.Hour),
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)),
		},
	}
	binding := &AgentRuntimeBinding{
		AgentID: "agent-a", PublicKeyB64: publicB64,
		CellID: assignment.CellID, AssignmentGeneration: assignment.AssignmentGeneration,
		EndpointRevision: assignment.EndpointRevision, LeaseExpiresAt: assignment.LeaseExpiresAt,
		NHPUDPEndpoint:       assignment.Endpoint,
		authoritativeAgentID: "agent-a", authoritativePublicKeyB64: publicB64,
		authoritativeAssignment: assignment.clone(),
	}
	now := time.Now().UTC()
	return binding, privateBytes, NativeSessionOperationInput{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: "cell-01",
		PreparedAtMillis: now.Add(-time.Second).UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
		OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
		ResourceID: "resource-a", RunAttempt: 7, RunID: "0123456789abcdef",
		SessionControlTable: "sandbox-session-control",
	}
}

func testNativeSessionOperation(t *testing.T) (*AgentRuntimeBinding, []byte, NativeSessionOperation) {
	t.Helper()
	binding, privateKey, input := testNativeSessionOperationBinding(t)
	operation, err := PrepareNativeSessionOperation(binding, privateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	return binding, privateKey, *operation
}

func TestNativeSessionOperationNHPContractFixture(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	operation := NativeSessionOperation{
		AgentID: "agent-a", AgentKeySchema: 2, AgentPublicKeyB64: publicKey, AuthServiceID: "agent",
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", BindingSchema: 1,
		CellID: "cell-01", ConnectorIDClaim: "", CredentialKind: "account",
		ExpiresAtMillis: 1_800_001_210_000, OwnerID: "auth0|canary-owner",
		PreparedAtMillis: 1_800_000_009_000, QURLAgentKeysTable: "control-agent-keys",
		ResourceID: "resource-a", RunAttempt: 7, RunID: "0123456789abcdef", Schema: 1,
		SessionControlTable: "sandbox-session-control",
	}
	var err error
	operation.OperationID, err = nativeSessionOperationID(publicKey, operation.RunID, operation.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	operation.BindingSHA256, err = nativeSessionOperationBindingSHA256(operation)
	if err != nil {
		t.Fatal(err)
	}
	if operation.OperationID != "3b2a3a9eabea3af78d8c317ea710e7f0601580163e25c98d50d5e2e17b68f3cc" ||
		operation.BindingSHA256 != "73add3ded83c588697131214c3e362ecc651512afa9c2ff4bad7d790a43593d8" {
		t.Fatalf("NHP operation fixture drifted: %s/%s", operation.OperationID, operation.BindingSHA256)
	}
}

func TestPrepareNativeSessionOperationIsOfflineAndClosed(t *testing.T) {
	binding, privateKey, input := testNativeSessionOperationBinding(t)
	operation, err := PrepareNativeSessionOperation(binding, privateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	if operation.AgentID != binding.AgentID || operation.AgentPublicKeyB64 != binding.PublicKeyB64 ||
		operation.CellID != input.CellID || operation.OwnerID != input.OwnerID ||
		operation.AgentKeySchema != 2 || operation.CredentialKind != "account" ||
		operation.ConnectorIDClaim != "" {
		t.Fatalf("prepared operation = %#v", operation)
	}
	raw, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	var restored NativeSessionOperation
	if err := json.Unmarshal(raw, &restored); err != nil || restored != *operation {
		t.Fatalf("operation round trip = %#v, %v", restored, err)
	}
	if bytes.Contains(raw, privateKey) {
		t.Fatal("serialized operation contains private key bytes")
	}
	if !bytes.HasPrefix(raw, []byte(`{"agent_id":`)) || !bytes.HasSuffix(raw, []byte(`"session_control_table":"sandbox-session-control"}`)) {
		t.Fatalf("operation JSON is not sorted canonical: %s", raw)
	}

	mutations := map[string][]byte{
		"unknown":       append(bytes.TrimSuffix(bytes.Clone(raw), []byte("}")), []byte(`,"unknown":1}`)...),
		"duplicate":     bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"trailing":      append(bytes.Clone(raw), []byte(`{}`)...),
		"missing":       bytes.Replace(raw, []byte(`,"owner_id":"auth0|canary-owner"`), nil, 1),
		"binding drift": bytes.Replace(raw, []byte(`"owner_id":"auth0|canary-owner"`), []byte(`"owner_id":"auth0|other"`), 1),
		"whitespace":    bytes.Replace(raw, []byte(`{"agent_id"`), []byte(`{ "agent_id"`), 1),
		"key order":     bytes.Replace(raw, []byte(`{"agent_id":"agent-a","agent_key_schema_version":2`), []byte(`{"agent_key_schema_version":2,"agent_id":"agent-a"`), 1),
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			var decoded NativeSessionOperation
			if err := json.Unmarshal(mutation, &decoded); err == nil {
				t.Fatal("mutated operation decoded")
			}
		})
	}

	wrongCell := input
	wrongCell.CellID = "cell-02"
	if _, err := PrepareNativeSessionOperation(binding, privateKey, wrongCell); !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("wrong cell = %v", err)
	}
	wrongOwner := input
	wrongOwner.OwnerID = " owner"
	if _, err := PrepareNativeSessionOperation(binding, privateKey, wrongOwner); !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("wrong owner = %v", err)
	}
	invalidUTF8 := input
	invalidUTF8.OwnerID = string([]byte{'o', 0xff})
	if _, err := PrepareNativeSessionOperation(binding, privateKey, invalidUTF8); !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("invalid UTF-8 owner = %v", err)
	}
	wrongRegion := input
	wrongRegion.AWSRegion = "sandbox"
	if _, err := PrepareNativeSessionOperation(binding, privateKey, wrongRegion); !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("wrong AWS region = %v", err)
	}
}

func TestNativeSessionOperationWireProjectionIsExactAndLegacyUnchanged(t *testing.T) {
	_, _, operation := testNativeSessionOperation(t)
	legacy, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{RunID: operation.RunID, RunAttempt: operation.RunAttempt})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "operation_id") {
		t.Fatalf("legacy wire grew operation fields: %s", legacy)
	}
	body, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{RunID: operation.RunID, RunAttempt: operation.RunAttempt, Operation: &operation})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"headerType":1,"usrId":"agent-a","devId":"agent-a","aspId":"agent","resId":"resource-a","runId":"0123456789abcdef","runAttempt":7,"operation_id":"` +
		operation.OperationID + `","binding_sha256":"` + operation.BindingSHA256 +
		`","owner_id":"auth0|canary-owner","prepared_at_ms":` +
		jsonNumber(operation.PreparedAtMillis) + `,"expires_at_ms":` + jsonNumber(operation.ExpiresAtMillis) + `}`
	if string(body) != want {
		t.Fatalf("operation wire = %s\nwant = %s", body, want)
	}
	drifted := operation
	drifted.OwnerID = "auth0|other"
	if _, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{RunID: operation.RunID, RunAttempt: operation.RunAttempt, Operation: &drifted}); !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("drifted wire = %v", err)
	}
}

func jsonNumber(value int64) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestRecoverNativeSessionOperationUsesExactEndpointAndBody(t *testing.T) {
	binding, privateKey, operation := testNativeSessionOperation(t)
	contract := loadAssignmentFixture(t)
	canceledACK := `{"errCode":"0","operation_id":"` + operation.OperationID +
		`","binding_sha256":"` + operation.BindingSHA256 + `","state":"CANCELED"}`
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeExit, replyType: relayknock.TypeACK, replyBody: canceledACK,
	}})
	endpoint := NHPUDPEndpoint{
		Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, contract.Keys.AssignedCell.StaticPubHex)),
	}
	result, err := RecoverNativeSessionOperation(context.Background(), binding, privateKey, operation, endpoint,
		WithAgentRuntimeUDPResolver(f.resolver), WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(runtimeReplyTimeout, 1))
	if err != nil || result == nil || result.State != "CANCELED" || result.OperationID != operation.OperationID {
		t.Fatalf("recovery = %#v, %v", result, err)
	}
	requests := f.cellUDP.snapshot()
	if len(requests) != 1 || requests[0].typeID != relayknock.TypeExit {
		t.Fatalf("recovery packets = %#v", requests)
	}
	want := `{"headerType":16,"usrId":"agent-a","devId":"agent-a","aspId":"agent","resId":"resource-a","runId":"0123456789abcdef","runAttempt":7,"operation_id":"` +
		operation.OperationID + `","binding_sha256":"` + operation.BindingSHA256 +
		`","owner_id":"auth0|canary-owner","prepared_at_ms":` + jsonNumber(operation.PreparedAtMillis) +
		`,"expires_at_ms":` + jsonNumber(operation.ExpiresAtMillis) + `}`
	if string(requests[0].body) != want {
		t.Fatalf("recovery body = %s\nwant = %s", requests[0].body, want)
	}
}

func TestConsumeNativeSessionOperationRecoveryReplyClosedUnion(t *testing.T) {
	_, _, operation := testNativeSessionOperation(t)
	closed := `{"errCode":"0","operation_id":"` + operation.OperationID +
		`","binding_sha256":"` + operation.BindingSHA256 +
		`","state":"CLOSED","cellId":"cell-01","sessId":123,"sessIssuedAtMillis":1800000000000,` +
		`"runId":"0123456789abcdef","runAttempt":7,"closeEventId":"0123456789abcdef0123456789abcdef"}`
	result, err := consumeNativeSessionOperationRecoveryReply(&relayknock.Reply{
		Type: relayknock.TypeACK, Body: []byte(closed),
	}, operation)
	if err != nil || result == nil || result.State != "CLOSED" || result.SessionID != 123 ||
		result.CloseEventID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("closed recovery = %#v, %v", result, err)
	}
	emptyMessage := strings.Replace(closed, `"errCode":"0"`, `"errCode":"0","errMsg":""`, 1)
	if result, err := consumeNativeSessionOperationRecoveryReply(&relayknock.Reply{
		Type: relayknock.TypeACK, Body: []byte(emptyMessage),
	}, operation); err != nil || result == nil || result.State != "CLOSED" {
		t.Fatalf("empty optional errMsg = %#v, %v", result, err)
	}
	for name, body := range map[string]string{
		"unknown":         strings.TrimSuffix(closed, "}") + `,"extra":1}`,
		"duplicate":       strings.Replace(closed, `"state":"CLOSED"`, `"state":"CLOSED","state":"CLOSED"`, 1),
		"wrong operation": strings.Replace(closed, operation.OperationID, strings.Repeat("a", 64), 1),
		"wrong binding":   strings.Replace(closed, operation.BindingSHA256, strings.Repeat("b", 64), 1),
		"wrong cell":      strings.Replace(closed, `"cell-01"`, `"cell-02"`, 1),
		"bad state":       strings.Replace(closed, `"CLOSED"`, `"MAPPED"`, 1),
		"nonempty errMsg": strings.Replace(closed, `"errCode":"0"`, `"errCode":"0","errMsg":"unexpected"`, 1),
		"canceled session": `{"errCode":"0","operation_id":"` + operation.OperationID +
			`","binding_sha256":"` + operation.BindingSHA256 + `","state":"CANCELED","sessId":123}`,
		"deny authority": `{"errCode":"52029","errMsg":"recover","operation_id":"` + operation.OperationID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := consumeNativeSessionOperationRecoveryReply(&relayknock.Reply{
				Type: relayknock.TypeACK, Body: []byte(body),
			}, operation)
			if got != nil || !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("recovery mutation = %#v, %v", got, err)
			}
		})
	}
	denial, err := consumeNativeSessionOperationRecoveryReply(&relayknock.Reply{
		Type: relayknock.TypeACK, Body: []byte(`{"errCode":"52029","errMsg":"native session operation recovery required"}`),
	}, operation)
	if denial != nil || !NativeSessionOperationRecoveryRequired(err) {
		t.Fatalf("recovery required classification = %#v, %v", denial, err)
	}
}

func TestNativeSessionOperationAbsentRecoveryDeadlineBoundary(t *testing.T) {
	_, _, operation := testNativeSessionOperation(t)
	deadline, err := NativeSessionOperationAbsentRecoveryDeadline(operation)
	if err != nil {
		t.Fatal(err)
	}
	wantPrepared := time.UnixMilli(operation.PreparedAtMillis).Add(24 * time.Hour)
	wantExpires := time.UnixMilli(operation.ExpiresAtMillis).Add(125 * time.Second)
	want := wantPrepared
	if wantExpires.After(want) {
		want = wantExpires
	}
	if !deadline.Equal(want.UTC()) {
		t.Fatalf("deadline = %s, want %s", deadline, want.UTC())
	}
}
