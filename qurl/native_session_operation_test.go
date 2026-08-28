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

const nativeOperationProtectedResourceID = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"

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
		ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
		RunAttempt: 7, RunID: "0123456789abcdef",
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
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", BindingSchema: 2,
		CellID: "cell-01", ConnectorIDClaim: "", CredentialKind: "account",
		ExpiresAtMillis: 1_800_001_210_000, OwnerID: "auth0|canary-owner",
		PreparedAtMillis: 1_800_000_009_000, ProtectedResourceID: nativeOperationProtectedResourceID,
		QURLAgentKeysTable: "control-agent-keys", ResourceID: "resource-a",
		RunAttempt: 7, RunID: "0123456789abcdef", Schema: 2,
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
		operation.BindingSHA256 != "8cde8a58630c4e6739b4f0663da3069fccedf5a2d90e3d4d65d802044fc2c551" {
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
		"duplicate":     bytes.Replace(raw, []byte(`"schema":2`), []byte(`"schema":2,"schema":2`), 1),
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

func TestPrepareLiveNativeSessionOperationReturnsExactRecoveryEndpoint(t *testing.T) {
	binding, privateKey, input := testNativeSessionOperationBinding(t)
	input.CellID = ""
	operation, recoveryEndpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	if operation.CellID != binding.Assignment().CellID || recoveryEndpoint != binding.Assignment().Endpoint {
		t.Fatalf("live operation = %#v, recovery endpoint = %#v", operation, recoveryEndpoint)
	}
	input.CellID = operation.CellID
	if operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey, input); operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) {
		t.Fatalf("caller-selected live cell = %#v, %#v, %v", operation, endpoint, err)
	}
}

func TestPrepareLiveNativeSessionOperationRejectsInvalidArguments(t *testing.T) {
	binding, privateKey, input := testNativeSessionOperationBinding(t)
	input.CellID = ""
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		binding *AgentRuntimeBinding
		key     []byte
		input   NativeSessionOperationInput
		wantErr error
	}{
		{name: "nil context", binding: binding, key: privateKey, input: input, wantErr: ErrInvalidNativeSessionOperation},
		{name: "canceled context", ctx: canceled, binding: binding, key: privateKey, input: input, wantErr: context.Canceled},
		{name: "nil binding", ctx: context.Background(), key: privateKey, input: input, wantErr: ErrInvalidNativeSessionOperation},
		{name: "short key", ctx: context.Background(), binding: binding, key: privateKey[:31], input: input, wantErr: ErrInvalidNativeSessionOperation},
		{
			name: "caller cell", ctx: context.Background(), binding: binding, key: privateKey,
			input:   func() NativeSessionOperationInput { changed := input; changed.CellID = "cell-01"; return changed }(),
			wantErr: ErrInvalidNativeSessionOperation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, endpoint, err := PrepareLiveNativeSessionOperation(test.ctx, test.binding, test.key, test.input)
			if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, test.wantErr) {
				t.Fatalf("invalid preparation = %#v, %#v, %v", operation, endpoint, err)
			}
		})
	}
}

func TestPrepareLiveNativeSessionOperationRejectsInputBeforeHubIO(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, test := range []struct {
		name string
		edit func(*NativeSessionOperationInput)
	}{
		{name: "run attempt", edit: func(input *NativeSessionOperationInput) { input.RunAttempt = 0 }},
		{name: "AWS region", edit: func(input *NativeSessionOperationInput) { input.AWSRegion = "sandbox" }},
		{name: "creation window", edit: func(input *NativeSessionOperationInput) { input.ExpiresAtMillis = input.PreparedAtMillis }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil).expectSilence()
			seedSessionLease(t, f, contract, time.Now().Add(sessionLeaseRenewalLead+nativeSessionOperationJournalMargin/2))
			binding, privateKey := openSessionBinding(t, f)
			now := time.Now().UTC()
			input := NativeSessionOperationInput{
				AWSAccountID: "111122223333", AWSRegion: "us-east-2",
				PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
				OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
				ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
				RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
			}
			test.edit(&input)
			operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey, input)
			if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) {
				t.Fatalf("invalid input preparation = %#v, %#v, %v", operation, endpoint, err)
			}
			if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("invalid input I/O Hub/cell = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestPrepareLiveNativeSessionOperationSkipsRenewalWithSafeMargin(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
	binding, privateKey := openSessionBinding(t, f)
	now := time.Now().UTC()
	operation, recoveryEndpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if err != nil || operation == nil || recoveryEndpoint.Host == "" {
		t.Fatalf("safe-margin preparation = %#v, %#v, %v", operation, recoveryEndpoint, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("safe-margin preparation I/O Hub/cell = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestPrepareLiveNativeSessionOperationDoesNotMislabelTamperAsLeaseExpiry(t *testing.T) {
	binding, privateKey, input := testNativeSessionOperationBinding(t)
	input.CellID = ""
	binding.CellID = "tampered-cell"
	operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey, input)
	if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) ||
		!errors.Is(err, ErrInvalidNativeKnockInput) || errors.Is(err, ErrAssignmentLeaseExpired) {
		t.Fatalf("tampered preparation = %#v, %#v, %v", operation, endpoint, err)
	}
}

func TestPrepareLiveNativeSessionOperationRenewsBeforeJournalMargin(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: rewriteRefreshAssignment(t, contract, renewed),
		}}, nil)
	lease := time.Now().Add(sessionLeaseRenewalLead + nativeSessionOperationJournalMargin/2)
	seedSessionLease(t, f, contract, lease)
	binding, privateKey := openSessionBinding(t, f)
	original := binding.Assignment()
	now := time.Now().UTC()
	operation, recoveryEndpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("preparation Hub renewals = %d, want 1", len(f.hubUDP.snapshot()))
	}
	if operation.CellID != renewed.CellID || recoveryEndpoint != renewed.Endpoint ||
		operation.CellID == original.CellID || recoveryEndpoint == original.Endpoint ||
		binding.Assignment().CellID != renewed.CellID || binding.Assignment().Endpoint != renewed.Endpoint ||
		!binding.Assignment().LeaseExpiresAt.After(lease) {
		t.Fatalf("renewed operation = %#v, recovery endpoint = %#v", operation, recoveryEndpoint)
	}
}

func TestPrepareLiveNativeSessionOperationRejectsShortSuccessfulRenewal(t *testing.T) {
	contract := loadAssignmentFixture(t)
	renewed := newReassignmentTarget(t, contract, "cell0", 1, "", time.Now().Add(3*time.Minute))
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult,
			replyBody: rewriteRefreshAssignment(t, contract, renewed),
		}}, nil)
	seedSessionLease(t, f, contract, time.Now().Add(nativeSessionOperationJournalMargin))
	binding, privateKey := openSessionBinding(t, f)
	now := time.Now().UTC()
	operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if operation != nil || endpoint != (NHPUDPEndpoint{}) ||
		!errors.Is(err, ErrNativeSessionOperationLeaseMargin) || errors.Is(err, ErrAssignmentLeaseExpired) {
		t.Fatalf("short renewed lease = %#v, %#v, %v", operation, endpoint, err)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("short renewed lease I/O Hub/cell = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestReleasedAssignmentLeaseHasNativeSessionOperationHeadroom(t *testing.T) {
	contract := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply(
		[]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	required := nativeSessionOperationJournalMargin + sessionLeaseRenewalLead
	if !assignmentFixtureNow.Add(required).Before(initial.Assignment.LeaseExpiresAt) {
		t.Fatalf("released assignment lease does not exceed native session operation headroom %s: %#v", required, initial.Assignment)
	}
}

func TestPrepareLiveNativeSessionOperationClassifiesExpiredOfflineBinding(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	seedSessionLease(t, f, contract, time.Now().Add(-time.Minute))
	binding, privateKey := openSessionBinding(t, f, WithAgentRuntimeOfflineOpen())
	now := time.Now().UTC()
	operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) ||
		!errors.Is(err, ErrAssignmentLeaseExpired) || errors.Is(err, ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("expired offline binding = %#v, %#v, %v", operation, endpoint, err)
	}
}

func TestLiveSessionAssignmentStrictRejectsOfflineMarginRequirement(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	seedSessionLease(t, f, contract,
		time.Now().Add(sessionLeaseRenewalLead+nativeSessionOperationJournalMargin/2))
	binding, privateKey := openSessionBinding(t, f, WithAgentRuntimeOfflineOpen())
	decisionAt := time.Now().UTC().Add(nativeSessionOperationJournalMargin)
	assignment, err := binding.liveSessionAssignmentStrict(context.Background(), privateKey, decisionAt)
	if assignment != nil || !errors.Is(err, errAgentRuntimeRenewalUnavailable) {
		t.Fatalf("strict offline assignment = %#v, %v", assignment, err)
	}
}

func TestPrepareLiveNativeSessionOperationClassifiesExpiredOnlineBindingWhenHubIsUnavailable(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	seedSessionLease(t, f, contract, time.Now().Add(-time.Minute))
	binding, privateKey := openSessionBinding(t, f)
	now := time.Now().UTC()
	operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) ||
		!errors.Is(err, ErrAssignmentLeaseExpired) || errors.Is(err, ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("expired online binding = %#v, %#v, %v", operation, endpoint, err)
	}
	if len(f.hubUDP.snapshot()) == 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("expired online binding I/O Hub/cell = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestPrepareLiveNativeSessionOperationRejectsInvalidLiveEndpoint(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	seedSessionLease(t, f, contract, time.Now().Add(12*time.Hour))
	binding, privateKey := openSessionBinding(t, f)
	live := binding.Assignment()
	binding.renewedAssignment = live.clone()
	binding.renewedAssignment.Endpoint.Host = "192.0.2.1"
	now := time.Now().UTC()
	operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
		NativeSessionOperationInput{
			AWSAccountID: "111122223333", AWSRegion: "us-east-2",
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
			ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
			RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
		})
	if operation != nil || endpoint != (NHPUDPEndpoint{}) || !errors.Is(err, ErrInvalidNativeSessionOperation) ||
		errors.Is(err, ErrNativeSessionOperationLeaseMargin) {
		t.Fatalf("invalid live endpoint = %#v, %#v, %v", operation, endpoint, err)
	}
}

func TestPrepareLiveNativeSessionOperationFailsWithoutSafeLeaseMargin(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, test := range []struct {
		name      string
		remaining time.Duration
	}{
		{name: "lease remains live at shifted clock", remaining: sessionLeaseRenewalLead + nativeSessionOperationJournalMargin/2},
		{name: "lease expires before shifted clock", remaining: nativeSessionOperationJournalMargin / 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil).expectSilence()
			seedSessionLease(t, f, contract, time.Now().Add(test.remaining))
			binding, privateKey := openSessionBinding(t, f)
			now := time.Now().UTC()
			operation, endpoint, err := PrepareLiveNativeSessionOperation(context.Background(), binding, privateKey,
				NativeSessionOperationInput{
					AWSAccountID: "111122223333", AWSRegion: "us-east-2",
					PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
					OwnerID: "auth0|canary-owner", QURLAgentKeysTable: "control-agent-keys",
					ProtectedResourceID: nativeOperationProtectedResourceID, ResourceID: "resource-a",
					RunAttempt: 1, RunID: "0123456789abcdef", SessionControlTable: "sandbox-session-control",
				})
			if operation != nil || endpoint != (NHPUDPEndpoint{}) ||
				!errors.Is(err, ErrNativeSessionOperationLeaseMargin) ||
				errors.Is(err, ErrInvalidNativeSessionOperation) || errors.Is(err, ErrAssignmentLeaseExpired) {
				t.Fatalf("unsafe lease preparation = %#v, %#v, %v", operation, endpoint, err)
			}
			if len(f.hubUDP.snapshot()) == 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("unsafe lease I/O Hub/cell = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestNativeSessionOperationWireProjectionIsExactAndLegacyUnchanged(t *testing.T) {
	_, _, operation := testNativeSessionOperation(t)
	legacy, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{ProtectedResourceID: operation.ProtectedResourceID, RunID: operation.RunID, RunAttempt: operation.RunAttempt})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "operation_id") {
		t.Fatalf("legacy wire grew operation fields: %s", legacy)
	}
	body, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{ProtectedResourceID: operation.ProtectedResourceID, RunID: operation.RunID, RunAttempt: operation.RunAttempt, Operation: &operation})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"headerType":1,"usrId":"agent-a","devId":"agent-a","aspId":"agent","resId":"resource-a","runId":"0123456789abcdef","runAttempt":7,"protected_resource_id":"` +
		operation.ProtectedResourceID + `","operation_id":"` +
		operation.OperationID + `","binding_sha256":"` + operation.BindingSHA256 +
		`","owner_id":"auth0|canary-owner","prepared_at_ms":` +
		jsonNumber(operation.PreparedAtMillis) + `,"expires_at_ms":` + jsonNumber(operation.ExpiresAtMillis) + `}`
	if string(body) != want {
		t.Fatalf("operation wire = %s\nwant = %s", body, want)
	}
	drifted := operation
	drifted.OwnerID = "auth0|other"
	if _, err := marshalNativeKnockApplicationBody(operation.AgentID, operation.ResourceID,
		NativeKnockOptions{ProtectedResourceID: operation.ProtectedResourceID, RunID: operation.RunID, RunAttempt: operation.RunAttempt, Operation: &drifted}); !errors.Is(err, ErrInvalidNativeSessionOperation) {
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
		`,"expires_at_ms":` + jsonNumber(operation.ExpiresAtMillis) +
		`,"protected_resource_id":"` + operation.ProtectedResourceID + `"}`
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
