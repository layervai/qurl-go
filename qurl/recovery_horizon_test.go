package qurl

import (
	"context"
	"errors"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

func recoveryTestPendingActivation(t *testing.T) (*AgentState, *InitialAgentAssignment) {
	t.Helper()
	contract := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply(
		[]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	state.AgentID = "agent-conform"
	state.Assignment = initial.Assignment.clone()
	state.SchemaVersion = agentStateSchemaVersion
	state.PendingActivation, err = newPendingAgentActivation(
		initial, state, "conformance-host", "0.0.0-conformance",
		conformance.AgentAssignmentBootstrapCredentialFixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	return state, initial
}

func TestAgentRegistrationRecoveryHorizonContract(t *testing.T) {
	if AgentRegistrationRecoveryHorizon != 90*24*time.Hour {
		t.Fatalf("AgentRegistrationRecoveryHorizon = %s, want 90 days", AgentRegistrationRecoveryHorizon)
	}
	state, initial := recoveryTestPendingActivation(t)
	want := initial.AssignmentTicketExpiresAt.Add(AgentRegistrationRecoveryHorizon)
	if !state.PendingActivation.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("activation recovery deadline = %s, want %s", state.PendingActivation.RecoveryExpiresAt, want)
	}

	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	store := &memoryAgentStateStore{state: state.clone()}
	if err := cfg.transitionPendingActivation(context.Background(), store, state); err != nil {
		t.Fatal(err)
	}
	if state.PendingActivation != nil || state.PendingCompletion == nil ||
		!state.PendingCompletion.AssignmentTicketExpiresAt.Equal(initial.AssignmentTicketExpiresAt) ||
		!state.PendingCompletion.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("RAK transition reset or lost recovery deadline: %#v", state)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil || loaded.PendingCompletion == nil ||
		!loaded.PendingCompletion.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("persisted completion recovery deadline = %#v, %v", loaded, err)
	}
}

func TestRegisterAgentRuntime_MigratesLegacyActivationThenExpiresWithoutUDP(t *testing.T) {
	state, initial := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation.RecoveryExpiresAt = time.Time{}
	f := newRuntimeFixture(t, nil, nil)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	wantDeadline := initial.AssignmentTicketExpiresAt.Add(AgentRegistrationRecoveryHorizon)

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return wantDeadline }))...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) ||
		expired.Phase != AgentRecoveryPhaseActivation || !expired.RecoveryExpiresAt.Equal(wantDeadline) {
		t.Fatalf("legacy activation expiry = %T %#v / %v", err, expired, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("expired legacy activation sent Hub/cell UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.SchemaVersion != agentStateSchemaVersion || loaded.PendingActivation == nil ||
		loaded.PendingActivation.AssignmentTicket != initial.AssignmentTicket ||
		!loaded.PendingActivation.RecoveryExpiresAt.Equal(wantDeadline) {
		t.Fatalf("legacy activation migration did not preserve exact pending state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_LegacyActivationMigrationMustPersistBeforeUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation.RecoveryExpiresAt = time.Time{}
	f := newRuntimeFixture(t, nil, nil)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	f.store.fail = 2 // fixture save succeeds; migration save fails

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options()...,
	)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("legacy activation migration save = %v, want ErrAgentBindingPersistence", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("unpersisted legacy migration sent Hub/cell UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.SchemaVersion != 5 || loaded.PendingActivation == nil ||
		!loaded.PendingActivation.RecoveryExpiresAt.IsZero() {
		t.Fatalf("failed migration mutated stored state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_LegacyCompletionRequiresExplicitMigrationWithoutUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation = nil
	state.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey:         canonicalNativeDeviceCredential,
		CellID:               state.Assignment.CellID,
		AssignmentGeneration: state.Assignment.AssignmentGeneration,
	}
	f := newRuntimeFixture(t, nil, nil)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, _, err := RegisterAgentRuntime(context.Background(), "", f.store, f.options()...)
	var migration *AgentRecoveryMigrationRequiredError
	if !errors.Is(err, ErrAgentRecoveryMigrationRequired) || !errors.As(err, &migration) ||
		migration.Phase != AgentRecoveryPhaseCompletion || migration.SchemaVersion != 5 {
		t.Fatalf("legacy completion migration = %T %#v / %v", err, migration, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("legacy completion sent Hub/cell UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.SchemaVersion != 5 || loaded.PendingCompletion == nil ||
		!loaded.PendingCompletion.RecoveryExpiresAt.IsZero() || loaded.DeviceAPIKey != "" {
		t.Fatalf("legacy completion migration mutated pending state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_ExpiredCompletionPreservesStateWithoutUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	ticketExpiresAt := state.PendingActivation.AssignmentTicketExpiresAt
	state.PendingActivation = nil
	state.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey:              canonicalNativeDeviceCredential,
		CellID:                    state.Assignment.CellID,
		AssignmentGeneration:      state.Assignment.AssignmentGeneration,
		AssignmentTicketExpiresAt: ticketExpiresAt,
		RecoveryExpiresAt:         deadline,
	}
	f := newRuntimeFixture(t, nil, nil)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, _, err := RegisterAgentRuntime(
		context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return deadline }))...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) ||
		expired.Phase != AgentRecoveryPhaseCompletion || !expired.RecoveryExpiresAt.Equal(deadline) {
		t.Fatalf("completion expiry = %T %#v / %v", err, expired, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("expired completion sent Hub/cell UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion == nil ||
		loaded.PendingCompletion.DeviceAPIKey != canonicalNativeDeviceCredential ||
		!loaded.PendingCompletion.RecoveryExpiresAt.Equal(deadline) {
		t.Fatalf("expired completion state was not preserved: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_RejectsTamperedRecoveryAuthorityBeforeUDP(t *testing.T) {
	activation, _ := recoveryTestPendingActivation(t)
	completion := activation.clone()
	completion.PendingActivation = nil
	completion.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey:              canonicalNativeDeviceCredential,
		CellID:                    completion.Assignment.CellID,
		AssignmentGeneration:      completion.Assignment.AssignmentGeneration,
		AssignmentTicketExpiresAt: activation.PendingActivation.AssignmentTicketExpiresAt,
		RecoveryExpiresAt:         activation.PendingActivation.RecoveryExpiresAt,
	}
	tests := []struct {
		name       string
		state      *AgentState
		credential string
		mutate     func(*AgentState)
	}{
		{
			name: "activation deadline", state: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate: func(state *AgentState) {
				state.PendingActivation.RecoveryExpiresAt = state.PendingActivation.RecoveryExpiresAt.Add(time.Second)
			},
		},
		{
			name: "completion ticket anchor", state: completion,
			mutate: func(state *AgentState) {
				state.PendingCompletion.AssignmentTicketExpiresAt = state.PendingCompletion.AssignmentTicketExpiresAt.Add(time.Second)
			},
		},
		{
			name: "completion deadline", state: completion,
			mutate: func(state *AgentState) {
				state.PendingCompletion.RecoveryExpiresAt = state.PendingCompletion.RecoveryExpiresAt.Add(time.Second)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := test.state.clone()
			test.mutate(state)
			f := newRuntimeFixture(t, nil, nil)
			if err := f.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}

			_, _, err := RegisterAgentRuntime(context.Background(), test.credential, f.store, f.options()...)
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("tampered %s = %v, want invalid persisted state", test.name, err)
			}
			if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("tampered %s sent Hub/cell UDP = %d/%d", test.name, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRequirePendingRecoveryLive_DeadlineBoundaryAndClockFailure(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.clock = func() time.Time { return deadline.Add(-time.Nanosecond) }
	if err := cfg.requirePendingRecoveryLive(state); err != nil {
		t.Fatalf("instant before recovery deadline = %v", err)
	}
	cfg.clock = func() time.Time { return deadline }
	if err := cfg.requirePendingRecoveryLive(state); !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("recovery deadline instant = %v, want ErrAgentRecoveryExpired", err)
	}
	cfg.clock = func() time.Time { return time.Time{} }
	if err := cfg.requirePendingRecoveryLive(state); !errors.Is(err, ErrInvalidRegisterConfig) || errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("zero recovery clock = %v, want invalid config only", err)
	}
}

func TestRecoveryBoundExchange_RefusesRetryAtDeadline(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	now := deadline.Add(-time.Nanosecond)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.clock = func() time.Time { return now }
	calls := 0
	exchange := cfg.recoveryBoundExchange(state, func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) (*relayknock.Reply, error) {
		calls++
		return &relayknock.Reply{}, nil
	})

	if _, err := exchange(context.Background(), nativeudp.Endpoint{}, nil, nativeudp.Options{}); err != nil || calls != 1 {
		t.Fatalf("live recovery exchange = calls %d / %v, want one dispatch", calls, err)
	}
	now = deadline
	if _, err := exchange(context.Background(), nativeudp.Endpoint{}, nil, nativeudp.Options{}); !errors.Is(err, ErrAgentRecoveryExpired) || calls != 1 {
		t.Fatalf("expired recovery retry = calls %d / %v, want no second dispatch", calls, err)
	}
}
