package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
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

func seedRecoveryRuntimePendingActivation(t *testing.T, f *runtimeFixture) *AgentState {
	t.Helper()
	initial, err := parseInitialAssignmentReply(
		[]byte(f.contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.Assignment = initial.Assignment.clone()
	state.SchemaVersion = agentStateSchemaVersion
	state.PendingActivation, err = newPendingAgentActivation(
		initial, state, "conformance-host", "0.0.0-conformance",
		conformance.AgentAssignmentBootstrapCredentialFixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	return state
}

func assignmentResultWithTicketExpiry(t *testing.T, body, ticket string, expiry time.Time) string {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatal(err)
	}
	list := envelope["list"].(map[string]any)
	list["assignment_ticket"] = ticket
	list["assignment_ticket_expires_at"] = expiry.UTC().Format(time.RFC3339)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func setTestRecoveryDeadline(state *AgentState, deadline time.Time) {
	anchor := deadline.Add(-AgentRegistrationRecoveryHorizon)
	if state.PendingActivation != nil {
		state.PendingActivation.RecoveryAnchorTicketExpiresAt = anchor
		state.PendingActivation.RecoveryExpiresAt = deadline
	}
	if state.PendingCompletion != nil {
		state.PendingCompletion.RecoveryAnchorTicketExpiresAt = anchor
		state.PendingCompletion.RecoveryExpiresAt = deadline
	}
}

func TestAgentRegistrationRecoveryHorizonContract(t *testing.T) {
	if AgentRegistrationRecoveryHorizon != 90*24*time.Hour {
		t.Fatalf("AgentRegistrationRecoveryHorizon = %s, want 90 days", AgentRegistrationRecoveryHorizon)
	}
	state, initial := recoveryTestPendingActivation(t)
	want := initial.AssignmentTicketExpiresAt.Add(AgentRegistrationRecoveryHorizon)
	if !state.PendingActivation.RecoveryAnchorTicketExpiresAt.Equal(initial.AssignmentTicketExpiresAt) ||
		!state.PendingActivation.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("activation recovery deadline = %s, want %s", state.PendingActivation.RecoveryExpiresAt, want)
	}

	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	store := &memoryAgentStateStore{state: state.clone()}
	if err := cfg.transitionPendingActivation(context.Background(), store, state); err != nil {
		t.Fatal(err)
	}
	if state.PendingActivation != nil || state.PendingCompletion == nil ||
		!state.PendingCompletion.RecoveryAnchorTicketExpiresAt.Equal(initial.AssignmentTicketExpiresAt) ||
		!state.PendingCompletion.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("RAK transition reset or lost recovery deadline: %#v", state)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil || loaded.PendingCompletion == nil ||
		!loaded.PendingCompletion.RecoveryExpiresAt.Equal(want) {
		t.Fatalf("persisted completion recovery deadline = %#v, %v", loaded, err)
	}
}

func TestRegisterAgentRuntime_SchemaV6PendingRecoveryRemainsResumable(t *testing.T) {
	contract := loadAssignmentFixture(t)
	for _, phase := range []AgentRecoveryPhase{AgentRecoveryPhaseActivation, AgentRecoveryPhaseCompletion} {
		t.Run(string(phase), func(t *testing.T) {
			steps := []runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON}}
			if phase == AgentRecoveryPhaseActivation {
				steps = append([]runtimeUDPStep{{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON}}, steps...)
			}
			f := newRuntimeFixture(t, nil, steps)
			state := seedRecoveryRuntimePendingActivation(t, f)
			candidate := canonicalNativeDeviceCredential
			if phase == AgentRecoveryPhaseCompletion {
				activation := state.PendingActivation
				state.PendingActivation = nil
				state.PendingCompletion = &PendingAgentCompletion{
					DeviceAPIKey: candidate, CellID: state.Assignment.CellID, AssignmentGeneration: state.Assignment.AssignmentGeneration,
					RecoveryAnchorTicketExpiresAt: activation.RecoveryAnchorTicketExpiresAt,
					RecoveryExpiresAt:             activation.RecoveryExpiresAt,
				}
			}
			state.SchemaVersion = registrationRecoveryStateSchemaVersion
			if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			credential := ""
			if phase == AgentRecoveryPhaseActivation {
				credential = conformance.AgentAssignmentBootstrapCredentialFixture
			}
			client, binding, err := RegisterAgentRuntime(context.Background(), credential, f.store, f.options()...)
			if err != nil || client == nil || binding == nil {
				t.Fatalf("schema-v6 %s resume = %v/%v/%v", phase, client, binding, err)
			}
			defer binding.Destroy()
			requests := f.cellUDP.snapshot()
			if len(f.hubUDP.snapshot()) != 0 || len(requests) != len(steps) || !bytes.Contains(requests[len(requests)-1].body, []byte(candidate)) {
				t.Fatalf("schema-v6 %s rotated/fell back: Hub=%d cell=%v", phase, len(f.hubUDP.snapshot()), requests)
			}
		})
	}
}

func TestRegisterAgentRuntime_ReplacementKeepsFirstRecoveryAnchorAcrossInvocations(t *testing.T) {
	contract := loadAssignmentFixture(t)
	firstExpiry := assignmentFixtureNow.Add(5 * time.Minute)
	secondExpiry := assignmentFixtureNow.Add(10 * time.Minute)
	thirdExpiry := assignmentFixtureNow.Add(maxAssignmentTicketLifetime)
	first := assignmentResultWithTicketExpiry(t, contract.InitialAssignment.Result.BodyJSON, "conformance-assignment-ticket-0001", firstExpiry)
	second := assignmentResultWithTicketExpiry(t, contract.InitialAssignment.Result.BodyJSON, "conformance-assignment-ticket-0002", secondExpiry)
	third := assignmentResultWithTicketExpiry(t, contract.InitialAssignment.Result.BodyJSON, "conformance-assignment-ticket-0003", thirdExpiry)
	verdict := `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: first},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: second},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: third},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: verdict},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: verdict},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: verdict},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: verdict},
		},
	)

	for invocation := 1; invocation <= 2; invocation++ {
		_, _, err := RegisterAgentRuntime(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
		if !errors.Is(err, ErrAssignmentTicketExpired) {
			t.Fatalf("invocation %d replacement verdict = %v, want ErrAssignmentTicketExpired", invocation, err)
		}
		pending, loadErr := f.store.LoadAgentState(context.Background())
		if loadErr != nil || pending.PendingActivation == nil {
			t.Fatalf("invocation %d pending state = %#v / %v", invocation, pending, loadErr)
		}
		wantCurrentExpiry := secondExpiry
		if invocation == 2 {
			wantCurrentExpiry = thirdExpiry
		}
		if !pending.PendingActivation.AssignmentTicketExpiresAt.Equal(wantCurrentExpiry) ||
			!pending.PendingActivation.RecoveryAnchorTicketExpiresAt.Equal(firstExpiry) ||
			!pending.PendingActivation.RecoveryExpiresAt.Equal(firstExpiry.Add(AgentRegistrationRecoveryHorizon)) {
			t.Fatalf("invocation %d reset recovery episode: %#v", invocation, pending.PendingActivation)
		}
	}
}

func TestRegisterAgentRuntime_MigratesLegacyActivationThenExpiresWithoutUDP(t *testing.T) {
	state, initial := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = time.Time{}
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
		!loaded.PendingActivation.RecoveryAnchorTicketExpiresAt.Equal(initial.AssignmentTicketExpiresAt) ||
		!loaded.PendingActivation.RecoveryExpiresAt.Equal(wantDeadline) {
		t.Fatalf("legacy activation migration did not preserve exact pending state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_RejectsSubsecondLegacyActivationMigrationBeforeSaveOrUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation.AssignmentTicketExpiresAt = state.PendingActivation.AssignmentTicketExpiresAt.Add(500 * time.Millisecond)
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = time.Time{}
	state.PendingActivation.RecoveryExpiresAt = time.Time{}
	f := newRuntimeFixture(t, nil, nil)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	beforeSaves := len(f.store.snapshots())

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options()...,
	)
	if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
		t.Fatalf("subsecond legacy activation migration = %v, want invalid state/config", err)
	}
	if len(f.store.snapshots()) != beforeSaves || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("invalid legacy migration saved or sent UDP: saves=%d/%d Hub/cell=%d/%d",
			len(f.store.snapshots()), beforeSaves, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.SchemaVersion != 5 || loaded.PendingActivation == nil ||
		loaded.PendingActivation.AssignmentTicketExpiresAt.Nanosecond() == 0 ||
		!loaded.PendingActivation.RecoveryAnchorTicketExpiresAt.IsZero() ||
		!loaded.PendingActivation.RecoveryExpiresAt.IsZero() {
		t.Fatalf("invalid legacy migration mutated durable state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_LegacyActivationMigrationMustPersistBeforeUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	state.SchemaVersion = 5 // v0.1.1
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = time.Time{}
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
		!loaded.PendingActivation.RecoveryAnchorTicketExpiresAt.IsZero() || !loaded.PendingActivation.RecoveryExpiresAt.IsZero() {
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
		!loaded.PendingCompletion.RecoveryAnchorTicketExpiresAt.IsZero() ||
		!loaded.PendingCompletion.RecoveryExpiresAt.IsZero() || loaded.DeviceAPIKey != "" {
		t.Fatalf("legacy completion migration mutated pending state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_RejectsSchemaV5ForwardRecoveryFields(t *testing.T) {
	for _, phase := range []AgentRecoveryPhase{AgentRecoveryPhaseActivation, AgentRecoveryPhaseCompletion} {
		for _, fields := range []string{"anchor", "deadline", "anchor and deadline"} {
			t.Run(string(phase)+"/"+fields, func(t *testing.T) {
				f := newRuntimeFixture(t, nil, nil)
				state := seedRecoveryRuntimePendingActivation(t, f)
				anchor := state.PendingActivation.RecoveryAnchorTicketExpiresAt
				deadline := state.PendingActivation.RecoveryExpiresAt
				state.SchemaVersion = 5
				state.PendingActivation.RecoveryAnchorTicketExpiresAt = time.Time{}
				state.PendingActivation.RecoveryExpiresAt = time.Time{}
				if phase == AgentRecoveryPhaseCompletion {
					state.PendingActivation = nil
					state.PendingCompletion = &PendingAgentCompletion{
						DeviceAPIKey: canonicalNativeDeviceCredential, CellID: state.Assignment.CellID,
						AssignmentGeneration: state.Assignment.AssignmentGeneration,
					}
				}
				setFields := func(anchorValue, deadlineValue time.Time) {
					if phase == AgentRecoveryPhaseActivation {
						state.PendingActivation.RecoveryAnchorTicketExpiresAt = anchorValue
						state.PendingActivation.RecoveryExpiresAt = deadlineValue
					} else {
						state.PendingCompletion.RecoveryAnchorTicketExpiresAt = anchorValue
						state.PendingCompletion.RecoveryExpiresAt = deadlineValue
					}
				}
				switch fields {
				case "anchor":
					setFields(anchor, time.Time{})
				case "deadline":
					setFields(time.Time{}, deadline)
				default:
					setFields(anchor, deadline)
				}
				if err := f.store.SaveAgentState(context.Background(), state); err != nil {
					t.Fatal(err)
				}

				credential := ""
				if phase == AgentRecoveryPhaseActivation {
					credential = conformance.AgentAssignmentBootstrapCredentialFixture
				}
				_, _, err := RegisterAgentRuntime(context.Background(), credential, f.store, f.options()...)
				if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
					t.Fatalf("schema-v5 forward fields = %v, want invalid state", err)
				}
				if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
					t.Fatalf("schema-v5 forward fields sent UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
				}
			})
		}
	}
}

func TestRegisterAgentRuntime_RejectsUnsupportedSchemaVersionsBeforeNetworkIO(t *testing.T) {
	for _, version := range []int{-1, agentStateSchemaVersion + 1} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			f := newRuntimeFixture(t, nil, nil)
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			state.SchemaVersion = version
			if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			resolver := &noIONativeResolver{}
			dialer := &noIONativeDialer{}

			_, _, err = RegisterAgentRuntime(
				context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
				f.options(WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))...,
			)
			if !errors.Is(err, ErrInvalidAgentState) || !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("schema version %d = %v, want invalid state/config", version, err)
			}
			if len(f.store.snapshots()) != 0 || resolver.calls.Load() != 0 || dialer.calls.Load() != 0 ||
				len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("schema version %d performed I/O: saves=%d resolver=%d dialer=%d Hub/cell=%d/%d",
					version, len(f.store.snapshots()), resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRegisterAgentRuntime_DeadlineDoesNotMaskPostRAKPersistenceAmbiguity(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeRegister,
		replyType:   relayknock.TypeRegisterAck,
		replyBody:   contract.AssignedCellRegistration.Result.BodyJSON,
	}})
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := assignmentFixtureNow.Add(time.Second)
	now := deadline.Add(-500 * time.Millisecond)
	setTestRecoveryDeadline(state, deadline)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	// Seed + deadline rewrite succeed. The post-RAK transition commits, waits
	// for its bounded context to expire, then loses its acknowledgement.
	f.store.waitForContextAfterCommit = 3
	f.store.failAfterCommit = 3

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return now }))...,
	)
	if !errors.Is(err, ErrAgentCompletionCandidatePersistence) || !errors.Is(err, ErrAgentBindingPersistence) || errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("deadline-racing post-RAK save = %v, want reload-first candidate persistence only", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion == nil || loaded.PendingActivation != nil {
		t.Fatalf("post-RAK committed state = %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_DeadlineDoesNotMaskReplacementPersistenceAmbiguity(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002")}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`}},
	)
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := assignmentFixtureNow.Add(time.Second)
	now := deadline.Add(-500 * time.Millisecond)
	setTestRecoveryDeadline(state, deadline)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	f.store.waitForContextAfterCommit = 3
	f.store.failAfterCommit = 3

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return now }))...,
	)
	if !errors.Is(err, ErrAgentBindingPersistence) || errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("deadline-racing replacement save = %v, want reload-first binding persistence only", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingActivation == nil || loaded.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0002" {
		t.Fatalf("committed replacement state = %#v / %v", loaded, loadErr)
	}
}

// A resumed registration completes at the placement its candidate is bound to
// without first renewing the lease. Completion carries no lease and the pending
// candidate is 90-day-lived while a lease lasts hours, so requiring a live lease
// here used to strand ordinary resumes. The Hub is unreachable in this fixture:
// if completion still needed a refresh first, this could not succeed.
func TestRegisterAgentRuntime_ResumedCompletionDoesNotRequireLiveLease(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		nil, // no Hub steps at all
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON}},
	)
	state := seedRecoveryRuntimePendingActivation(t, f)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	if err := cfg.transitionPendingActivation(context.Background(), f.store, state); err != nil {
		t.Fatal(err)
	}
	// Expired lease, live recovery horizon: the ordinary delayed-resume shape.
	state.Assignment.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Hour)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, binding, err := RegisterAgentRuntime(context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }))...)
	if binding != nil {
		defer binding.Destroy()
	}
	// The completion itself must have reached the bound cell.
	if len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("resumed completion sent %d cell datagrams, want 1; err=%v", len(f.cellUDP.snapshot()), err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	// Completion committed durably even though the lease was expired and no Hub
	// was reachable. Placement reconciliation is a separate, later step.
	if loaded.PendingCompletion != nil || loaded.RegisteredAt == nil || loaded.DeviceAPIKey != canonicalNativeDeviceCredential {
		t.Fatalf("resumed completion did not commit: %#v", loaded)
	}
}

func TestRegisterAgentRuntime_DeadlineDoesNotMaskFinalPromotionPersistenceAmbiguity(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeListRequest,
		replyType:   relayknock.TypeListResult,
		replyBody:   contract.RegistrationCompletion.Result.BodyJSON,
	}})
	state := seedRecoveryRuntimePendingActivation(t, f)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	if err := cfg.transitionPendingActivation(context.Background(), f.store, state); err != nil {
		t.Fatal(err)
	}
	deadline := assignmentFixtureNow.Add(time.Second)
	now := deadline.Add(-500 * time.Millisecond)
	setTestRecoveryDeadline(state, deadline)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	f.store.waitForContextAfterCommit = 4
	f.store.failAfterCommit = 4

	_, _, err := RegisterAgentRuntime(context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return now }))...)
	if !errors.Is(err, ErrAgentBindingPersistence) || errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("deadline-racing final promotion = %v, want reload-first binding persistence only", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion != nil || loaded.RegisteredAt == nil || loaded.DeviceAPIKey != canonicalNativeDeviceCredential {
		t.Fatalf("committed final state = %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_AuthenticatedCompletionCrossingHorizonIsPromoted(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{
		requestType: relayknock.TypeListRequest,
		replyType:   relayknock.TypeListResult,
		replyBody:   contract.RegistrationCompletion.Result.BodyJSON,
	}})
	state := seedRecoveryRuntimePendingActivation(t, f)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	if err := cfg.transitionPendingActivation(context.Background(), f.store, state); err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCompletion.RecoveryExpiresAt
	state.Assignment.LeaseExpiresAt = deadline.Add(time.Hour)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time {
		if len(f.cellUDP.snapshot()) == 0 {
			return deadline.Add(-time.Second)
		}
		return deadline
	}

	client, binding, err := RegisterAgentRuntime(
		context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(clock))...,
	)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("horizon-crossing authenticated success = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion != nil ||
		loaded.DeviceAPIKey != canonicalNativeDeviceCredential ||
		loaded.DeviceAPIKeyID != "key_DvK9mN2pQr7S" ||
		loaded.RegisteredAt == nil || !loaded.RegisteredAt.Equal(deadline) {
		t.Fatalf("horizon-crossing success was not promoted: state=%#v load=%v", loaded, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("horizon-crossing success network = Hub %d cell %d, want 0/1",
			len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_ExpiredCompletionPreservesStateWithoutUDP(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	recoveryAnchor := state.PendingActivation.RecoveryAnchorTicketExpiresAt
	state.PendingActivation = nil
	state.PendingCompletion = &PendingAgentCompletion{
		DeviceAPIKey:                  canonicalNativeDeviceCredential,
		CellID:                        state.Assignment.CellID,
		AssignmentGeneration:          state.Assignment.AssignmentGeneration,
		RecoveryAnchorTicketExpiresAt: recoveryAnchor,
		RecoveryExpiresAt:             deadline,
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
		DeviceAPIKey:                  canonicalNativeDeviceCredential,
		CellID:                        completion.Assignment.CellID,
		AssignmentGeneration:          completion.Assignment.AssignmentGeneration,
		RecoveryAnchorTicketExpiresAt: activation.PendingActivation.RecoveryAnchorTicketExpiresAt,
		RecoveryExpiresAt:             activation.PendingActivation.RecoveryExpiresAt,
	}
	tests := []struct {
		name       string
		state      *AgentState
		credential string
		mutate     func(*AgentState)
	}{
		{
			name: "activation anchor", state: activation,
			credential: conformance.AgentAssignmentBootstrapCredentialFixture,
			mutate: func(state *AgentState) {
				state.PendingActivation.RecoveryAnchorTicketExpiresAt = state.PendingActivation.RecoveryAnchorTicketExpiresAt.Add(time.Second)
			},
		},
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
				state.PendingCompletion.RecoveryAnchorTicketExpiresAt = state.PendingCompletion.RecoveryAnchorTicketExpiresAt.Add(time.Second)
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
	cfg.clock = func() time.Time { return deadline.Add(time.Nanosecond) }
	if err := cfg.requirePendingRecoveryLive(state); !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("instant after recovery deadline = %v, want ErrAgentRecoveryExpired", err)
	}
	cfg.clock = func() time.Time { return time.Time{} }
	if err := cfg.requirePendingRecoveryLive(state); !errors.Is(err, ErrInvalidRegisterConfig) || errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("zero recovery clock = %v, want invalid config only", err)
	}
}

func TestAgentRecoveryBoundary_LatchesClosedAcrossClockRollback(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	now := deadline.Add(-time.Nanosecond)
	boundary, err := newAgentRecoveryBoundary(state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = deadline
	if err := boundary.check(); !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("deadline check = %v, want ErrAgentRecoveryExpired", err)
	}
	now = deadline.Add(-time.Hour)
	if err := boundary.check(); !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("rolled-back clock reopened recovery fence: %v", err)
	}
}

func TestAgentRecoveryBoundary_MapErrorFailsClosedWhenRealTimeoutPrecedesInjectedClock(t *testing.T) {
	state, _ := recoveryTestPendingActivation(t)
	deadline := state.PendingActivation.RecoveryExpiresAt
	frozenNow := deadline.Add(-20 * time.Millisecond)
	boundary, recoveryCtx, cancel, err := boundedRecovery(
		context.Background(), state, func() time.Time { return frozenNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	select {
	case <-recoveryCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("real recovery timeout did not fire")
	}
	if err := boundary.check(); err != nil {
		t.Fatalf("injected clock crossed unexpectedly: %v", err)
	}
	sentinel := errors.New("injected transport failure")
	mapped := boundary.mapError(context.Background(), recoveryCtx, sentinel)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(mapped, ErrAgentRecoveryExpired) || !errors.As(mapped, &expired) ||
		errors.Is(mapped, sentinel) || expired.Phase != AgentRecoveryPhaseActivation ||
		!expired.RecoveryExpiresAt.Equal(deadline) {
		t.Fatalf("real-timeout map = %T %#v / %v, want fail-closed recovery expiry", mapped, expired, mapped)
	}
}

func TestRegisterAgentRuntime_RecoveryDNSCannotCrossDeadline(t *testing.T) {
	f := newRuntimeFixture(t, nil, nil)
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = deadline.Add(-AgentRegistrationRecoveryHorizon)
	state.PendingActivation.RecoveryExpiresAt = deadline
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	resolver := runtimeResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(time.Now), WithAgentRuntimeUDPResolver(resolver))...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) || expired.Phase != AgentRecoveryPhaseActivation {
		t.Fatalf("DNS deadline = %T %#v / %v", err, expired, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("deadline-crossing DNS sent UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRegisterAgentRuntime_RecoveryBackoffCannotDispatchAtDeadline(t *testing.T) {
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}})
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := state.PendingActivation.RecoveryExpiresAt
	now := deadline.Add(-time.Hour)

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(
			withAgentRuntimeClock(func() time.Time { return now }),
			WithAgentRuntimeAssignmentRetryBudget(2, time.Second),
			withTestAgentRuntimeAssignmentSleep(func(context.Context, time.Duration) error {
				now = deadline
				return nil
			}),
		)...,
	)
	if !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("backoff crossing recovery deadline = %v, want ErrAgentRecoveryExpired", err)
	}
	if got := len(f.cellUDP.snapshot()); got != 1 {
		t.Fatalf("backoff dispatched %d datagrams, want only pre-deadline attempt", got)
	}
}

// The recovery deadline still fences the completion datagram itself. Completion
// is now the first network step of a resume, so this is where the horizon has to
// hold: nothing may be sent at or after it, and the candidate must survive.
func TestRegisterAgentRuntime_PendingCompletionCannotCrossDeadline(t *testing.T) {
	f := newRuntimeFixture(t, nil, nil)
	state := seedRecoveryRuntimePendingActivation(t, f)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	if err := cfg.transitionPendingActivation(context.Background(), f.store, state); err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCompletion.RecoveryExpiresAt
	now := state.Assignment.LeaseExpiresAt.Add(time.Second)
	cellHost := state.Assignment.Endpoint.Host
	resolver := runtimeResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host == cellHost {
			now = deadline
		}
		return f.resolver.LookupNetIP(ctx, network, host)
	})

	_, _, err := RegisterAgentRuntime(
		context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return now }), WithAgentRuntimeUDPResolver(resolver))...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) || expired.Phase != AgentRecoveryPhaseCompletion {
		t.Fatalf("completion boundary = %T %#v / %v", err, expired, err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("deadline-crossing completion sent UDP = %d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCompletion == nil || loaded.PendingCompletion.DeviceAPIKey != canonicalNativeDeviceCredential {
		t.Fatalf("completion boundary did not preserve the candidate: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_ReplacementHubCannotCrossOriginalDeadline(t *testing.T) {
	verdict := `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`
	f := newRuntimeFixture(t, nil, []runtimeUDPStep{
		{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: verdict},
	})
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := state.PendingActivation.RecoveryExpiresAt
	now := deadline.Add(-time.Hour)
	resolver := runtimeResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host == f.hub.Host {
			now = deadline
		}
		return f.resolver.LookupNetIP(ctx, network, host)
	})

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return now }), WithAgentRuntimeUDPResolver(resolver))...,
	)
	if !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("replacement Hub boundary = %v, want ErrAgentRecoveryExpired", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("replacement boundary Hub/cell UDP = %d/%d, want 0/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingActivation == nil || loaded.PendingActivation.AssignmentTicket != state.PendingActivation.AssignmentTicket ||
		!loaded.PendingActivation.RecoveryExpiresAt.Equal(deadline) {
		t.Fatalf("replacement boundary lost old pending state: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_ReplacementBoundarySetupExpiryReturnsWithoutPanic(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest,
			replyType:   relayknock.TypeListResult,
			replyBody:   bootstrapAssignmentResult(contract, "conformance-assignment-ticket-0002"),
		}},
		[]runtimeUDPStep{{
			requestType: relayknock.TypeRegister,
			replyType:   relayknock.TypeRegisterAck,
			replyBody:   `{"errCode":"52111","errMsg":"expired","aspId":"agent"}`,
		}},
	)
	state := seedRecoveryRuntimePendingActivation(t, f)
	deadline := state.PendingActivation.RecoveryExpiresAt
	postReplacementClockCalls := 0
	clock := func() time.Time {
		// The second persisted snapshot is the replacement activation. Step the
		// clock across its deadline between boundary construction and context setup.
		if len(f.store.snapshots()) < 2 {
			return assignmentFixtureNow
		}
		postReplacementClockCalls++
		if postReplacementClockCalls == 1 {
			return deadline.Add(-time.Nanosecond)
		}
		return deadline
	}

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.options(withAgentRuntimeClock(clock))...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) ||
		expired.Phase != AgentRecoveryPhaseActivation || !expired.RecoveryExpiresAt.Equal(deadline) {
		t.Fatalf("replacement boundary setup expiry = %T %#v / %v", err, expired, err)
	}
	if postReplacementClockCalls != 2 {
		t.Fatalf("post-replacement boundary clock samples = %d, want construction then context", postReplacementClockCalls)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("replacement boundary setup Hub/cell calls = %d/%d, want replacement LST and no replacement REG",
			len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingActivation == nil ||
		loaded.PendingActivation.AssignmentTicket != "conformance-assignment-ticket-0002" {
		t.Fatalf("replacement boundary setup lost committed replacement: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_ReplacementOTPCannotCrossOriginalDeadline(t *testing.T) {
	contract := loadAssignmentFixture(t)
	first := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001")
	second := accountAssignmentResult(contract, "conformance-account-assignment-ticket-0002")
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: first},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: second},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: `{"errCode":"52101","errMsg":"expired","aspId":"agent"}`},
		},
	)
	now := assignmentFixtureNow
	cellResolutions := 0
	resolver := runtimeResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host == "cell0.nhp.layerv.ai" {
			cellResolutions++
			if cellResolutions == 3 {
				now = assignmentFixtureNow.Add(maxAssignmentTicketLifetime + AgentRegistrationRecoveryHorizon)
			}
		}
		return f.resolver.LookupNetIP(ctx, network, host)
	})
	codes := []string{"12345678", "87654321"}
	callbacks := 0
	provider := func(context.Context, AgentOTPChallenge) (string, error) {
		code := codes[callbacks]
		callbacks++
		return code, nil
	}

	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			withAgentRuntimeClock(func() time.Time { return now }),
			WithAgentRuntimeUDPResolver(resolver),
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(provider),
		)...,
	)
	if !errors.Is(err, ErrAgentRecoveryExpired) {
		t.Fatalf("replacement OTP boundary = %v, want ErrAgentRecoveryExpired", err)
	}
	if callbacks != 1 || len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 2 {
		t.Fatalf("replacement OTP boundary callbacks/Hub/cell = %d/%d/%d, want 1/2/2", callbacks, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingActivation == nil || loaded.PendingActivation.AssignmentTicket != "conformance-account-assignment-ticket-0001" {
		t.Fatalf("replacement OTP boundary replaced old pending: %#v / %v", loaded, loadErr)
	}
}

func TestRegisterAgentRuntime_PendingAccountOTPProviderCannotOutliveDeadline(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{
			requestType: relayknock.TypeListRequest,
			replyType:   relayknock.TypeListResult,
			replyBody:   accountAssignmentResult(contract, "conformance-account-assignment-ticket-0001"),
		}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeOTP, noReply: true},
			{requestType: relayknock.TypeRegister, noReply: true},
		},
	)
	firstProvider := func(context.Context, AgentOTPChallenge) (string, error) {
		return "12345678", nil
	}
	_, _, err := RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(firstProvider),
		)...,
	)
	if !errors.Is(err, ErrRegistrationRecoveryRequired) {
		t.Fatalf("seed account recovery = %v, want ErrRegistrationRecoveryRequired", err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil || state.PendingActivation == nil {
		t.Fatalf("load pending account activation = %#v / %v", state, err)
	}
	deadline := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = deadline.Add(-AgentRegistrationRecoveryHorizon)
	state.PendingActivation.RecoveryExpiresAt = deadline
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	beforeHub, beforeCell := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())
	blockingProvider := func(ctx context.Context, _ AgentOTPChallenge) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	started := time.Now()
	_, _, err = RegisterAgentRuntime(
		context.Background(), conformance.AgentAssignmentAccountCredentialFixture, f.store,
		f.options(
			withAgentRuntimeClock(time.Now),
			WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindAccount),
			WithAgentRuntimeOTPProvider(blockingProvider),
		)...,
	)
	var expired *AgentRecoveryExpiredError
	if !errors.Is(err, ErrAgentRecoveryExpired) || !errors.As(err, &expired) || expired.Phase != AgentRecoveryPhaseActivation {
		t.Fatalf("blocking pending OTP deadline = %T %#v / %v", err, expired, err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("blocking pending OTP returned after %s, want bounded by recovery deadline", elapsed)
	}
	if gotHub, gotCell := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()); gotHub != beforeHub || gotCell != beforeCell {
		t.Fatalf("expired pending OTP sent Hub/cell UDP = %d/%d, want unchanged %d/%d", gotHub, gotCell, beforeHub, beforeCell)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingActivation == nil || loaded.PendingActivation.AssignmentTicket != state.PendingActivation.AssignmentTicket {
		t.Fatalf("expired pending OTP did not preserve activation: %#v / %v", loaded, loadErr)
	}
}

// The case that used to be a permanent dead end: a registration interrupted
// after RAK, resumed once its lease had expired, while LayerV had relocated the
// agent in between. Completion now lands at the cell that minted the candidate,
// and only then does placement reconcile onto the new cell.
func TestRegisterAgentRuntime_ResumesInterruptedRegistrationAcrossRelocation(t *testing.T) {
	contract := loadAssignmentFixture(t)
	moved := newReassignmentTarget(t, contract, "cell1", 2, "", time.Time{})
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: rewriteRefreshAssignment(t, contract, moved)}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON}},
	)
	state := seedRecoveryRuntimePendingActivation(t, f)
	cfg := defaultNativeAgentRuntimeConfig()
	cfg.deviceCredential = canonicalNativeDeviceCredential
	if err := cfg.transitionPendingActivation(context.Background(), f.store, state); err != nil {
		t.Fatal(err)
	}
	boundCell := state.PendingCompletion.CellID
	state.Assignment.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Hour)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	client, binding, err := RegisterAgentRuntime(context.Background(), "", f.store,
		f.options(withAgentRuntimeClock(func() time.Time { return assignmentFixtureNow }))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("resume across relocation = client %v, binding %v, err %v", client, binding, err)
	}
	defer binding.Destroy()
	if binding.CellID != "cell1" || binding.AssignmentGeneration != 2 {
		t.Fatalf("resumed binding did not land on the new placement: %#v", binding)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	// Registration committed with its original candidate, and placement followed
	// the move: one completion at the bound cell, one Hub renewal.
	if loaded.PendingCompletion != nil || loaded.DeviceAPIKey != canonicalNativeDeviceCredential ||
		!sameAgentAssignment(loaded.Assignment, moved) {
		t.Fatalf("resume across relocation left the wrong state: %#v", loaded)
	}
	if boundCell != "cell0" || len(f.cellUDP.snapshot()) != 1 || len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("expected one completion at the bound cell %q and one Hub renewal, got cell=%d Hub=%d",
			boundCell, len(f.cellUDP.snapshot()), len(f.hubUDP.snapshot()))
	}
}
