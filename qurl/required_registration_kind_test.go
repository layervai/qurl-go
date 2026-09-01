package qurl

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
)

func TestRequiredRegistrationKeyKindPolicyIsExactAndRedacted(t *testing.T) {
	for _, kind := range []RegistrationKeyKind{
		RegistrationKeyKindBootstrap,
		RegistrationKeyKindConnectorBootstrap,
		RegistrationKeyKindAgent,
		RegistrationKeyKindAccount,
	} {
		t.Run(string(kind), func(t *testing.T) {
			cfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
				WithAgentRuntimeHub(runtimeTestHub()),
				WithAgentRuntimeRequiredRegistrationKeyKind(kind),
			})
			if err != nil {
				t.Fatalf("newNativeAgentRuntimeConfig: %v", err)
			}
			if cfg.requiredRegistrationKeyKind != kind {
				t.Fatalf("required kind = %q, want %q", cfg.requiredRegistrationKeyKind, kind)
			}
			if err := cfg.requireAllowedRegistrationKeyKind(string(kind)); err != nil {
				t.Fatalf("exact kind refused: %v", err)
			}

			mismatch := RegistrationKeyKindBootstrap
			if mismatch == kind {
				mismatch = RegistrationKeyKindAccount
			}
			err = cfg.requireAllowedRegistrationKeyKind(string(mismatch))
			var disallowed *RegistrationKeyKindDisallowedError
			if !errors.As(err, &disallowed) || disallowed.Kind != mismatch || len(disallowed.Allowed) != 1 || disallowed.Allowed[0] != kind {
				t.Fatalf("known mismatch = %#v, want exact typed refusal for %q", err, mismatch)
			}

			for _, malformed := range []string{" " + string(kind), string(kind) + " ", "future-private-kind"} {
				err = cfg.requireAllowedRegistrationKeyKind(malformed)
				if !errors.Is(err, ErrAssignmentInvalidResponse) || errors.Is(err, ErrRegistrationKeyKindDisallowed) {
					t.Fatalf("malformed kind = %v, want redacted assignment error", err)
				}
				if strings.Contains(err.Error(), malformed) {
					t.Fatalf("malformed kind leaked in error: %q", err)
				}
			}
		})
	}

	const privateKind = RegistrationKeyKind("future-private-kind")
	_, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeRequiredRegistrationKeyKind(privateKind),
	})
	if !errors.Is(err, ErrInvalidRegisterConfig) || strings.Contains(err.Error(), string(privateKind)) {
		t.Fatalf("invalid required kind = %v, want fixed redacted config error", err)
	}
}

func TestRequiredRegistrationKeyKindPolicyRejectsAmbiguousPolicyComposition(t *testing.T) {
	hub := WithAgentRuntimeHub(runtimeTestHub())
	required := WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap)
	requiredOther := WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindAccount)
	headless := WithAgentRuntimeHeadlessEnrollment()
	allowed := WithAgentRuntimeAllowedRegistrationKeyKinds(RegistrationKeyKindBootstrap)

	for name, opts := range map[string][]AgentRuntimeRegistrationOption{
		"required then headless":           {hub, required, headless},
		"headless then required":           {hub, headless, required},
		"required then allowed":            {hub, required, allowed},
		"allowed then required":            {hub, allowed, required},
		"different required assertions":    {hub, required, requiredOther},
		"different required reverse order": {hub, requiredOther, required},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newNativeAgentRuntimeConfig(opts); !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("config error = %v, want ErrInvalidRegisterConfig", err)
			}
		})
	}

	if _, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{hub, required, required}); err != nil {
		t.Fatalf("duplicate identical required assertion must be idempotent: %v", err)
	}

	_, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
		hub,
		required,
		WithAgentRuntimeOTPProvider(testOTPProvider),
	})
	if !errors.Is(err, ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), "required registration lineage") || strings.Contains(err.Error(), "HeadlessEnrollment declares") {
		t.Fatalf("required-kind OTP contradiction = %v, want assertion-specific guidance", err)
	}
}

func TestRequiredRegistrationKeyKindValidatesEveryPersistedLifecyclePhase(t *testing.T) {
	newConfig := func(t *testing.T, kind RegistrationKeyKind) *nativeAgentRuntimeConfig {
		t.Helper()
		cfg, err := newNativeAgentRuntimeConfig([]AgentRuntimeRegistrationOption{
			WithAgentRuntimeHub(runtimeTestHub()),
			WithAgentRuntimeRequiredRegistrationKeyKind(kind),
		})
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	clean, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	clean.AgentID = "agent-clean"

	pendingActivation := clean.clone()
	pendingActivation.PendingActivation = &PendingAgentActivation{
		Registration: AssignmentRegistration{KeyKind: string(RegistrationKeyKindBootstrap)},
	}

	pendingCompletion := clean.clone()
	pendingCompletion.PendingCompletion = &PendingAgentCompletion{}
	pendingCompletion.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)

	completed := completedNativeTestState(t)
	completed.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)

	recoveryRuntime, recoveryFixture := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	recoveryBase, err := recoveryRuntime.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recoveryBase.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)
	if err := recoveryRuntime.store.inner.SaveAgentState(context.Background(), recoveryBase); err != nil {
		t.Fatal(err)
	}
	pendingRecoveryIssue := recoveryBase.clone()
	pendingRecoveryIssue.PendingCredentialRecoveryIssue = &PendingAgentCredentialRecoveryIssue{
		RequestNonce:                     recoveryFixture.Fixtures.RequestNonce,
		ReplayNotAfter:                   credentialRecoveryFixtureNow.Add(AgentCredentialRecoveryHorizon),
		RecoveryCredentialFingerprintB64: credentialRecoveryCredentialFingerprint(recoveryFixture.Fixtures.RecoveryCredential),
		AgentID:                          pendingRecoveryIssue.AgentID,
		AgentPublicKeyB64:                pendingRecoveryIssue.PublicKeyB64,
		HubHost:                          recoveryRuntime.hub.Host,
		HubPort:                          recoveryRuntime.hub.Port,
		HubServerPublicKeyB64:            recoveryRuntime.hub.ServerPublicKeyB64,
	}
	if err := validateLoadedAgentAssignment(pendingRecoveryIssue); err != nil {
		t.Fatalf("pending recovery issue fixture is not structurally valid: %v", err)
	}
	seedPendingCredentialRecovery(t, recoveryRuntime, recoveryFixture, false)
	pendingRecovery, err := recoveryRuntime.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLoadedAgentAssignment(pendingRecovery); err != nil {
		t.Fatalf("pending recovery fixture is not structurally valid: %v", err)
	}

	recovering := completed.clone()
	recovering.CredentialRecoveryRefreshRequired = true
	if err := validateLoadedAgentAssignment(recovering); err != nil {
		t.Fatalf("post-recovery fixture is not structurally valid: %v", err)
	}

	for _, tc := range []struct {
		name  string
		state *AgentState
	}{
		{name: "clean identity before enrollment", state: clean},
		{name: "pending activation", state: pendingActivation},
		{name: "pending completion", state: pendingCompletion},
		{name: "completed", state: completed},
		{name: "pending credential recovery issue", state: pendingRecoveryIssue},
		{name: "pending credential recovery", state: pendingRecovery},
		{name: "post-recovery refresh", state: recovering},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := newConfig(t, RegistrationKeyKindBootstrap).requirePersistedRegistrationKeyKind(tc.state, ErrInvalidRegisterConfig); err != nil {
				t.Fatalf("required lineage refused: %v", err)
			}
		})
	}

	knownMismatch := completed.clone()
	knownMismatch.EnrollmentCredentialKind = string(RegistrationKeyKindAccount)
	err = newConfig(t, RegistrationKeyKindBootstrap).requirePersistedRegistrationKeyKind(knownMismatch, ErrInvalidRegisterConfig)
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || errors.Is(err, ErrInvalidAgentState) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("known persisted mismatch = %#v, want only typed disallowed error", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*AgentState)
		secret string
	}{
		{name: "completed missing lineage", mutate: func(s *AgentState) { s.EnrollmentCredentialKind = "" }},
		{name: "completed whitespace lineage", secret: " bootstrap", mutate: func(s *AgentState) { s.EnrollmentCredentialKind = " bootstrap" }},
		{name: "completed unknown lineage", secret: "future-private-kind", mutate: func(s *AgentState) { s.EnrollmentCredentialKind = "future-private-kind" }},
		{name: "clean state with stray lineage", mutate: func(s *AgentState) {
			*s = *clean.clone()
			s.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)
		}},
		{name: "activation with promoted lineage", mutate: func(s *AgentState) {
			*s = *pendingActivation.clone()
			s.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)
		}},
		{name: "activation with malformed authority", secret: " bootstrap", mutate: func(s *AgentState) {
			*s = *pendingActivation.clone()
			s.PendingActivation.Registration.KeyKind = " bootstrap"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := completed.clone()
			tc.mutate(state)
			err := newConfig(t, RegistrationKeyKindBootstrap).requirePersistedRegistrationKeyKind(state, ErrInvalidRegisterConfig)
			if !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, ErrInvalidAgentState) || errors.Is(err, ErrRegistrationKeyKindDisallowed) {
				t.Fatalf("invalid persisted lineage = %v, want fixed invalid-state error", err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("persisted lineage leaked in error: %q", err)
			}
		})
	}
}

func TestRequiredRegistrationKeyKindFailsBeforeWarmOpenPrivateKeyWork(t *testing.T) {
	state := completedNativeTestState(t)
	state.EnrollmentCredentialKind = string(RegistrationKeyKindAccount)
	state.PrivateKeyB64 = "private-state-that-must-not-be-decoded"
	store := &memoryAgentStateStore{state: state}

	client, binding, err := ConnectAgentRuntime(context.Background(), store,
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap),
	)
	if client != nil || binding != nil {
		t.Fatalf("mismatched lineage returned runtime: %v/%v", client, binding)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("warm-open error = %v, want lineage mismatch before private-key validation", err)
	}
}

func TestRequiredRegistrationKeyKindRejectsStrayCredentialBeforePrivateKeyWork(t *testing.T) {
	state, err := newAgentState()
	if err != nil {
		t.Fatal(err)
	}
	state.AgentID = "agent-stray-credential"
	state.DeviceAPIKey = canonicalNativeDeviceCredential
	state.PrivateKeyB64 = "private-state-that-must-not-be-decoded"
	store := &memoryAgentStateStore{state: state}

	client, binding, err := ConnectAgentRuntime(context.Background(), store,
		WithAgentRuntimeHub(runtimeTestHub()),
		WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap),
	)
	if client != nil || binding != nil {
		t.Fatalf("stray credential returned runtime: %v/%v", client, binding)
	}
	if !errors.Is(err, ErrInvalidRegisterConfig) || !errors.Is(err, ErrInvalidAgentState) {
		t.Fatalf("stray credential error = %v, want fixed persisted-lineage failure", err)
	}
	for _, forbidden := range []string{"private key", state.PrivateKeyB64, state.DeviceAPIKey} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("stray credential error exposed later validation or private state: %q", err)
		}
	}
}

func TestRequiredRegistrationKeyKindFreshEnrollmentPersistsExactLineage(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)

	client, binding, err := connectWithEnrollment(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.baseOptions(true, WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("exact fresh enrollment = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	persisted, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.EnrollmentCredentialKind != string(RegistrationKeyKindBootstrap) || persisted.RegisteredAt == nil {
		t.Fatalf("persisted exact lineage = %#v", persisted)
	}
}

func TestRequiredRegistrationKeyKindFreshMismatchStopsBeforeActivation(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		nil,
	)

	client, binding, err := connectWithEnrollment(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.baseOptions(true, WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindConnectorBootstrap))...)
	if client != nil || binding != nil {
		t.Fatalf("mismatched fresh lineage returned runtime: %v/%v", client, binding)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindBootstrap {
		t.Fatalf("fresh mismatch = %v, want typed bootstrap refusal", err)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != 1 {
		t.Fatalf("fresh mismatch Hub/cell/saves = %d/%d/%d, want 1/0/1 identity save", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), len(f.store.snapshots()))
	}
	persisted, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if persisted.Assignment != nil || persisted.PendingActivation != nil || persisted.EnrollmentCredentialKind != "" {
		t.Fatalf("fresh mismatch persisted lifecycle progress: %#v", persisted)
	}
}

func TestRequiredRegistrationKeyKindPreV6PendingActivationFailsBeforeMigration(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeRegister, noReply: true}},
	).expectSilence()
	_, _, err := connectWithEnrollment(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrRegistrationRecoveryRequired) {
		t.Fatalf("seed pending activation = %v", err)
	}
	state, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.SchemaVersion = 5
	state.PendingActivation.RecoveryAnchorTicketExpiresAt = time.Time{}
	state.PendingActivation.RecoveryExpiresAt = time.Time{}
	if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	savesBefore := len(f.store.snapshots())
	hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())

	_, _, err = connectWithEnrollment(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store,
		f.baseOptions(true, WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindAccount))...)
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindBootstrap {
		t.Fatalf("pending activation mismatch = %v, want typed bootstrap refusal", err)
	}
	if len(f.store.snapshots()) != savesBefore || len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
		t.Fatalf("pending mismatch mutated state or used network: saves %d/%d, Hub %d/%d, cell %d/%d",
			len(f.store.snapshots()), savesBefore, len(f.hubUDP.snapshot()), hubBefore, len(f.cellUDP.snapshot()), cellBefore)
	}
	unchanged, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.SchemaVersion != 5 || !unchanged.PendingActivation.RecoveryExpiresAt.IsZero() {
		t.Fatalf("lineage mismatch migrated pre-v6 state: %#v", unchanged.PendingActivation)
	}
}

func TestRequiredRegistrationKeyKindPendingCompletionFailsBeforeLST(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, noReply: true},
		},
	).expectSilence()
	_, _, err := connectWithEnrollment(context.Background(), conformance.AgentAssignmentBootstrapCredentialFixture, f.store, f.options()...)
	if !errors.Is(err, ErrCompletionRecoveryRequired) {
		t.Fatalf("seed pending completion = %v", err)
	}
	savesBefore := len(f.store.snapshots())
	hubBefore, cellBefore := len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot())

	_, _, err = ConnectAgentRuntime(context.Background(), f.store,
		f.baseOptions(true, WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindAccount))...)
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindBootstrap {
		t.Fatalf("pending completion mismatch = %v, want typed bootstrap refusal", err)
	}
	if len(f.store.snapshots()) != savesBefore || len(f.hubUDP.snapshot()) != hubBefore || len(f.cellUDP.snapshot()) != cellBefore {
		t.Fatalf("pending completion mismatch performed work: saves %d/%d, Hub %d/%d, cell %d/%d",
			len(f.store.snapshots()), savesBefore, len(f.hubUDP.snapshot()), hubBefore, len(f.cellUDP.snapshot()), cellBefore)
	}
}

func TestRequiredRegistrationKeyKindRefreshFailsBeforePrivateKeyAndNetwork(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)
	state, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.EnrollmentCredentialKind = string(RegistrationKeyKindAccount)
	state.PrivateKeyB64 = "private-state-that-must-not-be-decoded"
	if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	savesBefore := len(f.store.snapshots())

	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))...)
	if client != nil || binding != nil {
		t.Fatalf("mismatched refresh returned runtime: %v/%v", client, binding)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("refresh mismatch = %v, want lineage refusal before private-key validation", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != savesBefore {
		t.Fatalf("refresh mismatch Hub/cell/saves = %d/%d/%d, want 0/0/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), len(f.store.snapshots()), savesBefore)
	}
}

func TestRequiredRegistrationKeyKindRefreshAcceptsExactPersistedLineage(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RefreshAssignment.Result.BodyJSON}},
		nil,
	)
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedRuntimeAssignment(t, f, &initial.Assignment)

	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("exact strict refresh = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	persisted, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.EnrollmentCredentialKind != string(RegistrationKeyKindBootstrap) {
		t.Fatalf("strict refresh changed registration lineage: %q", persisted.EnrollmentCredentialKind)
	}
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("strict refresh Hub/cell = %d/%d, want 1/0", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRequiredRegistrationKeyKindRecoveryFailsBeforeProviderPrivateKeyAndNetwork(t *testing.T) {
	f, fixture := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	state, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.EnrollmentCredentialKind = string(RegistrationKeyKindAccount)
	state.PrivateKeyB64 = "private-state-that-must-not-be-decoded"
	if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	var providerCalls atomic.Int32
	provider := AgentRuntimeRecoveryCredentialProvider(func(context.Context) (string, error) {
		providerCalls.Add(1)
		return fixture.Fixtures.RecoveryCredential, nil
	})
	savesBefore := len(f.store.snapshots())

	client, binding, err := RecoverAgentRuntimeWithCredentialProvider(context.Background(), provider, f.store,
		recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow },
			WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))...)
	if client != nil || binding != nil {
		t.Fatalf("mismatched recovery returned runtime: %v/%v", client, binding)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("recovery mismatch = %v, want lineage refusal before private-key validation", err)
	}
	if providerCalls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != savesBefore {
		t.Fatalf("recovery mismatch provider/Hub/cell/saves = %d/%d/%d/%d, want 0/0/0/%d",
			providerCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), len(f.store.snapshots()), savesBefore)
	}
}

func TestRequiredRegistrationKeyKindRecoveryAcceptsExactPersistedLineage(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	state, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.EnrollmentCredentialKind = string(RegistrationKeyKindBootstrap)
	if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store,
		recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow },
			WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("exact strict recovery = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	persisted, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.EnrollmentCredentialKind != string(RegistrationKeyKindBootstrap) || persisted.PendingCredentialRecovery != nil || persisted.PendingCredentialRecoveryIssue != nil || persisted.CredentialRecoveryRefreshRequired {
		t.Fatalf("strict recovery did not preserve lineage through continuation: %#v", persisted)
	}
	if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("strict recovery Hub/cell = %d/%d, want issue+refresh/cell completion", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRequiredRegistrationKeyKindHeldBindingRenewalRechecksDurableLineage(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t, nil, nil).expectSilence()
	initial, err := parseInitialAssignmentReply([]byte(contract.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	seeded := seedExpiredSessionLease(t, f, &initial.Assignment)
	binding, key := openSessionBinding(t, f, WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap))
	state, err := f.store.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.EnrollmentCredentialKind = string(RegistrationKeyKindAccount)
	state.PrivateKeyB64 = "private-state-that-must-not-be-decoded"
	if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	_, err = binding.liveSessionAssignment(context.Background(), key, time.Now())
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("held renewal mismatch = %v, want durable lineage refusal", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("held renewal mismatch used network: Hub/cell=%d/%d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
	if live := binding.Assignment(); !sameAgentAssignment(&live, seeded) {
		t.Fatalf("held renewal mismatch changed live assignment: %#v", live)
	}
}

func TestRequiredRegistrationKeyKindSerializesConcurrentFreshEnrollment(t *testing.T) {
	contract := loadAssignmentFixture(t)
	f := newRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.InitialAssignment.Result.BodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeRegister, replyType: relayknock.TypeRegisterAck, replyBody: contract.AssignedCellRegistration.Result.BodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: contract.RegistrationCompletion.Result.BodyJSON},
		},
	)
	clearRuntimeFixtureAgentID(t, f)

	providerStarted := make(chan struct{})
	releaseProvider := make(chan struct{})
	var providerCalls atomic.Int32
	provider := func(ctx context.Context, _ AgentEnrollmentCredentialRequest) (string, error) {
		if providerCalls.Add(1) == 1 {
			close(providerStarted)
		}
		select {
		case <-releaseProvider:
			return conformance.AgentAssignmentBootstrapCredentialFixture, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	opts := f.baseOptions(true,
		WithAgentRuntimeRequiredRegistrationKeyKind(RegistrationKeyKindBootstrap),
		WithAgentRuntimeEnrollmentCredentialProvider(provider),
	)
	type connectResult struct {
		client  *Client
		binding *AgentRuntimeBinding
		err     error
	}
	results := make(chan connectResult, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracker := &setupLockAttemptTracker{secondAttempted: make(chan struct{})}
	store := &setupLockAttemptSignalingStore{inner: f.store, tracker: tracker}
	connect := func() {
		client, binding, err := ConnectAgentRuntime(ctx, store, opts...)
		results <- connectResult{client: client, binding: binding, err: err}
	}
	go connect()
	select {
	case <-providerStarted:
	case <-ctx.Done():
		t.Fatal("first strict provider callback did not start")
	}
	loadsWhileLocked := f.store.loads.Load()
	go connect()
	select {
	case <-tracker.secondAttempted:
	case <-ctx.Done():
		t.Fatal("second strict connect did not reach setup-lock acquisition")
	}
	if got := f.store.loads.Load(); got != loadsWhileLocked {
		t.Fatalf("second strict start loaded state while first held setup lock: loads %d -> %d", loadsWhileLocked, got)
	}
	close(releaseProvider)
	for range 2 {
		result := <-results
		if result.err != nil || result.client == nil || result.binding == nil {
			t.Fatalf("concurrent strict connect = client %v, binding %v, err %v", result.client, result.binding, result.err)
		}
		result.binding.Destroy()
	}
	if providerCalls.Load() != 1 || len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 2 {
		t.Fatalf("concurrent strict calls/provider/Hub/cell = %d/%d/%d, want 1/1/2", providerCalls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

type setupLockAttemptSignalingStore struct {
	inner   AgentStateStore
	tracker *setupLockAttemptTracker
}

type setupLockAttemptTracker struct {
	attempts        atomic.Int32
	secondAttempted chan struct{}
}

func (s *setupLockAttemptSignalingStore) LoadAgentState(ctx context.Context) (*AgentState, error) {
	return s.inner.LoadAgentState(ctx)
}

func (s *setupLockAttemptSignalingStore) SaveAgentState(ctx context.Context, state *AgentState) error {
	return s.inner.SaveAgentState(ctx, state)
}

func (s *setupLockAttemptSignalingStore) decoratedAgentStateStore() AgentStateStore {
	return s.inner
}

func (s *setupLockAttemptSignalingStore) withDecoratedAgentStateStore(inner AgentStateStore) AgentStateStore {
	return &setupLockAttemptSignalingStore{inner: inner, tracker: s.tracker}
}

func (s *setupLockAttemptSignalingStore) acquireSetupLock(ctx context.Context) (setupLock, error) {
	if s.tracker.attempts.Add(1) == 2 {
		close(s.tracker.secondAttempted)
	}
	locker, ok := s.inner.(setupLockingAgentStateStore)
	if !ok {
		return nil, errors.New("setup-lock signaling test store lost lock capability")
	}
	return locker.acquireSetupLock(ctx)
}
