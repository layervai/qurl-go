package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/relayknock"
)

var credentialRecoveryFixtureNow = time.Date(2026, 7, 20, 11, 1, 0, 0, time.UTC)

func TestCredentialRecoveryProtocolConstantsMatchConformance(t *testing.T) {
	if credentialRecoveryGrantPrefix != conformance.AgentCredentialRecoveryGrantPrefix ||
		credentialRecoveryMaxGrantBytes != conformance.AgentCredentialRecoveryMaxGrantBytes ||
		credentialRecoveryGrantLifetime != time.Duration(conformance.AgentCredentialRecoveryGrantLifetimeSeconds)*time.Second ||
		AgentCredentialRecoveryHorizon != time.Duration(conformance.AgentCredentialRecoveryHorizonSeconds)*time.Second ||
		nhpcontract.MaxApplicationBodySize != conformance.AgentCredentialRecoveryMaxBodyBytes {
		t.Fatal("credential recovery protocol constants drifted from qurl-conformance v0.9")
	}
}

func TestValidateCredentialRecoveryCredentialExactConformanceShape(t *testing.T) {
	body := base64.RawURLEncoding.EncodeToString([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	for _, prefix := range []string{deviceKeyPrefix, credentialRecoveryTestAPIKeyPrefix} {
		if err := validateCredentialRecoveryCredential(prefix + body); err != nil {
			t.Fatalf("valid %s recovery credential: %v", prefix, err)
		}
	}

	valid := deviceKeyPrefix + body
	allOnesBody := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, deviceKeyRandomLength))
	noncanonical := valid[:len(valid)-1] + "9"
	canonicalBytes, err := base64.RawURLEncoding.DecodeString(valid[len(deviceKeyPrefix):])
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalBytes, err := base64.RawURLEncoding.DecodeString(noncanonical[len(deviceKeyPrefix):])
	if err != nil || !bytes.Equal(noncanonicalBytes, canonicalBytes) {
		t.Fatalf("test setup: noncanonical spelling must decode to the canonical bytes: %x / %x, %v", noncanonicalBytes, canonicalBytes, err)
	}
	for name, credential := range map[string]string{
		"wrong prefix":               "lv_prod_" + body,
		"wrong decoded length":       deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, deviceKeyRandomLength-1)),
		"padding":                    valid + "=",
		"standard alphabet":          deviceKeyPrefix + strings.Replace(allOnesBody, "_", "/", 1),
		"invalid body":               deviceKeyPrefix + "!" + body[1:],
		"noncanonical trailing bits": noncanonical,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCredentialRecoveryCredential(credential); !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("validateCredentialRecoveryCredential(%q) = %v, want ErrInvalidRegisterConfig", credential, err)
			}
		})
	}
}

func loadCredentialRecoveryFixture(t *testing.T) *conformance.AgentCredentialRecoveryFile {
	t.Helper()
	fixture, err := conformance.AgentCredentialRecovery()
	if err != nil {
		t.Fatalf("load credential recovery conformance: %v", err)
	}
	if fixture.Artifact != conformance.AgentCredentialRecoveryArtifactID || fixture.SchemaVersion != 1 {
		t.Fatalf("recovery fixture identity = %q/v%d", fixture.Artifact, fixture.SchemaVersion)
	}
	return fixture
}

func recoveryTestOption(f func(*nativeAgentRuntimeConfig) error) AgentRuntimeRecoveryOption {
	return nativeRuntimeRecoveryOptionFunc(f)
}

func recoveryOptions(t *testing.T, f *runtimeFixture, fixture *conformance.AgentCredentialRecoveryFile, now func() time.Time, extra ...AgentRuntimeRecoveryOption) []AgentRuntimeRecoveryOption {
	t.Helper()
	opts := []AgentRuntimeRecoveryOption{
		WithAgentRuntimeRecoveryHub(f.hub),
		WithAgentRuntimeUDPResolver(f.resolver),
		WithAgentRuntimeUDPDialer(f.dialer),
		WithAgentRuntimeUDPBounds(100*time.Millisecond, 1),
		WithAgentRuntimeAssignmentRetryBudget(1, time.Second),
		withAgentRuntimeClock(now),
		withTestAgentRuntimeAssignmentNonce(fixture.Fixtures.RequestNonce),
		recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
			candidate, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(fixture.Fixtures.DeviceAPIKeyCandidate, deviceKeyPrefix))
			if err != nil {
				return err
			}
			c.random = bytes.NewReader(candidate)
			return nil
		}),
	}
	return append(opts, extra...)
}

func recoveryAssignmentFromFixture(t *testing.T, fixture *conformance.AgentCredentialRecoveryFile) *AgentAssignment {
	t.Helper()
	issue, err := parseCredentialRecoveryIssueReply(
		[]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON),
		fixture.Fixtures.AgentID,
		credentialRecoveryFixtureNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	return issue.Assignment.clone()
}

func newCredentialRecoveryRuntimeFixture(t *testing.T, hubSteps, cellSteps []runtimeUDPStep) (*runtimeFixture, *conformance.AgentCredentialRecoveryFile) {
	t.Helper()
	fixture := loadCredentialRecoveryFixture(t)
	f := newRuntimeFixture(t, hubSteps, cellSteps)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := credentialRecoveryFixtureNow.Add(-24 * time.Hour)
	state.RegisteredAt = &registeredAt
	state.Assignment = recoveryAssignmentFromFixture(t, fixture)
	state.DeviceAPIKey = deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, deviceKeyRandomLength))
	state.DeviceAPIKeyID = "key_OldDvK123456"
	state.SchemaVersion = agentStateSchemaVersion
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	return f, fixture
}

func TestRecoverAgentRuntime_ConformanceGoldenEndToEndAndZeroLifecycleHTTP(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	var httpCalls atomic.Int32
	client, binding, err := RecoverAgentRuntime(
		context.Background(), fixture.Fixtures.RecoveryCredential, f.store,
		recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow },
			WithAgentClientHTTPClient(doerFunc(func(*http.Request) (*http.Response, error) {
				httpCalls.Add(1)
				return nil, errors.New("HTTP is forbidden during credential recovery")
			})),
		)...,
	)
	if err != nil {
		t.Fatalf("RecoverAgentRuntime: %v", err)
	}
	if client == nil || binding == nil {
		t.Fatal("recovery returned nil client or binding")
	}
	defer binding.Destroy()
	if httpCalls.Load() != 0 {
		t.Fatalf("credential recovery made %d HTTP calls", httpCalls.Load())
	}
	hubRequests := f.hubUDP.snapshot()
	cellRequests := f.cellUDP.snapshot()
	if len(hubRequests) != 1 || string(hubRequests[0].body) != fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON {
		t.Fatalf("Hub recovery requests = %#v, want exact conformance body", hubRequests)
	}
	if len(cellRequests) != 1 || string(cellRequests[0].body) != fixture.PublicExchanges["assigned_cell_complete_recovery"].RequestBodyJSON {
		t.Fatalf("cell recovery requests = %#v, want exact conformance body", cellRequests)
	}
	for _, request := range append(hubRequests, cellRequests...) {
		for _, forbidden := range []string{"http://", "https://", "relay_url", "resource_id", "cell_id", "takeover"} {
			if bytes.Contains(request.body, []byte(forbidden)) {
				t.Fatalf("recovery request contains forbidden placement/transport field %q: %s", forbidden, request.body)
			}
		}
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingCredentialRecovery != nil || state.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate || state.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID ||
		state.Assignment.CellID != fixture.Fixtures.CellID || state.Assignment.Endpoint.Host != fixture.Fixtures.NHPHost ||
		binding.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID || binding.NHPUDPEndpoint.Host != fixture.Fixtures.NHPHost {
		t.Fatalf("recovered state/binding drifted: state=%#v binding=%s", state, binding)
	}
}

func TestRecoverAgentRuntime_TestRecoveryCredentialGoldenPath(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	testCredential := credentialRecoveryTestAPIKeyPrefix + strings.TrimPrefix(fixture.Fixtures.RecoveryCredential, deviceKeyPrefix)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	client, binding, err := RecoverAgentRuntime(context.Background(), testCredential, f.store,
		recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("RecoverAgentRuntime with lv_test_ credential = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	hubRequests := f.hubUDP.snapshot()
	wantBody := strings.Replace(fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON,
		fixture.Fixtures.RecoveryCredential, testCredential, 1)
	if len(hubRequests) != 1 || string(hubRequests[0].body) != wantBody {
		t.Fatalf("Hub recovery requests = %#v, want exact lv_test_ body", hubRequests)
	}
}

func TestRecoverAgentRuntime_AuthenticatedCellSuccessCrossingHorizonIsPromoted(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCredentialRecovery.RecoveryExpiresAt
	// Keep assignment liveness independent from the recovery-horizon race this
	// test isolates; the successful result should produce an immediately usable
	// binding after it is promoted.
	state.Assignment.LeaseExpiresAt = deadline.Add(time.Hour)
	state.PendingCredentialRecovery.Assignment.LeaseExpiresAt = deadline.Add(time.Hour)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time {
		if len(f.cellUDP.snapshot()) == 0 {
			return deadline.Add(-time.Second)
		}
		return deadline
	}
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, clock)...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("horizon-crossing authenticated success = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery != nil || loaded.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate ||
		loaded.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID || binding.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID {
		t.Fatalf("horizon-crossing success was not promoted: state=%#v binding=%v load=%v", loaded, binding, loadErr)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("horizon-crossing success network = Hub %d cell %d, want 0/1", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_AuthenticatedCompletionIgnoresCallerCancellationForFinalSave(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCredentialRecovery.RecoveryExpiresAt
	state.Assignment.LeaseExpiresAt = deadline.Add(time.Hour)
	state.PendingCredentialRecovery.Assignment.LeaseExpiresAt = deadline.Add(time.Hour)
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.store.cancelBeforeSave = 4 // completed seed, pending recovery, live-lease adjustment, final promotion
	f.store.cancel = cancel
	clock := func() time.Time {
		if len(f.cellUDP.snapshot()) == 0 {
			return deadline.Add(-time.Second)
		}
		return deadline
	}
	client, binding, err := RecoverAgentRuntime(ctx, "", f.store, recoveryOptions(t, f, fixture, clock)...)
	if err != nil || client == nil || binding == nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("canceled post-auth promotion = %v/%v/%v; context=%v", client, binding, err, ctx.Err())
	}
	defer binding.Destroy()
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery != nil || loaded.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate ||
		loaded.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("canceled post-auth result was not durable: state=%#v load=%v Hub=%d cell=%d", loaded, loadErr, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_DelayedCompletionRefreshesExpiredAssignment(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	now := time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC)
	fresh := recoveryAssignmentFromFixture(t, fixture)
	fresh.LeaseExpiresAt = now.Add(time.Hour)
	refreshBody := rewriteRefreshAssignment(t, loadAssignmentFixture(t), fresh)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: refreshBody}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, func() time.Time { return now })...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("delayed committed completion = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery != nil || loaded.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID ||
		!loaded.Assignment.LeaseExpiresAt.Equal(fresh.LeaseExpiresAt) || !binding.LeaseExpiresAt.Equal(fresh.LeaseExpiresAt) {
		t.Fatalf("post-completion refresh state/binding = %#v/%v/%v", loaded, binding, loadErr)
	}
	if len(f.cellUDP.snapshot()) != 1 || len(f.hubUDP.snapshot()) != 1 {
		t.Fatalf("delayed completion routing = cell %d Hub %d, want 1/1", len(f.cellUDP.snapshot()), len(f.hubUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_DelayedCompletionRefreshFailureIsTypedAndRecoverable(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	now := time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC)
	fresh := recoveryAssignmentFromFixture(t, fixture)
	fresh.LeaseExpiresAt = now.Add(time.Hour)
	refreshBody := rewriteRefreshAssignment(t, loadAssignmentFixture(t), fresh)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, noReply: true},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: refreshBody},
		},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	_, _, err := RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, func() time.Time { return now })...)
	var refreshRequired *CredentialRecoveredAssignmentRefreshRequiredError
	if !errors.As(err, &refreshRequired) || !errors.Is(err, ErrCredentialRecoveredAssignmentRefreshRequired) || !errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("post-recovery refresh failure = %v", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery != nil || loaded.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate || loaded.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID {
		t.Fatalf("credential was not durably promoted before refresh failure: %#v/%v", loaded, loadErr)
	}
	client, binding, err := RefreshAgentRuntime(context.Background(), f.hub, f.store,
		f.refreshOptions(withAgentRuntimeClock(func() time.Time { return now }))...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("explicit RefreshAgentRuntime recovery = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	if len(f.cellUDP.snapshot()) != 1 || len(f.hubUDP.snapshot()) != 2 {
		t.Fatalf("refresh recovery replayed credential completion: cell %d Hub %d", len(f.cellUDP.snapshot()), len(f.hubUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_UnanchoredIssueReplayExpiresWithoutAnotherDatagram(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, noReply: true}}, nil,
	)
	anchor := mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt)
	authorityDeadline, err := credentialRecoveryDeadline(anchor)
	if err != nil {
		t.Fatal(err)
	}
	initialOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, initialOpts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("lost initial Issue reply = %v, want retry required", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecoveryIssue == nil || loaded.PendingCredentialRecovery != nil ||
		!loaded.PendingCredentialRecoveryIssue.ReplayNotAfter.Before(authorityDeadline) || loaded.DeviceAPIKey == "" || loaded.DeviceAPIKeyID == "" {
		t.Fatalf("unanchored Issue intent/cutoff = %#v/%v", loaded, loadErr)
	}
	beforeSaves := len(f.store.snapshots())
	for _, now := range []time.Time{loaded.PendingCredentialRecoveryIssue.ReplayNotAfter, authorityDeadline} {
		opts := recoveryOptions(t, f, fixture, func() time.Time { return now })
		_, _, err = RecoverAgentRuntime(context.Background(), "", f.store, opts...)
		if !errors.Is(err, ErrCredentialRecoveryExpired) || len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 0 || len(f.store.snapshots()) != beforeSaves {
			t.Fatalf("expired unanchored Issue at %s = %v, Hub %d cell %d saves %d/%d", now, err, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), beforeSaves, len(f.store.snapshots()))
		}
	}
}

func TestRecoverAgentRuntime_StaleExactIssueReplayRenewsOnceBeforeCell(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	anchor := mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt)
	for _, test := range []struct {
		name                 string
		now                  time.Time
		freshIssuedAt        string
		freshExpiresAt       string
		freshLeaseExpiresAt  string
		loseCandidateSaveAck bool
	}{
		{
			name: "exact grant boundary", now: anchor,
			freshIssuedAt: "2026-07-20T11:15:00Z", freshExpiresAt: "2026-07-20T11:30:00Z", freshLeaseExpiresAt: "2026-07-20T13:00:00Z",
		},
		{
			name: "after assignment lease", now: time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC),
			freshIssuedAt: "2026-07-20T12:01:00Z", freshExpiresAt: "2026-07-20T12:16:00Z", freshLeaseExpiresAt: "2026-07-20T13:00:00Z",
		},
		{
			name: "stale result save acknowledgement lost", now: time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC),
			freshIssuedAt: "2026-07-20T12:01:00Z", freshExpiresAt: "2026-07-20T12:16:00Z", freshLeaseExpiresAt: "2026-07-20T13:00:00Z",
			loseCandidateSaveAck: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			freshGrant := "qrg1.conformance-recovery-grant-renewed-in-call"
			freshBody := strings.NewReplacer(
				fixture.Fixtures.RecoveryGrant, freshGrant,
				fixture.Fixtures.RecoveryGrantIssuedAt, test.freshIssuedAt,
				fixture.Fixtures.RecoveryGrantExpiresAt, test.freshExpiresAt,
				fixture.Fixtures.LeaseExpiresAt, test.freshLeaseExpiresAt,
			).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: freshBody},
				},
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
			)
			if test.loseCandidateSaveAck {
				// completed-state seed, Issue intent, then the stale candidate/anchor.
				f.store.failAfterCommit = 3
			}
			firstNonce, err := base64.RawURLEncoding.DecodeString(fixture.Fixtures.RequestNonce)
			if err != nil {
				t.Fatal(err)
			}
			secondNonce := bytes.Repeat([]byte{0xa7}, assignmentRequestNonceBytes)
			var nonceDraws atomic.Int32
			opts := recoveryOptions(t, f, fixture, func() time.Time { return test.now }, recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
				c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
					if nonceDraws.Add(1) == 1 {
						return bytes.Clone(firstNonce), nil
					}
					return bytes.Clone(secondNonce), nil
				}))
				return nil
			}))
			client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
			if err != nil || client == nil || binding == nil {
				t.Fatalf("stale Issue renewal = %v/%v/%v", client, binding, err)
			}
			defer binding.Destroy()
			hub := f.hubUDP.snapshot()
			cell := f.cellUDP.snapshot()
			if len(hub) != 2 || bytes.Equal(hub[0].body, hub[1].body) || len(cell) != 1 || nonceDraws.Load() != 2 {
				t.Fatalf("renewal network/nonces = Hub %v cell %v draws %d", hub, cell, nonceDraws.Load())
			}
			var stale *AgentState
			for _, snapshot := range f.store.snapshots() {
				if snapshot.PendingCredentialRecovery != nil && snapshot.PendingCredentialRecovery.NeedsFreshGrant {
					stale = snapshot
					break
				}
			}
			deadline, deadlineErr := credentialRecoveryDeadline(anchor)
			if stale == nil || deadlineErr != nil || !stale.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Equal(anchor) ||
				!stale.PendingCredentialRecovery.RecoveryExpiresAt.Equal(deadline) || stale.PendingCredentialRecovery.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate {
				t.Fatalf("stale replay did not preserve anchor/candidate: %#v/%v", stale, deadlineErr)
			}
			loaded, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil || loaded.PendingCredentialRecovery != nil || loaded.DeviceAPIKeyID != fixture.Fixtures.DeviceAPIKeyID ||
				!loaded.Assignment.LeaseExpiresAt.Equal(mustRecoveryTime(t, test.freshLeaseExpiresAt)) {
				t.Fatalf("renewed completion state = %#v/%v", loaded, loadErr)
			}
		})
	}
}

func TestRecoverAgentRuntime_StaleFreshIssueIsBoundedWithoutCellWrite(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
		}, nil,
	)
	firstNonce, err := base64.RawURLEncoding.DecodeString(fixture.Fixtures.RequestNonce)
	if err != nil {
		t.Fatal(err)
	}
	secondNonce := bytes.Repeat([]byte{0xa8}, assignmentRequestNonceBytes)
	var draws atomic.Int32
	opts := recoveryOptions(t, f, fixture, func() time.Time { return mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt) }, recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
		c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
			if draws.Add(1) == 1 {
				return bytes.Clone(firstNonce), nil
			}
			return bytes.Clone(secondNonce), nil
		}))
		return nil
	}))
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) || len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 0 || draws.Load() != 2 {
		t.Fatalf("bounded stale renewal = %v; Hub=%d cell=%d draws=%d", err, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), draws.Load())
	}
}

func TestRecoverAgentRuntime_MissingAssignmentFailsBeforeMutationOrNetwork(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, pendingIssue := range []bool{false, true} {
		name := "completed state"
		if pendingIssue {
			name = "pending Hub issue"
		}
		t.Run(name, func(t *testing.T) {
			var hubSteps []runtimeUDPStep
			if pendingIssue {
				hubSteps = []runtimeUDPStep{{requestType: relayknock.TypeListRequest, noReply: true}}
			}
			f, _ := newCredentialRecoveryRuntimeFixture(t, hubSteps, nil)
			opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
			if pendingIssue {
				_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
				if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
					t.Fatalf("seed pending Issue = %v", err)
				}
			}
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			state.Assignment = nil
			if err := f.store.inner.SaveAgentState(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			beforeSaves := len(f.store.snapshots())
			beforeHub := len(f.hubUDP.snapshot())
			var resolves atomic.Int32
			noResolve := runtimeResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				resolves.Add(1)
				return nil, errors.New("resolver must not run")
			})
			_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store,
				recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow }, WithAgentRuntimeUDPResolver(noResolve))...)
			if !errors.Is(err, ErrInvalidRegisterConfig) || resolves.Load() != 0 || len(f.store.snapshots()) != beforeSaves ||
				len(f.hubUDP.snapshot()) != beforeHub || len(f.cellUDP.snapshot()) != 0 {
				t.Fatalf("missing assignment = %v; resolves=%d saves=%d/%d Hub=%d/%d cell=%d", err, resolves.Load(), beforeSaves, len(f.store.snapshots()), beforeHub, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRecoverAgentRuntime_InitialIssueEnforcesAssignmentContinuityBeforeCell(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, test := range []struct {
		name        string
		mutateState func(*AgentAssignment, *runtimeFixture)
		hubBody     func(string) string
		wantReject  bool
	}{
		{name: "generation rollback", mutateState: func(a *AgentAssignment, _ *runtimeFixture) { a.AssignmentGeneration++ }, wantReject: true},
		{name: "same-generation cell drift", mutateState: func(a *AgentAssignment, _ *runtimeFixture) { a.CellID = "cell1" }, wantReject: true},
		{name: "same-generation key drift", mutateState: func(a *AgentAssignment, f *runtimeFixture) { a.Endpoint.ServerPublicKeyB64 = f.hub.ServerPublicKeyB64 }, wantReject: true},
		{name: "revision rollback", mutateState: func(a *AgentAssignment, _ *runtimeFixture) { a.EndpointRevision++ }, wantReject: true},
		{name: "generation advance", hubBody: func(body string) string {
			return strings.Replace(body, `"assignment_generation":1`, `"assignment_generation":2`, 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hubBody := fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON
			if test.hubBody != nil {
				hubBody = test.hubBody(hubBody)
			}
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: hubBody}},
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
			)
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if test.mutateState != nil {
				test.mutateState(state.Assignment, f)
				if err := f.store.SaveAgentState(context.Background(), state); err != nil {
					t.Fatal(err)
				}
			}
			client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store,
				recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })...)
			if test.wantReject {
				if client != nil || binding != nil || !errors.Is(err, ErrCredentialRecoveryInvalidResponse) || len(f.cellUDP.snapshot()) != 0 {
					t.Fatalf("initial continuity rejection = %v/%v/%v, cell writes %d", client, binding, err, len(f.cellUDP.snapshot()))
				}
				return
			}
			if err != nil || client == nil || binding == nil {
				t.Fatalf("initial generation advance = %v/%v/%v", client, binding, err)
			}
			defer binding.Destroy()
			loaded, loadErr := f.store.LoadAgentState(context.Background())
			if loadErr != nil || loaded.Assignment.AssignmentGeneration != 2 || len(f.cellUDP.snapshot()) != 1 {
				t.Fatalf("initial generation advance state/network = %#v/%v cell=%d", loaded, loadErr, len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestCredentialRecoveryOwnedEncodersGoldenAndExactCapacity(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	hub, err := marshalCredentialRecoveryIssueRequest(fixture.Fixtures.AgentID, fixture.Fixtures.RequestNonce, fixture.Fixtures.RecoveryCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(hub)
	cell, err := marshalCredentialRecoveryCompletionRequest(fixture.Fixtures.AgentID, fixture.Fixtures.RecoveryGrant, fixture.Fixtures.DeviceAPIKeyCandidate)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(cell)
	if string(hub) != fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON || len(hub) != cap(hub) ||
		string(cell) != fixture.PublicExchanges["assigned_cell_complete_recovery"].RequestBodyJSON || len(cell) != cap(cell) {
		t.Fatalf("owned encoder drift: Hub %d/%d cell %d/%d", len(hub), cap(hub), len(cell), cap(cell))
	}
	maximumHub, err := marshalCredentialRecoveryIssueRequest(strings.Repeat("a", 64), fixture.Fixtures.RequestNonce, fixture.Fixtures.RecoveryCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(maximumHub)
	maxGrant := credentialRecoveryGrantPrefix + strings.Repeat("A", credentialRecoveryMaxGrantBytes-len(credentialRecoveryGrantPrefix))
	maximum, err := marshalCredentialRecoveryCompletionRequest(strings.Repeat("a", 64), maxGrant, fixture.Fixtures.DeviceAPIKeyCandidate)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(maximum)
	if len(maximumHub) != cap(maximumHub) || len(maximumHub) > conformance.AgentCredentialRecoveryMaxBodyBytes ||
		len(maximum) != cap(maximum) || len(maximum) > conformance.AgentCredentialRecoveryMaxBodyBytes {
		t.Fatalf("maximum owned bodies: Hub %d/%d cell %d/%d, protocol max %d", len(maximumHub), cap(maximumHub), len(maximum), cap(maximum), conformance.AgentCredentialRecoveryMaxBodyBytes)
	}
}

func TestRecoverAgentRuntime_HubAssignmentReplacesOldCellWithoutFallback(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	advancedHubResult := strings.Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON,
		`"assignment_generation":1`, `"assignment_generation":10`, 1)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: advancedHubResult}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, noReply: true},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
		},
	)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old := state.Assignment.clone()
	old.CellID = "cell9"
	old.AssignmentGeneration = 9
	old.EndpointRevision = 3
	old.Endpoint.Host = "cell9.nhp.layerv.ai"
	old.Endpoint.ServerPublicKeyB64 = f.hub.ServerPublicKeyB64
	state.Assignment = old
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	var (
		hostsMu sync.Mutex
		hosts   []string
	)
	recorder := runtimeResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		hostsMu.Lock()
		hosts = append(hosts, host)
		hostsMu.Unlock()
		return f.resolver.LookupNetIP(ctx, network, host)
	})
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow }, WithAgentRuntimeUDPResolver(recorder))
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("assigned cell ambiguity = %v", err)
	}
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("assigned cell resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	hostsMu.Lock()
	gotHosts := append([]string(nil), hosts...)
	hostsMu.Unlock()
	for _, host := range gotHosts {
		if host == old.Endpoint.Host {
			t.Fatalf("recovery resolved the old cell: hosts=%v", gotHosts)
		}
	}
	if strings.Join(gotHosts, ",") != "hub.nhp.layerv.ai,hub.nhp.layerv.ai,cell0.nhp.layerv.ai,cell0.nhp.layerv.ai" ||
		binding.CellID != fixture.Fixtures.CellID || binding.NHPUDPEndpoint.ServerPublicKeyB64 != fixture.Fixtures.ServerPublicKeyB64 {
		t.Fatalf("Hub-authoritative placement = hosts %v binding %#v", gotHosts, binding)
	}
}

func TestCredentialRecoveryResultRejectsUseRealParsers(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	executed := make(map[string]struct{}, len(fixture.ResultRejects))
	for _, testCase := range fixture.ResultRejects {
		t.Run(testCase.Name, func(t *testing.T) {
			var err error
			switch testCase.Phase {
			case conformance.AgentCredentialRecoveryHubPhase:
				_, err = parseCredentialRecoveryIssueReply([]byte(testCase.BodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
			case conformance.AgentCredentialRecoveryCellPhase:
				_, err = parseCredentialRecoveryCompletionReply([]byte(testCase.BodyJSON))
			default:
				t.Fatalf("unknown recovery phase %q", testCase.Phase)
			}
			if !errors.Is(err, ErrCredentialRecoveryInvalidResponse) {
				t.Fatalf("reject %q = %v, want ErrCredentialRecoveryInvalidResponse", testCase.Name, err)
			}
			for _, secret := range []string{fixture.Fixtures.RecoveryCredential, fixture.Fixtures.RecoveryGrant, fixture.Fixtures.DeviceAPIKeyCandidate} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("reject error leaked recovery secret: %v", err)
				}
			}
		})
		executed[testCase.Name] = struct{}{}
	}
	if len(executed) != len(fixture.ResultRejects) || len(executed) != 9 {
		t.Fatalf("executed recovery result rejects = %d/%d, want frozen 9", len(executed), len(fixture.ResultRejects))
	}
}

func TestCredentialRecoveryRequestRejectsUseRuntimeValidators(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	executed := make(map[string]struct{}, len(fixture.RequestRejects))
	for _, testCase := range fixture.RequestRejects {
		t.Run(testCase.Name, func(t *testing.T) {
			var err error
			switch testCase.Phase {
			case conformance.AgentCredentialRecoveryHubPhase:
				err = validateCredentialRecoveryIssueRequest([]byte(testCase.BodyJSON))
			case conformance.AgentCredentialRecoveryCellPhase:
				err = validateCredentialRecoveryCompletionRequest([]byte(testCase.BodyJSON))
			default:
				t.Fatalf("unknown recovery phase %q", testCase.Phase)
			}
			if !errors.Is(err, ErrInvalidRegisterConfig) {
				t.Fatalf("request reject %q = %v, want ErrInvalidRegisterConfig", testCase.Name, err)
			}
			for _, secret := range []string{fixture.Fixtures.RecoveryCredential, fixture.Fixtures.RecoveryGrant, fixture.Fixtures.DeviceAPIKeyCandidate} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("request reject leaked recovery secret: %v", err)
				}
			}
		})
		executed[testCase.Name] = struct{}{}
	}
	if len(executed) != len(fixture.RequestRejects) || len(executed) != 16 {
		t.Fatalf("executed recovery request rejects = %d/%d, want frozen 16", len(executed), len(fixture.RequestRejects))
	}
}

func TestCredentialRecoveryClosedErrorTaxonomy(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	want := map[string]error{
		"hub_unavailable":              ErrCredentialRecoveryUnavailable,
		"recovery_credential_rejected": ErrRecoveryCredentialRejected,
		"hub_identity_rejected":        ErrCredentialRecoveryIdentityRejected,
		"revoke_required":              ErrCredentialRecoveryRevokeRequired,
		"hub_rate_limited":             ErrCredentialRecoveryRateLimited,
		"invalid_hub_request":          ErrCredentialRecoveryRequestRejected,
		"assignment_recovery_required": ErrCredentialRecoveryAssignmentRequired,
		"cell_unavailable":             ErrCredentialReplacementUnavailable,
		"grant_rejected":               ErrCredentialRecoveryGrantRejected,
		"cell_identity_rejected":       ErrCredentialRecoveryIdentityRejected,
		"candidate_conflict":           ErrCredentialRecoveryCandidateConflict,
		"invalid_cell_request":         ErrCredentialRecoveryRequestRejected,
	}
	executed := make(map[string]struct{}, len(fixture.ErrorCases))
	for _, testCase := range fixture.ErrorCases {
		t.Run(testCase.Name, func(t *testing.T) {
			phase := credentialRecoveryPhase(testCase.Phase)
			_, err := parseCredentialRecoveryEnvelope([]byte(testCase.BodyJSON), phase)
			if !errors.Is(err, want[testCase.Name]) {
				t.Fatalf("%s = %v, want %v", testCase.Name, err, want[testCase.Name])
			}
			var classified *CredentialRecoveryError
			if !errors.As(err, &classified) || classified.Code != testCase.ErrCode || classified.Phase != testCase.Phase ||
				classified.RetryAfter != time.Duration(testCase.RetryAfterSeconds)*time.Second {
				t.Fatalf("%s classification = %#v", testCase.Name, classified)
			}
			_, retryable := credentialRecoveryRetryInfo(err)
			if retryable != (testCase.RetryAfterSeconds > 0) {
				t.Fatalf("%s retryable = %t, outcome %q", testCase.Name, retryable, testCase.Outcome)
			}
		})
		executed[testCase.Name] = struct{}{}
	}
	if len(executed) != len(want) || len(fixture.ErrorCases) != len(want) {
		t.Fatalf("executed recovery errors = %d/%d", len(executed), len(fixture.ErrorCases))
	}
}

func TestRecoverAgentRuntime_TransportAmbiguityResumesCellWithoutHubOrCandidateRotation(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, noReply: true},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
		},
	)
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("ambiguous completion = %v, want retry required", err)
	}
	state, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.PendingCredentialRecovery == nil || state.PendingCredentialRecovery.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate || state.PendingCredentialRecovery.NeedsFreshGrant {
		t.Fatalf("ambiguous completion did not preserve exact pending candidate/grant: %#v", state.PendingCredentialRecovery)
	}
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("exact pending resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	if len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 2 ||
		!bytes.Equal(f.cellUDP.snapshot()[0].body, f.cellUDP.snapshot()[1].body) {
		t.Fatalf("resume Hub/cell/body = %d/%d/%v", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()), f.cellUDP.snapshot())
	}
}

func TestRecoverAgentRuntime_LostHubReplyReusesDurableNonceAndExactBody(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, noReply: true},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
		},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	var nonceDraws atomic.Int32
	nonceBytes, err := base64.RawURLEncoding.DecodeString(fixture.Fixtures.RequestNonce)
	if err != nil {
		t.Fatal(err)
	}
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow },
		recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
			c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
				nonceDraws.Add(1)
				return bytes.Clone(nonceBytes), nil
			}))
			return nil
		}),
	)
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("lost Hub reply = %v, want retry required", err)
	}
	pending, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending.PendingCredentialRecoveryIssue == nil || pending.PendingCredentialRecovery != nil {
		t.Fatalf("lost Hub reply state = %#v", pending)
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(fixture.Fixtures.RecoveryCredential)) {
		t.Fatal("persisted Hub issue intent contains the raw recovery credential")
	}
	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("Hub reply resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	hub := f.hubUDP.snapshot()
	if len(hub) != 2 || !bytes.Equal(hub[0].body, hub[1].body) || string(hub[0].body) != fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON || nonceDraws.Load() != 1 {
		t.Fatalf("Hub replay body/draws = %v/%d", hub, nonceDraws.Load())
	}
}

func TestRecoverAgentRuntime_IssueResponsePersistenceFailureReplaysSameLogicalOperation(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
		},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	candidate, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(fixture.Fixtures.DeviceAPIKeyCandidate, deviceKeyPrefix))
	if err != nil {
		t.Fatal(err)
	}
	f.store.fail = 3 // completed seed, Hub intent, then first authenticated Issue result
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow },
		recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
			c.random = bytes.NewReader(append(bytes.Clone(candidate), candidate...))
			return nil
		}),
	)
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	var persistence *CredentialRecoveryCandidatePersistenceError
	if !errors.As(err, &persistence) || !errors.Is(err, ErrCredentialRecoveryCandidatePersistence) || !errors.Is(err, ErrAgentBindingPersistence) || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("Issue result save failure = %v, cell writes %d", err, len(f.cellUDP.snapshot()))
	}
	f.store.fail = 0
	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("Issue result save resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	hub := f.hubUDP.snapshot()
	if len(hub) != 2 || !bytes.Equal(hub[0].body, hub[1].body) {
		t.Fatalf("Issue result save replay changed logical operation: %v", hub)
	}
	var persistedPending *AgentState
	for _, snapshot := range f.store.snapshots() {
		if snapshot.PendingCredentialRecovery != nil {
			persistedPending = snapshot
		}
	}
	if persistedPending == nil || !persistedPending.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Equal(mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt)) ||
		persistedPending.DeviceAPIKey != "" || persistedPending.DeviceAPIKeyID != "" || persistedPending.PendingCredentialRecoveryIssue != nil {
		t.Fatalf("persisted recovery anchor/old-credential clearing = %#v", persistedPending)
	}
}

func TestRecoverAgentRuntime_PendingHubIssueRejectsChangedCredentialWithoutIO(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, noReply: true}}, nil,
	)
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("initial lost Hub reply = %v", err)
	}
	other := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6a}, deviceKeyRandomLength))
	before := len(f.hubUDP.snapshot())
	_, _, err = RecoverAgentRuntime(context.Background(), other, f.store, opts...)
	if !errors.Is(err, ErrInvalidRegisterConfig) || len(f.hubUDP.snapshot()) != before {
		t.Fatalf("changed pending recovery credential = %v, Hub writes %d/%d", err, before, len(f.hubUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_PendingHubIssuePinsTrustRoot(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, mutation := range []struct {
		name string
		edit func(*HubBootstrap)
	}{
		{name: "host", edit: func(h *HubBootstrap) { h.Host = "hub2.nhp.layerv.ai" }},
		{name: "port", edit: func(h *HubBootstrap) { h.Port++ }},
		{name: "server key", edit: func(h *HubBootstrap) {
			h.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7b}, 32))
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, noReply: true}}, nil,
			)
			opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
			_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
			if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
				t.Fatalf("initial lost Hub reply = %v", err)
			}
			changed := f.hub
			mutation.edit(&changed)
			changedOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow }, WithAgentRuntimeRecoveryHub(changed))
			before := len(f.hubUDP.snapshot())
			_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, changedOpts...)
			if !errors.Is(err, ErrInvalidRegisterConfig) || len(f.hubUDP.snapshot()) != before {
				t.Fatalf("Hub %s drift = %v, writes %d/%d", mutation.name, err, before, len(f.hubUDP.snapshot()))
			}
		})
	}
}

func TestRecoverAgentRuntime_TerminalHubDenialClearsIntentForCorrectedAttempt(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, test := range []struct {
		name             string
		denial           string
		want             error
		secondCredential string
	}{
		{name: "revoke required", denial: `{"errCode":"52403","errMsg":"revoke current device credential before recovery"}`, want: ErrCredentialRecoveryRevokeRequired, secondCredential: fixture.Fixtures.RecoveryCredential},
		{name: "credential rejected", denial: `{"errCode":"52401","errMsg":"recovery credential rejected"}`, want: ErrRecoveryCredentialRejected, secondCredential: deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, deviceKeyRandomLength))},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: test.denial},
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
				},
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
			)
			var draws atomic.Int32
			nonceA, _ := base64.RawURLEncoding.DecodeString(fixture.Fixtures.RequestNonce)
			nonceB := bytes.Repeat([]byte{0x99}, assignmentRequestNonceBytes)
			opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow }, recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
				c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
					if draws.Add(1) == 1 {
						return bytes.Clone(nonceA), nil
					}
					return bytes.Clone(nonceB), nil
				}))
				return nil
			}))
			_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
			if !errors.Is(err, test.want) {
				t.Fatalf("terminal Hub denial = %v, want %v", err, test.want)
			}
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil || state.PendingCredentialRecoveryIssue != nil {
				t.Fatalf("terminal Hub denial retained intent: %#v/%v", state, err)
			}
			client, binding, err := RecoverAgentRuntime(context.Background(), test.secondCredential, f.store, opts...)
			if err != nil || client == nil || binding == nil {
				t.Fatalf("corrected recovery = %v/%v/%v", client, binding, err)
			}
			defer binding.Destroy()
			hub := f.hubUDP.snapshot()
			if len(hub) != 2 || bytes.Equal(hub[0].body, hub[1].body) || draws.Load() != 2 {
				t.Fatalf("corrected attempt did not use a new Hub logical operation: %v/%d", hub, draws.Load())
			}
		})
	}
}

func TestRecoverAgentRuntime_TerminalHubIntentClearFailureReplaysExactDenial(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	denial := `{"errCode":"52401","errMsg":"recovery credential rejected"}`
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: denial},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: denial},
		}, nil,
	)
	f.store.fail = 3 // seed, issue intent, then terminal-intent clear
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrRecoveryCredentialRejected) || !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("terminal clear failure = %v", err)
	}
	other := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6c}, deviceKeyRandomLength))
	before := len(f.hubUDP.snapshot())
	_, _, changedErr := RecoverAgentRuntime(context.Background(), other, f.store, opts...)
	if !errors.Is(changedErr, ErrInvalidRegisterConfig) || len(f.hubUDP.snapshot()) != before {
		t.Fatalf("changed credential after ambiguous clear = %v, writes %d/%d", changedErr, before, len(f.hubUDP.snapshot()))
	}
	f.store.fail = 0
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrRecoveryCredentialRejected) {
		t.Fatalf("exact terminal replay = %v", err)
	}
	hub := f.hubUDP.snapshot()
	state, loadErr := f.store.LoadAgentState(context.Background())
	if len(hub) != 2 || !bytes.Equal(hub[0].body, hub[1].body) || loadErr != nil || state.PendingCredentialRecoveryIssue != nil {
		t.Fatalf("terminal replay/clear = Hub %v state %#v load %v", hub, state, loadErr)
	}
}

func TestRecoverAgentRuntime_FinalPersistenceFailureReplaysCellOnly(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
		},
	)
	f.store.fail = 4 // seed, Hub intent, pending candidate, then final promotion
	opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("final promotion save = %v", err)
	}
	f.store.fail = 0
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("final promotion resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	cell := f.cellUDP.snapshot()
	if len(f.hubUDP.snapshot()) != 1 || len(cell) != 2 || !bytes.Equal(cell[0].body, cell[1].body) {
		t.Fatalf("final save retry reminted network operation: Hub=%d cell=%v", len(f.hubUDP.snapshot()), cell)
	}
}

func TestRecoverAgentRuntime_PostCommitSaveErrorsReconcileWithoutExtraNetwork(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, test := range []struct {
		name string
		call int
	}{
		{name: "Hub intent", call: 2},
		{name: "pending candidate", call: 3},
		{name: "final promotion", call: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
				[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
			)
			f.store.failAfterCommit = test.call
			client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })...)
			if err != nil || client == nil || binding == nil {
				t.Fatalf("post-commit %s = %v/%v/%v", test.name, client, binding, err)
			}
			defer binding.Destroy()
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil || state.PendingCredentialRecoveryIssue != nil || state.PendingCredentialRecovery != nil || state.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate ||
				len(f.hubUDP.snapshot()) != 1 || len(f.cellUDP.snapshot()) != 1 {
				t.Fatalf("post-commit %s state/network = %#v/%v Hub=%d cell=%d", test.name, state, err, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func mustRecoveryTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestRecoverAgentRuntime_AuthenticatedGrantRejectRequiresExplicitRenewalAndPreservesAnchor(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	grantRejected := `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`
	renewedGrant := "qrg1.conformance-recovery-grant-0002"
	renewedIssued := "2026-07-20T11:10:00Z"
	renewedExpires := "2026-07-20T11:25:00Z"
	renewedHubResult := strings.NewReplacer(
		fixture.Fixtures.RecoveryGrant, renewedGrant,
		fixture.Fixtures.RecoveryGrantIssuedAt, renewedIssued,
		fixture.Fixtures.RecoveryGrantExpiresAt, renewedExpires,
	).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)
	renewedCellResult := fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedHubResult},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: grantRejected},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedCellResult},
		},
	)
	firstOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, firstOpts...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("grant reject = %v", err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	anchor := state.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt
	deadline := state.PendingCredentialRecovery.RecoveryExpiresAt
	if !state.PendingCredentialRecovery.NeedsFreshGrant {
		t.Fatal("authenticated grant reject did not persist explicit renewal state")
	}
	secondNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, assignmentRequestNonceBytes))
	secondOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow.Add(time.Minute) },
		recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
			nonce, err := base64.RawURLEncoding.DecodeString(secondNonce)
			if err != nil {
				return err
			}
			c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) { return bytes.Clone(nonce), nil }))
			return nil
		}),
	)
	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, secondOpts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("renewed recovery = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	state, err = f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingCredentialRecovery != nil {
		t.Fatalf("completed renewed recovery retained pending state: %#v", state.PendingCredentialRecovery)
	}
	snapshots := f.store.snapshots()
	var renewal *AgentState
	for _, snapshot := range snapshots {
		if snapshot.PendingCredentialRecovery != nil && snapshot.PendingCredentialRecovery.RecoveryGrant == renewedGrant {
			renewal = snapshot
		}
	}
	if renewal == nil || !renewal.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Equal(anchor) ||
		!renewal.PendingCredentialRecovery.RecoveryExpiresAt.Equal(deadline) ||
		renewal.PendingCredentialRecovery.DeviceAPIKey != fixture.Fixtures.DeviceAPIKeyCandidate {
		t.Fatalf("renewal moved anchor/deadline/candidate: %#v", renewal)
	}
}

func TestRecoverAgentRuntime_RenewalResponsePersistenceFailureReusesNonceAndAnchor(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	grantRejected := `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`
	renewedGrant := "qrg1.conformance-recovery-grant-renewed"
	renewedHubResult := strings.NewReplacer(
		fixture.Fixtures.RecoveryGrant, renewedGrant,
		fixture.Fixtures.RecoveryGrantIssuedAt, "2026-07-20T11:10:00Z",
		fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:25:00Z",
	).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedHubResult},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedHubResult},
		},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: grantRejected},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
		},
	)
	initialOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, initialOpts...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("initial grant reject = %v", err)
	}
	rejected, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	anchor := rejected.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt
	deadline := rejected.PendingCredentialRecovery.RecoveryExpiresAt
	var renewalNonceDraws atomic.Int32
	renewalNonce := bytes.Repeat([]byte{0x99}, assignmentRequestNonceBytes)
	renewalOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow.Add(time.Minute) },
		recoveryTestOption(func(c *nativeAgentRuntimeConfig) error {
			c.assignmentOptions = append(c.assignmentOptions, withAssignmentNonceSource(func() ([]byte, error) {
				renewalNonceDraws.Add(1)
				return bytes.Clone(renewalNonce), nil
			}))
			return nil
		}),
	)
	f.store.fail = 6 // seed, issue intent, candidate, reject marker, renewal intent, renewed result
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, renewalOpts...)
	if !errors.Is(err, ErrAgentBindingPersistence) {
		t.Fatalf("renewed result save = %v", err)
	}
	f.store.fail = 0
	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, renewalOpts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("renewal save resume = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	hub := f.hubUDP.snapshot()
	if len(hub) != 3 || !bytes.Equal(hub[1].body, hub[2].body) || renewalNonceDraws.Load() != 1 {
		t.Fatalf("renewal replay body/draws = %v/%d", hub, renewalNonceDraws.Load())
	}
	var renewed *AgentState
	for _, snapshot := range f.store.snapshots() {
		if snapshot.PendingCredentialRecovery != nil && snapshot.PendingCredentialRecovery.RecoveryGrant == renewedGrant {
			renewed = snapshot
		}
	}
	if renewed == nil || !renewed.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Equal(anchor) ||
		!renewed.PendingCredentialRecovery.RecoveryExpiresAt.Equal(deadline) || renewed.PendingCredentialRecoveryIssue != nil {
		t.Fatalf("renewal moved the immutable episode anchor: %#v", renewed)
	}
}

func TestRecoverAgentRuntime_PostCommitRenewalTransitionsReconcileInCall(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	renewedHubResult := strings.NewReplacer(
		fixture.Fixtures.RecoveryGrant, "qrg1.conformance-recovery-grant-postcommit",
		fixture.Fixtures.RecoveryGrantIssuedAt, "2026-07-20T11:10:00Z",
		fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:25:00Z",
	).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)
	for _, test := range []struct {
		name string
		call int
	}{
		{name: "renewal intent", call: 5},
		{name: "renewed grant", call: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := newCredentialRecoveryRuntimeFixture(t,
				[]runtimeUDPStep{
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON},
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedHubResult},
				},
				[]runtimeUDPStep{
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`},
					{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
				},
			)
			opts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
			_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
			if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
				t.Fatalf("initial grant rejection = %v", err)
			}
			f.store.failAfterCommit = test.call
			client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
			if err != nil || client == nil || binding == nil {
				t.Fatalf("post-commit %s = %v/%v/%v", test.name, client, binding, err)
			}
			defer binding.Destroy()
			if len(f.hubUDP.snapshot()) != 2 || len(f.cellUDP.snapshot()) != 2 {
				t.Fatalf("post-commit %s repeated network: Hub=%d cell=%d", test.name, len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
			}
		})
	}
}

func TestRecoverAgentRuntime_RenewalClockStepFencesHubWrite(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	grantRejected := `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON}},
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: grantRejected}},
	)
	initialOpts := recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })
	_, _, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, initialOpts...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("initial grant reject = %v", err)
	}
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCredentialRecovery.RecoveryExpiresAt
	var nowNanos atomic.Int64
	nowNanos.Store(deadline.Add(-time.Second).UnixNano())
	var resolverCalls atomic.Int32
	steppingResolver := runtimeResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		resolverCalls.Add(1)
		nowNanos.Store(deadline.UnixNano())
		return f.resolver.LookupNetIP(ctx, network, host)
	})
	beforeHub := len(f.hubUDP.snapshot())
	beforeCell := len(f.cellUDP.snapshot())
	renewalOpts := recoveryOptions(t, f, fixture, func() time.Time { return time.Unix(0, nowNanos.Load()).UTC() }, WithAgentRuntimeUDPResolver(steppingResolver))
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, renewalOpts...)
	if !errors.Is(err, ErrCredentialRecoveryExpired) {
		t.Fatalf("clock-step renewal = %v, want expired", err)
	}
	if resolverCalls.Load() == 0 || len(f.hubUDP.snapshot()) != beforeHub || len(f.cellUDP.snapshot()) != beforeCell {
		t.Fatalf("clock-step wrote after boundary: resolver=%d Hub=%d/%d cell=%d/%d", resolverCalls.Load(), beforeHub, len(f.hubUDP.snapshot()), beforeCell, len(f.cellUDP.snapshot()))
	}
}

func TestCredentialRecoveryBoundaryPreservesAuthenticatedClassification(t *testing.T) {
	deadline := credentialRecoveryFixtureNow.Add(time.Hour)
	boundary := &credentialRecoveryBoundary{deadline: deadline, clock: func() time.Time { return deadline }}
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	bounded, cancelBounded := context.WithCancel(context.Background())
	cancelBounded()
	classified := &CredentialRecoveryError{Code: credentialRecoveryGrantRejectCode, Phase: string(credentialRecoveryCellPhase), kind: ErrCredentialRecoveryGrantRejected}
	for _, err := range []error{classified, invalidCredentialRecoveryResponse(credentialRecoveryCellPhase)} {
		if got := boundary.mapError(parent, bounded, err); !errors.Is(got, err) {
			t.Fatalf("authenticated classification %v mapped to %v", err, got)
		}
	}
}

func TestCredentialRecoveryBoundaryRejectsZeroClockWithoutLatching(t *testing.T) {
	deadline := credentialRecoveryFixtureNow.Add(time.Hour)
	now := time.Time{}
	boundary := &credentialRecoveryBoundary{deadline: deadline, clock: func() time.Time { return now }}
	if err := boundary.check(); !errors.Is(err, ErrInvalidRegisterConfig) || errors.Is(err, ErrCredentialRecoveryExpired) {
		t.Fatalf("zero credential recovery clock = %v, want invalid config only", err)
	}
	now = deadline.Add(-time.Second)
	if err := boundary.check(); err != nil {
		t.Fatalf("valid clock after zero result remained latched: %v", err)
	}
}

func TestRecoverAgentRuntime_GrantRejectAtHorizonPersistsRenewalMarker(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := state.PendingCredentialRecovery.RecoveryExpiresAt
	clock := func() time.Time {
		if len(f.cellUDP.snapshot()) == 0 {
			return deadline.Add(-time.Second)
		}
		return deadline
	}
	_, _, err = RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, clock)...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("horizon-racing grant rejection = %v", err)
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery == nil || !loaded.PendingCredentialRecovery.NeedsFreshGrant {
		t.Fatalf("horizon-racing grant rejection marker = %#v/%v", loaded, loadErr)
	}
}

func TestRecoverAgentRuntime_AuthenticatedGrantRejectIgnoresCallerCancellationForMarkerSave(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.store.mu.Lock()
	f.store.cancelBeforeSave = f.store.calls + 1
	f.store.cancel = cancel
	f.store.mu.Unlock()

	_, _, err := RecoverAgentRuntime(ctx, "", f.store, recoveryOptions(t, f, fixture, func() time.Time { return credentialRecoveryFixtureNow })...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("caller-canceled grant rejection = %v", err)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("caller context = %v, want canceled", ctx.Err())
	}
	loaded, loadErr := f.store.LoadAgentState(context.Background())
	if loadErr != nil || loaded.PendingCredentialRecovery == nil || !loaded.PendingCredentialRecovery.NeedsFreshGrant {
		t.Fatalf("caller-canceled grant rejection marker = %#v/%v", loaded, loadErr)
	}
}

func TestSameCredentialRecoveryStateComparesIssueTimeByInstant(t *testing.T) {
	left := &AgentState{PendingCredentialRecoveryIssue: &PendingAgentCredentialRecoveryIssue{
		RequestNonce: "nonce", ReplayNotAfter: credentialRecoveryFixtureNow,
		RecoveryCredentialFingerprintB64: "fingerprint", AgentID: "agent-conform",
		AgentPublicKeyB64: "public-key", HubHost: "hub.nhp.layerv.ai", HubPort: standardNHPUDPPort,
		HubServerPublicKeyB64: "server-key",
	}}
	right := left.clone()
	right.PendingCredentialRecoveryIssue.ReplayNotAfter = credentialRecoveryFixtureNow.In(time.FixedZone("same-instant", -7*60*60))
	if !sameCredentialRecoveryState(left, right) {
		t.Fatal("same recovery Issue instant compared by time representation")
	}
}

func TestRecoverAgentRuntime_CommittedReplayAfterGrantExpiryUsesPersistedCellRequest(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	now := mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt).Add(time.Second)
	client, binding, err := RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, func() time.Time { return now })...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("committed replay after grant expiry = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 || string(f.cellUDP.snapshot()[0].body) != fixture.PublicExchanges["assigned_cell_complete_recovery"].RequestBodyJSON {
		t.Fatalf("expired committed replay routing/body = Hub %d cell %v", len(f.hubUDP.snapshot()), f.cellUDP.snapshot())
	}
}

func TestRecoverAgentRuntime_UncommittedExpiredGrantRenewsWithoutMovingAnchor(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	grantRejected := `{"errCode":"52411","errMsg":"credential recovery grant rejected"}`
	renewedHubResult := strings.NewReplacer(
		fixture.Fixtures.RecoveryGrant, "qrg1.conformance-recovery-grant-after-expiry",
		fixture.Fixtures.RecoveryGrantIssuedAt, "2026-07-20T11:16:00Z",
		fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:31:00Z",
	).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)
	f, _ := newCredentialRecoveryRuntimeFixture(t,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: renewedHubResult}},
		[]runtimeUDPStep{
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: grantRejected},
			{requestType: relayknock.TypeListRequest, replyType: relayknock.TypeListResult, replyBody: fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON},
		},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	before, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	anchor := before.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt
	deadline := before.PendingCredentialRecovery.RecoveryExpiresAt
	now := mustRecoveryTime(t, fixture.Fixtures.RecoveryGrantExpiresAt).Add(time.Minute)
	opts := recoveryOptions(t, f, fixture, func() time.Time { return now })
	_, _, err = RecoverAgentRuntime(context.Background(), "", f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryGrantRejected) {
		t.Fatalf("uncommitted expired grant = %v", err)
	}
	client, binding, err := RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if err != nil || client == nil || binding == nil {
		t.Fatalf("expired grant renewal = %v/%v/%v", client, binding, err)
	}
	defer binding.Destroy()
	for _, snapshot := range f.store.snapshots() {
		if snapshot.PendingCredentialRecovery != nil && snapshot.PendingCredentialRecovery.RecoveryGrant == "qrg1.conformance-recovery-grant-after-expiry" {
			if !snapshot.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Equal(anchor) || !snapshot.PendingCredentialRecovery.RecoveryExpiresAt.Equal(deadline) {
				t.Fatalf("expired grant renewal moved anchor: %#v", snapshot.PendingCredentialRecovery)
			}
			return
		}
	}
	t.Fatal("did not observe persisted renewed grant")
}

func TestPersistRenewedCredentialRecoveryEnforcesAssignmentContinuity(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, test := range []struct {
		name    string
		mutate  func(*AgentAssignment)
		wantErr bool
	}{
		{name: "generation rollback", mutate: func(a *AgentAssignment) { a.AssignmentGeneration-- }, wantErr: true},
		{name: "same-generation cell drift", mutate: func(a *AgentAssignment) { a.CellID = "cell1" }, wantErr: true},
		{name: "same-revision key drift", mutate: func(a *AgentAssignment) {
			a.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
		}, wantErr: true},
		{name: "revision rollback", mutate: func(a *AgentAssignment) { a.EndpointRevision-- }, wantErr: true},
		{name: "generation advance", mutate: func(a *AgentAssignment) { a.CellID = "cell1"; a.AssignmentGeneration++; a.EndpointRevision = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := newCredentialRecoveryRuntimeFixture(t, nil, nil)
			seedPendingCredentialRecovery(t, f, fixture, true)
			state, err := f.store.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			issued, err := parseCredentialRecoveryIssueReply([]byte(strings.NewReplacer(
				fixture.Fixtures.RecoveryGrant, "qrg1.conformance-recovery-grant-continuity",
				fixture.Fixtures.RecoveryGrantIssuedAt, "2026-07-20T11:10:00Z",
				fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:25:00Z",
			).Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON)), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&issued.Assignment)
			cfg := defaultNativeAgentRuntimeConfig()
			cfg.clock = func() time.Time { return credentialRecoveryFixtureNow }
			err = cfg.persistRenewedCredentialRecovery(context.Background(), f.store, state, issued)
			if (err != nil) != test.wantErr {
				t.Fatalf("continuity result = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func seedPendingCredentialRecovery(t *testing.T, f *runtimeFixture, fixture *conformance.AgentCredentialRecoveryFile, needsFresh bool) {
	t.Helper()
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := parseCredentialRecoveryIssueReply([]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := credentialRecoveryDeadline(issued.RecoveryGrantExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	state.Assignment = issued.Assignment.clone()
	state.DeviceAPIKey = ""
	state.DeviceAPIKeyID = ""
	state.PendingCredentialRecovery = &PendingAgentCredentialRecovery{
		RecoveryGrant: issued.RecoveryGrant, RecoveryGrantIssuedAt: issued.RecoveryGrantIssuedAt,
		RecoveryGrantExpiresAt: issued.RecoveryGrantExpiresAt, RecoveryAnchorGrantExpiresAt: issued.RecoveryGrantExpiresAt,
		RecoveryExpiresAt: deadline, DeviceAPIKey: fixture.Fixtures.DeviceAPIKeyCandidate, Assignment: issued.Assignment,
		NeedsFreshGrant: needsFresh,
	}
	state.PendingCredentialRecoveryIssue = nil
	state.SchemaVersion = agentStateSchemaVersion
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverAgentRuntime_ExactHorizonFailsBeforeAnyNetwork(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := parseCredentialRecoveryIssueReply([]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := credentialRecoveryDeadline(issued.RecoveryGrantExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	state.Assignment = issued.Assignment.clone()
	state.DeviceAPIKey = ""
	state.DeviceAPIKeyID = ""
	state.PendingCredentialRecovery = &PendingAgentCredentialRecovery{
		RecoveryGrant: issued.RecoveryGrant, RecoveryGrantIssuedAt: issued.RecoveryGrantIssuedAt,
		RecoveryGrantExpiresAt: issued.RecoveryGrantExpiresAt, RecoveryAnchorGrantExpiresAt: issued.RecoveryGrantExpiresAt,
		RecoveryExpiresAt: deadline, DeviceAPIKey: fixture.Fixtures.DeviceAPIKeyCandidate, Assignment: issued.Assignment,
	}
	if err := f.store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	resolver := &noIONativeResolver{}
	dialer := &noIONativeDialer{}
	opts := recoveryOptions(t, f, fixture, func() time.Time { return deadline }, WithAgentRuntimeUDPResolver(resolver), WithAgentRuntimeUDPDialer(dialer))
	_, _, err = RecoverAgentRuntime(context.Background(), fixture.Fixtures.RecoveryCredential, f.store, opts...)
	if !errors.Is(err, ErrCredentialRecoveryExpired) {
		t.Fatalf("exact horizon = %v, want expired", err)
	}
	if resolver.calls.Load() != 0 || dialer.calls.Load() != 0 || len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 0 {
		t.Fatalf("expired recovery did I/O: resolver=%d dialer=%d hub=%d cell=%d", resolver.calls.Load(), dialer.calls.Load(), len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestRecoverAgentRuntime_OneSecondBeforeHorizonSendsCellRequest(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil,
		[]runtimeUDPStep{{requestType: relayknock.TypeListRequest, noReply: true}},
	)
	seedPendingCredentialRecovery(t, f, fixture, false)
	state, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := state.PendingCredentialRecovery.RecoveryExpiresAt.Add(-time.Second)
	_, _, err = RecoverAgentRuntime(context.Background(), "", f.store, recoveryOptions(t, f, fixture, func() time.Time { return now })...)
	if !errors.Is(err, ErrCredentialRecoveryRetryRequired) {
		t.Fatalf("one-second-before recovery = %v, want sent/ambiguous", err)
	}
	if len(f.hubUDP.snapshot()) != 0 || len(f.cellUDP.snapshot()) != 1 {
		t.Fatalf("one-second-before routing = Hub %d cell %d", len(f.hubUDP.snapshot()), len(f.cellUDP.snapshot()))
	}
}

func TestPendingCredentialRecoveryValidationFailsClosed(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	base, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := parseCredentialRecoveryIssueReply([]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := credentialRecoveryDeadline(issued.RecoveryGrantExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	base.Assignment = issued.Assignment.clone()
	base.DeviceAPIKey = ""
	base.DeviceAPIKeyID = ""
	base.PendingCredentialRecovery = &PendingAgentCredentialRecovery{
		RecoveryGrant: issued.RecoveryGrant, RecoveryGrantIssuedAt: issued.RecoveryGrantIssuedAt,
		RecoveryGrantExpiresAt: issued.RecoveryGrantExpiresAt, RecoveryAnchorGrantExpiresAt: issued.RecoveryGrantExpiresAt,
		RecoveryExpiresAt: deadline, DeviceAPIKey: fixture.Fixtures.DeviceAPIKeyCandidate, Assignment: issued.Assignment,
	}
	mutations := map[string]func(*AgentState){
		"candidate":  func(s *AgentState) { s.PendingCredentialRecovery.DeviceAPIKey = "lv_live_bad" },
		"grant":      func(s *AgentState) { s.PendingCredentialRecovery.RecoveryGrant = "qrg1.bad\\grant" },
		"assignment": func(s *AgentState) { s.Assignment.Endpoint.Host = "cell1.nhp.layerv.ai" },
		"anchor": func(s *AgentState) {
			s.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt = s.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Add(time.Second)
		},
		"deadline": func(s *AgentState) {
			s.PendingCredentialRecovery.RecoveryExpiresAt = s.PendingCredentialRecovery.RecoveryExpiresAt.Add(time.Second)
		},
		"grant lifetime": func(s *AgentState) {
			s.PendingCredentialRecovery.RecoveryGrantExpiresAt = s.PendingCredentialRecovery.RecoveryGrantExpiresAt.Add(time.Second)
		},
		"retained revoked secret": func(s *AgentState) { s.DeviceAPIKey = canonicalNativeDeviceCredential },
		"retained revoked id":     func(s *AgentState) { s.DeviceAPIKeyID = "key_OldDvK123456" },
		"legacy schema":           func(s *AgentState) { s.SchemaVersion = credentialRecoveryStateSchemaVersion - 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			state := base.clone()
			mutate(state)
			if err := validateLoadedAgentAssignment(state); !errors.Is(err, ErrInvalidAgentState) {
				t.Fatalf("mutation %s = %v, want ErrInvalidAgentState", name, err)
			}
		})
	}
}

func TestCredentialRecoveryIssueReplayCasesDispositionAndConsumerState(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	base, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	base.PendingCredentialRecoveryIssue = &PendingAgentCredentialRecoveryIssue{
		RequestNonce: fixture.Fixtures.RequestNonce, ReplayNotAfter: credentialRecoveryFixtureNow.Add(AgentCredentialRecoveryHorizon),
		RecoveryCredentialFingerprintB64: credentialRecoveryCredentialFingerprint(fixture.Fixtures.RecoveryCredential),
		AgentID:                          base.AgentID, AgentPublicKeyB64: base.PublicKeyB64,
		HubHost: f.hub.Host, HubPort: f.hub.Port, HubServerPublicKeyB64: f.hub.ServerPublicKeyB64,
	}
	for name, mutate := range map[string]func(*PendingAgentCredentialRecoveryIssue){
		"missing cutoff": func(issue *PendingAgentCredentialRecoveryIssue) { issue.ReplayNotAfter = time.Time{} },
		"noncanonical cutoff": func(issue *PendingAgentCredentialRecoveryIssue) {
			issue.ReplayNotAfter = issue.ReplayNotAfter.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *base.PendingCredentialRecoveryIssue
			mutate(&changed)
			if err := validatePendingCredentialRecoveryIssue(&changed); !errors.Is(err, ErrInvalidAgentState) {
				t.Fatalf("invalid Issue cutoff = %v", err)
			}
		})
	}
	executed := map[string]struct{}{}
	for _, testCase := range fixture.IssueReplayCases {
		t.Run(testCase.Name, func(t *testing.T) {
			switch testCase.Mutation {
			case "none", "same_hub_request_id_and_semantic_fingerprint":
				if err := validateLoadedAgentAssignment(base.clone()); err != nil || !sameCredentialRecoveryCredential(fixture.Fixtures.RecoveryCredential, base.PendingCredentialRecoveryIssue.RecoveryCredentialFingerprintB64) {
					t.Fatalf("exact replay state = %v", err)
				}
			case "same_hub_request_id_changed_recovery_credential":
				other := deviceKeyPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6d}, deviceKeyRandomLength))
				if sameCredentialRecoveryCredential(other, base.PendingCredentialRecoveryIssue.RecoveryCredentialFingerprintB64) {
					t.Fatal("changed recovery credential matched durable issue")
				}
			case "same_hub_request_id_changed_agent_id":
				changed := base.clone()
				changed.AgentID = "agent-other"
				if err := validateLoadedAgentAssignment(changed); !errors.Is(err, ErrInvalidAgentState) {
					t.Fatalf("changed agent = %v", err)
				}
			case "same_hub_request_id_changed_authenticated_peer":
				changed := base.clone()
				changed.PublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6e}, 32))
				if err := validateLoadedAgentAssignment(changed); !errors.Is(err, ErrInvalidAgentState) {
					t.Fatalf("changed peer = %v", err)
				}
			case "same_nonce_and_body_returns_new_grant_or_times_or_assignment":
				// Producer-only replay-drift disposition: stored-result byte
				// identity is unknowable when the first response is lost. The
				// consumer-observable half is the durable exact request identity.
				if testCase.RejectClass != "replay_drift" {
					t.Fatalf("producer replay-drift class = %q", testCase.RejectClass)
				}
				if _, err := parseCredentialRecoveryIssueReply([]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow); err != nil || base.PendingCredentialRecoveryIssue.RequestNonce != fixture.Fixtures.RequestNonce {
					t.Fatalf("replay result/request identity = %v", err)
				}
			case "transport_retry_changes_nonce_or_serialized_body":
				body := []byte(fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON)
				if err := validateCredentialRecoveryIssueRequest(body); err != nil || !bytes.Contains(body, []byte(base.PendingCredentialRecoveryIssue.RequestNonce)) {
					t.Fatalf("durable logical request = %v", err)
				}
			default:
				t.Fatalf("unimplemented issue replay mutation %q", testCase.Mutation)
			}
		})
		executed[testCase.Name] = struct{}{}
	}
	if len(executed) != len(fixture.IssueReplayCases) || len(executed) != 7 {
		t.Fatalf("executed issue replay cases = %d/%d", len(executed), len(fixture.IssueReplayCases))
	}
}

func TestCredentialRecoveryGrantBindingCasesDispositionAndConsumerChecks(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	f, _ := newCredentialRecoveryRuntimeFixture(t, nil, nil)
	seedPendingCredentialRecovery(t, f, fixture, false)
	base, err := f.store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	executed := map[string]struct{}{}
	for _, testCase := range fixture.GrantBindingCases {
		t.Run(testCase.Name, func(t *testing.T) {
			switch testCase.RejectClass {
			case "":
				if err := validateLoadedAgentAssignment(base.clone()); err != nil {
					t.Fatalf("accepted durable binding = %v", err)
				}
				if _, err := parseCredentialRecoveryCompletionReply([]byte(fixture.PublicExchanges["assigned_cell_complete_recovery"].SuccessBodyJSON)); err != nil {
					t.Fatalf("accepted completion = %v", err)
				}
			case "recovery_anchor":
				changed := base.clone()
				changed.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt = changed.PendingCredentialRecovery.RecoveryAnchorGrantExpiresAt.Add(time.Second)
				if err := validateLoadedAgentAssignment(changed); !errors.Is(err, ErrInvalidAgentState) {
					t.Fatalf("re-anchored state = %v", err)
				}
			case "recovery_expired":
				boundary := &credentialRecoveryBoundary{deadline: base.PendingCredentialRecovery.RecoveryExpiresAt, clock: func() time.Time { return base.PendingCredentialRecovery.RecoveryExpiresAt }}
				if err := boundary.check(); !errors.Is(err, ErrCredentialRecoveryExpired) {
					t.Fatalf("exact horizon = %v", err)
				}
			case "grant_lifetime":
				body := strings.Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON, fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:15:01Z", 1)
				if testCase.Mutation == "recovery_grant_lifetime_seconds_899" {
					body = strings.Replace(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON, fixture.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:14:59Z", 1)
				}
				if _, err := parseCredentialRecoveryIssueReply([]byte(body), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow); !errors.Is(err, ErrCredentialRecoveryInvalidResponse) {
					t.Fatalf("grant lifetime = %v", err)
				}
			case "revoke_required":
				if _, err := parseCredentialRecoveryEnvelope([]byte(`{"errCode":"52403","errMsg":"revoke current device credential before recovery"}`), credentialRecoveryHubPhase); !errors.Is(err, ErrCredentialRecoveryRevokeRequired) {
					t.Fatalf("revoke required = %v", err)
				}
			case "credential_conflict":
				if _, err := parseCredentialRecoveryEnvelope([]byte(`{"errCode":"52413","errMsg":"different replacement credential candidate already recorded"}`), credentialRecoveryCellPhase); !errors.Is(err, ErrCredentialRecoveryCandidateConflict) {
					t.Fatalf("candidate conflict = %v", err)
				}
			default:
				// Producer-only signed-grant semantics are opaque to the SDK. Keep
				// them explicitly dispositioned without pretending a generic 52411
				// parser test executes Authority's mutation.
				producerOnly := map[string]string{
					"agent_id": "grant_binding", "authenticated_peer_public_key_b64": "grant_binding",
					"recovery_credential_key_id": "grant_binding", "recovery_credential_hash": "grant_binding",
					"recovery_credential_fence": "grant_binding", "recovery_credential_kind_or_scope": "grant_binding",
					"bound_recovery_credential_becomes_inactive_revoked_or_expired_after_issue": "grant_rejected",
					"environment": "grant_binding", "cell_id": "grant_binding", "assignment_generation": "grant_binding",
					"revoked_device_credential_fence": "grant_binding", "expired_grant_without_committed_result": "grant_expired",
				}
				if want, ok := producerOnly[testCase.Mutation]; !ok || testCase.RejectClass != want {
					t.Fatalf("undispositioned producer-only grant mutation %q/%q", testCase.Mutation, testCase.RejectClass)
				}
			}
		})
		executed[testCase.Name] = struct{}{}
	}
	if len(executed) != len(fixture.GrantBindingCases) || len(executed) != 24 {
		t.Fatalf("executed grant binding cases = %d/%d", len(executed), len(fixture.GrantBindingCases))
	}
}

func TestCredentialRecoveryFlowCasesDispositionAndConsumerChecks(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	hubBody := []byte(fixture.PublicExchanges["hub_issue_recovery"].RequestBodyJSON)
	cellBody := []byte(fixture.PublicExchanges["assigned_cell_complete_recovery"].RequestBodyJSON)
	executed := map[string]struct{}{}
	for _, flow := range fixture.FlowCases {
		t.Run(flow.Name, func(t *testing.T) {
			switch flow.Mutation {
			case "none":
				if err := validateCredentialRecoveryIssueRequest(hubBody); err != nil {
					t.Fatal(err)
				}
			case "resource_401_triggers_recovery":
				if errors.Is(&APIError{StatusCode: http.StatusUnauthorized}, ErrCredentialRecoveryRetryRequired) {
					t.Fatal("resource 401 classified as explicit recovery")
				}
			case "public_http_used_for_hub_or_cell", "browser_relay_used":
				if bytes.Contains(hubBody, []byte("http")) || bytes.Contains(cellBody, []byte("http")) || bytes.Contains(hubBody, []byte("relay")) || bytes.Contains(cellBody, []byte("relay")) {
					t.Fatal("native recovery body contains HTTP/relay routing")
				}
			case "client_derives_or_probes_cell", "cell_exchange_falls_back_to_other_cell":
				issue, err := parseCredentialRecoveryIssueReply([]byte(fixture.PublicExchanges["hub_issue_recovery"].SuccessBodyJSON), fixture.Fixtures.AgentID, credentialRecoveryFixtureNow)
				if err != nil || issue.Assignment.Endpoint.Host != fixture.Fixtures.NHPHost {
					t.Fatalf("Hub-authoritative assignment = %#v/%v", issue, err)
				}
			case "hub_invokes_authority_before_cookie_proof":
				// Authority invocation count is producer-owned; the SDK's real
				// cookie packet path is exercised by the v0.9 golden KAT test.
				if fixture.HubCookie.AuthorityInvocationsBeforeProof != 0 || fixture.HubCookie.AuthorityInvocationsAfterProof != 1 {
					t.Fatal("cookie proof gate drifted")
				}
			case "different_authenticated_peer_for_same_agent":
				withTakeover := []byte(strings.Replace(string(hubBody), `"aspId":"agent"`, `"aspId":"agent","takeover":true`, 1))
				if err := validateCredentialRecoveryIssueRequest(withTakeover); !errors.Is(err, ErrInvalidRegisterConfig) {
					t.Fatalf("takeover request = %v", err)
				}
			case "candidate_not_durable_before_cell_send", "candidate_rotated_after_ambiguous_reply":
				if err := validateCredentialRecoveryCompletionRequest(cellBody); err != nil || !bytes.Contains(cellBody, []byte(fixture.Fixtures.DeviceAPIKeyCandidate)) {
					t.Fatalf("exact candidate request = %v", err)
				}
			default:
				t.Fatalf("unimplemented flow mutation %q", flow.Mutation)
			}
		})
		executed[flow.Name] = struct{}{}
	}
	if len(executed) != len(fixture.FlowCases) || len(executed) != 10 {
		t.Fatalf("executed flow cases = %d/%d", len(executed), len(fixture.FlowCases))
	}
}

func TestCredentialRecoveryErrorsNeverContainSecrets(t *testing.T) {
	fixture := loadCredentialRecoveryFixture(t)
	for _, body := range []string{
		fmt.Sprintf(`{"errCode":"future","errMsg":%q}`, fixture.Fixtures.RecoveryCredential),
		fmt.Sprintf(`{"errCode":"0","list":{"query":"bad","version":1,"device_api_key_id":%q}}`, fixture.Fixtures.DeviceAPIKeyCandidate),
	} {
		_, err := parseCredentialRecoveryCompletionReply([]byte(body))
		if err == nil {
			t.Fatal("secret-bearing malformed body unexpectedly accepted")
		}
		for _, secret := range []string{fixture.Fixtures.RecoveryCredential, fixture.Fixtures.RecoveryGrant, fixture.Fixtures.DeviceAPIKeyCandidate} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("credential recovery error leaked %q: %v", secret, err)
			}
		}
	}
}
