package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

var assignmentFixtureNow = time.Date(2026, 7, 15, 23, 0, 0, 0, time.UTC)

func loadAssignmentFixture(t *testing.T) *conformance.AgentAssignmentFile {
	t.Helper()
	fixture, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatalf("load agent-assignment conformance: %v", err)
	}
	return fixture
}

func assignmentHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

type assignmentTestResolver struct{}

func (assignmentTestResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type assignmentTestDialer struct{ target string }

func (d assignmentTestDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

type assignmentTestServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	agentPub   []byte
	replies    [][]byte
	done       chan struct{}

	mu       sync.Mutex
	requests [][]byte
}

func newAssignmentTestServer(t *testing.T, serverPriv, agentPub []byte, replies ...string) *assignmentTestServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	server := &assignmentTestServer{
		t: t, conn: conn, serverPriv: serverPriv, agentPub: agentPub,
		replies: make([][]byte, len(replies)), done: make(chan struct{}),
	}
	for i, reply := range replies {
		server.replies[i] = []byte(reply)
	}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("assignment test server did not stop")
		}
	})
	return server
}

func (s *assignmentTestServer) serve() {
	defer close(s.done)
	buffer := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		opened, err := relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, append([]byte(nil), buffer[:n]...))
		if err != nil {
			s.t.Errorf("open assignment request: %v", err)
			continue
		}
		if opened.Type != conformance.AgentAssignmentRequestHeaderType {
			s.t.Errorf("assignment request type = %d, want NHP_LST (%d)", opened.Type, conformance.AgentAssignmentRequestHeaderType)
			continue
		}
		s.mu.Lock()
		index := len(s.requests)
		s.requests = append(s.requests, append([]byte(nil), opened.Body...))
		s.mu.Unlock()
		if index >= len(s.replies) {
			continue
		}
		packet, err := relayknocktest.BuildReply(relayknock.TypeListResult, &relayknock.KnockInputs{
			DeviceStaticPriv: s.serverPriv,
			ServerStaticPub:  s.agentPub,
			EphemeralPriv:    bytes.Repeat([]byte{byte(0x80 + index)}, 32),
			TimestampNanos:   uint64(assignmentFixtureNow.UnixNano()) + uint64(index),
			Counter:          opened.Counter,
			Preamble:         uint32(0x11223344 + index),
			Body:             s.replies[index],
		})
		if err != nil {
			s.t.Errorf("build assignment reply: %v", err)
			continue
		}
		if _, err := s.conn.WriteToUDP(packet, addr); err != nil {
			s.t.Logf("write assignment reply: %v", err)
		}
	}
}

func (s *assignmentTestServer) requestBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, len(s.requests))
	for i := range s.requests {
		result[i] = append([]byte(nil), s.requests[i]...)
	}
	return result
}

func assignmentTestSetup(t *testing.T, replies ...string) (HubBootstrap, nativeudp.Options, *assignmentTestServer) {
	t.Helper()
	fixture := loadAssignmentFixture(t)
	agentPriv := assignmentHex(t, fixture.Keys.Agent.StaticPrivHex)
	agentKey, err := ecdh.X25519().NewPrivateKey(agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	hubPriv := assignmentHex(t, fixture.Keys.Hub.StaticPrivHex)
	server := newAssignmentTestServer(t, hubPriv, agentKey.PublicKey().Bytes(), replies...)
	hub := HubBootstrap{
		Host:               "hub.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, fixture.Keys.Hub.StaticPubHex)),
	}
	transport := nativeudp.Options{
		DeviceStaticPriv: agentPriv,
		Resolver:         assignmentTestResolver{},
		Dialer:           assignmentTestDialer{target: server.conn.LocalAddr().String()},
		Timeout:          2 * time.Second,
	}
	return hub, transport, server
}

func deterministicAssignmentOptions(slept *[]time.Duration, maxAttempts int) []AssignmentOption {
	return []AssignmentOption{
		WithAssignmentRetryBudget(maxAttempts, time.Minute),
		withAssignmentClock(func() time.Time { return assignmentFixtureNow }),
		withAssignmentJitter(func(time.Duration) (time.Duration, error) { return 0, nil }),
		withAssignmentSleep(func(_ context.Context, delay time.Duration) error {
			*slept = append(*slept, delay)
			return nil
		}),
	}
}

func TestHubAssignmentInitialAndRefreshMatchConformanceBodies(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	hub, transport, server := assignmentTestSetup(t,
		fixture.InitialAssignment.Result.BodyJSON,
		fixture.RefreshAssignment.Result.BodyJSON,
	)
	var slept []time.Duration
	initial, err := FetchInitialAgentAssignment(
		context.Background(), hub, "agent-conform", conformance.AgentAssignmentBootstrapCredentialFixture,
		transport, deterministicAssignmentOptions(&slept, 1)...,
	)
	if err != nil {
		t.Fatalf("FetchInitialAgentAssignment: %v", err)
	}
	if initial.Registration != (AssignmentRegistration{KeyID: "key_BsT4rP8wXn6Q", KeyKind: "bootstrap"}) ||
		initial.Assignment.CellID != "cell0" || initial.AssignmentTicket != "conformance-assignment-ticket-0001" {
		t.Fatalf("initial result = %#v", initial)
	}
	refreshed, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport, deterministicAssignmentOptions(&slept, 1)...,
	)
	if err != nil {
		t.Fatalf("RefreshAgentAssignment: %v", err)
	}
	if *refreshed != initial.Assignment {
		t.Fatalf("refresh = %#v, initial assignment = %#v", refreshed, initial.Assignment)
	}
	requests := server.requestBodies()
	if len(requests) != 2 || string(requests[0]) != fixture.InitialAssignment.Request.BodyJSON || string(requests[1]) != fixture.RefreshAssignment.Request.BodyJSON {
		t.Fatalf("request bodies do not match conformance:\n got %q\nwant %q / %q", requests, fixture.InitialAssignment.Request.BodyJSON, fixture.RefreshAssignment.Request.BodyJSON)
	}
	if bytes.Contains(requests[1], []byte(conformance.AgentAssignmentBootstrapCredentialFixture)) || bytes.Contains(requests[1], []byte("device_api_key")) {
		t.Fatalf("refresh leaked a credential field: %s", requests[1])
	}
}

func TestHubAssignmentRetriesOnlyBoundedRetryableResults(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	retryBody := `{"errCode":"52200","errMsg":"temporary","retryAfterSeconds":5}`
	hub, transport, server := assignmentTestSetup(t, retryBody, retryBody, fixture.RefreshAssignment.Result.BodyJSON)
	var slept []time.Duration
	assignment, err := RefreshAgentAssignment(context.Background(), hub, "agent-conform", transport, deterministicAssignmentOptions(&slept, 3)...)
	if err != nil || assignment.CellID != "cell0" {
		t.Fatalf("RefreshAgentAssignment = %#v, %v", assignment, err)
	}
	if fmt.Sprint(slept) != "[5s 5s]" || len(server.requestBodies()) != 3 {
		t.Fatalf("slept/requests = %v/%d, want [5s 5s]/3", slept, len(server.requestBodies()))
	}

	hub, transport, server = assignmentTestSetup(t, retryBody, retryBody)
	slept = nil
	_, err = RefreshAgentAssignment(context.Background(), hub, "agent-conform", transport, deterministicAssignmentOptions(&slept, 2)...)
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, ErrAssignmentUnavailable) || recovery.Attempts != 2 {
		t.Fatalf("exhaustion error = %#v, want typed recovery/unavailable", err)
	}
	if len(server.requestBodies()) != 2 {
		t.Fatalf("requests = %d, want 2", len(server.requestBodies()))
	}
}

func TestHubAssignmentTerminalResultDoesNotRetry(t *testing.T) {
	hub, transport, server := assignmentTestSetup(t, `{"errCode":"52204","errMsg":"slow down","retryAfterSeconds":60}`)
	var slept []time.Duration
	_, err := RefreshAgentAssignment(context.Background(), hub, "agent-conform", transport, deterministicAssignmentOptions(&slept, 4)...)
	var appErr *AssignmentError
	if !errors.As(err, &appErr) || !errors.Is(err, ErrAssignmentRateLimited) || appErr.RetryAfter != time.Minute {
		t.Fatalf("rate-limit error = %#v", err)
	}
	if len(slept) != 0 || len(server.requestBodies()) != 1 {
		t.Fatalf("terminal error slept/sent = %v/%d", slept, len(server.requestBodies()))
	}
}

func TestHubAssignmentRetryBudgetBoundsInFlightUDP(t *testing.T) {
	hub, transport, server := assignmentTestSetup(t)
	transport.Timeout = 2 * time.Second
	started := time.Now()
	_, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport,
		WithAssignmentRetryBudget(4, 50*time.Millisecond),
	)
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || recovery.Attempts != 1 {
		t.Fatalf("error = %#v, want one-attempt recovery-required", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("transaction took %s; retry budget did not bound the UDP receive", elapsed)
	}
	if len(server.requestBodies()) != 1 {
		t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
	}
}

func TestAssignmentConformanceSuccessRejectCases(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	for _, testCase := range fixture.SuccessResultCases {
		var parse func([]byte) error
		switch testCase.Phase {
		case "initial_assignment":
			parse = func(body []byte) error {
				_, err := parseInitialAssignmentReply(body, "agent-conform", assignmentFixtureNow)
				return err
			}
		case "refresh_assignment":
			parse = func(body []byte) error {
				_, err := parseRefreshAssignmentReply(body, "agent-conform", assignmentFixtureNow)
				return err
			}
		default:
			continue
		}
		t.Run(testCase.Name, func(t *testing.T) {
			if err := parse([]byte(testCase.BodyJSON)); !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

func TestAssignmentConformanceErrorTaxonomy(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	want := map[string]error{
		"52200": ErrAssignmentUnavailable,
		"52201": ErrAssignmentIdentityRejected,
		"52202": ErrAssignmentReassignmentRequired,
		"52203": ErrAssignmentQuotaExceeded,
		"52204": ErrAssignmentRateLimited,
		"52205": ErrAssignmentRequestRejected,
		"52106": ErrAssignmentKeyRejected,
		"52107": ErrAssignmentRegistrationDisabled,
		"52108": ErrAssignmentBootstrapConsumed,
		"52109": ErrAssignmentRequestRejected,
	}
	groups := [][]conformance.AgentAssignmentErrorCase{
		fixture.ErrorContract.AssignmentCases,
		fixture.ErrorContract.InitialCredentialCases,
	}
	for _, group := range groups {
		for _, testCase := range group {
			t.Run(testCase.Name, func(t *testing.T) {
				initial := testCase.Phase == "initial_assignment"
				_, err := parseAssignmentEnvelope([]byte(testCase.BodyJSON), initial)
				if !errors.Is(err, want[testCase.ErrCode]) || errors.Is(err, ErrAssignmentInvalidResponse) {
					t.Fatalf("error = %v, want %v only", err, want[testCase.ErrCode])
				}
			})
		}
	}
	for _, testCase := range fixture.ErrorContract.MalformedCases {
		if testCase.Phase != "cell_assignment" && testCase.Phase != "initial_assignment" {
			continue
		}
		t.Run(testCase.Name, func(t *testing.T) {
			_, err := parseAssignmentEnvelope([]byte(testCase.BodyJSON), testCase.Phase == "initial_assignment")
			if !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

func TestHubAssignmentRejectsInvalidInputsBeforeIO(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	validHub, validTransport, _ := assignmentTestSetup(t, fixture.InitialAssignment.Result.BodyJSON)
	lowOrder := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name       string
		hub        HubBootstrap
		agentID    string
		credential string
		transport  nativeudp.Options
	}{
		{name: "missing hub", agentID: "agent-conform", credential: "valid", transport: validTransport},
		{name: "IP hub", hub: HubBootstrap{Host: "203.0.113.1", Port: standardNHPUDPPort, ServerPublicKeyB64: validHub.ServerPublicKeyB64}, agentID: "agent-conform", credential: "valid", transport: validTransport},
		{name: "AWS hub", hub: HubBootstrap{Host: "internal-hub.elb.amazonaws.com", Port: standardNHPUDPPort, ServerPublicKeyB64: validHub.ServerPublicKeyB64}, agentID: "agent-conform", credential: "valid", transport: validTransport},
		{name: "unsupported port", hub: HubBootstrap{Host: validHub.Host, Port: 443, ServerPublicKeyB64: validHub.ServerPublicKeyB64}, agentID: "agent-conform", credential: "valid", transport: validTransport},
		{name: "low-order key", hub: HubBootstrap{Host: validHub.Host, Port: standardNHPUDPPort, ServerPublicKeyB64: lowOrder}, agentID: "agent-conform", credential: "valid", transport: validTransport},
		{name: "invalid agent id", hub: validHub, agentID: "Bad_ID", credential: "valid", transport: validTransport},
		{name: "invalid credential", hub: validHub, agentID: "agent-conform", credential: " secret ", transport: validTransport},
		{name: "short initiator key", hub: validHub, agentID: "agent-conform", credential: "valid", transport: nativeudp.Options{DeviceStaticPriv: make([]byte, 31)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := FetchInitialAgentAssignment(context.Background(), testCase.hub, testCase.agentID, testCase.credential, testCase.transport)
			if !errors.Is(err, ErrInvalidAssignmentConfig) {
				t.Fatalf("error = %v, want ErrInvalidAssignmentConfig", err)
			}
		})
	}
}

func TestAgentAssignmentStatePersistsOnlyDurableBinding(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply([]byte(fixture.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := secureAgentStateTestDir(t)
	path := filepath.Join(dir, "agent-state.json")
	store := FileAgentState(path)
	state := &AgentState{
		AgentID: "agent-conform", PrivateKeyB64: base64.StdEncoding.EncodeToString(assignmentHex(t, fixture.Keys.Agent.StaticPrivHex)),
		PublicKeyB64:  base64.StdEncoding.EncodeToString(assignmentHex(t, fixture.Keys.Agent.StaticPubHex)),
		SchemaVersion: agentStateSchemaVersion, Assignment: initial.Assignment.clone(),
	}
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(initial.AssignmentTicket)) || bytes.Contains(raw, []byte(initial.Registration.KeyID)) || bytes.Contains(raw, []byte("assignment_ticket")) || bytes.Contains(raw, []byte("registration")) {
		t.Fatalf("state persisted ephemeral registration material: %s", raw)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	var persistedAssignment map[string]json.RawMessage
	if err := json.Unmarshal(document["assignment"], &persistedAssignment); err != nil {
		t.Fatal(err)
	}
	if _, duplicated := persistedAssignment["agent_id"]; duplicated {
		t.Fatalf("assignment duplicates AgentState.AgentID: %s", document["assignment"])
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil || loaded.Assignment == nil || *loaded.Assignment != initial.Assignment {
		t.Fatalf("LoadAgentState = %#v, %v", loaded, err)
	}
}

func TestAgentAssignmentCloneAndLease(t *testing.T) {
	assignment := &AgentAssignment{CellID: "cell0", LeaseExpiresAt: assignmentFixtureNow.Add(time.Hour), Endpoint: NHPUDPEndpoint{Host: "cell0.nhp.layerv.ai"}}
	clone := assignment.clone()
	clone.CellID = "cell1"
	clone.Endpoint.Host = "cell1.nhp.layerv.ai"
	if assignment.CellID != "cell0" || assignment.Endpoint.Host != "cell0.nhp.layerv.ai" {
		t.Fatalf("clone mutated source: %#v", assignment)
	}
	if assignment.LeaseExpired(assignmentFixtureNow) || !assignment.LeaseExpired(assignment.LeaseExpiresAt) {
		t.Fatal("LeaseExpired boundary is wrong")
	}
	var absent *AgentAssignment
	if !absent.LeaseExpired(assignmentFixtureNow) {
		t.Fatal("nil assignment must be expired")
	}
}

func TestInitialAssignmentDeadlineClocksAreIndependent(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	packetTimeNanos, err := strconv.ParseInt(fixture.InitialAssignment.Result.TimestampNanos, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	packetTime := time.Unix(0, packetTimeNanos).UTC()
	initial, err := parseInitialAssignmentReply([]byte(fixture.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if !packetTime.Before(assignmentFixtureNow) || !initial.AssignmentTicketExpiresAt.After(assignmentFixtureNow) ||
		!initial.Assignment.LeaseExpiresAt.After(initial.AssignmentTicketExpiresAt) {
		t.Fatalf("packet/ticket/lease clocks = %s / %s / %s", packetTime, initial.AssignmentTicketExpiresAt, initial.Assignment.LeaseExpiresAt)
	}
	if _, err := parseInitialAssignmentReply([]byte(fixture.InitialAssignment.Result.BodyJSON), "agent-conform", initial.AssignmentTicketExpiresAt); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("ticket-expiry boundary error = %v, want ErrAssignmentInvalidResponse", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal([]byte(fixture.InitialAssignment.Result.BodyJSON), &envelope); err != nil {
		t.Fatal(err)
	}
	list := envelope["list"].(map[string]any)
	assignment := list["assignment"].(map[string]any)
	list["assignment_ticket_expires_at"] = assignment["lease_expires_at"]
	notOrdered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseInitialAssignmentReply(notOrdered, "agent-conform", assignmentFixtureNow); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("unordered ticket/lease error = %v, want ErrAssignmentInvalidResponse", err)
	}
}

func TestExactObjectFieldsRejectsNestedDuplicateAndTrailing(t *testing.T) {
	for _, raw := range []string{
		`{"outer":{"key":1,"key":2}}`,
		`{"outer":1}{"trailing":2}`,
		`null`,
		`[]`,
	} {
		if _, err := exactObjectFields([]byte(raw)); err == nil {
			t.Fatalf("strict parser accepted %s", raw)
		}
	}
	deep := append([]byte(`{"value":`), bytes.Repeat([]byte("["), maxAssignmentJSONDepth)...)
	deep = append(deep, '0')
	deep = append(deep, bytes.Repeat([]byte("]"), maxAssignmentJSONDepth)...)
	deep = append(deep, '}')
	if _, err := exactObjectFields(deep); err == nil {
		t.Fatalf("strict parser accepted %d-level nested value", maxAssignmentJSONDepth+1)
	}
}

func TestAssignmentErrorRejectsNullDiagnostic(t *testing.T) {
	if _, err := parseAssignmentEnvelope([]byte(`{"errCode":"52201","errMsg":null}`), false); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
	}
}
