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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/nhpcontract"
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

type assignmentTestResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f assignmentTestResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type assignmentTestDialer struct{ target string }

func (d assignmentTestDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

type assignmentTestServer struct {
	t           *testing.T
	conn        *net.UDPConn
	serverPriv  []byte
	agentPub    []byte
	replies     [][]byte
	done        chan struct{}
	requestSeen chan struct{}

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
		replies: make([][]byte, len(replies)), done: make(chan struct{}), requestSeen: make(chan struct{}, 8),
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
		select {
		case s.requestSeen <- struct{}{}:
		default:
		}
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
		Resolver: assignmentTestResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer:  assignmentTestDialer{target: server.conn.LocalAddr().String()},
		Timeout: 2 * time.Second,
	}
	return hub, transport, server
}

func deterministicAssignmentOptions(slept *[]time.Duration, maxAttempts int) []AssignmentOption {
	return []AssignmentOption{
		WithAssignmentRetryBudget(maxAttempts, time.Minute),
		fixedAssignmentClock(),
		zeroAssignmentJitter(),
		withAssignmentSleep(func(_ context.Context, delay time.Duration) error {
			*slept = append(*slept, delay)
			return nil
		}),
	}
}

func fixedAssignmentClock() AssignmentOption {
	return withAssignmentClock(func() time.Time { return assignmentFixtureNow })
}

func zeroAssignmentJitter() AssignmentOption {
	return withAssignmentJitter(func(time.Duration) (time.Duration, error) { return 0, nil })
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
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, ErrAssignmentUnavailable) || recovery.Attempts != 2 || recovery.Elapsed != 0 {
		t.Fatalf("exhaustion error = %#v, want typed recovery/unavailable", err)
	}
	if len(server.requestBodies()) != 2 {
		t.Fatalf("requests = %d, want 2", len(server.requestBodies()))
	}
}

func TestHubAssignmentRetriesResolveFailure(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	hub, transport, server := assignmentTestSetup(t, fixture.RefreshAssignment.Result.BodyJSON)
	resolveCalls := 0
	transport.Resolver = assignmentTestResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		resolveCalls++
		if resolveCalls == 1 {
			return nil, errors.New("injected DNS failure")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	var slept []time.Duration
	assignment, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport,
		deterministicAssignmentOptions(&slept, 2)...,
	)
	if err != nil || assignment.CellID != "cell0" {
		t.Fatalf("RefreshAgentAssignment = %#v, %v", assignment, err)
	}
	if resolveCalls != 2 || fmt.Sprint(slept) != "[0s]" || len(server.requestBodies()) != 1 {
		t.Fatalf("resolve/sleep/request counts = %d/%v/%d, want 2/[0s]/1", resolveCalls, slept, len(server.requestBodies()))
	}
}

func TestRunNativeExchangeWipesDecryptedReply(t *testing.T) {
	for _, parseFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("parse_failure_%t", parseFails), func(t *testing.T) {
			hub, transport, _ := assignmentTestSetup(t, `{"assignment_ticket":"one-shot-secret"}`)
			endpoint, err := validateAssignmentInputs(context.Background(), hub, "agent-conform", transport)
			if err != nil {
				t.Fatal(err)
			}
			var slept []time.Duration
			cfg, err := newAssignmentConfig(deterministicAssignmentOptions(&slept, 1))
			if err != nil {
				t.Fatal(err)
			}
			var decrypted []byte
			parseErr := errors.New("parse failed")
			_, err = runNativeExchange(
				context.Background(), cfg, endpoint, []byte(`{}`), transport,
				nativeudp.List,
				assignmentRetryInfo, newAssignmentRecovery,
				func(reply []byte, _ time.Time) (*struct{}, error) {
					decrypted = reply
					if parseFails {
						return nil, parseErr
					}
					return &struct{}{}, nil
				},
			)
			if (err != nil) != parseFails || parseFails && !errors.Is(err, parseErr) {
				t.Fatalf("runNativeExchange error = %v, parseFails = %t", err, parseFails)
			}
			if len(decrypted) == 0 || !bytes.Equal(decrypted, make([]byte, len(decrypted))) {
				t.Fatalf("decrypted reply was not wiped: %q", decrypted)
			}
		})
	}
}

func TestAssignmentBackoffWindowsAndJitterBounds(t *testing.T) {
	var windows []time.Duration
	cfg := &assignmentConfig{jitter: func(window time.Duration) (time.Duration, error) {
		windows = append(windows, window)
		return window - time.Nanosecond, nil
	}}
	for _, attempt := range []int{1, 2, 3, 4, 5, 6, 64} {
		delay, err := cfg.backoff(attempt, 0)
		if err != nil {
			t.Fatalf("attempt %d backoff: %v", attempt, err)
		}
		if delay != windows[len(windows)-1]-time.Nanosecond {
			t.Fatalf("attempt %d delay = %s, want jitter result", attempt, delay)
		}
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	if fmt.Sprint(windows) != fmt.Sprint(want) {
		t.Fatalf("backoff windows = %v, want %v", windows, want)
	}
	if delay, err := (&assignmentConfig{jitter: func(time.Duration) (time.Duration, error) {
		return 400 * time.Millisecond, nil
	}}).backoff(1, 100*time.Millisecond); err != nil || delay != 400*time.Millisecond {
		t.Fatalf("jitter above RetryAfter = %s, %v; want 400ms", delay, err)
	}

	for _, testCase := range []struct {
		name   string
		jitter func(time.Duration) (time.Duration, error)
	}{
		{name: "source failure", jitter: func(time.Duration) (time.Duration, error) { return 0, errors.New("entropy unavailable") }},
		{name: "negative", jitter: func(time.Duration) (time.Duration, error) { return -1, nil }},
		{name: "equal to window", jitter: func(window time.Duration) (time.Duration, error) { return window, nil }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := (&assignmentConfig{jitter: testCase.jitter}).backoff(1, 0); err == nil {
				t.Fatal("invalid jitter result accepted")
			}
		})
	}
}

func TestHubAssignmentJitterFailureRequiresRecovery(t *testing.T) {
	hub, transport, server := assignmentTestSetup(t, `{"errCode":"52200","errMsg":"temporary"}`)
	_, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport,
		WithAssignmentRetryBudget(4, time.Minute),
		fixedAssignmentClock(),
		withAssignmentJitter(func(time.Duration) (time.Duration, error) { return 0, errors.New("entropy unavailable") }),
	)
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentUnavailable) || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("jitter failure = %#v, want typed recovery with unavailable and jitter causes", err)
	}
	if recovery.Attempts != 1 || len(server.requestBodies()) != 1 {
		t.Fatalf("attempts/requests = %d/%d, want 1/1", recovery.Attempts, len(server.requestBodies()))
	}
}

func TestHubAssignmentRetryDelayCannotExceedRemainingBudget(t *testing.T) {
	hub, transport, server := assignmentTestSetup(t, `{"errCode":"52200","errMsg":"temporary","retryAfterSeconds":5}`)
	var slept []time.Duration
	_, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport,
		WithAssignmentRetryBudget(4, time.Second),
		fixedAssignmentClock(),
		zeroAssignmentJitter(),
		withAssignmentSleep(func(_ context.Context, delay time.Duration) error {
			slept = append(slept, delay)
			return nil
		}),
	)
	var recovery *AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentUnavailable) || recovery.Attempts != 1 {
		t.Fatalf("oversized retry delay = %#v, want one-attempt recovery", err)
	}
	if len(slept) != 0 || len(server.requestBodies()) != 1 {
		t.Fatalf("slept/requests = %v/%d, want none/1", slept, len(server.requestBodies()))
	}
}

func TestHubAssignmentTerminalResultWinsElapsedBudget(t *testing.T) {
	hub, transport, server := assignmentTestSetup(t, `{"errCode":"52201","errMsg":"identity rejected"}`)
	clockCalls := 0
	_, err := RefreshAgentAssignment(
		context.Background(), hub, "agent-conform", transport,
		WithAssignmentRetryBudget(4, 100*time.Millisecond),
		withAssignmentClock(func() time.Time {
			clockCalls++
			if clockCalls == 2 {
				return assignmentFixtureNow.Add(time.Second)
			}
			return assignmentFixtureNow
		}),
	)
	if !errors.Is(err, ErrAssignmentIdentityRejected) || errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("concurrent terminal result = %#v, want terminal identity rejection only", err)
	}
	if len(server.requestBodies()) != 1 {
		t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
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
	if !errors.As(err, &recovery) || !errors.Is(err, ErrAssignmentRecoveryRequired) || recovery.Attempts != 1 || recovery.Elapsed < 50*time.Millisecond {
		t.Fatalf("error = %#v, want one-attempt recovery-required", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("transaction took %s; retry budget did not bound the UDP receive", elapsed)
	}
	if len(server.requestBodies()) != 1 {
		t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
	}
}

func TestHubAssignmentParentCancellation(t *testing.T) {
	t.Run("in flight", func(t *testing.T) {
		hub, transport, server := assignmentTestSetup(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cancelled := make(chan struct{})
		timedOut := make(chan struct{}, 1)
		go func() {
			defer close(cancelled)
			select {
			case <-server.requestSeen:
				cancel()
			case <-time.After(time.Second):
				timedOut <- struct{}{}
				cancel()
			}
		}()

		_, err := RefreshAgentAssignment(
			ctx, hub, "agent-conform", transport,
			WithAssignmentRetryBudget(4, time.Minute),
		)
		<-cancelled
		select {
		case <-timedOut:
			t.Fatal("assignment server did not observe the in-flight request before timeout")
		default:
		}
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAssignmentRecoveryRequired) {
			t.Fatalf("in-flight cancellation error = %#v, want parent context.Canceled only", err)
		}
		if len(server.requestBodies()) != 1 {
			t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
		}
	})

	t.Run("during backoff", func(t *testing.T) {
		hub, transport, server := assignmentTestSetup(t, `{"errCode":"52200","errMsg":"temporary"}`)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := RefreshAgentAssignment(
			ctx, hub, "agent-conform", transport,
			WithAssignmentRetryBudget(4, time.Minute),
			fixedAssignmentClock(),
			zeroAssignmentJitter(),
			withAssignmentSleep(func(sleepCtx context.Context, _ time.Duration) error {
				cancel()
				return sleepCtx.Err()
			}),
		)
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAssignmentRecoveryRequired) {
			t.Fatalf("backoff cancellation error = %#v, want parent context.Canceled only", err)
		}
		if len(server.requestBodies()) != 1 {
			t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
		}
	})
}

func TestHubAssignmentSleepFailures(t *testing.T) {
	t.Run("transaction budget", func(t *testing.T) {
		hub, transport, server := assignmentTestSetup(t, `{"errCode":"52200","errMsg":"temporary"}`)
		_, err := RefreshAgentAssignment(
			context.Background(), hub, "agent-conform", transport,
			WithAssignmentRetryBudget(4, 50*time.Millisecond),
			fixedAssignmentClock(),
			zeroAssignmentJitter(),
			withAssignmentSleep(func(sleepCtx context.Context, _ time.Duration) error {
				<-sleepCtx.Done()
				return sleepCtx.Err()
			}),
		)
		var recovery *AssignmentRecoveryRequiredError
		if !errors.As(err, &recovery) || !errors.Is(err, context.DeadlineExceeded) || recovery.Attempts != 1 || recovery.Elapsed < 50*time.Millisecond {
			t.Fatalf("transaction-budget sleep error = %#v, want one-attempt recovery with deadline", err)
		}
		if len(server.requestBodies()) != 1 {
			t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
		}
	})

	t.Run("sleep implementation", func(t *testing.T) {
		hub, transport, server := assignmentTestSetup(t, `{"errCode":"52200","errMsg":"temporary"}`)
		sentinel := errors.New("injected sleep failure")
		_, err := RefreshAgentAssignment(
			context.Background(), hub, "agent-conform", transport,
			WithAssignmentRetryBudget(4, time.Minute),
			fixedAssignmentClock(),
			zeroAssignmentJitter(),
			withAssignmentSleep(func(context.Context, time.Duration) error { return sentinel }),
		)
		if !errors.Is(err, sentinel) || errors.Is(err, ErrAssignmentRecoveryRequired) {
			t.Fatalf("sleep implementation error = %#v, want sentinel only", err)
		}
		if len(server.requestBodies()) != 1 {
			t.Fatalf("requests = %d, want 1", len(server.requestBodies()))
		}
	})
}

func TestAssignmentConformanceSuccessRejectCases(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	executedByPhase := map[string]int{}
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
		executedByPhase[testCase.Phase]++
		t.Run(testCase.Name, func(t *testing.T) {
			if err := parse([]byte(testCase.BodyJSON)); !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
	if executedByPhase["initial_assignment"] == 0 || executedByPhase["refresh_assignment"] == 0 {
		t.Fatalf("conformance success-reject cases executed by phase = %v, want initial and refresh coverage", executedByPhase)
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
	executedErrors := 0
	for groupIndex, group := range groups {
		if len(group) == 0 {
			t.Fatalf("conformance error group %d is empty", groupIndex)
		}
		for _, testCase := range group {
			expected, ok := want[testCase.ErrCode]
			if !ok {
				t.Fatalf("conformance error case %q has unknown code %q", testCase.Name, testCase.ErrCode)
			}
			executedErrors++
			t.Run(testCase.Name, func(t *testing.T) {
				initial := testCase.Phase == "initial_assignment"
				_, err := parseAssignmentEnvelope([]byte(testCase.BodyJSON), initial)
				if !errors.Is(err, expected) || errors.Is(err, ErrAssignmentInvalidResponse) {
					t.Fatalf("error = %v, want %v only", err, expected)
				}
			})
		}
	}
	if executedErrors == 0 {
		t.Fatal("conformance error fixture executed no taxonomy cases")
	}
	executedMalformed := 0
	for _, testCase := range fixture.ErrorContract.MalformedCases {
		if testCase.Phase != "cell_assignment" && testCase.Phase != "initial_assignment" {
			continue
		}
		executedMalformed++
		t.Run(testCase.Name, func(t *testing.T) {
			_, err := parseAssignmentEnvelope([]byte(testCase.BodyJSON), testCase.Phase == "initial_assignment")
			if !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
	if executedMalformed == 0 {
		t.Fatal("conformance malformed fixture executed no assignment cases")
	}
}

func TestAssignmentInitialCredentialErrorsAreInvalidDuringRefresh(t *testing.T) {
	for _, code := range []string{"52106", "52107", "52108", "52109"} {
		t.Run(code, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"errCode":%q,"errMsg":"initial-only"}`, code))
			_, err := parseAssignmentEnvelope(body, false)
			if !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("refresh error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

func TestHubAssignmentRejectsInvalidInputsBeforeIO(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	validHub, validTransport, _ := assignmentTestSetup(t, fixture.InitialAssignment.Result.BodyJSON)
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
		{name: "low-order key", hub: HubBootstrap{Host: validHub.Host, Port: standardNHPUDPPort, ServerPublicKeyB64: lowOrderTestNHPServerPublicKeyB64}, agentID: "agent-conform", credential: "valid", transport: validTransport},
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
			if errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("config error leaked response sentinel: %v", err)
			}
		})
	}
}

func TestHubAssignmentRejectsOversizedEncodedCredentialBeforeIO(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	hub, transport, server := assignmentTestSetup(t, fixture.InitialAssignment.Result.BodyJSON)
	credentials := map[string]string{
		"long printable": strings.Repeat("a", nhpcontract.MaxApplicationBodySize),
		"JSON expanding": strings.Repeat(`"`, nhpcontract.MaxApplicationBodySize/2),
	}
	for name, credential := range credentials {
		t.Run(name, func(t *testing.T) {
			_, err := FetchInitialAgentAssignment(context.Background(), hub, "agent-conform", credential, transport)
			if !errors.Is(err, ErrInvalidAssignmentConfig) || errors.Is(err, nativeudp.ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidAssignmentConfig only", err)
			}
		})
	}
	if requests := server.requestBodies(); len(requests) != 0 {
		t.Fatalf("oversized requests reached I/O: %d", len(requests))
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
	var assertValueOnly func(string, reflect.Type)
	assertValueOnly = func(path string, valueType reflect.Type) {
		t.Helper()
		if valueType == reflect.TypeOf(time.Time{}) {
			return // time.Time is an immutable value despite its internal location pointer.
		}
		switch valueType.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer:
			t.Fatalf("%s has reference kind %s; update AgentAssignment.clone and its isolation test", path, valueType.Kind())
		case reflect.Array:
			assertValueOnly(path+"[]", valueType.Elem())
		case reflect.Struct:
			for i := range valueType.NumField() {
				field := valueType.Field(i)
				assertValueOnly(path+"."+field.Name, field.Type)
			}
		}
	}
	assertValueOnly("AgentAssignment", reflect.TypeOf(AgentAssignment{}))

	assignment := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 1,
		LeaseExpiresAt: assignmentFixtureNow.Add(time.Hour),
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: standardNHPUDPPort,
			ServerPublicKeyB64: validTestNHPServerPublicKeyB64,
		},
	}
	clone := assignment.clone()
	clone.CellID = "cell1"
	clone.Endpoint.Host = "cell1.nhp.layerv.ai"
	if assignment.CellID != "cell0" || assignment.Endpoint.Host != "cell0.nhp.layerv.ai" {
		t.Fatalf("clone mutated source: %#v", assignment)
	}
	if assignment.LeaseExpired(assignmentFixtureNow) || !assignment.LeaseExpired(assignment.LeaseExpiresAt) {
		t.Fatal("LeaseExpired boundary is wrong")
	}
	if err := assignment.Validate(assignment.LeaseExpiresAt); !errors.Is(err, ErrAssignmentLeaseExpired) || !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("expired assignment Validate error = %v, want lease-expired + invalid-response classes", err)
	}
	var absent *AgentAssignment
	if !absent.LeaseExpired(assignmentFixtureNow) {
		t.Fatal("nil assignment must be expired")
	}
}

func TestSameAgentAssignmentComparesLeaseInstant(t *testing.T) {
	base := &AgentAssignment{
		CellID: "cell0", AssignmentGeneration: 1, EndpointRevision: 2,
		LeaseExpiresAt: assignmentFixtureNow,
		Endpoint: NHPUDPEndpoint{
			Host: "cell0.nhp.layerv.ai", Port: 62206,
			ServerPublicKeyB64: validTestNHPServerPublicKeyB64,
		},
	}
	sameInstant := base.clone()
	sameInstant.LeaseExpiresAt = base.LeaseExpiresAt.In(time.FixedZone("same-instant", 3600))
	if !sameAgentAssignment(base, sameInstant) {
		t.Fatal("equal lease instants with different locations compared unequal")
	}

	changed := base.clone()
	changed.EndpointRevision++
	if sameAgentAssignment(base, changed) || sameAgentAssignment(base, nil) || sameAgentAssignment(nil, base) || !sameAgentAssignment(nil, nil) {
		t.Fatal("assignment field or nil difference compared equal")
	}
}

func TestPersistedAgentAssignmentTrustFieldsValidatedOnLoad(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply([]byte(fixture.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Assignment.Validate(assignmentFixtureNow); err != nil {
		t.Fatalf("fresh assignment Validate: %v", err)
	}

	newState := func(t *testing.T, assignment *AgentAssignment) *AgentState {
		t.Helper()
		state, err := newAgentState()
		if err != nil {
			t.Fatal(err)
		}
		state.AgentID = "agent-assignment-state"
		state.SchemaVersion = agentStateSchemaVersion
		state.Assignment = assignment
		return state
	}
	invalidAssignments := map[string]func(*AgentAssignment){
		"host outside LayerV apex": func(a *AgentAssignment) { a.Endpoint.Host = "attacker.example.com" },
		"low-order server key": func(a *AgentAssignment) {
			a.Endpoint.ServerPublicKeyB64 = lowOrderTestNHPServerPublicKeyB64
		},
		"invalid cell":      func(a *AgentAssignment) { a.CellID = "CELL0" },
		"zero generation":   func(a *AgentAssignment) { a.AssignmentGeneration = 0 },
		"zero endpoint rev": func(a *AgentAssignment) { a.EndpointRevision = 0 },
		"zero port":         func(a *AgentAssignment) { a.Endpoint.Port = 0 },
		"zero lease":        func(a *AgentAssignment) { a.LeaseExpiresAt = time.Time{} },
	}
	for _, factory := range localAgentStateStoreFactories() {
		storeName := factory.name
		newStore := func(t *testing.T) AgentStateStore {
			store, _ := factory.new(t)
			return store
		}
		for mutationName, mutate := range invalidAssignments {
			t.Run(storeName+"/"+mutationName, func(t *testing.T) {
				assignment := initial.Assignment.clone()
				mutate(assignment)
				store := newStore(t)
				if err := store.SaveAgentState(context.Background(), newState(t, assignment)); err != nil {
					t.Fatalf("persist malformed assignment fixture: %v", err)
				}
				if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrInvalidAgentState) {
					t.Fatalf("LoadAgentState error = %v, want ErrInvalidAgentState", err)
				}
			})
		}

		t.Run(storeName+"/expired lease remains refreshable", func(t *testing.T) {
			assignment := initial.Assignment.clone()
			assignment.LeaseExpiresAt = assignmentFixtureNow.Add(-time.Second)
			store := newStore(t)
			if err := store.SaveAgentState(context.Background(), newState(t, assignment)); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.LoadAgentState(context.Background())
			if err != nil || loaded.Assignment == nil || !loaded.Assignment.LeaseExpired(assignmentFixtureNow) {
				t.Fatalf("expired assignment load = %#v, %v", loaded, err)
			}
			if err := loaded.Assignment.Validate(assignmentFixtureNow); !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("expired assignment Validate = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

func TestAgentAssignmentDecodedServerKeyRevalidatesState(t *testing.T) {
	fixture := loadAssignmentFixture(t)
	initial, err := parseInitialAssignmentReply([]byte(fixture.InitialAssignment.Result.BodyJSON), "agent-conform", assignmentFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := initial.Assignment.DecodedServerKey()
	if err != nil {
		t.Fatalf("DecodedServerKey: %v", err)
	}
	if want := assignmentHex(t, fixture.Keys.AssignedCell.StaticPubHex); !bytes.Equal(decoded, want) {
		t.Fatalf("decoded server key = %x, want %x", decoded, want)
	}

	tampered := initial.Assignment
	tampered.Endpoint.ServerPublicKeyB64 = lowOrderTestNHPServerPublicKeyB64
	if _, err := tampered.DecodedServerKey(); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("tampered persisted key error = %v, want ErrAssignmentInvalidResponse", err)
	}
	var absent *AgentAssignment
	if _, err := absent.DecodedServerKey(); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("nil assignment key error = %v, want ErrAssignmentInvalidResponse", err)
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

func TestParseCanonicalRFC3339PinsProducerSpelling(t *testing.T) {
	canonical := "2026-07-15T23:30:00Z"
	parsed, err := parseCanonicalRFC3339(canonical)
	if err != nil || parsed.Format(time.RFC3339) != canonical {
		t.Fatalf("canonical timestamp = %s, %v; want %s", parsed, err, canonical)
	}
	for name, value := range map[string]string{
		"numeric zero offset": "2026-07-15T23:30:00+00:00",
		"fractional seconds":  "2026-07-15T23:30:00.123Z",
		"non-UTC offset":      "2026-07-15T17:30:00-06:00",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCanonicalRFC3339(value); err == nil {
				t.Fatalf("non-canonical timestamp %q accepted", value)
			}
		})
	}
}

func TestExactObjectFieldsRejectsNestedDuplicateAndTrailing(t *testing.T) {
	for _, raw := range []string{
		`{"key":1,"key":2}`,
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
	if _, err := parseAssignmentEnvelope([]byte(`{"errCode":"0","list":{},"extra":true}`), false); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("success envelope unknown-field error = %v, want ErrAssignmentInvalidResponse", err)
	}
}

func TestAssignmentErrorRejectsNullDiagnostic(t *testing.T) {
	if _, err := parseAssignmentEnvelope([]byte(`{"errCode":"52201","errMsg":null}`), false); !errors.Is(err, ErrAssignmentInvalidResponse) {
		t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
	}
}

func TestAssignmentErrorRejectsInvalidUTF8Diagnostic(t *testing.T) {
	body := append([]byte(`{"errCode":"52201","errMsg":"`), 0xff)
	body = append(body, []byte(`"}`)...)
	if _, err := parseAssignmentEnvelope(body, false); !errors.Is(err, ErrAssignmentInvalidResponse) || errors.Is(err, ErrAssignmentIdentityRejected) {
		t.Fatalf("error = %v, want ErrAssignmentInvalidResponse only", err)
	}
}

func TestAssignmentErrorsNeverRetainOrRenderProducerControlledSecrets(t *testing.T) {
	const reflectedSecret = "lv_live_reflected_enrollment_credential"
	_, err := parseAssignmentEnvelope([]byte(`{"errCode":"52201","errMsg":"`+reflectedSecret+`"}`), false)
	var assignmentErr *AssignmentError
	if !errors.As(err, &assignmentErr) || !errors.Is(err, ErrAssignmentIdentityRejected) {
		t.Fatalf("known assignment error = %T: %v", err, err)
	}
	if strings.Contains(err.Error(), reflectedSecret) || strings.Contains(fmt.Sprintf("%#v", assignmentErr), reflectedSecret) {
		t.Fatalf("known assignment error retained/reflected Hub diagnostic: %#v", assignmentErr)
	}

	const unsafeCode = "lv_live_reflected_as_error_code"
	_, err = parseAssignmentEnvelope([]byte(`{"errCode":"`+unsafeCode+`","errMsg":"ignored"}`), false)
	if !errors.Is(err, ErrAssignmentInvalidResponse) || strings.Contains(err.Error(), unsafeCode) {
		t.Fatalf("unknown assignment code = %v, want redacted invalid response", err)
	}
}

func TestAssignmentTicketMatchesReleasedConformanceBoundary(t *testing.T) {
	ticketArtifact, err := conformance.AssignmentTicket()
	if err != nil {
		t.Fatalf("load assignment-ticket conformance: %v", err)
	}
	if maxAssignmentTicketBytes != ticketArtifact.Contract.MaxTicketASCIIBytes {
		t.Fatalf("SDK ticket limit = %d, released conformance limit = %d", maxAssignmentTicketBytes, ticketArtifact.Contract.MaxTicketASCIIBytes)
	}

	maxTicket := "!" + strings.Repeat("~", maxAssignmentTicketBytes-1)
	if err := validateOpaqueAssignmentTicket(maxTicket); err != nil {
		t.Fatalf("exact-max printable ticket rejected: %v", err)
	}
	if err := validateOpaqueAssignmentTicket(maxTicket + "!"); err == nil {
		t.Fatal("max+1 ticket accepted")
	}

	for name, ticket := range map[string]string{
		"space":     "qat1 bad",
		"control":   "qat1\x1f",
		"delete":    "qat1\x7f",
		"non_ascii": "qat1.é",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOpaqueAssignmentTicket(ticket); err == nil {
				t.Fatalf("non-printable-ASCII ticket %q accepted", ticket)
			}
		})
	}
}
