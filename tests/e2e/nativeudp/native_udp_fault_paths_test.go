package nativeudp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	// The native lifecycle only ever speaks to UDP 443; a fault proof that
	// targeted any other port would pass for the wrong reason.
	standardNHPUDPPort             = 443
	faultUDPAttemptTimeout         = 5 * time.Second
	currentAgentStateSchemaVersion = 7
	nonSecretFaultCredential       = "not-server-minted-native-udp-proof-credential"
)

// Keep tests that install lifecycleHTTPTrap serial: they temporarily replace
// process-wide net/http defaults to prove that the native lifecycle uses no HTTP.
var errLifecycleHTTP = errors.New("native lifecycle attempted forbidden HTTP")

type lifecycleHTTPTrap struct {
	calls atomic.Int64
	mu    sync.Mutex
	first string
}

type failureResolver struct {
	calls atomic.Int64
	mu    sync.Mutex
	host  string
	net   string
}

func (r *failureResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.net, r.host = network, host
	r.mu.Unlock()
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *failureResolver) snapshot() (int64, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls.Load(), r.net, r.host
}

type fixedResolver struct {
	address netip.Addr
	calls   atomic.Int64
	mu      sync.Mutex
	host    string
	net     string
}

func (r *fixedResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.net, r.host = network, host
	r.mu.Unlock()
	return []netip.Addr{r.address}, nil
}

func (r *fixedResolver) snapshot() (int64, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls.Load(), r.net, r.host
}

type redirectingDialer struct {
	target string
	calls  atomic.Int64
	mu     sync.Mutex
	net    string
	addr   string
}

func (d *redirectingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.net, d.addr = network, address
	d.mu.Unlock()
	if d.target == "" {
		return nil, errors.New("unexpected native UDP dial")
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *redirectingDialer) snapshot() (int64, string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls.Load(), d.net, d.addr
}

func (t *lifecycleHTTPTrap) Do(request *http.Request) (*http.Response, error) {
	return nil, t.reject(request)
}

func (t *lifecycleHTTPTrap) RoundTrip(request *http.Request) (*http.Response, error) {
	return nil, t.reject(request)
}

func (t *lifecycleHTTPTrap) reject(request *http.Request) error {
	call := t.calls.Add(1)
	t.mu.Lock()
	if t.first == "" {
		t.first = request.Method + " " + request.URL.Scheme + "://" + request.URL.Host + request.URL.EscapedPath()
	}
	t.mu.Unlock()
	return fmt.Errorf("%w (call %d)", errLifecycleHTTP, call)
}

func (t *lifecycleHTTPTrap) snapshot() (int64, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls.Load(), t.first
}

func installLifecycleHTTPTrap(t *testing.T) *lifecycleHTTPTrap {
	t.Helper()
	trap := &lifecycleHTTPTrap{}
	previousDefaultClient := http.DefaultClient
	previousDefaultTransport := http.DefaultTransport
	http.DefaultClient = &http.Client{Transport: trap}
	http.DefaultTransport = trap
	t.Cleanup(func() {
		http.DefaultClient = previousDefaultClient
		http.DefaultTransport = previousDefaultTransport
		assertNoLifecycleHTTP(t, trap)
	})
	return trap
}

func TestNativeUDPClientFaultPaths(t *testing.T) {
	hub := qurl.HubBootstrap{
		Host:               "hub.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
	httpTrap := installLifecycleHTTPTrap(t)
	t.Run("hub_dns_failure", func(t *testing.T) {
		proveHubDNSFailure(t.Context(), t, hub, httpTrap)
	})
	t.Run("packet_timeout", func(t *testing.T) {
		provePacketTimeout(t.Context(), t, hub, httpTrap)
	})
	t.Run("wrong_hub_key", func(t *testing.T) {
		proveWrongHubKey(t.Context(), t, httpTrap)
	})
	t.Run("wrong_cell_key", func(t *testing.T) {
		proveWrongCellKey(t.Context(), t, httpTrap)
	})
	t.Run("oversize_packet", func(t *testing.T) {
		provePacketOversize(t.Context(), t, httpTrap)
	})
	t.Run("cell_dns_failure", func(t *testing.T) {
		proveCellDNSFailure(t.Context(), t, httpTrap)
	})
	t.Run("remaining_phase_timeouts", func(t *testing.T) {
		provePacketRemainingPhaseTimeouts(t.Context(), t, httpTrap)
	})
	t.Run("malformed_packet", func(t *testing.T) {
		provePacketMalformed(t.Context(), t, httpTrap)
	})
	t.Run("packet_duplicate", func(t *testing.T) {
		provePacketDuplicate(t.Context(), t, httpTrap)
	})
	t.Run("hub_dns_address_refresh", func(t *testing.T) {
		proveHubDNSAddressRefresh(t.Context(), t, httpTrap)
	})
	t.Run("cell_dns_address_refresh", func(t *testing.T) {
		proveCellDNSAddressRefresh(t.Context(), t, httpTrap)
	})
	t.Run("multi_address_ipv4_ipv6_bounds", func(t *testing.T) {
		proveMultiAddressBounds(t.Context(), t, httpTrap)
	})
	t.Run("packet_cancellation", func(t *testing.T) {
		provePacketCancellation(t.Context(), t, httpTrap)
	})
	t.Run("packet_loss", func(t *testing.T) {
		provePacketLoss(t.Context(), t, httpTrap)
	})
	t.Run("packet_delay", func(t *testing.T) {
		provePacketDelay(t.Context(), t, httpTrap)
	})
	t.Run("packet_replay", func(t *testing.T) {
		provePacketReplay(t.Context(), t, httpTrap)
	})
	t.Run("packet_reorder", func(t *testing.T) {
		provePacketReorder(t.Context(), t, httpTrap)
	})
	t.Run("unknown_message", func(t *testing.T) {
		provePacketUnknownMessage(t.Context(), t, httpTrap)
	})
	t.Run("public_resource_and_knock_resource_id_wire_distinction", func(t *testing.T) {
		provePublicResourceAndKnockResourceIDWireDistinction(t.Context(), t, httpTrap)
	})
	t.Run("hub_cookie_proof_lst_return_routability", func(t *testing.T) {
		proveHubCookieProofRoutability(t.Context(), t, httpTrap)
	})
	t.Run("assigned_cell_cookie_reknock_return_routability", func(t *testing.T) {
		proveCellCookieReknockRoutability(t.Context(), t, httpTrap)
	})
	t.Run("authenticated_invalid_assignment_matrix", func(t *testing.T) {
		proveAuthenticatedInvalidAssignmentMatrix(t.Context(), t, httpTrap)
	})
}

func proveHubDNSFailure(ctx context.Context, t *testing.T, hub qurl.HubBootstrap, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const agentID = "qurl-go-fault-proof-dns"
	store := faultStateStore(t)
	resolver := &failureResolver{}
	dialer := &redirectingDialer{}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store, //nolint:staticcheck // deliberately exercises the deprecated wrapper: ConnectAgentRuntime supersedes it, but the compatibility path must keep working.
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "dns-failure"),
		qurl.WithAgentRuntimeUDPResolver(resolver),
		qurl.WithAgentRuntimeUDPDialer(dialer),
		qurl.WithAgentRuntimeUDPBounds(faultUDPAttemptTimeout, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(1, 15*time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	var recovery *qurl.AssignmentRecoveryRequiredError
	classified := client == nil && !bindingNonNil && errors.As(err, &recovery) &&
		errors.Is(err, qurl.ErrAssignmentRecoveryRequired) && errors.Is(err, nativeudp.ErrResolve) &&
		!errors.Is(err, nativeudp.ErrTransport) && recovery.Attempts == 1
	if !classified {
		t.Fatalf("Hub DNS failure classification mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t recovery=%t assignment_recovery=%t resolve=%t transport=%t attempts=%d",
			err,
			client != nil, bindingNonNil, errors.As(err, &recovery), errors.Is(err, qurl.ErrAssignmentRecoveryRequired),
			errors.Is(err, nativeudp.ErrResolve), errors.Is(err, nativeudp.ErrTransport), recoveryAttempts(recovery))
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("Hub DNS failure reflected the enrollment credential")
	}
	resolverCalls, network, host := resolver.snapshot()
	if resolverCalls != 1 || network != "ip" || host != hub.Host {
		t.Fatalf("Hub DNS lookup = calls=%d network=%q host=%q; want 1, ip, %q", resolverCalls, network, host, hub.Host)
	}
	if calls, network, address := dialer.snapshot(); calls != 0 {
		t.Fatalf("Hub DNS failure dialed a fallback: calls=%d network=%q address=%q", calls, network, address)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "hub_dns_failure")
	assertNoLifecycleHTTP(t, httpTrap)
	t.Log("EVIDENCE hub_dns_failure attempts=1 resolver_calls=1 dial_calls=0 lifecycle_http_calls=0")
}

func provePacketTimeout(ctx context.Context, t *testing.T, hub qurl.HubBootstrap, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const (
		agentID        = "qurl-go-fault-proof-timeout"
		attemptTimeout = 250 * time.Millisecond
	)
	store := faultStateStore(t)
	listener := startUDPBlackhole(t)
	resolver := &fixedResolver{address: netip.MustParseAddr("8.8.8.8")}
	dialer := &redirectingDialer{target: listener.LocalAddr().String()}
	timeoutHub := hub
	timeoutHub.Host = "timeout-proof.nhp.layerv.ai"
	started := time.Now()
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store, //nolint:staticcheck // deliberately exercises the deprecated wrapper: ConnectAgentRuntime supersedes it, but the compatibility path must keep working.
		qurl.WithAgentRuntimeHub(timeoutHub),
		qurl.WithAgentRuntimeIdentity(agentID),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
		qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", "packet-timeout"),
		qurl.WithAgentRuntimeUDPResolver(resolver),
		qurl.WithAgentRuntimeUDPDialer(dialer),
		qurl.WithAgentRuntimeUDPBounds(attemptTimeout, 1),
		qurl.WithAgentRuntimeAssignmentRetryBudget(1, time.Second),
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	elapsed := time.Since(started)
	bindingNonNil := binding != nil
	if binding != nil {
		binding.Destroy()
	}
	var recovery *qurl.AssignmentRecoveryRequiredError
	var netErr net.Error
	classified := client == nil && !bindingNonNil && errors.As(err, &recovery) &&
		errors.Is(err, qurl.ErrAssignmentRecoveryRequired) && errors.Is(err, nativeudp.ErrTransport) &&
		!errors.Is(err, nativeudp.ErrResolve) && errors.As(err, &netErr) && netErr.Timeout() &&
		recovery.Attempts == 1 && elapsed >= attemptTimeout/2
	if !classified {
		t.Fatalf("UDP timeout classification mismatch: error_type=%T client_non_nil=%t binding_non_nil=%t recovery=%t assignment_recovery=%t transport=%t resolve=%t net_timeout=%t attempts=%d elapsed_at_least_half_timeout=%t",
			err,
			client != nil, bindingNonNil, errors.As(err, &recovery), errors.Is(err, qurl.ErrAssignmentRecoveryRequired),
			errors.Is(err, nativeudp.ErrTransport), errors.Is(err, nativeudp.ErrResolve), netErr != nil && netErr.Timeout(),
			recoveryAttempts(recovery), elapsed >= attemptTimeout/2)
	}
	if strings.Contains(err.Error(), nonSecretFaultCredential) {
		t.Fatal("UDP timeout reflected the enrollment credential")
	}
	resolverCalls, resolverNetwork, resolverHost := resolver.snapshot()
	if resolverCalls != 1 || resolverNetwork != "ip" || resolverHost != timeoutHub.Host {
		t.Fatalf("timeout DNS lookup = calls=%d network=%q host=%q; want 1, ip, %q", resolverCalls, resolverNetwork, resolverHost, timeoutHub.Host)
	}
	dialCalls, dialNetwork, dialAddress := dialer.snapshot()
	wantAddress := net.JoinHostPort(resolver.address.String(), fmt.Sprint(standardNHPUDPPort))
	if dialCalls != 1 || dialNetwork != "udp" || dialAddress != wantAddress {
		t.Fatalf("timeout logical dial = calls=%d network=%q address=%q; want 1, udp, %q", dialCalls, dialNetwork, dialAddress, wantAddress)
	}
	datagrams, bytes := drainUDPBlackhole(t, listener)
	if datagrams != 1 {
		t.Fatalf("UDP timeout emitted %d datagrams, want exactly 1 for one bounded address attempt", datagrams)
	}
	assertInitialIdentityOnly(ctx, t, store, agentID, "packet_timeout")
	assertNoLifecycleHTTP(t, httpTrap)
	t.Logf("EVIDENCE packet_timeout attempts=1 resolver_calls=1 dial_calls=1 udp_datagrams=%d udp_bytes=%d lifecycle_http_calls=0", datagrams, bytes)
}

func recoveryAttempts(recovery *qurl.AssignmentRecoveryRequiredError) int {
	if recovery == nil {
		return 0
	}
	return recovery.Attempts
}

func faultStateStore(t *testing.T) qurl.AgentStateStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("secure fault-state directory: %v", err)
	}
	return qurl.FileAgentState(filepath.Join(dir, "agent-state.json"))
}

func assertInitialIdentityOnly(ctx context.Context, t *testing.T, store qurl.AgentStateStore, agentID, phase string) {
	t.Helper()
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		t.Fatalf("%s load state: %v", phase, err)
	}
	if state.AgentID != agentID || state.PrivateKeyB64 == "" || state.PublicKeyB64 == "" ||
		state.SchemaVersion != currentAgentStateSchemaVersion || state.RegisteredAt != nil || state.Assignment != nil || state.DeviceAPIKeyID != "" ||
		state.DeviceAPIKey != "" || state.PendingActivation != nil || state.PendingCompletion != nil {
		t.Fatalf("%s initial-state invariant failed: agent_id_match=%t private_key_present=%t public_key_present=%t schema_version=%d registered=%t assignment_present=%t device_api_key_id_present=%t device_api_key_present=%t pending_activation=%t pending_completion=%t",
			phase,
			state.AgentID == agentID,
			state.PrivateKeyB64 != "",
			state.PublicKeyB64 != "",
			state.SchemaVersion,
			state.RegisteredAt != nil,
			state.Assignment != nil,
			state.DeviceAPIKeyID != "",
			state.DeviceAPIKey != "",
			state.PendingActivation != nil,
			state.PendingCompletion != nil,
		)
	}
}

func assertNoLifecycleHTTP(t *testing.T, trap *lifecycleHTTPTrap) {
	t.Helper()
	if calls, first := trap.snapshot(); calls != 0 {
		t.Fatalf("native lifecycle made %d forbidden HTTP call(s); first=%q", calls, first)
	}
}

func startUDPBlackhole(t *testing.T) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind ephemeral UDP blackhole: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func drainUDPBlackhole(t *testing.T, listener *net.UDPConn) (int, int) {
	t.Helper()
	buffer := make([]byte, 64*1024)
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set initial UDP blackhole read deadline: %v", err)
	}
	bytes, _, err := listener.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read timed-out UDP request from blackhole: %v", err)
	}
	datagrams := 1
	totalBytes := bytes
	for {
		if err := listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatalf("set UDP blackhole drain deadline: %v", err)
		}
		bytes, _, err = listener.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return datagrams, totalBytes
			}
			t.Fatalf("drain UDP blackhole: %v", err)
		}
		datagrams++
		totalBytes += bytes
	}
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
