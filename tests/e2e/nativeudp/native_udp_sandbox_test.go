package nativeudp_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
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
	sandboxProofTimeout            = 50 * time.Minute
	faultUDPAttemptTimeout         = 5 * time.Second
	currentAgentStateSchemaVersion = 6
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

type osFailureResolver struct {
	calls atomic.Int64
	mu    sync.Mutex
	host  string
	net   string
}

func (r *osFailureResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.net, r.host = network, host
	r.mu.Unlock()
	return net.DefaultResolver.LookupNetIP(ctx, network, "qurl-native-udp-proof.invalid")
}

func (r *osFailureResolver) snapshot() (int64, string, string) {
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

type sandboxProofProvenance struct {
	SchemaVersion int                   `json:"schema_version"`
	BuildSHA      string                `json:"build_sha"`
	AgentID       string                `json:"agent_id"`
	Hub           sandboxHubEvidence    `json:"hub"`
	AssignedCells []sandboxCellEvidence `json:"assigned_cells"`
}

type sandboxHubEvidence struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
}

type sandboxCellEvidence struct {
	Phase                 string `json:"phase"`
	CellID                string `json:"cell_id"`
	AssignmentGeneration  int64  `json:"assignment_generation"`
	EndpointRevision      int64  `json:"endpoint_revision"`
	LeaseExpiresAt        string `json:"lease_expires_at"`
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
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

func TestSandboxNativeUDPLifecycle(t *testing.T) {
	cfg, enabled, err := loadSandboxConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("attended proof only; set QURL_GO_SANDBOX_STRICT=true to require live sandbox execution")
	}

	httpTrap := &lifecycleHTTPTrap{}
	previousDefaultClient := http.DefaultClient
	previousDefaultTransport := http.DefaultTransport
	http.DefaultClient = &http.Client{Transport: httpTrap}
	http.DefaultTransport = httpTrap
	t.Cleanup(func() {
		http.DefaultClient = previousDefaultClient
		http.DefaultTransport = previousDefaultTransport
		calls, first := httpTrap.snapshot()
		if calls != 0 {
			t.Errorf("native lifecycle made %d forbidden HTTP call(s); first=%q", calls, first)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), sandboxProofTimeout)
	defer cancel()

	hub := qurl.HubBootstrap{
		Host:               cfg.hubHost,
		Port:               cfg.hubPort,
		ServerPublicKeyB64: cfg.hubServerKeyB64,
	}
	store := qurl.FileAgentState(cfg.statePath)
	for name, path := range map[string]string{statePathEnv: cfg.statePath, provenancePathEnv: cfg.provenancePath} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("strict proof requires a fresh path but %s already exists", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect fresh %s: %v", name, err)
		}
	}
	t.Cleanup(func() { cleanupSandboxProofFiles(cfg) })

	if !runTypedEvidenceScenario(t, "provenance_and_hub_trust", "provenance.exact_build_and_hub_trust", []string{"build_provenance"}, func(t *testing.T) {
		assertBuildProvenance(t, cfg.buildSHA)
		t.Logf("EVIDENCE build_sha=%s hub_host=%s hub_port=%d hub_server_public_key_b64=%s agent_id=%s",
			cfg.buildSHA, hub.Host, hub.Port, hub.ServerPublicKeyB64, cfg.agentID)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "hub_dns_failure", "negative.hub_dns_failure", []string{"rejection_observation"}, func(t *testing.T) {
		proveHubDNSFailure(ctx, t, hub, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_timeout", "packet.hub_first_lst_timeout", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketTimeout(ctx, t, hub, httpTrap)
	}) {
		return
	}

	cellEvidence := make([]sandboxCellEvidence, 0, 3)
	// Happy-path lifecycle calls deliberately omit UDP and retry overrides so
	// the deployed proof measures the SDK's out-of-box production defaults.
	if !runTypedEvidenceScenario(t, "fresh_registration_via_hub_and_assigned_cell", "registration.public_api_lifecycle_success", []string{"lifecycle_exchange"}, func(t *testing.T) {
		client, binding, err := qurl.RegisterAgentRuntime(ctx, cfg.enrollment, store,
			qurl.WithAgentRuntimeHub(hub),
			qurl.WithAgentRuntimeIdentity(cfg.agentID),
			qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", cfg.buildSHA),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RegisterAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RegisterAgentRuntime returned a nil client or binding")
		}
		defer binding.Destroy()
		cellEvidence = append(cellEvidence, assertAssignedCell(t, cfg, binding, "registration"))
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "persisted_runtime_warm_open", "state.persisted_runtime_warm_open", []string{"state_observation"}, func(t *testing.T) {
		client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("OpenRegisteredAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("OpenRegisteredAgentRuntime returned a nil client or binding")
		}
		defer binding.Destroy()
		cellEvidence = append(cellEvidence, assertAssignedCell(t, cfg, binding, "warm_open"))
	}) {
		return
	}

	var refreshed *qurl.AgentRuntimeBinding
	refreshPassed := runTypedEvidenceScenario(t, "authenticated_hub_refresh", "assignment.authenticated_refresh", []string{"assignment_response"}, func(t *testing.T) {
		client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
			qurl.WithAgentRuntimeReassignmentAdoption(),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RefreshAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RefreshAgentRuntime returned a nil client or binding")
		}
		refreshed = binding
		cellEvidence = append(cellEvidence, assertAssignedCell(t, cfg, binding, "refresh"))
	})
	if refreshed != nil {
		defer refreshed.Destroy()
	}
	if !refreshPassed {
		return
	}

	privateKey := refreshed.TakeDeviceStaticPrivateKey()
	if len(privateKey) != x25519PublicKeyLength {
		wipe(privateKey)
		t.Fatalf("refreshed runtime private key length = %d, want %d", len(privateKey), x25519PublicKeyLength)
	}
	defer wipe(privateKey)
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		t.Fatalf("NewCycleRunID: %v", err)
	}
	knockOptions := qurl.NativeKnockOptions{RunID: runID}

	if !runTypedEvidenceScenario(t, "assigned_cell_knock", "session.public_api_knock_success", []string{"lifecycle_exchange"}, func(t *testing.T) {
		result, err := qurl.KnockRegisteredAgent(ctx, refreshed, privateKey, cfg.knockResourceID, knockOptions)
		if err != nil {
			t.Fatalf("KnockRegisteredAgent: %v", err)
		}
		if result == nil || result.ACToken == "" || result.ResourceHost == "" {
			t.Fatal("KnockRegisteredAgent returned incomplete authenticated admission")
		}
		t.Logf("EVIDENCE knock_resource_host=%s knock_open_time=%d", result.ResourceHost, result.OpenTime)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "assigned_cell_clean_exit", "session.public_api_exit_success", []string{"lifecycle_exchange"}, func(t *testing.T) {
		if err := qurl.ExitRegisteredAgentSession(ctx, refreshed, privateKey, cfg.knockResourceID, knockOptions); err != nil {
			t.Fatalf("ExitRegisteredAgentSession: %v", err)
		}
		t.Log("EVIDENCE assigned-cell EXT received an authenticated ACK")
	}) {
		return
	}

	runTypedEvidenceScenario(t, "zero_lifecycle_http", "transport.zero_http_injected_trap", []string{"transport_capture"}, func(t *testing.T) {
		calls, first := httpTrap.snapshot()
		if calls != 0 {
			t.Fatalf("native lifecycle made %d forbidden HTTP call(s); first=%q", calls, first)
		}
		writeSandboxProvenance(t, cfg, hub, cellEvidence)
		t.Log("EVIDENCE lifecycle_http_calls=0")
	})
}

func TestNativeUDPClientFaultPaths(t *testing.T) {
	hub := qurl.HubBootstrap{
		Host:               "hub.nhp.layerv.ai",
		Port:               standardNHPUDPPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
	httpTrap := &lifecycleHTTPTrap{}
	previousDefaultClient := http.DefaultClient
	previousDefaultTransport := http.DefaultTransport
	http.DefaultClient = &http.Client{Transport: httpTrap}
	http.DefaultTransport = httpTrap
	t.Cleanup(func() {
		http.DefaultClient = previousDefaultClient
		http.DefaultTransport = previousDefaultTransport
		assertNoLifecycleHTTP(t, httpTrap)
	})
	t.Run("hub_dns_failure", func(t *testing.T) {
		proveHubDNSFailure(t.Context(), t, hub, httpTrap)
	})
	t.Run("packet_timeout", func(t *testing.T) {
		provePacketTimeout(t.Context(), t, hub, httpTrap)
	})
	assertNoLifecycleHTTP(t, httpTrap)
}

func TestSandboxProofProvenanceIsAllowlisted(t *testing.T) {
	serverKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	cfg := sandboxConfig{
		buildSHA:       strings.Repeat("a", 40),
		agentID:        "qurl-go-proof-provenance",
		provenancePath: filepath.Join(t.TempDir(), "provenance.json"),
	}
	hub := qurl.HubBootstrap{Host: "hub.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: serverKey}
	cells := []sandboxCellEvidence{{
		Phase:                 "registration",
		CellID:                "cell0",
		AssignmentGeneration:  1,
		EndpointRevision:      2,
		LeaseExpiresAt:        "2026-07-22T12:00:00Z",
		Host:                  "cell0.nhp.layerv.ai",
		Port:                  standardNHPUDPPort,
		ServerPublicKeySHA256: publicKeySHA256(t, serverKey),
	}}
	writeSandboxProvenance(t, cfg, hub, cells)

	raw, err := os.ReadFile(cfg.provenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), serverKey) || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "credential") {
		t.Fatalf("provenance retained raw key or credential-shaped data: %s", raw)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var got sandboxProofProvenance
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.BuildSHA != cfg.buildSHA || got.AgentID != cfg.agentID || got.Hub.Host != hub.Host || len(got.AssignedCells) != 1 {
		t.Fatalf("provenance mismatch: %#v", got)
	}
	info, err := os.Stat(cfg.provenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("provenance mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCleanupSandboxProofFiles(t *testing.T) {
	directory := t.TempDir()
	cfg := sandboxConfig{
		statePath:      filepath.Join(directory, "agent-state.json"),
		provenancePath: filepath.Join(directory, "provenance.json"),
	}
	paths := []string{cfg.statePath, cfg.statePath + ".lock", cfg.provenancePath, cfg.provenancePath + ".tmp"}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("proof-test"), 0o600); err != nil {
			t.Fatalf("create cleanup fixture %s: %v", filepath.Base(path), err)
		}
	}

	cleanupSandboxProofFiles(cfg)

	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cleanup left %s: %v", filepath.Base(path), err)
		}
	}
}

func proveHubDNSFailure(ctx context.Context, t *testing.T, hub qurl.HubBootstrap, httpTrap *lifecycleHTTPTrap) {
	t.Helper()
	const agentID = "qurl-go-fault-proof-dns"
	store := faultStateStore(t)
	resolver := &osFailureResolver{}
	dialer := &redirectingDialer{}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeIdentity(agentID),
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
	client, binding, err := qurl.RegisterAgentRuntime(ctx, nonSecretFaultCredential, store,
		qurl.WithAgentRuntimeHub(timeoutHub),
		qurl.WithAgentRuntimeIdentity(agentID),
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

func cleanupSandboxProofFiles(cfg sandboxConfig) {
	for _, path := range [...]string{
		cfg.provenancePath + ".tmp",
		cfg.provenancePath,
		cfg.statePath + ".lock",
		cfg.statePath,
	} {
		_ = os.Remove(path)
	}
}

func assertBuildProvenance(t *testing.T, expected string) {
	t.Helper()
	revision := gitOutput(t, "rev-parse", "HEAD")
	if revision != expected {
		t.Fatalf("tested build revision = %q, want exact workflow SHA %q", revision, expected)
	}
	if status := gitOutput(t, "status", "--short", "--untracked-files=all"); status != "" {
		t.Fatalf("tested source checkout is not clean:\n%s", status)
	}
}

func gitOutput(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func assertAssignedCell(t *testing.T, cfg sandboxConfig, binding *qurl.AgentRuntimeBinding, phase string) sandboxCellEvidence {
	t.Helper()
	if binding.AgentID != cfg.agentID {
		t.Fatalf("%s agent id = %q, want %q", phase, binding.AgentID, cfg.agentID)
	}
	if cfg.expectedCellID != "" && binding.CellID != cfg.expectedCellID {
		t.Fatalf("%s assigned cell = %q, want operator-pinned %q", phase, binding.CellID, cfg.expectedCellID)
	}
	if binding.CellID == "" || binding.AssignmentGeneration < 1 || binding.EndpointRevision < 1 ||
		binding.NHPUDPEndpoint.Host == "" || binding.NHPUDPEndpoint.Port < 1 || binding.NHPUDPEndpoint.ServerPublicKeyB64 == "" {
		t.Fatalf("%s returned incomplete assigned-cell trust binding: %v", phase, binding)
	}
	t.Logf("EVIDENCE phase=%s cell_id=%s assignment_generation=%d endpoint_revision=%d lease_expires_at=%s nhp_host=%s nhp_port=%d server_public_key_b64=%s",
		phase,
		binding.CellID,
		binding.AssignmentGeneration,
		binding.EndpointRevision,
		binding.LeaseExpiresAt.UTC().Format(time.RFC3339Nano),
		binding.NHPUDPEndpoint.Host,
		binding.NHPUDPEndpoint.Port,
		binding.NHPUDPEndpoint.ServerPublicKeyB64,
	)
	return sandboxCellEvidence{
		Phase:                 phase,
		CellID:                binding.CellID,
		AssignmentGeneration:  binding.AssignmentGeneration,
		EndpointRevision:      binding.EndpointRevision,
		LeaseExpiresAt:        binding.LeaseExpiresAt.UTC().Format(time.RFC3339Nano),
		Host:                  binding.NHPUDPEndpoint.Host,
		Port:                  binding.NHPUDPEndpoint.Port,
		ServerPublicKeySHA256: publicKeySHA256(t, binding.NHPUDPEndpoint.ServerPublicKeyB64),
	}
}

func writeSandboxProvenance(t *testing.T, cfg sandboxConfig, hub qurl.HubBootstrap, cells []sandboxCellEvidence) {
	t.Helper()
	if len(cells) == 0 {
		t.Fatal("refuse to write sandbox provenance without an authenticated assigned-cell observation")
	}
	evidence := sandboxProofProvenance{
		SchemaVersion: 1,
		BuildSHA:      cfg.buildSHA,
		AgentID:       cfg.agentID,
		Hub: sandboxHubEvidence{
			Host:                  hub.Host,
			Port:                  hub.Port,
			ServerPublicKeySHA256: publicKeySHA256(t, hub.ServerPublicKeyB64),
		},
		AssignedCells: cells,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal sandbox provenance: %v", err)
	}
	temporary := cfg.provenancePath + ".tmp"
	t.Cleanup(func() { _ = os.Remove(temporary) })
	if err := os.WriteFile(temporary, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sandbox provenance: %v", err)
	}
	if err := os.Rename(temporary, cfg.provenancePath); err != nil {
		t.Fatalf("publish sandbox provenance: %v", err)
	}
}

func publicKeySHA256(t *testing.T, encoded string) string {
	t.Helper()
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != x25519PublicKeyLength {
		t.Fatal("validated sandbox server public key became non-canonical")
	}
	digest := sha256.Sum256(key)
	wipe(key)
	return hex.EncodeToString(digest[:])
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
