package nativeudp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

const (
	sandboxProofTimeout = 8 * time.Minute
	udpAttemptTimeout   = 5 * time.Second
	udpMaxAddresses     = 4
)

var errLifecycleHTTP = errors.New("native lifecycle attempted forbidden HTTP")

type lifecycleHTTPTrap struct {
	calls atomic.Int64
	mu    sync.Mutex
	first string
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
	if _, err := os.Stat(cfg.statePath); err == nil {
		t.Fatalf("strict proof requires fresh state but %s already exists", statePathEnv)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect fresh state path: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(cfg.statePath)
		_ = os.Remove(cfg.statePath + ".lock")
	})

	if !t.Run("provenance_and_hub_trust", func(t *testing.T) {
		assertBuildProvenance(t, cfg.buildSHA)
		t.Logf("EVIDENCE build_sha=%s hub_host=%s hub_port=%d hub_server_public_key_b64=%s agent_id=%s",
			cfg.buildSHA, hub.Host, hub.Port, hub.ServerPublicKeyB64, cfg.agentID)
	}) {
		return
	}

	if !t.Run("fresh_registration_via_hub_and_assigned_cell", func(t *testing.T) {
		client, binding, err := qurl.RegisterAgentRuntime(ctx, cfg.enrollment, store,
			qurl.WithAgentRuntimeHub(hub),
			qurl.WithAgentRuntimeIdentity(cfg.agentID),
			qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", cfg.buildSHA),
			qurl.WithAgentRuntimeUDPBounds(udpAttemptTimeout, udpMaxAddresses),
			qurl.WithAgentRuntimeAssignmentRetryBudget(4, 30*time.Second),
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
		assertAssignedCell(t, cfg, binding, "registration")
	}) {
		return
	}

	if !t.Run("persisted_runtime_warm_open", func(t *testing.T) {
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
		assertAssignedCell(t, cfg, binding, "warm_open")
	}) {
		return
	}

	var refreshed *qurl.AgentRuntimeBinding
	if !t.Run("authenticated_hub_refresh", func(t *testing.T) {
		client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
			qurl.WithAgentRuntimeReassignmentAdoption(),
			qurl.WithAgentRuntimeUDPBounds(udpAttemptTimeout, udpMaxAddresses),
			qurl.WithAgentRuntimeAssignmentRetryBudget(4, 30*time.Second),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RefreshAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RefreshAgentRuntime returned a nil client or binding")
		}
		assertAssignedCell(t, cfg, binding, "refresh")
		refreshed = binding
	}) {
		return
	}
	defer refreshed.Destroy()

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
	udpOptions := []qurl.AgentRuntimeUDPOption{qurl.WithAgentRuntimeUDPBounds(udpAttemptTimeout, udpMaxAddresses)}

	if !t.Run("assigned_cell_knock", func(t *testing.T) {
		result, err := qurl.KnockRegisteredAgent(ctx, refreshed, privateKey, cfg.knockResourceID, knockOptions, udpOptions...)
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

	if !t.Run("assigned_cell_clean_exit", func(t *testing.T) {
		if err := qurl.ExitRegisteredAgentSession(ctx, refreshed, privateKey, cfg.knockResourceID, knockOptions, udpOptions...); err != nil {
			t.Fatalf("ExitRegisteredAgentSession: %v", err)
		}
		t.Log("EVIDENCE assigned-cell EXT received an authenticated ACK")
	}) {
		return
	}

	t.Run("zero_lifecycle_http", func(t *testing.T) {
		calls, first := httpTrap.snapshot()
		if calls != 0 {
			t.Fatalf("native lifecycle made %d forbidden HTTP call(s); first=%q", calls, first)
		}
		t.Log("EVIDENCE lifecycle_http_calls=0")
	})
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

func assertAssignedCell(t *testing.T, cfg sandboxConfig, binding *qurl.AgentRuntimeBinding, phase string) {
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
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
