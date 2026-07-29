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
	"slices"
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

type auditingResolver struct {
	mu        sync.Mutex
	hosts     []string
	addresses []netip.Addr
}

func (r *auditingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.addresses = append(r.addresses, addresses...)
	r.mu.Unlock()
	return addresses, err
}

func (r *auditingResolver) snapshot() ([]string, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hosts...), append([]netip.Addr(nil), r.addresses...)
}

type auditingDialer struct {
	mu        sync.Mutex
	addresses []string
}

func (d *auditingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *auditingDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

type sandboxProofProvenance struct {
	SchemaVersion               int                   `json:"schema_version"`
	BuildSHA                    string                `json:"build_sha"`
	AgentID                     string                `json:"agent_id"`
	DeploymentManifestSHA256    string                `json:"deployment_manifest_sha256"`
	TypedEvidenceContractSHA256 string                `json:"typed_evidence_contract_sha256"`
	Hub                         sandboxHubEvidence    `json:"hub"`
	AssignedCells               []sandboxCellEvidence `json:"assigned_cells"`
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

func TestSandboxNativeUDPLifecycle(t *testing.T) {
	cfg, enabled, err := loadSandboxConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("attended proof only; set QURL_GO_SANDBOX_STRICT=true to require live sandbox execution")
	}

	httpTrap := installLifecycleHTTPTrap(t)

	ctx, cancel := context.WithTimeout(t.Context(), sandboxProofTimeout)
	defer cancel()

	hub := qurl.HubBootstrap{
		Host:               cfg.hubHost,
		Port:               cfg.hubPort,
		ServerPublicKeyB64: cfg.hubServerKeyB64,
	}
	for name, path := range map[string]string{statePathEnv: cfg.statePath, provenancePathEnv: cfg.provenancePath} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("strict proof requires a fresh path but %s already exists", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect fresh %s: %v", name, err)
		}
	}
	t.Cleanup(func() { cleanupSandboxProofFiles(cfg) })
	t.Cleanup(func() { cleanupSandboxSealedProofFiles(cfg) })
	sealedStore, err := openSandboxKMSSealedStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var store qurl.AgentStateStore = sealedStore
	t.Cleanup(func() {
		if sealedStore != nil {
			_ = sealedStore.Close()
		}
	})

	if !runTypedEvidenceScenario(t, "provenance_and_hub_trust", "provenance.exact_build_and_hub_trust", []string{"build_provenance"}, func(t *testing.T) {
		assertBuildProvenance(t, cfg.buildSHA)
		t.Logf("EVIDENCE build_sha=%s hub_host=%s hub_port=%d hub_server_public_key_b64=%s agent_id=%s",
			cfg.buildSHA, hub.Host, hub.Port, hub.ServerPublicKeyB64, cfg.agentID)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "exact_qurl_go_93_candidate", "provenance.exact_qurl_go_93_candidate", []string{"build_provenance"}, func(t *testing.T) {
		proveExactQURLGo93Candidate(t, cfg)
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

	// Self-contained authentication and packet-boundary proofs. Like the DNS and
	// timeout proofs above they drive the real transport over loopback sockets and
	// need no live cell, so they run identically here and in the always-on
	// TestNativeUDPClientFaultPaths.
	if !runTypedEvidenceScenario(t, "wrong_hub_key", "negative.wrong_hub_key", []string{"rejection_observation"}, func(t *testing.T) {
		proveWrongHubKey(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "wrong_cell_key", "negative.wrong_cell_key", []string{"rejection_observation"}, func(t *testing.T) {
		proveWrongCellKey(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "oversize_packet", "packet.oversize", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketOversize(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "cell_dns_failure", "negative.cell_dns_failure", []string{"rejection_observation"}, func(t *testing.T) {
		proveCellDNSFailure(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "remaining_phase_timeouts", "packet.remaining_phase_timeouts", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketRemainingPhaseTimeouts(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "malformed_packet", "packet.malformed", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketMalformed(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_duplicate", "packet.duplicate", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketDuplicate(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "hub_dns_address_refresh", "dns.hub_authoritative_address_refresh", []string{"dns_resolution"}, func(t *testing.T) {
		proveHubDNSAddressRefresh(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "cell_dns_address_refresh", "dns.cell_authoritative_address_refresh", []string{"dns_resolution"}, func(t *testing.T) {
		proveCellDNSAddressRefresh(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "multi_address_ipv4_ipv6_bounds", "dns.multi_address_ipv4_ipv6_bounds", []string{"dns_resolution"}, func(t *testing.T) {
		proveMultiAddressBounds(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_cancellation", "packet.cancellation", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketCancellation(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_loss", "packet.loss", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketLoss(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_delay", "packet.delay", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketDelay(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_replay", "packet.replay", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketReplay(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "packet_reorder", "packet.reorder", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketReorder(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "unknown_message", "packet.unknown_message", []string{"packet_fault_observation"}, func(t *testing.T) {
		provePacketUnknownMessage(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "public_resource_and_knock_resource_id_wire_distinction", "identity.public_resource_id_distinct_from_knock_resource_id", []string{"identity_binding"}, func(t *testing.T) {
		provePublicResourceAndKnockResourceIDWireDistinction(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "hub_cookie_proof_lst_return_routability", "assignment.hub_cookie_proof_lst_return_routability", []string{"assignment_response"}, func(t *testing.T) {
		proveHubCookieProofRoutability(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "assigned_cell_cookie_reknock_return_routability", "session.cell_cookie_reknock_return_routability", []string{"lifecycle_exchange"}, func(t *testing.T) {
		proveCellCookieReknockRoutability(ctx, t, httpTrap)
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "authenticated_invalid_assignment_matrix", "assignment.authenticated_invalid_response_matrix", []string{"assignment_response"}, func(t *testing.T) {
		proveAuthenticatedInvalidAssignmentMatrix(ctx, t, httpTrap)
	}) {
		return
	}

	for _, proof := range nativeDurabilityProofAdapters() {
		if !runTypedEvidenceScenario(t, proof.adapterName, proof.scenarioKey, []string{proof.evidenceKind}, func(t *testing.T) {
			runProductionStateMachineProofs(t, proof.productionTests)
		}) {
			return
		}
	}

	cellEvidence := make([]sandboxCellEvidence, 0, 4)
	otpMailbox := newSandboxOTPMailbox(cfg)
	var registeredClient *qurl.Client
	var registeredBinding *qurl.AgentRuntimeBinding
	// Happy-path lifecycle calls deliberately omit UDP and retry overrides so
	// the deployed proof measures the SDK's out-of-box production defaults.
	if !runTypedEvidenceScenario(t, "account_otp_send", "otp.send", []string{"otp_flow_observation"}, func(t *testing.T) {
		client, binding, err := qurl.RegisterAgentRuntime(ctx, cfg.enrollment, store,
			qurl.WithAgentRuntimeHub(hub),
			qurl.WithAgentRuntimeIdentity(cfg.agentID),
			qurl.WithAgentRuntimeMetadata("qurl-go-sandbox", cfg.buildSHA),
			qurl.WithAgentRuntimeAllowedRegistrationKeyKinds(qurl.RegistrationKeyKindAccount),
			qurl.WithAgentRuntimeOTPProvider(otpMailbox.provide),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RegisterAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RegisterAgentRuntime returned a nil client or binding")
		}
		registeredClient = client
		registeredBinding = binding
		t.Cleanup(binding.Destroy)
		calls, fresh := otpMailbox.snapshot()
		if calls != 1 || !fresh {
			t.Fatalf("account OTP provider calls = %d, fresh=%t; want one fresh delivered code", calls, fresh)
		}
		t.Log("EVIDENCE one real out-of-band account OTP completed authenticated UDP registration")
	}) {
		return
	}

	if !runTypedEvidenceScenario(t, "fresh_registration_via_hub_and_assigned_cell", "registration.public_api_lifecycle_success", []string{"lifecycle_exchange"}, func(t *testing.T) {
		if registeredClient == nil || registeredBinding == nil {
			t.Fatal("account OTP scenario did not return the registered runtime")
		}
		cellEvidence = append(cellEvidence, assertAssignedCell(t, cfg, registeredBinding, "registration"))
	}) {
		return
	}

	var sealedKeyARN string
	if !runTypedEvidenceScenario(t, "sealed_kms_cold_enrollment", "state.sealed_cold_start", []string{"state_observation"}, func(t *testing.T) {
		sealedKeyARN = proveSandboxKMSColdState(ctx, t, cfg, store)
		t.Logf("EVIDENCE kms_key_arn=%s provider=aws-kms plaintext_private_key_persisted=false setup_credential_persisted=false", sealedKeyARN)
	}) {
		return
	}
	if err := sealedStore.Close(); err != nil {
		t.Fatalf("close cold KMS-sealed state: %v", err)
	}
	sealedStore = nil
	removeSandboxSetupCredential(t, &cfg)
	sealedStore, err = openSandboxKMSSealedStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	store = sealedStore

	if !runTypedEvidenceScenario(t, "sealed_kms_credentialless_warm_restart", "state.sealed_warm_restart_without_setup_credential", []string{"state_observation"}, func(t *testing.T) {
		proveSandboxKMSCredentiallessWarmRestart(ctx, t, cfg, store, httpTrap)
		t.Logf("EVIDENCE kms_key_arn=%s enrollment_credential_sources=0 recovery_credential_sources=0 warm_open=true authenticated_knock=true", sealedKeyARN)
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
		assertRegistrationWarmContinuity(t, cellEvidence[0], cellEvidence[1])
	}) {
		return
	}

	var credentialRecoveryEvidence sandboxCellEvidence
	if !runTypedEvidenceScenario(t, "device_credential_recovery", "recovery.device_credential", []string{"recovery_transition"}, func(t *testing.T) {
		before, err := store.LoadAgentState(ctx)
		if err != nil || before == nil || before.Assignment == nil ||
			before.DeviceAPIKeyID == "" || before.AgentID != cfg.agentID {
			t.Fatalf("load registered state before recovery: state_present=%t assignment_present=%t device_key_id_present=%t agent_match=%t err=%v",
				before != nil,
				before != nil && before.Assignment != nil,
				before != nil && before.DeviceAPIKeyID != "",
				before != nil && before.AgentID == cfg.agentID,
				err,
			)
		}
		recoveryCredential := exchangeSandboxRecoveryCredential(ctx, t, before)
		client, binding, err := qurl.RecoverAgentRuntime(ctx, recoveryCredential, store,
			qurl.WithAgentRuntimeRecoveryHub(hub),
			qurl.WithExpectedAgentRuntimeRecoveryAgentID(cfg.agentID),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RecoverAgentRuntime: %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RecoverAgentRuntime returned a nil client or binding")
		}
		defer binding.Destroy()
		credentialRecoveryEvidence = assertAssignedCell(t, cfg, binding, "credential_recovery")
		if !sameSandboxAssignmentBinding(credentialRecoveryEvidence, cellEvidence[1]) {
			t.Fatalf("credential recovery changed the warm assignment binding: recovery=%+v warm=%+v", credentialRecoveryEvidence, cellEvidence[1])
		}

		after, err := store.LoadAgentState(ctx)
		if err != nil || after == nil || after.AgentID != before.AgentID ||
			after.PublicKeyB64 != before.PublicKeyB64 ||
			after.DeviceAPIKeyID == "" || after.DeviceAPIKeyID == before.DeviceAPIKeyID ||
			after.Assignment == nil ||
			after.Assignment.CellID != before.Assignment.CellID ||
			after.Assignment.AssignmentGeneration != before.Assignment.AssignmentGeneration {
			t.Fatalf("recovered state violated identity/assignment continuity: state_present=%t agent_match=%t public_key_match=%t device_rotated=%t assignment_match=%t err=%v",
				after != nil,
				after != nil && after.AgentID == before.AgentID,
				after != nil && after.PublicKeyB64 == before.PublicKeyB64,
				after != nil && after.DeviceAPIKeyID != "" && after.DeviceAPIKeyID != before.DeviceAPIKeyID,
				after != nil && after.Assignment != nil &&
					after.Assignment.CellID == before.Assignment.CellID &&
					after.Assignment.AssignmentGeneration == before.Assignment.AssignmentGeneration,
				err,
			)
		}
		t.Logf("EVIDENCE recovery_agent_id=%s old_device_api_key_id=%s new_device_api_key_id=%s cell_id=%s assignment_generation=%d",
			after.AgentID, before.DeviceAPIKeyID, after.DeviceAPIKeyID,
			after.Assignment.CellID, after.Assignment.AssignmentGeneration)
	}) {
		return
	}

	assignmentReceipt := completeAssignmentHandshake(ctx, t, cfg, cellEvidence[1])

	var reassigned *qurl.AgentRuntimeBinding
	var reassignedPrivateKey []byte
	reassignmentPassed := runTypedEvidenceScenario(t, "cell0_to_cell1_reassignment", "reassignment.cell0_to_cell1", []string{"assignment_transition"}, func(t *testing.T) {
		rejectedClient, rejectedBinding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if rejectedBinding != nil {
			rejectedBinding.Destroy()
		}
		if rejectedClient != nil || rejectedBinding != nil || !errors.Is(err, qurl.ErrAssignmentReassignmentRequired) {
			t.Fatalf(
				"implicit reassignment = client_non_nil:%t binding_non_nil:%t err:%v; want explicit-adoption rejection",
				rejectedClient != nil,
				rejectedBinding != nil,
				err,
			)
		}
		persistedClient, persistedBinding, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil || persistedClient == nil || persistedBinding == nil {
			t.Fatalf("open after rejected implicit reassignment = client:%v binding:%v err:%v", persistedClient, persistedBinding, err)
		}
		persistedEvidence := assertAssignedCell(t, cfg, persistedBinding, "warm_open")
		persistedBinding.Destroy()
		if !sameSandboxAssignmentBinding(persistedEvidence, cellEvidence[1]) {
			t.Fatalf("rejected implicit reassignment changed persisted placement: persisted=%+v warm=%+v", persistedEvidence, cellEvidence[1])
		}

		client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
			qurl.WithAgentRuntimeReassignmentAdoption(),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RefreshAgentRuntime(reassignment): %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RefreshAgentRuntime(reassignment) returned a nil client or binding")
		}
		reassigned = binding
		cellEvidence = append(cellEvidence, assertAssignedCell(t, cfg, binding, "reassignment"))
		assertCell0ToCell1Reassignment(t, cellEvidence[1], cellEvidence[2])
		assertAssignmentReceiptMatchesRefresh(t, assignmentReceipt, cellEvidence[2])
		reassignedPrivateKey = binding.TakeDeviceStaticPrivateKey()
		if len(reassignedPrivateKey) != x25519PublicKeyLength {
			length := len(reassignedPrivateKey)
			wipe(reassignedPrivateKey)
			reassignedPrivateKey = nil
			t.Fatalf("reassigned runtime private key length = %d, want %d", length, x25519PublicKeyLength)
		}
	})
	if !reassignmentPassed {
		if reassigned != nil {
			reassigned.Destroy()
		}
		wipe(reassignedPrivateKey)
		return
	}

	staleAssignmentPassed := runTypedEvidenceScenario(t, "stale_assignment_rejection", "reassignment.stale_assignment_rejection", []string{"assignment_transition"}, func(t *testing.T) {
		waitForAssignmentLeaseExpiry(ctx, t, reassigned.LeaseExpiresAt)
		resolver := &fixedResolver{address: netip.MustParseAddr("127.0.0.1")}
		dialer := &redirectingDialer{}
		runID, err := qurl.NewCycleRunID()
		if err != nil {
			t.Fatalf("NewCycleRunID: %v", err)
		}
		result, err := qurl.KnockRegisteredAgent(
			ctx,
			reassigned,
			reassignedPrivateKey,
			cfg.knockResourceID,
			qurl.NativeKnockOptions{RunID: runID},
			qurl.WithAgentRuntimeUDPResolver(resolver),
			qurl.WithAgentRuntimeUDPDialer(dialer),
		)
		resolverCalls, _, _ := resolver.snapshot()
		dialerCalls, _, _ := dialer.snapshot()
		if result != nil || !errors.Is(err, qurl.ErrInvalidNativeKnockInput) ||
			!errors.Is(err, qurl.ErrAssignmentLeaseExpired) ||
			resolverCalls != 0 || dialerCalls != 0 {
			t.Fatalf(
				"stale assignment rejection = result_non_nil:%t err:%v resolver_calls:%d dialer_calls:%d; want lease rejection before DNS or UDP",
				result != nil,
				err,
				resolverCalls,
				dialerCalls,
			)
		}
		assertNoLifecycleHTTP(t, httpTrap)
		t.Logf(
			"EVIDENCE stale_cell_id=%s stale_generation=%d stale_revision=%d lease_expires_at=%s resolver_calls=0 udp_dial_calls=0 lifecycle_http_calls=0",
			reassigned.CellID,
			reassigned.AssignmentGeneration,
			reassigned.EndpointRevision,
			reassigned.LeaseExpiresAt.UTC().Format(time.RFC3339Nano),
		)
	})
	reassigned.Destroy()
	reassigned = nil
	wipe(reassignedPrivateKey)
	reassignedPrivateKey = nil
	if !staleAssignmentPassed {
		return
	}

	var leaseRefreshed *qurl.AgentRuntimeBinding
	leaseRefreshPassed := runTypedEvidenceScenario(t, "expired_lease_refresh", "assignment.lease_expiry_refresh", []string{"assignment_response"}, func(t *testing.T) {
		client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if client != nil || binding != nil || !errors.Is(err, qurl.ErrAssignmentLeaseExpired) {
			if binding != nil {
				binding.Destroy()
			}
			t.Fatalf("open expired assignment = client_non_nil:%t binding_non_nil:%t err:%v; want ErrAssignmentLeaseExpired", client != nil, binding != nil, err)
		}

		client, binding, err = qurl.RefreshAgentRuntime(ctx, hub, store,
			qurl.WithAgentRuntimeReassignmentAdoption(),
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("RefreshAgentRuntime(expired lease): %v", err)
		}
		if client == nil || binding == nil {
			t.Fatal("RefreshAgentRuntime(expired lease) returned a nil client or binding")
		}
		leaseRefreshed = binding
		refreshedEvidence := assertAssignedCell(t, cfg, binding, "refresh")
		assertSameCellRefresh(t, cellEvidence[2], refreshedEvidence)
		if refreshedEvidence.AssignmentGeneration != assignmentReceipt.Move.Result.NewAssignmentGeneration ||
			refreshedEvidence.CellID != assignmentReceipt.Move.Result.NewCellID {
			t.Fatalf("expired-lease refresh lost the exact controller generation: refresh=%+v move=%+v", refreshedEvidence, assignmentReceipt.Move.Result)
		}
		assertNoLifecycleHTTP(t, httpTrap)
		t.Log("EVIDENCE expired persisted assignment rejected before cell I/O and renewed only through authenticated Hub refresh with explicit adoption")
	})
	if leaseRefreshed != nil {
		leaseRefreshed.Destroy()
		leaseRefreshed = nil
	}
	if !leaseRefreshPassed {
		return
	}

	var refreshed *qurl.AgentRuntimeBinding
	refreshPassed := runTypedEvidenceScenario(t, "authenticated_hub_refresh", "assignment.authenticated_refresh", []string{"assignment_response"}, func(t *testing.T) {
		client, binding, err := qurl.RefreshAgentRuntime(ctx, hub, store,
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
		assertSameCellRefresh(t, cellEvidence[2], cellEvidence[3])
	})
	if refreshed != nil {
		defer refreshed.Destroy()
	}
	if !refreshPassed {
		return
	}

	if !runTypedEvidenceScenario(t, "two_cell_completion_refresh_recovery", "recovery.two_cell_completion_refresh", []string{"recovery_transition"}, func(t *testing.T) {
		client, recovered, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
			qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
			qurl.WithAgentClientHTTPClient(httpTrap),
		)
		if err != nil {
			t.Fatalf("OpenRegisteredAgentRuntime(two-cell recovery): %v", err)
		}
		if client == nil || recovered == nil {
			t.Fatal("two-cell recovery returned a nil client or binding")
		}
		defer recovered.Destroy()
		recoveredEvidence := assertAssignedCell(t, cfg, recovered, "recovery")
		if credentialRecoveryEvidence.CellID != "cell0" ||
			recoveredEvidence.CellID != "cell1" ||
			recoveredEvidence.AssignmentGeneration != assignmentReceipt.Move.Result.NewAssignmentGeneration ||
			!sameSandboxAssignmentBinding(recoveredEvidence, cellEvidence[3]) {
			t.Fatalf(
				"two-cell recovery did not complete on cell0 then reopen exact refreshed cell1: completion=%+v recovered=%+v refresh=%+v",
				credentialRecoveryEvidence,
				recoveredEvidence,
				cellEvidence[3],
			)
		}
		privateKey := recovered.TakeDeviceStaticPrivateKey()
		if len(privateKey) != x25519PublicKeyLength {
			wipe(privateKey)
			t.Fatalf("recovered runtime private key length = %d, want %d", len(privateKey), x25519PublicKeyLength)
		}
		defer wipe(privateKey)
		runID, err := qurl.NewCycleRunID()
		if err != nil {
			t.Fatalf("NewCycleRunID: %v", err)
		}
		resolver := &auditingResolver{}
		dialer := &auditingDialer{}
		result, err := qurl.KnockRegisteredAgent(
			ctx,
			recovered,
			privateKey,
			cfg.knockResourceID,
			qurl.NativeKnockOptions{RunID: runID},
			qurl.WithAgentRuntimeUDPResolver(resolver),
			qurl.WithAgentRuntimeUDPDialer(dialer),
		)
		if err != nil {
			t.Fatalf("KnockRegisteredAgent(two-cell recovery): %v", err)
		}
		if result == nil || result.ACToken == "" || result.ResourceHost == "" {
			t.Fatal("two-cell recovery knock returned incomplete authenticated admission")
		}
		resolvedHosts, resolvedAddresses := resolver.snapshot()
		assertOnlyAssignedCellTraffic(t, resolvedHosts, resolvedAddresses, dialer.snapshot(), recovered)
		assertNoLifecycleHTTP(t, httpTrap)
		t.Logf(
			"EVIDENCE completed_cell=%s refreshed_cell=%s recovered_cell=%s exact_generation=%d cell0_fallback=0 hostname_inference=0 lifecycle_http_calls=0",
			credentialRecoveryEvidence.CellID,
			cellEvidence[3].CellID,
			recovered.CellID,
			recovered.AssignmentGeneration,
		)
	}) {
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

	runTypedEvidenceScenario(t, "zero_lifecycle_http_packet_capture_and_route_counters", "transport.zero_http_packet_capture_and_route_counters", []string{"transport_capture"}, func(t *testing.T) {
		completeTransportProof(ctx, t, cfg, httpTrap, cellEvidence)
	})
}

type sandboxRecoveryControlRequest struct {
	Version              int    `json:"version"`
	ControllerRunID      string `json:"controller_run_id"`
	ControllerRunAttempt string `json:"controller_run_attempt"`
	GrantCorrelationID   string `json:"grant_correlation_id"`
	AgentID              string `json:"agent_id"`
	DeviceAPIKeyID       string `json:"device_api_key_id"`
	CellID               string `json:"cell_id"`
	AssignmentGeneration string `json:"assignment_generation"`
}

type sandboxRecoveryControlResponse struct {
	Version int `json:"version"`
	Result  struct {
		ControllerRunID         string `json:"controller_run_id"`
		ControllerRunAttempt    string `json:"controller_run_attempt"`
		GrantCorrelationID      string `json:"grant_correlation_id"`
		AgentID                 string `json:"agent_id"`
		RevokedDeviceAPIKeyID   string `json:"revoked_device_api_key_id"`
		CellID                  string `json:"cell_id"`
		AssignmentGeneration    string `json:"assignment_generation"`
		RecoveryCredential      string `json:"recovery_credential"`
		RecoveryCredentialKeyID string `json:"recovery_credential_key_id"`
		RevokedAt               string `json:"revoked_at"`
	} `json:"result"`
}

func exchangeSandboxRecoveryCredential(
	ctx context.Context,
	t *testing.T,
	state *qurl.AgentState,
) string {
	t.Helper()
	requestPath := os.Getenv("QURL_GO_SANDBOX_RECOVERY_REQUEST_PATH")
	responsePath := os.Getenv("QURL_GO_SANDBOX_RECOVERY_RESPONSE_PATH")
	controllerRunID := os.Getenv("QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID")
	controllerRunAttempt := os.Getenv("QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT")
	correlationID := os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID")
	correlationPrefix := "nhp-" + controllerRunID + "-" + controllerRunAttempt +
		"-qurl_go-" + os.Getenv("QURL_GO_SANDBOX_PROOF_PHASE") + "-"
	correlationNonce := strings.TrimPrefix(correlationID, correlationPrefix)
	if state == nil || state.Assignment == nil ||
		!canonicalPositiveProofInteger(controllerRunID, 20) ||
		!canonicalPositiveProofInteger(controllerRunAttempt, 20) ||
		correlationPrefix+correlationNonce != correlationID ||
		!canonicalLowerHex(correlationNonce, 32) {
		t.Fatal("sandbox recovery controller binding is invalid")
	}
	for name, path := range map[string]string{
		"recovery request path":  requestPath,
		"recovery response path": responsePath,
	} {
		if !filepath.IsAbs(path) {
			t.Fatalf("%s must be absolute", name)
		}
		info, err := os.Stat(filepath.Dir(path))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
			info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s parent must be a private 0700 non-symlink directory", name)
		}
	}
	if filepath.Clean(requestPath) == filepath.Clean(responsePath) {
		t.Fatal("sandbox recovery request and response paths must be distinct")
	}

	request := sandboxRecoveryControlRequest{
		Version: 1, ControllerRunID: controllerRunID,
		ControllerRunAttempt: controllerRunAttempt, GrantCorrelationID: correlationID,
		AgentID: state.AgentID, DeviceAPIKeyID: state.DeviceAPIKeyID,
		CellID:               state.Assignment.CellID,
		AssignmentGeneration: fmt.Sprintf("%d", state.Assignment.AssignmentGeneration),
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode recovery checkpoint: %v", err)
	}
	if err := writeExclusivePrivateFile(requestPath, payload); err != nil {
		t.Fatalf("publish recovery checkpoint: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(requestPath)
		_ = os.Remove(responsePath)
	})

	var responsePayload []byte
	for {
		responsePayload, err = os.ReadFile(responsePath)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read recovery controller response: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("recovery controller response did not arrive before proof deadline")
		case <-time.After(250 * time.Millisecond):
		}
	}
	if err := os.Remove(responsePath); err != nil {
		t.Fatalf("remove consumed recovery controller response: %v", err)
	}
	response, err := decodeStrictJSON[sandboxRecoveryControlResponse](
		responsePayload,
		"recovery controller response",
	)
	for index := range responsePayload {
		responsePayload[index] = 0
	}
	if err != nil {
		t.Fatalf("decode recovery controller response: %v", err)
	}
	result := response.Result
	if response.Version != 1 ||
		result.ControllerRunID != controllerRunID ||
		result.ControllerRunAttempt != controllerRunAttempt ||
		result.GrantCorrelationID != correlationID ||
		result.AgentID != state.AgentID ||
		result.RevokedDeviceAPIKeyID != state.DeviceAPIKeyID ||
		result.CellID != state.Assignment.CellID ||
		result.AssignmentGeneration != request.AssignmentGeneration ||
		result.RecoveryCredentialKeyID == "" ||
		!canonicalSandboxRecoveryCredential(result.RecoveryCredential) {
		t.Fatal("recovery controller response did not match the exact proof checkpoint")
	}
	if _, err := time.Parse(time.RFC3339, result.RevokedAt); err != nil {
		t.Fatal("recovery controller response carried a noncanonical revocation receipt")
	}
	return result.RecoveryCredential
}

func canonicalSandboxRecoveryCredential(value string) bool {
	const prefixLength = len("lv_live_")
	if len(value) != prefixLength+43 ||
		(!strings.HasPrefix(value, "lv_live_") && !strings.HasPrefix(value, "lv_test_")) {
		return false
	}
	encoded := value[prefixLength:]
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(secret) == 32 &&
		base64.RawURLEncoding.EncodeToString(secret) == encoded
}

func TestCanonicalSandboxRecoveryCredential(t *testing.T) {
	t.Parallel()
	canonical := "lv_live_" + strings.Repeat("A", 43)
	if !canonicalSandboxRecoveryCredential(canonical) {
		t.Fatal("canonical 32-byte recovery credential was rejected")
	}
	for _, value := range []string{
		"lv_live_" + strings.Repeat("A", 42) + "B",
		"lv_test_" + strings.Repeat("A", 42) + "=",
		"lv_live_" + strings.Repeat("A", 42),
		"lv_prod_" + strings.Repeat("A", 43),
	} {
		if canonicalSandboxRecoveryCredential(value) {
			t.Fatalf("noncanonical recovery credential accepted: %q", value)
		}
	}
}

func canonicalPositiveProofInteger(value string, maxDigits int) bool {
	if value == "" || len(value) > maxDigits || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func writeExclusivePrivateFile(path string, payload []byte) (retErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); retErr == nil && closeErr != nil {
			retErr = closeErr
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	return file.Sync()
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

func TestSandboxProofProvenanceIsAllowlisted(t *testing.T) {
	serverKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	provenanceDirectory := filepath.Join(t.TempDir(), "qurl-go-native-udp")
	if err := os.Mkdir(provenanceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := sandboxConfig{
		buildSHA:         strings.Repeat("a", 40),
		agentID:          "qurl-go-proof-provenance",
		provenancePath:   filepath.Join(provenanceDirectory, "provenance.json"),
		deploymentSHA:    strings.Repeat("d", 64),
		typedContractSHA: strings.Repeat("e", 64),
	}
	hub := qurl.HubBootstrap{Host: "hub.nhp.layerv.ai", Port: standardNHPUDPPort, ServerPublicKeyB64: serverKey}
	cell0Key := publicKeySHA256(t, serverKey)
	cell1Key := strings.Repeat("1", 64)
	cells := sandboxProvenanceCellChain(cell0Key, cell1Key)
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
	if got.SchemaVersion != 2 || got.BuildSHA != cfg.buildSHA || got.AgentID != cfg.agentID ||
		got.DeploymentManifestSHA256 != cfg.deploymentSHA ||
		got.TypedEvidenceContractSHA256 != cfg.typedContractSHA ||
		got.Hub.Host != hub.Host || len(got.AssignedCells) != 4 {
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

func TestSandboxProofProvenanceRejectsNonPrivateParent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	err := validateSandboxProvenanceDirectory(filepath.Join(directory, "provenance.json"))
	if err == nil || !strings.Contains(err.Error(), "private 0700 non-symlink directory") {
		t.Fatalf("non-private provenance directory error = %v", err)
	}
}

func sandboxProvenanceCellChain(cell0Key, cell1Key string) []sandboxCellEvidence {
	return []sandboxCellEvidence{
		{
			Phase:                 "registration",
			CellID:                "cell0",
			AssignmentGeneration:  1,
			EndpointRevision:      2,
			LeaseExpiresAt:        "2026-07-22T12:00:00Z",
			Host:                  "cell0.nhp.layerv.ai",
			Port:                  standardNHPUDPPort,
			ServerPublicKeySHA256: cell0Key,
		},
		{
			Phase:                 "warm_open",
			CellID:                "cell0",
			AssignmentGeneration:  1,
			EndpointRevision:      2,
			LeaseExpiresAt:        "2026-07-22T12:00:00Z",
			Host:                  "cell0.nhp.layerv.ai",
			Port:                  standardNHPUDPPort,
			ServerPublicKeySHA256: cell0Key,
		},
		{
			Phase:                 "reassignment",
			CellID:                "cell1",
			AssignmentGeneration:  2,
			EndpointRevision:      1,
			LeaseExpiresAt:        "2026-07-22T12:30:00Z",
			Host:                  "cell1.nhp.layerv.ai",
			Port:                  standardNHPUDPPort,
			ServerPublicKeySHA256: cell1Key,
		},
		{
			Phase:                 "refresh",
			CellID:                "cell1",
			AssignmentGeneration:  2,
			EndpointRevision:      2,
			LeaseExpiresAt:        "2026-07-22T13:00:00Z",
			Host:                  "cell1.nhp.layerv.ai",
			Port:                  standardNHPUDPPort,
			ServerPublicKeySHA256: cell1Key,
		},
	}
}

func TestSandboxProvenanceTransitionValidation(t *testing.T) {
	base := sandboxProvenanceCellChain(strings.Repeat("0", 64), strings.Repeat("1", 64))
	if err := validateRegistrationWarmContinuity(base[0], base[1]); err != nil {
		t.Fatalf("valid registration/warm chain rejected: %v", err)
	}
	if err := validateCell0ToCell1Reassignment(base[1], base[2]); err != nil {
		t.Fatalf("valid reassignment rejected: %v", err)
	}
	if err := validateSameCellRefresh(base[2], base[3]); err != nil {
		t.Fatalf("valid same-cell refresh rejected: %v", err)
	}

	tests := map[string]func([]sandboxCellEvidence) error{
		"warm tuple drift": func(cells []sandboxCellEvidence) error {
			cells[1].LeaseExpiresAt = "2026-07-22T12:00:01Z"
			return validateRegistrationWarmContinuity(cells[0], cells[1])
		},
		"wrong reassignment destination": func(cells []sandboxCellEvidence) error {
			cells[2].CellID = "cell2"
			return validateCell0ToCell1Reassignment(cells[1], cells[2])
		},
		"stale reassignment generation": func(cells []sandboxCellEvidence) error {
			cells[2].AssignmentGeneration = cells[1].AssignmentGeneration
			return validateCell0ToCell1Reassignment(cells[1], cells[2])
		},
		"refresh endpoint drift": func(cells []sandboxCellEvidence) error {
			cells[3].Host = "other.nhp.layerv.ai"
			return validateSameCellRefresh(cells[2], cells[3])
		},
		"refresh revision regression": func(cells []sandboxCellEvidence) error {
			cells[3].EndpointRevision = cells[2].EndpointRevision - 1
			return validateSameCellRefresh(cells[2], cells[3])
		},
		"refresh lease regression": func(cells []sandboxCellEvidence) error {
			cells[3].LeaseExpiresAt = "2026-07-22T12:29:59.999999999Z"
			return validateSameCellRefresh(cells[2], cells[3])
		},
		"invalid refresh lease": func(cells []sandboxCellEvidence) error {
			cells[3].LeaseExpiresAt = "not-a-time"
			return validateSameCellRefresh(cells[2], cells[3])
		},
	}
	for name, mutateAndValidate := range tests {
		t.Run(name, func(t *testing.T) {
			cells := append([]sandboxCellEvidence(nil), base...)
			if err := mutateAndValidate(cells); err == nil {
				t.Fatal("invalid provenance transition was accepted")
			}
		})
	}
}

func TestPublishSandboxProvenanceIsExclusive(t *testing.T) {
	directory := t.TempDir()
	temporary := filepath.Join(directory, "provenance.json.tmp")
	destination := filepath.Join(directory, "provenance.json")
	payload := []byte("{\"schema_version\":2}\n")
	if err := publishSandboxProvenance(temporary, destination, payload); err != nil {
		t.Fatalf("publish fresh provenance: %v", err)
	}
	if raw, err := os.ReadFile(destination); err != nil || string(raw) != string(payload) {
		t.Fatalf("published provenance = %q, %v", raw, err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary provenance remains after publication: %v", err)
	}

	replacement := []byte("{\"schema_version\":999}\n")
	if err := publishSandboxProvenance(temporary, destination, replacement); err == nil {
		t.Fatal("exclusive publication replaced an existing provenance file")
	}
	if raw, err := os.ReadFile(destination); err != nil || string(raw) != string(payload) {
		t.Fatalf("failed replacement changed provenance = %q, %v", raw, err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary provenance remains after rejected replacement: %v", err)
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
	resolver := &failureResolver{}
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
	if cfg.expectedCellID != "" && (phase == "registration" || phase == "warm_open") && binding.CellID != cfg.expectedCellID {
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

func assertRegistrationWarmContinuity(t *testing.T, registration, warm sandboxCellEvidence) {
	t.Helper()
	if err := validateRegistrationWarmContinuity(registration, warm); err != nil {
		t.Fatal(err)
	}
}

func assertCell0ToCell1Reassignment(t *testing.T, previous, current sandboxCellEvidence) {
	t.Helper()
	if err := validateCell0ToCell1Reassignment(previous, current); err != nil {
		t.Fatal(err)
	}
}

func assertSameCellRefresh(t *testing.T, reassignment, refresh sandboxCellEvidence) {
	t.Helper()
	if err := validateSameCellRefresh(reassignment, refresh); err != nil {
		t.Fatal(err)
	}
}

func waitForAssignmentLeaseExpiry(ctx context.Context, t *testing.T, expiresAt time.Time) {
	t.Helper()
	wait := time.Until(expiresAt.Add(250 * time.Millisecond))
	if wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatalf("wait for assignment lease expiry: %v", ctx.Err())
	case <-timer.C:
	}
}

func assertOnlyAssignedCellTraffic(t *testing.T, hosts []string, resolved []netip.Addr, dialed []string, binding *qurl.AgentRuntimeBinding) {
	t.Helper()
	if len(hosts) == 0 || len(resolved) == 0 || len(dialed) == 0 {
		t.Fatalf("assigned-cell knock observed incomplete DNS or UDP dialing: hosts=%v resolved=%v dialed=%v", hosts, resolved, dialed)
	}
	for _, host := range hosts {
		if host != binding.NHPUDPEndpoint.Host {
			t.Fatalf("assigned-cell knock resolved inferred or fallback host %q, want exact Hub assignment %q", host, binding.NHPUDPEndpoint.Host)
		}
	}
	for _, address := range dialed {
		host, port, err := net.SplitHostPort(address)
		dialedIP, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || port != fmt.Sprint(binding.NHPUDPEndpoint.Port) || !slices.Contains(resolved, dialedIP) {
			t.Fatalf("assigned-cell knock dialed %q, want exact assigned UDP port %d", address, binding.NHPUDPEndpoint.Port)
		}
	}
}

func validateRegistrationWarmContinuity(registration, warm sandboxCellEvidence) error {
	if registration.Phase != "registration" || warm.Phase != "warm_open" || !sameSandboxAssignmentBinding(registration, warm) {
		return fmt.Errorf("credentialless warm open changed the registered assignment binding: registration=%+v warm_open=%+v", registration, warm)
	}
	return nil
}

func validateCell0ToCell1Reassignment(previous, current sandboxCellEvidence) error {
	if previous.Phase != "warm_open" || current.Phase != "reassignment" ||
		previous.CellID != "cell0" || current.CellID != "cell1" ||
		previous.Host == current.Host || previous.ServerPublicKeySHA256 == current.ServerPublicKeySHA256 ||
		current.AssignmentGeneration <= previous.AssignmentGeneration {
		return fmt.Errorf("authenticated reassignment is not a real cell0-to-cell1 generation advance: previous=%+v current=%+v", previous, current)
	}
	return nil
}

func validateSameCellRefresh(reassignment, refresh sandboxCellEvidence) error {
	reassignmentLease, reassignmentLeaseErr := time.Parse(time.RFC3339Nano, reassignment.LeaseExpiresAt)
	refreshLease, refreshLeaseErr := time.Parse(time.RFC3339Nano, refresh.LeaseExpiresAt)
	if reassignment.Phase != "reassignment" || refresh.Phase != "refresh" ||
		reassignment.CellID != refresh.CellID ||
		reassignment.AssignmentGeneration != refresh.AssignmentGeneration ||
		reassignment.Host != refresh.Host ||
		reassignment.Port != refresh.Port ||
		reassignment.ServerPublicKeySHA256 != refresh.ServerPublicKeySHA256 ||
		refresh.EndpointRevision < reassignment.EndpointRevision ||
		reassignmentLeaseErr != nil || refreshLeaseErr != nil ||
		refreshLease.Before(reassignmentLease) {
		return fmt.Errorf("same-cell refresh changed reassigned placement, regressed endpoint revision/lease, or carried an invalid lease: reassignment=%+v refresh=%+v", reassignment, refresh)
	}
	return nil
}

func sameSandboxAssignmentBinding(left, right sandboxCellEvidence) bool {
	return left.CellID == right.CellID &&
		left.AssignmentGeneration == right.AssignmentGeneration &&
		left.EndpointRevision == right.EndpointRevision &&
		left.LeaseExpiresAt == right.LeaseExpiresAt &&
		left.Host == right.Host &&
		left.Port == right.Port &&
		left.ServerPublicKeySHA256 == right.ServerPublicKeySHA256
}

func writeSandboxProvenance(t *testing.T, cfg sandboxConfig, hub qurl.HubBootstrap, cells []sandboxCellEvidence) {
	t.Helper()
	if err := validateSandboxProvenanceDirectory(cfg.provenancePath); err != nil {
		t.Fatal(err)
	}
	if len(cells) != 4 {
		t.Fatalf("refuse to write sandbox provenance without the exact four-observation chain: got %d", len(cells))
	}
	assertRegistrationWarmContinuity(t, cells[0], cells[1])
	assertCell0ToCell1Reassignment(t, cells[1], cells[2])
	assertSameCellRefresh(t, cells[2], cells[3])
	evidence := sandboxProofProvenance{
		SchemaVersion:               2,
		BuildSHA:                    cfg.buildSHA,
		AgentID:                     cfg.agentID,
		DeploymentManifestSHA256:    cfg.deploymentSHA,
		TypedEvidenceContractSHA256: cfg.typedContractSHA,
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
	if err := publishSandboxProvenance(temporary, cfg.provenancePath, append(raw, '\n')); err != nil {
		t.Fatalf("atomically publish sandbox provenance: %v", err)
	}
}

func validateSandboxProvenanceDirectory(path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect provenance directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o700 {
		return fmt.Errorf("provenance directory mode = %v, want a private 0700 non-symlink directory", parent.Mode())
	}
	return nil
}

func publishSandboxProvenance(temporary, destination string, payload []byte) (retErr error) {
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary provenance: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); retErr == nil && closeErr != nil {
				retErr = fmt.Errorf("close temporary provenance: %w", closeErr)
			}
		}
		if removeErr := os.Remove(temporary); retErr == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			retErr = fmt.Errorf("remove temporary provenance: %w", removeErr)
		}
	}()
	if written, err := file.Write(payload); err != nil {
		return fmt.Errorf("write temporary provenance: %w", err)
	} else if written != len(payload) {
		return fmt.Errorf("write temporary provenance: wrote %d of %d bytes", written, len(payload))
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary provenance: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary provenance before publication: %w", err)
	}
	closed = true
	if err := os.Link(temporary, destination); err != nil {
		return fmt.Errorf("publish provenance without replacement: %w", err)
	}
	return nil
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
