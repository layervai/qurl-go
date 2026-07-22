package nativeudp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const reviewedInventoryMappingSHA256 = "1dff59c8188ca1cb72847135b5e4a9e2c2bba4f737d788379c93a568152dc88d"

type scenarioInventory struct {
	SchemaVersion        int                    `json:"schema_version"`
	Gate                 string                 `json:"gate"`
	ProofPhases          []string               `json:"proof_phases"`
	AllScenariosRequired bool                   `json:"all_scenarios_required"`
	Scenarios            []scenarioInventoryRow `json:"scenarios"`
}

type scenarioInventoryRow struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Status      string `json:"status"`
	TestName    string `json:"test_name"`
	Requirement string `json:"requirement"`
}

func TestPreRetirementScenarioInventory(t *testing.T) {
	raw, err := os.ReadFile("pre_retirement_scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := decodeScenarioInventory(raw)
	if err != nil {
		t.Fatalf("decode scenario inventory: %v", err)
	}

	validateScenarioInventory(t, inventory)

	got, err := scenarioInventoryMappingSHA256(inventory)
	if err != nil {
		t.Fatalf("hash normalized scenario inventory mapping: %v", err)
	}
	if got != reviewedInventoryMappingSHA256 {
		t.Fatalf("normalized scenario inventory mapping SHA-256 = %s, want reviewed literal %s", got, reviewedInventoryMappingSHA256)
	}
}

func scenarioInventoryMappingSHA256(inventory scenarioInventory) (string, error) {
	rows := append([]scenarioInventoryRow(nil), inventory.Scenarios...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	normalizedRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		normalizedRows = append(normalizedRows, map[string]any{
			"id":          row.ID,
			"owner":       row.Owner,
			"requirement": row.Requirement,
			"status":      row.Status,
			"test_name":   row.TestName,
		})
	}
	normalized := map[string]any{
		"all_scenarios_required": inventory.AllScenariosRequired,
		"gate":                   inventory.Gate,
		"proof_phases":           inventory.ProofPhases,
		"scenarios":              normalizedRows,
		"schema_version":         inventory.SchemaVersion,
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return "", err
	}
	encoded := bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'})
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", digest), nil
}

func decodeScenarioInventory(raw []byte) (scenarioInventory, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return scenarioInventory{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var inventory scenarioInventory
	if err := decoder.Decode(&inventory); err != nil {
		return scenarioInventory{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return scenarioInventory{}, fmt.Errorf("scenario inventory contains trailing JSON: %w", err)
	}
	return inventory, nil
}

func validateScenarioInventory(t *testing.T, inventory scenarioInventory) {
	t.Helper()
	if inventory.SchemaVersion != 1 || inventory.Gate != "udp_lifecycle_retirement" ||
		!slicesEqual(inventory.ProofPhases, []string{"pre_removal", "post_removal"}) || !inventory.AllScenariosRequired {
		t.Fatalf("scenario inventory header = version %d, gate %q, phases %q, all required %t", inventory.SchemaVersion, inventory.Gate, inventory.ProofPhases, inventory.AllScenariosRequired)
	}

	expectedIDs := []string{
		"assignment.authenticated_invalid_response_matrix",
		"assignment.authenticated_refresh",
		"assignment.hub_cookie_proof_lst_return_routability",
		"assignment.lease_expiry_refresh",
		"connector.complete_strict_evidence_attestation",
		"connector.dns_key_destination_source_observations",
		"connector.exact_artifact_manifest",
		"connector.frp_authenticated_login_before_proxy",
		"connector.hardened_linux_container",
		"connector.provision_journal_crash_consistency",
		"connector.real_backend_traffic",
		"connector.remove_journal_crash_consistency",
		"connector.resource_id_distinct_from_knock_resource_id",
		"connector.sealed_restart_without_setup_mount",
		"connector.zero_http_network_capture",
		"dns.cell_authoritative_address_refresh",
		"dns.hub_authoritative_address_refresh",
		"dns.multi_address_ipv4_ipv6_bounds",
		"identity.public_resource_id_distinct_from_knock_resource_id",
		"negative.cell_dns_failure",
		"negative.hub_dns_failure",
		"negative.wrong_caller",
		"negative.wrong_cell_key",
		"negative.wrong_hub_key",
		"negative.wrong_source",
		"orchestrator.dedicated_linux_fault_runner",
		"orchestrator.real_hub_authority_and_two_cells",
		"otp.dedupe",
		"otp.error",
		"otp.rate_limit",
		"otp.send",
		"packet.cancellation",
		"packet.delay",
		"packet.duplicate",
		"packet.hub_first_lst_timeout",
		"packet.loss",
		"packet.malformed",
		"packet.oversize",
		"packet.remaining_phase_timeouts",
		"packet.reorder",
		"packet.replay",
		"packet.unknown_message",
		"provenance.exact_build_and_hub_trust",
		"provenance.exact_qurl_go_93_candidate",
		"reassignment.cell0_to_cell1",
		"reassignment.stale_assignment_rejection",
		"recovery.ambiguous_completion_lrt",
		"recovery.ambiguous_rak",
		"recovery.device_credential",
		"recovery.final_state_save_ambiguity",
		"recovery.registration_restart",
		"recovery.two_cell_completion_refresh",
		"registration.public_api_lifecycle_success",
		"retirement.generated_artifact_parity",
		"retirement.http_lifecycle_surface_state",
		"retirement.nhp_registrar_surface_state",
		"retirement.relay_rejects_native_lifecycle_messages",
		"retirement.terraform_saved_plan_and_live_state",
		"session.cell_cookie_reknock_return_routability",
		"session.public_api_exit_success",
		"session.public_api_knock_success",
		"state.persisted_runtime_warm_open",
		"state.sealed_cold_start",
		"state.sealed_warm_restart_without_setup_credential",
		"transport.zero_http_injected_trap",
		"transport.zero_http_packet_capture_and_route_counters",
		"wire.registration_lst_lrt_reg_rak_completion",
		"wire.session_knk_ack_ext_ack",
	}

	idPattern := regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	seenIDs := make(map[string]struct{}, len(inventory.Scenarios))
	seenTests := make(map[string]string, len(inventory.Scenarios))
	actualIDs := make([]string, 0, len(inventory.Scenarios))
	implemented := 0
	for _, scenario := range inventory.Scenarios {
		if !idPattern.MatchString(scenario.ID) {
			t.Errorf("scenario id %q is not canonical", scenario.ID)
		}
		if _, ok := seenIDs[scenario.ID]; ok {
			t.Errorf("duplicate scenario id %q", scenario.ID)
		}
		seenIDs[scenario.ID] = struct{}{}
		actualIDs = append(actualIDs, scenario.ID)
		if scenario.Requirement == "" || scenario.TestName == "" {
			t.Errorf("scenario %q is missing requirement or exact test name", scenario.ID)
		}
		if prior, ok := seenTests[scenario.TestName]; ok {
			t.Errorf("scenarios %q and %q share test name %q", prior, scenario.ID, scenario.TestName)
		}
		seenTests[scenario.TestName] = scenario.ID
		switch scenario.Owner {
		case "qurl-go", "qurl-connector", "nhp-orchestrator":
		default:
			t.Errorf("scenario %q has unknown owner %q", scenario.ID, scenario.Owner)
		}
		switch scenario.Status {
		case "implemented", "todo", "external_dependency":
		default:
			t.Errorf("scenario %q has invalid status %q", scenario.ID, scenario.Status)
		}
		if scenario.Owner == "qurl-go" && scenario.Status == "external_dependency" {
			t.Errorf("qurl-go-owned scenario %q cannot be an external dependency", scenario.ID)
		}
		if scenario.Owner != "qurl-go" && scenario.Status == "todo" {
			t.Errorf("externally owned scenario %q must remain external_dependency until its exact evidence adapter is implemented", scenario.ID)
		}
		if err := validateScenarioAdapterNamespace(scenario); err != nil {
			t.Errorf("scenario %q: %v", scenario.ID, err)
		}
		if scenario.Status == "implemented" {
			implemented++
		}
	}
	sort.Strings(actualIDs)
	if !slicesEqual(actualIDs, expectedIDs) {
		t.Fatalf("scenario inventory ids =\n%q\nwant exact pre-retirement inventory\n%q", actualIDs, expectedIDs)
	}
	if implemented != 10 || len(inventory.Scenarios)-implemented != 58 {
		t.Fatalf("scenario counts = %d implemented/%d blocking, want the current 10/58 honest gate", implemented, len(inventory.Scenarios)-implemented)
	}
}

func TestDecodeScenarioInventoryRejectsAmbiguousJSON(t *testing.T) {
	tests := map[string]string{
		"duplicate key": `{"schema_version":1,"schema_version":1}`,
		"unknown key":   `{"unknown":true}`,
		"trailing JSON": `{}` + `{}`,
		"non-finite":    `{"schema_version":1e9999}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeScenarioInventory([]byte(raw)); err == nil {
				t.Fatal("decode accepted ambiguous scenario inventory JSON")
			}
		})
	}
}

func validateScenarioAdapterNamespace(scenario scenarioInventoryRow) error {
	switch scenario.Owner {
	case "qurl-go":
		if !strings.HasPrefix(scenario.TestName, "TestSandboxNativeUDPLifecycle/") {
			return errors.New("qurl-go evidence must use TestSandboxNativeUDPLifecycle")
		}
	case "qurl-connector":
		if !strings.HasPrefix(scenario.TestName, "TestSandboxConnectorUDP/") {
			return errors.New("qURL Connector evidence must use TestSandboxConnectorUDP")
		}
	case "nhp-orchestrator":
		if !strings.HasPrefix(scenario.TestName, "TestSandboxWireEvidence/") &&
			!strings.HasPrefix(scenario.TestName, "TestSandboxTopology/") {
			return errors.New("orchestrator evidence must use TestSandboxWireEvidence or TestSandboxTopology")
		}
	default:
		return fmt.Errorf("unknown owner %q", scenario.Owner)
	}
	return nil
}

func TestScenarioAdapterNamespacesFailClosed(t *testing.T) {
	tests := []scenarioInventoryRow{
		{Owner: "qurl-go", TestName: "TestSandboxConnectorUDP/not-sdk"},
		{Owner: "qurl-connector", TestName: "TestSandboxNativeUDPLifecycle/not-connector"},
		{Owner: "nhp-orchestrator", TestName: "TestSandboxNativeUDPLifecycle/not-orchestrator"},
		{Owner: "unknown", TestName: "TestSandboxTopology/unknown-owner"},
	}
	for _, scenario := range tests {
		if err := validateScenarioAdapterNamespace(scenario); err == nil {
			t.Fatalf("owner %q accepted wrong adapter %q", scenario.Owner, scenario.TestName)
		}
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
