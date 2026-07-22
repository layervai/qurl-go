package nativeudp_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"testing"
)

type scenarioInventory struct {
	SchemaVersion        int                    `json:"schema_version"`
	Gate                 string                 `json:"gate"`
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var inventory scenarioInventory
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatalf("decode scenario inventory: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("scenario inventory contains trailing JSON: %v", err)
	}
	if inventory.SchemaVersion != 1 || inventory.Gate != "udp_lifecycle_pre_retirement" || !inventory.AllScenariosRequired {
		t.Fatalf("scenario inventory header = version %d, gate %q, all required %t", inventory.SchemaVersion, inventory.Gate, inventory.AllScenariosRequired)
	}

	expectedIDs := []string{
		"assignment.authenticated_refresh",
		"assignment.hub_cookie_reknock_return_routability",
		"assignment.lease_expiry_refresh",
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
		"packet.loss",
		"packet.malformed",
		"packet.oversize",
		"packet.reorder",
		"packet.replay",
		"packet.timeout",
		"packet.unknown_message",
		"provenance.exact_build_and_hub_trust",
		"reassignment.cell0_to_cell1",
		"reassignment.stale_assignment_rejection",
		"recovery.ambiguous_rak",
		"recovery.device_credential",
		"recovery.registration_restart",
		"recovery.two_cell_completion_refresh",
		"registration.public_api_lifecycle_success",
		"session.cell_cookie_reknock_return_routability",
		"session.public_api_exit_success",
		"session.public_api_knock_success",
		"state.persisted_runtime_warm_open",
		"state.sealed_cold_start",
		"state.sealed_warm_restart_without_setup_credential",
		"transport.zero_http_injected_trap",
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
		case "qurl-go":
			if scenario.Status != "implemented" && scenario.Status != "todo" {
				t.Errorf("qurl-go scenario %q has invalid status %q", scenario.ID, scenario.Status)
			}
		case "qurl-connector", "nhp-orchestrator":
			if scenario.Status != "external_dependency" {
				t.Errorf("external scenario %q has invalid status %q", scenario.ID, scenario.Status)
			}
		default:
			t.Errorf("scenario %q has unknown owner %q", scenario.ID, scenario.Owner)
		}
		if scenario.Status == "implemented" {
			implemented++
		}
	}
	sort.Strings(actualIDs)
	if !slicesEqual(actualIDs, expectedIDs) {
		t.Fatalf("scenario inventory ids =\n%q\nwant exact pre-retirement inventory\n%q", actualIDs, expectedIDs)
	}
	if implemented != 7 {
		t.Fatalf("implemented scenario count = %d, want the current seven honest proof scenarios", implemented)
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
