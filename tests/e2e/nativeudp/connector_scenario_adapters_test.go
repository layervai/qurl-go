package nativeudp_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

const (
	connectorScenarioEvidenceMapPath = "connector_scenario_evidence_map.json"
	connectorStrictScenarioNamesPath = "connector_strict_scenario_names.json"
	connectorAdapterTestPrefix       = "TestSandboxConnectorUDP/"
	connectorScenarioOwner           = "qurl-connector"
)

// connectorScenarioEvidenceMap records which qurl-connector strict-proof rows
// must be attested as passing before a qurl-connector-owned qurl-go scenario can
// be asserted here. It is reviewed data, not evidence: it never marks a scenario
// passed and never changes a scenario's status.
type connectorScenarioEvidenceMap struct {
	SchemaVersion int                                     `json:"schema_version"`
	Gate          string                                  `json:"gate"`
	Comment       string                                  `json:"comment"`
	Scenarios     map[string]connectorScenarioEvidenceRow `json:"scenarios"`
}

type connectorScenarioEvidenceRow struct {
	TestName           string   `json:"test_name"`
	EvidenceKinds      []string `json:"evidence_kinds"`
	ConnectorScenarios []string `json:"connector_scenarios"`
	Rationale          string   `json:"rationale"`
}

type connectorStrictScenarioNameSet struct {
	SchemaVersion int      `json:"schema_version"`
	Gate          string   `json:"gate"`
	ScenarioNames []string `json:"scenario_names"`
}

func loadConnectorScenarioEvidenceMap(t *testing.T) connectorScenarioEvidenceMap {
	t.Helper()
	raw, err := os.ReadFile(connectorScenarioEvidenceMapPath)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictJSON[connectorScenarioEvidenceMap](raw, "connector scenario evidence map")
	if err != nil {
		t.Fatalf("decode connector scenario evidence map: %v", err)
	}
	if value.SchemaVersion != 1 || value.Gate != connectorRetirementProofGate {
		t.Fatalf("connector scenario evidence map header = schema %d, gate %q", value.SchemaVersion, value.Gate)
	}
	return value
}

func loadConnectorStrictScenarioNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(connectorStrictScenarioNamesPath)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictJSON[connectorStrictScenarioNameSet](raw, "connector strict scenario names")
	if err != nil {
		t.Fatalf("decode connector strict scenario names: %v", err)
	}
	if value.SchemaVersion != 1 || value.Gate != connectorRetirementProofGate ||
		len(value.ScenarioNames) != connectorScenarioCount {
		t.Fatalf("connector strict scenario names = schema %d, gate %q, %d names; want 1, %q, %d",
			value.SchemaVersion, value.Gate, len(value.ScenarioNames), connectorRetirementProofGate, connectorScenarioCount)
	}
	return value.ScenarioNames
}

func loadPreRetirementInventory(t *testing.T) scenarioInventory {
	t.Helper()
	raw, err := os.ReadFile("pre_retirement_scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := decodeScenarioInventory(raw)
	if err != nil {
		t.Fatalf("decode scenario inventory: %v", err)
	}
	return inventory
}

func loadTypedEvidenceContractScenarios(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile("typed_evidence_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Scenarios map[string][]string `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	return contract.Scenarios
}

// TestConnectorScenarioEvidenceMapMatchesBothInventories keeps the reviewed
// mapping bound to the two reviewed inventories it claims to join. A drifted
// test name, evidence kind, or Connector row name fails here rather than
// silently asserting the wrong scenario during a strict proof.
func TestConnectorScenarioEvidenceMapMatchesBothInventories(t *testing.T) {
	mapping := loadConnectorScenarioEvidenceMap(t)
	inventory := loadPreRetirementInventory(t)
	contract := loadTypedEvidenceContractScenarios(t)
	connectorNames := loadConnectorStrictScenarioNames(t)

	blocked := make(map[string]scenarioInventoryRow)
	for _, scenario := range inventory.Scenarios {
		if scenario.Owner == connectorScenarioOwner && scenario.Status == "external_dependency" {
			blocked[scenario.ID] = scenario
		}
	}
	if len(blocked) == 0 {
		t.Fatal("inventory has no externally blocked Connector scenarios to map")
	}

	mappedIDs := make([]string, 0, len(mapping.Scenarios))
	for id := range mapping.Scenarios {
		mappedIDs = append(mappedIDs, id)
	}
	blockedIDs := make([]string, 0, len(blocked))
	for id := range blocked {
		blockedIDs = append(blockedIDs, id)
	}
	sort.Strings(mappedIDs)
	sort.Strings(blockedIDs)
	if !slices.Equal(mappedIDs, blockedIDs) {
		t.Fatalf("evidence map covers %q, want exactly the blocked Connector scenarios %q", mappedIDs, blockedIDs)
	}

	for id, row := range mapping.Scenarios {
		if row.TestName != blocked[id].TestName {
			t.Errorf("scenario %q maps test %q, want inventory test %q", id, row.TestName, blocked[id].TestName)
		}
		if !strings.HasPrefix(row.TestName, connectorAdapterTestPrefix) {
			t.Errorf("scenario %q test %q is outside the Connector adapter namespace", id, row.TestName)
		}
		if row.Rationale == "" {
			t.Errorf("scenario %q has no reviewed rationale", id)
		}
		if !slices.Equal(row.EvidenceKinds, contract[id]) {
			t.Errorf("scenario %q maps kinds %q, want typed evidence contract kinds %q", id, row.EvidenceKinds, contract[id])
		}
		if len(row.ConnectorScenarios) == 0 {
			t.Errorf("scenario %q names no Connector row; it would assert a vacuous pass", id)
		}
		if !sort.StringsAreSorted(row.ConnectorScenarios) {
			t.Errorf("scenario %q Connector rows are not sorted", id)
		}
		seen := make(map[string]struct{}, len(row.ConnectorScenarios))
		for _, name := range row.ConnectorScenarios {
			if _, duplicate := seen[name]; duplicate {
				t.Errorf("scenario %q repeats Connector row %q", id, name)
			}
			seen[name] = struct{}{}
			if !slices.Contains(connectorNames, name) {
				t.Errorf("scenario %q references unknown Connector row %q", id, name)
			}
		}
	}
}

// TestConnectorScenarioEvidenceMapIsNotAStatusChange guards the honest gate: the
// adapters exist so a passing Connector run can be consumed, but no Connector
// row may be promoted out of external_dependency by this mapping.
func TestConnectorScenarioEvidenceMapIsNotAStatusChange(t *testing.T) {
	inventory := loadPreRetirementInventory(t)
	mapping := loadConnectorScenarioEvidenceMap(t)
	for _, scenario := range inventory.Scenarios {
		if _, mapped := mapping.Scenarios[scenario.ID]; !mapped {
			continue
		}
		if scenario.Status != "external_dependency" {
			t.Errorf("mapped scenario %q status = %q; the mapping is a consumption mechanism, not a status change",
				scenario.ID, scenario.Status)
		}
	}
}

// connectorScenarioAdapters runs one adapter per externally blocked
// qurl-connector scenario. Each adapter passes only when the Connector attested
// an exact pass for every reviewed Connector row that discharges it.
func connectorScenarioAdapters(t *testing.T, attestation connectorProofAttestation) {
	t.Helper()
	mapping := loadConnectorScenarioEvidenceMap(t)
	ids := make([]string, 0, len(mapping.Scenarios))
	for id := range mapping.Scenarios {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := mapping.Scenarios[id]
		subtest := strings.TrimPrefix(row.TestName, connectorAdapterTestPrefix)
		runTypedEvidenceScenario(t, subtest, id, row.EvidenceKinds, func(t *testing.T) {
			if err := requireConnectorScenarioPass(attestation, row.ConnectorScenarios...); err != nil {
				t.Fatalf("%s is not proven by the Connector attestation: %v", id, err)
			}
			t.Logf("EVIDENCE scenario=%s connector_rows=%s connector_commit_sha=%s connector_run_id=%d",
				id, strings.Join(row.ConnectorScenarios, ","), attestation.ConnectorCommitSHA, attestation.ConnectorRunID)
		})
	}
}

func TestRequireConnectorScenarioPassFailsClosed(t *testing.T) {
	names := loadConnectorStrictScenarioNames(t)
	complete := func() connectorProofAttestation {
		records := make([]connectorScenarioRecord, 0, len(names))
		for index, name := range names {
			test := fmt.Sprintf("TestConnectorScenario%d", index)
			records = append(records, connectorScenarioRecord{
				Name:                  name,
				ObservedEvidenceKinds: []string{"cell_exchange"},
				Outcome:               connectorScenarioOutcomePass,
				RequiredEvidenceKinds: []string{"cell_exchange"},
				Status:                "implemented",
				Test:                  &test,
			})
		}
		return connectorProofAttestation{Scenarios: records}
	}

	if err := requireConnectorScenarioPass(complete(), names[0], names[1]); err != nil {
		t.Fatalf("complete attestation rejected: %v", err)
	}
	if err := requireConnectorScenarioPass(complete()); err == nil {
		t.Fatal("naming no Connector scenario was accepted as a pass")
	}
	if err := requireConnectorScenarioPass(complete(), "no-such-connector-row"); err == nil {
		t.Fatal("unknown Connector scenario was accepted as a pass")
	}

	tests := map[string]func(*connectorProofAttestation){
		"unproven outcome":  func(v *connectorProofAttestation) { v.Scenarios[0].Outcome = "not_proven" },
		"empty outcome":     func(v *connectorProofAttestation) { v.Scenarios[0].Outcome = "" },
		"todo status":       func(v *connectorProofAttestation) { v.Scenarios[0].Status = "todo" },
		"missing test":      func(v *connectorProofAttestation) { v.Scenarios[0].Test = nil },
		"dropped row":       func(v *connectorProofAttestation) { v.Scenarios = v.Scenarios[1:] },
		"duplicated row":    func(v *connectorProofAttestation) { v.Scenarios[1] = v.Scenarios[0] },
		"partial evidence":  func(v *connectorProofAttestation) { v.Scenarios[0].ObservedEvidenceKinds = nil },
		"noncanonical name": func(v *connectorProofAttestation) { v.Scenarios[0].Name = "Not_Canonical" },
		"no required kinds": func(v *connectorProofAttestation) {
			v.Scenarios[0].RequiredEvidenceKinds = nil
			v.Scenarios[0].ObservedEvidenceKinds = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			attestation := complete()
			mutate(&attestation)
			if err := requireConnectorScenarioPass(attestation, names[0]); err == nil {
				t.Fatal("invalid Connector scenario projection was accepted as a pass")
			}
		})
	}
}

func TestConnectorAttestationRejectsAggregateOnlySchema(t *testing.T) {
	// A v1 attestation carries no per-scenario records at all. It must be
	// rejected outright: consuming it would silently reduce every per-scenario
	// assertion to the aggregate gate this change exists to replace.
	raw := []byte(`{"schema_version":1,"gate":"udp_lifecycle_retirement"}`)
	attestation, err := decodeConnectorProofAttestation(raw)
	if err != nil {
		t.Fatalf("decode minimal v1 attestation: %v", err)
	}
	if err := validateConnectorProofAttestation(attestation, "pre_removal", strings.Repeat("d", 64), ""); err == nil {
		t.Fatal("aggregate-only v1 attestation was accepted")
	}
	if err := requireConnectorScenarioPass(attestation, "host-file-cold-enrollment-round-trip"); err == nil {
		t.Fatal("aggregate-only v1 attestation proved a scenario")
	}
}
