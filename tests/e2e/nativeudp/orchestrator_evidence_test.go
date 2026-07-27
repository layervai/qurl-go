package nativeudp_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The orchestrator half of the cross-repository proof. layervai/nhp already
// produces a frozen `orchestrator-evidence.json` document
// (.github/scripts/udp_proof_orchestrator_contract.py); qurl-go is the client
// that must refuse to believe it unless every binding is exact. Without this
// adapter the attended workflow's -run filter names two proof top levels that
// do not exist, so no orchestrator-owned inventory row can ever be finished.
//
// Like the Connector adapter this is read-only: it verifies an immutable
// producer run identity, the deployment manifest both sides observed, and the
// reviewed retired-lifecycle-surface contract. It never simulates a result.
const (
	orchestratorEvidencePathEnv = "QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH"
	orchestratorEvidenceSHAEnv  = "QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256"
	nhpControllerRunIDEnv       = "QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ID"
	nhpControllerRunAttemptEnv  = "QURL_GO_SANDBOX_NHP_CONTROLLER_RUN_ATTEMPT"

	orchestratorProofRepository      = "layervai/nhp"
	orchestratorProducerWorkflowPath = ".github/workflows/udp-proof-deployment-manifest.yml"
	orchestratorRetirementProofGate  = "udp_lifecycle_retirement"
	maxOrchestratorEvidenceBytes     = 64 * 1024

	// The producer pins the same two digests over qurl-go's own reviewed
	// surface contract, so neither side can quote a different revision.
	retiredLifecycleSurfaceContractPath      = "tests/e2e/nativeudp/retired_lifecycle_surface.json"
	retiredLifecycleSurfaceRawSHA256         = "39fe3deb3c92c5506e8b101b843529099d67ab462d350168122d3732a8adf3eb"
	retiredLifecycleSurfaceCanonicalSHA256v1 = "3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c"
)

// orchestratorProducedRows is the exact frozen row set layervai/nhp proves
// today (PRODUCED_ROWS in udp_proof_orchestrator_contract.py). Widening it here
// without the producer widening it too must fail closed.
var orchestratorProducedRows = []string{"retirement.nhp_registrar_surface_state"}

type orchestratorProofEvidence struct {
	SchemaVersion int                                  `json:"schema_version"`
	Gate          string                               `json:"gate"`
	Phase         string                               `json:"phase"`
	ObservedAt    string                               `json:"observed_at"`
	Producer      orchestratorEvidenceProducer         `json:"producer"`
	Bindings      orchestratorEvidenceBindings         `json:"bindings"`
	ProducedRows  []string                             `json:"produced_rows"`
	Rows          map[string]orchestratorEvidenceRowV1 `json:"rows"`
}

type orchestratorEvidenceProducer struct {
	Repository   string `json:"repository"`
	WorkflowPath string `json:"workflow_path"`
	RunID        int64  `json:"run_id"`
	RunAttempt   int64  `json:"run_attempt"`
	HeadSHA      string `json:"head_sha"`
}

type orchestratorEvidenceBindings struct {
	DeploymentManifestSHA256              string `json:"deployment_manifest_sha256"`
	DeploymentRuntimeInputsSHA256         string `json:"deployment_runtime_inputs_sha256"`
	NHPSourceSHA                          string `json:"nhp_source_sha"`
	QurlGoSourceSHA                       string `json:"qurl_go_source_sha"`
	RetiredLifecycleSurfacePath           string `json:"retired_lifecycle_surface_path"`
	RetiredLifecycleSurfaceRawSHA256      string `json:"retired_lifecycle_surface_raw_sha256"`
	RetiredLifecycleSurfaceCanonicalSHA25 string `json:"retired_lifecycle_surface_canonical_sha256"`
}

type orchestratorEvidenceRowV1 struct {
	Phase             string `json:"phase"`
	InterfacesSHA256  string `json:"interfaces_sha256"`
	NHPSourceSHA      string `json:"nhp_source_sha"`
	DispatchesWork    bool   `json:"dispatches_lifecycle_work"`
	SurfaceEntryCount int    `json:"surface_entry_count"`
}

func decodeOrchestratorProofEvidence(raw []byte) (orchestratorProofEvidence, error) {
	return decodeStrictJSON[orchestratorProofEvidence](raw, "orchestrator evidence")
}

// validateOrchestratorProofEvidence fails closed on every binding the producer
// promises. The qurl-go side deliberately re-derives nothing from the producer:
// each expectation is supplied by the attended workflow, so a compromised or
// stale evidence document cannot pick its own reference values.
func validateOrchestratorProofEvidence(
	evidence orchestratorProofEvidence,
	phase, deploymentSHA, controllerRunID, controllerRunAttempt string,
) error {
	if evidence.SchemaVersion != 1 || evidence.Gate != orchestratorRetirementProofGate || evidence.Phase != phase {
		return fmt.Errorf("orchestrator evidence header = schema %d, gate %q, phase %q; want 1, %q, %q",
			evidence.SchemaVersion, evidence.Gate, evidence.Phase, orchestratorRetirementProofGate, phase)
	}
	if evidence.ObservedAt == "" {
		return errors.New("orchestrator evidence must record observed_at")
	}

	producer := evidence.Producer
	if producer.Repository != orchestratorProofRepository || producer.WorkflowPath != orchestratorProducerWorkflowPath {
		return fmt.Errorf("orchestrator producer identity drift: repository=%q workflow_path=%q",
			producer.Repository, producer.WorkflowPath)
	}
	if !canonicalLowerHex(producer.HeadSHA, 40) {
		return fmt.Errorf("orchestrator producer head_sha %q is not a canonical commit SHA", producer.HeadSHA)
	}
	if producer.RunID < 1 || producer.RunAttempt < 1 {
		return errors.New("orchestrator producer run id and attempt must be positive")
	}
	// The attended controller run that created this proof runner is the only
	// run allowed to have produced the evidence it is now judged by.
	if !canonicalPositiveDecimal(controllerRunID) || !canonicalPositiveDecimal(controllerRunAttempt) {
		return errors.New("attended NHP controller run identity must be canonical positive decimals")
	}
	if fmt.Sprintf("%d", producer.RunID) != controllerRunID ||
		fmt.Sprintf("%d", producer.RunAttempt) != controllerRunAttempt {
		return fmt.Errorf("orchestrator evidence producer run %d/%d is not the attended controller run %s/%s",
			producer.RunID, producer.RunAttempt, controllerRunID, controllerRunAttempt)
	}

	bindings := evidence.Bindings
	for name, value := range map[string]string{
		"deployment_manifest_sha256":                 bindings.DeploymentManifestSHA256,
		"deployment_runtime_inputs_sha256":           bindings.DeploymentRuntimeInputsSHA256,
		"retired_lifecycle_surface_raw_sha256":       bindings.RetiredLifecycleSurfaceRawSHA256,
		"retired_lifecycle_surface_canonical_sha256": bindings.RetiredLifecycleSurfaceCanonicalSHA25,
	} {
		if !canonicalLowerHex(value, sha256.Size*2) {
			return fmt.Errorf("orchestrator evidence %s is not a canonical SHA-256 digest", name)
		}
	}
	for name, value := range map[string]string{
		"nhp_source_sha":     bindings.NHPSourceSHA,
		"qurl_go_source_sha": bindings.QurlGoSourceSHA,
	} {
		if !canonicalLowerHex(value, 40) {
			return fmt.Errorf("orchestrator evidence %s is not a canonical commit SHA", name)
		}
	}
	if bindings.DeploymentManifestSHA256 != deploymentSHA {
		return fmt.Errorf("orchestrator deployment manifest SHA-256 = %q, want current qurl-go manifest %q",
			bindings.DeploymentManifestSHA256, deploymentSHA)
	}
	if bindings.RetiredLifecycleSurfacePath != retiredLifecycleSurfaceContractPath ||
		bindings.RetiredLifecycleSurfaceRawSHA256 != retiredLifecycleSurfaceRawSHA256 ||
		bindings.RetiredLifecycleSurfaceCanonicalSHA25 != retiredLifecycleSurfaceCanonicalSHA256v1 {
		return fmt.Errorf("orchestrator evidence is not bound to the reviewed retired lifecycle surface contract: path=%q raw=%q canonical=%q",
			bindings.RetiredLifecycleSurfacePath,
			bindings.RetiredLifecycleSurfaceRawSHA256,
			bindings.RetiredLifecycleSurfaceCanonicalSHA25,
		)
	}

	if len(evidence.Rows) == 0 {
		return errors.New("orchestrator evidence rows must be non-empty")
	}
	if !slices.Equal(evidence.ProducedRows, orchestratorProducedRows) {
		return fmt.Errorf("orchestrator evidence produced_rows = %q, want the frozen producer row set %q",
			evidence.ProducedRows, orchestratorProducedRows)
	}
	rowIDs := make([]string, 0, len(evidence.Rows))
	for id := range evidence.Rows {
		rowIDs = append(rowIDs, id)
	}
	slices.Sort(rowIDs)
	if !slices.Equal(rowIDs, orchestratorProducedRows) {
		return fmt.Errorf("orchestrator evidence rows %q do not match produced_rows %q", rowIDs, orchestratorProducedRows)
	}
	for _, id := range orchestratorProducedRows {
		row := evidence.Rows[id]
		if row.Phase != phase {
			return fmt.Errorf("orchestrator row %q phase = %q, want %q", id, row.Phase, phase)
		}
		if !canonicalLowerHex(row.InterfacesSHA256, sha256.Size*2) {
			return fmt.Errorf("orchestrator row %q interfaces_sha256 is not a canonical SHA-256 digest", id)
		}
		if row.NHPSourceSHA != bindings.NHPSourceSHA {
			return fmt.Errorf("orchestrator row %q observed NHP revision %q, want the bound %q",
				id, row.NHPSourceSHA, bindings.NHPSourceSHA)
		}
		if row.SurfaceEntryCount < 1 {
			return fmt.Errorf("orchestrator row %q must enumerate at least one surface entry", id)
		}
		// A retired surface may remain deployed pre-removal, but it must never
		// still dispatch lifecycle work in either phase.
		if row.DispatchesWork {
			return fmt.Errorf("orchestrator row %q still dispatches lifecycle work", id)
		}
	}
	return nil
}

// readOrchestratorProofEvidence enforces the same immutable-artifact handling
// the Connector adapter requires: one canonical absolute path, a regular
// read-only file, a bounded size, and a workflow-verified digest.
func readOrchestratorProofEvidence(t *testing.T) orchestratorProofEvidence {
	t.Helper()
	expectedSHA := os.Getenv(orchestratorEvidenceSHAEnv)
	if !canonicalLowerHex(expectedSHA, sha256.Size*2) {
		t.Fatalf("%s must be an exact lowercase SHA-256 digest", orchestratorEvidenceSHAEnv)
	}
	path := os.Getenv(orchestratorEvidencePathEnv)
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) {
		t.Fatalf("%s must be one canonical absolute path", orchestratorEvidencePathEnv)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect orchestrator evidence: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("orchestrator evidence must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("orchestrator evidence mode = %o, want 444", info.Mode().Perm())
	}
	if info.Size() <= 0 || info.Size() > maxOrchestratorEvidenceBytes {
		t.Fatalf("orchestrator evidence size = %d, want 1..%d", info.Size(), maxOrchestratorEvidenceBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read orchestrator evidence: %v", err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != expectedSHA {
		t.Fatalf("orchestrator evidence SHA-256 = %q, want workflow-verified %q", got, expectedSHA)
	}
	evidence, err := decodeOrchestratorProofEvidence(raw)
	if err != nil {
		t.Fatalf("decode orchestrator evidence: %v", err)
	}
	return evidence
}

// requireOrchestratorProofInputs gates both orchestrator proof top levels.
// Absent inputs skip rather than fail: every orchestrator-owned row is still
// external_dependency, so the inventory gate stays red on its own and a skip
// here cannot be mistaken for evidence. Only rows whose status is already
// "implemented" are skip-checked by the workflow.
func requireOrchestratorProofInputs(t *testing.T) (orchestratorProofEvidence, string) {
	t.Helper()
	switch os.Getenv(strictEnv) {
	case "", "0", "false":
		t.Skip("attended proof only; the workflow must attest an exact same-phase NHP orchestrator run")
	case "1", "true":
	default:
		t.Fatalf("%s must be true/1 or false/0", strictEnv)
	}
	if os.Getenv(orchestratorEvidencePathEnv) == "" {
		t.Skip("attended proof only; the attended controller must publish orchestrator evidence")
	}
	phase := os.Getenv(proofPhaseEnv)
	if phase != "pre_removal" && phase != "post_removal" {
		t.Fatalf("%s must be pre_removal or post_removal", proofPhaseEnv)
	}
	deploymentSHA := os.Getenv(deploymentManifestSHAEnv)
	if !canonicalLowerHex(deploymentSHA, sha256.Size*2) {
		t.Fatalf("%s must be an exact lowercase SHA-256 digest", deploymentManifestSHAEnv)
	}
	evidence := readOrchestratorProofEvidence(t)
	if err := validateOrchestratorProofEvidence(
		evidence, phase, deploymentSHA,
		os.Getenv(nhpControllerRunIDEnv), os.Getenv(nhpControllerRunAttemptEnv),
	); err != nil {
		t.Fatal(err)
	}
	return evidence, phase
}

func logOrchestratorEvidence(t *testing.T, evidence orchestratorProofEvidence) {
	t.Helper()
	t.Logf("EVIDENCE orchestrator_repository=%s producer_run_id=%d producer_run_attempt=%d producer_head_sha=%s nhp_source_sha=%s deployment_manifest_sha256=%s",
		evidence.Producer.Repository,
		evidence.Producer.RunID,
		evidence.Producer.RunAttempt,
		evidence.Producer.HeadSHA,
		evidence.Bindings.NHPSourceSHA,
		evidence.Bindings.DeploymentManifestSHA256,
	)
}

// TestSandboxTopology is the orchestrator topology/retirement proof top level
// named by the attended workflow's -run filter and by the inventory's
// nhp-orchestrator adapter namespace.
func TestSandboxTopology(t *testing.T) {
	evidence, _ := requireOrchestratorProofInputs(t)
	logOrchestratorEvidence(t, evidence)

	// Only rows the producer actually proves get a subtest. The remaining
	// orchestrator rows stay external_dependency until nhp widens PRODUCED_ROWS.
	if slices.Contains(evidence.ProducedRows, "retirement.nhp_registrar_surface_state") {
		t.Run("nhp_registrar_surface_state", func(t *testing.T) {
			row := evidence.Rows["retirement.nhp_registrar_surface_state"]
			t.Logf("EVIDENCE interfaces_sha256=%s surface_entry_count=%d dispatches_lifecycle_work=%t",
				row.InterfacesSHA256, row.SurfaceEntryCount, row.DispatchesWork)
		})
	}
}

// TestSandboxWireEvidence is the orchestrator wire-attribution proof top level.
// layervai/nhp does not yet produce either wire_trace row, so this currently
// has no provable subtest; the top level exists so the attended workflow's
// -run filter resolves and the rows are finishable without reassigning owners.
func TestSandboxWireEvidence(t *testing.T) {
	evidence, _ := requireOrchestratorProofInputs(t)
	logOrchestratorEvidence(t, evidence)
	for _, id := range []string{
		"wire.registration_lst_lrt_reg_rak_completion",
		"wire.session_knk_ack_ext_ack",
	} {
		if slices.Contains(evidence.ProducedRows, id) {
			t.Fatalf("orchestrator evidence claims %s but this adapter has no verifier for it", id)
		}
	}
	t.Skip("no orchestrator wire_trace row is produced yet; both wire rows remain external_dependency")
}

func TestDecodeOrchestratorProofEvidenceRejectsAmbiguousJSON(t *testing.T) {
	tests := map[string]string{
		"duplicate key": `{"schema_version":1,"schema_version":1}`,
		"unknown key":   `{"unknown":true}`,
		"trailing JSON": `{}` + `{}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOrchestratorProofEvidence([]byte(raw)); err == nil {
				t.Fatal("decode accepted ambiguous orchestrator evidence JSON")
			}
		})
	}
}

func TestValidateOrchestratorProofEvidenceFailsClosed(t *testing.T) {
	deploymentSHA := strings.Repeat("d", 64)
	valid := func(phase string) orchestratorProofEvidence {
		return orchestratorProofEvidence{
			SchemaVersion: 1,
			Gate:          orchestratorRetirementProofGate,
			Phase:         phase,
			ObservedAt:    "2026-07-27T00:00:00Z",
			Producer: orchestratorEvidenceProducer{
				Repository:   orchestratorProofRepository,
				WorkflowPath: orchestratorProducerWorkflowPath,
				RunID:        12,
				RunAttempt:   3,
				HeadSHA:      strings.Repeat("a", 40),
			},
			Bindings: orchestratorEvidenceBindings{
				DeploymentManifestSHA256:              deploymentSHA,
				DeploymentRuntimeInputsSHA256:         strings.Repeat("1", 64),
				NHPSourceSHA:                          strings.Repeat("b", 40),
				QurlGoSourceSHA:                       strings.Repeat("c", 40),
				RetiredLifecycleSurfacePath:           retiredLifecycleSurfaceContractPath,
				RetiredLifecycleSurfaceRawSHA256:      retiredLifecycleSurfaceRawSHA256,
				RetiredLifecycleSurfaceCanonicalSHA25: retiredLifecycleSurfaceCanonicalSHA256v1,
			},
			ProducedRows: []string{"retirement.nhp_registrar_surface_state"},
			Rows: map[string]orchestratorEvidenceRowV1{
				"retirement.nhp_registrar_surface_state": {
					Phase:             phase,
					InterfacesSHA256:  strings.Repeat("2", 64),
					NHPSourceSHA:      strings.Repeat("b", 40),
					DispatchesWork:    false,
					SurfaceEntryCount: 2,
				},
			},
		}
	}

	for _, phase := range []string{"pre_removal", "post_removal"} {
		if err := validateOrchestratorProofEvidence(valid(phase), phase, deploymentSHA, "12", "3"); err != nil {
			t.Fatalf("valid %s orchestrator evidence rejected: %v", phase, err)
		}
	}

	tests := map[string]func(*orchestratorProofEvidence){
		"schema drift":           func(v *orchestratorProofEvidence) { v.SchemaVersion = 2 },
		"gate drift":             func(v *orchestratorProofEvidence) { v.Gate = "other_gate" },
		"phase drift":            func(v *orchestratorProofEvidence) { v.Phase = "pre_removal" },
		"missing observed_at":    func(v *orchestratorProofEvidence) { v.ObservedAt = "" },
		"foreign repository":     func(v *orchestratorProofEvidence) { v.Producer.Repository = "layervai/qurl-go" },
		"foreign workflow":       func(v *orchestratorProofEvidence) { v.Producer.WorkflowPath = ".github/workflows/ci.yml" },
		"bad head sha":           func(v *orchestratorProofEvidence) { v.Producer.HeadSHA = "not-a-sha" },
		"zero run id":            func(v *orchestratorProofEvidence) { v.Producer.RunID = 0 },
		"zero run attempt":       func(v *orchestratorProofEvidence) { v.Producer.RunAttempt = 0 },
		"unattended run id":      func(v *orchestratorProofEvidence) { v.Producer.RunID = 99 },
		"unattended run attempt": func(v *orchestratorProofEvidence) { v.Producer.RunAttempt = 9 },
		"wrong deployment":       func(v *orchestratorProofEvidence) { v.Bindings.DeploymentManifestSHA256 = strings.Repeat("e", 64) },
		"bad runtime inputs":     func(v *orchestratorProofEvidence) { v.Bindings.DeploymentRuntimeInputsSHA256 = "short" },
		"bad nhp source":         func(v *orchestratorProofEvidence) { v.Bindings.NHPSourceSHA = "nope" },
		"bad qurl-go source":     func(v *orchestratorProofEvidence) { v.Bindings.QurlGoSourceSHA = "nope" },
		"surface path drift":     func(v *orchestratorProofEvidence) { v.Bindings.RetiredLifecycleSurfacePath = "other.json" },
		"surface raw drift": func(v *orchestratorProofEvidence) {
			v.Bindings.RetiredLifecycleSurfaceRawSHA256 = strings.Repeat("f", 64)
		},
		"surface canonical drift": func(v *orchestratorProofEvidence) {
			v.Bindings.RetiredLifecycleSurfaceCanonicalSHA25 = strings.Repeat("f", 64)
		},
		"no rows": func(v *orchestratorProofEvidence) { v.Rows = nil },
		"widened produced rows": func(v *orchestratorProofEvidence) {
			v.ProducedRows = append(v.ProducedRows, "wire.session_knk_ack_ext_ack")
		},
		"rows disagree with produced_rows": func(v *orchestratorProofEvidence) {
			v.Rows["wire.session_knk_ack_ext_ack"] = orchestratorEvidenceRowV1{}
		},
		"row phase drift": func(v *orchestratorProofEvidence) {
			row := v.Rows["retirement.nhp_registrar_surface_state"]
			row.Phase = "pre_removal"
			v.Rows["retirement.nhp_registrar_surface_state"] = row
		},
		"row interfaces digest drift": func(v *orchestratorProofEvidence) {
			row := v.Rows["retirement.nhp_registrar_surface_state"]
			row.InterfacesSHA256 = "short"
			v.Rows["retirement.nhp_registrar_surface_state"] = row
		},
		"row nhp revision drift": func(v *orchestratorProofEvidence) {
			row := v.Rows["retirement.nhp_registrar_surface_state"]
			row.NHPSourceSHA = strings.Repeat("9", 40)
			v.Rows["retirement.nhp_registrar_surface_state"] = row
		},
		"row enumerates nothing": func(v *orchestratorProofEvidence) {
			row := v.Rows["retirement.nhp_registrar_surface_state"]
			row.SurfaceEntryCount = 0
			v.Rows["retirement.nhp_registrar_surface_state"] = row
		},
		"row still dispatches lifecycle work": func(v *orchestratorProofEvidence) {
			row := v.Rows["retirement.nhp_registrar_surface_state"]
			row.DispatchesWork = true
			v.Rows["retirement.nhp_registrar_surface_state"] = row
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := valid("post_removal")
			mutate(&evidence)
			if err := validateOrchestratorProofEvidence(evidence, "post_removal", deploymentSHA, "12", "3"); err == nil {
				t.Fatal("invalid orchestrator evidence was accepted")
			}
		})
	}

	// The attended controller identity itself must be canonical.
	for name, controller := range map[string][2]string{
		"empty controller run":     {"", "3"},
		"empty controller attempt": {"12", ""},
		"zero-prefixed run":        {"012", "3"},
		"non-numeric attempt":      {"12", "3a"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOrchestratorProofEvidence(
				valid("post_removal"), "post_removal", deploymentSHA, controller[0], controller[1],
			); err == nil {
				t.Fatal("non-canonical attended controller identity was accepted")
			}
		})
	}
}

// TestOrchestratorAdapterNamespacesMatchInventory proves the two proof top
// levels this file defines are exactly the ones the inventory requires for
// nhp-orchestrator rows, so the adapter namespace and the gate cannot drift.
func TestOrchestratorAdapterNamespacesMatchInventory(t *testing.T) {
	for _, row := range []scenarioInventoryRow{
		{Owner: "nhp-orchestrator", TestName: "TestSandboxTopology/nhp_registrar_surface_state"},
		{Owner: "nhp-orchestrator", TestName: "TestSandboxWireEvidence/session_knk_ack_ext_ack"},
	} {
		if err := validateScenarioAdapterNamespace(row); err != nil {
			t.Fatalf("orchestrator adapter %q rejected by the inventory namespace rule: %v", row.TestName, err)
		}
	}
	// Every produced row must be an orchestrator-owned row in the inventory.
	inventory := readInventoryForOrchestratorAdapter(t)
	for _, id := range orchestratorProducedRows {
		index := slices.IndexFunc(inventory.Scenarios, func(row scenarioInventoryRow) bool { return row.ID == id })
		if index < 0 {
			t.Fatalf("produced row %q is absent from the inventory", id)
		}
		row := inventory.Scenarios[index]
		if row.Owner != "nhp-orchestrator" {
			t.Fatalf("produced row %q owner = %q, want nhp-orchestrator", id, row.Owner)
		}
		if !strings.HasPrefix(row.TestName, "TestSandboxTopology/") &&
			!strings.HasPrefix(row.TestName, "TestSandboxWireEvidence/") {
			t.Fatalf("produced row %q test name %q is outside the orchestrator adapter namespace", id, row.TestName)
		}
	}
}

func readInventoryForOrchestratorAdapter(t *testing.T) scenarioInventory {
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
