package nativeudp_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
	orchestratorEvidencePathEnv   = "QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_PATH"
	orchestratorEvidenceSHAEnv    = "QURL_GO_SANDBOX_ORCHESTRATOR_EVIDENCE_SHA256"
	deploymentProvenanceSHAEnv    = "QURL_GO_SANDBOX_DEPLOYMENT_PROVENANCE_SHA256"
	deploymentRuntimeInputsSHAEnv = "QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_SHA256"
	deploymentProducerRunIDEnv    = "QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ID"
	deploymentProducerAttemptEnv  = "QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ATTEMPT"
	deploymentProducerHeadSHAEnv  = "QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_HEAD_SHA"
	orchestratorNHPSourceSHAEnv   = "QURL_GO_SANDBOX_NHP_SOURCE_SHA"
	qurlServiceSourceSHAEnv       = "QURL_GO_SANDBOX_QURL_SERVICE_SOURCE_SHA"
	qurlServiceAuthorityImageEnv  = "QURL_GO_SANDBOX_QURL_SERVICE_AUTHORITY_IMAGE_DIGEST"

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

// orchestratorProducedRows is the exact static row set the trusted-main NHP
// producer can honestly observe before the attended client run. Runtime
// rejection, runner, live-route, and wire rows are added later by the NHP
// controller and must never be smuggled into this pre-run artifact.
var orchestratorProducedRows = []string{
	"orchestrator.real_hub_authority_and_two_cells",
	"retirement.generated_artifact_parity",
	"retirement.nhp_registrar_surface_state",
	"retirement.terraform_saved_plan_and_live_state",
}

var (
	orchestratorRetiredMessageTypes = []string{
		"NHP_LRT", "NHP_LST", "NHP_OTP", "NHP_RAK", "NHP_REG",
	}
	orchestratorRetiredHTTPOperations = []orchestratorRetiredHTTPOperation{
		{Method: "POST", Path: "/internal/v1/agent/otp"},
		{Method: "POST", Path: "/internal/v1/agent/register"},
	}
)

const (
	orchestratorRegistrarRowKind     = "surface_inventory"
	orchestratorRegistrarSurface     = "nhp_registrar"
	orchestratorMessageTypeSource    = "nhp/core/packet.go"
	orchestratorLegacyRegistrarRole  = "legacy_registrar"
	orchestratorNativeRuntimeRole    = "native_runtime"
	maxOrchestratorSurfaceInterfaces = 64
)

type orchestratorProofEvidence struct {
	SchemaVersion int                          `json:"schema_version"`
	Gate          string                       `json:"gate"`
	Phase         string                       `json:"phase"`
	ObservedAt    string                       `json:"observed_at"`
	Producer      orchestratorEvidenceProducer `json:"producer"`
	Bindings      orchestratorEvidenceBindings `json:"bindings"`
	ProducedRows  []string                     `json:"produced_rows"`
	Rows          map[string]json.RawMessage   `json:"rows"`
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
	DeploymentProvenanceSHA256            string `json:"deployment_provenance_sha256"`
	DeploymentRuntimeInputsSHA256         string `json:"deployment_runtime_inputs_sha256"`
	NHPSourceSHA                          string `json:"nhp_source_sha"`
	QurlGoSourceSHA                       string `json:"qurl_go_source_sha"`
	RetiredLifecycleSurfacePath           string `json:"retired_lifecycle_surface_path"`
	RetiredLifecycleSurfaceRawSHA256      string `json:"retired_lifecycle_surface_raw_sha256"`
	RetiredLifecycleSurfaceCanonicalSHA25 string `json:"retired_lifecycle_surface_canonical_sha256"`
}

type orchestratorRegistrarSurfaceRow struct {
	Kind                          string                               `json:"kind"`
	Surface                       string                               `json:"surface"`
	Phase                         string                               `json:"phase"`
	SourceRepository              string                               `json:"source_repository"`
	SourceSHA                     string                               `json:"source_sha"`
	MessageTypeSourcePath         string                               `json:"message_type_source_path"`
	MessageTypeSourceSHA256       string                               `json:"message_type_source_sha256"`
	RetiredMessageTypeWireValues  orchestratorRetiredMessageTypeValues `json:"retired_message_type_wire_values"`
	RetiredInternalHTTPOperations []orchestratorRetiredHTTPOperation   `json:"retired_internal_http_operations"`
	Interfaces                    []orchestratorNHPInterface           `json:"interfaces"`
	InterfacesSHA256              string                               `json:"interfaces_sha256"`
}

type orchestratorTopologyEndpoint struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
}

type orchestratorTopologyCell struct {
	CellID string `json:"cell_id"`
	orchestratorTopologyEndpoint
}

type orchestratorTopologyAuthority struct {
	SourceSHA                  string `json:"source_sha"`
	ImageDigest                string `json:"image_digest"`
	ProofPolicyConsumersActive bool   `json:"proof_policy_consumers_active"`
}

type orchestratorTopologyRow struct {
	Kind                       string                        `json:"kind"`
	ManifestTopologySHA256     string                        `json:"manifest_topology_sha256"`
	RuntimeTopologySHA256      string                        `json:"runtime_topology_sha256"`
	PublicIdentitiesSHA256     string                        `json:"public_identities_sha256"`
	WorkloadObservationsSHA256 string                        `json:"workload_observations_sha256"`
	Hub                        orchestratorTopologyEndpoint  `json:"hub"`
	Cells                      []orchestratorTopologyCell    `json:"cells"`
	Authority                  orchestratorTopologyAuthority `json:"authority"`
}

type orchestratorGeneratedContract struct {
	Repository      string `json:"repository"`
	Path            string `json:"path"`
	SourceSHA       string `json:"source_sha"`
	RawSHA256       string `json:"raw_sha256"`
	CanonicalSHA256 string `json:"canonical_sha256"`
}

type orchestratorGeneratedArtifact struct {
	Surface        string `json:"surface"`
	Repository     string `json:"repository"`
	SourceSHA      string `json:"source_sha"`
	Path           string `json:"path"`
	PathSHA256     string `json:"path_sha256"`
	ContractSHA256 string `json:"contract_sha256"`
	State          string `json:"state"`
}

type orchestratorGeneratedArtifactParityRow struct {
	Kind              string                          `json:"kind"`
	Surface           string                          `json:"surface"`
	Phase             string                          `json:"phase"`
	CanonicalContract orchestratorGeneratedContract   `json:"canonical_contract"`
	Artifacts         []orchestratorGeneratedArtifact `json:"artifacts"`
	ArtifactsSHA256   string                          `json:"artifacts_sha256"`
}

type orchestratorTerraformResource struct {
	Address string `json:"address"`
	State   string `json:"state"`
}

type orchestratorTerraformState struct {
	Lineage           string                          `json:"lineage"`
	Serial            int64                           `json:"serial"`
	ObservationSHA256 string                          `json:"observation_sha256"`
	Resources         []orchestratorTerraformResource `json:"resources"`
}

type orchestratorTerraformPlan struct {
	SavedPlanSHA256   *string  `json:"saved_plan_sha256"`
	ApplyRunID        *int64   `json:"apply_run_id"`
	ApprovedDeletions []string `json:"approved_deletions"`
}

type orchestratorTerraformRetirementRow struct {
	Kind      string                     `json:"kind"`
	Surface   string                     `json:"surface"`
	Phase     string                     `json:"phase"`
	State     orchestratorTerraformState `json:"state"`
	Plan      orchestratorTerraformPlan  `json:"plan"`
	RowSHA256 string                     `json:"row_sha256"`
}

type orchestratorRetiredMessageTypeValues struct {
	LST int `json:"NHP_LST"`
	LRT int `json:"NHP_LRT"`
	OTP int `json:"NHP_OTP"`
	REG int `json:"NHP_REG"`
	RAK int `json:"NHP_RAK"`
}

type orchestratorRetiredHTTPOperation struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type orchestratorNHPInterface struct {
	Symbol                  string   `json:"symbol"`
	Path                    string   `json:"path"`
	PathSHA256              string   `json:"path_sha256"`
	Role                    string   `json:"role"`
	State                   string   `json:"state"`
	LifecycleMessageTypes   []string `json:"lifecycle_message_types"`
	DispatchesLifecycleWork bool     `json:"dispatches_lifecycle_work"`
}

type orchestratorProofExpectations struct {
	Phase                      string
	DeploymentManifestSHA256   string
	DeploymentProvenanceSHA256 string
	DeploymentRuntimeSHA256    string
	ProducerRunID              string
	ProducerRunAttempt         string
	ProducerHeadSHA            string
	NHPSourceSHA               string
	QurlServiceSourceSHA       string
	QurlServiceAuthorityImage  string
	QurlGoSourceSHA            string
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
	expected orchestratorProofExpectations,
) error {
	if evidence.SchemaVersion != 1 || evidence.Gate != orchestratorRetirementProofGate || evidence.Phase != expected.Phase {
		return fmt.Errorf("orchestrator evidence header = schema %d, gate %q, phase %q; want 1, %q, %q",
			evidence.SchemaVersion, evidence.Gate, evidence.Phase, orchestratorRetirementProofGate, expected.Phase)
	}
	if !canonicalWholeSecondUTC(evidence.ObservedAt) {
		return errors.New("orchestrator evidence observed_at must be whole-second UTC RFC3339")
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
	// The controller authenticates one immutable deployment-producer artifact.
	// Bind the embedded producer identity to that exact run, not to the distinct
	// controller run that dispatched this client proof.
	if !canonicalPositiveDecimal(expected.ProducerRunID) || !canonicalPositiveDecimal(expected.ProducerRunAttempt) {
		return errors.New("authenticated deployment producer run identity must be canonical positive decimals")
	}
	if !canonicalLowerHex(expected.ProducerHeadSHA, 40) {
		return errors.New("authenticated deployment producer head SHA must be a canonical commit SHA")
	}
	if !canonicalLowerHex(expected.QurlServiceSourceSHA, 40) ||
		!strings.HasPrefix(expected.QurlServiceAuthorityImage, "sha256:") ||
		!canonicalLowerHex(strings.TrimPrefix(expected.QurlServiceAuthorityImage, "sha256:"), sha256.Size*2) {
		return errors.New("authenticated qurl-service authority source and image must be canonical")
	}
	if fmt.Sprintf("%d", producer.RunID) != expected.ProducerRunID ||
		fmt.Sprintf("%d", producer.RunAttempt) != expected.ProducerRunAttempt ||
		producer.HeadSHA != expected.ProducerHeadSHA {
		return fmt.Errorf("orchestrator evidence producer run %d/%d is not the authenticated deployment producer run %s/%s",
			producer.RunID, producer.RunAttempt, expected.ProducerRunID, expected.ProducerRunAttempt)
	}

	bindings := evidence.Bindings
	for name, value := range map[string]string{
		"deployment_manifest_sha256":                 bindings.DeploymentManifestSHA256,
		"deployment_provenance_sha256":               bindings.DeploymentProvenanceSHA256,
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
	if bindings.DeploymentManifestSHA256 != expected.DeploymentManifestSHA256 {
		return fmt.Errorf("orchestrator deployment manifest SHA-256 = %q, want current qurl-go manifest %q",
			bindings.DeploymentManifestSHA256, expected.DeploymentManifestSHA256)
	}
	if bindings.DeploymentProvenanceSHA256 != expected.DeploymentProvenanceSHA256 {
		return fmt.Errorf("orchestrator deployment provenance SHA-256 = %q, want authenticated producer provenance %q",
			bindings.DeploymentProvenanceSHA256, expected.DeploymentProvenanceSHA256)
	}
	if bindings.DeploymentRuntimeInputsSHA256 != expected.DeploymentRuntimeSHA256 {
		return fmt.Errorf("orchestrator deployment runtime inputs SHA-256 = %q, want current qurl-go runtime inputs %q",
			bindings.DeploymentRuntimeInputsSHA256, expected.DeploymentRuntimeSHA256)
	}
	if bindings.NHPSourceSHA != expected.NHPSourceSHA {
		return fmt.Errorf("orchestrator NHP source SHA = %q, want deployed NHP revision %q",
			bindings.NHPSourceSHA, expected.NHPSourceSHA)
	}
	if bindings.QurlGoSourceSHA != expected.QurlGoSourceSHA {
		return fmt.Errorf("orchestrator qurl-go source SHA = %q, want current qurl-go revision %q",
			bindings.QurlGoSourceSHA, expected.QurlGoSourceSHA)
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
		if err := validateOrchestratorStaticRow(
			id,
			evidence.Rows[id],
			expected.Phase,
			bindings.NHPSourceSHA,
			expected.QurlServiceSourceSHA,
			expected.QurlServiceAuthorityImage,
			bindings.QurlGoSourceSHA,
		); err != nil {
			return fmt.Errorf("orchestrator row %q: %w", id, err)
		}
	}
	return nil
}

func validateOrchestratorStaticRow(
	id string,
	raw json.RawMessage,
	phase, nhpSourceSHA, qurlServiceSourceSHA, qurlServiceAuthorityImage, qurlGoSourceSHA string,
) error {
	switch id {
	case "orchestrator.real_hub_authority_and_two_cells":
		row, err := decodeStrictJSON[orchestratorTopologyRow](raw, "NHP topology row")
		if err != nil {
			return err
		}
		return validateOrchestratorTopologyRow(
			row,
			qurlServiceSourceSHA,
			qurlServiceAuthorityImage,
		)
	case "retirement.generated_artifact_parity":
		row, err := decodeStrictJSON[orchestratorGeneratedArtifactParityRow](raw, "generated artifact parity row")
		if err != nil {
			return err
		}
		return validateGeneratedArtifactParityRow(row, phase, qurlGoSourceSHA)
	case "retirement.nhp_registrar_surface_state":
		row, err := decodeStrictJSON[orchestratorRegistrarSurfaceRow](raw, "NHP registrar surface row")
		if err != nil {
			return err
		}
		return validateNHPRegistrarSurfaceRow(row, phase, nhpSourceSHA)
	case "retirement.terraform_saved_plan_and_live_state":
		row, err := decodeStrictJSON[orchestratorTerraformRetirementRow](raw, "Terraform retirement row")
		if err != nil {
			return err
		}
		return validateTerraformRetirementRow(row, phase)
	default:
		return errors.New("row is not in the frozen static producer set")
	}
}

func canonicalWholeSecondUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil &&
		parsed.Nanosecond() == 0 &&
		parsed.Location() == time.UTC &&
		parsed.Format(time.RFC3339) == value
}

func validateNHPRegistrarSurfaceRow(row orchestratorRegistrarSurfaceRow, phase, nhpSourceSHA string) error {
	if row.Kind != orchestratorRegistrarRowKind ||
		row.Surface != orchestratorRegistrarSurface ||
		row.Phase != phase ||
		row.SourceRepository != orchestratorProofRepository ||
		row.SourceSHA != nhpSourceSHA {
		return errors.New("NHP registrar surface identity or source binding drift")
	}
	if row.MessageTypeSourcePath != orchestratorMessageTypeSource ||
		!canonicalLowerHex(row.MessageTypeSourceSHA256, sha256.Size*2) {
		return errors.New("NHP registrar message-type source binding drift")
	}
	if row.RetiredMessageTypeWireValues != (orchestratorRetiredMessageTypeValues{
		LST: 5,
		LRT: 6,
		OTP: 12,
		REG: 13,
		RAK: 14,
	}) {
		return errors.New("NHP registrar retired message-type wire values drift")
	}
	if !slices.Equal(row.RetiredInternalHTTPOperations, orchestratorRetiredHTTPOperations) {
		return errors.New("NHP registrar retired internal HTTP operations drift")
	}
	if len(row.Interfaces) < 1 || len(row.Interfaces) > maxOrchestratorSurfaceInterfaces {
		return fmt.Errorf("NHP registrar interfaces must contain 1..%d entries", maxOrchestratorSurfaceInterfaces)
	}

	seen := make(map[string]struct{}, len(row.Interfaces))
	roleCoverage := map[string]map[string]struct{}{
		orchestratorLegacyRegistrarRole: {},
		orchestratorNativeRuntimeRole:   {},
	}
	for index, item := range row.Interfaces {
		if err := validateNHPRegistrarInterface(item, phase); err != nil {
			return fmt.Errorf("NHP registrar interfaces[%d]: %w", index, err)
		}
		identity := item.Path + "\x00" + item.Symbol
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("NHP registrar interfaces[%d] duplicates an earlier entry", index)
		}
		seen[identity] = struct{}{}
		for _, messageType := range item.LifecycleMessageTypes {
			roleCoverage[item.Role][messageType] = struct{}{}
		}
	}
	for role, covered := range roleCoverage {
		if len(covered) != len(orchestratorRetiredMessageTypes) {
			return fmt.Errorf("NHP registrar role %q does not cover every retired message type", role)
		}
		for _, messageType := range orchestratorRetiredMessageTypes {
			if _, ok := covered[messageType]; !ok {
				return fmt.Errorf("NHP registrar role %q does not cover %s", role, messageType)
			}
		}
	}

	interfacesRaw, err := json.Marshal(row.Interfaces)
	if err != nil {
		return fmt.Errorf("encode NHP registrar interfaces: %w", err)
	}
	interfacesSHA, err := canonicalJSONSHA256(interfacesRaw)
	if err != nil {
		return fmt.Errorf("hash NHP registrar interfaces: %w", err)
	}
	if row.InterfacesSHA256 != interfacesSHA {
		return fmt.Errorf("NHP registrar interfaces SHA-256 = %q, want %q", row.InterfacesSHA256, interfacesSHA)
	}
	return nil
}

func validateOrchestratorTopologyRow(
	row orchestratorTopologyRow,
	qurlServiceSourceSHA, qurlServiceAuthorityImage string,
) error {
	if row.Kind != "topology_observation" {
		return errors.New("topology row kind drift")
	}
	for name, value := range map[string]string{
		"manifest_topology_sha256":     row.ManifestTopologySHA256,
		"runtime_topology_sha256":      row.RuntimeTopologySHA256,
		"public_identities_sha256":     row.PublicIdentitiesSHA256,
		"workload_observations_sha256": row.WorkloadObservationsSHA256,
	} {
		if !canonicalLowerHex(value, sha256.Size*2) {
			return fmt.Errorf("%s must be a canonical SHA-256", name)
		}
	}
	if err := validateTopologyEndpoint(row.Hub); err != nil {
		return fmt.Errorf("hub: %w", err)
	}
	if len(row.Cells) != 2 ||
		row.Cells[0].CellID != "cell0" ||
		row.Cells[1].CellID != "cell1" {
		return errors.New("topology cells must be the exact ordered cell0/cell1 pair")
	}
	seenHosts := map[string]struct{}{row.Hub.Host: {}}
	seenKeys := map[string]struct{}{row.Hub.ServerPublicKeySHA256: {}}
	for index, cell := range row.Cells {
		if err := validateTopologyEndpoint(cell.orchestratorTopologyEndpoint); err != nil {
			return fmt.Errorf("cells[%d]: %w", index, err)
		}
		if _, duplicate := seenHosts[cell.Host]; duplicate {
			return errors.New("topology hub and cells must have distinct hosts")
		}
		if _, duplicate := seenKeys[cell.ServerPublicKeySHA256]; duplicate {
			return errors.New("topology hub and cells must have distinct public identities")
		}
		seenHosts[cell.Host] = struct{}{}
		seenKeys[cell.ServerPublicKeySHA256] = struct{}{}
	}
	if row.Authority.SourceSHA != qurlServiceSourceSHA ||
		row.Authority.ImageDigest != qurlServiceAuthorityImage ||
		!row.Authority.ProofPolicyConsumersActive {
		return errors.New("topology authority is not bound to the deployed active qurl-service authority")
	}
	return nil
}

func validateTopologyEndpoint(endpoint orchestratorTopologyEndpoint) error {
	if endpoint.Host == "" ||
		endpoint.Host != strings.TrimSpace(endpoint.Host) ||
		len(endpoint.Host) > 253 ||
		strings.ContainsAny(endpoint.Host, "/\\:@") {
		return errors.New("host must be one bounded DNS name")
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return errors.New("port is outside the UDP port range")
	}
	if !canonicalLowerHex(endpoint.ServerPublicKeySHA256, sha256.Size*2) {
		return errors.New("server public key fingerprint must be a canonical SHA-256")
	}
	return nil
}

func validateGeneratedArtifactParityRow(
	row orchestratorGeneratedArtifactParityRow,
	phase, qurlGoSourceSHA string,
) error {
	if row.Kind != "surface_inventory" ||
		row.Surface != "generated_artifact_parity" ||
		row.Phase != phase {
		return errors.New("generated artifact parity identity or phase drift")
	}
	contract := row.CanonicalContract
	if contract.Repository != "layervai/qurl-go" ||
		contract.Path != retiredLifecycleSurfaceContractPath ||
		contract.SourceSHA != qurlGoSourceSHA ||
		contract.RawSHA256 != retiredLifecycleSurfaceRawSHA256 ||
		contract.CanonicalSHA256 != retiredLifecycleSurfaceCanonicalSHA256v1 {
		return errors.New("generated artifact parity canonical contract drift")
	}
	expectedSurfaces := []string{
		"connector_tarball",
		"distribution",
		"generated_config",
		"go",
		"integration_installer",
		"mcp",
		"python",
		"typescript",
		"website",
	}
	if len(row.Artifacts) != len(expectedSurfaces) {
		return fmt.Errorf("generated artifact parity has %d artifacts, want %d", len(row.Artifacts), len(expectedSurfaces))
	}
	observedSurfaces := make([]string, 0, len(row.Artifacts))
	seenPaths := make(map[string]struct{}, len(row.Artifacts))
	for index, artifact := range row.Artifacts {
		observedSurfaces = append(observedSurfaces, artifact.Surface)
		if artifact.Repository == "" ||
			!strings.HasPrefix(artifact.Repository, "layervai/") ||
			artifact.SourceSHA == "" ||
			!canonicalLowerHex(artifact.SourceSHA, 40) ||
			artifact.Path == "" ||
			artifact.Path != strings.TrimSpace(artifact.Path) ||
			strings.HasPrefix(artifact.Path, "/") ||
			strings.Contains(artifact.Path, "\\") ||
			slices.Contains(strings.Split(artifact.Path, "/"), "..") ||
			!canonicalLowerHex(artifact.PathSHA256, sha256.Size*2) ||
			artifact.ContractSHA256 != contract.CanonicalSHA256 ||
			artifact.State != "matches_contract" {
			return fmt.Errorf("generated artifact parity artifacts[%d] is not an exact matching surface", index)
		}
		identity := artifact.Repository + "\x00" + artifact.Path
		if _, duplicate := seenPaths[identity]; duplicate {
			return fmt.Errorf("generated artifact parity artifacts[%d] duplicates a repository path", index)
		}
		seenPaths[identity] = struct{}{}
	}
	if !slices.Equal(observedSurfaces, expectedSurfaces) {
		return fmt.Errorf("generated artifact surfaces = %q, want %q", observedSurfaces, expectedSurfaces)
	}
	artifactsRaw, err := json.Marshal(row.Artifacts)
	if err != nil {
		return fmt.Errorf("encode generated artifacts: %w", err)
	}
	artifactsSHA, err := canonicalJSONSHA256(artifactsRaw)
	if err != nil {
		return fmt.Errorf("hash generated artifacts: %w", err)
	}
	if row.ArtifactsSHA256 != artifactsSHA {
		return errors.New("generated artifacts SHA-256 is not bound to the artifact list")
	}
	return nil
}

func validateTerraformRetirementRow(row orchestratorTerraformRetirementRow, phase string) error {
	if row.Kind != "surface_inventory" ||
		row.Surface != "terraform_retirement" ||
		row.Phase != phase {
		return errors.New("Terraform retirement identity or phase drift")
	}
	if row.State.Lineage == "" ||
		row.State.Lineage != strings.TrimSpace(row.State.Lineage) ||
		len(row.State.Lineage) > 128 ||
		row.State.Serial < 1 ||
		!canonicalLowerHex(row.State.ObservationSHA256, sha256.Size*2) ||
		len(row.State.Resources) == 0 ||
		len(row.State.Resources) > 64 {
		return errors.New("Terraform live-state observation is incomplete")
	}
	addresses := make([]string, 0, len(row.State.Resources))
	absent := make([]string, 0, len(row.State.Resources))
	for index, resource := range row.State.Resources {
		if resource.Address == "" ||
			resource.Address != strings.TrimSpace(resource.Address) ||
			len(resource.Address) > 512 {
			return fmt.Errorf("Terraform resources[%d] address is invalid", index)
		}
		addresses = append(addresses, resource.Address)
		switch phase {
		case "pre_removal":
			if resource.State != "present" {
				return fmt.Errorf("Terraform resources[%d] is not present before removal", index)
			}
		case "post_removal":
			if resource.State != "absent" && resource.State != "retargeted" {
				return fmt.Errorf("Terraform resources[%d] is not absent or retargeted after removal", index)
			}
			if resource.State == "absent" {
				absent = append(absent, resource.Address)
			}
		}
	}
	if !slices.IsSorted(addresses) {
		return errors.New("Terraform resources must be sorted by address")
	}
	for index := 1; index < len(addresses); index++ {
		if addresses[index] == addresses[index-1] {
			return errors.New("Terraform resources must not contain duplicate addresses")
		}
	}
	if phase == "pre_removal" {
		if row.Plan.SavedPlanSHA256 != nil ||
			row.Plan.ApplyRunID != nil ||
			len(row.Plan.ApprovedDeletions) != 0 {
			return errors.New("pre-removal Terraform row must not claim an apply plan")
		}
	} else {
		if row.Plan.SavedPlanSHA256 == nil ||
			!canonicalLowerHex(*row.Plan.SavedPlanSHA256, sha256.Size*2) ||
			row.Plan.ApplyRunID == nil ||
			*row.Plan.ApplyRunID < 1 ||
			!slices.Equal(row.Plan.ApprovedDeletions, absent) {
			return errors.New("post-removal Terraform row is not bound to the saved plan and exact deletions")
		}
	}
	if !canonicalLowerHex(row.RowSHA256, sha256.Size*2) {
		return errors.New("Terraform row SHA-256 is invalid")
	}
	return nil
}

func validateNHPRegistrarInterface(item orchestratorNHPInterface, phase string) error {
	if item.Symbol == "" || item.Symbol != strings.TrimSpace(item.Symbol) {
		return errors.New("symbol must be a non-empty trimmed string")
	}
	if item.Path == "" ||
		item.Path != strings.TrimSpace(item.Path) ||
		strings.HasPrefix(item.Path, "/") ||
		strings.HasSuffix(item.Path, "/") ||
		strings.Contains(item.Path, "//") ||
		strings.Contains(item.Path, "\\") ||
		slices.Contains(strings.Split(item.Path, "/"), "..") {
		return errors.New("path must be a clean relative repository path")
	}
	if !canonicalLowerHex(item.PathSHA256, sha256.Size*2) {
		return errors.New("path_sha256 must be a canonical SHA-256 digest")
	}
	if item.Role != orchestratorLegacyRegistrarRole && item.Role != orchestratorNativeRuntimeRole {
		return errors.New("role is not an allowed NHP registrar role")
	}
	if item.State != "present" && item.State != "absent" {
		return errors.New("state must be present or absent")
	}
	if len(item.LifecycleMessageTypes) == 0 ||
		!slices.IsSorted(item.LifecycleMessageTypes) ||
		slices.ContainsFunc(item.LifecycleMessageTypes, func(messageType string) bool {
			return !slices.Contains(orchestratorRetiredMessageTypes, messageType)
		}) {
		return errors.New("lifecycle_message_types must be a sorted non-empty retired-message subset")
	}
	for index := 1; index < len(item.LifecycleMessageTypes); index++ {
		if item.LifecycleMessageTypes[index] == item.LifecycleMessageTypes[index-1] {
			return errors.New("lifecycle_message_types must not contain duplicates")
		}
	}

	if item.Role == orchestratorNativeRuntimeRole {
		if item.State != "present" || !item.DispatchesLifecycleWork {
			return errors.New("retained native runtime must remain present and dispatching")
		}
		return nil
	}
	if item.DispatchesLifecycleWork {
		return errors.New("legacy registrar still dispatches lifecycle work")
	}
	if phase == "pre_removal" && item.State != "present" {
		return errors.New("legacy registrar must remain present before removal")
	}
	if phase == "post_removal" && item.State != "absent" {
		return errors.New("legacy registrar must be absent after removal")
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
	expected := orchestratorProofExpectations{
		Phase:                      phase,
		DeploymentManifestSHA256:   os.Getenv(deploymentManifestSHAEnv),
		DeploymentProvenanceSHA256: os.Getenv(deploymentProvenanceSHAEnv),
		DeploymentRuntimeSHA256:    os.Getenv(deploymentRuntimeInputsSHAEnv),
		ProducerRunID:              os.Getenv(deploymentProducerRunIDEnv),
		ProducerRunAttempt:         os.Getenv(deploymentProducerAttemptEnv),
		ProducerHeadSHA:            os.Getenv(deploymentProducerHeadSHAEnv),
		NHPSourceSHA:               os.Getenv(orchestratorNHPSourceSHAEnv),
		QurlServiceSourceSHA:       os.Getenv(qurlServiceSourceSHAEnv),
		QurlServiceAuthorityImage:  os.Getenv(qurlServiceAuthorityImageEnv),
		QurlGoSourceSHA:            os.Getenv(buildSHAEnv),
	}
	for name, value := range map[string]string{
		deploymentManifestSHAEnv:      expected.DeploymentManifestSHA256,
		deploymentProvenanceSHAEnv:    expected.DeploymentProvenanceSHA256,
		deploymentRuntimeInputsSHAEnv: expected.DeploymentRuntimeSHA256,
	} {
		if !canonicalLowerHex(value, sha256.Size*2) {
			t.Fatalf("%s must be an exact lowercase SHA-256 digest", name)
		}
	}
	for name, value := range map[string]string{
		deploymentProducerHeadSHAEnv: expected.ProducerHeadSHA,
		orchestratorNHPSourceSHAEnv:  expected.NHPSourceSHA,
		qurlServiceSourceSHAEnv:      expected.QurlServiceSourceSHA,
		buildSHAEnv:                  expected.QurlGoSourceSHA,
	} {
		if !canonicalLowerHex(value, 40) {
			t.Fatalf("%s must be an exact lowercase commit SHA", name)
		}
	}
	if !strings.HasPrefix(expected.QurlServiceAuthorityImage, "sha256:") ||
		!canonicalLowerHex(strings.TrimPrefix(expected.QurlServiceAuthorityImage, "sha256:"), sha256.Size*2) {
		t.Fatalf("%s must be an exact sha256 image digest", qurlServiceAuthorityImageEnv)
	}
	evidence := readOrchestratorProofEvidence(t)
	if err := validateOrchestratorProofEvidence(evidence, expected); err != nil {
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

	for _, scenario := range []struct {
		id   string
		kind string
		name string
	}{
		{
			id:   "orchestrator.real_hub_authority_and_two_cells",
			kind: "topology_observation",
			name: "real_hub_authority_and_two_cells",
		},
		{
			id:   "retirement.generated_artifact_parity",
			kind: "surface_inventory",
			name: "generated_artifact_parity",
		},
		{
			id:   "retirement.nhp_registrar_surface_state",
			kind: "surface_inventory",
			name: "nhp_registrar_surface_state",
		},
		{
			id:   "retirement.terraform_saved_plan_and_live_state",
			kind: "surface_inventory",
			name: "terraform_saved_plan_and_live_state",
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			raw := evidence.Rows[scenario.id]
			rowSHA256, err := canonicalJSONSHA256(raw)
			if err != nil {
				t.Fatalf("hash authenticated NHP row %q: %v", scenario.id, err)
			}
			t.Cleanup(func() {
				if t.Failed() || t.Skipped() {
					return
				}
				if err := appendNHPOrchestratorTypedEvidence(
					os.Getenv(typedEvidencePathEnv),
					scenario.id,
					scenario.kind,
					nhpTypedEvidenceBinding{
						ProducerRunID: evidence.Producer.RunID,
						RowSHA256:     rowSHA256,
						SourceSHA:     evidence.Bindings.NHPSourceSHA,
					},
				); err != nil {
					t.Errorf("append typed evidence for %s: %v", scenario.id, err)
				}
			})
			t.Logf("EVIDENCE scenario=%s row_sha256=%s", scenario.id, rowSHA256)
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
	expected := orchestratorProofExpectations{
		Phase:                      "post_removal",
		DeploymentManifestSHA256:   deploymentSHA,
		DeploymentProvenanceSHA256: strings.Repeat("2", 64),
		DeploymentRuntimeSHA256:    strings.Repeat("1", 64),
		ProducerRunID:              "12",
		ProducerRunAttempt:         "3",
		ProducerHeadSHA:            strings.Repeat("a", 40),
		NHPSourceSHA:               strings.Repeat("b", 40),
		QurlServiceSourceSHA:       strings.Repeat("e", 40),
		QurlServiceAuthorityImage:  "sha256:" + strings.Repeat("f", 64),
		QurlGoSourceSHA:            strings.Repeat("c", 40),
	}
	rawRow := func(value any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	interfacesForPhase := func(phase string) []orchestratorNHPInterface {
		legacyState := "present"
		if phase == "post_removal" {
			legacyState = "absent"
		}
		return []orchestratorNHPInterface{
			{
				Symbol:                  "legacyRegistrar",
				Path:                    "endpoints/server/staticplugins/agent/registrar.go",
				PathSHA256:              strings.Repeat("4", 64),
				Role:                    orchestratorLegacyRegistrarRole,
				State:                   legacyState,
				LifecycleMessageTypes:   slices.Clone(orchestratorRetiredMessageTypes),
				DispatchesLifecycleWork: false,
			},
			{
				Symbol:                  "(*UdpServer).dispatchReceivedMessage",
				Path:                    "endpoints/server/udpserver.go",
				PathSHA256:              strings.Repeat("5", 64),
				Role:                    orchestratorNativeRuntimeRole,
				State:                   "present",
				LifecycleMessageTypes:   slices.Clone(orchestratorRetiredMessageTypes),
				DispatchesLifecycleWork: true,
			},
		}
	}
	valid := func(phase string) orchestratorProofEvidence {
		interfaces := interfacesForPhase(phase)
		interfacesRaw, err := json.Marshal(interfaces)
		if err != nil {
			t.Fatal(err)
		}
		interfacesSHA, err := canonicalJSONSHA256(interfacesRaw)
		if err != nil {
			t.Fatal(err)
		}
		artifacts := make([]orchestratorGeneratedArtifact, 0, 9)
		for index, surface := range []string{
			"connector_tarball",
			"distribution",
			"generated_config",
			"go",
			"integration_installer",
			"mcp",
			"python",
			"typescript",
			"website",
		} {
			artifacts = append(artifacts, orchestratorGeneratedArtifact{
				Surface:        surface,
				Repository:     "layervai/" + strings.ReplaceAll(surface, "_", "-"),
				SourceSHA:      strings.Repeat(fmt.Sprintf("%x", index%15+1), 40),
				Path:           "proof/" + surface + ".json",
				PathSHA256:     strings.Repeat(fmt.Sprintf("%x", (index+1)%15+1), 64),
				ContractSHA256: retiredLifecycleSurfaceCanonicalSHA256v1,
				State:          "matches_contract",
			})
		}
		artifactsRaw, err := json.Marshal(artifacts)
		if err != nil {
			t.Fatal(err)
		}
		artifactsSHA, err := canonicalJSONSHA256(artifactsRaw)
		if err != nil {
			t.Fatal(err)
		}

		resourceState := "present"
		var plan orchestratorTerraformPlan
		if phase == "post_removal" {
			resourceState = "absent"
			savedPlanSHA := strings.Repeat("e", 64)
			applyRunID := int64(41)
			plan = orchestratorTerraformPlan{
				SavedPlanSHA256:   &savedPlanSHA,
				ApplyRunID:        &applyRunID,
				ApprovedDeletions: []string{"module.retirement.resource.first", "module.retirement.resource.second"},
			}
		}
		resources := []orchestratorTerraformResource{
			{Address: "module.retirement.resource.first", State: resourceState},
			{Address: "module.retirement.resource.second", State: resourceState},
		}
		rows := map[string]json.RawMessage{
			"orchestrator.real_hub_authority_and_two_cells": rawRow(orchestratorTopologyRow{
				Kind:                       "topology_observation",
				ManifestTopologySHA256:     strings.Repeat("1", 64),
				RuntimeTopologySHA256:      strings.Repeat("2", 64),
				PublicIdentitiesSHA256:     strings.Repeat("3", 64),
				WorkloadObservationsSHA256: strings.Repeat("4", 64),
				Hub: orchestratorTopologyEndpoint{
					Host:                  "hub.nhp.layerv.ai",
					Port:                  443,
					ServerPublicKeySHA256: strings.Repeat("5", 64),
				},
				Cells: []orchestratorTopologyCell{
					{
						CellID: "cell0",
						orchestratorTopologyEndpoint: orchestratorTopologyEndpoint{
							Host:                  "cell0.nhp.layerv.ai",
							Port:                  443,
							ServerPublicKeySHA256: strings.Repeat("6", 64),
						},
					},
					{
						CellID: "cell1",
						orchestratorTopologyEndpoint: orchestratorTopologyEndpoint{
							Host:                  "cell1.nhp.layerv.ai",
							Port:                  443,
							ServerPublicKeySHA256: strings.Repeat("7", 64),
						},
					},
				},
				Authority: orchestratorTopologyAuthority{
					SourceSHA:                  strings.Repeat("e", 40),
					ImageDigest:                "sha256:" + strings.Repeat("f", 64),
					ProofPolicyConsumersActive: true,
				},
			}),
			"retirement.generated_artifact_parity": rawRow(orchestratorGeneratedArtifactParityRow{
				Kind:    "surface_inventory",
				Surface: "generated_artifact_parity",
				Phase:   phase,
				CanonicalContract: orchestratorGeneratedContract{
					Repository:      "layervai/qurl-go",
					Path:            retiredLifecycleSurfaceContractPath,
					SourceSHA:       strings.Repeat("c", 40),
					RawSHA256:       retiredLifecycleSurfaceRawSHA256,
					CanonicalSHA256: retiredLifecycleSurfaceCanonicalSHA256v1,
				},
				Artifacts:       artifacts,
				ArtifactsSHA256: artifactsSHA,
			}),
			"retirement.nhp_registrar_surface_state": rawRow(orchestratorRegistrarSurfaceRow{
				Kind:                    orchestratorRegistrarRowKind,
				Surface:                 orchestratorRegistrarSurface,
				Phase:                   phase,
				SourceRepository:        orchestratorProofRepository,
				SourceSHA:               strings.Repeat("b", 40),
				MessageTypeSourcePath:   orchestratorMessageTypeSource,
				MessageTypeSourceSHA256: strings.Repeat("3", 64),
				RetiredMessageTypeWireValues: orchestratorRetiredMessageTypeValues{
					LST: 5,
					LRT: 6,
					OTP: 12,
					REG: 13,
					RAK: 14,
				},
				RetiredInternalHTTPOperations: slices.Clone(orchestratorRetiredHTTPOperations),
				Interfaces:                    interfaces,
				InterfacesSHA256:              interfacesSHA,
			}),
			"retirement.terraform_saved_plan_and_live_state": rawRow(orchestratorTerraformRetirementRow{
				Kind:    "surface_inventory",
				Surface: "terraform_retirement",
				Phase:   phase,
				State: orchestratorTerraformState{
					Lineage:           "deployment-state-lineage",
					Serial:            17,
					ObservationSHA256: strings.Repeat("9", 64),
					Resources:         resources,
				},
				Plan:      plan,
				RowSHA256: strings.Repeat("a", 64),
			}),
		}
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
				DeploymentProvenanceSHA256:            strings.Repeat("2", 64),
				DeploymentRuntimeInputsSHA256:         strings.Repeat("1", 64),
				NHPSourceSHA:                          strings.Repeat("b", 40),
				QurlGoSourceSHA:                       strings.Repeat("c", 40),
				RetiredLifecycleSurfacePath:           retiredLifecycleSurfaceContractPath,
				RetiredLifecycleSurfaceRawSHA256:      retiredLifecycleSurfaceRawSHA256,
				RetiredLifecycleSurfaceCanonicalSHA25: retiredLifecycleSurfaceCanonicalSHA256v1,
			},
			ProducedRows: slices.Clone(orchestratorProducedRows),
			Rows:         rows,
		}
	}
	mutateRow := func(
		evidence *orchestratorProofEvidence,
		id string,
		target any,
		mutate func(),
	) {
		t.Helper()
		if err := json.Unmarshal(evidence.Rows[id], target); err != nil {
			t.Fatal(err)
		}
		mutate()
		evidence.Rows[id] = rawRow(target)
	}

	for _, phase := range []string{"pre_removal", "post_removal"} {
		phaseExpected := expected
		phaseExpected.Phase = phase
		evidence := valid(phase)
		raw, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeOrchestratorProofEvidence(raw)
		if err != nil {
			t.Fatalf("decode producer-shaped %s orchestrator evidence: %v", phase, err)
		}
		if err := validateOrchestratorProofEvidence(decoded, phaseExpected); err != nil {
			t.Fatalf("valid %s orchestrator evidence rejected: %v", phase, err)
		}
	}

	tests := map[string]func(*orchestratorProofEvidence){
		"schema drift":        func(v *orchestratorProofEvidence) { v.SchemaVersion = 2 },
		"gate drift":          func(v *orchestratorProofEvidence) { v.Gate = "other_gate" },
		"phase drift":         func(v *orchestratorProofEvidence) { v.Phase = "pre_removal" },
		"missing observed_at": func(v *orchestratorProofEvidence) { v.ObservedAt = "" },
		"fractional observed_at": func(v *orchestratorProofEvidence) {
			v.ObservedAt = "2026-07-27T00:00:00.123Z"
		},
		"offset observed_at": func(v *orchestratorProofEvidence) {
			v.ObservedAt = "2026-07-26T18:00:00-06:00"
		},
		"foreign repository":     func(v *orchestratorProofEvidence) { v.Producer.Repository = "layervai/qurl-go" },
		"foreign workflow":       func(v *orchestratorProofEvidence) { v.Producer.WorkflowPath = ".github/workflows/ci.yml" },
		"bad head sha":           func(v *orchestratorProofEvidence) { v.Producer.HeadSHA = "not-a-sha" },
		"zero run id":            func(v *orchestratorProofEvidence) { v.Producer.RunID = 0 },
		"zero run attempt":       func(v *orchestratorProofEvidence) { v.Producer.RunAttempt = 0 },
		"wrong producer run id":  func(v *orchestratorProofEvidence) { v.Producer.RunID = 99 },
		"wrong producer attempt": func(v *orchestratorProofEvidence) { v.Producer.RunAttempt = 9 },
		"wrong deployment":       func(v *orchestratorProofEvidence) { v.Bindings.DeploymentManifestSHA256 = strings.Repeat("e", 64) },
		"wrong provenance":       func(v *orchestratorProofEvidence) { v.Bindings.DeploymentProvenanceSHA256 = strings.Repeat("e", 64) },
		"bad runtime inputs":     func(v *orchestratorProofEvidence) { v.Bindings.DeploymentRuntimeInputsSHA256 = "short" },
		"wrong runtime inputs":   func(v *orchestratorProofEvidence) { v.Bindings.DeploymentRuntimeInputsSHA256 = strings.Repeat("4", 64) },
		"bad nhp source":         func(v *orchestratorProofEvidence) { v.Bindings.NHPSourceSHA = "nope" },
		"wrong nhp source":       func(v *orchestratorProofEvidence) { v.Bindings.NHPSourceSHA = strings.Repeat("8", 40) },
		"bad qurl-go source":     func(v *orchestratorProofEvidence) { v.Bindings.QurlGoSourceSHA = "nope" },
		"wrong qurl-go source":   func(v *orchestratorProofEvidence) { v.Bindings.QurlGoSourceSHA = strings.Repeat("7", 40) },
		"wrong producer head":    func(v *orchestratorProofEvidence) { v.Producer.HeadSHA = strings.Repeat("6", 40) },
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
			v.Rows["wire.session_knk_ack_ext_ack"] = json.RawMessage(`{}`)
		},
		"row phase drift": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.Phase = "pre_removal"
			})
		},
		"row interfaces digest drift": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.InterfacesSHA256 = "short"
			})
		},
		"row nhp revision drift": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.SourceSHA = strings.Repeat("9", 40)
			})
		},
		"row enumerates nothing": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.Interfaces = nil
			})
		},
		"row still dispatches lifecycle work": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.Interfaces[0].DispatchesLifecycleWork = true
			})
		},
		"row wire value drift": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.RetiredMessageTypeWireValues.REG = 99
			})
		},
		"row operation drift": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.RetiredInternalHTTPOperations[0].Path = "/other"
			})
		},
		"row native runtime stops dispatching": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.Interfaces[1].DispatchesLifecycleWork = false
			})
		},
		"row interface message types are unsorted": func(v *orchestratorProofEvidence) {
			var row orchestratorRegistrarSurfaceRow
			mutateRow(v, "retirement.nhp_registrar_surface_state", &row, func() {
				row.Interfaces[0].LifecycleMessageTypes = []string{"NHP_REG", "NHP_LST"}
			})
		},
		"topology duplicate identity": func(v *orchestratorProofEvidence) {
			var row orchestratorTopologyRow
			mutateRow(v, "orchestrator.real_hub_authority_and_two_cells", &row, func() {
				row.Cells[0].ServerPublicKeySHA256 = row.Hub.ServerPublicKeySHA256
			})
		},
		"generated artifact mismatch": func(v *orchestratorProofEvidence) {
			var row orchestratorGeneratedArtifactParityRow
			mutateRow(v, "retirement.generated_artifact_parity", &row, func() {
				row.Artifacts[0].State = "stale"
			})
		},
		"terraform plan missing": func(v *orchestratorProofEvidence) {
			var row orchestratorTerraformRetirementRow
			mutateRow(v, "retirement.terraform_saved_plan_and_live_state", &row, func() {
				row.Plan = orchestratorTerraformPlan{}
			})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := valid("post_removal")
			mutate(&evidence)
			if err := validateOrchestratorProofEvidence(evidence, expected); err == nil {
				t.Fatal("invalid orchestrator evidence was accepted")
			}
		})
	}

	// The authenticated producer identity itself must be canonical.
	for name, producer := range map[string][2]string{
		"empty producer run":     {"", "3"},
		"empty producer attempt": {"12", ""},
		"zero-prefixed run":      {"012", "3"},
		"non-numeric attempt":    {"12", "3a"},
	} {
		t.Run(name, func(t *testing.T) {
			invalidExpected := expected
			invalidExpected.ProducerRunID = producer[0]
			invalidExpected.ProducerRunAttempt = producer[1]
			if err := validateOrchestratorProofEvidence(valid("post_removal"), invalidExpected); err == nil {
				t.Fatal("non-canonical authenticated producer identity was accepted")
			}
		})
	}

	t.Run("controller identity cannot substitute for producer identity", func(t *testing.T) {
		evidence := valid("post_removal")
		if err := validateOrchestratorProofEvidence(evidence, expected); err != nil {
			t.Fatalf("exact producer identity rejected: %v", err)
		}
		controllerExpected := expected
		controllerExpected.ProducerRunID = "98"
		controllerExpected.ProducerRunAttempt = "7"
		if err := validateOrchestratorProofEvidence(evidence, controllerExpected); err == nil {
			t.Fatal("distinct controller identity was accepted as the deployment producer")
		}
	})
}

func TestLegacyNHPProducerFixtureIsRejected(t *testing.T) {
	raw, err := os.ReadFile("testdata/nhp_orchestrator_evidence_pre_removal.json")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := decodeOrchestratorProofEvidence(raw)
	if err != nil {
		t.Fatalf("decode checked-in NHP producer fixture: %v", err)
	}
	expected := orchestratorProofExpectations{
		Phase:                      "pre_removal",
		DeploymentManifestSHA256:   "bc21a6d296b57a8ead9a7233c1bbb7835d3d2f3f473093e94c28b72f5721aacc",
		DeploymentProvenanceSHA256: strings.Repeat("2", 64),
		DeploymentRuntimeSHA256:    "93d1cf0f77f2f8d71f856ca4ae80d80ccab09bdf7fb01f0b6f8eab450707a3cf",
		ProducerRunID:              "999",
		ProducerRunAttempt:         "1",
		ProducerHeadSHA:            strings.Repeat("a", 40),
		NHPSourceSHA:               strings.Repeat("b", 40),
		QurlGoSourceSHA:            strings.Repeat("d", 40),
	}
	if err := validateOrchestratorProofEvidence(evidence, expected); err == nil {
		t.Fatal("legacy one-row NHP producer fixture was accepted by the four-row aggregate contract")
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
