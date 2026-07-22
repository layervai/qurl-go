package nativeudp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	connectorAttestationPathEnv  = "QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_PATH"
	connectorAttestationSHAEnv   = "QURL_GO_SANDBOX_CONNECTOR_ATTESTATION_SHA256"
	deploymentManifestSHAEnv     = "QURL_GO_SANDBOX_DEPLOYMENT_MANIFEST_SHA256"
	proofPhaseEnv                = "QURL_GO_SANDBOX_PROOF_PHASE"
	preRemovalConnectorRunIDEnv  = "QURL_GO_SANDBOX_PRE_REMOVAL_CONNECTOR_PROOF_RUN_ID"
	connectorProofRepository     = "layervai/qurl-connector"
	connectorRetirementProofGate = "udp_lifecycle_retirement"
	maxConnectorAttestationBytes = 32 * 1024
)

type connectorProofAttestation struct {
	SchemaVersion            int                        `json:"schema_version"`
	Gate                     string                     `json:"gate"`
	Phase                    string                     `json:"phase"`
	ConnectorRepository      string                     `json:"connector_repository"`
	ConnectorCommitSHA       string                     `json:"connector_commit_sha"`
	ConnectorWorkflowID      int64                      `json:"connector_workflow_id"`
	ConnectorRunID           int64                      `json:"connector_run_id"`
	ConnectorRunAttempt      int64                      `json:"connector_run_attempt"`
	ConnectorRunURL          string                     `json:"connector_run_url"`
	PreRemovalRunID          *string                    `json:"pre_removal_run_id"`
	ArtifactName             string                     `json:"artifact_name"`
	ArtifactID               int64                      `json:"artifact_id"`
	ArtifactSHA256           string                     `json:"artifact_sha256"`
	EvidenceSHA256           string                     `json:"evidence_sha256"`
	DeploymentManifestSHA256 string                     `json:"deployment_manifest_sha256"`
	InventorySHA256          string                     `json:"inventory_sha256"`
	ScenarioContractSHA256   string                     `json:"scenario_contract_sha256"`
	ProofHarnessSHA256       string                     `json:"proof_harness_sha256"`
	InputOutcome             string                     `json:"input_outcome"`
	EnforcementOutcome       string                     `json:"enforcement_outcome"`
	InputsUnchanged          bool                       `json:"inputs_unchanged"`
	GatePassed               bool                       `json:"gate_passed"`
	Counts                   connectorAttestationCounts `json:"counts"`
	ProvenanceValid          bool                       `json:"provenance_valid"`
	TwoCellProvenance        bool                       `json:"two_cell_provenance"`
}

type connectorAttestationCounts struct {
	Implemented int `json:"implemented"`
	Blocking    int `json:"blocking"`
	Failures    int `json:"failures"`
	Skips       int `json:"skips"`
	ExactPasses int `json:"exact_passes"`
}

func TestSandboxConnectorUDP(t *testing.T) {
	switch os.Getenv(strictEnv) {
	case "", "0", "false":
		t.Skip("attended proof only; the workflow must attest an exact same-phase Connector run")
	case "1", "true":
	default:
		t.Fatalf("%s must be true/1 or false/0", strictEnv)
	}

	runTypedEvidenceScenario(t, "complete_strict_evidence_attestation", "connector.complete_strict_evidence_attestation", []string{"connector_attestation"}, func(t *testing.T) {
		phase := os.Getenv(proofPhaseEnv)
		if phase != "pre_removal" && phase != "post_removal" {
			t.Fatalf("%s must be pre_removal or post_removal", proofPhaseEnv)
		}
		expectedAttestationSHA := os.Getenv(connectorAttestationSHAEnv)
		expectedDeploymentSHA := os.Getenv(deploymentManifestSHAEnv)
		if !canonicalLowerHex(expectedAttestationSHA, sha256.Size*2) {
			t.Fatalf("%s must be an exact lowercase SHA-256 digest", connectorAttestationSHAEnv)
		}
		if !canonicalLowerHex(expectedDeploymentSHA, sha256.Size*2) {
			t.Fatalf("%s must be an exact lowercase SHA-256 digest", deploymentManifestSHAEnv)
		}

		path := os.Getenv(connectorAttestationPathEnv)
		if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) {
			t.Fatalf("%s must be one canonical absolute path", connectorAttestationPathEnv)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("inspect Connector attestation: %v", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("Connector attestation must be a regular non-symlink file")
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("Connector attestation mode = %o, want 444", info.Mode().Perm())
		}
		if info.Size() <= 0 || info.Size() > maxConnectorAttestationBytes {
			t.Fatalf("Connector attestation size = %d, want 1..%d", info.Size(), maxConnectorAttestationBytes)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read Connector attestation: %v", err)
		}
		digest := sha256.Sum256(raw)
		if got := hex.EncodeToString(digest[:]); got != expectedAttestationSHA {
			t.Fatalf("Connector attestation SHA-256 = %q, want workflow-verified %q", got, expectedAttestationSHA)
		}
		attestation, err := decodeConnectorProofAttestation(raw)
		if err != nil {
			t.Fatalf("decode Connector attestation: %v", err)
		}
		if err := validateConnectorProofAttestation(attestation, phase, expectedDeploymentSHA, os.Getenv(preRemovalConnectorRunIDEnv)); err != nil {
			t.Fatal(err)
		}
		t.Logf("EVIDENCE connector_repository=%s connector_commit_sha=%s connector_run_id=%d connector_run_attempt=%d artifact_name=%s artifact_sha256=%s evidence_sha256=%s",
			attestation.ConnectorRepository,
			attestation.ConnectorCommitSHA,
			attestation.ConnectorRunID,
			attestation.ConnectorRunAttempt,
			attestation.ArtifactName,
			attestation.ArtifactSHA256,
			attestation.EvidenceSHA256,
		)
	})
}

func decodeConnectorProofAttestation(raw []byte) (connectorProofAttestation, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return connectorProofAttestation{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var attestation connectorProofAttestation
	if err := decoder.Decode(&attestation); err != nil {
		return connectorProofAttestation{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return connectorProofAttestation{}, fmt.Errorf("attestation contains trailing JSON: %w", err)
	}
	return attestation, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return fmt.Errorf("JSON contains trailing data: %w", err)
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("JSON contains duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not properly closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not properly closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateConnectorProofAttestation(attestation connectorProofAttestation, phase, deploymentSHA, expectedPreRemovalRunID string) error {
	if attestation.SchemaVersion != 1 || attestation.Gate != connectorRetirementProofGate || attestation.Phase != phase {
		return fmt.Errorf("Connector attestation header = schema %d, gate %q, phase %q; want 1, %q, %q",
			attestation.SchemaVersion, attestation.Gate, attestation.Phase, connectorRetirementProofGate, phase)
	}
	if attestation.ConnectorRepository != connectorProofRepository || !canonicalLowerHex(attestation.ConnectorCommitSHA, 40) {
		return fmt.Errorf("Connector attestation repository/commit is not canonical: repository=%q commit=%q",
			attestation.ConnectorRepository, attestation.ConnectorCommitSHA)
	}
	if attestation.ConnectorWorkflowID < 1 || attestation.ConnectorRunID < 1 || attestation.ConnectorRunAttempt < 1 || attestation.ArtifactID < 1 {
		return errors.New("Connector attestation workflow, run, attempt, and artifact ids must be positive")
	}
	wantRunURL := fmt.Sprintf("https://github.com/%s/actions/runs/%d", connectorProofRepository, attestation.ConnectorRunID)
	if attestation.ConnectorRunURL != wantRunURL {
		return fmt.Errorf("Connector run URL = %q, want %q", attestation.ConnectorRunURL, wantRunURL)
	}
	if phase == "pre_removal" {
		if expectedPreRemovalRunID != "" || attestation.PreRemovalRunID != nil {
			return errors.New("pre-removal Connector attestation must not carry a paired pre-removal run")
		}
	} else {
		if !canonicalPositiveDecimal(expectedPreRemovalRunID) || attestation.PreRemovalRunID == nil || *attestation.PreRemovalRunID != expectedPreRemovalRunID {
			return fmt.Errorf("post-removal Connector attestation pre-removal run does not match paired qurl-go proof: got=%v want=%q",
				attestation.PreRemovalRunID, expectedPreRemovalRunID)
		}
	}
	wantArtifactName := fmt.Sprintf("strict-sandbox-proof-%s-%s-%d", phase, attestation.ConnectorCommitSHA, attestation.ConnectorRunAttempt)
	if attestation.ArtifactName != wantArtifactName {
		return fmt.Errorf("Connector artifact name = %q, want %q", attestation.ArtifactName, wantArtifactName)
	}
	for name, value := range map[string]string{
		"artifact_sha256":            attestation.ArtifactSHA256,
		"evidence_sha256":            attestation.EvidenceSHA256,
		"deployment_manifest_sha256": attestation.DeploymentManifestSHA256,
		"inventory_sha256":           attestation.InventorySHA256,
		"scenario_contract_sha256":   attestation.ScenarioContractSHA256,
		"proof_harness_sha256":       attestation.ProofHarnessSHA256,
	} {
		if !canonicalLowerHex(value, sha256.Size*2) {
			return fmt.Errorf("Connector attestation %s is not a canonical SHA-256 digest", name)
		}
	}
	if attestation.DeploymentManifestSHA256 != deploymentSHA {
		return fmt.Errorf("Connector deployment manifest SHA-256 = %q, want current qurl-go manifest %q",
			attestation.DeploymentManifestSHA256, deploymentSHA)
	}
	if attestation.InputOutcome != "success" || attestation.EnforcementOutcome != "success" ||
		!attestation.InputsUnchanged || !attestation.GatePassed || !attestation.ProvenanceValid || !attestation.TwoCellProvenance {
		return fmt.Errorf("Connector proof is incomplete: input=%q enforcement=%q inputs_unchanged=%t gate_passed=%t provenance_valid=%t two_cell_provenance=%t",
			attestation.InputOutcome,
			attestation.EnforcementOutcome,
			attestation.InputsUnchanged,
			attestation.GatePassed,
			attestation.ProvenanceValid,
			attestation.TwoCellProvenance,
		)
	}
	if attestation.Counts.Implemented != 60 || attestation.Counts.Blocking != 0 || attestation.Counts.Failures != 0 ||
		attestation.Counts.Skips != 0 || attestation.Counts.ExactPasses != 60 {
		return fmt.Errorf("Connector proof counts are incomplete: %+v", attestation.Counts)
	}
	return nil
}

func canonicalPositiveDecimal(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func TestDecodeConnectorProofAttestationRejectsAmbiguousJSON(t *testing.T) {
	tests := map[string]string{
		"duplicate key": `{"schema_version":1,"schema_version":1}`,
		"unknown key":   `{"unknown":true}`,
		"trailing JSON": `{}` + `{}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConnectorProofAttestation([]byte(raw)); err == nil {
				t.Fatal("decode accepted ambiguous Connector attestation JSON")
			}
		})
	}
}

func TestValidateConnectorProofAttestationFailsClosed(t *testing.T) {
	deploymentSHA := strings.Repeat("d", 64)
	valid := func(phase string) connectorProofAttestation {
		attestation := connectorProofAttestation{
			SchemaVersion:            1,
			Gate:                     connectorRetirementProofGate,
			Phase:                    phase,
			ConnectorRepository:      connectorProofRepository,
			ConnectorCommitSHA:       strings.Repeat("a", 40),
			ConnectorWorkflowID:      1,
			ConnectorRunID:           2,
			ConnectorRunAttempt:      3,
			ConnectorRunURL:          "https://github.com/layervai/qurl-connector/actions/runs/2",
			ArtifactName:             "strict-sandbox-proof-" + phase + "-" + strings.Repeat("a", 40) + "-3",
			ArtifactID:               4,
			ArtifactSHA256:           strings.Repeat("1", 64),
			EvidenceSHA256:           strings.Repeat("2", 64),
			DeploymentManifestSHA256: deploymentSHA,
			InventorySHA256:          strings.Repeat("3", 64),
			ScenarioContractSHA256:   strings.Repeat("4", 64),
			ProofHarnessSHA256:       strings.Repeat("5", 64),
			InputOutcome:             "success",
			EnforcementOutcome:       "success",
			InputsUnchanged:          true,
			GatePassed:               true,
			Counts:                   connectorAttestationCounts{Implemented: 60, ExactPasses: 60},
			ProvenanceValid:          true,
			TwoCellProvenance:        true,
		}
		if phase == "post_removal" {
			runID := "456"
			attestation.PreRemovalRunID = &runID
		}
		return attestation
	}

	if err := validateConnectorProofAttestation(valid("pre_removal"), "pre_removal", deploymentSHA, ""); err != nil {
		t.Fatalf("valid pre-removal attestation rejected: %v", err)
	}
	if err := validateConnectorProofAttestation(valid("post_removal"), "post_removal", deploymentSHA, "456"); err != nil {
		t.Fatalf("valid post-removal attestation rejected: %v", err)
	}

	tests := map[string]func(*connectorProofAttestation){
		"gate false":                func(value *connectorProofAttestation) { value.GatePassed = false },
		"inputs changed":            func(value *connectorProofAttestation) { value.InputsUnchanged = false },
		"blocking":                  func(value *connectorProofAttestation) { value.Counts.Blocking = 1 },
		"failures":                  func(value *connectorProofAttestation) { value.Counts.Failures = 1 },
		"skips":                     func(value *connectorProofAttestation) { value.Counts.Skips = 1 },
		"passes mismatch":           func(value *connectorProofAttestation) { value.Counts.ExactPasses-- },
		"truncated scenario count":  func(value *connectorProofAttestation) { value.Counts.Implemented = 58; value.Counts.ExactPasses = 58 },
		"provenance false":          func(value *connectorProofAttestation) { value.ProvenanceValid = false },
		"two-cell false":            func(value *connectorProofAttestation) { value.TwoCellProvenance = false },
		"wrong deployment":          func(value *connectorProofAttestation) { value.DeploymentManifestSHA256 = strings.Repeat("e", 64) },
		"wrong pre baseline":        func(value *connectorProofAttestation) { wrong := "455"; value.PreRemovalRunID = &wrong },
		"missing post pre baseline": func(value *connectorProofAttestation) { value.PreRemovalRunID = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			attestation := valid("post_removal")
			mutate(&attestation)
			if err := validateConnectorProofAttestation(attestation, "post_removal", deploymentSHA, "456"); err == nil {
				t.Fatal("invalid Connector attestation was accepted")
			}
		})
	}
}
