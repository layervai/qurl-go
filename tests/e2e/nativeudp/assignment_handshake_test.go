package nativeudp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	assignmentHandshakeBucket = "layerv-nhp-sandbox-udp-proof-handshake-767397897469"
)

var (
	assignmentRunRE   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	assignmentHex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	assignmentHex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assignmentKMSRE   = regexp.MustCompile(`^arn:aws:kms:us-east-2:767397897469:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	assignmentAliasRE = regexp.MustCompile(`^arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pm:(blue|green)$`)
	assignmentTimeRE  = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$`)
)

type assignmentHandshake struct {
	Descriptor assignmentHandshakeDescriptor `json:"descriptor"`
	Arm        assignmentMutationEnvelope    `json:"arm"`
	Transport  transportProofDescriptor      `json:"transport"`
}

type assignmentHandshakeDescriptor struct {
	Version              int    `json:"version"`
	ControllerRunID      string `json:"controller_run_id"`
	ControllerRunAttempt string `json:"controller_run_attempt"`
	Client               string `json:"client"`
	ProofPhase           string `json:"proof_phase"`
	ChannelID            string `json:"channel_id"`
	CorrelationID        string `json:"correlation_id"`
	AgentID              string `json:"agent_id"`
	Bucket               string `json:"bucket"`
	KMSKeyARN            string `json:"kms_key_arn"`
	CheckpointKey        string `json:"checkpoint_key"`
	ReceiptKey           string `json:"receipt_key"`
	CAPMAliasARN         string `json:"ca_pm_alias_arn"`
	PinnedCellID         string `json:"pinned_cell_id"`
	TargetCellID         string `json:"target_cell_id"`
	ArmLeaseSeconds      int    `json:"arm_lease_seconds"`
	ExpireLeaseSeconds   int    `json:"expire_lease_seconds"`
	ArmRequestID         string `json:"arm_request_id"`
	MoveRequestID        string `json:"move_request_id"`
	ExpireRequestID      string `json:"expire_request_id"`
}

type assignmentMutationEnvelope struct {
	Version int                      `json:"version"`
	Result  assignmentMutationResult `json:"result"`
}

type assignmentMutationResult struct {
	Mutation                     string `json:"mutation"`
	AgentID                      string `json:"agent_id"`
	PinnedCellID                 string `json:"pinned_cell_id,omitempty"`
	TargetCellID                 string `json:"target_cell_id,omitempty"`
	LeaseSeconds                 int    `json:"lease_seconds,omitempty"`
	GrantCorrelationID           string `json:"grant_correlation_id,omitempty"`
	PreviousCellID               string `json:"previous_cell_id,omitempty"`
	PreviousAssignmentGeneration int64  `json:"previous_assignment_generation,omitempty"`
	NewCellID                    string `json:"new_cell_id,omitempty"`
	NewAssignmentGeneration      int64  `json:"new_assignment_generation,omitempty"`
	LeaseExpiresAt               string `json:"lease_expires_at,omitempty"`
	MutatedAt                    string `json:"mutated_at"`
}

type assignmentCheckpoint struct {
	Version              int    `json:"version"`
	ControllerRunID      string `json:"controller_run_id"`
	ControllerRunAttempt string `json:"controller_run_attempt"`
	ChannelID            string `json:"channel_id"`
	ClientRunID          string `json:"client_run_id"`
	ClientSHA            string `json:"client_sha"`
	CorrelationID        string `json:"correlation_id"`
	AgentID              string `json:"agent_id"`
	ObservedCellID       string `json:"observed_cell_id"`
	AssignmentGeneration int64  `json:"assignment_generation"`
	LeaseExpiresAt       string `json:"lease_expires_at"`
	WarmOpenConfirmed    bool   `json:"warm_open_confirmed"`
}

type assignmentReceipt struct {
	Version          int                           `json:"version"`
	Descriptor       assignmentHandshakeDescriptor `json:"descriptor"`
	Arm              assignmentMutationEnvelope    `json:"arm"`
	ClientRunID      string                        `json:"client_run_id"`
	ClientSHA        string                        `json:"client_sha"`
	CheckpointSHA256 string                        `json:"checkpoint_sha256"`
	Move             assignmentMutationEnvelope    `json:"move"`
	ExpireLease      assignmentMutationEnvelope    `json:"expire_lease"`
}

func completeAssignmentHandshake(
	ctx context.Context,
	t *testing.T,
	cfg sandboxConfig,
	warm sandboxCellEvidence,
) assignmentReceipt {
	t.Helper()
	handshake := loadAssignmentHandshake(t, cfg)
	checkpoint := assignmentCheckpoint{
		Version:              1,
		ControllerRunID:      handshake.Descriptor.ControllerRunID,
		ControllerRunAttempt: handshake.Descriptor.ControllerRunAttempt,
		ChannelID:            handshake.Descriptor.ChannelID,
		ClientRunID:          cfg.clientRunID,
		ClientSHA:            cfg.buildSHA,
		CorrelationID:        handshake.Descriptor.CorrelationID,
		AgentID:              handshake.Descriptor.AgentID,
		ObservedCellID:       warm.CellID,
		AssignmentGeneration: warm.AssignmentGeneration,
		LeaseExpiresAt:       warm.LeaseExpiresAt,
		WarmOpenConfirmed:    true,
	}
	checkpointRaw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw = append(checkpointRaw, '\n')
	directory := t.TempDir()
	checkpointPath := filepath.Join(directory, "checkpoint.json")
	if err := os.WriteFile(checkpointPath, checkpointRaw, 0o600); err != nil {
		t.Fatalf("write assignment checkpoint: %v", err)
	}
	runAWS(
		ctx,
		t,
		"s3api", "put-object",
		"--region", "us-east-2",
		"--bucket", handshake.Descriptor.Bucket,
		"--key", handshake.Descriptor.CheckpointKey,
		"--body", checkpointPath,
		"--content-type", "application/json",
		"--server-side-encryption", "aws:kms",
		"--ssekms-key-id", handshake.Descriptor.KMSKeyARN,
		"--if-none-match", "*",
	)

	receiptPath := filepath.Join(directory, "receipt.json")
	var raw []byte
	for {
		if err := ctx.Err(); err != nil {
			t.Fatalf("wait for assignment mutation receipt: %v", err)
		}
		_ = os.Remove(receiptPath)
		command := exec.CommandContext(
			ctx,
			"aws",
			"s3api", "get-object",
			"--region", "us-east-2",
			"--bucket", handshake.Descriptor.Bucket,
			"--key", handshake.Descriptor.ReceiptKey,
			receiptPath,
		)
		output, commandErr := command.CombinedOutput()
		if commandErr == nil {
			raw, err = os.ReadFile(receiptPath)
			if err != nil {
				t.Fatalf("read assignment mutation receipt: %v", err)
			}
			break
		}
		if !bytes.Contains(output, []byte("NoSuchKey")) && !bytes.Contains(output, []byte("404")) {
			t.Fatalf("read assignment mutation receipt: %v: %s", commandErr, boundedOutput(output))
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	receipt, err := decodeStrictJSON[assignmentReceipt](raw, "assignment mutation receipt")
	if err != nil {
		t.Fatalf("decode assignment mutation receipt: %v", err)
	}
	digest := sha256.Sum256(checkpointRaw)
	if receipt.Version != 1 ||
		receipt.Descriptor != handshake.Descriptor ||
		receipt.Arm != handshake.Arm ||
		receipt.ClientRunID != cfg.clientRunID ||
		receipt.ClientSHA != cfg.buildSHA ||
		receipt.CheckpointSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("assignment mutation receipt is not bound to this checkpoint and controller run")
	}
	validateAssignmentMutation(t, receipt.Move, "move", handshake.Descriptor)
	validateAssignmentMutation(t, receipt.ExpireLease, "expire_lease", handshake.Descriptor)
	moveMutatedAt, _ := parseAssignmentTimestamp(receipt.Move.Result.MutatedAt)
	moveLeaseExpiresAt, _ := parseAssignmentTimestamp(receipt.Move.Result.LeaseExpiresAt)
	expireMutatedAt, _ := parseAssignmentTimestamp(receipt.ExpireLease.Result.MutatedAt)
	expireLeaseExpiresAt, _ := parseAssignmentTimestamp(receipt.ExpireLease.Result.LeaseExpiresAt)
	if expireMutatedAt.Before(moveMutatedAt) || !expireLeaseExpiresAt.Before(moveLeaseExpiresAt) {
		t.Fatal("expire receipt does not shorten the exact moved assignment lease")
	}
	if receipt.Move.Result.PreviousCellID != warm.CellID ||
		receipt.Move.Result.PreviousAssignmentGeneration != warm.AssignmentGeneration ||
		receipt.Move.Result.NewCellID != handshake.Descriptor.TargetCellID ||
		receipt.Move.Result.NewAssignmentGeneration != warm.AssignmentGeneration+1 {
		t.Fatal("assignment move receipt does not advance the observed warm assignment")
	}
	return receipt
}

func loadAssignmentHandshake(t *testing.T, cfg sandboxConfig) assignmentHandshake {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(cfg.assignmentHandshake)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != cfg.assignmentHandshake {
		t.Fatal("assignment handshake is not canonical base64")
	}
	handshake, err := decodeStrictJSON[assignmentHandshake](raw, "assignment handshake")
	if err != nil {
		t.Fatalf("decode assignment handshake: %v", err)
	}
	descriptor := handshake.Descriptor
	prefix := "handshake/v1/" + cfg.controllerRunID + "/" + cfg.controllerRunAttempt + "/" + descriptor.ChannelID
	if descriptor.Version != 1 ||
		descriptor.ControllerRunID != cfg.controllerRunID ||
		descriptor.ControllerRunAttempt != cfg.controllerRunAttempt ||
		!assignmentRunRE.MatchString(descriptor.ControllerRunID) ||
		!assignmentRunRE.MatchString(descriptor.ControllerRunAttempt) ||
		descriptor.Client != "qurl_go" ||
		(descriptor.ProofPhase != "pre_removal" && descriptor.ProofPhase != "post_removal") ||
		!assignmentHex32RE.MatchString(descriptor.ChannelID) ||
		descriptor.CorrelationID != "nhp-"+cfg.controllerRunID+"-"+cfg.controllerRunAttempt+"-qurl_go-"+descriptor.ProofPhase+"-"+descriptor.ChannelID ||
		descriptor.AgentID != cfg.agentID ||
		descriptor.Bucket != assignmentHandshakeBucket ||
		!assignmentKMSRE.MatchString(descriptor.KMSKeyARN) ||
		descriptor.CheckpointKey != prefix+"/checkpoint.json" ||
		descriptor.ReceiptKey != prefix+"/receipt.json" ||
		!assignmentAliasRE.MatchString(descriptor.CAPMAliasARN) ||
		descriptor.PinnedCellID != "cell0" ||
		descriptor.TargetCellID != "cell1" ||
		descriptor.ArmLeaseSeconds != 2100 ||
		descriptor.ExpireLeaseSeconds != 30 ||
		!assignmentHex64RE.MatchString(descriptor.ArmRequestID) ||
		!assignmentHex64RE.MatchString(descriptor.MoveRequestID) ||
		!assignmentHex64RE.MatchString(descriptor.ExpireRequestID) ||
		descriptor.ArmRequestID == descriptor.MoveRequestID ||
		descriptor.ArmRequestID == descriptor.ExpireRequestID ||
		descriptor.MoveRequestID == descriptor.ExpireRequestID {
		t.Fatal("assignment handshake descriptor is not bound to this controller run")
	}
	if descriptor.CorrelationID != os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID") ||
		descriptor.ProofPhase != os.Getenv(proofPhaseEnv) {
		t.Fatal("assignment handshake differs from authenticated dispatch inputs")
	}
	validateAssignmentMutation(t, handshake.Arm, "arm", descriptor)
	if handshake.Arm.Result.PinnedCellID != descriptor.PinnedCellID ||
		handshake.Arm.Result.TargetCellID != descriptor.TargetCellID ||
		handshake.Arm.Result.LeaseSeconds != descriptor.ArmLeaseSeconds ||
		handshake.Arm.Result.GrantCorrelationID != descriptor.CorrelationID {
		t.Fatal("assignment arm receipt differs from the descriptor")
	}
	validateTransportProofDescriptor(t, handshake.Transport, descriptor, cfg)
	return handshake
}

func validateAssignmentMutation(
	t *testing.T,
	envelope assignmentMutationEnvelope,
	mutation string,
	descriptor assignmentHandshakeDescriptor,
) {
	t.Helper()
	if envelope.Version != 1 ||
		envelope.Result.Mutation != mutation ||
		envelope.Result.AgentID != descriptor.AgentID {
		t.Fatalf("%s mutation envelope is not run-bound", mutation)
	}
	mutatedAt, err := parseAssignmentTimestamp(envelope.Result.MutatedAt)
	if err != nil {
		t.Fatalf("%s mutated_at: %v", mutation, err)
	}
	switch mutation {
	case "arm":
		if envelope.Result.PreviousCellID != "" ||
			envelope.Result.NewCellID != "" ||
			envelope.Result.NewAssignmentGeneration != 0 ||
			envelope.Result.LeaseExpiresAt != "" {
			t.Fatal("arm receipt carries move-only fields")
		}
	case "move":
		if envelope.Result.PinnedCellID != "" ||
			envelope.Result.TargetCellID != "" ||
			envelope.Result.LeaseSeconds != 0 ||
			envelope.Result.GrantCorrelationID != "" {
			t.Fatal("move receipt carries arm-only fields")
		}
		leaseExpiresAt, err := parseAssignmentTimestamp(envelope.Result.LeaseExpiresAt)
		if err != nil {
			t.Fatalf("move lease_expires_at: %v", err)
		}
		if leaseExpiresAt.Sub(mutatedAt) != time.Duration(descriptor.ArmLeaseSeconds)*time.Second {
			t.Fatal("move lease transition does not equal the armed lease")
		}
	case "expire_lease":
		if envelope.Result.PinnedCellID != "" ||
			envelope.Result.TargetCellID != "" ||
			envelope.Result.LeaseSeconds != 0 ||
			envelope.Result.GrantCorrelationID != "" ||
			envelope.Result.PreviousCellID != "" ||
			envelope.Result.NewCellID != "" ||
			envelope.Result.NewAssignmentGeneration != 0 {
			t.Fatal("expire receipt carries fields from another mutation")
		}
		leaseExpiresAt, err := parseAssignmentTimestamp(envelope.Result.LeaseExpiresAt)
		if err != nil {
			t.Fatalf("expire lease_expires_at: %v", err)
		}
		if leaseExpiresAt.Sub(mutatedAt) != time.Duration(descriptor.ExpireLeaseSeconds)*time.Second {
			t.Fatal("expire lease transition does not equal the reviewed floor")
		}
	default:
		t.Fatalf("unsupported mutation %q", mutation)
	}
}

func assertAssignmentReceiptMatchesRefresh(
	t *testing.T,
	receipt assignmentReceipt,
	reassignment sandboxCellEvidence,
) {
	t.Helper()
	reassignmentLease, reassignmentLeaseErr := parseAssignmentTimestamp(reassignment.LeaseExpiresAt)
	receiptLease, receiptLeaseErr := parseAssignmentTimestamp(receipt.ExpireLease.Result.LeaseExpiresAt)
	if reassignment.CellID != receipt.Move.Result.NewCellID ||
		reassignment.AssignmentGeneration != receipt.Move.Result.NewAssignmentGeneration ||
		reassignmentLeaseErr != nil ||
		receiptLeaseErr != nil ||
		!reassignmentLease.Equal(receiptLease) {
		t.Fatalf(
			"refreshed assignment differs from controller mutation receipt: reassignment=%+v move=%+v expire=%+v",
			reassignment,
			receipt.Move.Result,
			receipt.ExpireLease.Result,
		)
	}
}

func parseAssignmentTimestamp(value string) (time.Time, error) {
	if !assignmentTimeRE.MatchString(value) {
		return time.Time{}, fmt.Errorf("must be canonical whole-second UTC")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, fmt.Errorf("must be a real canonical whole-second UTC timestamp")
	}
	return parsed, nil
}

func runAWS(ctx context.Context, t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.CommandContext(ctx, "aws", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("aws %s: %v: %s", strings.Join(arguments, " "), err, boundedOutput(output))
	}
}

func boundedOutput(raw []byte) string {
	const maximum = 4096
	if len(raw) > maximum {
		raw = raw[:maximum]
	}
	return strconv.QuoteToASCII(string(raw))
}
