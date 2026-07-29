package nativeudp_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	transportCapturePathEnv    = "QURL_GO_SANDBOX_TRANSPORT_CAPTURE_PATH"
	transportCapturePIDPathEnv = "QURL_GO_SANDBOX_TRANSPORT_CAPTURE_PID_PATH"
	transportCaptureDoneEnv    = "QURL_GO_SANDBOX_TRANSPORT_CAPTURE_DONE_PATH"
	transportCaptureStartEnv   = "QURL_GO_SANDBOX_TRANSPORT_CAPTURE_STARTED_AT"
	transportCaptureTargetsEnv = "QURL_GO_SANDBOX_TRANSPORT_CAPTURE_TARGETS_B64"
	transportProofSourceIP     = "3.141.109.76"
	transportMaxCaptureBytes   = 4 * 1024 * 1024
)

var (
	transportHTTPHosts = []string{
		"api.layerv.xyz",
		"bootstrap.layerv.xyz",
		"relay.qurl.link.layerv.xyz",
	}
	transportQURLLogGroups = []string{
		"/layerv/nhp/sandbox/cell0/qurl-api",
		"/layerv/nhp/sandbox/cell1/qurl-api",
	}
	transportLegacyRoutes = []transportProofRoute{
		{Method: "GET", Path: "/v1/agent/registration-info"},
		{Method: "POST", Path: "/v1/agent/bootstrap"},
		{Method: "POST", Path: "/v1/agent/registration/complete"},
	}
	transportPIDRE = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

type transportProofRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type transportProofDescriptor struct {
	Version                   int                   `json:"version"`
	ControllerRunID           string                `json:"controller_run_id"`
	ControllerRunAttempt      string                `json:"controller_run_attempt"`
	Client                    string                `json:"client"`
	ProofPhase                string                `json:"proof_phase"`
	ChannelID                 string                `json:"channel_id"`
	CorrelationID             string                `json:"correlation_id"`
	AgentID                   string                `json:"agent_id"`
	Bucket                    string                `json:"bucket"`
	KMSKeyARN                 string                `json:"kms_key_arn"`
	CheckpointKey             string                `json:"checkpoint_key"`
	ReceiptKey                string                `json:"receipt_key"`
	ProofSourceIP             string                `json:"proof_source_ip"`
	LifecycleHTTPHosts        []string              `json:"lifecycle_http_hosts"`
	QURLServiceLogGroups      []string              `json:"qurl_service_log_groups"`
	RelayLogGroup             string                `json:"relay_log_group"`
	LegacyLifecycleHTTPRoutes []transportProofRoute `json:"legacy_lifecycle_http_routes"`
}

type transportCaptureTarget struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
}

type transportCaptureTargets struct {
	Version int                      `json:"version"`
	Hosts   []transportCaptureTarget `json:"hosts"`
}

type transportCaptureObservation struct {
	RawSHA256      string
	TargetsSHA256  string
	PacketCount    int
	UDPOutbound    int
	UDPInbound     int
	CaptureStarted string
	CaptureEnded   string
}

type transportProofCheckpoint struct {
	Version              int      `json:"version"`
	ControllerRunID      string   `json:"controller_run_id"`
	ControllerRunAttempt string   `json:"controller_run_attempt"`
	ChannelID            string   `json:"channel_id"`
	ClientRunID          string   `json:"client_run_id"`
	ClientSHA            string   `json:"client_sha"`
	CorrelationID        string   `json:"correlation_id"`
	AgentID              string   `json:"agent_id"`
	CaptureStartedAt     string   `json:"capture_started_at"`
	CaptureEndedAt       string   `json:"capture_ended_at"`
	CaptureSHA256        string   `json:"capture_sha256"`
	CaptureTargetsSHA256 string   `json:"capture_targets_sha256"`
	CapturedPacketCount  int      `json:"captured_packet_count"`
	UDP62206Outbound     int      `json:"udp_62206_outbound"`
	UDP62206Inbound      int      `json:"udp_62206_inbound"`
	HTTPTrapCalls        int64    `json:"http_trap_calls"`
	ObservedCellIDs      []string `json:"observed_cell_ids"`
	NHPUDPLifecycleOK    bool     `json:"nhp_udp_lifecycle_success"`
}

type transportCounterReceipt struct {
	Version                     int                      `json:"version"`
	Descriptor                  transportProofDescriptor `json:"descriptor"`
	ClientRunID                 string                   `json:"client_run_id"`
	ClientSHA                   string                   `json:"client_sha"`
	CheckpointSHA256            string                   `json:"checkpoint_sha256"`
	CaptureSHA256               string                   `json:"capture_sha256"`
	CaptureTargetsSHA256        string                   `json:"capture_targets_sha256"`
	CaptureStartedAt            string                   `json:"capture_started_at"`
	CaptureEndedAt              string                   `json:"capture_ended_at"`
	NHPUDPLifecycleOK           bool                     `json:"nhp_udp_lifecycle_success"`
	QURLServiceLegacyRouteCount int                      `json:"qurl_service_legacy_route_count"`
	RelayRouteCount             int                      `json:"relay_route_count"`
	CountersObservedAt          string                   `json:"counters_observed_at"`
}

func validateTransportProofDescriptor(
	t *testing.T,
	transport transportProofDescriptor,
	assignment assignmentHandshakeDescriptor,
	cfg sandboxConfig,
) {
	t.Helper()
	prefix := "handshake/v1/" + cfg.controllerRunID + "/" + cfg.controllerRunAttempt + "/" + assignment.ChannelID
	if transport.Version != 1 ||
		transport.ControllerRunID != assignment.ControllerRunID ||
		transport.ControllerRunAttempt != assignment.ControllerRunAttempt ||
		transport.Client != assignment.Client ||
		transport.ProofPhase != assignment.ProofPhase ||
		transport.ChannelID != assignment.ChannelID ||
		transport.CorrelationID != assignment.CorrelationID ||
		transport.AgentID != assignment.AgentID ||
		transport.Bucket != assignment.Bucket ||
		transport.KMSKeyARN != assignment.KMSKeyARN ||
		transport.CheckpointKey != prefix+"/transport-checkpoint.json" ||
		transport.ReceiptKey != prefix+"/transport-receipt.json" ||
		transport.ProofSourceIP != transportProofSourceIP ||
		transport.RelayLogGroup != "/layerv/nhp/sandbox/relay" ||
		!slices.Equal(transport.LifecycleHTTPHosts, transportHTTPHosts) ||
		!slices.Equal(transport.QURLServiceLogGroups, transportQURLLogGroups) ||
		!reflect.DeepEqual(transport.LegacyLifecycleHTTPRoutes, transportLegacyRoutes) {
		t.Fatal("transport proof descriptor is not bound to the assignment controller run")
	}
}

func completeTransportProof(
	ctx context.Context,
	t *testing.T,
	cfg sandboxConfig,
	httpTrap *lifecycleHTTPTrap,
	cells []sandboxCellEvidence,
) {
	t.Helper()
	handshake := loadAssignmentHandshake(t, cfg)
	calls, first := httpTrap.snapshot()
	if calls != 0 {
		t.Fatalf("native lifecycle made %d forbidden HTTP call(s); first=%q", calls, first)
	}
	observation := stopAndValidateTransportCapture(t, cfg, handshake.Transport, cells)
	cellIDs := make([]string, 0, len(cells))
	for _, cell := range cells {
		if !slices.Contains(cellIDs, cell.CellID) {
			cellIDs = append(cellIDs, cell.CellID)
		}
	}
	slices.Sort(cellIDs)
	if !slices.Equal(cellIDs, []string{"cell0", "cell1"}) {
		t.Fatalf("transport proof observed cells = %v, want exact cell0/cell1 lifecycle", cellIDs)
	}
	checkpoint := transportProofCheckpoint{
		Version:              1,
		ControllerRunID:      handshake.Transport.ControllerRunID,
		ControllerRunAttempt: handshake.Transport.ControllerRunAttempt,
		ChannelID:            handshake.Transport.ChannelID,
		ClientRunID:          cfg.clientRunID,
		ClientSHA:            cfg.buildSHA,
		CorrelationID:        handshake.Transport.CorrelationID,
		AgentID:              handshake.Transport.AgentID,
		CaptureStartedAt:     observation.CaptureStarted,
		CaptureEndedAt:       observation.CaptureEnded,
		CaptureSHA256:        observation.RawSHA256,
		CaptureTargetsSHA256: observation.TargetsSHA256,
		CapturedPacketCount:  observation.PacketCount,
		UDP62206Outbound:     observation.UDPOutbound,
		UDP62206Inbound:      observation.UDPInbound,
		HTTPTrapCalls:        calls,
		ObservedCellIDs:      cellIDs,
		NHPUDPLifecycleOK:    true,
	}
	checkpointRaw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw = append(checkpointRaw, '\n')
	directory := t.TempDir()
	checkpointPath := filepath.Join(directory, "transport-checkpoint.json")
	if err := os.WriteFile(checkpointPath, checkpointRaw, 0o600); err != nil {
		t.Fatalf("write transport checkpoint: %v", err)
	}
	runAWS(
		ctx,
		t,
		"s3api", "put-object",
		"--region", "us-east-2",
		"--bucket", handshake.Transport.Bucket,
		"--key", handshake.Transport.CheckpointKey,
		"--body", checkpointPath,
		"--content-type", "application/json",
		"--server-side-encryption", "aws:kms",
		"--ssekms-key-id", handshake.Transport.KMSKeyARN,
		"--if-none-match", "*",
	)

	receiptRaw := waitForTransportReceipt(ctx, t, handshake.Transport, directory)
	receipt, err := decodeStrictJSON[transportCounterReceipt](receiptRaw, "transport counter receipt")
	if err != nil {
		t.Fatalf("decode transport counter receipt: %v", err)
	}
	checkpointDigest := sha256.Sum256(checkpointRaw)
	if receipt.Version != 1 ||
		!reflect.DeepEqual(receipt.Descriptor, handshake.Transport) ||
		receipt.ClientRunID != cfg.clientRunID ||
		receipt.ClientSHA != cfg.buildSHA ||
		receipt.CheckpointSHA256 != hex.EncodeToString(checkpointDigest[:]) ||
		receipt.CaptureSHA256 != checkpoint.CaptureSHA256 ||
		receipt.CaptureTargetsSHA256 != checkpoint.CaptureTargetsSHA256 ||
		receipt.CaptureStartedAt != checkpoint.CaptureStartedAt ||
		receipt.CaptureEndedAt != checkpoint.CaptureEndedAt ||
		!receipt.NHPUDPLifecycleOK ||
		receipt.QURLServiceLegacyRouteCount != 0 ||
		receipt.RelayRouteCount != 0 {
		t.Fatal("transport receipt is not exact-run zero-HTTP evidence")
	}
	observedAt, err := parseAssignmentTimestamp(receipt.CountersObservedAt)
	if err != nil {
		t.Fatalf("transport counters_observed_at: %v", err)
	}
	captureEnded, _ := parseAssignmentTimestamp(receipt.CaptureEndedAt)
	if observedAt.Before(captureEnded) || observedAt.Sub(captureEnded) > 20*time.Minute {
		t.Fatal("transport counter observation is outside the bounded post-capture interval")
	}
	t.Logf(
		"EVIDENCE transport_capture_sha256=%s packets=%d udp_62206_outbound=%d udp_62206_inbound=%d qurl_service_legacy_routes=0 relay_routes=0",
		observation.RawSHA256,
		observation.PacketCount,
		observation.UDPOutbound,
		observation.UDPInbound,
	)
}

func stopAndValidateTransportCapture(
	t *testing.T,
	cfg sandboxConfig,
	descriptor transportProofDescriptor,
	cells []sandboxCellEvidence,
) transportCaptureObservation {
	t.Helper()
	tracePath := canonicalAbsoluteEnvPath(t, transportCapturePathEnv)
	pidPath := canonicalAbsoluteEnvPath(t, transportCapturePIDPathEnv)
	donePath := canonicalAbsoluteEnvPath(t, transportCaptureDoneEnv)
	startedAt := os.Getenv(transportCaptureStartEnv)
	if _, err := parseAssignmentTimestamp(startedAt); err != nil {
		t.Fatalf("%s: %v", transportCaptureStartEnv, err)
	}
	targetRaw, err := base64.StdEncoding.Strict().DecodeString(os.Getenv(transportCaptureTargetsEnv))
	if err != nil || base64.StdEncoding.EncodeToString(targetRaw) != os.Getenv(transportCaptureTargetsEnv) {
		t.Fatalf("%s is not canonical standard base64", transportCaptureTargetsEnv)
	}
	targets, err := decodeStrictJSON[transportCaptureTargets](targetRaw, "transport capture targets")
	if err != nil {
		t.Fatalf("decode transport capture targets: %v", err)
	}
	canonicalTargets, err := json.Marshal(targets)
	if err != nil || !bytes.Equal(canonicalTargets, targetRaw) {
		t.Fatal("transport capture targets are not canonical JSON")
	}
	allowedAddresses := validateTransportCaptureTargets(t, cfg, descriptor, cells, targets)

	pidRaw, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read transport capture pid: %v", err)
	}
	pidText := strings.TrimSpace(string(pidRaw))
	if !transportPIDRE.MatchString(pidText) {
		t.Fatal("transport capture pid is invalid")
	}
	pidValue, _ := strconv.Atoi(pidText)
	cmdline, err := os.ReadFile("/proc/" + pidText + "/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("tcpdump")) {
		t.Fatal("transport capture pid is not the expected tcpdump process")
	}
	process, err := os.FindProcess(pidValue)
	if err != nil || process.Signal(os.Interrupt) != nil {
		t.Fatal("could not stop the transport metadata capture")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, readErr := os.ReadFile(donePath)
		if readErr == nil {
			if string(raw) != "ok\n" {
				t.Fatal("transport capture did not exit cleanly")
			}
			break
		}
		if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatalf("read transport capture completion: %v", readErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out stopping transport metadata capture")
		}
		time.Sleep(100 * time.Millisecond)
	}
	endedAt := time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	started, _ := parseAssignmentTimestamp(startedAt)
	ended, _ := parseAssignmentTimestamp(endedAt)
	if ended.Before(started) || ended.Sub(started) > sandboxProofTimeout {
		t.Fatal("transport capture interval is invalid")
	}
	info, err := os.Lstat(tracePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > transportMaxCaptureBytes {
		t.Fatal("transport metadata capture file is invalid")
	}
	traceRaw, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read transport metadata capture: %v", err)
	}
	packetCount, outbound, inbound, err := validateTransportCapture(traceRaw, allowedAddresses)
	if err != nil {
		t.Fatal(err)
	}
	if packetCount < 2 || outbound < 1 || inbound < 1 {
		t.Fatal("transport capture does not contain a successful bidirectional NHP UDP lifecycle")
	}
	traceDigest := sha256.Sum256(traceRaw)
	targetDigest := sha256.Sum256(targetRaw)
	return transportCaptureObservation{
		RawSHA256:      hex.EncodeToString(traceDigest[:]),
		TargetsSHA256:  hex.EncodeToString(targetDigest[:]),
		PacketCount:    packetCount,
		UDPOutbound:    outbound,
		UDPInbound:     inbound,
		CaptureStarted: startedAt,
		CaptureEnded:   endedAt,
	}
}

func canonicalAbsoluteEnvPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		t.Fatalf("%s must be one canonical absolute path", name)
	}
	return value
}

func validateTransportCaptureTargets(
	t *testing.T,
	cfg sandboxConfig,
	descriptor transportProofDescriptor,
	cells []sandboxCellEvidence,
	targets transportCaptureTargets,
) map[netip.Addr]struct{} {
	t.Helper()
	expectedHosts := append([]string(nil), descriptor.LifecycleHTTPHosts...)
	expectedHosts = append(expectedHosts, cfg.hubHost)
	for _, cell := range cells {
		expectedHosts = append(expectedHosts, cell.Host)
	}
	slices.Sort(expectedHosts)
	expectedHosts = slices.Compact(expectedHosts)
	if targets.Version != 1 || len(targets.Hosts) != len(expectedHosts) {
		t.Fatal("transport capture target set does not cover the exact lifecycle hosts")
	}
	addresses := make(map[netip.Addr]struct{})
	observedHosts := make([]string, 0, len(targets.Hosts))
	for _, target := range targets.Hosts {
		if target.Host == "" || !slices.IsSorted(target.Addresses) || len(target.Addresses) < 1 {
			t.Fatal("transport capture target is malformed")
		}
		observedHosts = append(observedHosts, target.Host)
		previous := ""
		for _, raw := range target.Addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.Is4() || address.String() != raw || raw == previous {
				t.Fatal("transport capture target address is not a unique canonical IPv4 address")
			}
			addresses[address] = struct{}{}
			previous = raw
		}
	}
	if !slices.IsSorted(observedHosts) || !slices.Equal(observedHosts, expectedHosts) {
		t.Fatal("transport capture target hosts differ from the authenticated lifecycle topology")
	}
	return addresses
}

func validateTransportCapture(raw []byte, allowed map[netip.Addr]struct{}) (int, int, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	packets := 0
	outbound := 0
	inbound := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || !strings.Contains(line, ": UDP,") {
			return 0, 0, 0, fmt.Errorf("transport capture contains non-UDP metadata")
		}
		separator := strings.Index(line, " > ")
		if separator < 0 {
			return 0, 0, 0, fmt.Errorf("transport capture packet shape is malformed")
		}
		leftFields := strings.Fields(line[:separator])
		rightFields := strings.Fields(line[separator+3:])
		if len(leftFields) < 1 || len(rightFields) < 1 {
			return 0, 0, 0, fmt.Errorf("transport capture endpoints are missing")
		}
		sourceIP, sourcePort, err := parseTCPDumpEndpoint(leftFields[len(leftFields)-1])
		if err != nil {
			return 0, 0, 0, err
		}
		destinationIP, destinationPort, err := parseTCPDumpEndpoint(strings.TrimSuffix(rightFields[0], ":"))
		if err != nil {
			return 0, 0, 0, err
		}
		_, sourceTarget := allowed[sourceIP]
		_, destinationTarget := allowed[destinationIP]
		if sourceTarget == destinationTarget {
			return 0, 0, 0, fmt.Errorf("transport capture packet is not between the runner and one exact lifecycle target")
		}
		switch {
		case destinationTarget && destinationPort == standardNHPUDPPort:
			outbound++
		case sourceTarget && sourcePort == standardNHPUDPPort:
			inbound++
		default:
			return 0, 0, 0, fmt.Errorf("transport capture contains lifecycle traffic outside UDP %d", standardNHPUDPPort)
		}
		packets++
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("scan transport capture: %w", err)
	}
	return packets, outbound, inbound, nil
}

func parseTCPDumpEndpoint(value string) (netip.Addr, int, error) {
	index := strings.LastIndexByte(value, '.')
	if index < 1 {
		return netip.Addr{}, 0, fmt.Errorf("transport capture endpoint is malformed")
	}
	address, err := netip.ParseAddr(value[:index])
	if err != nil || !address.Is4() {
		return netip.Addr{}, 0, fmt.Errorf("transport capture endpoint address is invalid")
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("transport capture endpoint port is invalid")
	}
	return address, port, nil
}

func waitForTransportReceipt(
	ctx context.Context,
	t *testing.T,
	descriptor transportProofDescriptor,
	directory string,
) []byte {
	t.Helper()
	receiptPath := filepath.Join(directory, "transport-receipt.json")
	for {
		if err := ctx.Err(); err != nil {
			t.Fatalf("wait for transport counter receipt: %v", err)
		}
		_ = os.Remove(receiptPath)
		command := exec.CommandContext(
			ctx,
			"aws",
			"s3api", "get-object",
			"--region", "us-east-2",
			"--bucket", descriptor.Bucket,
			"--key", descriptor.ReceiptKey,
			receiptPath,
		)
		output, commandErr := command.CombinedOutput()
		if commandErr == nil {
			raw, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatalf("read transport counter receipt: %v", err)
			}
			return raw
		}
		if !bytes.Contains(output, []byte("NoSuchKey")) && !bytes.Contains(output, []byte("404")) {
			t.Fatalf("read transport counter receipt: %v: %s", commandErr, boundedOutput(output))
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func TestValidateTransportCaptureRejectsHTTPAndWrongUDPPort(t *testing.T) {
	allowed := map[netip.Addr]struct{}{netip.MustParseAddr("203.0.113.10"): {}}
	valid := []byte(
		"1.000000 eth0 Out IP 10.0.0.5.49152 > 203.0.113.10.62206: UDP, length 100\n" +
			"1.100000 eth0 In IP 203.0.113.10.62206 > 10.0.0.5.49152: UDP, length 120\n",
	)
	if packets, outbound, inbound, err := validateTransportCapture(valid, allowed); err != nil ||
		packets != 2 || outbound != 1 || inbound != 1 {
		t.Fatalf("valid transport capture rejected: packets=%d outbound=%d inbound=%d err=%v", packets, outbound, inbound, err)
	}
	for name, raw := range map[string][]byte{
		"tcp":        []byte("1.000000 eth0 Out IP 10.0.0.5.49152 > 203.0.113.10.443: Flags [S], length 0\n"),
		"wrong port": []byte("1.000000 eth0 Out IP 10.0.0.5.49152 > 203.0.113.10.53: UDP, length 10\n"),
		"foreign":    []byte("1.000000 eth0 Out IP 10.0.0.5.49152 > 198.51.100.10.62206: UDP, length 10\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := validateTransportCapture(raw, allowed); err == nil {
				t.Fatal("invalid transport capture passed")
			}
		})
	}
}
