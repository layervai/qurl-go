package nativeudp_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	runtimeProbePathEnv        = "QURL_GO_SANDBOX_RUNTIME_PROBE_PATH"
	retirementProbeTargetsEnv  = "QURL_GO_SANDBOX_RETIREMENT_PROBE_TARGETS_PATH"
	runtimeProbeGate           = "udp_lifecycle_retirement"
	runtimeRelayBaseURL        = "https://relay.qurl.link.layerv.xyz"
	runtimeMaxHTTPResponseSize = 1 << 20
	runtimeProbeTimeLayout     = "2006-01-02T15:04:05.000000000Z"
)

var (
	protocolErrorCodeRE = regexp.MustCompile(`^[1-9][0-9]{4}$`)
	relayServerIDRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
)

type runtimeProbeEndpoint struct {
	TargetRole string
	CellID     string
}

type runtimeWireEvent struct {
	Ordinal     int     `json:"ordinal"`
	Direction   string  `json:"direction"`
	TargetRole  string  `json:"target_role"`
	CellID      string  `json:"cell_id"`
	MessageType string  `json:"message_type"`
	PacketSHA   string  `json:"packet_sha256"`
	RunID       *string `json:"run_id"`
}

type runtimeWireRecorder struct {
	mu        sync.Mutex
	endpoints map[string]runtimeProbeEndpoint
	events    []runtimeWireEvent
	runID     string
}

func newRuntimeWireRecorder(ctx context.Context, t *testing.T) *runtimeWireRecorder {
	t.Helper()
	path := os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_PATH")
	if !filepath.IsAbs(path) {
		t.Fatalf("QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_PATH must be absolute")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read deployment runtime inputs for wire audit: %v", err)
	}
	var inputs struct {
		Hub struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"hub"`
		Cells []struct {
			CellID string `json:"cell_id"`
			Host   string `json:"host"`
			Port   int    `json:"port"`
		} `json:"cells"`
	}
	if err := json.Unmarshal(raw, &inputs); err != nil {
		t.Fatalf("decode deployment runtime inputs for wire audit: %v", err)
	}
	recorder := &runtimeWireRecorder{endpoints: make(map[string]runtimeProbeEndpoint)}
	recorder.addResolvedEndpoint(ctx, t, inputs.Hub.Host, inputs.Hub.Port, runtimeProbeEndpoint{TargetRole: "hub"})
	for _, cell := range inputs.Cells {
		recorder.addResolvedEndpoint(ctx, t, cell.Host, cell.Port, runtimeProbeEndpoint{TargetRole: "cell", CellID: cell.CellID})
	}
	return recorder
}

func (r *runtimeWireRecorder) addResolvedEndpoint(ctx context.Context, t *testing.T, host string, port int, endpoint runtimeProbeEndpoint) {
	t.Helper()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		t.Fatalf("resolve runtime wire endpoint %s: %v", host, err)
	}
	for _, address := range addresses {
		key := net.JoinHostPort(address.String(), strconv.Itoa(port))
		if prior, exists := r.endpoints[key]; exists && prior != endpoint {
			t.Fatalf("runtime wire endpoint %s is shared by incompatible roles", key)
		}
		r.endpoints[key] = endpoint
	}
}

func (r *runtimeWireRecorder) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	endpoint, ok := r.endpoints[address]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("runtime wire audit rejected unbound destination %s", address)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &runtimeAuditConn{Conn: conn, recorder: r, endpoint: endpoint}, nil
}

func (r *runtimeWireRecorder) setRunID(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runID = runID
}

func (r *runtimeWireRecorder) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *runtimeWireRecorder) since(mark int) []runtimeWireEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mark < 0 || mark > len(r.events) {
		return nil
	}
	result := slices.Clone(r.events[mark:])
	for index := range result {
		result[index].Ordinal = index + 1
	}
	return result
}

func (r *runtimeWireRecorder) record(direction string, endpoint runtimeProbeEndpoint, packet []byte) error {
	messageType, err := runtimePacketType(packet)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(packet)
	r.mu.Lock()
	defer r.mu.Unlock()
	var runID *string
	if r.runID != "" && messageType != "COK" {
		value := r.runID
		runID = &value
	}
	r.events = append(r.events, runtimeWireEvent{
		Direction: direction, TargetRole: endpoint.TargetRole, CellID: endpoint.CellID,
		MessageType: messageType, PacketSHA: hex.EncodeToString(digest[:]), RunID: runID,
	})
	return nil
}

type runtimeAuditConn struct {
	net.Conn
	recorder *runtimeWireRecorder
	endpoint runtimeProbeEndpoint
}

func (c *runtimeAuditConn) Write(packet []byte) (int, error) {
	n, err := c.Conn.Write(packet)
	if n > 0 {
		if auditErr := c.recorder.record("request", c.endpoint, packet[:n]); auditErr != nil && err == nil {
			err = auditErr
		}
	}
	return n, err
}

func (c *runtimeAuditConn) Read(packet []byte) (int, error) {
	n, err := c.Conn.Read(packet)
	if n > 0 {
		if auditErr := c.recorder.record("response", c.endpoint, packet[:n]); auditErr != nil && err == nil {
			err = auditErr
		}
	}
	return n, err
}

func runtimePacketType(packet []byte) (string, error) {
	if len(packet) < 24 {
		return "", errors.New("runtime wire packet is shorter than the NHP header")
	}
	preamble := binary.BigEndian.Uint32(packet[0:4])
	typeAndSize := preamble ^ binary.BigEndian.Uint32(packet[4:8])
	switch int(typeAndSize >> 16) {
	case relayknock.TypeKnock:
		return "KNK", nil
	case relayknock.TypeACK:
		return "ACK", nil
	case relayknock.TypeListRequest:
		return "LST", nil
	case relayknock.TypeListResult:
		return "LRT", nil
	case relayknock.TypeCookieChallenge:
		return "COK", nil
	case relayknock.TypeReknock:
		return "RKN", nil
	case relayknock.TypeOTP:
		return "OTP", nil
	case relayknock.TypeRegister:
		return "REG", nil
	case relayknock.TypeRegisterAck:
		return "RAK", nil
	case relayknock.TypeExit:
		return "EXT", nil
	default:
		return "", fmt.Errorf("runtime wire packet has unsupported NHP type %d", typeAndSize>>16)
	}
}

type wrongCallerProbe struct {
	TargetRole        string `json:"target_role"`
	CellID            string `json:"cell_id"`
	Operation         string `json:"operation"`
	RequestType       string `json:"request_type"`
	ResponseType      string `json:"response_type"`
	ErrorCode         string `json:"error_code"`
	PeerPublicKeySHA  string `json:"peer_public_key_sha256"`
	RequestPacketSHA  string `json:"request_packet_sha256"`
	ResponsePacketSHA string `json:"response_packet_sha256"`
	Outcome           string `json:"outcome"`
}

type wrongSourceInjection struct {
	TargetRole        string `json:"target_role"`
	CellID            string `json:"cell_id"`
	RequestType       string `json:"request_type"`
	ResponseType      string `json:"response_type"`
	ExpectedSource    string `json:"expected_source"`
	InjectedSource    string `json:"injected_source"`
	RequestPacketSHA  string `json:"request_packet_sha256"`
	InjectedPacketSHA string `json:"injected_packet_sha256"`
	ErrorClass        string `json:"error_class"`
	Outcome           string `json:"outcome"`
}

type wrongSourceDialer struct {
	mu                       sync.Mutex
	targetRole               string
	cellID                   string
	forbiddenInjectedSources map[string]struct{}
	injections               []wrongSourceInjection
}

func (d *wrongSourceDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "udp" {
		return nil, fmt.Errorf("wrong-source proof requires udp, got %s", network)
	}
	proxy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	client, err := (&net.Dialer{}).DialContext(ctx, "udp", proxy.LocalAddr().String())
	if err != nil {
		_ = proxy.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer proxy.Close()
		request := make([]byte, 4097)
		n, clientAddress, readErr := proxy.ReadFromUDP(request)
		if readErr != nil {
			return
		}
		upstream, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", target)
		if dialErr != nil {
			return
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, writeErr := upstream.Write(request[:n]); writeErr != nil {
			return
		}
		response := make([]byte, 4097)
		responseN, readErr := upstream.Read(response)
		if readErr != nil {
			return
		}
		var injector *net.UDPConn
		for attempts := 0; attempts < 10; attempts++ {
			candidate, listenErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if listenErr != nil {
				return
			}
			d.mu.Lock()
			_, forbidden := d.forbiddenInjectedSources[candidate.LocalAddr().String()]
			d.mu.Unlock()
			if !forbidden {
				injector = candidate
				break
			}
			_ = candidate.Close()
		}
		if injector == nil {
			return
		}
		defer injector.Close()
		if _, writeErr := injector.WriteToUDP(response[:responseN], clientAddress); writeErr != nil {
			return
		}
		requestType, requestErr := runtimePacketType(request[:n])
		responseType, responseErr := runtimePacketType(response[:responseN])
		if requestErr != nil || responseErr != nil {
			return
		}
		requestDigest := sha256.Sum256(request[:n])
		responseDigest := sha256.Sum256(response[:responseN])
		d.mu.Lock()
		d.injections = append(d.injections, wrongSourceInjection{
			TargetRole: d.targetRole, CellID: d.cellID,
			RequestType: requestType, ResponseType: responseType,
			ExpectedSource: proxy.LocalAddr().String(), InjectedSource: injector.LocalAddr().String(),
			RequestPacketSHA:  hex.EncodeToString(requestDigest[:]),
			InjectedPacketSHA: hex.EncodeToString(responseDigest[:]),
			ErrorClass:        "nativeudp.ErrTransport", Outcome: "rejected",
		})
		d.mu.Unlock()
	}()
	return &wrongSourceConn{Conn: client, done: done}, nil
}

func (d *wrongSourceDialer) result(t *testing.T) wrongSourceInjection {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.injections) != 1 {
		t.Fatalf("wrong-source proxy produced %d injections, want exactly one", len(d.injections))
	}
	return d.injections[0]
}

type wrongSourceConn struct {
	net.Conn
	done chan struct{}
}

func (c *wrongSourceConn) Close() error {
	err := c.Conn.Close()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		if err == nil {
			err = errors.New("wrong-source proxy did not finish")
		}
	}
	return err
}

type runtimeHTTPProbe struct {
	Method              string `json:"method"`
	Path                string `json:"path"`
	Host                string `json:"host"`
	Status              int    `json:"status"`
	CorrelationIDSHA256 string `json:"correlation_id_sha256"`
	ResponseSHA256      string `json:"response_sha256"`
}

type retirementProbeTargets struct {
	SchemaVersion  int                       `json:"schema_version"`
	Gate           string                    `json:"gate"`
	Phase          string                    `json:"phase"`
	ObservedAt     string                    `json:"observed_at"`
	Producer       retirementTargetsProducer `json:"producer"`
	HTTPOperations []retirementHTTPTarget    `json:"http_operations"`
	Relay          retirementRelayTargets    `json:"relay"`
}

type retirementTargetsProducer struct {
	HeadSHA                    string `json:"head_sha"`
	RunID                      int64  `json:"run_id"`
	RunAttempt                 int64  `json:"run_attempt"`
	DeploymentProvenanceSHA256 string `json:"deployment_provenance_sha256"`
	SurfaceContractSHA256      string `json:"surface_contract_sha256"`
}

type retirementHTTPTarget struct {
	Host    string                   `json:"host"`
	Method  string                   `json:"method"`
	Path    string                   `json:"path"`
	Route53 retirementRoute53Binding `json:"route53"`
}

type retirementRoute53Binding struct {
	ZoneID       string `json:"zone_id"`
	RecordName   string `json:"record_name"`
	AliasDNSName string `json:"alias_dns_name"`
}

type retirementRelayTargets struct {
	BaseURL string                   `json:"base_url"`
	SSM     retirementSSMBinding     `json:"ssm"`
	Route53 retirementRoute53Binding `json:"route53"`
	Aliases []retirementRelayAlias   `json:"aliases"`
}

type retirementSSMBinding struct {
	Name        string `json:"name"`
	Version     int64  `json:"version"`
	ValueSHA256 string `json:"value_sha256"`
}

type retirementRelayAlias struct {
	CellID   string `json:"cell_id"`
	ServerID string `json:"server_id"`
}

type runtimeRelayProbe struct {
	CellID              string `json:"cell_id"`
	ServerID            string `json:"server_id"`
	MessageType         string `json:"message_type"`
	WireValue           int    `json:"wire_value"`
	HTTPStatus          int    `json:"http_status"`
	Outcome             string `json:"outcome"`
	CorrelationIDSHA256 string `json:"correlation_id_sha256"`
	RequestSHA256       string `json:"request_sha256"`
	ResponseSHA256      string `json:"response_sha256"`
}

type runtimeProbeObservations struct {
	WrongCaller struct {
		Probes []wrongCallerProbe `json:"probes"`
	} `json:"wrong_caller"`
	WrongSource struct {
		AcceptedPackets int                    `json:"accepted_packets"`
		Injections      []wrongSourceInjection `json:"injections"`
	} `json:"wrong_source"`
	RegistrationWire runtimeRegistrationWireObservation `json:"registration_wire"`
	SessionWire      struct {
		Cycles      []runtimeSessionCycle `json:"cycles"`
		AuditSHA256 string                `json:"audit_sha256"`
	} `json:"session_wire"`
	HTTPLifecycle struct {
		Probes                      []runtimeHTTPProbe `json:"probes"`
		LegacyRouteObservationCount int                `json:"legacy_route_observation_count"`
	} `json:"http_lifecycle"`
	RelayLifecycle struct {
		Probes          []runtimeRelayProbe `json:"probes"`
		RelayRouteCount int                 `json:"relay_route_count"`
	} `json:"relay_lifecycle"`
}

type runtimeRegistrationWireObservation struct {
	Events            []runtimeWireEvent `json:"events"`
	AgentIDSHA256     string             `json:"agent_id_sha256"`
	CorrelationSHA256 string             `json:"correlation_id_sha256"`
	AuditSHA256       string             `json:"audit_sha256"`
}

type runtimeSessionCycle struct {
	RunID  string             `json:"run_id"`
	Events []runtimeWireEvent `json:"events"`
}

type runtimeProbeArtifact struct {
	SchemaVersion                int                       `json:"schema_version"`
	Gate                         string                    `json:"gate"`
	Phase                        string                    `json:"phase"`
	ObservedAt                   string                    `json:"observed_at"`
	ProbeStartedAt               string                    `json:"probe_started_at"`
	ProbeEndedAt                 string                    `json:"probe_ended_at"`
	RetirementProbeTargetsSHA256 string                    `json:"retirement_probe_targets_sha256"`
	ClientBinding                runtimeProbeClientBinding `json:"client_binding"`
	Capture                      runtimeProbeCapture       `json:"capture"`
	Observations                 runtimeProbeObservations  `json:"observations"`
}

type runtimeProbeClientBinding struct {
	Repository            string `json:"repository"`
	WorkflowPath          string `json:"workflow_path"`
	HeadSHA               string `json:"head_sha"`
	RunID                 string `json:"run_id"`
	RunAttempt            string `json:"run_attempt"`
	ControllerRunID       string `json:"controller_run_id"`
	ControllerRunAttempt  string `json:"controller_run_attempt"`
	DispatchCorrelationID string `json:"dispatch_correlation_id"`
}

type runtimeProbeCapture struct {
	StartedAt     string `json:"started_at"`
	EndedAt       string `json:"ended_at"`
	RawSHA256     string `json:"raw_sha256"`
	TargetsSHA256 string `json:"targets_sha256"`
}

func runtimeEventsSHA256(t *testing.T, value any) string {
	t.Helper()
	raw := canonicalRuntimeJSON(t, value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func canonicalRuntimeJSON(t *testing.T, value any) []byte {
	t.Helper()
	structured, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(structured))
	decoder.UseNumber()
	var canonicalValue any
	if err := decoder.Decode(&canonicalValue); err != nil {
		t.Fatalf("canonicalize runtime JSON: %v", err)
	}
	raw, err := json.Marshal(canonicalValue)
	if err != nil {
		t.Fatalf("encode canonical runtime JSON: %v", err)
	}
	return raw
}

func assertRuntimeSequence(t *testing.T, events []runtimeWireEvent, want []string) {
	t.Helper()
	got := make([]string, len(events))
	for index := range events {
		got[index] = events[index].MessageType
	}
	if !slices.Equal(got, want) {
		t.Fatalf("runtime wire sequence = %v, want %v", got, want)
	}
}

func loadRetirementProbeTargets(t *testing.T) (retirementProbeTargets, string) {
	t.Helper()
	path := os.Getenv(retirementProbeTargetsEnv)
	if !filepath.IsAbs(path) {
		t.Fatalf("%s must be an absolute path", retirementProbeTargetsEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retirement probe targets: %v", err)
	}
	if len(raw) == 0 || len(raw) > 16*1024 {
		t.Fatalf("retirement probe target size %d is outside 1..16384 bytes", len(raw))
	}
	digest := sha256.Sum256(raw)
	rawSHA256 := hex.EncodeToString(digest[:])
	if rawSHA256 != os.Getenv("QURL_GO_SANDBOX_RETIREMENT_PROBE_TARGETS_SHA256") {
		t.Fatal("retirement probe target bytes do not match the workflow-authenticated digest")
	}
	targets, err := decodeStrictJSON[retirementProbeTargets](raw, "retirement probe targets")
	if err != nil {
		t.Fatalf("decode retirement probe targets: %v", err)
	}
	validateRetirementProbeTargets(t, targets)
	return targets, rawSHA256
}

func validateRetirementProbeTargets(t *testing.T, targets retirementProbeTargets) {
	t.Helper()
	producerRunID, err := strconv.ParseInt(os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ID"), 10, 64)
	if err != nil || producerRunID < 1 {
		t.Fatal("deployment producer run id is invalid")
	}
	producerRunAttempt, err := strconv.ParseInt(os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_RUN_ATTEMPT"), 10, 64)
	if err != nil || producerRunAttempt < 1 {
		t.Fatal("deployment producer run attempt is invalid")
	}
	if targets.SchemaVersion != 1 ||
		targets.Gate != runtimeProbeGate ||
		targets.Phase != os.Getenv("QURL_GO_SANDBOX_PROOF_PHASE") ||
		targets.Producer.HeadSHA != os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_PRODUCER_HEAD_SHA") ||
		targets.Producer.RunID != producerRunID ||
		targets.Producer.RunAttempt != producerRunAttempt ||
		targets.Producer.DeploymentProvenanceSHA256 != os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_PROVENANCE_SHA256") ||
		targets.Producer.SurfaceContractSHA256 != os.Getenv("QURL_GO_SANDBOX_RETIRED_LIFECYCLE_SURFACE_SHA256") ||
		!canonicalLowerHex(targets.Producer.HeadSHA, 40) ||
		!canonicalLowerHex(targets.Producer.DeploymentProvenanceSHA256, 64) ||
		!canonicalLowerHex(targets.Producer.SurfaceContractSHA256, 64) {
		t.Fatal("retirement probe targets are not bound to the authenticated deployment producer")
	}
	if _, err := parseAssignmentTimestamp(targets.ObservedAt); err != nil {
		t.Fatalf("retirement probe target observed_at: %v", err)
	}
	expectedHTTP := []struct {
		host, method, path string
	}{
		{"bootstrap.layerv.xyz", http.MethodPost, "/v1/agent/bootstrap"},
		{"api.layerv.xyz", http.MethodGet, "/v1/agent/registration-info"},
		{"api.layerv.xyz", http.MethodPost, "/v1/agent/registration/complete"},
		{"internal-api.qurl.layerv.xyz", http.MethodPost, "/internal/v1/agent/otp"},
		{"internal-api.qurl.layerv.xyz", http.MethodPost, "/internal/v1/agent/register"},
	}
	if len(targets.HTTPOperations) != len(expectedHTTP) {
		t.Fatalf("retirement target HTTP operation count = %d, want %d", len(targets.HTTPOperations), len(expectedHTTP))
	}
	for index, expected := range expectedHTTP {
		target := targets.HTTPOperations[index]
		if target.Host != expected.host || target.Method != expected.method || target.Path != expected.path {
			t.Fatalf("retirement HTTP target %d is not the canonical operation", index)
		}
		validateRetirementRoute53Binding(t, target.Route53, target.Host)
	}
	if targets.Relay.BaseURL != runtimeRelayBaseURL ||
		targets.Relay.SSM.Name != "/sandbox/nhp/qurl/relay-url" ||
		targets.Relay.SSM.Version < 1 ||
		targets.Relay.SSM.ValueSHA256 != runtimeStringSHA256(targets.Relay.BaseURL) ||
		len(targets.Relay.Aliases) != 2 {
		t.Fatal("retirement relay target is not the exact controller-owned surface")
	}
	validateRetirementRoute53Binding(t, targets.Relay.Route53, "relay.qurl.link.layerv.xyz")
	for index, cellID := range []string{"cell0", "cell1"} {
		alias := targets.Relay.Aliases[index]
		if alias.CellID != cellID || !relayServerIDRE.MatchString(alias.ServerID) {
			t.Fatalf("retirement relay alias %d is invalid", index)
		}
	}
	if targets.Relay.Aliases[0].ServerID == targets.Relay.Aliases[1].ServerID {
		t.Fatal("retirement relay aliases reuse a server id")
	}
}

func validateRetirementRoute53Binding(t *testing.T, binding retirementRoute53Binding, host string) {
	t.Helper()
	if !strings.HasPrefix(binding.ZoneID, "Z") ||
		strings.TrimSuffix(binding.RecordName, ".") != host ||
		strings.TrimSpace(binding.AliasDNSName) == "" {
		t.Fatalf("retirement target %s has an invalid Route53 binding", host)
	}
}

func newRetirementProbeHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func readRetirementProbeResponse(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, runtimeMaxHTTPResponseSize+1))
	if err != nil {
		t.Fatalf("read retirement probe response: %v", err)
	}
	if len(raw) > runtimeMaxHTTPResponseSize {
		t.Fatal("retirement probe response exceeded the 1 MiB bound")
	}
	return raw
}

func postRemovalHTTPProbes(ctx context.Context, t *testing.T, targets retirementProbeTargets, client *http.Client) []runtimeHTTPProbe {
	t.Helper()
	probes := make([]runtimeHTTPProbe, 0, len(targets.HTTPOperations))
	for _, target := range targets.HTTPOperations {
		correlationID := fmt.Sprintf(
			"%s:http:%s:%s",
			os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID"),
			target.Method,
			target.Path,
		)
		var body io.Reader = http.NoBody
		if target.Method == http.MethodPost {
			body = strings.NewReader(`{}`)
		}
		request, err := http.NewRequestWithContext(ctx, target.Method, "https://"+target.Host+target.Path, body)
		if err != nil {
			t.Fatalf("build retired HTTP operation probe: %v", err)
		}
		if target.Method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set("X-LayerV-UDP-Proof-Correlation", correlationID)
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("execute retired HTTP operation %s %s: %v", target.Method, target.Path, err)
		}
		responseBody := readRetirementProbeResponse(t, response)
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("retired HTTP operation %s %s returned %d, want 404", target.Method, target.Path, response.StatusCode)
		}
		digest := sha256.Sum256(responseBody)
		probes = append(probes, runtimeHTTPProbe{
			Method: target.Method, Path: target.Path, Host: target.Host, Status: response.StatusCode,
			CorrelationIDSHA256: runtimeStringSHA256(correlationID),
			ResponseSHA256:      hex.EncodeToString(digest[:]),
		})
	}
	return probes
}

func loadRuntimeCellPublicKeys(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("QURL_GO_SANDBOX_DEPLOYMENT_RUNTIME_INPUTS_PATH"))
	if err != nil {
		t.Fatalf("read runtime inputs for relay probes: %v", err)
	}
	var runtime struct {
		Cells []struct {
			CellID             string `json:"cell_id"`
			ServerPublicKeyB64 string `json:"server_public_key_b64"`
		} `json:"cells"`
	}
	if err := json.Unmarshal(raw, &runtime); err != nil {
		t.Fatalf("decode runtime inputs for relay probes: %v", err)
	}
	keys := make(map[string][]byte, len(runtime.Cells))
	for _, cell := range runtime.Cells {
		key, err := base64.StdEncoding.Strict().DecodeString(cell.ServerPublicKeyB64)
		if err != nil || len(key) != 32 {
			t.Fatalf("decode %s relay server key", cell.CellID)
		}
		keys[cell.CellID] = key
	}
	if len(keys) != 2 {
		t.Fatalf("runtime cell key count = %d, want 2", len(keys))
	}
	t.Cleanup(func() {
		for _, key := range keys {
			wipe(key)
		}
	})
	return keys
}

func buildRetirementRelayPacket(t *testing.T, serverKey []byte, messageType string, wireValue int) []byte {
	t.Helper()
	buildType := wireValue
	if messageType == "NHP_LRT" {
		buildType = relayknock.TypeListRequest
	}
	deviceKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate relay probe device key: %v", err)
	}
	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate relay probe ephemeral key: %v", err)
	}
	devicePrivate := deviceKey.Bytes()
	ephemeralPrivate := ephemeralKey.Bytes()
	defer wipe(devicePrivate)
	defer wipe(ephemeralPrivate)
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("generate relay probe transaction values: %v", err)
	}
	counter := binary.BigEndian.Uint64(random[:8])
	preamble := binary.BigEndian.Uint32(random[8:])
	packet, err := relayknock.BuildMessage(buildType, &relayknock.KnockInputs{
		DeviceStaticPriv: devicePrivate,
		ServerStaticPub:  serverKey,
		EphemeralPriv:    ephemeralPrivate,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         preamble,
		Body:             []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("build %s relay probe: %v", messageType, err)
	}
	if messageType == "NHP_LRT" {
		typeAndSize := preamble ^ binary.BigEndian.Uint32(packet[4:8])
		typeAndSize = uint32(relayknock.TypeListResult)<<16 | typeAndSize&0xffff
		binary.BigEndian.PutUint32(packet[4:8], preamble^typeAndSize)
	}
	return packet
}

func postRemovalRelayProbes(ctx context.Context, t *testing.T, targets retirementProbeTargets, client *http.Client) []runtimeRelayProbe {
	t.Helper()
	keys := loadRuntimeCellPublicKeys(t)
	messageTypes := []struct {
		name      string
		wireValue int
	}{
		{"NHP_LST", relayknock.TypeListRequest},
		{"NHP_LRT", relayknock.TypeListResult},
		{"NHP_OTP", relayknock.TypeOTP},
		{"NHP_REG", relayknock.TypeRegister},
	}
	probes := make([]runtimeRelayProbe, 0, len(targets.Relay.Aliases)*len(messageTypes))
	for _, alias := range targets.Relay.Aliases {
		serverKey := keys[alias.CellID]
		if len(serverKey) != 32 || relayknock.PubKeyFingerprint(serverKey) != alias.ServerID {
			t.Fatalf("relay alias %s is not bound to the deployed %s server key", alias.ServerID, alias.CellID)
		}
		for _, messageType := range messageTypes {
			correlationID := fmt.Sprintf(
				"%s:relay:%s:%s",
				os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID"),
				alias.CellID,
				messageType.name,
			)
			packet := buildRetirementRelayPacket(t, serverKey, messageType.name, messageType.wireValue)
			request, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				targets.Relay.BaseURL+"/relay/"+alias.ServerID,
				bytes.NewReader(packet),
			)
			if err != nil {
				t.Fatalf("build %s relay rejection probe: %v", messageType.name, err)
			}
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("X-LayerV-UDP-Proof-Correlation", correlationID)
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("execute %s relay rejection probe for %s: %v", messageType.name, alias.CellID, err)
			}
			responseBody := readRetirementProbeResponse(t, response)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s relay probe for %s returned %d, want 400", messageType.name, alias.CellID, response.StatusCode)
			}
			requestDigest := sha256.Sum256(packet)
			responseDigest := sha256.Sum256(responseBody)
			probes = append(probes, runtimeRelayProbe{
				CellID: alias.CellID, ServerID: alias.ServerID,
				MessageType: messageType.name, WireValue: messageType.wireValue,
				HTTPStatus: response.StatusCode, Outcome: "terminal_rejection",
				CorrelationIDSHA256: runtimeStringSHA256(correlationID),
				RequestSHA256:       hex.EncodeToString(requestDigest[:]), ResponseSHA256: hex.EncodeToString(responseDigest[:]),
			})
		}
	}
	return probes
}

func wrongCallerProbes(ctx context.Context, t *testing.T, cfg sandboxConfig, hub qurl.HubBootstrap, binding *qurl.AgentRuntimeBinding) []wrongCallerProbe {
	t.Helper()
	wrongPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong-caller identity: %v", err)
	}
	wrongPriv := wrongPrivate.Bytes()
	defer wipe(wrongPriv)
	peerDigest := sha256.Sum256(wrongPrivate.PublicKey().Bytes())

	recorder := newRuntimeWireRecorder(ctx, t)
	hubMark := recorder.mark()
	assignment, err := qurl.RefreshAgentAssignment(
		ctx,
		hub,
		cfg.agentID,
		nativeudp.Options{DeviceStaticPriv: wrongPriv, Dialer: recorder, Timeout: 5 * time.Second, MaxAddresses: 1},
		qurl.WithAssignmentRetryBudget(1, 10*time.Second),
	)
	if assignment != nil {
		t.Fatal("wrong authenticated Hub caller received an assignment")
	}
	var assignmentErr *qurl.AssignmentError
	if !errors.As(err, &assignmentErr) || assignmentErr.Code == "" || !protocolErrorCodeRE.MatchString(assignmentErr.Code) {
		t.Fatalf("wrong authenticated Hub caller did not receive a terminal protocol denial: %v", err)
	}
	hubEvents := recorder.since(hubMark)
	assertRuntimeSequence(t, hubEvents, []string{"LST", "COK", "LST", "LRT"})

	cellKey, err := base64.StdEncoding.Strict().DecodeString(binding.NHPUDPEndpoint.ServerPublicKeyB64)
	if err != nil || len(cellKey) != 32 {
		t.Fatal("decode assigned-cell key for wrong-caller proof")
	}
	defer wipe(cellKey)
	candidateRaw := make([]byte, 32)
	if _, err := rand.Read(candidateRaw); err != nil {
		t.Fatalf("generate wrong-caller completion candidate: %v", err)
	}
	candidate := "lv_live_" + base64.RawURLEncoding.EncodeToString(candidateRaw)
	wipe(candidateRaw)
	body, err := json.Marshal(map[string]any{
		"usrId": "", "devId": cfg.agentID, "aspId": "agent",
		"usrData": map[string]any{
			"query": "agent_registration_completion", "version": 1, "device_api_key": candidate,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(body)
	cellMark := recorder.mark()
	reply, err := nativeudp.List(ctx, nativeudp.Endpoint{
		Host: binding.NHPUDPEndpoint.Host, Port: binding.NHPUDPEndpoint.Port, ServerStaticPub: cellKey,
	}, body, nativeudp.Options{DeviceStaticPriv: wrongPriv, Dialer: recorder, Timeout: 5 * time.Second, MaxAddresses: 1})
	if err != nil || reply == nil || !reply.IsListResult() {
		t.Fatalf("wrong authenticated cell caller did not receive an authenticated LRT denial: reply=%v err=%v", reply, err)
	}
	defer wipe(reply.Body)
	var denial struct {
		ErrCode string `json:"errCode"`
	}
	if err := json.Unmarshal(reply.Body, &denial); err != nil || !protocolErrorCodeRE.MatchString(denial.ErrCode) {
		t.Fatal("wrong authenticated cell caller returned a malformed/nonterminal denial")
	}
	cellEvents := recorder.since(cellMark)
	assertRuntimeSequence(t, cellEvents, []string{"LST", "LRT"})

	return []wrongCallerProbe{
		{
			TargetRole: "hub", Operation: "registered_assignment_refresh", RequestType: "LST", ResponseType: "LRT",
			ErrorCode: assignmentErr.Code, PeerPublicKeySHA: hex.EncodeToString(peerDigest[:]),
			RequestPacketSHA: hubEvents[2].PacketSHA, ResponsePacketSHA: hubEvents[3].PacketSHA, Outcome: "terminal_denial",
		},
		{
			TargetRole: "cell", CellID: binding.CellID, Operation: "registration_completion", RequestType: "LST", ResponseType: "LRT",
			ErrorCode: denial.ErrCode, PeerPublicKeySHA: hex.EncodeToString(peerDigest[:]),
			RequestPacketSHA: cellEvents[0].PacketSHA, ResponsePacketSHA: cellEvents[1].PacketSHA, Outcome: "terminal_denial",
		},
	}
}

func wrongSourceProbes(ctx context.Context, t *testing.T, cfg sandboxConfig, hub qurl.HubBootstrap, binding *qurl.AgentRuntimeBinding, privateKey []byte) []wrongSourceInjection {
	t.Helper()
	hubDialer := &wrongSourceDialer{targetRole: "hub"}
	assignment, err := qurl.RefreshAgentAssignment(
		ctx,
		hub,
		cfg.agentID,
		nativeudp.Options{DeviceStaticPriv: privateKey, Dialer: hubDialer, Timeout: 2 * time.Second, MaxAddresses: 1},
		qurl.WithAssignmentRetryBudget(1, 4*time.Second),
	)
	if assignment != nil || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("wrong-source Hub response was not rejected by the connected UDP socket: assignment=%v err=%v", assignment, err)
	}
	hubInjection := hubDialer.result(t)

	cellDialer := &wrongSourceDialer{
		targetRole: "cell",
		cellID:     binding.CellID,
		forbiddenInjectedSources: map[string]struct{}{
			hubInjection.InjectedSource: {},
		},
	}
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		t.Fatal(err)
	}
	result, err := qurl.KnockRegisteredAgent(
		ctx, binding, privateKey, cfg.knockResourceID, qurl.NativeKnockOptions{RunID: runID},
		qurl.WithAgentRuntimeUDPDialer(cellDialer),
		qurl.WithAgentRuntimeUDPBounds(2*time.Second, 1),
	)
	if result != nil || !errors.Is(err, nativeudp.ErrTransport) {
		t.Fatalf("wrong-source cell response was not rejected by the connected UDP socket: result=%v err=%v", result, err)
	}
	return []wrongSourceInjection{hubInjection, cellDialer.result(t)}
}

func publishRuntimeProbeArtifact(
	t *testing.T,
	cfg sandboxConfig,
	capture transportCaptureObservation,
	receipt transportCounterReceipt,
	targetsSHA256 string,
	probeStartedAt time.Time,
	probeEndedAt time.Time,
	observations runtimeProbeObservations,
) {
	t.Helper()
	path := os.Getenv(runtimeProbePathEnv)
	if !filepath.IsAbs(path) {
		t.Fatalf("%s must be an absolute path", runtimeProbePathEnv)
	}
	if receipt.CaptureSHA256 != capture.RawSHA256 ||
		receipt.CaptureTargetsSHA256 != capture.TargetsSHA256 ||
		receipt.CaptureStartedAt != capture.CaptureStarted ||
		receipt.CaptureEndedAt != capture.CaptureEnded {
		t.Fatal("runtime probe capture does not equal the authenticated transport receipt")
	}
	observations.RegistrationWire.AgentIDSHA256 = runtimeStringSHA256(cfg.agentID)
	observations.RegistrationWire.CorrelationSHA256 = runtimeStringSHA256(os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID"))
	observations.RegistrationWire.AuditSHA256 = runtimeEventsSHA256(t, observations.RegistrationWire.Events)
	observations.SessionWire.AuditSHA256 = runtimeEventsSHA256(t, observations.SessionWire.Cycles)
	observations.RelayLifecycle.RelayRouteCount = receipt.RelayRouteCount
	observations.HTTPLifecycle.LegacyRouteObservationCount = receipt.QURLServiceLegacyRouteCount

	artifact := runtimeProbeArtifact{
		SchemaVersion: 1, Gate: runtimeProbeGate, Phase: os.Getenv("QURL_GO_SANDBOX_PROOF_PHASE"),
		ObservedAt:                   probeEndedAt.Format(runtimeProbeTimeLayout),
		ProbeStartedAt:               probeStartedAt.Format(runtimeProbeTimeLayout),
		ProbeEndedAt:                 probeEndedAt.Format(runtimeProbeTimeLayout),
		RetirementProbeTargetsSHA256: targetsSHA256,
		ClientBinding: runtimeProbeClientBinding{
			Repository: "layervai/qurl-go", WorkflowPath: ".github/workflows/native-udp-sandbox.yml",
			HeadSHA: cfg.buildSHA, RunID: cfg.clientRunID, RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"),
			ControllerRunID: cfg.controllerRunID, ControllerRunAttempt: cfg.controllerRunAttempt,
			DispatchCorrelationID: os.Getenv("QURL_GO_SANDBOX_DISPATCH_CORRELATION_ID"),
		},
		Capture: runtimeProbeCapture{
			StartedAt: capture.CaptureStarted, EndedAt: capture.CaptureEnded,
			RawSHA256: capture.RawSHA256, TargetsSHA256: capture.TargetsSHA256,
		},
		Observations: observations,
	}
	validateRuntimeProbeArtifact(t, artifact)
	raw := canonicalRuntimeJSON(t, artifact)
	if err := writeExclusivePrivateFile(path, raw); err != nil {
		t.Fatalf("publish runtime probe artifact: %v", err)
	}
}

func validateRuntimeProbeArtifact(t *testing.T, artifact runtimeProbeArtifact) {
	t.Helper()
	if artifact.SchemaVersion != 1 ||
		artifact.Gate != runtimeProbeGate ||
		(artifact.Phase != "pre_removal" && artifact.Phase != "post_removal") ||
		artifact.ClientBinding.Repository != "layervai/qurl-go" ||
		artifact.ClientBinding.WorkflowPath != ".github/workflows/native-udp-sandbox.yml" ||
		!canonicalLowerHex(artifact.ClientBinding.HeadSHA, 40) ||
		!assignmentRunRE.MatchString(artifact.ClientBinding.RunID) ||
		!assignmentRunRE.MatchString(artifact.ClientBinding.RunAttempt) ||
		!assignmentRunRE.MatchString(artifact.ClientBinding.ControllerRunID) ||
		!assignmentRunRE.MatchString(artifact.ClientBinding.ControllerRunAttempt) ||
		artifact.ClientBinding.DispatchCorrelationID == "" ||
		!canonicalLowerHex(artifact.RetirementProbeTargetsSHA256, 64) ||
		!canonicalLowerHex(artifact.Capture.RawSHA256, 64) ||
		!canonicalLowerHex(artifact.Capture.TargetsSHA256, 64) {
		t.Fatal("runtime probe artifact header/binding is incomplete")
	}
	observedAt, err := parseRuntimeProbeTimestamp(artifact.ObservedAt)
	if err != nil {
		t.Fatalf("runtime probe observed_at: %v", err)
	}
	if _, err := parseAssignmentTimestamp(artifact.Capture.StartedAt); err != nil {
		t.Fatalf("runtime probe capture started_at: %v", err)
	}
	captureEndedAt, err := parseAssignmentTimestamp(artifact.Capture.EndedAt)
	if err != nil {
		t.Fatalf("runtime probe capture ended_at: %v", err)
	}
	probeStartedAt, err := parseRuntimeProbeTimestamp(artifact.ProbeStartedAt)
	if err != nil {
		t.Fatalf("runtime probe probe_started_at: %v", err)
	}
	probeEndedAt, err := parseRuntimeProbeTimestamp(artifact.ProbeEndedAt)
	if err != nil {
		t.Fatalf("runtime probe probe_ended_at: %v", err)
	}
	if probeStartedAt.Before(captureEndedAt) ||
		probeEndedAt.Before(probeStartedAt) ||
		probeEndedAt.Sub(probeStartedAt) > 15*time.Minute ||
		observedAt.Before(probeEndedAt) {
		t.Fatal("runtime active-probe window is invalid or overlaps the zero-use transport capture")
	}
	if len(artifact.Observations.WrongCaller.Probes) != 2 ||
		len(artifact.Observations.WrongSource.Injections) != 2 ||
		artifact.Observations.WrongSource.AcceptedPackets != 0 ||
		len(artifact.Observations.RegistrationWire.Events) != 8 ||
		len(artifact.Observations.SessionWire.Cycles) != 2 ||
		artifact.Observations.SessionWire.Cycles[0].RunID ==
			artifact.Observations.SessionWire.Cycles[1].RunID {
		t.Fatal("runtime probe artifact is missing a required live observation")
	}
	validateRuntimeRegistrationWire(t, artifact.Observations.RegistrationWire)
	for _, cycle := range artifact.Observations.SessionWire.Cycles {
		validateRuntimeSessionCycle(t, cycle)
	}
	validateWrongCallerObservations(t, artifact.Observations.WrongCaller.Probes)
	validateWrongSourceObservations(t, artifact.Observations.WrongSource.Injections)
	if artifact.Phase == "pre_removal" {
		if len(artifact.Observations.HTTPLifecycle.Probes) != 0 ||
			len(artifact.Observations.RelayLifecycle.Probes) != 0 {
			t.Fatal("pre-removal runtime artifact must carry only zero-use HTTP/relay observations")
		}
	} else {
		validatePostRemovalHTTPObservations(
			t,
			artifact.ClientBinding.DispatchCorrelationID,
			artifact.Observations.HTTPLifecycle.Probes,
		)
		validatePostRemovalRelayObservations(
			t,
			artifact.ClientBinding.DispatchCorrelationID,
			artifact.Observations.RelayLifecycle.Probes,
		)
	}
	if artifact.Observations.HTTPLifecycle.LegacyRouteObservationCount != 0 ||
		artifact.Observations.RelayLifecycle.RelayRouteCount != 0 {
		t.Fatal("runtime transport receipt observed a legacy HTTP or relay route")
	}
}

func parseRuntimeProbeTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(runtimeProbeTimeLayout, value)
	if err != nil ||
		!strings.HasSuffix(value, "Z") ||
		parsed.Format(runtimeProbeTimeLayout) != value {
		return time.Time{}, errors.New("must be canonical fixed-nanosecond UTC")
	}
	return parsed, nil
}

func validateRuntimeRegistrationWire(t *testing.T, observation runtimeRegistrationWireObservation) {
	t.Helper()
	wantTypes := []string{"LST", "COK", "LST", "LRT", "REG", "RAK", "LST", "LRT"}
	wantDirections := []string{"request", "response", "request", "response", "request", "response", "request", "response"}
	assertRuntimeSequence(t, observation.Events, wantTypes)
	if !canonicalLowerHex(observation.AgentIDSHA256, 64) ||
		!canonicalLowerHex(observation.CorrelationSHA256, 64) ||
		!canonicalLowerHex(observation.AuditSHA256, 64) {
		t.Fatal("registration wire identity/audit hash is not canonical")
	}
	cellID := observation.Events[4].CellID
	if cellID == "" {
		t.Fatal("registration wire cell id is empty")
	}
	for index, event := range observation.Events {
		targetRole := "hub"
		expectedCellID := ""
		if index >= 4 {
			targetRole = "cell"
			expectedCellID = cellID
		}
		if event.Ordinal != index+1 ||
			event.Direction != wantDirections[index] ||
			event.TargetRole != targetRole ||
			event.CellID != expectedCellID ||
			!canonicalLowerHex(event.PacketSHA, 64) ||
			event.RunID != nil {
			t.Fatalf("registration wire event %d is not exact", index)
		}
	}
}

func validateRuntimeSessionCycle(t *testing.T, cycle runtimeSessionCycle) {
	t.Helper()
	if err := qurl.ValidateCycleRunID(cycle.RunID); err != nil {
		t.Fatalf("session cycle RunID: %v", err)
	}
	wantTypes := []string{"KNK", "COK", "RKN", "ACK", "EXT", "ACK"}
	wantDirections := []string{"request", "response", "request", "response", "request", "response"}
	assertRuntimeSequence(t, cycle.Events, wantTypes)
	cellID := cycle.Events[0].CellID
	if cellID == "" {
		t.Fatal("session cycle cell id is empty")
	}
	for index, event := range cycle.Events {
		if event.Ordinal != index+1 ||
			event.Direction != wantDirections[index] ||
			event.TargetRole != "cell" ||
			event.CellID != cellID ||
			!canonicalLowerHex(event.PacketSHA, 64) {
			t.Fatalf("session wire event %d is not exact", index)
		}
		if event.MessageType == "COK" {
			if event.RunID != nil {
				t.Fatal("COK incorrectly claims a RunID carried on the wire")
			}
		} else if event.RunID == nil || *event.RunID != cycle.RunID {
			t.Fatal("session wire event lost its caller-owned RunID")
		}
	}
}

func validateWrongCallerObservations(t *testing.T, probes []wrongCallerProbe) {
	t.Helper()
	want := []struct {
		role, operation string
	}{
		{"hub", "registered_assignment_refresh"},
		{"cell", "registration_completion"},
	}
	peerHash := probes[0].PeerPublicKeySHA
	for index, probe := range probes {
		if probe.TargetRole != want[index].role ||
			probe.Operation != want[index].operation ||
			probe.RequestType != "LST" ||
			probe.ResponseType != "LRT" ||
			!protocolErrorCodeRE.MatchString(probe.ErrorCode) ||
			!canonicalLowerHex(probe.PeerPublicKeySHA, 64) ||
			probe.PeerPublicKeySHA != peerHash ||
			!canonicalLowerHex(probe.RequestPacketSHA, 64) ||
			!canonicalLowerHex(probe.ResponsePacketSHA, 64) ||
			probe.Outcome != "terminal_denial" {
			t.Fatalf("wrong-caller observation %d is not an authenticated terminal denial", index)
		}
		if (probe.TargetRole == "hub" && probe.CellID != "") ||
			(probe.TargetRole == "cell" && probe.CellID == "") {
			t.Fatalf("wrong-caller observation %d has invalid target identity", index)
		}
	}
}

func validateWrongSourceObservations(t *testing.T, injections []wrongSourceInjection) {
	t.Helper()
	want := []struct {
		role, requestType string
	}{
		{"hub", "LST"},
		{"cell", "KNK"},
	}
	for index, injection := range injections {
		if injection.TargetRole != want[index].role ||
			injection.RequestType != want[index].requestType ||
			injection.ResponseType != "COK" ||
			injection.ExpectedSource == injection.InjectedSource ||
			!canonicalLowerHex(injection.RequestPacketSHA, 64) ||
			!canonicalLowerHex(injection.InjectedPacketSHA, 64) ||
			injection.ErrorClass != "nativeudp.ErrTransport" ||
			injection.Outcome != "rejected" {
			t.Fatalf("wrong-source injection %d is not an exact connected-UDP rejection", index)
		}
		if _, _, err := net.SplitHostPort(injection.ExpectedSource); err != nil {
			t.Fatalf("wrong-source expected address %d: %v", index, err)
		}
		if _, _, err := net.SplitHostPort(injection.InjectedSource); err != nil {
			t.Fatalf("wrong-source injected address %d: %v", index, err)
		}
		if (injection.TargetRole == "hub" && injection.CellID != "") ||
			(injection.TargetRole == "cell" && injection.CellID == "") {
			t.Fatalf("wrong-source injection %d has invalid target identity", index)
		}
	}
	if injections[0].InjectedSource == injections[1].InjectedSource {
		t.Fatal("wrong-source probes reused the injected UDP source")
	}
}

func validatePostRemovalHTTPObservations(t *testing.T, dispatchCorrelationID string, probes []runtimeHTTPProbe) {
	t.Helper()
	want := []struct {
		host, method, path string
	}{
		{"bootstrap.layerv.xyz", http.MethodPost, "/v1/agent/bootstrap"},
		{"api.layerv.xyz", http.MethodGet, "/v1/agent/registration-info"},
		{"api.layerv.xyz", http.MethodPost, "/v1/agent/registration/complete"},
		{"internal-api.qurl.layerv.xyz", http.MethodPost, "/internal/v1/agent/otp"},
		{"internal-api.qurl.layerv.xyz", http.MethodPost, "/internal/v1/agent/register"},
	}
	if len(probes) != len(want) {
		t.Fatalf("post-removal HTTP probe count = %d, want %d", len(probes), len(want))
	}
	for index, probe := range probes {
		if probe.Host != want[index].host ||
			probe.Method != want[index].method ||
			probe.Path != want[index].path ||
			probe.Status != http.StatusNotFound ||
			probe.CorrelationIDSHA256 != runtimeStringSHA256(
				fmt.Sprintf(
					"%s:http:%s:%s",
					dispatchCorrelationID,
					want[index].method,
					want[index].path,
				),
			) ||
			!canonicalLowerHex(probe.ResponseSHA256, 64) {
			t.Fatalf("post-removal HTTP probe %d is not the exact terminal 404", index)
		}
	}
}

func validatePostRemovalRelayObservations(t *testing.T, dispatchCorrelationID string, probes []runtimeRelayProbe) {
	t.Helper()
	wantTypes := []struct {
		name      string
		wireValue int
	}{
		{"NHP_LST", relayknock.TypeListRequest},
		{"NHP_LRT", relayknock.TypeListResult},
		{"NHP_OTP", relayknock.TypeOTP},
		{"NHP_REG", relayknock.TypeRegister},
	}
	if len(probes) != 8 {
		t.Fatalf("post-removal relay probe count = %d, want 8", len(probes))
	}
	serverIDs := make(map[string]string, 2)
	for cellIndex, cellID := range []string{"cell0", "cell1"} {
		for typeIndex, messageType := range wantTypes {
			probe := probes[cellIndex*len(wantTypes)+typeIndex]
			if probe.CellID != cellID ||
				!relayServerIDRE.MatchString(probe.ServerID) ||
				probe.MessageType != messageType.name ||
				probe.WireValue != messageType.wireValue ||
				probe.HTTPStatus != http.StatusBadRequest ||
				probe.Outcome != "terminal_rejection" ||
				probe.CorrelationIDSHA256 != runtimeStringSHA256(
					fmt.Sprintf("%s:relay:%s:%s", dispatchCorrelationID, cellID, messageType.name),
				) ||
				!canonicalLowerHex(probe.RequestSHA256, 64) ||
				!canonicalLowerHex(probe.ResponseSHA256, 64) {
				t.Fatalf("post-removal relay probe %d is not the exact terminal rejection", cellIndex*len(wantTypes)+typeIndex)
			}
			if existing := serverIDs[cellID]; existing != "" && existing != probe.ServerID {
				t.Fatalf("relay probes for %s changed server id", cellID)
			}
			serverIDs[cellID] = probe.ServerID
		}
	}
	if serverIDs["cell0"] == serverIDs["cell1"] {
		t.Fatal("post-removal relay probes reused a server id across cells")
	}
}

func runtimeStringSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestRuntimePacketType(t *testing.T) {
	for wireType, want := range map[int]string{
		relayknock.TypeKnock: "KNK", relayknock.TypeACK: "ACK",
		relayknock.TypeListRequest: "LST", relayknock.TypeListResult: "LRT",
		relayknock.TypeCookieChallenge: "COK", relayknock.TypeReknock: "RKN",
		relayknock.TypeOTP: "OTP", relayknock.TypeRegister: "REG",
		relayknock.TypeRegisterAck: "RAK", relayknock.TypeExit: "EXT",
	} {
		packet := make([]byte, 24)
		binary.BigEndian.PutUint32(packet[0:4], 0x10203040)
		binary.BigEndian.PutUint32(packet[4:8], 0x10203040^uint32(wireType<<16))
		got, err := runtimePacketType(packet)
		if err != nil || got != want {
			t.Fatalf("runtimePacketType(%d) = %q, %v; want %q", wireType, got, err, want)
		}
	}
}

func TestRuntimeProbeArtifactCanonicalJSON(t *testing.T) {
	value := runtimeProbeArtifact{
		SchemaVersion: 1, Gate: runtimeProbeGate, Phase: "pre_removal",
		ObservedAt: "2026-07-29T00:00:00Z",
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var roundTrip runtimeProbeArtifact
	if err := decoder.Decode(&roundTrip); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(roundTrip)
	if err != nil || !bytes.Equal(raw, reencoded) {
		t.Fatal("runtime probe artifact is not canonical under its strict shape")
	}
}
