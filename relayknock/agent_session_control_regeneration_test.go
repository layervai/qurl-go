package relayknock_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

const (
	regenerateAgentSessionVectorsEnv = "QURL_REGENERATE_AGENT_SESSION_VECTORS"
	agentSessionProducerRevisionEnv  = "QURL_AGENT_SESSION_PRODUCER_REVISION"
	legacyCurveHeaderSize            = 240
	legacyCurveHeaderDigestOffset    = 208
)

// TestRegenerateAgentSessionControlVectors is an opt-in maintainer tool for
// the current NHP 1.1 envelope. It deliberately regenerates only the exact
// session exit request/ACK and denial ACK packets: the overload
// KNK/COK/RKN/ACK vectors remain immutable.
// The producer revision is required explicitly so a generated artifact cannot
// silently claim provenance from a dirty or different checkout.
func TestRegenerateAgentSessionControlVectors(t *testing.T) {
	conformanceRoot := os.Getenv(regenerateAgentSessionVectorsEnv)
	if conformanceRoot == "" {
		t.Skipf("set %s to a qurl-conformance checkout", regenerateAgentSessionVectorsEnv)
	}
	producerRevision := os.Getenv(agentSessionProducerRevisionEnv)
	if len(producerRevision) != 40 {
		t.Fatalf("%s must be the exact 40-character producer commit", agentSessionProducerRevisionEnv)
	}

	path := filepath.Join(conformanceRoot, "vectors", "agent_session_control_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	keys := requiredVectorObject(t, root, "keys")
	agent := requiredVectorObject(t, keys, "agent")
	cell := requiredVectorObject(t, keys, "assigned_cell")
	exactExit := requiredVectorObject(t, root, "exact_session_exit")
	requestTemplate := requiredVectorObject(t, exactExit, "request")
	ackTemplate := requiredVectorObject(t, exactExit, "ack")
	denialACKs := requiredVectorObject(t, root, "denial_acks")
	knockDenialTemplate := requiredVectorObject(t, denialACKs, "knock")
	exitDenialTemplate := requiredVectorObject(t, denialACKs, "exit")

	exitBodyJSON := requiredVectorString(t, requestTemplate, "body_json")
	exitBody := []byte(exitBodyJSON)
	request := vectorPacketInputs(t, requestTemplate, agent, cell, exitBody)
	requestPacket, err := relayknock.BuildMessage(relayknock.TypeExit, request)
	if err != nil {
		t.Fatalf("build exact-session EXT: %v", err)
	}

	ackBodyJSON := requiredVectorString(t, ackTemplate, "body_json")
	ackInputs := vectorPacketInputs(t, ackTemplate, cell, agent, []byte(ackBodyJSON))
	ackPacket, err := relayknocktest.BuildReply(relayknock.TypeACK, ackInputs)
	if err != nil {
		t.Fatalf("build exact-session EXT ACK: %v", err)
	}
	knockDenialBodyJSON := requiredVectorString(t, knockDenialTemplate, "body_json")
	knockDenialInputs := vectorPacketInputs(t, knockDenialTemplate, cell, agent, []byte(knockDenialBodyJSON))
	knockDenialPacket, err := relayknocktest.BuildReply(relayknock.TypeACK, knockDenialInputs)
	if err != nil {
		t.Fatalf("build knock denial ACK: %v", err)
	}
	exitDenialBodyJSON := requiredVectorString(t, exitDenialTemplate, "body_json")
	exitDenialInputs := vectorPacketInputs(t, exitDenialTemplate, cell, agent, []byte(exitDenialBodyJSON))
	exitDenialPacket, err := relayknocktest.BuildReply(relayknock.TypeACK, exitDenialInputs)
	if err != nil {
		t.Fatalf("build exit denial ACK: %v", err)
	}
	validateExactSessionVectorBodies(t, exitBodyJSON, ackBodyJSON, knockDenialBodyJSON, exitDenialBodyJSON)

	root["schema_version"] = float64(4)
	root["producer_revision"] = producerRevision
	root["description"] = "Deterministic NHP 1.1 overload re-knock and strict exact-session retirement request/ACK vectors"
	root["notes"] = []string{
		"Every packet was sealed by the exact producer revision with fixed synthetic key, ephemeral, timestamp, counter, preamble, body, and cookie inputs; independent consumers must rebuild initiator packets and authenticate-open replies.",
		"The producer intentionally echoes the NHP_KNK counter in NHP_COK for relay compatibility, as frozen here, but native UDP consumers must treat the authenticated COK wire counter as unconstrained and correlate only when decrypted trxId equals the originating NHP_KNK counter. Every NHP_ACK counter must echo its request.",
		"KNK and RKN carry the same canonical RunID and positive uint64 runAttempt. A successful knock ACK returns the immutable exact receipt cellId, sessId, sessIssuedAtMillis, runId, and runAttempt.",
		"NHP_RKN mixes the exact decoded 32-byte cookie into the ordinary NHP 1.1 header digest. NHP_EXT uses the ordinary no-cookie digest and carries the exact immutable receipt, never resource-scoped or bodyless exit authority.",
		"A successful exact-retirement ACK repeats the exact receipt and adds a canonical 32-lowercase-hex closeEventId plus state closing or closed. Authenticated denials omit every session receipt and close-event field.",
		"The producer revision is the signed qurl-go main commit whose deterministic regeneration gate reproduces every committed body and packet byte.",
		"All identities, hosts, keys, cookies, counters, tokens, receipts, and event IDs are synthetic conformance data.",
	}
	protocol := requiredVectorObject(t, root, "protocol")
	protocol["knock_run_attempt"] = "positive_uint64_bound_across_knk_rkn"
	protocol["success_ack_receipt"] = "exact_cell_session_issuance_run_attempt"
	protocol["exit_body"] = "exact_session_receipt"
	protocol["exit_response"] = "strict_close_ack"
	protocol["denial_receipt_fields"] = "must_be_omitted"
	protocol["exit_cookie_challenge_allowed"] = false
	exactExit["request"] = vectorPacketRecord(requestTemplate, exitBodyJSON, requestPacket)
	exactExit["ack"] = vectorPacketRecord(ackTemplate, ackBodyJSON, ackPacket)
	denialACKs["knock"] = vectorPacketRecord(knockDenialTemplate, knockDenialBodyJSON, knockDenialPacket)
	denialACKs["exit"] = vectorPacketRecord(exitDenialTemplate, exitDenialBodyJSON, exitDenialPacket)
	delete(root, "clean_exit")

	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updated = append(updated, '\n')
	for _, destination := range []string{
		path,
		filepath.Join(conformanceRoot, "npm", "vectors", "agent_session_control_vectors.json"),
		filepath.Join(conformanceRoot, "python", "qurl_conformance", "_data", "agent_session_control_vectors.json"),
	} {
		if err := os.WriteFile(destination, updated, 0o644); err != nil {
			t.Fatalf("write %s: %v", destination, err)
		}
	}
}

func vectorPacketInputs(t *testing.T, template, sender, receiver map[string]any, body []byte) *relayknock.KnockInputs {
	t.Helper()
	timestamp, err := strconv.ParseUint(requiredVectorString(t, template, "timestamp_nanos"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := strconv.ParseUint(requiredVectorString(t, template, "counter"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	preamble, err := strconv.ParseUint(requiredVectorString(t, template, "preamble_hex"), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &relayknock.KnockInputs{
		DeviceStaticPriv: mustVectorHex(t, requiredVectorString(t, sender, "static_private_hex")),
		ServerStaticPub:  mustVectorHex(t, requiredVectorString(t, receiver, "static_public_hex")),
		EphemeralPriv:    mustVectorHex(t, requiredVectorString(t, template, "ephemeral_private_hex")),
		TimestampNanos:   timestamp, Counter: counter, Preamble: uint32(preamble), Body: body,
	}
}

func vectorPacketRecord(template map[string]any, bodyJSON string, packet []byte) map[string]any {
	record := make(map[string]any, len(template)+2)
	for key, value := range template {
		record[key] = value
	}
	record["body_json"] = bodyJSON
	record["body_hex"] = hex.EncodeToString([]byte(bodyJSON))
	record["packet_hex"] = hex.EncodeToString(packet)
	if len(packet) >= legacyCurveHeaderSize {
		record["header_digest_hex"] = hex.EncodeToString(packet[legacyCurveHeaderDigestOffset:legacyCurveHeaderSize])
	}
	return record
}

type vectorSessionReceipt struct {
	CellID                string `json:"cellId"`
	SessionID             uint64 `json:"sessId"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis"`
	RunID                 string `json:"runId"`
	RunAttempt            uint64 `json:"runAttempt"`
}

type vectorExactSessionCloseRequest struct {
	HeaderType    int    `json:"headerType"`
	AuthServiceID string `json:"aspId"`
	vectorSessionReceipt
}

type vectorExactSessionCloseACK struct {
	ErrCode string `json:"errCode"`
	vectorSessionReceipt
	CloseEventID string `json:"closeEventId"`
	State        string `json:"state"`
}

type vectorKnockDenialACK struct {
	ErrCode  string `json:"errCode"`
	ErrMsg   string `json:"errMsg"`
	OpenTime uint32 `json:"opnTime"`
}

type vectorExitDenialACK struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
}

func validateExactSessionVectorBodies(t *testing.T, requestBody, ackBody, knockDenialBody, exitDenialBody string) {
	t.Helper()

	var request vectorExactSessionCloseRequest
	requireCanonicalVectorBody(t, "exact-session EXT", requestBody, &request)
	if request.HeaderType != relayknock.TypeExit || request.AuthServiceID != "agent" || !validVectorReceipt(request.vectorSessionReceipt) {
		t.Fatalf("exact-session EXT authority drifted: %#v", request)
	}

	var ack vectorExactSessionCloseACK
	requireCanonicalVectorBody(t, "exact-session ACK", ackBody, &ack)
	if ack.ErrCode != "0" || ack.vectorSessionReceipt != request.vectorSessionReceipt ||
		!isLowerHex(ack.CloseEventID, 32) || (ack.State != "closing" && ack.State != "closed") {
		t.Fatalf("exact-session ACK authority drifted: %#v", ack)
	}

	var knockDenial vectorKnockDenialACK
	requireCanonicalVectorBody(t, "knock denial ACK", knockDenialBody, &knockDenial)
	if knockDenial.ErrCode == "" || knockDenial.ErrCode == "0" || strings.TrimSpace(knockDenial.ErrMsg) == "" || knockDenial.OpenTime != 0 {
		t.Fatalf("knock denial ACK authority drifted: %#v", knockDenial)
	}

	var exitDenial vectorExitDenialACK
	requireCanonicalVectorBody(t, "exit denial ACK", exitDenialBody, &exitDenial)
	if exitDenial.ErrCode == "" || exitDenial.ErrCode == "0" || strings.TrimSpace(exitDenial.ErrMsg) == "" {
		t.Fatalf("exit denial ACK authority drifted: %#v", exitDenial)
	}
}

func requireCanonicalVectorBody(t *testing.T, name, raw string, destination any) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s body: %v", name, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("decode %s body: trailing JSON or read failure: %v", name, err)
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		t.Fatalf("marshal %s body: %v", name, err)
	}
	if !bytes.Equal(canonical, []byte(raw)) {
		t.Fatalf("%s body is not canonical:\n got=%s\nwant=%s", name, raw, canonical)
	}
}

func validVectorReceipt(receipt vectorSessionReceipt) bool {
	return receipt.CellID != "" && receipt.CellID == strings.TrimSpace(receipt.CellID) &&
		receipt.SessionID != 0 && receipt.SessionIssuedAtMillis > 0 &&
		isLowerHex(receipt.RunID, 16) && receipt.RunAttempt != 0
}

func isLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func requiredVectorObject(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("vector field %s is not an object", key)
	}
	return value
}

func requiredVectorString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok || value == "" {
		t.Fatalf("vector field %s is not a nonempty string", key)
	}
	return value
}

func mustVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
