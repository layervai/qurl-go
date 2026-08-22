package relayknock_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
// the current NHP 1.1 envelope. It deliberately regenerates only the clean-exit
// request/ACK pair: the overload KNK/COK/RKN/ACK vectors remain immutable.
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
	cleanExit := requiredVectorObject(t, root, "clean_exit")
	requestTemplate := requiredVectorObject(t, cleanExit, "request")
	overload := requiredVectorObject(t, root, "overload_reknock")
	ackTemplate := requiredVectorObject(t, overload, "ack")

	const exitBodyJSON = `{"headerType":16,"usrId":"agent-conformance-01","devId":"agent-conformance-01","aspId":"agent","resId":"connector-conformance-01","runId":"0123456789abcdef"}`
	exitBody := []byte(exitBodyJSON)
	request := vectorPacketInputs(t, requestTemplate, agent, cell, exitBody)
	requestPacket, err := relayknock.BuildMessage(relayknock.TypeExit, request)
	if err != nil {
		t.Fatalf("build resource-scoped EXT: %v", err)
	}

	ackBodyJSON := requiredVectorString(t, ackTemplate, "body_json")
	ackInputs := &relayknock.KnockInputs{
		DeviceStaticPriv: mustVectorHex(t, requiredVectorString(t, cell, "static_private_hex")),
		ServerStaticPub:  mustVectorHex(t, requiredVectorString(t, agent, "static_public_hex")),
		EphemeralPriv:    mustVectorHex(t, "d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0"),
		TimestampNanos:   1800000000000000006,
		Counter:          request.Counter,
		Preamble:         0x66666666,
		Body:             []byte(ackBodyJSON),
	}
	ackPacket, err := relayknocktest.BuildReply(relayknock.TypeACK, ackInputs)
	if err != nil {
		t.Fatalf("build resource-scoped EXT ACK: %v", err)
	}

	root["schema_version"] = float64(3)
	root["producer_revision"] = producerRevision
	root["description"] = "Deterministic NHP 1.1 overload re-knock and resource-scoped clean-exit request/ACK vectors"
	protocol := requiredVectorObject(t, root, "protocol")
	protocol["exit_body"] = "protected_resource_session_identity"
	protocol["exit_response"] = "counter_echoing_ack"
	cleanExit["request"] = vectorPacketRecord(requestTemplate, exitBodyJSON, requestPacket)
	cleanExit["ack"] = vectorPacketRecord(map[string]any{
		"header_name": "NHP_ACK", "header_type": float64(relayknock.TypeACK),
		"sender_key": "assigned_cell", "receiver_key": "agent",
		"ephemeral_private_hex": hex.EncodeToString(ackInputs.EphemeralPriv),
		"timestamp_nanos":       strconv.FormatUint(ackInputs.TimestampNanos, 10),
		"counter":               strconv.FormatUint(ackInputs.Counter, 10), "preamble_hex": "66666666",
	}, ackBodyJSON, ackPacket)

	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updated = append(updated, '\n')
	for _, destination := range []string{
		path,
		filepath.Join(conformanceRoot, "npm", "vectors", "agent_session_control_vectors.json"),
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
