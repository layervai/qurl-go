package nhpwire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const regenerateNHP12VectorsEnv = "QURL_REGENERATE_NHP12_VECTORS"

// TestRegenerateNHP12PacketArtifacts is an opt-in maintainer tool. It reseals
// every NHP packet artifact with this codec while preserving the surrounding
// JSON layout. CI deliberately skips it: qurl-conformance remains independent
// of its consumers and records this producer's exact commit instead.
func TestRegenerateNHP12PacketArtifacts(t *testing.T) {
	conformanceRoot := os.Getenv(regenerateNHP12VectorsEnv)
	if conformanceRoot == "" {
		t.Skipf("set %s to a qurl-conformance checkout", regenerateNHP12VectorsEnv)
	}

	files := map[string]int{
		"relay_knock_golden.json":            2,
		"agent_registration_golden.json":     5,
		"agent_assignment_golden.json":       9,
		"agent_session_control_vectors.json": 5,
	}
	for name, wantPackets := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(conformanceRoot, "vectors", name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var root map[string]any
			if err := json.Unmarshal(raw, &root); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}

			updates := collectNHP12PacketUpdates(t, name, root)
			if len(updates) != wantPackets {
				t.Fatalf("%s packet count = %d, want %d", name, len(updates), wantPackets)
			}
			for _, update := range updates {
				raw = replaceJSONStringValue(t, raw, "packet_hex", update.oldPacketHex, update.newPacketHex)
				if update.oldMACHex != "" {
					raw = replaceJSONStringValue(t, raw, update.macField, update.oldMACHex, update.newMACHex)
				}
			}
			if name == "agent_session_control_vectors.json" {
				raw = []byte(strings.ReplaceAll(string(raw), `"header_digest_hex"`, `"header_mac_hex"`))
			}
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		})
	}
}

type nhp12PacketUpdate struct {
	oldPacketHex string
	newPacketHex string
	oldMACHex    string
	newMACHex    string
	macField     string
}

func collectNHP12PacketUpdates(t *testing.T, artifact string, root map[string]any) []nhp12PacketUpdate {
	t.Helper()
	var updates []nhp12PacketUpdate
	var walk func(value any, path []string)
	walk = func(value any, path []string) {
		switch node := value.(type) {
		case map[string]any:
			if _, ok := node["packet_hex"]; ok {
				updates = append(updates, regenerateNHP12Packet(t, artifact, root, node, path))
			}
			for key, child := range node {
				walk(child, append(path, key))
			}
		case []any:
			for i, child := range node {
				walk(child, append(path, strconv.Itoa(i)))
			}
		}
	}
	walk(root, nil)
	return updates
}

func regenerateNHP12Packet(t *testing.T, artifact string, root, packetCase map[string]any, path []string) nhp12PacketUpdate {
	t.Helper()
	pathName := strings.Join(path, ".")
	oldPacketHex := requiredString(t, packetCase, "packet_hex", pathName)
	oldPacket := decodeVectorHex(t, pathName+".packet_hex", oldPacketHex)
	if len(oldPacket) < HeaderSize {
		t.Fatalf("%s packet is %d bytes, want at least %d", pathName, len(oldPacket), HeaderSize)
	}

	senderPriv, receiverPub := vectorPacketKeys(t, artifact, root, packetCase, path)
	headerType := vectorPacketType(t, artifact, packetCase, path)
	body := decodeVectorHex(t, pathName+".body_hex", requiredString(t, packetCase, "body_hex", pathName))
	counter := vectorPacketCounter(t, packetCase, pathName)
	timestamp := requiredDecimalU64(t, packetCase, "timestamp_millis", pathName)
	material := sha256.Sum256([]byte("qurl-nhp-1.2-vector:" + artifact + ":" + pathName))
	ephemeral := material[:]
	if value, ok := stringValue(packetCase, "ephemeral_priv_hex"); ok {
		ephemeral = decodeVectorHex(t, pathName+".ephemeral_priv_hex", value)
	} else if value, ok := stringValue(packetCase, "ephemeral_private_hex"); ok {
		ephemeral = decodeVectorHex(t, pathName+".ephemeral_private_hex", value)
	}
	preamble := binary.BigEndian.Uint32(material[28:32])
	if value, ok := stringValue(packetCase, "preamble_hex"); ok {
		parsed, err := strconv.ParseUint(value, 16, 32)
		if err != nil {
			t.Fatalf("parse %s.preamble_hex: %v", pathName, err)
		}
		preamble = uint32(parsed)
	}

	inputs := &Inputs{
		DeviceStaticPriv: senderPriv,
		ServerStaticPub:  receiverPub,
		EphemeralPriv:    ephemeral,
		TimestampMillis:  timestamp,
		Counter:          counter,
		Preamble:         preamble,
		Body:             body,
		Compress:         vectorPacketCompressed(artifact, packetCase, path),
	}
	if headerType == TypeRKN {
		overload := requiredMap(t, root, "overload_reknock", artifact)
		inputs.Cookie = decodeVectorHex(t, artifact+".overload_reknock.cookie_hex", requiredString(t, overload, "cookie_hex", artifact))
	}
	packet, err := BuildMessage(headerType, inputs)
	if err != nil {
		t.Fatalf("build %s: %v", pathName, err)
	}

	update := nhp12PacketUpdate{
		oldPacketHex: oldPacketHex,
		newPacketHex: hex.EncodeToString(packet),
		newMACHex:    hex.EncodeToString(packet[offHeaderMAC:HeaderSize]),
	}
	if value, ok := stringValue(packetCase, "header_digest_hex"); ok {
		update.oldMACHex = value
		update.macField = "header_digest_hex"
	} else if value, ok := stringValue(packetCase, "header_mac_hex"); ok {
		update.oldMACHex = value
		update.macField = "header_mac_hex"
	}
	return update
}

func vectorPacketCompressed(artifact string, packetCase map[string]any, path []string) bool {
	// The reference server's ordinary relay ACK path always compresses. All
	// other packet families in the frozen set are uncompressed. This semantic
	// mapping is independent of the old packet's flag bit so a flag-layout hard
	// cut can regenerate the new bytes without interpreting bit 0 under the new
	// vocabulary as if it were the old extended-length bit.
	return artifact == "relay_knock_golden.json" && path[len(path)-1] == "ack"
}

func vectorPacketKeys(t *testing.T, artifact string, root, packetCase map[string]any, path []string) ([]byte, []byte) {
	t.Helper()
	pathName := strings.Join(path, ".")
	if sender, ok := stringValue(packetCase, "sender_key"); ok {
		receiver := requiredString(t, packetCase, "receiver_key", pathName)
		keys := requiredMap(t, root, "keys", artifact)
		senderKey := requiredMap(t, keys, sender, artifact+".keys")
		receiverKey := requiredMap(t, keys, receiver, artifact+".keys")
		return decodeVectorHex(t, pathName+" sender private key", requiredKeyString(t, senderKey, "static_priv_hex", "static_private_hex", sender)),
			decodeVectorHex(t, pathName+" receiver public key", requiredKeyString(t, receiverKey, "static_pub_hex", "static_public_hex", receiver))
	}
	if priv, ok := stringValue(packetCase, "device_static_priv_hex"); ok {
		return decodeVectorHex(t, pathName+".device_static_priv_hex", priv),
			decodeVectorHex(t, pathName+".server_static_pub_hex", requiredString(t, packetCase, "server_static_pub_hex", pathName))
	}

	switch artifact {
	case "relay_knock_golden.json":
		knock := requiredMap(t, root, "knock", artifact)
		return decodeVectorHex(t, "knock.server_static_priv_hex", requiredString(t, knock, "server_static_priv_hex", artifact)),
			decodeVectorHex(t, "knock.device_static_pub_hex", requiredString(t, knock, "device_static_pub_hex", artifact))
	case "agent_registration_golden.json":
		otp := requiredMap(t, root, "otp", artifact)
		return decodeVectorHex(t, "otp.server_static_priv_hex", requiredString(t, otp, "server_static_priv_hex", artifact)),
			decodeVectorHex(t, "otp.device_static_pub_hex", requiredString(t, otp, "device_static_pub_hex", artifact))
	default:
		t.Fatalf("%s has no key mapping for packet %s", artifact, pathName)
		return nil, nil
	}
}

func vectorPacketType(t *testing.T, artifact string, packetCase map[string]any, path []string) int {
	t.Helper()
	if value, ok := packetCase["header_type"].(float64); ok {
		return int(value)
	}
	name := path[len(path)-1]
	switch artifact {
	case "relay_knock_golden.json":
		if name == "knock" {
			return TypeKNK
		}
		if name == "ack" {
			return TypeACK
		}
	case "agent_registration_golden.json":
		switch {
		case name == "otp":
			return TypeOTP
		case strings.HasPrefix(name, "reg_"):
			return TypeREG
		case strings.HasPrefix(name, "rak_"):
			return TypeRAK
		}
	}
	t.Fatalf("%s packet %s has no header type", artifact, strings.Join(path, "."))
	return 0
}

func vectorPacketCounter(t *testing.T, packetCase map[string]any, path string) uint64 {
	t.Helper()
	if _, ok := packetCase["counter"]; ok {
		return requiredDecimalU64(t, packetCase, "counter", path)
	}
	value := requiredString(t, packetCase, "counter_hex", path)
	parsed, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		t.Fatalf("parse %s.counter_hex: %v", path, err)
	}
	return parsed
}

func requiredDecimalU64(t *testing.T, object map[string]any, field, path string) uint64 {
	t.Helper()
	value := requiredString(t, object, field, path)
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("parse %s.%s: %v", path, field, err)
	}
	return parsed
}

func requiredMap(t *testing.T, object map[string]any, field, path string) map[string]any {
	t.Helper()
	value, ok := object[field].(map[string]any)
	if !ok {
		t.Fatalf("%s.%s is not an object", path, field)
	}
	return value
}

func stringValue(object map[string]any, field string) (string, bool) {
	value, ok := object[field].(string)
	return value, ok
}

func requiredString(t *testing.T, object map[string]any, field, path string) string {
	t.Helper()
	value, ok := stringValue(object, field)
	if !ok {
		t.Fatalf("%s.%s is not a string", path, field)
	}
	return value
}

func requiredKeyString(t *testing.T, object map[string]any, first, second, path string) string {
	t.Helper()
	if value, ok := stringValue(object, first); ok {
		return value
	}
	return requiredString(t, object, second, path)
}

func decodeVectorHex(t *testing.T, name, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return decoded
}

func replaceJSONStringValue(t *testing.T, raw []byte, field, oldValue, newValue string) []byte {
	t.Helper()
	oldLiteral := []byte(fmt.Sprintf("%q: %q", field, oldValue))
	newLiteral := []byte(fmt.Sprintf("%q: %q", field, newValue))
	if count := strings.Count(string(raw), string(oldLiteral)); count != 1 {
		t.Fatalf("field %s old value occurs %d times, want exactly 1", field, count)
	}
	return []byte(strings.Replace(string(raw), string(oldLiteral), string(newLiteral), 1))
}
