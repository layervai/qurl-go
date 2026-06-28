package relayknock

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

// strictRawURLEncoding decodes the golden cell_public_key_b64 with strict
// canonical-trailing-bit checking, rejecting non-canonical encodings — a step
// toward qv2/claims.go's stricter decode of the same field. (qv2's decodeB64 is
// stricter still: it adds a re-encode-and-compare backstop that also rejects
// embedded CR/LF, which base64.Strict() silently tolerates; for the canonical
// pinned golden vectors here that distinction is immaterial.)
// Hoisted once because base64.Encoding.Strict() allocates per call.
var strictRawURLEncoding = base64.RawURLEncoding.Strict()

// These golden vectors are consumed byte-for-byte from the public qurl-conformance
// package (github.com/layervai/qurl-conformance): the relay-knock golden packets
// (RelayKnockGolden) and the cross-language fingerprint vectors carried in the qv2
// conformance server_id class. They are themselves pinned to the reference NHP
// relay server output. If this relayknock port matches them, it is wire-compatible
// with the deployed server BY CONSTRUCTION — so a live failure is auth/network, not
// crypto. The dependency version pins the bytes via go.sum; this is a test-only
// import (no production relayknock file pulls the conformance module). Do NOT edit
// an assertion to make a test pass: a mismatch means the port drifted from the
// server wire format (or the pinned vectors were bumped and must be re-synced from
// the reference implementation).

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// mustDecimalU64 parses a base-10 uint64 field (timestamp_nanos, knock counter),
// which the conformance artifact carries as a decimal string because the values
// exceed 2^53.
func mustDecimalU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("parse decimal uint64 %q: %v", s, err)
	}
	return v
}

// mustHexU64 parses a hex uint64 field (the ack counter_hex: no 0x prefix, no
// padding).
func mustHexU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		t.Fatalf("parse hex uint64 %q: %v", s, err)
	}
	return v
}

// mustHexU32 parses a hex uint32 field (the knock preamble_hex).
func mustHexU32(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		t.Fatalf("parse hex uint32 %q: %v", s, err)
	}
	return uint32(v)
}

// loadRelayKnockGolden loads the pinned relay-knock golden artifact (knock + ack
// cases) from the conformance package, failing the test rather than skipping if the
// bytes are absent or malformed.
func loadRelayKnockGolden(t *testing.T) *conformance.RelayKnockFile {
	t.Helper()
	f, err := conformance.RelayKnockGolden()
	if err != nil {
		t.Fatalf("load relay-knock golden: %v", err)
	}
	return f
}

// TestBuildKnock_GoldenVector reproduces the relay-knock packet vector
// byte-for-byte from the conformance golden inputs, proving the handshake seal
// chain, header framing, and digest match the reference server.
func TestBuildKnock_GoldenVector(t *testing.T) {
	knock := loadRelayKnockGolden(t).Knock

	wantServerPubHex := knock.ServerStaticPubHex
	wantDevicePubHex := knock.DeviceStaticPubHex
	wantPacketHex := knock.PacketHex

	serverPriv := mustHex(t, knock.ServerStaticPrivHex)
	devicePriv := mustHex(t, knock.DeviceStaticPrivHex)
	ephemeralPriv := mustHex(t, knock.EphemeralPrivHex)
	timestampNanos := mustDecimalU64(t, knock.TimestampNanos)
	counter := mustDecimalU64(t, knock.Counter)
	preamble := mustHexU32(t, knock.PreambleHex)

	serverPub, err := x25519Public(serverPriv)
	if err != nil {
		t.Fatalf("derive server pub: %v", err)
	}
	if got := hex.EncodeToString(serverPub); got != wantServerPubHex {
		t.Fatalf("server pub = %s, want %s", got, wantServerPubHex)
	}
	devicePub, err := x25519Public(devicePriv)
	if err != nil {
		t.Fatalf("derive device pub: %v", err)
	}
	if got := hex.EncodeToString(devicePub); got != wantDevicePubHex {
		t.Fatalf("device pub = %s, want %s", got, wantDevicePubHex)
	}

	packet, err := BuildKnock(&KnockInputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    ephemeralPriv,
		TimestampNanos:   timestampNanos,
		Counter:          counter,
		Preamble:         preamble,
		Body:             mustHex(t, knock.BodyHex),
	})
	if err != nil {
		t.Fatalf("BuildKnock: %v", err)
	}
	if got := hex.EncodeToString(packet); got != wantPacketHex {
		t.Fatalf("knock packet mismatch:\n got=%s\nwant=%s", got, wantPacketHex)
	}
}

// TestDecryptReply_GoldenVector decrypts the relay-knock ack reply packet vector
// (server-built) and checks the recovered fields, proving the responder-side
// transcript + AEAD opens match the reference server.
func TestDecryptReply_GoldenVector(t *testing.T) {
	ack := loadRelayKnockGolden(t).Ack

	serverPubHex := ack.ServerStaticPubHex
	agentPrivHex := ack.AgentStaticPrivHex
	timestampNanos := mustDecimalU64(t, ack.TimestampNanos)
	wantCounter := mustHexU64(t, ack.CounterHex)
	bodyHex := ack.BodyHex
	ackPacketHex := ack.PacketHex

	reply, err := DecryptReply(mustHex(t, agentPrivHex), mustHex(t, serverPubHex), mustHex(t, ackPacketHex))
	if err != nil {
		t.Fatalf("DecryptReply: %v", err)
	}
	if !reply.IsACK() {
		t.Errorf("reply.Type = %d, want %d (NHP_ACK)", reply.Type, nhpACK)
	}
	if reply.Counter != wantCounter {
		t.Errorf("counter = %#x, want %#x", reply.Counter, wantCounter)
	}
	if reply.TimestampNanos != timestampNanos {
		t.Errorf("timestampNanos = %d, want %d", reply.TimestampNanos, timestampNanos)
	}
	if got := hex.EncodeToString(reply.Body); got != bodyHex {
		t.Fatalf("body mismatch:\n got=%s\nwant=%s", got, bodyHex)
	}
}

// TestPubKeyFingerprint_GoldenVectors pins {serverId} derivation against the
// shared cross-language fingerprint vectors, sourced from the qv2 conformance
// server_id class (cell_fill_0x42_golden -> "Ql7U5KNrMOo",
// cell_seq_1to32_golden -> "riFsLvUkejc"). These are the SAME inputs/outputs the
// qv2 conformance server_id class reuses (its runServerIDClass recomputes
// PubKeyFingerprint over the full class), so this fence and the qv2 routing
// contract cannot fork.
func TestPubKeyFingerprint_GoldenVectors(t *testing.T) {
	cf, err := conformance.ConformanceVectors()
	if err != nil {
		t.Fatalf("load conformance vectors: %v", err)
	}
	serverID, ok := cf.Classes["server_id"]
	if !ok {
		t.Fatal("conformance vectors missing server_id class")
	}
	byName := make(map[string]conformance.ConformanceVector, len(serverID.Vectors))
	for _, v := range serverID.Vectors {
		byName[v.Name] = v
	}

	// The two fingerprint golden cases the relayknock fence pins. The full
	// server_id class (these plus the non-golden cells) is exercised by qv2's
	// TestConformanceVectors/server_id; here we assert the two named golden cases
	// directly so the relayknock derivation is fenced in-package too.
	for _, name := range []string{"cell_fill_0x42_golden", "cell_seq_1to32_golden"} {
		v, ok := byName[name]
		if !ok {
			t.Fatalf("server_id class missing golden vector %q", name)
		}
		t.Run(name, func(t *testing.T) {
			key, err := strictRawURLEncoding.DecodeString(v.CellPublicKeyB64)
			if err != nil {
				t.Fatalf("decode cell_public_key_b64 %q: %v", v.CellPublicKeyB64, err)
			}
			got := PubKeyFingerprint(key)
			if got != v.ServerID {
				t.Errorf("PubKeyFingerprint = %q, want %q", got, v.ServerID)
			}
			if len(got) != PubKeyFingerprintLen {
				t.Errorf("fingerprint length = %d, want %d", len(got), PubKeyFingerprintLen)
			}
		})
	}
}
