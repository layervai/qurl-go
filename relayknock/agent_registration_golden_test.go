package relayknock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// BYTE-EXACT cross-language wire fence for the NHP agent-registration messages
// (OTP / REG / RAK), the analog of relay_knock's knock_golden_test.go and of the
// TypeScript crypto/golden.test.ts fence.
//
// Unlike message_test.go — which round-trips BuildMessage↔DecryptReply with the
// SAME in-repo nhpwire codec and so cannot catch a divergence from the Go/OpenNHP
// server wire — this test pins the real relayknock initiator API against the
// qurl-conformance golden vectors: the same artifact the OpenNHP reference server
// responder and the TypeScript SDK are fenced by. If BuildMessage reproduces
// packet_hex byte-for-byte from the fixed inputs and DecryptReply opens the frozen
// RAK replies, this port is wire-compatible with the deployed server BY
// CONSTRUCTION — so a live failure is auth/network, not crypto.
//
// VENDORED VECTORS — TEMPORARY. relayknock/testdata/agent_registration_golden.json
// is a byte-identical vendor of the qurl-conformance artifact
// "qurl-agent-registration-golden-vectors"
// (github.com/layervai/qurl-conformance, vectors/agent_registration_golden.json).
// It is copied verbatim so this fence exists in-repo NOW, rather than blocking on
// the conformance Go module publishing an accessor for these vectors. The sibling
// knock_golden_test.go already consumes the RELEASED conformance accessors
// (conformance.RelayKnockGolden(), conformance.ConformanceVectors()); the
// agent-registration vectors live in a conformance revision that is not yet tagged,
// so there is no conformance.AgentRegistrationGolden() to import here yet.
//
// MIGRATION: once qurl-conformance tags the release carrying these vectors, replace
// loadAgentRegistrationGolden + the vendored testdata file with the published
// accessor — i.e. mirror knock_golden_test.go's loadRelayKnockGolden and call
// conformance.AgentRegistrationGolden() (bumping the go.mod require to that tag).
// At that point this fence keeps its assertions and only swaps its data source.
// Tracked in layervai/qurl-go#50. Do NOT hand-edit the vendored JSON: it is
// source-of-truth data owned by qurl-conformance; the SHA-256 integrity check
// below fails closed if it is touched, and CI diffs it against the canonical
// upstream copy (see .github/workflows/agent-reg-vectors-drift.yml) so it cannot
// silently diverge. Do NOT edit an assertion to make a test pass: a mismatch means
// the port drifted from the server wire format (or the vectors were re-vendored and
// must be re-synced from the reference implementation).

// agentRegVectorsFile is the vendored artifact's path, relative to this package.
const agentRegVectorsFile = "testdata/agent_registration_golden.json"

// agentRegVectorsSHA256 pins the SHA-256 of the vendored artifact. Because the file
// is a temporary hand-copied vendor (not a go.sum-pinned module import like the
// relay-knock vectors), a silent local edit would otherwise quietly downgrade this
// cross-language fence into a self-consistency check. If the upstream artifact
// legitimately changes, re-vendor from qurl-conformance and update this digest
// deliberately. This is the SAME digest the TypeScript fence pins for the same file.
const agentRegVectorsSHA256 = "77dc8634eb15e8a986df1093923b70b341386ba3c15421814ffed1a668f2d2bc"

// agentRegInitiatorVector is one deterministic initiator case (otp / reg_emailed /
// reg_preissued): the fixed inputs a conformant BuildMessage must turn back into
// packet_hex byte-for-byte. Only the fields this fence drives are decoded; the
// server_static_priv / device_static_pub fields the artifact also carries (for the
// server-side decrypt fence) are intentionally omitted here.
type agentRegInitiatorVector struct {
	ServerStaticPubHex  string `json:"server_static_pub_hex"`
	DeviceStaticPrivHex string `json:"device_static_priv_hex"`
	EphemeralPrivHex    string `json:"ephemeral_priv_hex"`
	TimestampNanos      string `json:"timestamp_nanos"`
	Counter             string `json:"counter"`
	PreambleHex         string `json:"preamble_hex"`
	BodyHex             string `json:"body_hex"`
	PacketHex           string `json:"packet_hex"`
}

// agentRegReplyVector is one frozen server reply case (rak_success / rak_error):
// sealed by the reference server with a RANDOM ephemeral, so it is NOT reproducible
// by a client — only decryptable. DecryptReply must open it and recover NHP_RAK,
// the echoed counter, the timestamp, and the body.
type agentRegReplyVector struct {
	ServerStaticPubHex string `json:"server_static_pub_hex"`
	AgentStaticPrivHex string `json:"agent_static_priv_hex"`
	TimestampNanos     string `json:"timestamp_nanos"`
	CounterHex         string `json:"counter_hex"`
	BodyHex            string `json:"body_hex"`
	PacketHex          string `json:"packet_hex"`
}

// agentRegGoldenFile is the vendored artifact document. The artifact id is asserted
// on load so a consumer that relies on "the loader rejects a malformed file" cannot
// silently load a DIFFERENT document — mirroring conformance.ParseRelayKnockFile's
// artifact-id gate for the relay-knock vectors.
type agentRegGoldenFile struct {
	Artifact     string                  `json:"artifact"`
	OTP          agentRegInitiatorVector `json:"otp"`
	RegEmailed   agentRegInitiatorVector `json:"reg_emailed"`
	RegPreissued agentRegInitiatorVector `json:"reg_preissued"`
	RAKSuccess   agentRegReplyVector     `json:"rak_success"`
	RAKError     agentRegReplyVector     `json:"rak_error"`
}

const agentRegArtifactID = "qurl-agent-registration-golden-vectors"

// loadAgentRegistrationGolden reads and strictly parses the vendored artifact,
// after asserting its bytes match the pinned SHA-256. It FAILS (never skips) if the
// bytes are absent, tampered, or malformed, so the fence cannot silently no-op.
//
// This is the vendored-data stand-in for a published
// conformance.AgentRegistrationGolden() accessor; see the file header for the
// migration plan.
func loadAgentRegistrationGolden(t *testing.T) *agentRegGoldenFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(agentRegVectorsFile))
	if err != nil {
		t.Fatalf("read vendored agent-registration vectors %s: %v", agentRegVectorsFile, err)
	}

	// Integrity gate first: a mismatch here means the vendored copy was edited (or
	// corrupted), which would invalidate every byte-exact assertion below.
	if got := hex.EncodeToString(sha256Sum(raw)); got != agentRegVectorsSHA256 {
		t.Fatalf("vendored agent-registration vectors SHA-256 = %s, want %s\n"+
			"the vendored %s was modified; it must stay byte-identical to the qurl-conformance source. "+
			"Re-vendor from upstream and update agentRegVectorsSHA256 only for a deliberate upstream change.",
			got, agentRegVectorsSHA256, agentRegVectorsFile)
	}

	var f agentRegGoldenFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vendored agent-registration vectors: %v", err)
	}
	if f.Artifact != agentRegArtifactID {
		t.Fatalf("vendored artifact id = %q, want %q", f.Artifact, agentRegArtifactID)
	}
	// Fail closed on a blank load-bearing packet: a byte-exact fence must not
	// "pass" on an empty want.
	for name, packetHex := range map[string]string{
		"otp":           f.OTP.PacketHex,
		"reg_emailed":   f.RegEmailed.PacketHex,
		"reg_preissued": f.RegPreissued.PacketHex,
		"rak_success":   f.RAKSuccess.PacketHex,
		"rak_error":     f.RAKError.PacketHex,
	} {
		if packetHex == "" {
			t.Fatalf("vendored agent-registration vectors missing %s.packet_hex", name)
		}
	}
	return &f
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// buildFromInitiatorVector drives the REAL relayknock.BuildMessage over one
// deterministic initiator vector and returns the produced packet. serverStaticPub
// is fed from the vector's server_static_pub_hex (KnockInputs takes the responder's
// PUBLIC static key), matching the TypeScript fence's buildFromVector.
func buildFromInitiatorVector(t *testing.T, v agentRegInitiatorVector, headerType int) []byte {
	t.Helper()
	packet, err := BuildMessage(headerType, &KnockInputs{
		DeviceStaticPriv: mustHex(t, v.DeviceStaticPrivHex),
		ServerStaticPub:  mustHex(t, v.ServerStaticPubHex),
		EphemeralPriv:    mustHex(t, v.EphemeralPrivHex),
		TimestampNanos:   mustDecimalU64(t, v.TimestampNanos),
		Counter:          mustDecimalU64(t, v.Counter),
		Preamble:         mustHexU32(t, v.PreambleHex),
		Body:             mustHex(t, v.BodyHex),
	})
	if err != nil {
		t.Fatalf("BuildMessage(type %d): %v", headerType, err)
	}
	return packet
}

// TestAgentRegistrationVendoredVectors_Integrity fails if the vendored artifact
// drifts from the pinned SHA-256 (a silent local edit), keeping this cross-language
// fence from decaying into a self-consistency check. loadAgentRegistrationGolden
// enforces the same gate, but a dedicated named case makes the failure legible.
func TestAgentRegistrationVendoredVectors_Integrity(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(agentRegVectorsFile))
	if err != nil {
		t.Fatalf("read vendored agent-registration vectors: %v", err)
	}
	if got := hex.EncodeToString(sha256Sum(raw)); got != agentRegVectorsSHA256 {
		t.Fatalf("vendored vectors SHA-256 = %s, want %s (the vendored copy was edited)", got, agentRegVectorsSHA256)
	}
}

// TestBuildMessage_AgentRegistrationGolden reproduces the deterministic OTP and REG
// packets byte-for-byte from the conformance golden inputs, proving the NHP
// registration-message seal chain, header framing, and type gating match the
// reference server for all three cases (356/425/425-byte packets: OTP, emailed REG,
// pre-issued REG).
func TestBuildMessage_AgentRegistrationGolden(t *testing.T) {
	g := loadAgentRegistrationGolden(t)

	cases := []struct {
		name       string
		vec        agentRegInitiatorVector
		headerType int
	}{
		{name: "otp", vec: g.OTP, headerType: TypeOTP},
		{name: "reg_emailed", vec: g.RegEmailed, headerType: TypeRegister},
		{name: "reg_preissued", vec: g.RegPreissued, headerType: TypeRegister},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packet := buildFromInitiatorVector(t, tc.vec, tc.headerType)
			if got := hex.EncodeToString(packet); got != tc.vec.PacketHex {
				t.Fatalf("%s packet mismatch:\n got=%s\nwant=%s", tc.name, got, tc.vec.PacketHex)
			}
		})
	}
}

// TestDecryptReply_AgentRegistrationGolden decrypts the frozen server RAK replies
// (success and error) and checks the recovered fields, proving the responder-side
// transcript + AEAD opens match the reference server. Both replies echo
// counter_hex = 0xb, which is reg_emailed.counter (11): the conformance
// matched-counter pair, so this also fences the RAK→REG counter-echo contract with
// a positive fixture.
func TestDecryptReply_AgentRegistrationGolden(t *testing.T) {
	g := loadAgentRegistrationGolden(t)

	// The success and error RAKs share a decrypt shape; only the recovered body
	// differs. Both must open to NHP_RAK (14) and echo the REG counter.
	cases := []struct {
		name string
		vec  agentRegReplyVector
	}{
		{name: "rak_success", vec: g.RAKSuccess},
		{name: "rak_error", vec: g.RAKError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply, err := DecryptReply(
				mustHex(t, tc.vec.AgentStaticPrivHex),
				mustHex(t, tc.vec.ServerStaticPubHex),
				mustHex(t, tc.vec.PacketHex),
			)
			if err != nil {
				t.Fatalf("DecryptReply: %v", err)
			}
			if !reply.IsRegisterAck() {
				t.Errorf("reply.Type = %d, want %d (NHP_RAK)", reply.Type, TypeRegisterAck)
			}
			wantCounter := mustHexU64(t, tc.vec.CounterHex)
			if reply.Counter != wantCounter {
				t.Errorf("counter = %#x, want %#x", reply.Counter, wantCounter)
			}
			// Both frozen RAKs echo reg_emailed.counter (the matched-counter pair):
			// pin that cross-case invariant directly.
			if wantReg := mustDecimalU64(t, g.RegEmailed.Counter); reply.Counter != wantReg {
				t.Errorf("counter = %#x, want reg_emailed.counter %#x (matched-counter pair)", reply.Counter, wantReg)
			}
			if wantTS := mustDecimalU64(t, tc.vec.TimestampNanos); reply.TimestampNanos != wantTS {
				t.Errorf("timestampNanos = %d, want %d", reply.TimestampNanos, wantTS)
			}
			// The decrypted body must equal the vector's plaintext body_hex
			// (frozen decrypt-only cross-check): proves the AEAD open recovered the
			// exact bytes, not merely a well-formed tag.
			if got := hex.EncodeToString(reply.Body); got != tc.vec.BodyHex {
				t.Fatalf("%s body mismatch:\n got=%s\nwant=%s", tc.name, got, tc.vec.BodyHex)
			}
		})
	}
}
