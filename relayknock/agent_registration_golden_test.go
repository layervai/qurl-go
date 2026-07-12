package relayknock

import (
	"encoding/hex"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
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
// The vectors are consumed from the released qurl-conformance module through its
// typed accessor. go.sum pins the embedded artifact bytes; the conformance loader
// strictly rejects unknown fields, a wrong artifact identity, a missing schema
// version, and blank load-bearing bodies or packets before the production-path
// assertions validate every remaining input. The registered-agent KNK/ACK
// application vectors added in the same release belong to qurl-connector's
// serializer/interpreter and are intentionally consumed there rather than by this
// packet-level SDK.
//
// Do NOT edit an assertion to make a test pass: a mismatch means the port drifted
// from the server wire format (or the pinned vectors changed and must be reconciled
// with the reference implementation).

func loadAgentRegistrationGolden(t *testing.T) *conformance.AgentRegistrationFile {
	t.Helper()
	f, err := conformance.AgentRegistrationGolden()
	if err != nil {
		t.Fatalf("load agent-registration golden: %v", err)
	}
	return f
}

// buildFromInitiatorVector drives the REAL relayknock.BuildMessage over one
// deterministic initiator vector and returns the produced packet. serverStaticPub
// is fed from the vector's server_static_pub_hex (KnockInputs takes the responder's
// PUBLIC static key), matching the TypeScript fence's buildFromVector.
func buildFromInitiatorVector(t *testing.T, v conformance.AgentRegistrationCase, headerType int) []byte {
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

// TestBuildMessage_AgentRegistrationGolden reproduces the deterministic OTP and REG
// packets byte-for-byte from the conformance golden inputs, proving the NHP
// registration-message seal chain, header framing, and type gating match the
// reference server for all three cases (356/404/445-byte packets: OTP, emailed REG,
// pre-issued REG — the two REGs differ in size, 148B vs 189B bodies).
func TestBuildMessage_AgentRegistrationGolden(t *testing.T) {
	g := loadAgentRegistrationGolden(t)

	cases := []struct {
		name       string
		vec        conformance.AgentRegistrationCase
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
		vec  conformance.AgentRegistrationCase
	}{
		{name: "rak_success", vec: g.RakSuccess},
		{name: "rak_error", vec: g.RakError},
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
