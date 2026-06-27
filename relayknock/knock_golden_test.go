package relayknock

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// These golden vectors are copied byte-for-byte from the nhp js-agent's
// cross-language fixtures (endpoints/js-agent/test/testdata/*.json and
// fingerprint.test.ts), which are themselves pinned to the Go nhp/core server
// output, and were carried verbatim through the qurl-service #1021 clean-room
// smoke client. If this relayknock port matches them, it is wire-compatible with
// the deployed server BY CONSTRUCTION — so a live failure is auth/network, not
// crypto. Do NOT edit a constant to make a test pass: a mismatch means the port
// drifted from the server wire format (or the fixture was regenerated and must be
// re-synced from nhp).

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// fillBytes returns n bytes where b[i] = start+i (mod 256) — the fixed key
// material the js-agent fixtures use (SERVER_PRIV=1.., DEVICE_PRIV=0x41..,
// EPHEMERAL_PRIV=0x81..).
func fillBytes(n, start int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

// TestBuildKnock_GoldenVector reproduces the js-agent knock.json packet
// byte-for-byte from the same fixed inputs, proving the handshake seal chain,
// header framing, and digest match the Go server.
func TestBuildKnock_GoldenVector(t *testing.T) {
	const (
		wantServerPubHex = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
		wantDevicePubHex = "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466"
		bodyHex          = "7b2274657374223a226a732d6167656e74206b6e6f636b227d" // {"test":"js-agent knock"}
		timestampNanos   = uint64(1700000000000000000)
		counter          = uint64(1)
		preamble         = uint32(0x11223344)
		wantPacketHex    = "112233441123336d01000000000000000000000000000001883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c770000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e033f9d754b03a03eac48c26963c36f336bd3f1cd4ebf20c39cb3179646bf3b8ac43e2e886508ebded4a9d25e693f13d6f8bbd76bde5ac81b3cf11ca8bfc60dac9f5d290dfb7e979e019974fa54fbf0f501cae15125de39e22f6fd6d4be21f53724f2edb234b305275e5958b30dbee3212980ea4ca98b63f436c12da56e6587097ba12762e2f4d61dcb8023603f82f1d6d"
	)

	serverPriv := fillBytes(32, 1)
	devicePriv := fillBytes(32, 0x41)
	ephemeralPriv := fillBytes(32, 0x81)

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
		Body:             mustHex(t, bodyHex),
	})
	if err != nil {
		t.Fatalf("BuildKnock: %v", err)
	}
	if got := hex.EncodeToString(packet); got != wantPacketHex {
		t.Fatalf("knock packet mismatch:\n got=%s\nwant=%s", got, wantPacketHex)
	}
}

// TestDecryptReply_GoldenVector decrypts the js-agent ack.json reply packet
// (server-built) and checks the recovered fields, proving the responder-side
// transcript + AEAD opens match the Go server.
func TestDecryptReply_GoldenVector(t *testing.T) {
	const (
		serverPubHex   = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
		agentPrivHex   = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
		timestampNanos = uint64(1781494443173070000)
		wantCounter    = uint64(0x1122334455667788)
		bodyHex        = "7b22657272436f6465223a2230222c22726573486f7374223a7b22725f6a736167656e74223a2231302e302e302e37227d2c226f706e54696d65223a3930302c226167656e7441646472223a223230332e302e3131332e39222c226163546f6b656e73223a7b22725f6a736167656e74223a22746f6b2d616263313233227d7d"
		ackPacketHex   = "455e3ec8455c3e4b01000002000000001122334455667788345bdbe28c304e7dae8ca4e672fbca9b48d9ec7d673566ce09c9b7ef662707670000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a332e8cfa2e4eff64b7636eed1d047c275f7b0aced2debd8138daecf49e29bd92e89bc40a2cd98f2bf9f29d0c451b186b825b5d2d55a6668c06eed5f504087255b267fac40a7eac3f612fd2d62f6740740c53495dfbd7fc12d42acea3eab519b3015e532128a9bd3d75a3e46313f2b4ce17d50551f9eb1fbbbb331f2ccb5aa8ad1d04a191feabdebc03b0984b9098823085259197e4ba00cffc238599766960438fd6225d945f8af6edece5d9feffb9bda0ec3ec5d3f65b0e0eb9d35c36c500809edbb2854a4cf25ea206f96f33383ae71919ac3ad64e7178936e09906169d2197e42e52ad8e1676ccb5c5"
	)

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
// shared Go/js-agent fingerprint vectors. These are the SAME inputs/outputs the
// qv2 conformance server_id class reuses, so this fence and the qv2 routing
// contract cannot fork.
func TestPubKeyFingerprint_GoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		want string
	}{
		{"fill-0x42", bytes.Repeat([]byte{0x42}, 32), "Ql7U5KNrMOo"},
		{"seq-1to32", fillBytes(32, 1), "riFsLvUkejc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PubKeyFingerprint(tc.key)
			if got != tc.want {
				t.Errorf("PubKeyFingerprint = %q, want %q", got, tc.want)
			}
			if len(got) != PubKeyFingerprintLen {
				t.Errorf("fingerprint length = %d, want %d", len(got), PubKeyFingerprintLen)
			}
		})
	}
}
