package nhpwire

import (
	"bytes"
	"strings"
	"testing"
)

// framingFixture builds one valid initiator packet whose declared payload size
// matches its trailing bytes, so each PacketType subcase can perturb exactly one
// framing property of a known-good packet.
func framingFixture(t *testing.T, body []byte) []byte {
	t.Helper()
	devicePriv, _ := keyPair(t, 0x11)
	_, serverPub := keyPair(t, 0x22)
	packet, err := BuildMessage(TypeKNK, &Inputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          42,
		Preamble:         0x01020304,
		Body:             body,
	})
	if err != nil {
		t.Fatalf("build framing fixture: %v", err)
	}
	return packet
}

// TestPacketType_ValidatesFraming fences the only pre-send framing validator the
// public relayknock.RelayPost escape hatch has. RelayPost feeds it caller-built
// bytes, so each bound is a rejection a caller can actually reach: a runt, a
// packet past the responder's fixed receive buffer, and a self-described payload
// size that disagrees with the trailing bytes (either direction). The size
// disagreement matters because the declared size is what a responder frames on.
func TestPacketType_ValidatesFraming(t *testing.T) {
	valid := framingFixture(t, []byte("framing fixture body"))

	// A body at the plaintext ceiling seals to exactly the fixed receive buffer,
	// which must be accepted: the bound is >, not >=.
	atBuffer := framingFixture(t, make([]byte, maxApplicationBodySize))
	if len(atBuffer) != PacketBufferSize {
		t.Fatalf("max-body packet = %d bytes, want %d", len(atBuffer), PacketBufferSize)
	}

	tests := []struct {
		name     string
		packet   []byte
		wantType int
		wantSub  string
	}{
		{name: "valid knock", packet: valid, wantType: TypeKNK},
		{name: "exactly the receive buffer", packet: atBuffer, wantType: TypeKNK},
		{name: "shorter than the header", packet: make([]byte, HeaderSize-1), wantSub: "packet too short"},
		{name: "empty", packet: nil, wantSub: "packet too short"},
		{name: "past the receive buffer", packet: make([]byte, PacketBufferSize+1), wantSub: "packet too long"},
		{
			name:    "more trailing bytes than declared",
			packet:  append(bytes.Clone(valid), 0x00),
			wantSub: "does not match",
		},
		{
			name:    "fewer trailing bytes than declared",
			packet:  bytes.Clone(valid)[:len(valid)-1],
			wantSub: "does not match",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ, err := PacketType(tt.packet)
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("PacketType = %v, want accept", err)
				}
				if typ != tt.wantType {
					t.Fatalf("type = %d, want %d", typ, tt.wantType)
				}
				return
			}
			if err == nil {
				t.Fatalf("PacketType accepted a malformed packet as type %d, want reject", typ)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
			if typ != 0 {
				t.Errorf("rejected packet returned type %d alongside the error, want 0", typ)
			}
		})
	}
}

// TestVersionHeaderRoundTrip pins the version field the receive-side gate reads
// against the value the builder stamps, so the getter cannot drift from the
// setter's offsets and silently turn the gate into a no-op.
func TestVersionHeaderRoundTrip(t *testing.T) {
	header := make([]byte, HeaderSize)
	setVersion(header, 3, 9)
	if major, minor := getVersion(header); major != 3 || minor != 9 {
		t.Fatalf("getVersion = %d.%d, want 3.9", major, minor)
	}

	// Every packet this codec emits must carry the pinned version: the golden
	// vectors across all header types show 01 00.
	packet := framingFixture(t, []byte("version fixture"))
	if major, minor := getVersion(packet); major != protocolVersionMajor || minor != protocolVersionMinor {
		t.Fatalf("built packet version = %d.%d, want %d.%d", major, minor, protocolVersionMajor, protocolVersionMinor)
	}
	if packet[8] != protocolVersionMajor || packet[9] != protocolVersionMinor {
		t.Fatalf("version bytes = %#x %#x, want %#x %#x", packet[8], packet[9], protocolVersionMajor, protocolVersionMinor)
	}
}
