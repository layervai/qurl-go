package nhpwire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// keyPair derives a deterministic X25519 key pair from a repeated seed byte, so
// failures reproduce without golden fixtures (clamping is internal to
// X25519Public, so any 32 bytes are a valid scalar).
func keyPair(t *testing.T, seed byte) (priv, pub []byte) {
	t.Helper()
	priv = bytes.Repeat([]byte{seed}, 32)
	pub, err := X25519Public(priv)
	if err != nil {
		t.Fatalf("derive pub from seed %#x: %v", seed, err)
	}
	return priv, pub
}

// TestDecryptMessage_RejectsTamperedReply covers the crypto-rejection paths of
// DecryptMessage — the guards the exported relayknock.DecryptReply and the
// Knock resolve path both inherit. A valid NHP_ACK is built server→agent (the
// golden-ack direction: the server is the reply's Noise initiator, the agent the
// responder, so DecryptMessage(devicePriv, serverPub, …) opens it), then each
// subcase changes one field minimally to pin the rejection stage: length,
// version, static-field processing, expected identity, or the keyed header MAC.
func TestDecryptMessage_RejectsTamperedReply(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	_, otherServerPub := keyPair(t, 0x33)

	valid, err := BuildMessage(TypeACK, &Inputs{
		DeviceStaticPriv: serverPriv, // role-swapped: the server initiates the reply
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, 32),
		TimestampMillis:  1700000000123,
		Counter:          0x1234,
		Preamble:         0xa1b2c3d4,
		Body:             []byte("authorized admission body"),
	})
	if err != nil {
		t.Fatalf("build valid NHP_ACK: %v", err)
	}
	// Sanity: the untampered packet opens, so every rejection below is the tamper
	// and not a broken fixture.
	if _, err := DecryptMessage(devicePriv, serverPub, valid); err != nil {
		t.Fatalf("valid NHP_ACK did not open: %v", err)
	}

	// tamperedCopy returns a fresh copy of valid with fn applied, keeping each
	// subcase's mutation off the shared fixture.
	tamperedCopy := func(fn func(pkt []byte)) []byte {
		c := append([]byte(nil), valid...)
		fn(c)
		return c
	}

	tests := []struct {
		name      string
		packet    []byte
		serverPub []byte // expected server static pub passed to DecryptMessage
		wantSub   string
	}{
		{
			name:      "reply too short",
			packet:    make([]byte, HeaderSize-1),
			serverPub: serverPub,
			wantSub:   "reply too short",
		},
		{
			name:      "reply too long",
			packet:    make([]byte, PacketBufferSize+1),
			serverPub: serverPub,
			wantSub:   "reply too long",
		},
		{
			name: "unsupported protocol major version",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[8] = protocolVersionMajor + 1
			}),
			serverPub: serverPub,
			wantSub:   "unsupported NHP protocol version",
		},
		{
			name: "header MAC mismatch",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offHeaderMAC] ^= 0xff
			}),
			serverPub: serverPub,
			wantSub:   "HMAC mismatch",
		},
		{
			name: "es DH fails on a low-order server ephemeral",
			packet: tamperedCopy(func(pkt []byte) {
				clear(pkt[offEphemeral : offEphemeral+PublicKeySize])
			}),
			serverPub: serverPub,
			wantSub:   "es DH",
		},
		{
			name: "sealed server static open fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offStatic] ^= 0xff
			}),
			serverPub: serverPub,
			wantSub:   "open server static",
		},
		{
			name:      "unexpected server static key",
			packet:    valid, // untampered; opened against the wrong server key
			serverPub: otherServerPub,
			wantSub:   "unexpected server",
		},
		{
			name: "timestamp ciphertext rejected by header MAC",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offTimestamp] ^= 0xff
			}),
			serverPub: serverPub,
			wantSub:   "HMAC mismatch",
		},
		{
			name: "body ciphertext rejected by header MAC",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[HeaderSize] ^= 0xff // corrupt payload ciphertext covered by the MAC
			}),
			serverPub: serverPub,
			wantSub:   "HMAC mismatch",
		},
		{
			name: "compress flag set on a body that is not a zlib stream",
			packet: tamperedCopy(func(pkt []byte) {
				setFlag(pkt[:HeaderSize], nhpFlagCompress)
			}),
			serverPub: serverPub,
			wantSub:   "HMAC mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecryptMessage(devicePriv, tt.serverPub, tt.packet); err == nil {
				t.Fatal("DecryptMessage accepted a tampered/invalid reply, want reject")
			} else if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestDecryptMessage_RejectsBodylessHeaderTamper(t *testing.T) {
	agentPriv, agentPub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	packet, err := BuildMessage(TypeEXT, &Inputs{
		DeviceStaticPriv: agentPriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampMillis:  1700000000123,
		Counter:          0x1234,
		Preamble:         0xa1b2c3d4,
	})
	if err != nil {
		t.Fatalf("build bodyless EXT: %v", err)
	}
	if len(packet) != HeaderSize {
		t.Fatalf("bodyless packet length = %d, want %d", len(packet), HeaderSize)
	}
	if _, err := DecryptMessage(serverPriv, agentPub, packet); err != nil {
		t.Fatalf("bodyless EXT did not open: %v", err)
	}

	tampered := bytes.Clone(packet)
	setTypeAndPayloadSize(tampered, TypeKNK, 0, binary.BigEndian.Uint32(tampered[:4]))
	if _, err := DecryptMessage(serverPriv, agentPub, tampered); err == nil || !strings.Contains(err.Error(), "HMAC mismatch") {
		t.Fatalf("bodyless header tamper error = %v, want header HMAC rejection", err)
	}
}

func TestDecryptMessage_RejectsNoncanonicalFramingBeforeDH(t *testing.T) {
	agentPriv, agentPub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	build := func(body []byte) []byte {
		t.Helper()
		packet, err := BuildMessage(TypeACK, &Inputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  agentPub,
			EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
			TimestampMillis:  1700000000123,
			Counter:          0x1234,
			Preamble:         0xa1b2c3d4,
			Body:             body,
		})
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		return packet
	}
	bodyful := build([]byte(`{"errCode":"0","opnTime":120,"sessId":1}`))
	bodyless := build(nil)
	_, bodyfulSize := getTypeAndPayloadSize(bodyful)

	tests := []struct {
		name    string
		packet  []byte
		mutate  func([]byte)
		wantSub string
	}{
		{
			name:   "bodyful declared size below trailing bytes",
			packet: bodyful,
			mutate: func(packet []byte) {
				setTypeAndPayloadSize(packet, TypeACK, bodyfulSize-1, 0xa1b2c3d4)
			},
			wantSub: "declared payload size",
		},
		{
			name:   "bodyful declared size above trailing bytes",
			packet: bodyful,
			mutate: func(packet []byte) {
				setTypeAndPayloadSize(packet, TypeACK, bodyfulSize+1, 0xa1b2c3d4)
			},
			wantSub: "declared payload size",
		},
		{
			name:   "bodyless declared nonzero",
			packet: bodyless,
			mutate: func(packet []byte) {
				setTypeAndPayloadSize(packet, TypeACK, 1, 0xa1b2c3d4)
			},
			wantSub: "declared payload size",
		},
		{
			name:    "reserved header bytes",
			packet:  bodyful,
			mutate:  func(packet []byte) { packet[12] = 1 },
			wantSub: "reserved header bytes",
		},
		{
			name:    "reserved bit 2",
			packet:  bodyful,
			mutate:  func(packet []byte) { binary.BigEndian.PutUint16(packet[10:12], 1<<2) },
			wantSub: "flags",
		},
		{
			name:    "reserved high flag",
			packet:  bodyful,
			mutate:  func(packet []byte) { binary.BigEndian.PutUint16(packet[10:12], 1<<15) },
			wantSub: "flags",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet := bytes.Clone(tc.packet)
			tc.mutate(packet)
			// A low-order ephemeral would fail DH if the structural gate did not run
			// first. The exact error below pins the pre-DH ordering.
			clear(packet[offEphemeral : offEphemeral+PublicKeySize])
			if msg, err := DecryptMessage(agentPriv, serverPub, packet); err == nil || msg != nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DecryptMessage = %#v, %v; want pre-DH %q rejection", msg, err, tc.wantSub)
			}
		})
	}
}

// TestDecryptMessage_AcceptsMinorVersionBump pins the deliberate asymmetry in the
// version gate: the major is pinned and the minor is FLOORED, not pinned. A
// server can ship a compatible minor bump before a deployed agent is updated, so
// refusing a newer minor would strand clients on an ordinary coordinated release.
//
// The newer-minor packet is built at that version rather than edited after
// construction: protocol 1.2 authenticates the version with the header MAC, so
// a post-construction edit must fail the MAC check — which is what
// TestHeaderCommonFieldsAreBoundIntoHeaderMAC asserts. The counterpart rejections
// live in TestDecryptMessage_RejectsTamperedReply (major) and
// TestDecryptMessage_RejectsPreBindingMinorVersion (older minor).
func TestDecryptMessage_AcceptsMinorVersionBump(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	body := []byte("admission body from a newer minor")
	const newerMinor = protocolVersionMinor + 7

	packet, err := buildMessageWithVersion(TypeACK, 0, protocolVersionMajor, newerMinor, &Inputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampMillis:  1700000000123,
		Counter:          0x1234,
		Preamble:         0xa1b2c3d4,
		Body:             body,
	})
	if err != nil {
		t.Fatalf("build NHP_ACK: %v", err)
	}
	if major, minor := getVersion(packet); major != protocolVersionMajor || minor != newerMinor {
		t.Fatalf("builder stamped version %d.%d, want %d.%d", major, minor, protocolVersionMajor, newerMinor)
	}

	msg, err := DecryptMessage(devicePriv, serverPub, packet)
	if err != nil {
		t.Fatalf("a compatible minor bump was rejected: %v", err)
	}
	if !bytes.Equal(msg.Body, body) {
		t.Fatalf("Body = %q, want %q", msg.Body, body)
	}
}

// TestDecryptMessage_RejectsPreBindingMinorVersion is the rollout-diagnosability
// fence. A peer still speaking 1.1 does not produce the keyed header MAC, so its
// framing cannot authenticate under protocol 1.2. The gate must therefore run
// before key agreement, which is what the error substring below pins.
func TestDecryptMessage_RejectsPreBindingMinorVersion(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)

	for minor := byte(0); minor < minProtocolVersionMinor; minor++ {
		packet, err := buildMessageWithVersion(TypeACK, 0, protocolVersionMajor, minor, &Inputs{
			DeviceStaticPriv: serverPriv,
			ServerStaticPub:  devicePub,
			EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
			TimestampMillis:  1700000000123,
			Counter:          0x1234,
			Preamble:         0xa1b2c3d4,
			Body:             []byte(`{"errCode":"0"}`),
		})
		if err != nil {
			t.Fatalf("build NHP_ACK at 1.%d: %v", minor, err)
		}

		msg, err := DecryptMessage(devicePriv, serverPub, packet)
		if err == nil || msg != nil {
			t.Fatalf("1.%d packet accepted: %#v, %v", minor, msg, err)
		}
		want := fmt.Sprintf("unsupported NHP protocol version %d.%d", protocolVersionMajor, minor)
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("1.%d rejected as %q, want an explicit version error containing %q", minor, err, want)
		}
	}
}

func TestAcceptReplyMessageWipesBodyOnRejectedHeaderType(t *testing.T) {
	body := []byte("lv_live_reflected_plaintext")
	if msg, err := acceptReplyMessage(&Message{Type: TypeREG, Body: body}); msg != nil || err == nil {
		t.Fatalf("accepted reply = %#v, %v; want rejection", msg, err)
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatalf("rejected authenticated reply retained plaintext body: %x", body)
	}
}
