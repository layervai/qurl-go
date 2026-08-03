package nhpwire

import (
	"bytes"
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
// subcase tampers one field minimally to trip exactly one guard: the two length
// bounds, the protocol version, the header digest, the es DH, the es-keyed static
// open, the static-key match (opened against the wrong server key), the ss-keyed
// timestamp open (server authentication), the body open, and the inflate. The
// digest covers header[0:offDigest], so every subcase that mutates a header byte
// re-stamps it — that way the digest gate passes and the intended guard is the
// one that fails, not the digest. Re-stamping needs only the agent's PUBLIC key,
// which is why the digest cannot stand in for authentication of header fields.
//
// Every guard here is reachable pre-authentication, from a datagram an off-path
// attacker can synthesize: they all run before the ss-keyed opens complete.
func TestDecryptMessage_RejectsTamperedReply(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	_, otherServerPub := keyPair(t, 0x33)

	valid, err := BuildMessage(TypeACK, &Inputs{
		DeviceStaticPriv: serverPriv, // role-swapped: the server initiates the reply
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, 32),
		TimestampNanos:   1700000000123456789,
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
				pkt[8] = protocolVersionMajor + 1 // bump the major...
				// ...and re-stamp, so the version gate is the only guard left.
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:HeaderSize], nil))
			}),
			serverPub: serverPub,
			wantSub:   "unsupported NHP protocol major version",
		},
		{
			name: "header digest mismatch",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offDigest] ^= 0xff // corrupt the stored header digest
			}),
			serverPub: serverPub,
			wantSub:   "digest mismatch",
		},
		{
			name: "es DH fails on a low-order server ephemeral",
			packet: tamperedCopy(func(pkt []byte) {
				// An all-zero peer point drives X25519 to the all-zero shared
				// secret, which curve25519 refuses.
				clear(pkt[offEphemeral : offEphemeral+PublicKeySize])
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:HeaderSize], nil))
			}),
			serverPub: serverPub,
			wantSub:   "es DH",
		},
		{
			name: "sealed server static open fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offStatic] ^= 0xff // corrupt the es-sealed static field
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:HeaderSize], nil))
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
			name: "server authentication (timestamp open) fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offTimestamp] ^= 0xff // corrupt the sealed timestamp...
				// ...then re-stamp the digest so the digest gate passes and the
				// ss-keyed timestamp open is the guard that trips.
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:HeaderSize], nil))
			}),
			serverPub: serverPub,
			wantSub:   "server authentication failed",
		},
		{
			name: "body open fails",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[HeaderSize] ^= 0xff // corrupt the sealed body (outside the digest)
			}),
			serverPub: serverPub,
			wantSub:   "open body",
		},
		{
			// The compress bit rides outside the AEAD and can be SET by an
			// off-path attacker as cheaply as it can be cleared. This direction
			// fails closed on its own: the authenticated plaintext is not a zlib
			// stream, so the inflate rejects it. (The cleared direction does not
			// fail closed — see TestReplyCompressFlagIsUnauthenticated.)
			name: "compress flag set on a body that is not a zlib stream",
			packet: tamperedCopy(func(pkt []byte) {
				setFlag(pkt[:HeaderSize], nhpFlagCompress)
				copy(pkt[offDigest:offDigest+hashSize], headerDigest(devicePub, pkt[:HeaderSize], nil))
			}),
			serverPub: serverPub,
			wantSub:   "inflate body",
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

// TestDecryptMessage_AcceptsMinorVersionBump pins the deliberate asymmetry in the
// version gate: major is refused, minor is not. The server can ship a compatible
// minor bump before a deployed agent is updated, so gating on minor would strand
// clients on an ordinary coordinated release. The counterpart rejection subcase
// lives in TestDecryptMessage_RejectsTamperedReply.
func TestDecryptMessage_AcceptsMinorVersionBump(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	body := []byte("admission body from a newer minor")

	packet, err := BuildMessage(TypeACK, &Inputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  devicePub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          0x1234,
		Preamble:         0xa1b2c3d4,
		Body:             body,
	})
	if err != nil {
		t.Fatalf("build NHP_ACK: %v", err)
	}
	if major, minor := getVersion(packet); major != protocolVersionMajor || minor != protocolVersionMinor {
		t.Fatalf("builder stamped version %d.%d, want %d.%d", major, minor, protocolVersionMajor, protocolVersionMinor)
	}

	packet[9] = protocolVersionMinor + 7
	copy(packet[offDigest:offDigest+hashSize], headerDigest(devicePub, packet[:HeaderSize], nil))

	msg, err := DecryptMessage(devicePriv, serverPub, packet)
	if err != nil {
		t.Fatalf("a compatible minor bump was rejected: %v", err)
	}
	if !bytes.Equal(msg.Body, body) {
		t.Fatalf("Body = %q, want %q", msg.Body, body)
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
