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
// Exchange resolve path both inherit. A valid NHP_ACK is built server→agent (the
// golden-ack direction: the server is the reply's Noise initiator, the agent the
// responder, so DecryptMessage(devicePriv, serverPub, …) opens it), then each
// subcase tampers one field minimally to trip exactly one guard: the two length
// bounds, the header digest, the static-key match (opened against the wrong
// server key), the ss-keyed timestamp open (server authentication), and the body
// open. The digest covers header[0:offDigest], so the timestamp subcase re-stamps
// it after corrupting the sealed timestamp — that way the digest gate passes and
// the authentication open is the guard that fails, not the digest.
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
			name: "header digest mismatch",
			packet: tamperedCopy(func(pkt []byte) {
				pkt[offDigest] ^= 0xff // corrupt the stored header digest
			}),
			serverPub: serverPub,
			wantSub:   "digest mismatch",
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
