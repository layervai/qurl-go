package nhpwire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// DecryptMessageFromUnknownSender is the one open that takes no expected
// sender key. These tests pin what that does and does not give up: the open
// learns the key instead of comparing it, and still authenticates the sender
// exactly as far as the pinned open does.

func buildKnockFrom(t *testing.T, senderPriv, recipientPub []byte, body string) []byte {
	t.Helper()
	packet, err := BuildMessage(TypeKNK, &Inputs{
		DeviceStaticPriv: senderPriv,
		ServerStaticPub:  recipientPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          0x0102030405060708,
		Preamble:         0xa1b2c3d4,
		Body:             []byte(body),
	})
	if err != nil {
		t.Fatalf("build NHP_KNK: %v", err)
	}
	return packet
}

func TestDecryptMessageFromUnknownSender_LearnsTheSenderKey(t *testing.T) {
	recipientPriv, recipientPub := keyPair(t, 0x22)

	// Two senders the recipient was never told about. Each open must report the
	// key of the sender that actually built the packet.
	for _, seed := range []byte{0x11, 0x33} {
		senderPriv, senderPub := keyPair(t, seed)
		packet := buildKnockFrom(t, senderPriv, recipientPub, "knock from an unknown sender")

		msg, learned, err := DecryptMessageFromUnknownSender(recipientPriv, packet)
		if err != nil {
			t.Fatalf("seed %#x: open: %v", seed, err)
		}
		if !bytes.Equal(learned, senderPub) {
			t.Fatalf("seed %#x: learned sender key %x, want %x", seed, learned, senderPub)
		}
		if msg.Type != TypeKNK || msg.Counter != 0x0102030405060708 || msg.TimestampNanos != 1700000000123456789 ||
			string(msg.Body) != "knock from an unknown sender" {
			t.Fatalf("seed %#x: opened message = %+v", seed, msg)
		}

		// The learned key is the key a pinned open accepts, and no other.
		if _, err := DecryptMessage(recipientPriv, learned, packet); err != nil {
			t.Fatalf("seed %#x: pinned open with the learned key: %v", seed, err)
		}

		// The caller owns the returned key: changing it must not reach into the
		// packet or into a later open.
		learned[0] ^= 0xff
		_, again, err := DecryptMessageFromUnknownSender(recipientPriv, packet)
		if err != nil || !bytes.Equal(again, senderPub) {
			t.Fatalf("seed %#x: second open after mutating the first result = %x, %v", seed, again, err)
		}
	}
}

// The pinned open is the initiator-side path. Adding an open that learns the
// sender must not have loosened it: the same packet that opens without an
// expected key is still refused under the wrong one, and under none.
func TestDecryptMessage_StillPinsTheSender(t *testing.T) {
	recipientPriv, recipientPub := keyPair(t, 0x22)
	senderPriv, _ := keyPair(t, 0x11)
	_, otherPub := keyPair(t, 0x33)
	packet := buildKnockFrom(t, senderPriv, recipientPub, "knock")

	if _, _, err := DecryptMessageFromUnknownSender(recipientPriv, packet); err != nil {
		t.Fatalf("fixture does not open: %v", err)
	}
	for name, expected := range map[string][]byte{
		"another key": otherPub,
		"nil key":     nil,
		"empty key":   {},
		"short key":   otherPub[:16],
	} {
		msg, err := DecryptMessage(recipientPriv, expected, packet)
		if err == nil || msg != nil {
			t.Fatalf("%s: pinned open accepted an unexpected sender", name)
		}
		if !strings.Contains(err.Error(), "unexpected server") {
			t.Fatalf("%s: pinned open failed as %q, want the static-key pin", name, err)
		}
	}
}

// forgeClaimedSender builds a packet that names claimedPub as its static key
// while being produced by someone who holds only forgerPriv. Everything a
// forger CAN compute is computed correctly: the ephemeral exchange, the sealed
// static field carrying the claimed key, the header digest. The one thing they
// cannot is ss = DH(claimed private key, recipient key), so the timestamp is
// sealed under the forger's own ss instead. This is the strongest packet
// someone impersonating claimedPub can send.
func forgeClaimedSender(t *testing.T, forgerPriv, claimedPub, recipientPub []byte, body string) []byte {
	t.Helper()
	const counter = uint64(0x0a0b0c0d0e0f1011)
	ephemeralPriv := bytes.Repeat([]byte{0x55}, PublicKeySize)
	nonce := nonceForCounter(counter)

	ephemeralPub, err := X25519Public(ephemeralPriv)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, HeaderSize)
	copy(header[offEphemeral:offEphemeral+PublicKeySize], ephemeralPub)

	chainHash := newBlake2s()
	chainHash.Write(initialHash)
	chainKey := mixKey(chainHash.Sum(nil), initialChainKey)
	chainHash.Write(recipientPub)
	chainHash.Write(ephemeralPub)
	chainKey = mixKey(chainKey, ephemeralPub)

	es, err := x25519Shared(ephemeralPriv, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	var aeadKey []byte
	chainKey, aeadKey = keyGen2(chainKey, es)
	sealedStatic, err := aeadSeal(aeadKey, nonce, claimedPub, chainHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	copy(header[offStatic:offStatic+PublicKeySize+gcmTagSize], sealedStatic)
	chainHash.Write(sealedStatic)

	// The forger's ss, not the claimed key's.
	ss, err := x25519Shared(forgerPriv, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	chainKey, aeadKey = keyGen2(chainKey, ss)
	timestamp := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(timestamp, 1700000000123456789)
	sealedTimestamp, err := aeadSeal(aeadKey, nonce, timestamp, chainHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	copy(header[offTimestamp:offTimestamp+timestampSize+gcmTagSize], sealedTimestamp)
	chainHash.Write(sealedTimestamp)

	_, aeadKey = keyGen2(chainKey, sealedTimestamp)
	setVersion(header, protocolVersionMajor, protocolVersionMinor)
	setCounter(header, counter)
	setFlag(header, 0)
	setTypeAndPayloadSize(header, TypeKNK, len(body)+gcmTagSize, 0x01020304)
	chainHash.Write(header[:headerCommonSize])
	sealedBody, err := aeadSeal(aeadKey, nonce, []byte(body), chainHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	copy(header[offDigest:offDigest+hashSize], headerDigest(recipientPub, header, nil))
	packet := make([]byte, 0, HeaderSize+len(sealedBody))
	packet = append(packet, header...)
	return append(packet, sealedBody...)
}

// TestDecryptMessageFromUnknownSender_RefusesAClaimedKeyTheSenderDoesNotHold is
// the property that makes the learned key worth returning. Without an expected
// key to compare against, the only thing tying the key to the sender is the
// ss-keyed open, so a packet that names somebody else's key must fail there
// and must not hand that key back.
func TestDecryptMessageFromUnknownSender_RefusesAClaimedKeyTheSenderDoesNotHold(t *testing.T) {
	recipientPriv, recipientPub := keyPair(t, 0x22)
	forgerPriv, forgerPub := keyPair(t, 0x66)
	_, victimPub := keyPair(t, 0x11)

	// Control: the same construction naming the forger's OWN key opens, so the
	// rejection below is the claimed key and not a broken hand-built packet.
	honest := forgeClaimedSender(t, forgerPriv, forgerPub, recipientPub, "body")
	msg, learned, err := DecryptMessageFromUnknownSender(recipientPriv, honest)
	if err != nil {
		t.Fatalf("hand-built packet naming its own key did not open: %v", err)
	}
	if !bytes.Equal(learned, forgerPub) || string(msg.Body) != "body" || msg.Type != TypeKNK {
		t.Fatalf("control open = key %x, message %+v", learned, msg)
	}

	forged := forgeClaimedSender(t, forgerPriv, victimPub, recipientPub, "body")
	msg, learned, err = DecryptMessageFromUnknownSender(recipientPriv, forged)
	if err == nil {
		t.Fatalf("a packet claiming a key its sender does not hold opened as key %x", learned)
	}
	if msg != nil || learned != nil {
		t.Fatalf("failed open returned message %+v and key %x; both must be nil", msg, learned)
	}
	if !strings.Contains(err.Error(), "server authentication failed") {
		t.Fatalf("forged sender failed as %q, want the ss-keyed timestamp open", err)
	}
}

// Every other guard of the open transcript must hold on this path too, and
// none may leak the key it read from a packet it then refused.
func TestDecryptMessageFromUnknownSender_RejectsTamperedPackets(t *testing.T) {
	recipientPriv, recipientPub := keyPair(t, 0x22)
	senderPriv, _ := keyPair(t, 0x11)
	otherRecipientPriv, _ := keyPair(t, 0x77)
	valid := buildKnockFrom(t, senderPriv, recipientPub, "knock body")

	tamperedCopy := func(fn func(pkt []byte)) []byte {
		c := bytes.Clone(valid)
		fn(c)
		return c
	}
	restamp := func(pkt []byte) {
		copy(pkt[offDigest:offDigest+hashSize], headerDigest(recipientPub, pkt[:HeaderSize], nil))
	}

	for _, tt := range []struct {
		name      string
		recipient []byte
		packet    []byte
		wantSub   string
	}{
		{"too short", recipientPriv, make([]byte, HeaderSize-1), "too short"},
		{"too long", recipientPriv, make([]byte, PacketBufferSize+1), "too long"},
		{"sealed to another recipient", otherRecipientPriv, valid, "digest mismatch"},
		{"header digest corrupted", recipientPriv, tamperedCopy(func(pkt []byte) { pkt[offDigest] ^= 0xff }), "digest mismatch"},
		{"sealed static corrupted", recipientPriv, tamperedCopy(func(pkt []byte) {
			pkt[offStatic] ^= 0xff
			restamp(pkt)
		}), "open server static"},
		{"sealed timestamp corrupted", recipientPriv, tamperedCopy(func(pkt []byte) {
			pkt[offTimestamp] ^= 0xff
			restamp(pkt)
		}), "server authentication failed"},
		{"sealed body corrupted", recipientPriv, tamperedCopy(func(pkt []byte) { pkt[HeaderSize] ^= 0xff }), "open body"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msg, learned, err := DecryptMessageFromUnknownSender(tt.recipient, tt.packet)
			if err == nil {
				t.Fatal("open accepted a tampered packet")
			}
			if msg != nil || learned != nil {
				t.Fatalf("failed open returned message %+v and key %x; both must be nil", msg, learned)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}
