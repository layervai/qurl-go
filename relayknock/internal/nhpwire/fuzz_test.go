package nhpwire

import (
	"bytes"
	"encoding/hex"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

// Fuzz targets for the three functions that parse an UNAUTHENTICATED UDP
// datagram: DecryptMessage, DecryptReplyMessage, and PacketType. Everything they
// touch before the ss-keyed opens complete is attacker-reachable off-path, so
// these assert invariants rather than merely "does not crash": a rejected packet
// must never yield a message, and an accepted one must satisfy the framing,
// version, and profile bounds the rest of the SDK relies on.
//
// Seeds are split by provenance. Packets that must open under the fixed fuzz keys
// are BUILT here, because their bytes are a function of those keys. The pinned
// cross-language golden packets are pulled from the qurl-conformance module
// rather than copied into testdata, so this repo cannot fork the pinned wire
// bytes. Only the deliberately-corrupt mutations are committed under
// testdata/fuzz — they are not golden and have no other home.

// fuzzKeyPair derives the fixed identities the targets decrypt against. Fuzzing
// mutates only the datagram, so the keys must be deterministic for a seed that
// opens to keep opening.
func fuzzKeyPair(tb testing.TB, seed byte) (priv, pub []byte) {
	tb.Helper()
	priv = bytes.Repeat([]byte{seed}, PublicKeySize)
	pub, err := X25519Public(priv)
	if err != nil {
		tb.Fatalf("derive fuzz pub from seed %#x: %v", seed, err)
	}
	return priv, pub
}

// fuzzSeedPackets returns the in-code seeds: packets that open under the fixed
// fuzz keys, matching mutations of them, and the pinned conformance goldens.
func fuzzSeedPackets(tb testing.TB) [][]byte {
	tb.Helper()
	_, agentPub := fuzzKeyPair(tb, 0x11)
	serverPriv, _ := fuzzKeyPair(tb, 0x22)

	build := func(headerType int, flags uint16, body []byte) []byte {
		packet, err := buildMessageUnchecked(headerType, flags, &Inputs{
			DeviceStaticPriv: serverPriv, // role-swapped: the server initiates a reply
			ServerStaticPub:  agentPub,
			EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
			TimestampMillis:  1700000000123,
			Counter:          0x1122334455667788,
			Preamble:         0xa1b2c3d4,
			Body:             body,
		})
		if err != nil {
			tb.Fatalf("build fuzz seed (type %d flags %#04x): %v", headerType, flags, err)
		}
		return packet
	}

	replyBody := []byte(`{"errCode":"0","resHost":{"r_agent":"198.51.100.7"}}`)
	ack := build(TypeACK, nhpFlagCompress, replyBody)
	plainACK := build(TypeACK, 0, replyBody)
	seeds := [][]byte{
		ack,
		plainACK,
		build(TypeCOK, 0, []byte(`{"trxId":1,"cookie":"AAAA"}`)),
		build(TypeLRT, nhpFlagCompress, []byte(`{"ok":true}`)),
		build(TypeRAK, 0, []byte(`{"registered":true}`)),
		build(TypeKNK, 0, []byte(`{"test":"initiator"}`)),
		build(TypeEXT, 0, nil),
		build(99, 0, []byte("unknown type")),

		// Mutations of an opening packet, each aimed at one guard.
		func() []byte { p := bytes.Clone(ack); p[8] = protocolVersionMajor + 1; return p }(),
		func() []byte { p := bytes.Clone(ack); setFlag(p[:HeaderSize], 1<<3); return p }(),
		func() []byte { p := bytes.Clone(ack); setFlag(p[:HeaderSize], hubLSTCookieProofFlag); return p }(),
		func() []byte { p := bytes.Clone(plainACK); setFlag(p[:HeaderSize], nhpFlagCompress); return p }(),
		func() []byte { p := bytes.Clone(ack); clear(p[offEphemeral : offEphemeral+PublicKeySize]); return p }(),
		func() []byte { p := bytes.Clone(ack); p[offStatic] ^= 0xff; return p }(),
		func() []byte { p := bytes.Clone(ack); p[len(p)-1] ^= 0xff; return p }(),
		func() []byte { p := bytes.Clone(ack); p[offHeaderMAC] ^= 0xff; return p }(),
	}

	// The pinned cross-language goldens, loaded from the conformance module so the
	// bytes have exactly one source of truth. They do not open under the fuzz
	// keys; they seed the parser with real server framing.
	golden, err := conformance.RelayKnockGolden()
	if err != nil {
		tb.Fatalf("load relay-knock golden: %v", err)
	}
	for _, packetHex := range []string{golden.Knock.PacketHex, golden.Ack.PacketHex} {
		decoded, err := hex.DecodeString(packetHex)
		if err != nil {
			tb.Fatalf("decode golden packet: %v", err)
		}
		seeds = append(seeds, decoded)
	}
	return seeds
}

func addFuzzSeeds(f *testing.F) {
	f.Helper()
	for _, seed := range fuzzSeedPackets(f) {
		f.Add(seed)
	}
}

// checkDecrypted asserts the invariants every accepted datagram must satisfy,
// regardless of which entry point opened it.
func checkDecrypted(t *testing.T, packet []byte, msg *Message) {
	t.Helper()
	if msg == nil {
		t.Fatal("accepted packet returned a nil message")
	}
	if len(packet) < HeaderSize || len(packet) > PacketBufferSize {
		t.Fatalf("accepted a %d-byte packet outside [%d, %d]", len(packet), HeaderSize, PacketBufferSize)
	}
	if major, _ := getVersion(packet); major != protocolVersionMajor {
		t.Fatalf("accepted protocol major version %d, want %d", major, protocolVersionMajor)
	}
	if msg.Type < 0 || msg.Type > 0xffff {
		t.Fatalf("accepted header type %d outside the 16-bit wire field", msg.Type)
	}
	if msg.Flags != getFlag(packet) || msg.Counter != getCounter(packet) {
		t.Fatalf("message metadata (%#04x/%d) does not match the header (%#04x/%d)",
			msg.Flags, msg.Counter, getFlag(packet), getCounter(packet))
	}
	if len(msg.Body) > PacketBufferSize {
		t.Fatalf("accepted a %d-byte body past the %d-byte buffer", len(msg.Body), PacketBufferSize)
	}
	if msg.Flags&nhpFlagCompress == 0 {
		// Uncompressed: the body is exactly the sealed trailer minus its tag, so
		// it can never exceed the plaintext ceiling.
		want := 0
		if len(packet) > HeaderSize {
			want = len(packet) - HeaderSize - gcmTagSize
		}
		if len(msg.Body) != want {
			t.Fatalf("uncompressed body = %d bytes, want %d", len(msg.Body), want)
		}
		if len(msg.Body) > maxApplicationBodySize {
			t.Fatalf("uncompressed body = %d bytes, past the %d-byte ceiling", len(msg.Body), maxApplicationBodySize)
		}
	}
}

// FuzzDecryptMessage drives the generic codec, which applies no header-type gate:
// any authenticated type may come back, so the invariants here are the framing,
// version, and body bounds only.
func FuzzDecryptMessage(f *testing.F) {
	addFuzzSeeds(f)
	agentPriv, _ := fuzzKeyPair(f, 0x11)
	_, serverPub := fuzzKeyPair(f, 0x22)
	f.Fuzz(func(t *testing.T, packet []byte) {
		msg, err := DecryptMessage(agentPriv, serverPub, packet)
		if err != nil {
			if msg != nil {
				t.Fatalf("rejected packet returned a message: %#v", msg)
			}
			return
		}
		checkDecrypted(t, packet, msg)
	})
}

// FuzzDecryptReplyMessage adds the reply profile: an accepted datagram must carry
// one of the four reply types and an in-profile flag word.
func FuzzDecryptReplyMessage(f *testing.F) {
	addFuzzSeeds(f)
	agentPriv, _ := fuzzKeyPair(f, 0x11)
	_, serverPub := fuzzKeyPair(f, 0x22)
	f.Fuzz(func(t *testing.T, packet []byte) {
		msg, err := DecryptReplyMessage(agentPriv, serverPub, packet)
		if err != nil {
			if msg != nil {
				t.Fatalf("rejected packet returned a message: %#v", msg)
			}
			return
		}
		checkDecrypted(t, packet, msg)
		switch msg.Type {
		case TypeACK, TypeLRT, TypeCOK, TypeRAK:
		default:
			t.Fatalf("accepted header type %d as a server reply", msg.Type)
		}
		if msg.Flags != 0 && msg.Flags != nhpFlagCompress {
			t.Fatalf("accepted reply flags %#04x outside the profile", msg.Flags)
		}
	})
}

// FuzzPacketType drives the cleartext framing validator behind the public
// RelayPost escape hatch. It reads only the obfuscated type/size word, so the
// invariant is that acceptance implies a self-consistent frame.
func FuzzPacketType(f *testing.F) {
	addFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, packet []byte) {
		typ, err := PacketType(packet)
		if err != nil {
			if typ != 0 {
				t.Fatalf("rejected packet returned type %d alongside the error", typ)
			}
			return
		}
		if len(packet) < HeaderSize || len(packet) > PacketBufferSize {
			t.Fatalf("accepted a %d-byte packet outside [%d, %d]", len(packet), HeaderSize, PacketBufferSize)
		}
		declaredType, declaredSize := getTypeAndPayloadSize(packet)
		if typ != declaredType {
			t.Fatalf("returned type %d, want the declared %d", typ, declaredType)
		}
		if declaredSize != len(packet)-HeaderSize {
			t.Fatalf("accepted declared payload size %d against %d trailing bytes", declaredSize, len(packet)-HeaderSize)
		}
		if typ < 0 || typ > 0xffff {
			t.Fatalf("returned type %d outside the 16-bit wire field", typ)
		}
	})
}
