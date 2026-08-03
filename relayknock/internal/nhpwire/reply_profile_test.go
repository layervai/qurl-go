package nhpwire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestAcceptReplyMessage_FlagProfile pins the admitted flag words per reply type
// directly on the gate, including the body wipe on every rejection. Both 0 and
// compress are live on the wire — the reference responder compresses NHP_ACK,
// NHP_RAK, NHP_LRT and the overload NHP_COK unconditionally, while the Hub
// assignment NHP_COK/NHP_LRT are uncompressed — so a gate that admitted only one
// of the two would fail against a real server.
func TestAcceptReplyMessage_FlagProfile(t *testing.T) {
	tests := []struct {
		name       string
		headerType int
		flags      uint16
		wantSub    string // empty ⇒ accepted
	}{
		{name: "uncompressed ack", headerType: TypeACK},
		{name: "compressed ack", headerType: TypeACK, flags: nhpFlagCompress},
		{name: "uncompressed list result", headerType: TypeLRT},
		{name: "compressed list result", headerType: TypeLRT, flags: nhpFlagCompress},
		{name: "uncompressed cookie challenge", headerType: TypeCOK},
		{name: "compressed cookie challenge", headerType: TypeCOK, flags: nhpFlagCompress},
		{name: "uncompressed register ack", headerType: TypeRAK},
		{name: "compressed register ack", headerType: TypeRAK, flags: nhpFlagCompress},

		// The proof bit is initiator-only; it must never ride a reply.
		{name: "proof flag on an ack", headerType: TypeACK, flags: hubLSTCookieProofFlag, wantSub: "outside the reply profile"},
		{name: "proof flag on a cookie challenge", headerType: TypeCOK, flags: hubLSTCookieProofFlag, wantSub: "outside the reply profile"},
		{name: "unknown flag on a list result", headerType: TypeLRT, flags: 1 << 3, wantSub: "outside the reply profile"},
		{name: "compress combined with the proof flag", headerType: TypeRAK, flags: nhpFlagCompress | hubLSTCookieProofFlag, wantSub: "outside the reply profile"},

		{name: "initiator type", headerType: TypeKNK, wantSub: "is not a server reply"},
		{name: "unknown type", headerType: 99, flags: nhpFlagCompress, wantSub: "is not a server reply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("authenticated reply plaintext")
			msg, err := acceptReplyMessage(&Message{Type: tt.headerType, Flags: tt.flags, Body: body})
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("acceptReplyMessage = %v, want accept", err)
				}
				if msg == nil || !bytes.Equal(msg.Body, body) {
					t.Fatalf("accepted reply lost its body: %#v", msg)
				}
				return
			}
			if err == nil || msg != nil {
				t.Fatalf("acceptReplyMessage = %#v, %v; want rejection", msg, err)
			}
			if !errors.Is(err, ErrMalformedReply) {
				t.Errorf("error %q is not ErrMalformedReply; a consumer taxonomy cannot map it", err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
			if !bytes.Equal(body, make([]byte, len(body))) {
				t.Errorf("rejected reply retained plaintext body: %x", body)
			}
		})
	}

	t.Run("nil message", func(t *testing.T) {
		msg, err := acceptReplyMessage(nil)
		if msg != nil || !errors.Is(err, ErrMalformedReply) {
			t.Fatalf("acceptReplyMessage(nil) = %#v, %v; want a nil message and ErrMalformedReply", msg, err)
		}
	})
}

// TestDecryptReplyMessage_RejectsOutOfProfileFlagsEndToEnd drives the same gate
// through a real authenticated packet rather than a hand-built Message, so the
// flag word actually travels on the wire and is read back by getFlag. An
// out-of-profile flag word survives the AEAD chain untouched (it is not folded
// into any AAD), so only this gate stops it.
func TestDecryptReplyMessage_RejectsOutOfProfileFlagsEndToEnd(t *testing.T) {
	agentPriv, agentPub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)

	build := func(t *testing.T, flags uint16) []byte {
		t.Helper()
		packet, err := BuildReplyWithFlagsForTest(TypeACK, flags, &Inputs{
			DeviceStaticPriv: serverPriv, // role-swapped: the server initiates the reply
			ServerStaticPub:  agentPub,
			EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
			TimestampNanos:   1700000000123456789,
			Counter:          0x1234,
			Preamble:         0xa1b2c3d4,
			Body:             []byte(`{"errCode":"0"}`),
		})
		if err != nil {
			t.Fatalf("build reply with flags %#04x: %v", flags, err)
		}
		if got := getFlag(packet); got != flags {
			t.Fatalf("built reply carries flags %#04x, want %#04x", got, flags)
		}
		return packet
	}

	for _, flags := range []uint16{0, nhpFlagCompress} {
		if _, err := DecryptReplyMessage(agentPriv, serverPub, build(t, flags)); err != nil {
			t.Fatalf("in-profile flags %#04x were rejected: %v", flags, err)
		}
	}
	for _, flags := range []uint16{hubLSTCookieProofFlag, 1 << 3, nhpFlagCompress | hubLSTCookieProofFlag} {
		msg, err := DecryptReplyMessage(agentPriv, serverPub, build(t, flags))
		if err == nil || msg != nil {
			t.Fatalf("DecryptReplyMessage(flags %#04x) = %#v, %v; want rejection", flags, msg, err)
		}
		if !errors.Is(err, ErrMalformedReply) {
			t.Errorf("flags %#04x rejected as %q, want ErrMalformedReply", flags, err)
		}
	}
}

// TestDecryptCookieMessages_RejectWrongCookieLength pins the receive-side cookie
// length guards. They run before any parsing, so a wrong-length cookie is
// refused without the packet being touched at all — asserted here by passing a
// nil packet, which would otherwise trip the length check inside decryptMessage
// and report a different error.
func TestDecryptCookieMessages_RejectWrongCookieLength(t *testing.T) {
	devicePriv, _ := keyPair(t, 0x11)
	_, serverPub := keyPair(t, 0x22)

	openers := []struct {
		name    string
		open    func(cookie []byte) (*Message, error)
		wantSub string
	}{
		{
			name: "reknock",
			open: func(cookie []byte) (*Message, error) {
				return DecryptReknockMessage(devicePriv, serverPub, cookie, nil)
			},
			wantSub: "RKN cookie must be 32 bytes",
		},
		{
			name: "hub LST cookie proof",
			open: func(cookie []byte) (*Message, error) {
				return DecryptHubLSTCookieProofMessage(devicePriv, serverPub, cookie, nil)
			},
			wantSub: "hub LST proof cookie must be 32 bytes",
		},
	}
	cookies := []struct {
		name   string
		cookie []byte
	}{
		{name: "nil", cookie: nil},
		{name: "empty", cookie: []byte{}},
		{name: "one byte short", cookie: bytes.Repeat([]byte{0x44}, CookieSize-1)},
		{name: "one byte long", cookie: bytes.Repeat([]byte{0x44}, CookieSize+1)},
	}
	for _, opener := range openers {
		for _, c := range cookies {
			t.Run(opener.name+"/"+c.name, func(t *testing.T) {
				msg, err := opener.open(c.cookie)
				if err == nil || msg != nil {
					t.Fatalf("open with a %d-byte cookie = %#v, %v; want rejection", len(c.cookie), msg, err)
				}
				if !strings.Contains(err.Error(), opener.wantSub) {
					t.Errorf("error %q does not contain %q", err, opener.wantSub)
				}
			})
		}
	}
}

// TestReplyHeaderFlagsAreAuthenticated is the regression fence for the protocol
// 1.1 HeaderCommon AAD binding, and the exact probe that demonstrated the 1.0
// defect it closes.
//
// Under 1.0 the flag word rode outside the AEAD chain: the seal folded
// initialHash ‖ peerStaticPub ‖ ephemeralPub ‖ sealedStatic ‖ sealedTs and never
// the header, so the only thing covering the flags was the UNKEYED BLAKE2s
// header digest, whose inputs are all public. An off-path attacker holding the
// agent's static PUBLIC key could clear the compress bit on a legitimately
// compressed reply, re-stamp the digest, and have the packet still open — the
// agent then surfaced the raw zlib stream as the application body, and a JSON
// consumer failed on bytes the server never sent. No secret was needed and the
// AEAD tags never moved.
//
// Since 1.1 the serialized HeaderCommon is folded into the chain hash before the
// body AAD, so the identical probe changes the AAD and the body Open fails. The
// probe is kept verbatim rather than deleted: it is the only thing that proves
// the binding is load-bearing rather than incidental.
func TestReplyHeaderFlagsAreAuthenticated(t *testing.T) {
	agentPriv, agentPub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	plaintext := []byte(`{"errCode":"0","resHost":{"r_agent":"198.51.100.7"},"opnTime":120}`)

	honest, err := BuildReplyWithFlagsForTest(TypeACK, nhpFlagCompress, &Inputs{
		DeviceStaticPriv: serverPriv, // role-swapped: the server initiates the reply
		ServerStaticPub:  agentPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          0x1122334455667788,
		Preamble:         0xa1b2c3d4,
		Body:             plaintext,
	})
	if err != nil {
		t.Fatalf("build compressed NHP_ACK: %v", err)
	}
	if getFlag(honest) != nhpFlagCompress {
		t.Fatalf("fixture flags = %#04x, want %#04x", getFlag(honest), nhpFlagCompress)
	}

	// The honest packet opens to exactly what the server sealed. This assertion
	// predates the AAD change and must survive it unaltered: binding the header
	// must not cost a conforming reply.
	opened, err := DecryptReplyMessage(agentPriv, serverPub, honest)
	if err != nil {
		t.Fatalf("honest compressed NHP_ACK did not open: %v", err)
	}
	if !bytes.Equal(opened.Body, plaintext) {
		t.Fatalf("honest body = %q, want %q", opened.Body, plaintext)
	}

	// The probe: clear the compress bit and re-stamp the digest using ONLY the
	// agent's public key. Nothing else in the packet is touched.
	tampered := bytes.Clone(honest)
	setFlag(tampered[:HeaderSize], 0)
	copy(tampered[offDigest:offDigest+hashSize], headerDigest(agentPub, tampered[:HeaderSize], nil))
	if getFlag(tampered) != 0 {
		t.Fatalf("tampered flags = %#04x, want 0", getFlag(tampered))
	}
	// The digest gate must NOT be what rejects this — re-stamping defeats it. The
	// rejection has to come from the body AEAD, which is the whole point.
	if !bytes.Equal(headerDigest(agentPub, tampered[:HeaderSize], nil), tampered[offDigest:offDigest+hashSize]) {
		t.Fatal("probe left a stale header digest; it would be rejected by the digest gate, not the AAD")
	}

	tamperedMsg, err := DecryptReplyMessage(agentPriv, serverPub, tampered)
	if err == nil {
		t.Fatalf("tampered reply opened to %q; the flag word is not bound into the body AAD", tamperedMsg.Body)
	}
	if tamperedMsg != nil {
		t.Fatalf("rejected reply returned a message alongside the error: %#v", tamperedMsg)
	}
	// Specifically the body Open, not the digest, the version, or the reply
	// profile — those would each mean the probe stopped reaching the binding.
	if !strings.Contains(err.Error(), "open body") {
		t.Fatalf("tampered reply rejected as %q, want the body AEAD open to fail", err)
	}
}

// TestHeaderCommonFieldsAreBoundIntoBodyAAD extends the flag-word fence above to
// the rest of HeaderCommon. Under 1.0 every one of these fields was forgeable in
// flight by anyone holding the agent's static public key; the header type in
// particular decided which consumer parsed the body. Each subcase edits exactly
// one field of a valid reply and re-stamps the digest, so the unkeyed digest
// gate is defeated on purpose and the body AEAD is the only guard left.
func TestHeaderCommonFieldsAreBoundIntoBodyAAD(t *testing.T) {
	agentPriv, agentPub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)
	plaintext := []byte(`{"errCode":"0","opnTime":120}`)

	const (
		fixtureCounter  = 0x1122334455667788
		fixturePreamble = 0xa1b2c3d4
	)
	honest, err := BuildMessage(TypeACK, &Inputs{
		DeviceStaticPriv: serverPriv, // role-swapped: the server initiates the reply
		ServerStaticPub:  agentPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x44}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          fixtureCounter,
		Preamble:         fixturePreamble,
		Body:             plaintext,
	})
	if err != nil {
		t.Fatalf("build NHP_ACK: %v", err)
	}
	if _, err := DecryptReplyMessage(agentPriv, serverPub, honest); err != nil {
		t.Fatalf("honest NHP_ACK did not open, so no subcase below proves anything: %v", err)
	}
	honestType, honestSize := getTypeAndPayloadSize(honest)
	if honestType != TypeACK || honestSize != len(honest)-HeaderSize {
		t.Fatalf("fixture header decodes as type %d size %d, want %d and %d", honestType, honestSize, TypeACK, len(honest)-HeaderSize)
	}

	tests := []struct {
		name    string
		tamper  func(pkt []byte)
		wantSub string // which guard must reject it; "open body" ⇒ the new binding
	}{
		{
			// NHP_ACK -> NHP_LRT: the type selects which consumer parses the
			// authenticated body, so forging it redirected a real reply.
			name:    "header type",
			tamper:  func(pkt []byte) { setTypeAndPayloadSize(pkt, TypeLRT, honestSize, fixturePreamble) },
			wantSub: "open body",
		},
		{
			// The declared size is what a responder frames on; decryptMessage
			// deliberately does not cross-check it, so only the AAD covers it.
			name:    "declared payload size",
			tamper:  func(pkt []byte) { setTypeAndPayloadSize(pkt, TypeACK, honestSize-1, fixturePreamble) },
			wantSub: "open body",
		},
		{
			// Re-obfuscate under a different preamble, leaving the decoded type
			// and size identical — only the two literal words change.
			name:    "preamble",
			tamper:  func(pkt []byte) { setTypeAndPayloadSize(pkt, TypeACK, honestSize, fixturePreamble^0xffffffff) },
			wantSub: "open body",
		},
		{
			// A minor ABOVE the floor clears the version gate, so the AAD is what
			// catches it. The gate itself is fenced by the version tests.
			name:    "protocol version minor",
			tamper:  func(pkt []byte) { setVersion(pkt, protocolVersionMajor, minProtocolVersionMinor+7) },
			wantSub: "open body",
		},
		{
			// The counter is the one HeaderCommon field that was never forgeable:
			// it derives the GCM nonce, so editing it breaks the FIRST seal in the
			// chain and never reaches the body. Pinned at that earlier guard
			// rather than dropped, so a future nonce change that decouples the two
			// shows up here instead of silently leaving the field to the AAD alone.
			name:    "counter",
			tamper:  func(pkt []byte) { setCounter(pkt, fixtureCounter+1) },
			wantSub: "open server static",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := bytes.Clone(honest)
			tt.tamper(tampered[:HeaderSize])
			if bytes.Equal(tampered[:headerCommonSize], honest[:headerCommonSize]) {
				t.Fatal("tamper left HeaderCommon unchanged; the subcase proves nothing")
			}
			// Re-stamp so the unkeyed digest gate passes, exactly as an off-path
			// attacker holding only the agent's public key would.
			copy(tampered[offDigest:offDigest+hashSize], headerDigest(agentPub, tampered[:HeaderSize], nil))

			msg, err := DecryptReplyMessage(agentPriv, serverPub, tampered)
			if err == nil || msg != nil {
				t.Fatalf("tampered %s accepted: %#v, %v", tt.name, msg, err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("tampered %s rejected as %q, want an AEAD failure containing %q", tt.name, err, tt.wantSub)
			}
		})
	}
}
