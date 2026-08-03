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

// TestReplyCompressFlagIsUnauthenticated is a REGRESSION FENCE OVER A KNOWN,
// UNFIXED DEFECT, not a test of desired behavior.
//
// The header flag word rides outside the AEAD chain. buildMessageUnchecked folds
// initialHash ‖ peerStaticPub ‖ ephemeralPub ‖ sealedStatic ‖ sealedTs and never
// the flags, so the only thing covering them is the UNKEYED BLAKE2s header
// digest, whose inputs are all public: an off-path attacker who knows the agent's
// static PUBLIC key (it is public by construction) can flip a flag bit, recompute
// the digest, and hand the agent a packet that still opens. No secret is needed
// and the AEAD tags never move.
//
// The consequence proved below: clearing the compress bit on a legitimately
// compressed reply makes the agent surface the raw zlib stream as if it were the
// application body. A JSON consumer then fails on bytes the server never sent.
//
// THE FIX IS TO FOLD THE HEADER (INCLUDING THE FLAG WORD) INTO THE AEAD AAD. That
// is a breaking wire change requiring an ordered release with the NHP server and
// re-derived conformance vectors, so it is deliberately deferred and NOT
// mitigated here — a receive-side shape check on the body would pattern-match the
// consequence without authenticating the field, which is not a fix.
//
// WHEN THE AAD CHANGE LANDS this test must flip: the block marked CURRENT
// BEHAVIOR below becomes "DecryptReplyMessage returns an error and a nil
// message", and the honest-packet assertions stay exactly as they are.
func TestReplyCompressFlagIsUnauthenticated(t *testing.T) {
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
	// is permanent — the AAD change must not alter it.
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

	// ---- CURRENT BEHAVIOR (the defect) — flip this block when the AAD lands ----
	tamperedMsg, err := DecryptReplyMessage(agentPriv, serverPub, tampered)
	if err != nil {
		t.Fatalf("tampered reply was rejected: %v\n"+
			"If the header is now folded into the AEAD AAD, this defect is FIXED — "+
			"replace this block with an assertion that the rejection happened and "+
			"that no message is returned.", err)
	}
	if bytes.Equal(tamperedMsg.Body, plaintext) {
		t.Fatal("tampered reply yielded the honest plaintext; the probe no longer reproduces the defect")
	}
	// What the caller receives instead is the undecompressed zlib stream: 0x78 is
	// the RFC 1950 CMF for deflate with a 32K window. Inflating it recovers the
	// honest plaintext exactly, which is what makes this a real exposure and not
	// just corruption — the agent hands its consumer the server's payload in the
	// wrong encoding, and a JSON parse fails on bytes the server never sent.
	if len(tamperedMsg.Body) == 0 || tamperedMsg.Body[0] != 0x78 {
		t.Fatalf("tampered body = %x, want the raw zlib stream the server sealed", tamperedMsg.Body)
	}
	if inflated, err := inflateZlib(bytes.Clone(tamperedMsg.Body)); err != nil || !bytes.Equal(inflated, plaintext) {
		t.Fatalf("tampered body did not inflate to the honest plaintext: %q, %v", inflated, err)
	}
	// ---- end CURRENT BEHAVIOR ----
}
