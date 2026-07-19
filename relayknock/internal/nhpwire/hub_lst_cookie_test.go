package nhpwire

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func hubCookieHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

func TestHubLSTCookieProofDigestKAT(t *testing.T) {
	fixture, err := conformance.ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	kat := fixture.ProofDigestKAT
	prefix := hubCookieHex(t, kat.HeaderPrefixHex)
	hubPublic := hubCookieHex(t, kat.HubServerStaticPublicKeyHex)
	cookie := hubCookieHex(t, kat.RawCookieHex)
	got := headerDigest(hubPublic, prefix, cookie)
	if hex.EncodeToString(got) != kat.ExpectedDigestHex {
		t.Fatalf("proof digest = %x, want %s", got, kat.ExpectedDigestHex)
	}
	if getFlag(prefix) != conformance.ConnectorHubLSTCookieProofFlag {
		t.Fatalf("proof flag = %#04x, want %#04x", getFlag(prefix), conformance.ConnectorHubLSTCookieProofFlag)
	}
}

func TestBuildHubLSTCookieProofConsumesAssignmentFlows(t *testing.T) {
	fixture, err := conformance.ConnectorHubLSTCookie()
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := conformance.AgentAssignmentGolden()
	if err != nil {
		t.Fatal(err)
	}
	agentPrivate := hubCookieHex(t, assignment.Keys.Agent.StaticPrivHex)
	agentPublic := hubCookieHex(t, assignment.Keys.Agent.StaticPubHex)
	hubPrivate := hubCookieHex(t, assignment.Keys.Hub.StaticPrivHex)
	hubPublic := hubCookieHex(t, assignment.Keys.Hub.StaticPubHex)
	cookie := hubCookieHex(t, fixture.CookieKATs[0].CookieHex)

	for index, flow := range fixture.Flows {
		t.Run(flow.Phase, func(t *testing.T) {
			unprovenCounter, err := strconv.ParseUint(flow.UnprovenCounter, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			counter, err := strconv.ParseUint(flow.ProofCounter, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			unprovenFlags, err := strconv.ParseUint(flow.UnprovenHeaderFlagsHex, 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			proofFlags, err := strconv.ParseUint(flow.ProofHeaderFlagsHex, 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			unprovenPacket, err := BuildMessage(TypeLST, &Inputs{
				DeviceStaticPriv: agentPrivate,
				ServerStaticPub:  hubPublic,
				EphemeralPriv:    bytes.Repeat([]byte{byte(0x40 + index)}, PublicKeySize),
				TimestampNanos:   1700000000000001000 + uint64(index),
				Counter:          unprovenCounter,
				Preamble:         uint32(0x8192a3b4 + index),
				Body:             []byte(flow.UnprovenBodyJSON),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(unprovenPacket) != flow.UnprovenRequestPacketBytes || uint64(getFlag(unprovenPacket)) != unprovenFlags {
				t.Fatalf("unproven packet size/flags = %d/%#04x, want %d/%#04x", len(unprovenPacket), getFlag(unprovenPacket), flow.UnprovenRequestPacketBytes, unprovenFlags)
			}
			unproven, err := DecryptMessage(hubPrivate, agentPublic, unprovenPacket)
			if err != nil {
				t.Fatal(err)
			}
			if unproven.Type != TypeLST || unproven.Counter != unprovenCounter || string(unproven.Body) != flow.UnprovenBodyJSON {
				t.Fatalf("opened unproven assignment = %#v", unproven)
			}
			packet, err := BuildHubLSTCookieProof(&Inputs{
				DeviceStaticPriv: agentPrivate,
				ServerStaticPub:  hubPublic,
				EphemeralPriv:    bytes.Repeat([]byte{byte(0x60 + index)}, PublicKeySize),
				TimestampNanos:   1700000000000003000 + uint64(index),
				Counter:          counter,
				Preamble:         uint32(0xa1b2c3d4 + index),
				Body:             []byte(flow.ProofBodyJSON),
				Cookie:           cookie,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(packet) != flow.ProofRequestPacketBytes || uint64(getFlag(packet)) != proofFlags {
				t.Fatalf("proof packet size/flags = %d/%#04x, want %d/%#04x", len(packet), getFlag(packet), flow.ProofRequestPacketBytes, proofFlags)
			}
			opened, err := DecryptHubLSTCookieProofMessage(hubPrivate, agentPublic, cookie, packet)
			if err != nil {
				t.Fatal(err)
			}
			if opened.Type != TypeLST || opened.Counter != counter || string(opened.Body) != flow.UnprovenBodyJSON || flow.ProofBodyJSON != flow.UnprovenBodyJSON {
				t.Fatalf("opened proof/body linkage = %#v", opened)
			}
			wrongCookie := bytes.Clone(cookie)
			wrongCookie[0] ^= 0xff
			if _, err := DecryptHubLSTCookieProofMessage(hubPrivate, agentPublic, wrongCookie, packet); err == nil {
				t.Fatal("proof opened with a different Hub cookie")
			}
		})
	}
}

func TestHubLSTCookieProofBuilderIsNarrow(t *testing.T) {
	devicePrivate, _ := keyPair(t, 0x11)
	_, serverPublic := keyPair(t, 0x22)
	inputs := &Inputs{
		DeviceStaticPriv: devicePrivate,
		ServerStaticPub:  serverPublic,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, PublicKeySize),
		TimestampNanos:   1,
		Counter:          2,
		Preamble:         3,
		Body:             []byte("assignment"),
	}
	if _, err := BuildHubLSTCookieProof(inputs); err == nil {
		t.Fatal("proof builder accepted a missing cookie")
	}
	inputs.Cookie = bytes.Repeat([]byte{0x44}, CookieSize)
	if _, err := BuildMessage(TypeLST, inputs); err == nil {
		t.Fatal("ordinary LST builder accepted a proof cookie")
	}
}

func TestAcceptHubLSTCookieProofMessageWipesRejectedBody(t *testing.T) {
	for _, test := range []struct {
		name  string
		typ   int
		flags uint16
	}{
		{name: "ordinary LST", typ: TypeLST, flags: 0},
		{name: "wrong type", typ: TypeRKN, flags: hubLSTCookieProofFlag},
		{name: "combined flags", typ: TypeLST, flags: hubLSTCookieProofFlag | nhpFlagCompress},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("authenticated-proof-plaintext")
			if msg, err := acceptHubLSTCookieProofMessage(&Message{Type: test.typ, Flags: test.flags, Body: body}); msg != nil || err == nil {
				t.Fatalf("accepted proof = %#v, %v; want rejection", msg, err)
			}
			if !bytes.Equal(body, make([]byte, len(body))) {
				t.Fatalf("rejected proof retained plaintext body: %x", body)
			}
		})
	}
}
