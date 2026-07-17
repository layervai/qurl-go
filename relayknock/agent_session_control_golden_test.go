package relayknock

import (
	"bytes"
	"encoding/hex"
	"testing"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// This file consumes the immutable qurl-conformance v0.6 session-control
// artifact through the shipping codec. It never copies the vectors into this
// repository: go.mod/go.sum pin the exact public module bytes.

func loadAgentSessionControlGolden(t *testing.T) *conformance.AgentSessionControlFile {
	t.Helper()
	f, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-session vectors: %v", err)
	}
	return f
}

func buildAgentSessionPacket(t *testing.T, f *conformance.AgentSessionControlFile, p conformance.AgentSessionPacket, cookie []byte) []byte {
	t.Helper()
	packet, err := BuildMessage(p.HeaderType, &KnockInputs{
		DeviceStaticPriv: mustHex(t, f.Keys.Agent.StaticPrivateHex),
		ServerStaticPub:  mustHex(t, f.Keys.AssignedCell.StaticPublicHex),
		EphemeralPriv:    mustHex(t, p.EphemeralPrivateHex),
		TimestampNanos:   mustDecimalU64(t, p.TimestampNanos),
		Counter:          mustDecimalU64(t, p.Counter),
		Preamble:         mustHexU32(t, p.PreambleHex),
		Body:             mustHex(t, p.BodyHex),
		Cookie:           cookie,
	})
	if err != nil {
		t.Fatalf("BuildMessage(%s): %v", p.HeaderName, err)
	}
	return packet
}

func TestBuildMessage_AgentSessionControlGolden(t *testing.T) {
	f := loadAgentSessionControlGolden(t)
	cookie := mustHex(t, f.OverloadReknock.CookieHex)
	for _, tc := range []struct {
		name   string
		packet conformance.AgentSessionPacket
		cookie []byte
	}{
		{name: "knock", packet: f.OverloadReknock.KnockRequest},
		{name: "reknock", packet: f.OverloadReknock.ReknockRequest, cookie: cookie},
		{name: "exit", packet: f.CleanExit.Request},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := buildAgentSessionPacket(t, f, tc.packet, tc.cookie)
			if got := hex.EncodeToString(packet); got != tc.packet.PacketHex {
				t.Fatalf("%s packet mismatch:\n got=%s\nwant=%s", tc.name, got, tc.packet.PacketHex)
			}
		})
	}
}

func TestDecryptReply_AgentSessionControlGolden(t *testing.T) {
	f := loadAgentSessionControlGolden(t)
	for _, tc := range []struct {
		name   string
		packet conformance.AgentSessionPacket
	}{
		{name: "cookie", packet: f.OverloadReknock.CookieReply},
		{name: "reknock ack", packet: f.OverloadReknock.ACK},
		{name: "exit ack", packet: f.CleanExit.ACK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply, err := DecryptReply(
				mustHex(t, f.Keys.Agent.StaticPrivateHex),
				mustHex(t, f.Keys.AssignedCell.StaticPublicHex),
				mustHex(t, tc.packet.PacketHex),
			)
			if err != nil {
				t.Fatalf("DecryptReply: %v", err)
			}
			if reply.Type != tc.packet.HeaderType || reply.Counter != mustDecimalU64(t, tc.packet.Counter) ||
				reply.TimestampNanos != mustDecimalU64(t, tc.packet.TimestampNanos) ||
				!bytes.Equal(reply.Body, mustHex(t, tc.packet.BodyHex)) {
				t.Fatalf("opened reply = type:%d counter:%d timestamp:%d body:%x", reply.Type, reply.Counter, reply.TimestampNanos, reply.Body)
			}
		})
	}
}

func TestOpenReknockMessage_AgentSessionControlGolden(t *testing.T) {
	f := loadAgentSessionControlGolden(t)
	p := f.OverloadReknock.ReknockRequest
	packet := mustHex(t, p.PacketHex)
	cookie := mustHex(t, f.OverloadReknock.CookieHex)
	reply, err := nhpwire.DecryptReknockMessage(
		mustHex(t, f.Keys.AssignedCell.StaticPrivateHex),
		mustHex(t, f.Keys.Agent.StaticPublicHex),
		cookie,
		packet,
	)
	if err != nil {
		t.Fatalf("OpenReknockMessage: %v", err)
	}
	if reply.Type != TypeReknock || reply.Counter != mustDecimalU64(t, p.Counter) || !bytes.Equal(reply.Body, mustHex(t, p.BodyHex)) {
		t.Fatalf("opened reknock = type:%d counter:%d body:%x", reply.Type, reply.Counter, reply.Body)
	}

	wrongCookie := append([]byte(nil), cookie...)
	wrongCookie[0] ^= 1
	if _, err := nhpwire.DecryptReknockMessage(
		mustHex(t, f.Keys.AssignedCell.StaticPrivateHex),
		mustHex(t, f.Keys.Agent.StaticPublicHex),
		wrongCookie,
		packet,
	); err == nil {
		t.Fatal("OpenReknockMessage accepted a different cookie")
	}
}

func TestBuildMessage_AgentSessionCookieContract(t *testing.T) {
	f := loadAgentSessionControlGolden(t)
	p := f.OverloadReknock.ReknockRequest
	base := &KnockInputs{
		DeviceStaticPriv: mustHex(t, f.Keys.Agent.StaticPrivateHex),
		ServerStaticPub:  mustHex(t, f.Keys.AssignedCell.StaticPublicHex),
		EphemeralPriv:    mustHex(t, p.EphemeralPrivateHex),
		TimestampNanos:   mustDecimalU64(t, p.TimestampNanos),
		Counter:          mustDecimalU64(t, p.Counter),
		Preamble:         mustHexU32(t, p.PreambleHex),
		Body:             mustHex(t, p.BodyHex),
	}
	for _, size := range []int{0, nhpwire.CookieSize - 1, nhpwire.CookieSize + 1} {
		copyInputs := *base
		copyInputs.Cookie = make([]byte, size)
		if _, err := BuildMessage(TypeReknock, &copyInputs); err == nil {
			t.Fatalf("BuildMessage(TypeReknock) accepted %d-byte cookie", size)
		}
	}
	copyInputs := *base
	copyInputs.Cookie = make([]byte, nhpwire.CookieSize)
	if _, err := BuildMessage(TypeExit, &copyInputs); err == nil {
		t.Fatal("BuildMessage(TypeExit) accepted an RKN cookie")
	}
}
