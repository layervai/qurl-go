// Package relayknocktest provides the server/responder-role NHP wire helpers a
// test double (or cross-language conformance tooling) needs to stand in for an
// NHP relay+server: build a server-originated reply, and open an initiator
// packet an agent posted. They are the mirrors of the public initiator API in
// relayknock (BuildMessage / DecryptReply) and are deliberately kept OUT of that
// package — a client SDK's public surface should not ship responder-role wire
// operations. Like net/http/httptest, this is a test-support package that sits
// beside the package it supports.
//
// Both helpers speak the same role-symmetric transcript relayknock uses, so a
// reply built here opens under relayknock.DecryptReply and an initiator packet
// built by relayknock opens here — the wire bytes are fenced by the same golden
// vectors.
package relayknocktest

import (
	"fmt"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// BuildReply builds a complete server-originated NHP reply packet (240-byte
// header ‖ sealed body) for a supported reply type. Those types are
// relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge,
// and relayknock.TypeRegisterAck. It is the responder-role mirror of
// relayknock.BuildMessage: an agent never builds these, so relayknock's public
// builder rejects them. A server or conformance/test double that must answer a
// knock, list/query request, or registration builds them here. The transcript is
// role-symmetric (only the obfuscated type field differs), so a reply built here
// decrypts under relayknock.DecryptReply against the server's static key exactly
// as a real server reply would.
//
// Set inp.DeviceStaticPriv to the SERVER static private key and inp.ServerStaticPub
// to the AGENT (initiator) static public key — the roles are swapped relative to a
// knock, because the reply is a fresh handshake the server initiates back to the
// agent. inp.Counter must echo the counter of the request being answered so the
// caller can enforce request/reply correlation.
func BuildReply(headerType int, inp *relayknock.KnockInputs) ([]byte, error) {
	switch headerType {
	case relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, relayknock.TypeRegisterAck:
		// Reuse relayknock's single KnockInputs → nhpwire.Inputs converter rather
		// than a second copy here: a missed field on this responder path was a real
		// past risk, so both paths share the one WireInputs source of truth.
		return nhpwire.BuildMessage(headerType, inp.WireInputs())
	default:
		return nil, fmt.Errorf("unsupported reply header type %d (want relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, or relayknock.TypeRegisterAck)", headerType)
	}
}

// BuildReplyWithFlags builds a server reply with an explicit header flag word
// for fail-closed consumer tests. Production responders use BuildReply. This
// helper cannot build initiator messages, including Hub assignment proof LST.
func BuildReplyWithFlags(headerType int, flags uint16, inp *relayknock.KnockInputs) ([]byte, error) {
	switch headerType {
	case relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, relayknock.TypeRegisterAck:
		return nhpwire.BuildReplyWithFlagsForTest(headerType, flags, inp.WireInputs())
	default:
		return nil, fmt.Errorf("unsupported reply header type %d", headerType)
	}
}

// OpenInitiatorMessage decrypts and authenticates an initiator packet in the
// responder role. It accepts NHP_KNK, NHP_LST, NHP_OTP, NHP_REG, and NHP_EXT:
// the open a server (or test double) performs on an agent packet. It mirrors
// relayknock.DecryptReply, which opens server replies from the initiator side;
// the two split the role-symmetric transcript by admitted header type.
//
// serverPriv is the responder (server) static private key; expectedDevicePub is
// the initiator (agent) static public key the caller expects. Only initiator
// header types are accepted: a reply type is rejected, so a Reply this returns
// always carries an initiator type. The returned Reply.Counter is the request's
// transaction id — a responder echoes it in the reply it builds with BuildReply.
func OpenInitiatorMessage(serverPriv, expectedDevicePub, packet []byte) (*relayknock.Reply, error) {
	msg, err := nhpwire.DecryptMessage(serverPriv, expectedDevicePub, packet)
	if err != nil {
		return nil, err
	}
	switch msg.Type {
	case relayknock.TypeKnock, relayknock.TypeListRequest, relayknock.TypeOTP, relayknock.TypeRegister, relayknock.TypeExit:
		return &relayknock.Reply{
			Type:           msg.Type,
			Counter:        msg.Counter,
			TimestampNanos: msg.TimestampNanos,
			Body:           msg.Body,
		}, nil
	default:
		return nil, fmt.Errorf("not an initiator message: header type %d is not an initiator type", msg.Type)
	}
}

// OpenReknockMessage decrypts and authenticates an NHP_RKN initiator packet in
// the responder role. cookie is the exact decoded 32-byte value previously sent
// in NHP_COK; a wrong cookie fails the header-digest gate before body opening.
func OpenReknockMessage(serverPriv, expectedDevicePub, cookie, packet []byte) (*relayknock.Reply, error) {
	msg, err := nhpwire.DecryptReknockMessage(serverPriv, expectedDevicePub, cookie, packet)
	if err != nil {
		return nil, err
	}
	if msg.Type != relayknock.TypeReknock {
		return nil, fmt.Errorf("not a re-knock message: header type %d is not TypeReknock", msg.Type)
	}
	return &relayknock.Reply{
		Type:           msg.Type,
		Counter:        msg.Counter,
		TimestampNanos: msg.TimestampNanos,
		Body:           msg.Body,
	}, nil
}

// OpenHubLSTCookieProofMessage decrypts the assignment-only proof LST using the
// exact cookie the test Hub returned in its authenticated COK. It rejects an
// ordinary LST, any non-exclusive flag combination, or a digest built with a
// different cookie.
func OpenHubLSTCookieProofMessage(serverPriv, expectedDevicePub, cookie, packet []byte) (*relayknock.Reply, error) {
	msg, err := nhpwire.DecryptHubLSTCookieProofMessage(serverPriv, expectedDevicePub, cookie, packet)
	if err != nil {
		return nil, err
	}
	return &relayknock.Reply{
		Type:           msg.Type,
		Counter:        msg.Counter,
		TimestampNanos: msg.TimestampNanos,
		Body:           msg.Body,
	}, nil
}
