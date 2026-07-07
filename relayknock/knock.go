package relayknock

import (
	"fmt"

	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// Public initiator API over the internal NHP wire codec (nhpwire). The
// role-symmetric seal/open transcript lives in nhpwire; this file adds the
// public KnockInputs/Reply types, the initiator type-gating (an agent builds
// only knock/OTP/register), and the reply-type gate on DecryptReply. The wire
// bytes are fenced by the golden vectors in knock_golden_test.go, which reach
// nhpwire through BuildKnock / DecryptReply here.

// KnockInputs are the per-knock values. They are injectable (rather than minted
// internally) so a caller can drive a deterministic golden vector and so the
// enterPortal path can knock as a specific device identity (the per-qURL key)
// rather than a fresh random one. In production, DeviceStaticPriv / EphemeralPriv
// / Counter / Preamble are random; see Knock.
type KnockInputs struct {
	DeviceStaticPriv []byte // initiator (agent) static private key, 32 bytes
	ServerStaticPub  []byte // responder (server) static public key, 32 bytes (rs)
	EphemeralPriv    []byte // per-knock ephemeral private key, 32 bytes
	TimestampNanos   uint64 // send time (time.Now().UnixNano())
	Counter          uint64 // transaction id
	Preamble         uint32 // HeaderCommon obfuscation preamble
	Body             []byte // serialized, uncompressed application knock body
}

// wireInputs converts the public KnockInputs into the nhpwire codec's Inputs.
func (k *KnockInputs) wireInputs() *nhpwire.Inputs {
	return &nhpwire.Inputs{
		DeviceStaticPriv: k.DeviceStaticPriv,
		ServerStaticPub:  k.ServerStaticPub,
		EphemeralPriv:    k.EphemeralPriv,
		TimestampNanos:   k.TimestampNanos,
		Counter:          k.Counter,
		Preamble:         k.Preamble,
		Body:             k.Body,
	}
}

// BuildKnock builds a complete NHP_KNK packet (240-byte header ‖ sealed body)
// that the reference NHP relay responder decrypts. It is BuildMessage fixed to
// TypeKnock.
func BuildKnock(inp *KnockInputs) ([]byte, error) {
	return nhpwire.BuildMessage(nhpwire.TypeKNK, inp.wireInputs())
}

// BuildMessage builds a complete NHP packet (240-byte header ‖ sealed body) of
// the given initiator header type: TypeKnock, TypeOTP, or TypeRegister. Any
// other type — in particular the server-originated reply types — fails closed:
// an agent never builds those, so rejecting them here keeps a type mix-up from
// reaching the wire. (A server or test double answering a knock builds reply
// types with relayknock/relayknocktest.BuildReply instead.)
//
// BuildMessage is for callers that carry the packet themselves — deterministic
// construction (golden vectors, conformance tooling) or a custom transport.
// Typical agents use Knock, Exchange, or Send, which mint the per-message
// randomness and speak the relay HTTP contract.
func BuildMessage(headerType int, inp *KnockInputs) ([]byte, error) {
	switch headerType {
	case TypeKnock, TypeOTP, TypeRegister:
		return nhpwire.BuildMessage(headerType, inp.wireInputs())
	default:
		return nil, fmt.Errorf("unsupported initiator header type %d (want TypeKnock, TypeOTP, or TypeRegister)", headerType)
	}
}

// Exported NHP initiator header-type values — the message types an agent can
// originate (BuildMessage, Exchange, Send). Every other type is
// server-originated and is rejected by the exported builders.
//
// Adding a message type deliberately touches three sites, which encode three
// DIFFERENT predicates and are kept inline rather than force-unified: this
// block plus BuildMessage's initiator set (what an agent may build),
// Exchange's round-trip set (what elicits a reply at all), and
// replyTypeAllowed's request→reply pairing (which reply each request may
// receive).
const (
	// TypeKnock is NHP_KNK: the initial knock requesting admission; the server
	// answers with an NHP_ACK (or an NHP_COK under overload).
	TypeKnock = nhpwire.TypeKNK
	// TypeOTP is NHP_OTP: the one-way registration-bootstrap message (the NHP
	// spec's agent one-time-password request). The server does not reply to OTP
	// messages; a conforming relay acknowledges dispatch at the HTTP layer
	// instead (see Send).
	TypeOTP = nhpwire.TypeOTP
	// TypeRegister is NHP_REG: the agent registration message; the server
	// answers with an NHP_RAK.
	TypeRegister = nhpwire.TypeREG
)

// Exported NHP reply header-type values, so a consumer can construct or assert a
// Reply.Type (e.g. in tests) without importing the internal wire constants. These
// are the only reply types the initiator messages above can elicit: a knock is
// answered with an NHP_ACK or NHP_COK, a registration with an NHP_RAK, and an
// OTP message is never answered at all.
const (
	// TypeACK is NHP_ACK: an authorized-admission reply carrying the application
	// payload in Body.
	TypeACK = nhpwire.TypeACK
	// TypeCookieChallenge is NHP_COK: an overload cookie-challenge.
	TypeCookieChallenge = nhpwire.TypeCOK
	// TypeRegisterAck is NHP_RAK: the reply to an NHP_REG registration message.
	TypeRegisterAck = nhpwire.TypeRAK
)

// Reply is a decrypted, authenticated NHP server reply (NHP_ACK / NHP_COK /
// NHP_RAK). Body is the decrypted application body; the caller interprets it
// (relayknock is body-shape agnostic).
type Reply struct {
	// Type is the NHP header type (TypeACK / TypeCookieChallenge /
	// TypeRegisterAck). Prefer IsACK / IsCookieChallenge / IsRegisterAck for
	// intent; the exported constants exist so a consumer can also construct a
	// Reply with a specific type.
	Type           int
	Counter        uint64
	TimestampNanos uint64
	Body           []byte
}

// IsACK reports whether the reply is an NHP_ACK (the authorized-admission reply
// whose body carries the application payload).
func (r *Reply) IsACK() bool { return r.Type == nhpwire.TypeACK }

// IsCookieChallenge reports whether the reply is an NHP_COK overload
// cookie-challenge. The NHP_RKN cookie-answer path is out of scope for a single
// resolve, so a caller treats this as "retry later".
func (r *Reply) IsCookieChallenge() bool { return r.Type == nhpwire.TypeCOK }

// IsRegisterAck reports whether the reply is an NHP_RAK — the server's reply to
// an NHP_REG registration message.
//
// DecryptReply only ever returns a reply type, so a Reply it produced matches
// exactly one of IsACK / IsCookieChallenge / IsRegisterAck.
func (r *Reply) IsRegisterAck() bool { return r.Type == nhpwire.TypeRAK }

// DecryptReply decrypts and authenticates a server reply (NHP_ACK / NHP_COK /
// NHP_RAK — the transcript does not depend on the header type) against the
// static key of the server we messaged. The server is the initiator of this
// fresh handshake. Authentication completes at the ss-keyed opens: only the
// real server's static private key yields a valid tag there.
//
// Only reply header types are accepted: an authenticated packet carrying an
// initiator type (KNK/OTP/REG) is rejected, so a Reply this returns always
// matches one Is* predicate. (Opening an initiator packet in the responder
// role — as the reference server does — is relayknock/relayknocktest's
// OpenInitiatorMessage.)
func DecryptReply(devicePriv, expectedServerStaticPub, packet []byte) (*Reply, error) {
	msg, err := nhpwire.DecryptMessage(devicePriv, expectedServerStaticPub, packet)
	if err != nil {
		return nil, err
	}
	switch msg.Type {
	case nhpwire.TypeACK, nhpwire.TypeCOK, nhpwire.TypeRAK:
		return &Reply{Type: msg.Type, Counter: msg.Counter, TimestampNanos: msg.TimestampNanos, Body: msg.Body}, nil
	default:
		return nil, fmt.Errorf("not a server reply: header type %d is initiator-only", msg.Type)
	}
}
