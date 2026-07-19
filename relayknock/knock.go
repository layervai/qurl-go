package relayknock

import (
	"fmt"

	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
)

// Public initiator API over the internal NHP wire codec (nhpwire). The
// role-symmetric seal/open transcript lives in nhpwire; this file adds the
// public KnockInputs/Reply types, the initiator type-gating (an agent builds
// only KNK/LST/RKN/OTP/REG/EXT), and the reply-type gate on DecryptReply. The
// wire bytes are fenced by the golden vectors in knock_golden_test.go, which
// reach nhpwire through BuildKnock / DecryptReply here.

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
	Cookie           []byte // exact 32-byte COK cookie for NHP_RKN; empty otherwise
}

// WireInputs converts the public KnockInputs into the nhpwire codec's Inputs. It
// is the SINGLE source for this field mapping: both this package's builders and
// the responder-role relayknocktest.BuildReply go through it, so a new KnockInputs
// field cannot be wired into one path and missed on the other. The return type is
// the module-internal nhpwire.Inputs, so callers outside this module's relayknock
// subtree cannot name it — the method is effectively package-internal despite
// being exported, which is why exporting it does not widen the usable public API.
func (k *KnockInputs) WireInputs() *nhpwire.Inputs {
	return &nhpwire.Inputs{
		DeviceStaticPriv: k.DeviceStaticPriv,
		ServerStaticPub:  k.ServerStaticPub,
		EphemeralPriv:    k.EphemeralPriv,
		TimestampNanos:   k.TimestampNanos,
		Counter:          k.Counter,
		Preamble:         k.Preamble,
		Body:             k.Body,
		Cookie:           k.Cookie,
	}
}

// BuildKnock builds a complete NHP_KNK packet (240-byte header ‖ sealed body)
// that the reference NHP relay responder decrypts. It is BuildMessage fixed to
// TypeKnock.
func BuildKnock(inp *KnockInputs) ([]byte, error) {
	return nhpwire.BuildMessage(nhpwire.TypeKNK, inp.WireInputs())
}

// BuildMessage builds a complete NHP packet (240-byte header ‖ sealed body) of
// the given initiator header type: TypeKnock, TypeListRequest, TypeReknock,
// TypeOTP, TypeRegister, or TypeExit. Any other type fails closed. In
// particular, an agent never builds server-originated reply types, so rejecting
// them here keeps a type mix-up from reaching the wire. A server or test double
// answering a request builds replies with relayknock/relayknocktest.BuildReply.
//
// BuildMessage is for callers that carry the packet themselves — deterministic
// construction (golden vectors, conformance tooling) or a custom transport.
// Typical relay callers use Knock, Exchange, or Send, which mint the per-message
// randomness and speak the relay HTTP contract. Those HTTP helpers deliberately
// do not transport TypeListRequest; native assignment carries it directly over
// UDP.
func BuildMessage(headerType int, inp *KnockInputs) ([]byte, error) {
	switch headerType {
	case TypeKnock, TypeListRequest, TypeReknock, TypeOTP, TypeRegister, TypeExit:
		return nhpwire.BuildMessage(headerType, inp.WireInputs())
	default:
		return nil, fmt.Errorf("unsupported initiator header type %d (want TypeKnock, TypeListRequest, TypeReknock, TypeOTP, TypeRegister, or TypeExit)", headerType)
	}
}

// Exported NHP initiator header-type values — the message types an agent can
// originate with BuildMessage. The HTTP relay helpers intentionally support a
// narrower transport subset (Exchange: KNK/REG; Send: OTP). Every other type is
// server-originated and is rejected by the exported builders.
//
// Adding a message type deliberately considers three sites, which encode three
// DIFFERENT predicates and are kept inline rather than force-unified: this block
// plus BuildMessage's initiator set (what an agent may build), Exchange's HTTP
// round-trip set (what that transport carries), and replyTypeAllowed's HTTP
// request→reply pairing. A buildable type need not belong to the HTTP subset.
const (
	// TypeKnock is NHP_KNK: the initial knock requesting admission; the server
	// answers with an NHP_ACK (or an NHP_COK under overload).
	TypeKnock = nhpwire.TypeKNK
	// TypeListRequest is NHP_LST: a generic authenticated list/query request. The
	// server answers it with an NHP_LRT whose counter echoes this request. The
	// application body defines the query (for example, cell assignment); the wire
	// codec deliberately does not interpret that body.
	TypeListRequest = nhpwire.TypeLST
	// TypeReknock is NHP_RKN: the answer to an authenticated overload cookie
	// challenge. It carries the original knock application identity and mixes the
	// decoded COK cookie into its header digest.
	TypeReknock = nhpwire.TypeRKN
	// TypeOTP is NHP_OTP: the one-way registration-bootstrap message (the NHP
	// spec's agent one-time-password request). The server does not reply to OTP
	// messages; a conforming relay acknowledges dispatch at the HTTP layer
	// instead (see Send).
	TypeOTP = nhpwire.TypeOTP
	// TypeRegister is NHP_REG: the agent registration message; the server
	// answers with an NHP_RAK.
	TypeRegister = nhpwire.TypeREG
	// TypeExit is NHP_EXT: a clean exit for an admitted native UDP session. The
	// server answers it with an NHP_ACK and never an NHP_COK.
	TypeExit = nhpwire.TypeEXT
)

// Exported NHP reply header-type values, so a consumer can construct or assert a
// Reply.Type (e.g. in tests) without importing the internal wire constants. These
// are the only reply types the initiator messages above can elicit: KNK is
// answered with ACK or COK, LST with LRT, RKN and EXT with ACK, REG with RAK,
// and OTP is never answered at all.
const (
	// TypeACK is NHP_ACK: an authorized-admission reply carrying the application
	// payload in Body.
	TypeACK = nhpwire.TypeACK
	// TypeListResult is NHP_LRT: the authenticated result of an NHP_LST
	// list/query request.
	TypeListResult = nhpwire.TypeLRT
	// TypeCookieChallenge is NHP_COK: an authenticated cookie-challenge. KNK
	// uses it for overload shedding; Hub assignment uses it for return-routability.
	TypeCookieChallenge = nhpwire.TypeCOK
	// TypeRegisterAck is NHP_RAK: the reply to an NHP_REG registration message.
	TypeRegisterAck = nhpwire.TypeRAK
)

// Reply is a decrypted, authenticated NHP server reply (NHP_ACK / NHP_LRT /
// NHP_COK / NHP_RAK). Body is the decrypted application body; the caller
// interprets it (relayknock is body-shape agnostic).
type Reply struct {
	// Type is the NHP header type (TypeACK / TypeListResult /
	// TypeCookieChallenge / TypeRegisterAck). Prefer the Is* methods for intent;
	// the exported constants exist so a consumer can also assert a specific type.
	Type           int
	Counter        uint64
	TimestampNanos uint64
	Body           []byte
}

// IsACK reports whether the reply is an NHP_ACK (the authorized-admission reply
// whose body carries the application payload).
func (r *Reply) IsACK() bool { return r.Type == nhpwire.TypeACK }

// IsListResult reports whether the reply is an NHP_LRT — the server's reply to
// an NHP_LST list/query request.
func (r *Reply) IsListResult() bool { return r.Type == nhpwire.TypeLRT }

// IsCookieChallenge reports whether the reply is an NHP_COK cookie-challenge.
// Native UDP callers using KnockWithReknock or AssignmentList consume the
// challenge internally; raw single-message callers can inspect it directly.
func (r *Reply) IsCookieChallenge() bool { return r.Type == nhpwire.TypeCOK }

// IsRegisterAck reports whether the reply is an NHP_RAK — the server's reply to
// an NHP_REG registration message.
//
// DecryptReply only ever returns a reply type, so a Reply it produced matches
// exactly one of IsACK / IsListResult / IsCookieChallenge / IsRegisterAck.
func (r *Reply) IsRegisterAck() bool { return r.Type == nhpwire.TypeRAK }

// DecryptReply decrypts and authenticates a server reply (NHP_ACK / NHP_LRT /
// NHP_COK / NHP_RAK — the transcript does not depend on the header type) against
// the static key of the server we messaged. The server is the initiator of this
// fresh handshake. Authentication completes at the ss-keyed opens: only the real
// server's static private key yields a valid tag there.
//
// Only reply header types are accepted: an authenticated packet carrying an
// initiator type (KNK/LST/RKN/OTP/REG/EXT) is rejected, so a Reply this returns
// always matches one Is* predicate. (Opening an initiator packet in the
// responder role — as the reference server does — is
// relayknock/relayknocktest's OpenInitiatorMessage or OpenReknockMessage.)
//
// DecryptReply authenticates the sender and body, but it does not know which
// request the caller sent. A custom transport MUST additionally require the
// expected request→reply type pair and, for transaction replies, the echoed
// request counter. An authenticated NHP_COK is classified before that ordinary
// counter gate because it is not a completed transaction; whether a request type
// may receive COK is transport/profile policy. In particular, generic NHP_LST
// accepts only NHP_LRT. The native Hub-assignment transport has
// a dedicated, bounded LST/COK/proof-LST profile above this shared decrypt gate.
// Exchange performs the corresponding checks for its HTTP KNK/REG subset.
func DecryptReply(devicePriv, expectedServerStaticPub, packet []byte) (*Reply, error) {
	msg, err := nhpwire.DecryptReplyMessage(devicePriv, expectedServerStaticPub, packet)
	if err != nil {
		return nil, err
	}
	return replyFromWire(msg), nil
}

func replyFromWire(msg *nhpwire.Message) *Reply {
	return &Reply{
		Type:           msg.Type,
		Counter:        msg.Counter,
		TimestampNanos: msg.TimestampNanos,
		Body:           msg.Body,
	}
}
