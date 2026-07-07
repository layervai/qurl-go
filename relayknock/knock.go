package relayknock

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// NHP message construction (knock/OTP/register) and reply decryption
// (initiator/responder transcripts from the reference NHP relay implementation,
// ports of the browser agent's handshake and ack crypto). The seal/open ordering
// folds material into the chain hash/key in the exact order the reference server
// expects, so every AEAD opens; it is fenced byte-for-byte by the golden vectors.

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

// BuildKnock builds a complete NHP_KNK packet (240-byte header ‖ sealed body)
// that the reference NHP relay responder decrypts. It is BuildMessage fixed to
// TypeKnock.
func BuildKnock(inp *KnockInputs) ([]byte, error) { return buildMessage(nhpKNK, inp) }

// BuildMessage builds a complete NHP packet (240-byte header ‖ sealed body) of
// the given initiator header type: TypeKnock, TypeOTP, or TypeRegister. Any
// other type — in particular the server-originated reply types — fails closed:
// an agent never builds those, so rejecting them here keeps a type mix-up from
// reaching the wire.
//
// BuildMessage is for callers that carry the packet themselves — deterministic
// construction (golden vectors, conformance tooling) or a custom transport.
// Typical agents use Knock, Exchange, or Send, which mint the per-message
// randomness and speak the relay HTTP contract.
func BuildMessage(headerType int, inp *KnockInputs) ([]byte, error) {
	switch headerType {
	case TypeKnock, TypeOTP, TypeRegister:
		return buildMessage(headerType, inp)
	default:
		return nil, fmt.Errorf("unsupported initiator header type %d (want TypeKnock, TypeOTP, or TypeRegister)", headerType)
	}
}

// buildMessage builds a complete single-message NHP packet of the given header
// type. Folds material into the chain hash/key in the exact order the responder
// expects, so every AEAD opens. The transcript is independent of the header
// type — only the obfuscated type field in HeaderCommon[0:8] differs — so the
// NHP_KNK golden vector fences every type built here. Unexported (with no type
// restriction) so in-package tests can fabricate server-originated replies such
// as an NHP_RAK by swapping roles; external callers go through BuildKnock /
// BuildMessage.
func buildMessage(headerType int, inp *KnockInputs) ([]byte, error) {
	if len(inp.ServerStaticPub) != publicKeySize {
		return nil, fmt.Errorf("server static pub must be %d bytes, got %d", publicKeySize, len(inp.ServerStaticPub))
	}
	nonce := nonceForCounter(inp.Counter)

	ephemeralPub, err := x25519Public(inp.EphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pub: %w", err)
	}
	deviceStaticPub, err := x25519Public(inp.DeviceStaticPriv)
	if err != nil {
		return nil, fmt.Errorf("derive device static pub: %w", err)
	}

	header := make([]byte, headerSize)
	copy(header[offEphemeral:offEphemeral+publicKeySize], ephemeralPub) // -> e

	// ChainHash0/ChainKey0 from the two init constants.
	chainHash := newBlake2s()
	chainHash.Write(initialHash)
	chainKey := mixKey(chainHash.Sum(nil), initialChainKey)

	// Fold rs and e: ChainHash0->1, ChainKey0->1.
	chainHash.Write(inp.ServerStaticPub)
	chainHash.Write(ephemeralPub)
	chainKey = mixKey(chainKey, ephemeralPub)

	// es = DH(e, rs): seal the device static pub (AAD = ChainHash1).
	ess, err := x25519Shared(inp.EphemeralPriv, inp.ServerStaticPub)
	if err != nil {
		return nil, fmt.Errorf("es DH: %w", err)
	}
	var aeadKey []byte
	chainKey, aeadKey = keyGen2(chainKey, ess)
	sealedStatic, err := aeadSeal(aeadKey, nonce, deviceStaticPub, chainHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("seal static: %w", err)
	}
	copy(header[offStatic:offStatic+publicKeySize+gcmTagSize], sealedStatic)
	chainHash.Write(sealedStatic)

	// ss = DH(s, rs): seal the timestamp (AAD = ChainHash2).
	ss, err := x25519Shared(inp.DeviceStaticPriv, inp.ServerStaticPub)
	if err != nil {
		return nil, fmt.Errorf("ss DH: %w", err)
	}
	chainKey, aeadKey = keyGen2(chainKey, ss)
	tsBytes := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(tsBytes, inp.TimestampNanos)
	sealedTs, err := aeadSeal(aeadKey, nonce, tsBytes, chainHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("seal timestamp: %w", err)
	}
	copy(header[offTimestamp:offTimestamp+timestampSize+gcmTagSize], sealedTs)
	chainHash.Write(sealedTs)

	// Body AAD = ChainHash3; body key derives from the ts ciphertext (terminal
	// derivation — evolved chain key discarded).
	bodyAad := chainHash.Sum(nil)
	_, aeadKey = keyGen2(chainKey, sealedTs)
	var sealedBody []byte
	if len(inp.Body) > 0 { // empty body ⇒ no seal, size 0 (matches Go encryptBody)
		sealedBody, err = aeadSeal(aeadKey, nonce, inp.Body, bodyAad)
		if err != nil {
			return nil, fmt.Errorf("seal body: %w", err)
		}
	}
	if len(sealedBody) > maxSealedBodySize {
		return nil, fmt.Errorf("knock body too large: sealed %d bytes exceeds %d", len(sealedBody), maxSealedBodySize)
	}

	// HeaderCommon — set everything before the digest, which covers header[0:208].
	setVersion(header, protocolVersionMajor, protocolVersionMinor)
	setCounter(header, inp.Counter)
	setFlag(header, 0)
	setTypeAndPayloadSize(header, headerType, len(sealedBody), inp.Preamble)
	copy(header[offDigest:offDigest+hashSize], headerDigest(inp.ServerStaticPub, header))

	packet := make([]byte, headerSize+len(sealedBody))
	copy(packet, header)
	copy(packet[headerSize:], sealedBody)
	return packet, nil
}

// Exported NHP initiator header-type values — the message types an agent can
// originate (BuildMessage, Exchange, Send). Every other type is
// server-originated and is rejected by the exported builders.
const (
	// TypeKnock is NHP_KNK: the initial knock requesting admission; the server
	// answers with an NHP_ACK (or an NHP_COK under overload).
	TypeKnock = nhpKNK
	// TypeOTP is NHP_OTP: the one-way registration-bootstrap message (the NHP
	// spec's agent one-time-password request). The server does not reply to OTP
	// messages; a conforming relay acknowledges dispatch at the HTTP layer
	// instead (see Send).
	TypeOTP = nhpOTP
	// TypeRegister is NHP_REG: the agent registration message; the server
	// answers with an NHP_RAK.
	TypeRegister = nhpREG
)

// Exported NHP reply header-type values, so a consumer can construct or assert a
// Reply.Type (e.g. in tests) without importing the internal wire constants. These
// are the only reply types the initiator messages above can elicit: a knock is
// answered with an NHP_ACK or NHP_COK, a registration with an NHP_RAK, and an
// OTP message is never answered at all.
const (
	// TypeACK is NHP_ACK: an authorized-admission reply carrying the application
	// payload in Body.
	TypeACK = nhpACK
	// TypeCookieChallenge is NHP_COK: an overload cookie-challenge.
	TypeCookieChallenge = nhpCOK
	// TypeRegisterAck is NHP_RAK: the reply to an NHP_REG registration message.
	TypeRegisterAck = nhpRAK
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
func (r *Reply) IsACK() bool { return r.Type == nhpACK }

// IsCookieChallenge reports whether the reply is an NHP_COK overload
// cookie-challenge. The NHP_RKN cookie-answer path is out of scope for a single
// resolve, so a caller treats this as "retry later".
func (r *Reply) IsCookieChallenge() bool { return r.Type == nhpCOK }

// IsRegisterAck reports whether the reply is an NHP_RAK — the server's reply to
// an NHP_REG registration message.
func (r *Reply) IsRegisterAck() bool { return r.Type == nhpRAK }

// DecryptReply decrypts and authenticates a server reply (NHP_ACK / NHP_COK /
// NHP_RAK — the transcript does not depend on the header type) against the
// static key of the server we messaged. The server is the initiator of this
// fresh handshake. Authentication completes at the ss-keyed opens: only the
// real server's static private key yields a valid tag there.
func DecryptReply(devicePriv, expectedServerStaticPub, packet []byte) (*Reply, error) {
	if len(packet) < headerSize {
		return nil, fmt.Errorf("reply too short: %d bytes < %d-byte header", len(packet), headerSize)
	}
	if len(packet) > packetBufferSize {
		return nil, fmt.Errorf("reply too long: %d bytes > %d-byte buffer", len(packet), packetBufferSize)
	}
	header := packet[0:headerSize]
	sealedBody := packet[headerSize:]

	agentPub, err := x25519Public(devicePriv)
	if err != nil {
		return nil, fmt.Errorf("derive agent pub: %w", err)
	}
	if !bytes.Equal(headerDigest(agentPub, header), header[offDigest:offDigest+hashSize]) {
		return nil, errors.New("reply header digest mismatch (tampered, or wrong device key)")
	}

	counter := getCounter(header)
	nonce := nonceForCounter(counter)
	serverEph := header[offEphemeral : offEphemeral+publicKeySize]
	staticField := header[offStatic : offStatic+publicKeySize+gcmTagSize]
	tsField := header[offTimestamp : offTimestamp+timestampSize+gcmTagSize]

	chainHash := newBlake2s()
	chainHash.Write(initialHash)
	chainKey := mixKey(chainHash.Sum(nil), initialChainKey)
	chainHash.Write(agentPub)
	chainHash.Write(serverEph)
	chainKey = mixKey(chainKey, serverEph)

	// es = DH(agentPriv, serverEph): open the server static key (AAD = ChainHash1).
	es, err := x25519Shared(devicePriv, serverEph)
	if err != nil {
		return nil, fmt.Errorf("es DH: %w", err)
	}
	var aeadKey []byte
	chainKey, aeadKey = keyGen2(chainKey, es)
	serverStaticPub, err := aeadOpen(aeadKey, nonce, staticField, chainHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("open server static: %w", err)
	}
	if !bytes.Equal(serverStaticPub, expectedServerStaticPub) {
		return nil, errors.New("reply from an unexpected server (static key mismatch)")
	}
	chainHash.Write(staticField)

	// ss = DH(agentPriv, serverStatic): only the real server can derive this — a
	// valid open here authenticates the reply. Opens the timestamp (AAD = ChainHash2).
	ss, err := x25519Shared(devicePriv, serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("ss DH: %w", err)
	}
	chainKey, aeadKey = keyGen2(chainKey, ss)
	tsBytes, err := aeadOpen(aeadKey, nonce, tsField, chainHash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("open timestamp (server authentication failed): %w", err)
	}
	chainHash.Write(tsField)

	// Body AAD = ChainHash3; body key from the ts ciphertext.
	bodyAad := chainHash.Sum(nil)
	_, bodyKey := keyGen2(chainKey, tsField)
	var body []byte
	if len(sealedBody) > 0 {
		body, err = aeadOpen(bodyKey, nonce, sealedBody, bodyAad)
		if err != nil {
			return nil, fmt.Errorf("open body: %w", err)
		}
	}
	if len(body) > 0 && getFlag(header)&nhpFlagCompress != 0 {
		body, err = inflateZlib(body)
		if err != nil {
			return nil, fmt.Errorf("inflate body: %w", err)
		}
	}

	typ, _ := getTypeAndPayloadSize(header)
	return &Reply{
		Type:           typ,
		Counter:        counter,
		TimestampNanos: binary.BigEndian.Uint64(tsBytes),
		Body:           body,
	}, nil
}

// inflateZlib inflates a Go compress/zlib (RFC 1950) stream. Input is bounded by
// the packetBufferSize check in DecryptReply and is post-AEAD (in-TCB), so no
// decompression-bomb exposure beyond one buffer.
func inflateZlib(compressed []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }() // read-only zlib reader; Close cannot surface data loss
	return io.ReadAll(io.LimitReader(r, packetBufferSize))
}
