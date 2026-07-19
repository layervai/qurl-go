package nhpwire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/layervai/qurl-go/internal/cryptoutil"
)

// NHP message construction and reply decryption (initiator/responder transcripts
// from the reference NHP relay implementation, ports of the browser agent's
// handshake and ack crypto). The seal/open ordering folds material into the chain
// hash/key in the exact order the reference server expects, so every AEAD opens;
// it is fenced byte-for-byte by the golden vectors that reach it through
// relayknock.BuildKnock / relayknock.DecryptReply.

// Inputs are the per-message values for BuildMessage. They are injectable (rather
// than minted internally) so a caller can drive a deterministic golden vector and
// so a specific device identity can be presented. In production the ephemeral
// key, counter, and preamble are random.
type Inputs struct {
	DeviceStaticPriv []byte // initiator static private key, 32 bytes
	ServerStaticPub  []byte // responder static public key, 32 bytes (rs)
	EphemeralPriv    []byte // per-message ephemeral private key, 32 bytes
	TimestampNanos   uint64 // send time (time.Now().UnixNano())
	Counter          uint64 // transaction id
	Preamble         uint32 // HeaderCommon obfuscation preamble
	Body             []byte // serialized, uncompressed application body
	Cookie           []byte // exact 32-byte COK cookie for RKN or Hub LST proof
}

// Message is a decrypted, authenticated NHP message. Type is the raw NHP header
// type (one of the declared NHP header-type constants); the wrapping packages
// interpret it.
type Message struct {
	Type           int
	Flags          uint16
	Counter        uint64
	TimestampNanos uint64
	Body           []byte
}

// ErrMalformedReply marks an authenticated message whose header type is not a
// server reply. relayknock aliases this sentinel as its public
// ErrMalformedReply so every reply consumer observes one errors.Is identity
// while the shared type gate remains next to the private wire metadata.
var ErrMalformedReply = errors.New("relayknock: malformed reply")

// BuildMessage builds a complete single-message NHP packet (240-byte header ‖
// sealed body) of the given header type. It folds material into the chain
// hash/key in the exact order the responder expects, so every AEAD opens. For
// ordinary messages only the obfuscated type field in HeaderCommon[0:8]
// differs. RKN additionally mixes its exact COK cookie into the header digest;
// the dedicated session-control vectors fence that variant. Hub assignment LST
// proof is built only through BuildHubLSTCookieProof. BuildMessage enforces the
// ordinary/RKN cookie invariant but applies no initiator/reply type allowlist;
// directional type gating lives in the wrapping packages.
func BuildMessage(headerType int, inp *Inputs) ([]byte, error) {
	return buildMessage(headerType, 0, inp)
}

// BuildHubLSTCookieProof builds the one dedicated assignment-proof NHP_LST.
// The raw 32-byte Hub cookie is mixed into the header digest and the proof bit
// is set exclusively. Keeping this separate from BuildMessage prevents generic
// LST, REG, and KNK callers from acquiring the proof capability accidentally.
func BuildHubLSTCookieProof(inp *Inputs) ([]byte, error) {
	return buildMessage(TypeLST, hubLSTCookieProofFlag, inp)
}

// BuildReplyWithFlagsForTest builds a reply packet carrying an explicit flag
// word so relayknocktest can prove consumers fail closed on out-of-profile
// replies. It is internal to the relayknock subtree and cannot build initiator
// messages or carry proof/RKN cookies.
func BuildReplyWithFlagsForTest(headerType int, flags uint16, inp *Inputs) ([]byte, error) {
	if inp == nil {
		return nil, errors.New("message inputs must not be nil")
	}
	switch headerType {
	case TypeACK, TypeLRT, TypeCOK, TypeRAK:
	default:
		return nil, fmt.Errorf("header type %d is not a reply", headerType)
	}
	if len(inp.Cookie) != 0 {
		return nil, fmt.Errorf("reply header type %d must not carry a cookie", headerType)
	}
	return buildMessageUnchecked(headerType, flags, inp)
}

func buildMessage(headerType int, flags uint16, inp *Inputs) ([]byte, error) {
	if inp == nil {
		return nil, errors.New("message inputs must not be nil")
	}
	switch {
	case headerType == TypeRKN && flags == 0:
		if len(inp.Cookie) != CookieSize {
			return nil, fmt.Errorf("RKN cookie must be %d bytes, got %d", CookieSize, len(inp.Cookie))
		}
	case headerType == TypeLST && flags == hubLSTCookieProofFlag:
		if len(inp.Cookie) != CookieSize {
			return nil, fmt.Errorf("hub LST proof cookie must be %d bytes, got %d", CookieSize, len(inp.Cookie))
		}
	case flags != 0:
		return nil, fmt.Errorf("header type %d does not support flags %#04x", headerType, flags)
	case len(inp.Cookie) != 0:
		return nil, fmt.Errorf("header type %d must not carry a cookie", headerType)
	}
	return buildMessageUnchecked(headerType, flags, inp)
}

func buildMessageUnchecked(headerType int, flags uint16, inp *Inputs) ([]byte, error) {
	if len(inp.ServerStaticPub) != PublicKeySize {
		return nil, fmt.Errorf("server static pub must be %d bytes, got %d", PublicKeySize, len(inp.ServerStaticPub))
	}
	nonce := nonceForCounter(inp.Counter)

	ephemeralPub, err := X25519Public(inp.EphemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pub: %w", err)
	}
	deviceStaticPub, err := X25519Public(inp.DeviceStaticPriv)
	if err != nil {
		return nil, fmt.Errorf("derive device static pub: %w", err)
	}

	header := make([]byte, HeaderSize)
	copy(header[offEphemeral:offEphemeral+PublicKeySize], ephemeralPub) // -> e

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
	copy(header[offStatic:offStatic+PublicKeySize+gcmTagSize], sealedStatic)
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
	setFlag(header, flags)
	setTypeAndPayloadSize(header, headerType, len(sealedBody), inp.Preamble)
	copy(header[offDigest:offDigest+hashSize], headerDigest(inp.ServerStaticPub, header, inp.Cookie))

	packet := make([]byte, HeaderSize+len(sealedBody))
	copy(packet, header)
	copy(packet[HeaderSize:], sealedBody)
	return packet, nil
}

// DecryptMessage decrypts and authenticates any NHP message this package speaks
// against the sender's static key, admitting both reply and initiator types.
// DecryptReplyMessage applies the shared reply gate; responder/test code applies
// the corresponding initiator gate after calling this generic codec.
// Authentication completes at the ss-keyed opens: only the real sender's static
// private key yields a valid tag there.
func DecryptMessage(devicePriv, expectedServerStaticPub, packet []byte) (*Message, error) {
	return decryptMessage(devicePriv, expectedServerStaticPub, nil, packet)
}

// DecryptReplyMessage decrypts and authenticates a message and admits only the
// four server reply types. It intentionally returns the internal Message so
// transports with a narrower profile can inspect authenticated header metadata
// without widening relayknock.Reply's public API.
func DecryptReplyMessage(devicePriv, expectedServerStaticPub, packet []byte) (*Message, error) {
	msg, err := DecryptMessage(devicePriv, expectedServerStaticPub, packet)
	if err != nil {
		return nil, err
	}
	return acceptReplyMessage(msg)
}

func acceptReplyMessage(msg *Message) (*Message, error) {
	if msg == nil {
		return nil, fmt.Errorf("%w: decrypted message is nil", ErrMalformedReply)
	}
	switch msg.Type {
	case TypeACK, TypeLRT, TypeCOK, TypeRAK:
		return msg, nil
	default:
		cryptoutil.Wipe(msg.Body)
		return nil, fmt.Errorf("%w: header type %d is not a server reply", ErrMalformedReply, msg.Type)
	}
}

// DecryptReknockMessage opens an NHP_RKN request using the exact decoded COK
// cookie that the initiator mixed into the header digest. The authenticated
// message type is still returned to the caller for an explicit RKN gate.
func DecryptReknockMessage(devicePriv, expectedServerStaticPub, cookie, packet []byte) (*Message, error) {
	if len(cookie) != CookieSize {
		return nil, fmt.Errorf("RKN cookie must be %d bytes, got %d", CookieSize, len(cookie))
	}
	return decryptMessage(devicePriv, expectedServerStaticPub, cookie, packet)
}

// DecryptHubLSTCookieProofMessage opens the dedicated proof LST using the exact
// raw cookie returned by the Hub. Both its type and exclusive proof flag are
// verified after authenticated decryption so test/responder code cannot confuse
// an ordinary LST or RKN with this assignment-only transition.
func DecryptHubLSTCookieProofMessage(devicePriv, expectedServerStaticPub, cookie, packet []byte) (*Message, error) {
	if len(cookie) != CookieSize {
		return nil, fmt.Errorf("hub LST proof cookie must be %d bytes, got %d", CookieSize, len(cookie))
	}
	msg, err := decryptMessage(devicePriv, expectedServerStaticPub, cookie, packet)
	if err != nil {
		return nil, err
	}
	return acceptHubLSTCookieProofMessage(msg)
}

func acceptHubLSTCookieProofMessage(msg *Message) (*Message, error) {
	if msg == nil {
		return nil, errors.New("decrypted Hub LST cookie proof is nil")
	}
	if msg.Type != TypeLST || msg.Flags != hubLSTCookieProofFlag {
		cryptoutil.Wipe(msg.Body)
		return nil, fmt.Errorf("not a Hub LST cookie proof: type %d flags %#04x", msg.Type, msg.Flags)
	}
	return msg, nil
}

func decryptMessage(devicePriv, expectedServerStaticPub, cookie, packet []byte) (*Message, error) {
	if len(packet) < HeaderSize {
		return nil, fmt.Errorf("reply too short: %d bytes < %d-byte header", len(packet), HeaderSize)
	}
	if len(packet) > PacketBufferSize {
		return nil, fmt.Errorf("reply too long: %d bytes > %d-byte buffer", len(packet), PacketBufferSize)
	}
	header := packet[0:HeaderSize]
	sealedBody := packet[HeaderSize:]

	agentPub, err := X25519Public(devicePriv)
	if err != nil {
		return nil, fmt.Errorf("derive agent pub: %w", err)
	}
	if !bytes.Equal(headerDigest(agentPub, header, cookie), header[offDigest:offDigest+hashSize]) {
		return nil, errors.New("reply header digest mismatch (tampered, or wrong device key)")
	}

	counter := getCounter(header)
	nonce := nonceForCounter(counter)
	serverEph := header[offEphemeral : offEphemeral+PublicKeySize]
	staticField := header[offStatic : offStatic+PublicKeySize+gcmTagSize]
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

	// The decoded payload size (the discarded second return) is intentionally
	// ignored: the body AEAD opened above already fences the actual sealedBody
	// bytes, so the header's self-described size is not load-bearing for integrity
	// and needs no cross-check against len(sealedBody).
	// This generic codec does NOT gate the header type — the type rides outside
	// the AEAD, so a garbage type decrypts fine. DecryptReplyMessage applies the
	// single reply policy; responder/test code owns the initiator policy.
	typ, _ := getTypeAndPayloadSize(header)
	return &Message{
		Type:           typ,
		Flags:          getFlag(header),
		Counter:        counter,
		TimestampNanos: binary.BigEndian.Uint64(tsBytes),
		Body:           body,
	}, nil
}

// inflateZlib inflates a Go compress/zlib (RFC 1950) stream. Input is bounded by
// the PacketBufferSize check in DecryptMessage and is post-AEAD (in-TCB), so no
// decompression-bomb exposure beyond one buffer. The compress flag rides on the
// server's reply and is outside the agent's control, so this fails closed on an
// over-large inflated body rather than returning a silently truncated one. It
// takes ownership of compressed and wipes it on every return; any partial
// inflated plaintext is also wiped and suppressed on error.
func inflateZlib(compressed []byte) (body []byte, err error) {
	defer cryptoutil.Wipe(compressed)
	// Any read or size failure may occur after partial plaintext was produced.
	// Named returns let one guard wipe that buffer and prevent its escape.
	defer func() {
		if err != nil {
			cryptoutil.Wipe(body)
			body = nil
		}
	}()
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }() // read-only zlib reader; Close cannot surface data loss
	// Read one byte past the cap so a body that inflates to exactly the limit is
	// distinguishable from one truncated at it: return an explicit error instead
	// of a corrupt, silently-cut body for a downstream JSON parse to trip on.
	body, err = io.ReadAll(io.LimitReader(r, PacketBufferSize+1))
	if err != nil {
		return body, err
	}
	if len(body) > PacketBufferSize {
		return body, fmt.Errorf("inflated body exceeds %d-byte limit", PacketBufferSize)
	}
	return body, nil
}
