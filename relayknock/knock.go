package relayknock

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// NHP knock construction and reply decryption (initiator/responder transcripts:
// nhp/core initiator.go + responder.go, ports of js-agent crypto/handshake.ts +
// crypto/ack.ts). The seal/open ordering folds material into the chain hash/key
// in the exact order the Go server expects, so every AEAD opens; it is fenced
// byte-for-byte by the golden vectors.

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
// that the Go nhp/core responder decrypts. Folds material into the chain
// hash/key in the exact order the responder expects, so every AEAD opens.
func BuildKnock(inp *KnockInputs) ([]byte, error) {
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
	setTypeAndPayloadSize(header, nhpKNK, len(sealedBody), inp.Preamble)
	copy(header[offDigest:offDigest+hashSize], headerDigest(inp.ServerStaticPub, header))

	packet := make([]byte, headerSize+len(sealedBody))
	copy(packet, header)
	copy(packet[headerSize:], sealedBody)
	return packet, nil
}

// Reply is a decrypted, authenticated NHP server reply (NHP_ACK / NHP_COK). Body
// is the decrypted application body; the caller interprets it (relayknock is
// body-shape agnostic).
type Reply struct {
	// Type is the NHP header type. Use IsACK / IsCookieChallenge rather than
	// comparing the raw value, which keeps the wire constants unexported.
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

// DecryptReply decrypts and authenticates a server reply (NHP_ACK / NHP_COK)
// against the static key of the server we knocked. The server is the initiator
// of this fresh handshake. Authentication completes at the ss-keyed opens: only
// the real server's static private key yields a valid tag there.
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
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, packetBufferSize))
}
