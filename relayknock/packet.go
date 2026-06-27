package relayknock

import "encoding/binary"

// NHP packet header framing (nhp/core: header.go, packet.go, constants.go). The
// HeaderCurve is a fixed 240-byte big-endian structure; each sealed field is
// plaintext + a 16-byte GCM tag.

const (
	headerCommonSize = 24
	maxIdentitySize  = 64

	// Field offsets within the 240-byte HeaderCurve.
	offEphemeral = headerCommonSize                           // 24  (32-byte e)
	offIdentity  = offEphemeral + publicKeySize               // 56  (64+16, left zero)
	offStatic    = offIdentity + maxIdentitySize + gcmTagSize // 136 (32+16 sealed device pub)
	offTimestamp = offStatic + publicKeySize + gcmTagSize     // 184 (8+16 sealed timestamp)
	offDigest    = offTimestamp + timestampSize + gcmTagSize  // 208 (32 BLAKE2s header digest)
	headerSize   = offDigest + hashSize                       // 240

	packetBufferSize  = 4096 // server reads into a fixed [PacketBufferSize]byte
	maxSealedBodySize = packetBufferSize - headerSize

	// Header types (nhp/core/packet.go iota: KPL=0, KNK=1, ACK=2, …, COK=7, RKN=8).
	nhpKNK = 1
	nhpACK = 2
	nhpCOK = 7

	// Header flags (nhp/common/packet.go): COMPRESS = 1<<1. The agent never sets
	// it (bodies sent uncompressed); kept to decode a compressed reply.
	nhpFlagCompress = 1 << 1

	protocolVersionMajor = 1
	protocolVersionMinor = 0
)

// setTypeAndPayloadSize writes the obfuscated type+size into HeaderCommon[0:8]:
// [0:4]=preamble, [4:8]=(type<<16 | size) XOR preamble. Go SetTypeAndPayloadSize.
func setTypeAndPayloadSize(header []byte, typ, size int, preamble uint32) {
	tns := preamble ^ ((uint32(typ&0xffff) << 16) | uint32(size&0xffff))
	binary.BigEndian.PutUint32(header[0:4], preamble)
	binary.BigEndian.PutUint32(header[4:8], tns)
}

// getTypeAndPayloadSize decodes what setTypeAndPayloadSize wrote.
func getTypeAndPayloadSize(header []byte) (typ, size int) {
	preamble := binary.BigEndian.Uint32(header[0:4])
	tns := preamble ^ binary.BigEndian.Uint32(header[4:8])
	return int((tns >> 16) & 0xffff), int(tns & 0xffff)
}

func setVersion(header []byte, major, minor byte) { header[8], header[9] = major, minor }

// setFlag writes HeaderCommon[10:12] after stripping EXTENDEDLENGTH and masking
// to 12 bits (Go SetFlag).
func setFlag(header []byte, flag uint16) {
	binary.BigEndian.PutUint16(header[10:12], flag&^(1<<0)&0x0fff)
}

func getFlag(header []byte) uint16       { return binary.BigEndian.Uint16(header[10:12]) }
func setCounter(header []byte, c uint64) { binary.BigEndian.PutUint64(header[16:24], c) }
func getCounter(header []byte) uint64    { return binary.BigEndian.Uint64(header[16:24]) }

// nonceForCounter is the 12-byte GCM nonce: 4 zero bytes ‖ 8-byte BE counter
// (Go HeaderCurve.NonceBytes). One nonce per packet, each seal under a distinct
// derived key — no AES-GCM (key,nonce) reuse.
func nonceForCounter(counter uint64) []byte {
	nonce := make([]byte, gcmNonceSize)
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

// headerDigest is the unkeyed BLAKE2s(INITIAL_HASH ‖ peerStaticPub ‖
// header[0:offDigest]) (Go addHeaderDigest). Integrity, not authentication — all
// inputs are public.
func headerDigest(peerStaticPub, header []byte) []byte {
	return blake2sHash(initialHash, peerStaticPub, header[0:offDigest])
}
