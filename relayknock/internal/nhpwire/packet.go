package nhpwire

import (
	"encoding/binary"

	"github.com/layervai/qurl-go/internal/nhpcontract"
)

// NHP packet header framing (from the reference NHP relay implementation). The
// HeaderCurve is a fixed 240-byte big-endian structure; each sealed field is
// plaintext + a 16-byte GCM tag.

const (
	headerCommonSize = 24
	maxIdentitySize  = 64

	// Field offsets within the 240-byte HeaderCurve.
	offEphemeral = headerCommonSize                           // 24  (32-byte e)
	offIdentity  = offEphemeral + PublicKeySize               // 56  (64+16, left zero)
	offStatic    = offIdentity + maxIdentitySize + gcmTagSize // 136 (32+16 sealed device pub)
	offTimestamp = offStatic + PublicKeySize + gcmTagSize     // 184 (8+16 sealed timestamp)
	offDigest    = offTimestamp + timestampSize + gcmTagSize  // 208 (32 BLAKE2s header digest)

	// HeaderSize is the fixed 240-byte NHP header length. Exported because the
	// wrapping packages length-check reply packets against it.
	HeaderSize = offDigest + hashSize // 240

	// PacketBufferSize is the fixed buffer the reference server reads into; the
	// wrapping packages bound packet sizes by it.
	PacketBufferSize = 4096
	// maxApplicationBodySize is the largest plaintext body that fits after the
	// fixed header and the body's AEAD tag are added.
	maxApplicationBodySize = nhpcontract.MaxApplicationBodySize
	maxSealedBodySize      = maxApplicationBodySize + gcmTagSize

	// Header flags (reference NHP relay common): COMPRESS = 1<<1. The agent never sets
	// it (bodies sent uncompressed); kept to decode a compressed reply.
	nhpFlagCompress = 1 << 1

	protocolVersionMajor = 1
	protocolVersionMinor = 0
)

// Compile-time equality fence: if the codec's framing changes, update the
// shared contract deliberately rather than silently diverging from qurl's
// pre-packet body validation.
var (
	_ [PacketBufferSize - HeaderSize - gcmTagSize - maxApplicationBodySize]struct{}
	_ [maxApplicationBodySize - (PacketBufferSize - HeaderSize - gcmTagSize)]struct{}
)

// NHP header types (reference NHP relay iota: KPL=0, KNK=1, ACK=2, …, LST=5,
// LRT=6, COK=7, RKN=8, …, OTP=12, REG=13, RAK=14). Exported so the wrapping
// packages map them to their public Type* constants and enforce type-gating;
// this codec itself applies no restriction.
const (
	TypeKNK = 1  // NHP_KNK: knock
	TypeACK = 2  // NHP_ACK: admission reply
	TypeLST = 5  // NHP_LST: list/query request
	TypeLRT = 6  // NHP_LRT: list/query result
	TypeCOK = 7  // NHP_COK: overload cookie-challenge
	TypeRKN = 8  // NHP_RKN: cookie-authenticated re-knock
	TypeOTP = 12 // NHP_OTP: one-way OTP request
	TypeREG = 13 // NHP_REG: registration
	TypeRAK = 14 // NHP_RAK: registration reply
	TypeEXT = 16 // NHP_EXT: clean session exit

	// CookieSize is the exact decoded NHP_COK cookie length mixed into an
	// NHP_RKN header digest.
	CookieSize = 32
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
// header[0:offDigest] ‖ cookie). cookie is empty for every message except RKN,
// where it is the exact decoded 32-byte COK cookie. Integrity, not
// authentication — all inputs are public.
func headerDigest(peerStaticPub, header, cookie []byte) []byte {
	return blake2sHash(initialHash, peerStaticPub, header[0:offDigest], cookie)
}
