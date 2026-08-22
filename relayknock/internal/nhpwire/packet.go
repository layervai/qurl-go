package nhpwire

import (
	"encoding/binary"
	"fmt"

	"github.com/layervai/qurl-go/internal/nhpcontract"
)

// NHP packet header framing (from the reference NHP relay implementation). The
// HeaderCurve is the fixed 160-byte standard PKI/Curve structure; each sealed
// field is plaintext plus a 16-byte GCM tag. This codec does not serialize the
// specification table's IBC Identity field or implement the separate domestic
// cryptography profile.

const (
	headerCommonSize = 24

	// Field offsets within the 160-byte standard HeaderCurve.
	offEphemeral = headerCommonSize                          // 24  (32-byte e)
	offStatic    = offEphemeral + PublicKeySize              // 56  (32+16 sealed device pub)
	offTimestamp = offStatic + PublicKeySize + gcmTagSize    // 104 (8+16 sealed timestamp)
	offHeaderMAC = offTimestamp + timestampSize + gcmTagSize // 128 (32-byte keyed HMAC)

	// HeaderSize is the fixed 160-byte standard NHP header length. Exported because the
	// wrapping packages length-check reply packets against it.
	HeaderSize = offHeaderMAC + hashSize // 160

	// PacketBufferSize is the fixed buffer the reference server reads into; the
	// wrapping packages bound packet sizes by it.
	PacketBufferSize = 4096
	// maxApplicationBodySize is the largest plaintext body that fits after the
	// fixed header and the body's AEAD tag are added.
	maxApplicationBodySize = nhpcontract.MaxApplicationBodySize
	maxSealedBodySize      = maxApplicationBodySize + gcmTagSize
	// The server converts the unsigned wire milliseconds to its signed Unix-
	// nanosecond internal clock after authentication. Values above this bound
	// cannot be represented without overflow and are never emitted by this SDK.
	maxWireTimestampMillis = uint64(^uint64(0)>>1) / 1_000_000

	// Header flags (reference NHP relay common). Ordinary initiator bodies are
	// uncompressed. Compression is the standard profile's bit 0. The dedicated
	// Hub assignment proof builder is the sole SDK path that sets the LayerV bit
	// 1 extension; it always sets that bit exclusively.
	nhpFlagCompress       = 1 << 0
	hubLSTCookieProofFlag = 1 << 1
	supportedHeaderFlags  = nhpFlagCompress | hubLSTCookieProofFlag

	// protocolVersionMinor 2 authenticates the header prefix and payload
	// ciphertext with a key derived from ck3.
	protocolVersionMajor = 1
	protocolVersionMinor = 2

	// minProtocolVersionMinor is the oldest minor whose keyed header-MAC framing
	// this codec can reproduce. Later minors are allowed only for transcript-
	// compatible extensions. Any framing, KDF, MAC, or AEAD-transcript change
	// requires a new major because deployed floor-based receivers would otherwise
	// admit it. A sender below the floor is refused before key agreement.
	minProtocolVersionMinor = 2
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
	// NHP_RKN header MAC.
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

// PacketType returns the cleartext NHP header type after validating the packet's
// framing. It is used at transport boundaries that must reject unsupported
// message families before sending any bytes.
func PacketType(packet []byte) (int, error) {
	if len(packet) < HeaderSize {
		return 0, fmt.Errorf("packet too short: %d bytes < %d-byte header", len(packet), HeaderSize)
	}
	if len(packet) > PacketBufferSize {
		return 0, fmt.Errorf("packet too long: %d bytes > %d-byte buffer", len(packet), PacketBufferSize)
	}
	typ, payloadSize := getTypeAndPayloadSize(packet)
	if flag := getFlag(packet); flag&^supportedHeaderFlags != 0 {
		return 0, fmt.Errorf("packet flags %#04x are unsupported by the standard header profile", flag)
	} else if flag&hubLSTCookieProofFlag != 0 && typ != TypeLST {
		return 0, fmt.Errorf("Hub LST cookie proof flag is invalid on packet type %d", typ)
	}
	if payloadSize != len(packet)-HeaderSize {
		return 0, fmt.Errorf("packet payload size %d does not match %d trailing bytes", payloadSize, len(packet)-HeaderSize)
	}
	return typ, nil
}

func setVersion(header []byte, major, minor byte) { header[8], header[9] = major, minor }

// getVersion decodes HeaderCommon[8:10]. Receivers pin major and floor minor at
// minProtocolVersionMinor: a major bump is a wire break, an OLDER minor is a
// transcript this codec cannot open, and a NEWER minor stays admissible because
// the reference server may ship a compatible extension before a deployed client
// is updated — gating that direction would strand clients on an ordinary
// coordinated release. Both bytes are covered by the keyed header MAC, so a
// receiver that accepts a newer, transcript-compatible minor still authenticates
// the exact value it read. Authenticated-transcript changes require a new major;
// raising only the floor cannot make already-deployed receivers reject them.
func getVersion(header []byte) (major, minor byte) { return header[8], header[9] }

// setFlag writes HeaderCommon[10:12] after masking to 12 bits (Go SetFlag).
func setFlag(header []byte, flag uint16) {
	binary.BigEndian.PutUint16(header[10:12], flag&0x0fff)
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
