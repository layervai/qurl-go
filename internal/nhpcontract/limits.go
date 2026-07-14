// Package nhpcontract holds wire limits shared by the public qurl runtime and
// the internal NHP codec. It is internal so implementation limits do not widen
// the SDK's public API.
package nhpcontract

// MaxApplicationBodySize is the largest plaintext application body that fits
// in NHP's fixed 4096-byte receive buffer after its 240-byte header and the
// body's 16-byte AEAD tag.
const MaxApplicationBodySize = 4096 - 240 - 16
