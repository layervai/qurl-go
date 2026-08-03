package nhpwire

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// incompressibleBytes returns n deterministic bytes with no exploitable
// redundancy, produced by chaining the in-package BLAKE2s so the fixture needs
// no seeded PRNG and reproduces exactly on every run. zlib cannot shrink them,
// so a body of maxApplicationBodySize seals PAST the sealed-body ceiling.
func incompressibleBytes(n int) []byte {
	out := make([]byte, 0, n+hashSize)
	digest := blake2sHash([]byte("nhpwire incompressible body fixture"))
	for len(out) < n {
		digest = blake2sHash(digest)
		out = append(out, digest...)
	}
	return out[:n]
}

// TestBuildMessage_RejectsOutOfProfileInputs covers the builder's fail-closed
// guards. Each subcase perturbs exactly one input of an otherwise valid message
// so a single guard trips, and each asserts no packet escapes alongside the
// error — a half-built packet reaching the wire is the failure mode these guards
// exist to prevent.
func TestBuildMessage_RejectsOutOfProfileInputs(t *testing.T) {
	devicePriv, _ := keyPair(t, 0x11)
	_, serverPub := keyPair(t, 0x22)

	// valid returns a fresh, fully-valid input set for a subcase to perturb.
	valid := func() *Inputs {
		return &Inputs{
			DeviceStaticPriv: devicePriv,
			ServerStaticPub:  serverPub,
			EphemeralPriv:    bytes.Repeat([]byte{0x33}, PublicKeySize),
			TimestampNanos:   1700000000123456789,
			Counter:          7,
			Preamble:         0x01020304,
			Body:             []byte("builder guard fixture"),
		}
	}

	tests := []struct {
		name       string
		headerType int
		flags      uint16
		mutate     func(inp *Inputs)
		wantSub    string
	}{
		{
			// Only 0 and compress are buildable on a non-RKN, non-proof message;
			// the proof bit is reachable exclusively via BuildHubLSTCookieProof.
			name:       "proof flag on an ordinary knock",
			headerType: TypeKNK,
			flags:      hubLSTCookieProofFlag,
			wantSub:    "does not support flags",
		},
		{
			name:       "unknown flag bit",
			headerType: TypeLST,
			flags:      1 << 3,
			wantSub:    "does not support flags",
		},
		{
			name:       "proof flag on a re-knock",
			headerType: TypeRKN,
			flags:      hubLSTCookieProofFlag,
			wantSub:    "does not support flags",
		},
		{
			name:       "server static pub too short",
			headerType: TypeKNK,
			mutate:     func(inp *Inputs) { inp.ServerStaticPub = serverPub[:PublicKeySize-1] },
			wantSub:    "server static pub must be",
		},
		{
			name:       "server static pub too long",
			headerType: TypeKNK,
			mutate:     func(inp *Inputs) { inp.ServerStaticPub = append(bytes.Clone(serverPub), 0x00) },
			wantSub:    "server static pub must be",
		},
		{
			// The plaintext and sealed ceilings share an error prefix and a body
			// one byte over the plaintext ceiling also overflows the sealed one,
			// so this asserts the plaintext size to prove WHICH guard tripped.
			name:       "body past the plaintext ceiling",
			headerType: TypeKNK,
			mutate:     func(inp *Inputs) { inp.Body = make([]byte, maxApplicationBodySize+1) },
			wantSub:    fmt.Sprintf("knock body too large: %d bytes exceeds", maxApplicationBodySize+1),
		},
		{
			name:       "ephemeral private key is not a scalar",
			headerType: TypeKNK,
			mutate:     func(inp *Inputs) { inp.EphemeralPriv = bytes.Repeat([]byte{0x33}, PublicKeySize-1) },
			wantSub:    "derive ephemeral pub",
		},
		{
			name:       "device static private key is not a scalar",
			headerType: TypeKNK,
			mutate:     func(inp *Inputs) { inp.DeviceStaticPriv = devicePriv[:PublicKeySize-1] },
			wantSub:    "derive device static pub",
		},
		{
			// zlib EXPANDS incompressible input, so a body that is legal
			// uncompressed can still overflow the sealed ceiling once the
			// compress flag is set. Only the post-seal check catches this.
			name:       "compressed body expands past the sealed ceiling",
			headerType: TypeKNK,
			mutate: func(inp *Inputs) {
				inp.Body = incompressibleBytes(maxApplicationBodySize)
				inp.Compress = true
			},
			wantSub: "sealed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inp := valid()
			if tt.mutate != nil {
				tt.mutate(inp)
			}
			packet, err := buildMessage(tt.headerType, tt.flags, inp)
			if err == nil {
				t.Fatalf("buildMessage(%d, %#04x) accepted out-of-profile inputs, want reject", tt.headerType, tt.flags)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
			if packet != nil {
				t.Errorf("rejected build returned a %d-byte packet alongside the error", len(packet))
			}
		})
	}
}

// TestBuildMessage_AcceptsBodyAtCeiling pins the two ceilings as inclusive: an
// uncompressed body of exactly maxApplicationBodySize seals to exactly
// maxSealedBodySize and fills the responder's buffer precisely. Without this the
// oversize guards could be tightened to >= and no other test would notice.
func TestBuildMessage_AcceptsBodyAtCeiling(t *testing.T) {
	devicePriv, devicePub := keyPair(t, 0x11)
	serverPriv, serverPub := keyPair(t, 0x22)

	packet, err := BuildMessage(TypeKNK, &Inputs{
		DeviceStaticPriv: devicePriv,
		ServerStaticPub:  serverPub,
		EphemeralPriv:    bytes.Repeat([]byte{0x33}, PublicKeySize),
		TimestampNanos:   1700000000123456789,
		Counter:          7,
		Preamble:         0x01020304,
		Body:             incompressibleBytes(maxApplicationBodySize),
	})
	if err != nil {
		t.Fatalf("a body at the ceiling was rejected: %v", err)
	}
	if len(packet) != PacketBufferSize {
		t.Fatalf("packet = %d bytes, want exactly %d", len(packet), PacketBufferSize)
	}
	msg, err := DecryptMessage(serverPriv, devicePub, packet)
	if err != nil {
		t.Fatalf("ceiling-sized packet did not open: %v", err)
	}
	if !bytes.Equal(msg.Body, incompressibleBytes(maxApplicationBodySize)) {
		t.Fatal("ceiling-sized body did not survive the round trip")
	}
}
