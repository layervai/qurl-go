package relayknock

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func TestRelayErrorString(t *testing.T) {
	tests := []struct {
		name string
		err  *RelayError
		want string
	}{
		{name: "nil", err: nil, want: "relay error"},
		{name: "empty", err: &RelayError{}, want: "relay error"},
		{name: "message", err: &RelayError{Msg: "relay failed"}, want: "relay failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("RelayError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildKnockOutboundWipesMintedDevicePrivateKeyOnError(t *testing.T) {
	serverPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })
	captured := &captureRandomReader{failAt: 2}
	rand.Reader = captured
	if _, _, _, err := buildKnockOutbound(serverPrivate.PublicKey().Bytes(), nil, KnockOptions{}); err == nil {
		t.Fatal("buildKnockOutbound succeeded after injected ephemeral-key entropy failure")
	}
	if len(captured.buffers) != 1 || !allZero(captured.buffers[0]) {
		t.Fatalf("minted device private key was not wiped after build failure: %x", captured.buffers)
	}
}

type captureRandomReader struct {
	calls   int
	failAt  int
	buffers [][]byte
}

func (r *captureRandomReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == r.failAt {
		return 0, errors.New("injected entropy failure")
	}
	for i := range p {
		p[i] = byte(i + r.calls)
	}
	r.buffers = append(r.buffers, p)
	return len(p), nil
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
