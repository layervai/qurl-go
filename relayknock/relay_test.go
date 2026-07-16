package relayknock

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
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

func TestSendWipesMintedDevicePrivateKey(t *testing.T) {
	serverPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	})

	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })
	captured := &captureRandomReader{}
	rand.Reader = captured
	if err := Send(context.Background(), "https://relay.example", serverPrivate.PublicKey().Bytes(), []byte("otp"), KnockOptions{HTTPClient: httpClient}); err != nil {
		t.Fatal(err)
	}
	if len(captured.buffers) < 2 || !allZero(captured.buffers[0]) || !allZero(captured.buffers[1]) {
		t.Fatalf("minted device/ephemeral private keys were not wiped: %x", captured.buffers)
	}

	callerPrivate := bytes.Repeat([]byte{0x33}, 32)
	wantCallerPrivate := bytes.Clone(callerPrivate)
	rand.Reader = &captureRandomReader{}
	if err := Send(context.Background(), "https://relay.example", serverPrivate.PublicKey().Bytes(), []byte("otp"), KnockOptions{
		HTTPClient: httpClient, DeviceStaticPriv: callerPrivate,
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(callerPrivate, wantCallerPrivate) {
		t.Fatal("Send wiped its caller-owned device private key")
	}
}

func TestBuildOutboundWipesMintedDevicePrivateKeyOnError(t *testing.T) {
	serverPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	originalReader := rand.Reader
	t.Cleanup(func() { rand.Reader = originalReader })
	captured := &captureRandomReader{failAt: 2}
	rand.Reader = captured
	if _, _, _, err := buildOutbound(TypeKnock, serverPrivate.PublicKey().Bytes(), nil, KnockOptions{}); err == nil {
		t.Fatal("buildOutbound succeeded after injected ephemeral-key entropy failure")
	}
	if len(captured.buffers) != 1 || !allZero(captured.buffers[0]) {
		t.Fatalf("minted device private key was not wiped after build failure: %x", captured.buffers)
	}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

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
