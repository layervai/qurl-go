package relayknock

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/relayknock/internal/nhpwire"
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

// TestKnock_DeviceKeyOwnership pins the two halves of KnockOptions'
// key-ownership contract, which is otherwise invisible: a key Knock MINTED is a
// throwaway it must scrub before returning, and a key the CALLER supplied stays
// caller-owned and must come back untouched (the qURL path reuses its per-link
// key across knocks, so wiping it would break the next call).
//
// Both subcases drive the relay to a reply that cannot be decrypted, which is
// also the only coverage of Knock's decrypt-failure return: the deferred wipe
// runs on the error path too, so an error return must not leak the key. The
// reply is a header of 0xff, so it is refused at the version gate — the fake
// relay never needs the minted public key, keeping the key off the handler
// goroutine entirely.
func TestKnock_DeviceKeyOwnership(t *testing.T) {
	serverPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	serverPub := serverPrivate.PublicKey().Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bytes.Repeat([]byte{0xff}, nhpwire.HeaderSize))
	}))
	defer srv.Close()

	t.Run("minted throwaway key is wiped", func(t *testing.T) {
		originalReader := rand.Reader
		t.Cleanup(func() { rand.Reader = originalReader })
		captured := &captureRandomReader{}
		rand.Reader = captured

		_, err := Knock(context.Background(), srv.URL, serverPub, []byte("knock body"), KnockOptions{})
		if err == nil || !strings.Contains(err.Error(), "decrypt reply") {
			t.Fatalf("Knock error = %v, want an undecryptable-reply rejection", err)
		}
		var relayErr *RelayError
		if errors.As(err, &relayErr) {
			t.Errorf("decrypt failure surfaced as *RelayError (%v); it is not an HTTP transport fault", relayErr)
		}
		if len(captured.buffers) == 0 || len(captured.buffers[0]) != 32 {
			t.Fatalf("no 32-byte device key was minted: %x", captured.buffers)
		}
		if !allZero(captured.buffers[0]) {
			t.Fatalf("minted throwaway device key survived Knock: %x", captured.buffers[0])
		}
	})

	t.Run("caller-supplied key is left intact", func(t *testing.T) {
		devicePriv := bytes.Repeat([]byte{0x11}, 32)
		want := bytes.Clone(devicePriv)

		if _, err := Knock(context.Background(), srv.URL, serverPub, []byte("knock body"), KnockOptions{DeviceStaticPriv: devicePriv}); err == nil {
			t.Fatal("Knock succeeded against an undecryptable reply, want rejection")
		}
		if !bytes.Equal(devicePriv, want) {
			t.Fatalf("caller-owned device key was modified: %x, want %x", devicePriv, want)
		}
	})
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
