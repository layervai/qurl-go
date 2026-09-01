package sessionrelay_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
	"github.com/layervai/qurl-go/relayknock/sessionrelay"
)

type relayKeys struct {
	serverPriv []byte
	serverPub  []byte
	devicePriv []byte
	devicePub  []byte
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func newRelayKeys(t *testing.T) relayKeys {
	t.Helper()
	curve := ecdh.X25519()
	server, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return relayKeys{server.Bytes(), server.PublicKey().Bytes(), device.Bytes(), device.PublicKey().Bytes()}
}

func buildReply(t *testing.T, headerType int, keys relayKeys, counter uint64, body []byte) []byte {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := relayknocktest.BuildReply(headerType, &relayknock.KnockInputs{
		DeviceStaticPriv: keys.serverPriv,
		ServerStaticPub:  keys.devicePub,
		EphemeralPriv:    ephemeral.Bytes(),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         7,
		Body:             body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestKnockWithReknock_DirectACKUsesOneHTTPSFlight(t *testing.T) {
	keys := newRelayKeys(t)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/octet-stream" ||
			r.URL.Path != "/relay/"+relayknock.PubKeyFingerprint(keys.serverPub) {
			t.Errorf("request = %s %s (%s)", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		packet, readErr := io.ReadAll(io.LimitReader(r.Body, 4097))
		opened, err := relayknocktest.OpenInitiatorMessage(keys.serverPriv, keys.devicePub, packet)
		if readErr != nil {
			err = readErr
		}
		if err != nil || opened.Type != relayknock.TypeKnock || string(opened.Body) != `{"leg":"knock"}` {
			t.Errorf("open KNK = %#v, %v", opened, err)
			return
		}
		_, _ = w.Write(buildReply(t, relayknock.TypeACK, keys, opened.Counter, []byte(`{"errCode":"0"}`)))
	}))
	defer server.Close()
	transport, err := sessionrelay.New(server.URL+"/", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	reply, err := transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv,
		[]byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`))
	if err != nil || !reply.IsACK() || calls.Load() != 1 {
		t.Fatalf("reply/error/calls = %#v/%v/%d", reply, err, calls.Load())
	}
}

func TestKnockWithReknock_OneStrictCookieBoundRKN(t *testing.T) {
	keys := newRelayKeys(t)
	cookie := bytes.Repeat([]byte{0x5a}, 32)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, readErr := io.ReadAll(io.LimitReader(r.Body, 4097))
		if readErr != nil {
			t.Errorf("read relay request: %v", readErr)
			return
		}
		switch calls.Add(1) {
		case 1:
			opened, err := relayknocktest.OpenInitiatorMessage(keys.serverPriv, keys.devicePub, packet)
			if err != nil || opened.Type != relayknock.TypeKnock {
				t.Errorf("open KNK = %#v, %v", opened, err)
				return
			}
			body := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, opened.Counter, base64.StdEncoding.EncodeToString(cookie)))
			_, _ = w.Write(buildReply(t, relayknock.TypeCookieChallenge, keys, opened.Counter+1, body))
		case 2:
			opened, err := relayknocktest.OpenReknockMessage(keys.serverPriv, keys.devicePub, cookie, packet)
			if err != nil || opened.Type != relayknock.TypeReknock || string(opened.Body) != `{"leg":"reknock"}` {
				t.Errorf("open RKN = %#v, %v", opened, err)
				return
			}
			_, _ = w.Write(buildReply(t, relayknock.TypeACK, keys, opened.Counter, []byte(`{"errCode":"0"}`)))
		default:
			t.Error("unexpected third relay flight")
			http.Error(w, "extra", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	transport, err := sessionrelay.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	reply, err := transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv,
		[]byte(`{"leg":"knock"}`), []byte(`{"leg":"reknock"}`))
	if err != nil || !reply.IsACK() || calls.Load() != 2 {
		t.Fatalf("reply/error/calls = %#v/%v/%d", reply, err, calls.Load())
	}
}

func TestKnockWithReknock_RejectsUncorrelatedCOKWithoutRKN(t *testing.T) {
	keys := newRelayKeys(t)
	cookie := bytes.Repeat([]byte{0x5a}, 32)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		packet, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil {
			t.Errorf("read relay request: %v", err)
			return
		}
		opened, err := relayknocktest.OpenInitiatorMessage(keys.serverPriv, keys.devicePub, packet)
		if err != nil {
			t.Errorf("open KNK: %v", err)
			return
		}
		body := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, opened.Counter+1, base64.StdEncoding.EncodeToString(cookie)))
		_, _ = w.Write(buildReply(t, relayknock.TypeCookieChallenge, keys, opened.Counter, body))
	}))
	defer server.Close()
	transport, err := sessionrelay.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, relayknock.ErrMalformedReply) || calls.Load() != 1 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
	if !strings.Contains(err.Error(), "(counter)") || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(cookie)) {
		t.Fatalf("error lost safe rejection class or exposed cookie: %v", err)
	}
}

func TestTransport_RejectsReplyFromUnpinnedServer(t *testing.T) {
	keys := newRelayKeys(t)
	other := newRelayKeys(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil {
			t.Errorf("read relay request: %v", err)
			return
		}
		opened, err := relayknocktest.OpenInitiatorMessage(keys.serverPriv, keys.devicePub, packet)
		if err != nil {
			t.Errorf("open KNK: %v", err)
			return
		}
		forged := keys
		forged.serverPriv = other.serverPriv
		_, _ = w.Write(buildReply(t, relayknock.TypeACK, forged, opened.Counter, []byte(`{"errCode":"0"}`)))
	}))
	defer server.Close()
	transport, err := sessionrelay.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, sessionrelay.ErrServerUnauthenticated) {
		t.Fatalf("error = %v", err)
	}
}

func TestTransport_RefusesRedirectWithoutSecondRequest(t *testing.T) {
	keys := newRelayKeys(t)
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	transport, err := sessionrelay.New(origin.URL, origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, sessionrelay.ErrTransport) || targetCalls.Load() != 0 {
		t.Fatalf("error/target calls = %v/%d", err, targetCalls.Load())
	}
}

func TestTransport_RedactsHTTPErrorAndRejectsOversize(t *testing.T) {
	keys := newRelayKeys(t)
	for _, test := range []struct {
		name string
		body []byte
		code int
		want error
	}{
		{name: "HTTP error", body: []byte("internal-secret-detail"), code: http.StatusBadGateway, want: sessionrelay.ErrTransport},
		{name: "oversize", body: make([]byte, 4097), code: http.StatusOK, want: sessionrelay.ErrServerUnauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.code)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			transport, err := sessionrelay.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "internal-secret-detail") ||
				strings.Contains(err.Error(), relayknock.PubKeyFingerprint(keys.serverPub)) {
				t.Fatalf("error exposed relay detail: %v", err)
			}
		})
	}
}

func TestTransport_DoesNotSendCallerClientCookies(t *testing.T) {
	keys := newRelayKeys(t)
	var cookieHeader atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieHeader.Store(r.Header.Get("Cookie"))
		http.Error(w, "stop", http.StatusBadGateway)
	}))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(origin, []*http.Cookie{{Name: "unrelated_secret", Value: "must-not-leave-client"}})
	client := server.Client()
	client.Jar = jar
	transport, err := sessionrelay.New(server.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, sessionrelay.ErrTransport) {
		t.Fatalf("error = %v", err)
	}
	if got, _ := cookieHeader.Load().(string); got != "" {
		t.Fatalf("relay request carried caller cookie: %q", got)
	}
}

func TestTransport_BoundsHangingFlightAndPreservesEarlierCallerDeadline(t *testing.T) {
	keys := newRelayKeys(t)
	blockingClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	transport, err := sessionrelay.New("https://relay.example.test", blockingClient)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, sessionrelay.ErrTransport) {
		t.Fatalf("default-timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > sessionrelay.DefaultTimeout+2*time.Second {
		t.Fatalf("default timeout took %s, want at most %s", elapsed, sessionrelay.DefaultTimeout+2*time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started = time.Now()
	_, err = transport.KnockWithReknock(ctx, keys.serverPub, keys.devicePriv, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller-deadline error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("caller deadline took %s, want less than one second", elapsed)
	}
}

func TestTransport_RejectsInvalidConfigAndOversizeRequestBeforeIO(t *testing.T) {
	keys := newRelayKeys(t)
	for _, raw := range []string{
		"http://relay.example", "https://user@relay.example", "https://relay.example/path",
		"https://relay.example?q=1", "https://relay.example?", "https://relay.example#",
		"https://relay.example/?", "https://relay.example/#", "https://relay.example:",
		"https://relay.example:/", "https://relay.example//", "https://relay.example ",
	} {
		if _, err := sessionrelay.New(raw, nil); !errors.Is(err, sessionrelay.ErrInvalidConfig) {
			t.Fatalf("New(%q) error = %v", raw, err)
		}
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	transport, err := sessionrelay.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.KnockWithReknock(context.Background(), keys.serverPub, keys.devicePriv,
		make([]byte, nhpcontract.MaxApplicationBodySize+1), nil)
	if !errors.Is(err, sessionrelay.ErrInvalidRequest) || calls.Load() != 0 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
}
