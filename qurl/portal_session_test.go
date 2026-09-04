package qurl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/internal/qv2"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

func TestPortalSessionConcurrentBindingAndRedaction(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	frag, err := qv2.FragmentFromLinkAndVerify(link, trust.core())
	if err != nil {
		t.Fatal(err)
	}
	var session PortalSession
	var wg sync.WaitGroup
	secrets := make(chan string, 32)
	for range cap(secrets) {
		wg.Go(func() {
			secret, secretErr := session.secretFor(frag)
			if secretErr != nil {
				t.Error(secretErr)
				return
			}
			secrets <- secret
		})
	}
	wg.Wait()
	close(secrets)
	first := <-secrets
	decoded, err := b64url.Strict().DecodeString(first)
	if err != nil || len(decoded) != 32 || len(first) != 43 {
		t.Fatal("visitor capability is not canonical 32-byte base64url")
	}
	for secret := range secrets {
		if secret != first {
			t.Fatal("concurrent calls changed the visitor capability")
		}
	}
	if strings.Contains(link, first) || first == frag.Secret.QurlUserPrivateKeyB64 {
		t.Fatal("visitor capability was derived from the share link")
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", &session), fmt.Sprintf("%+v", &session),
		fmt.Sprintf("%#v", &session), fmt.Sprintf("%#v", Config{PortalSession: &session}),
	} {
		if strings.Contains(rendered, first) {
			t.Fatal("formatting exposed the visitor capability")
		}
	}
	encoded, err := json.Marshal(Config{PortalSession: &session})
	if err != nil || strings.Contains(string(encoded), first) || !strings.Contains(string(encoded), `"PortalSession":{}`) {
		t.Fatal("config JSON exposed visitor state")
	}
}

func TestPortalSessionFailedVerificationDoesNotBind(t *testing.T) {
	link, trust, _ := vendoredAcceptLink(t)
	var session PortalSession
	doer := &capturingDoer{}
	cfg := Config{TrustStore: freshTrustStore(t), RelayAllowlist: relayExampleAllowlist(), HTTPClient: doer, PortalSession: &session}
	if _, err := EnterPortalWith(t.Context(), link, cfg); err == nil {
		t.Fatal("untrusted link passed verification")
	}
	if session.state != nil || doer.gotURL != "" {
		t.Fatal("untrusted link bound a visitor or reached the relay")
	}
	cfg.TrustStore = trust
	if _, err := EnterPortalWith(t.Context(), link, cfg); err == nil {
		t.Fatal("capturing relay unexpectedly succeeded")
	}
	if session.state == nil || doer.gotURL == "" {
		t.Fatal("verified link did not bind a visitor before its first request")
	}
}

// portalSessionPeer decrypts real NHP packets received over HTTPS. Its small
// admission rule models the service's one-time visitor binding; service/NHP
// integration tests own the actual repository and verifier enforcement.
type portalSessionPeer struct {
	t          *testing.T
	server     *httptest.Server
	serverKey  *ecdh.PrivateKey
	devicePub  []byte
	fragment   *qv2.Fragment
	mu         sync.Mutex
	bound      [sha256.Size]byte
	boundSet   bool
	dropReply  bool
	capability []string
}

func newPortalSessionPeer(t *testing.T, loseFirstReply bool) (*portalSessionPeer, string, Config) {
	t.Helper()
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := &portalSessionPeer{t: t, serverKey: serverKey, dropReply: loseFirstReply}
	peer.server = httptest.NewTLSServer(http.HandlerFunc(peer.serveHTTP))
	t.Cleanup(peer.server.Close)
	signer, trust := mintSigner(t)
	params := validCreateParams(t)
	params.CellPublicKey = serverKey.PublicKey().Bytes()
	params.RelayURL = peer.server.URL
	link, err := CreatePortalWithParams(t.Context(), signer, params)
	if err != nil {
		t.Fatal(err)
	}
	peer.fragment, err = qv2.FragmentFromLinkAndVerify(link, trust.core())
	if err != nil {
		t.Fatal(err)
	}
	peer.devicePub = mustDecode(t, peer.fragment.Claims.QurlUserPublicKeyB64)
	relayURL, err := url.Parse(peer.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return peer, link, Config{
		TrustStore: trust, RelayAllowlist: NewRelayAllowlist([]string{relayURL.Host}),
		HTTPClient: peer.server.Client(),
	}
}

func (p *portalSessionPeer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/relay/"+relayknock.PubKeyFingerprint(p.serverKey.PublicKey().Bytes()) {
		p.t.Error("portal used the wrong relay route")
		http.Error(w, "wrong route", http.StatusBadRequest)
		return
	}
	packet, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		p.t.Error(err)
		return
	}
	message, err := relayknocktest.OpenInitiatorMessage(p.serverKey.Bytes(), p.devicePub, packet)
	if err != nil {
		p.t.Error(err)
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}
	var body agentKnockMsg
	if err := json.Unmarshal(message.Body, &body); err != nil {
		p.t.Error(err)
		return
	}
	// Pin the cross-repository ASP keys independently of the producer constants.
	secret := body.UsrData["qurl_session_secret"]
	raw, err := b64url.Strict().DecodeString(secret)
	if err != nil || len(raw) != 32 || len(secret) != 43 || len(body.UsrData) != 3 ||
		body.HeaderType != nhpKNKHeaderType || body.AspID != qurlAspID || body.ResID != p.fragment.Claims.ResourcePublicKeyB64 ||
		body.UsrData["qurl_claims_b64"] != p.fragment.ClaimsB64 || body.UsrData["qurl_issuer_sig_b64"] != p.fragment.SigB64 {
		p.t.Error("NHP user data lost its verified envelope or private visitor capability")
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	visitor := sha256.Sum256(raw)
	p.mu.Lock()
	p.capability = append(p.capability, secret)
	if !p.boundSet {
		p.bound, p.boundSet = visitor, true
	}
	allowed := visitor == p.bound
	drop := p.dropReply
	p.dropReply = false
	p.mu.Unlock()
	if drop {
		// The server committed the first visit, but its ACK never reached the
		// client. A later request needs the same private visitor capability.
		http.Error(w, "upstream reply lost", http.StatusBadGateway)
		return
	}
	ackBody := []byte(`{"errCode":"51004","opnTime":0}`)
	if allowed {
		ackBody = []byte(`{"errCode":"0","sessId":123,"opnTime":900,"redirectUrl":"https://resource.example.com/report","aspToken":"` + testAuthProviderToken + `"}`)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		p.t.Error(err)
		return
	}
	reply, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{
		DeviceStaticPriv: p.serverKey.Bytes(), ServerStaticPub: p.devicePub,
		EphemeralPriv: ephemeral.Bytes(), Counter: message.Counter,
		TimestampNanos: uint64(time.Now().UnixNano()), Body: ackBody,
	})
	if err != nil {
		p.t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(reply); err != nil {
		p.t.Error(err)
	}
}

func TestPortalSessionHTTPSLostReplyRenewalAndIsolatedReplay(t *testing.T) {
	peer, link, cfg := newPortalSessionPeer(t, true)
	cfg.PortalSession = &PortalSession{}
	if handle, err := EnterPortalWith(t.Context(), link, cfg); err == nil || handle != nil {
		t.Fatal("lost ACK must surface as a transport failure")
	}
	for range 2 {
		handle, err := EnterPortalWith(t.Context(), link, cfg)
		if err != nil || handle == nil || handle.SessionID != 123 {
			t.Fatalf("same visitor could not recover or renew: %v", err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, handle.ResourceURL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if err := handle.AuthorizeContentRequest(request); err != nil {
			t.Fatal(err)
		}
		if cookie, err := request.Cookie(qurlVsessionCookieName); err != nil || cookie.Value != testAuthProviderToken {
			t.Fatal("recovered visitor lost its content-session bearer")
		}
	}
	for _, session := range []*PortalSession{nil, {}} {
		independent := cfg
		independent.PortalSession = session
		handle, err := EnterPortalWith(t.Context(), link, independent)
		var denied *ServerDenyError
		if handle != nil || !errors.As(err, &denied) {
			t.Fatalf("another holder of the shared link recovered the first visitor: %v", err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.capability) != 5 || peer.capability[0] != peer.capability[1] || peer.capability[1] != peer.capability[2] ||
		peer.capability[3] == peer.capability[0] || peer.capability[4] == peer.capability[0] || peer.capability[3] == peer.capability[4] {
		t.Fatal("visitor capability did not follow the caller-held session")
	}
}

func TestPortalSessionDifferentVerifiedLinkFailsBeforeIO(t *testing.T) {
	_, link, cfg := newPortalSessionPeer(t, false)
	cfg.PortalSession = &PortalSession{}
	if _, err := EnterPortalWith(t.Context(), link, cfg); err != nil {
		t.Fatal(err)
	}
	otherLink, otherTrust, _ := vendoredAcceptLink(t)
	doer := &capturingDoer{}
	cfg.TrustStore, cfg.RelayAllowlist, cfg.HTTPClient = otherTrust, relayExampleAllowlist(), doer
	handle, err := EnterPortalWith(context.Background(), otherLink, cfg)
	if handle != nil || !errors.Is(err, ErrPortalSessionLinkMismatch) || doer.gotURL != "" {
		t.Fatalf("another verified link reused a visitor session: %v", err)
	}
}

func TestPortalSessionNativeUDPLostReplyAndIsolatedReplay(t *testing.T) {
	peer, _, _ := newPortalSessionPeer(t, true)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	go func() {
		defer close(done)
		packet := make([]byte, 65536)
		for {
			n, addr, readErr := conn.ReadFromUDP(packet)
			if readErr != nil {
				return
			}
			// Reuse the same decrypt/admit/reply peer on a real UDP socket.
			// No HTTPS or relay transport is involved in the SDK exchange.
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				peer.server.URL+"/relay/"+relayknock.PubKeyFingerprint(peer.serverKey.PublicKey().Bytes()), bytes.NewReader(packet[:n]))
			peer.serveHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				continue // Model a committed visit whose ACK was lost.
			}
			if _, writeErr := conn.WriteToUDP(recorder.Body.Bytes(), addr); writeErr != nil {
				t.Error(writeErr)
			}
		}
	}()
	deviceKey, err := qv2.DecodeQurlUserPrivateKey(peer.fragment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	options := nativeudp.Options{
		DeviceStaticPriv: deviceKey,
		Resolver: assignmentTestResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer: assignmentTestDialer{target: conn.LocalAddr().String()}, Timeout: 100 * time.Millisecond, MaxAddresses: 1,
	}
	endpoint := nativeudp.Endpoint{Host: "cell.example.com", Port: 443, ServerStaticPub: peer.serverKey.PublicKey().Bytes()}
	open := func(session *PortalSession) (*ResourceHandle, error) {
		secret, secretErr := session.secretFor(peer.fragment)
		if secretErr != nil {
			return nil, secretErr
		}
		body, bodyErr := buildKnockBody(peer.fragment, secret)
		if bodyErr != nil {
			return nil, bodyErr
		}
		reply, knockErr := nativeudp.Knock(t.Context(), endpoint, body, options)
		if knockErr != nil {
			return nil, knockErr
		}
		return interpretReply(reply)
	}
	session := &PortalSession{}
	if handle, err := open(session); handle != nil || !errors.Is(err, nativeudp.ErrNoReply) {
		t.Fatalf("lost UDP ACK = %v, want no reply", err)
	}
	for range 2 {
		if handle, err := open(session); err != nil || handle == nil || handle.SessionID != 123 {
			t.Fatalf("bound UDP visitor could not recover/renew: %v", err)
		}
	}
	var denied *ServerDenyError
	if handle, err := open(&PortalSession{}); handle != nil || !errors.As(err, &denied) {
		t.Fatalf("isolated UDP visitor recovered another session: %v", err)
	}
}
