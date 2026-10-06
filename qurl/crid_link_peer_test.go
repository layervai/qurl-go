package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// cridLinkPeer stands in for the relay and the cell behind it. It opens real
// NHP packets and seals real replies, so a test that uses it drives the
// production request path end to end: the knock is built, sealed, POSTed,
// opened, answered, authenticated, and interpreted by the code a caller runs.
//
// What makes it different from portalSessionPeer is the one thing a CRID link
// request changes on the wire: the initiator key is minted per request, so the
// peer cannot know it in advance and has to learn it from the packet.
type cridLinkPeer struct {
	t         *testing.T
	server    *httptest.Server
	serverKey *ecdh.PrivateKey

	mu     sync.Mutex
	knocks []cridLinkKnock
	answer func(cridLinkKnock) cridLinkAnswer
}

// cridLinkKnock is one request as the cell saw it after opening the packet.
type cridLinkKnock struct {
	devicePub  []byte
	headerType int
	counter    uint64
	body       []byte
}

// cridLinkAnswer is what the peer sends back for one request.
type cridLinkAnswer struct {
	// status, when nonzero, answers at the HTTP layer, as a relay that could
	// not get an answer from the cell does. text is its response body.
	status int
	text   string

	// Otherwise the peer sends an authenticated reply of replyType carrying
	// body, echoing the request counter plus counterSkew.
	replyType   int
	body        []byte
	counterSkew uint64
	// unknownType sends an authenticated packet whose header type is none this
	// SDK speaks, instead of replyType.
	unknownType int

	// sealedBy, when set, seals the reply under this static private key instead
	// of the cell's. It is the most a relay that makes up an answer can do:
	// everything about the reply is right except who it is from.
	sealedBy []byte

	// hold, when set, keeps the request open until it is closed or the client
	// goes away. It is how a relay that never answers is modeled.
	hold <-chan struct{}
}

func newCRIDLinkPeer(t *testing.T) *cridLinkPeer {
	t.Helper()
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := &cridLinkPeer{t: t, serverKey: serverKey}
	peer.server = httptest.NewTLSServer(http.HandlerFunc(peer.serveHTTP))
	t.Cleanup(peer.server.Close)
	return peer
}

// respond makes the peer give the same answer to every request.
func (p *cridLinkPeer) respond(answer cridLinkAnswer) {
	p.respondWith(func(cridLinkKnock) cridLinkAnswer { return answer })
}

func (p *cridLinkPeer) respondWith(answer func(cridLinkKnock) cridLinkAnswer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = answer
}

// seen returns the requests the peer has opened so far.
func (p *cridLinkPeer) seen() []cridLinkKnock {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]cridLinkKnock(nil), p.knocks...)
}

// config is an opener Config whose CRID link endpoint is this peer: its relay
// is the peer's HTTPS server and its one cell carries the peer's key.
func (p *cridLinkPeer) config(trust *TrustStore) Config {
	p.t.Helper()
	relay, err := url.Parse(p.server.URL)
	if err != nil {
		p.t.Fatal(err)
	}
	return Config{
		TrustStore:     trust,
		Cells:          p.cells(),
		RelayAllowlist: NewRelayAllowlist([]string{relay.Host}),
		HTTPClient:     p.server.Client(),
		CRIDLink:       &CRIDLinkConfig{RelayURL: p.server.URL, LinkOrigin: cridLinkTestOrigin},
	}
}

func (p *cridLinkPeer) cells() *CellCatalog {
	p.t.Helper()
	catalog, err := NewCellCatalog([]CellEntry{{
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(p.serverKey.PublicKey().Bytes()),
		CellID:             "crid-link-test-cell", Host: "cell.example.test", Port: standardNHPUDPPort,
	}})
	if err != nil {
		p.t.Fatal(err)
	}
	return catalog
}

func (p *cridLinkPeer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// The relay contract: the sealed packet is POSTed to /relay/{serverId},
	// where the id is the fingerprint of the key the packet is sealed to.
	wantPath := "/relay/" + relayknock.PubKeyFingerprint(p.serverKey.PublicKey().Bytes())
	if r.Method != http.MethodPost || r.URL.Path != wantPath || r.URL.RawQuery != "" {
		p.t.Errorf("relay request = %s %s, want POST %s", r.Method, r.URL.RequestURI(), wantPath)
		http.Error(w, "wrong route", http.StatusBadRequest)
		return
	}
	if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
		p.t.Errorf("relay Content-Type = %q, want application/octet-stream", got)
	}
	packet, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		p.t.Error(err)
		return
	}
	message, devicePub, err := relayknocktest.OpenUnknownInitiatorMessage(p.serverKey.Bytes(), packet)
	if err != nil {
		p.t.Errorf("open the request packet: %v", err)
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}
	knock := cridLinkKnock{devicePub: devicePub, headerType: message.Type, counter: message.Counter, body: message.Body}

	p.mu.Lock()
	p.knocks = append(p.knocks, knock)
	answer := p.answer
	p.mu.Unlock()
	if answer == nil {
		p.t.Error("the peer received a request no test told it how to answer")
		http.Error(w, "no answer configured", http.StatusInternalServerError)
		return
	}
	reply := answer(knock)

	if reply.hold != nil {
		select {
		case <-reply.hold:
		case <-r.Context().Done():
			return
		}
		// A held request with nothing else configured models a relay that
		// never answers. Being released, at test cleanup, is not an answer:
		// the handler may be let go before it has noticed the client leave.
		if reply.status == 0 && reply.replyType == 0 && reply.unknownType == 0 {
			return
		}
	}
	if reply.status != 0 {
		http.Error(w, reply.text, reply.status)
		return
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		p.t.Error(err)
		return
	}
	sealingKey := p.serverKey.Bytes()
	if reply.sealedBy != nil {
		sealingKey = reply.sealedBy
	}
	inputs := &relayknock.KnockInputs{
		DeviceStaticPriv: sealingKey,
		ServerStaticPub:  devicePub, // sealed to the key learned from the request
		EphemeralPriv:    ephemeral.Bytes(),
		Counter:          message.Counter + reply.counterSkew,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Body:             reply.body,
		// A server compresses its replies, so the peer does too: the client
		// has to inflate a link-issued answer exactly as it will in service.
		Compress: true,
	}
	var sealed []byte
	if reply.unknownType != 0 {
		sealed, err = relayknocktest.BuildUnknownReplyForTest(reply.unknownType, inputs)
	} else {
		sealed, err = relayknocktest.BuildReply(reply.replyType, inputs)
	}
	if err != nil {
		p.t.Errorf("build reply: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(sealed); err != nil {
		p.t.Error(err)
	}
}

// cridLinkTestOrigin is the link origin the tests configure. It is the origin
// CreatePortalWithParams mints links on.
const cridLinkTestOrigin = "https://qurl.link"

// cridLinkACK builds an ACK body in the shape a link request is answered
// with: nothing opened, no session, no routing. members are added on top.
func cridLinkACK(t *testing.T, code string, members map[string]any) []byte {
	t.Helper()
	ack := map[string]any{
		"errCode": code, "errMsg": "diagnostic text, never read",
		"resHost": nil, "opnTime": 0, "agentAddr": "203.0.113.9:49152", "acTokens": nil,
	}
	for name, value := range members {
		ack[name] = value
	}
	body, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// cridLinkDenied is an ACK reply carrying only a refusal code.
func cridLinkDenied(t *testing.T, code string) cridLinkAnswer {
	t.Helper()
	return cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, code, nil)}
}

// cridLinkIssued is a link-issued ACK reply. A nil info omits the metadata.
func cridLinkIssued(t *testing.T, link any, info any) cridLinkAnswer {
	t.Helper()
	members := map[string]any{"redirectUrl": link}
	if info != nil {
		members["redirectInfo"] = info
	}
	return cridLinkAnswer{replyType: relayknock.TypeACK, body: cridLinkACK(t, cridLinkCodeIssued, members)}
}

// cridLinkFixture is a peer, a CRID, and a link the peer can issue for it: the
// link is signed by an issuer the config trusts and its resource key derives
// the CRID.
type cridLinkFixture struct {
	peer        *cridLinkPeer
	signer      *LocalSigner
	cfg         Config
	crid        string
	resourceKey []byte
	foreignKey  []byte
	link        string
}

func newCRIDLinkFixture(t *testing.T) *cridLinkFixture {
	t.Helper()
	peer := newCRIDLinkPeer(t)
	signer, trust := mintSigner(t)
	// The CRID and both keys are the released CRID v1 key-match fixtures, so
	// the link checks are anchored to the frozen derivation, not to a helper
	// in this file.
	held, matching, foreign := cridKeyMatchFixture(t)
	fixture := &cridLinkFixture{
		peer: peer, signer: signer, cfg: peer.config(trust),
		crid: held, resourceKey: matching, foreignKey: foreign,
	}
	fixture.link = fixture.mint(t, matching)
	return fixture
}

// mint signs a link for resourceKey that names the peer as its cell.
func (f *cridLinkFixture) mint(t *testing.T, resourceKey []byte) string {
	t.Helper()
	link, err := CreatePortalWithParams(t.Context(), f.signer, CreateParams{
		CellPublicKey:     f.peer.serverKey.PublicKey().Bytes(),
		RelayURL:          f.peer.server.URL,
		ResourcePublicKey: resourceKey,
		CellID:            "crid-link-test-cell",
		JTI:               "qurl_01JCRIDLINKTEST",
		IssuedAt:          1781910000, NotBefore: 1781910000, Expiry: 1781910300,
	})
	if err != nil {
		t.Fatalf("mint link: %v", err)
	}
	return link
}

// info is well-formed reply metadata for the fixture's CRID.
func (f *cridLinkFixture) info() map[string]any {
	return map[string]any{
		"crid":                f.crid,
		"qurl_id":             "q_a1b2c3d4e5f",
		"expires_at":          "2026-06-19T23:05:00Z",
		"resource_created_at": "2026-06-18T09:30:00Z",
		"publisher":           map[string]any{"name": "Example Publisher", "verified": false},
	}
}

// testCRIDForKey derives the CRID of a DER resource key under a version byte
// and digest length. The crid package deliberately has no producer; tests that
// need a CRID for a key they minted, or for a version the registry does not
// carry, build it here. TestCRIDLinkTestDerivationMatchesTheArtifact pins this
// helper to the released fixtures.
func testCRIDForKey(version byte, digestLength int, derSPKI []byte) string {
	message := append(append([]byte("NHP-QURL-CRID-V1"), 0x00), derSPKI...)
	digest := sha256.Sum256(message)
	payload := append([]byte{version}, digest[:digestLength]...)
	payload = binary.BigEndian.AppendUint32(payload, crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	return base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding).EncodeToString(payload)
}

// startCRIDLinkCellUDP runs the peer's cell on a loopback UDP socket, for the
// second step of an open by CRID: the ordinary knock with the issued link. It
// returns the socket seam that routes the opener's native UDP exchange there,
// and a function reporting the initiator keys of the knocks it admitted.
//
// The cell admits a knock only if it is the link-opening knock for wantLink:
// sent under the link's own key, naming the link's resource, and carrying the
// link's signed claims. That is what an open by CRID must end in.
func startCRIDLinkCellUDP(t *testing.T, peer *cridLinkPeer, trust *TrustStore, wantLink, resourceURL string) (*nativeudp.Options, func() [][]byte) {
	t.Helper()
	fragment, err := VerifyLink(wantLink, trust)
	if err != nil {
		t.Fatalf("verify the fixture link: %v", err)
	}
	linkKey := mustDecode(t, fragment.Claims.QurlUserPublicKeyB64)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var admitted [][]byte
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
			// A knock under any other key does not open, exactly as a cell
			// that matches the initiator key to the signed claims refuses it.
			message, openErr := relayknocktest.OpenInitiatorMessage(peer.serverKey.Bytes(), linkKey, packet[:n])
			if openErr != nil {
				t.Errorf("the open knock was not sent under the link's own key: %v", openErr)
				continue
			}
			var body agentKnockMsg
			if err := json.Unmarshal(message.Body, &body); err != nil {
				t.Error(err)
				continue
			}
			if message.Type != relayknock.TypeKnock || body.HeaderType != nhpKNKHeaderType || body.AspID != qurlAspID ||
				body.ResID != fragment.Claims.ResourcePublicKeyB64 ||
				body.UsrData[claimsUserDataKey] != fragment.ClaimsB64 || body.UsrData[sigUserDataKey] != fragment.SigB64 {
				t.Error("the open knock is not the link-opening knock for the issued link")
				continue
			}
			mu.Lock()
			admitted = append(admitted, linkKey)
			mu.Unlock()

			ephemeral, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Error(keyErr)
				return
			}
			reply, buildErr := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{
				DeviceStaticPriv: peer.serverKey.Bytes(), ServerStaticPub: linkKey,
				EphemeralPriv: ephemeral.Bytes(), Counter: message.Counter,
				TimestampNanos: uint64(time.Now().UnixNano()), Compress: true,
				Body: []byte(`{"errCode":"0","sessId":123,"opnTime":900,"redirectUrl":"` + resourceURL +
					`","aspToken":"` + testAuthProviderToken + `"}`),
			})
			if buildErr != nil {
				t.Error(buildErr)
				return
			}
			if _, writeErr := conn.WriteToUDP(reply, addr); writeErr != nil {
				t.Error(writeErr)
			}
		}
	}()

	options := &nativeudp.Options{
		// nativeudp only sends to public addresses, so the cell's name resolves
		// to one and the dialer is what points the socket at loopback.
		Resolver: assignmentTestResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer:  assignmentTestDialer{target: conn.LocalAddr().String()},
		Timeout: 2 * time.Second, MaxAddresses: 1,
	}
	return options, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), admitted...)
	}
}
