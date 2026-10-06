// Package qurltest provides test doubles for code that calls package qurl.
// Like net/http/httptest, it is a test-support package that sits beside the
// package it supports. Nothing in it is for production use.
//
// CRIDLinkServer answers CRID link requests in process, so a test can drive
// qurl.RequestCRIDLink and qurl.RequestCRIDLinkWith without a server:
//
//	server := qurltest.NewCRIDLinkServer()
//	issued, err := qurl.RequestCRIDLinkWith(ctx, server.CRID(), server.Config())
//
// The call above is the production call. The request is built, sealed and
// sent by the SDK, the reply is authenticated by the SDK, and the link passes
// every check the SDK runs on an issued link. The double has no way to turn a
// check off. It only stands where the relay and the server would stand.
//
// The link and the keys come from the public conformance vectors
// (github.com/layervai/qurl-conformance). They are test material that anyone
// can read. A Config or a Deployment from this package trusts the vector
// issuer key, so it must never be used outside a test.
package qurltest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// The addresses a CRIDLinkServer configures. Nothing listens on them: the
// names end in the reserved top-level domain "invalid", so a request that is
// not handed to the server cannot reach a real host.
const (
	relayHost = "relay.qurltest.invalid"
	relayURL  = "https://" + relayHost
	cellHost  = "cell.qurltest.invalid"
	cellID    = "qurltest-cell"
	// cellPort is the one UDP port a cell catalog accepts.
	cellPort = 443
)

// The two outcome codes the server sends on its own. Every other code is the
// one a test passes to Refuse.
const (
	codeNotFound       = "52602"
	codeInvalidRequest = "52606"
)

// maxPacketBytes bounds the request body the server reads. A sealed request is
// far smaller.
const maxPacketBytes = 64 << 10

// CRIDLinkServer stands in for the relay and the server that answer a CRID
// link request. It listens on no socket. Hand it to the SDK as the HTTP client
// of a Config, which is what Config does, and the SDK's request reaches it in
// process.
//
// By default it answers as a server that holds one resource:
//
//   - A request for CRID gets a link. The link is the fixture link of the
//     public vectors, and it passes every check the SDK runs for that CRID.
//   - A request for any other CRID is refused as not found, the answer a
//     server gives for a CRID it does not know.
//
// Refuse makes it answer every request with one refusal code instead, and
// Issue returns it to the default.
//
// It answers the link request only. It does not open the link: the link names
// a cell of the vectors, not this server, so qurl.OpenCRIDWith gets the link
// and then fails with qurl.ErrCellNotInCatalog before it sends anything.
//
// The fixture link carries a fixed expiry that is in the past. The SDK does
// not look at the expiry when it requests a link, because the server enforces
// it when the link is opened.
//
// A CRIDLinkServer is safe for concurrent use.
type CRIDLinkServer struct {
	key      *ecdh.PrivateKey
	fixtures *cridLinkFixtures
	trust    *qurl.TrustStore
	cells    *qurl.CellCatalog

	mu       sync.Mutex
	refusal  string
	requests []CRIDLinkRequest
}

// CRIDLinkRequest is one CRID link request as the server saw it after it
// opened the packet.
type CRIDLinkRequest struct {
	// CRID is the CRID the request named.
	CRID string
	// UserAgent is the user agent the request carried, or empty when it
	// carried none.
	UserAgent string
}

// cridLinkFixtures is what a CRIDLinkServer takes from the public vectors.
type cridLinkFixtures struct {
	crid       string
	linkOrigin string
	// issued is the complete link-issued reply body for crid.
	issued []byte

	issuerKID string
	issuerDER []byte

	// The request grammar: what makes a knock a link request.
	authServiceID string
	resourceID    string
	cridKey       string
	userAgentKey  string
}

// loadCRIDLinkFixtures reads the vectors once. The loader checks the artifact
// as it reads it, so a value taken from it is one the artifact's own
// validation has accepted.
var loadCRIDLinkFixtures = sync.OnceValues(func() (*cridLinkFixtures, error) {
	vectors, err := conformance.CRIDLinkKnockV1()
	if err != nil {
		return nil, fmt.Errorf("load the CRID link knock vectors: %w", err)
	}
	issuer, err := conformance.SignatureVectors()
	if err != nil {
		return nil, fmt.Errorf("load the issuer vectors: %w", err)
	}
	issuerDER, err := base64.RawURLEncoding.Strict().DecodeString(issuer.Issuer.SPKIDERB64)
	if err != nil {
		return nil, fmt.Errorf("decode the vector issuer key: %w", err)
	}
	fixtures := &cridLinkFixtures{
		crid:          vectors.Fixtures.CRID,
		linkOrigin:    vectors.Constants.LinkOrigin,
		issuerKID:     issuer.Issuer.KID,
		issuerDER:     issuerDER,
		authServiceID: vectors.Constants.AuthServiceID,
		resourceID:    vectors.Constants.ResourceID,
		cridKey:       vectors.Constants.UserDataKeys.CRID,
		userAgentKey:  vectors.Constants.UserDataKeys.UserAgent,
	}
	// The artifact's own link-issued reply for the fixture CRID: the link, and
	// the display metadata a server reports beside it.
	for _, c := range vectors.ACKCases {
		if c.Name == "link_issued" && c.RequestedCRID == fixtures.crid {
			fixtures.issued = c.Body
		}
	}
	if fixtures.issued == nil {
		return nil, fmt.Errorf("the CRID link knock vectors have no link_issued reply for the fixture CRID")
	}
	return fixtures, nil
})

// NewCRIDLinkServer returns a server that issues the fixture link for CRID.
// Each server has its own key, so two servers never accept each other's
// requests.
//
// It panics if the vectors this module depends on cannot be read, which no
// test can recover from.
func NewCRIDLinkServer() *CRIDLinkServer {
	fixtures, err := loadCRIDLinkFixtures()
	if err != nil {
		panic("qurltest: " + err.Error())
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("qurltest: generate the server key: " + err.Error())
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{fixtures.issuerKID: fixtures.issuerDER})
	if err != nil {
		panic("qurltest: build the trust store: " + err.Error())
	}
	server := &CRIDLinkServer{key: key, fixtures: fixtures, trust: trust}
	server.cells, err = qurl.NewCellCatalog([]qurl.CellEntry{server.cell()})
	if err != nil {
		panic("qurltest: build the cell catalog: " + err.Error())
	}
	return server
}

// cell is the one cell of the server's configuration. Its key is the server's.
func (s *CRIDLinkServer) cell() qurl.CellEntry {
	return qurl.CellEntry{
		CellID: cellID, Host: cellHost, Port: cellPort,
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(s.key.PublicKey().Bytes()),
	}
}

// CRID returns the CRID the server issues a link for.
func (s *CRIDLinkServer) CRID() string { return s.fixtures.crid }

// Config returns the configuration to pass to qurl.RequestCRIDLinkWith. Its
// CRID link endpoint is this server, its HTTP client is Client, and its trust
// store holds the vector issuer key and nothing else. Each call returns a
// fresh value, so a test may change it, for example to set
// Config.CRIDLink.UserAgent.
//
// Never use it outside a test: the vector issuer key is public test material.
func (s *CRIDLinkServer) Config() qurl.Config {
	return qurl.Config{
		TrustStore:     s.trust,
		Cells:          s.cells,
		RelayAllowlist: qurl.NewRelayAllowlist([]string{relayHost}),
		HTTPClient:     s.Client(),
		CRIDLink:       &qurl.CRIDLinkConfig{RelayURL: relayURL, LinkOrigin: s.fixtures.linkOrigin},
	}
}

// Deployment returns the same configuration as a deployment, for code that
// reads its configuration from the file named by QURL_DEPLOYMENT. Encode it
// with encoding/json and write it to a file. A deployment carries no HTTP
// client, so the code under test also has to be given Client, or the server
// has to be installed as http.DefaultTransport for the test.
//
// Never use it outside a test: the vector issuer key is public test material.
func (s *CRIDLinkServer) Deployment() *qurl.Deployment {
	cell := s.cell()
	return &qurl.Deployment{
		Issuers: []qurl.ManifestIssuer{{
			Kid: s.fixtures.issuerKID, SPKIDERB64: base64.RawURLEncoding.EncodeToString(s.fixtures.issuerDER),
		}},
		Cells: []qurl.DeploymentCell{{
			CellID: cell.CellID, Host: cell.Host, Port: cell.Port, ServerPublicKeyB64: cell.ServerPublicKeyB64,
		}},
		RelayAllowlist: []string{relayHost},
		CRIDLink:       &qurl.DeploymentCRIDLink{RelayURL: relayURL, LinkOrigin: s.fixtures.linkOrigin},
	}
}

// Client returns an HTTP client whose every request goes to the server and
// nowhere else. It is the client Config carries.
func (s *CRIDLinkServer) Client() *http.Client {
	return &http.Client{Transport: s}
}

// Refuse makes the server answer every request with the refusal code, whatever
// CRID the request names, until Issue is called. The codes a CRID link request
// defines, and the error the SDK returns for each:
//
//	52601  qurl.ErrCRIDLinkUnavailable
//	52602  qurl.ErrCRIDLinkNotFound
//	52603  qurl.ErrCRIDLinkRateLimited
//	52604  qurl.ErrCRIDResourceOffline
//	52605  qurl.ErrCRIDResourceClosed
//	52606  qurl.ErrInvalidCRIDLinkRequest
//
// Any other decimal code is answered as well. The SDK returns it as a
// *qurl.ServerDenyError that carries the code and matches none of the six.
//
// Refuse panics for a value that is not a refusal: one that is not a decimal
// code, a success code, or the code that issues a link.
func (s *CRIDLinkServer) Refuse(code string) {
	if !isRefusalCode(code) {
		panic(fmt.Sprintf("qurltest: %q is not a refusal code", code))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusal = code
}

// Issue returns the server to its default: a link for CRID, and "not found"
// for any other CRID.
func (s *CRIDLinkServer) Issue() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusal = ""
}

// Requests returns the CRID link requests the server has answered so far,
// oldest first. A request the server could not open is not one of them.
func (s *CRIDLinkServer) Requests() []CRIDLinkRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CRIDLinkRequest(nil), s.requests...)
}

// isRefusalCode reports whether code is a decimal outcome code that refuses:
// not a success code and not the code that issues a link.
func isRefusalCode(code string) bool {
	if code == "" || code[0] == '0' || code == conformance.CRIDLinkKnockV1CodeLinkIssued {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// RoundTrip answers one relay request. It makes CRIDLinkServer an
// http.RoundTripper, which is how Client reaches it. Tests do not call it.
//
// It behaves as the relay does. The sealed request is POSTed to the route of
// the server's key, and the answer is a sealed reply. Anything else is an HTTP
// error, which the SDK reports as a *qurl.RelayError.
func (s *CRIDLinkServer) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	route := "/relay/" + relayknock.PubKeyFingerprint(s.key.PublicKey().Bytes())
	if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host != relayHost || req.URL.Path != route || req.Body == nil {
		return httpResponse(req, http.StatusNotFound, []byte("qurltest: not the relay route of this server")), nil
	}
	packet, err := io.ReadAll(io.LimitReader(req.Body, maxPacketBytes))
	if err != nil {
		return nil, err
	}
	// The request is sent under a key minted for it, so the key is learned
	// from the packet. The reply is sealed to it.
	message, devicePub, err := relayknocktest.OpenUnknownInitiatorMessage(s.key.Bytes(), packet)
	if err != nil || message.Type != relayknock.TypeKnock {
		return httpResponse(req, http.StatusBadRequest, []byte("qurltest: not a knock sealed to this server")), nil
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	reply, err := relayknocktest.BuildReply(relayknock.TypeACK, &relayknock.KnockInputs{
		DeviceStaticPriv: s.key.Bytes(),
		ServerStaticPub:  devicePub,
		EphemeralPriv:    ephemeral.Bytes(),
		Counter:          message.Counter,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Body:             s.answer(message.Body),
		// A server compresses its replies, so the SDK inflates this one as it
		// will in service.
		Compress: true,
	})
	if err != nil {
		return nil, err
	}
	return httpResponse(req, http.StatusOK, reply), nil
}

// answer records one request and returns the reply body for it.
func (s *CRIDLinkServer) answer(body []byte) []byte {
	var knock struct {
		AspID   string                     `json:"aspId"`
		ResID   string                     `json:"resId"`
		UsrData map[string]json.RawMessage `json:"usrData"`
	}
	// A knock is a link request when it names the link service and resource
	// and carries the CRID as a string. Anything else is not one.
	if json.Unmarshal(body, &knock) != nil ||
		knock.AspID != s.fixtures.authServiceID || knock.ResID != s.fixtures.resourceID {
		return refusalBody(codeInvalidRequest)
	}
	requested, ok := jsonString(knock.UsrData[s.fixtures.cridKey])
	if !ok {
		return refusalBody(codeInvalidRequest)
	}
	// The user agent is optional. One that is absent is recorded as empty.
	userAgent, _ := jsonString(knock.UsrData[s.fixtures.userAgentKey])
	request := CRIDLinkRequest{CRID: requested, UserAgent: userAgent}

	s.mu.Lock()
	s.requests = append(s.requests, request)
	refusal := s.refusal
	s.mu.Unlock()

	switch {
	case refusal != "":
		return refusalBody(refusal)
	case request.CRID == s.fixtures.crid:
		return s.fixtures.issued
	default:
		return refusalBody(codeNotFound)
	}
}

// jsonString reads raw as a JSON string. null and an absent member are not
// strings.
func jsonString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	return value, true
}

// refusalBody is the reply body of a refusal: the code, and the members a
// reply that opened nothing carries.
func refusalBody(code string) []byte {
	body, err := json.Marshal(struct {
		ErrCode  string  `json:"errCode"`
		ErrMsg   string  `json:"errMsg"`
		ResHost  *string `json:"resHost"`
		OpnTime  int     `json:"opnTime"`
		ACTokens *string `json:"acTokens"`
	}{ErrCode: code, ErrMsg: "qurltest refusal"})
	if err != nil {
		// Unreachable: the value is strings and an integer.
		panic("qurltest: encode a refusal: " + err.Error())
	}
	return body
}

func httpResponse(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
