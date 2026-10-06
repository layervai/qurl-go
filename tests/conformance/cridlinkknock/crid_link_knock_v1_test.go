// Package cridlinkknock_test runs the public CRID link knock vectors
// (qurl-crid-link-knock-v1-vectors in github.com/layervai/qurl-conformance)
// through this SDK.
//
// It is a black-box test on purpose. Every case goes through the exported
// calls a customer uses — qurl.RequestCRIDLinkWith and qurl.OpenCRIDWith — and
// over the real wire path: the SDK builds and seals the knock, a test cell
// opens it and seals the vector's reply, and the SDK authenticates and
// interprets that reply. Nothing is asserted against an internal function, so
// the vectors pin what a caller observes, not how it is implemented.
//
// A missing or unparseable artifact is a hard failure, never a skip, and the
// test fails if any section runs fewer cases than the artifact declares.
package cridlinkknock_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/crid"
	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

// cell stands in for the relay and the cell behind it. It opens the request
// packet with the cell's private key, learning the initiator key from the
// packet because a link request is sent under a key minted for it, and seals
// whatever reply the running case asks for back to that key.
type cell struct {
	t      *testing.T
	server *httptest.Server
	key    *ecdh.PrivateKey

	mu       sync.Mutex
	requests []request
	build    func(request) ([]byte, error)
}

// request is one knock as the cell saw it after opening the packet.
type request struct {
	headerType int
	counter    uint64
	devicePub  []byte
	body       []byte
}

func newCell(t *testing.T) *cell {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &cell{t: t, key: key}
	c.server = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

func (c *cell) serve(w http.ResponseWriter, r *http.Request) {
	wantPath := "/relay/" + relayknock.PubKeyFingerprint(c.key.PublicKey().Bytes())
	if r.Method != http.MethodPost || r.URL.Path != wantPath {
		c.t.Errorf("relay request = %s %s, want POST %s", r.Method, r.URL.Path, wantPath)
		http.Error(w, "wrong route", http.StatusBadRequest)
		return
	}
	packet, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		c.t.Error(err)
		return
	}
	message, devicePub, err := relayknocktest.OpenUnknownInitiatorMessage(c.key.Bytes(), packet)
	if err != nil {
		c.t.Errorf("open the request packet: %v", err)
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}
	seen := request{headerType: message.Type, counter: message.Counter, devicePub: devicePub, body: message.Body}

	c.mu.Lock()
	c.requests = append(c.requests, seen)
	build := c.build
	c.mu.Unlock()
	if build == nil {
		c.t.Error("the cell received a request no case told it how to answer")
		http.Error(w, "no answer configured", http.StatusInternalServerError)
		return
	}
	reply, err := build(seen)
	if err != nil {
		c.t.Errorf("build reply: %v", err)
		http.Error(w, "reply not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(reply)
}

// replyInputs are the sealing inputs for a reply to seen: sealed by the cell,
// to the key the request was sent under, echoing the request's counter.
func (c *cell) replyInputs(seen request, body []byte) *relayknock.KnockInputs {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		c.t.Fatal(err)
	}
	return &relayknock.KnockInputs{
		DeviceStaticPriv: c.key.Bytes(),
		ServerStaticPub:  seen.devicePub,
		EphemeralPriv:    ephemeral.Bytes(),
		Counter:          seen.counter,
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Body:             body,
		Compress:         true, // a server compresses its replies
	}
}

// answer makes the cell reply with the given header type and body.
func (c *cell) answer(headerType int, body []byte) {
	c.answerWith(func(seen request) ([]byte, error) {
		return relayknocktest.BuildReply(headerType, c.replyInputs(seen, body))
	})
}

func (c *cell) answerWith(build func(request) ([]byte, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.build = build
}

func (c *cell) seen() []request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

// harness is one cell plus the opener configuration the vectors call for: the
// composed issuer key as the whole trust store, and the artifact's link origin
// as the deployment's.
type harness struct {
	t       *testing.T
	vectors *conformance.CRIDLinkKnockV1File
	cell    *cell
	cfg     qurl.Config
}

func newHarness(t *testing.T, vectors *conformance.CRIDLinkKnockV1File) *harness {
	t.Helper()
	// composes.issuer_trust_anchor: the issuer key that signs the fixture link.
	issuer, err := conformance.SignatureVectors()
	if err != nil {
		t.Fatalf("the composed issuer artifact must load: %v", err)
	}
	issuerDER, err := base64.RawURLEncoding.Strict().DecodeString(issuer.Issuer.SPKIDERB64)
	if err != nil {
		t.Fatalf("decode the composed issuer key: %v", err)
	}
	trust, err := qurl.NewTrustStoreFromDER(map[string][]byte{issuer.Issuer.KID: issuerDER})
	if err != nil {
		t.Fatalf("build the trust store: %v", err)
	}

	c := newCell(t)
	relay, err := url.Parse(c.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cells, err := qurl.NewCellCatalog([]qurl.CellEntry{{
		ServerPublicKeyB64: base64.StdEncoding.EncodeToString(c.key.PublicKey().Bytes()),
		CellID:             "vector-cell", Host: "cell.example.test", Port: 443,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		t: t, vectors: vectors, cell: c,
		cfg: qurl.Config{
			TrustStore:     trust,
			Cells:          cells,
			RelayAllowlist: qurl.NewRelayAllowlist([]string{relay.Host}),
			HTTPClient:     c.server.Client(),
			CRIDLink:       &qurl.CRIDLinkConfig{RelayURL: c.server.URL, LinkOrigin: vectors.Constants.LinkOrigin},
		},
	}
}

// request sends one link request the way a caller does. userAgent is nil when
// the case reports none.
func (h *harness) request(resourceCRID string, userAgent *string) (*qurl.CRIDLink, error) {
	cfg := h.cfg
	endpoint := *h.cfg.CRIDLink
	if userAgent != nil {
		endpoint.UserAgent = *userAgent
	}
	cfg.CRIDLink = &endpoint
	return qurl.RequestCRIDLinkWith(context.Background(), resourceCRID, cfg)
}

// requestAfterACK answers the next request with body as an ACK and sends one.
func (h *harness) requestAfterACK(resourceCRID string, body json.RawMessage) (*qurl.CRIDLink, error) {
	h.cell.answer(relayknock.TypeACK, body)
	return h.request(resourceCRID, nil)
}

// ackCase returns the named ACK case, which several sections build on.
func (h *harness) ackCase(name string) conformance.CRIDLinkKnockV1ACKCase {
	h.t.Helper()
	for _, c := range h.vectors.ACKCases {
		if c.Name == name {
			return c
		}
	}
	h.t.Fatalf("the artifact has no ACK case %q", name)
	return conformance.CRIDLinkKnockV1ACKCase{}
}

// clientResult names the artifact's client result for what a request returned,
// or "" when the outcome is not a client result at all: a link that failed a
// check, or a transport fault.
//
// The six refusals are tested before the generic deny because each of them is
// a *qurl.ServerDenyError too.
func clientResult(issued *qurl.CRIDLink, err error) string {
	var deny *qurl.ServerDenyError
	switch {
	case err == nil && issued != nil:
		return conformance.CRIDLinkKnockV1ResultLink
	case errors.Is(err, qurl.ErrCRIDLinkUnavailable):
		return conformance.CRIDLinkKnockV1ResultUnavailable
	case errors.Is(err, qurl.ErrCRIDLinkNotFound):
		return conformance.CRIDLinkKnockV1ResultNotFound
	case errors.Is(err, qurl.ErrCRIDLinkRateLimited):
		return conformance.CRIDLinkKnockV1ResultRateLimited
	case errors.Is(err, qurl.ErrCRIDResourceOffline):
		return conformance.CRIDLinkKnockV1ResultOffline
	case errors.Is(err, qurl.ErrCRIDResourceClosed):
		return conformance.CRIDLinkKnockV1ResultClosed
	case errors.Is(err, qurl.ErrInvalidCRIDLinkRequest):
		return conformance.CRIDLinkKnockV1ResultInvalid
	case errors.Is(err, qurl.ErrCRIDLinkProtocol):
		return conformance.CRIDLinkKnockV1ResultProtocolViolation
	case errors.Is(err, qurl.ErrServerOverloaded):
		return conformance.CRIDLinkKnockV1ResultBusy
	case errors.As(err, &deny):
		return conformance.CRIDLinkKnockV1ResultServerError
	default:
		return ""
	}
}

// assertInfo compares the display metadata a caller receives with the
// artifact's sanitized view. The view keeps the two timestamps as the text the
// server wrote; the SDK returns them parsed. An absent expiry is the zero
// time, and an absent creation time is nil.
func assertInfo(t *testing.T, got *qurl.CRIDLink, want conformance.CRIDLinkKnockV1LinkInfo) {
	t.Helper()
	if got.QURLID != want.QURLID {
		t.Errorf("QURLID = %q, want %q", got.QURLID, want.QURLID)
	}
	if got.Publisher.Name != want.Publisher.Name || got.Publisher.Verified != want.Publisher.Verified {
		t.Errorf("Publisher = %+v, want %+v", got.Publisher, want.Publisher)
	}
	var createdAt time.Time
	if got.ResourceCreatedAt != nil {
		createdAt = *got.ResourceCreatedAt
		if createdAt.IsZero() {
			t.Error("ResourceCreatedAt points at the zero time; an absent creation time is nil")
		}
	}
	for _, timestamp := range []struct {
		name string
		got  time.Time
		want string
	}{
		{"ExpiresAt", got.ExpiresAt, want.ExpiresAt},
		{"ResourceCreatedAt", createdAt, want.ResourceCreatedAt},
	} {
		if timestamp.want == "" {
			if !timestamp.got.IsZero() {
				t.Errorf("%s = %v, want absent", timestamp.name, timestamp.got)
			}
			continue
		}
		parsed, err := time.Parse(time.RFC3339, timestamp.want)
		if err != nil {
			t.Fatalf("the artifact keeps %s %q, which is not RFC 3339: this comparison needs a rule for it", timestamp.name, timestamp.want)
		}
		if !timestamp.got.Equal(parsed) || timestamp.got.IsZero() {
			t.Errorf("%s = %v, want %v", timestamp.name, timestamp.got, parsed)
		}
	}
}

// sdkRejectClasses is every class the SDK can report, in the SDK's own
// declaration order.
var sdkRejectClasses = []qurl.CRIDLinkRejectClass{
	qurl.CRIDLinkRejectMissingRedirect,
	qurl.CRIDLinkRejectOrigin,
	qurl.CRIDLinkRejectPathOrQuery,
	qurl.CRIDLinkRejectTransport,
	qurl.CRIDLinkRejectIssuerSignature,
	qurl.CRIDLinkRejectCRIDMismatch,
	qurl.CRIDLinkRejectInfoCRIDMismatch,
}

func TestCRIDLinkKnockV1Vectors(t *testing.T) {
	vectors, err := conformance.CRIDLinkKnockV1()
	if err != nil {
		t.Fatalf("the CRID link knock artifact must load: %v", err)
	}
	if vectors.Artifact != conformance.CRIDLinkKnockV1ArtifactID || vectors.SchemaVersion != conformance.CRIDLinkKnockV1SchemaVersion {
		t.Fatalf("artifact %q schema %d is not the one this test was written for", vectors.Artifact, vectors.SchemaVersion)
	}
	h := newHarness(t, vectors)

	// ran counts the case bodies each section actually executed. It is
	// compared with the artifact at the end, so a section that returned early,
	// or a loop that matched nothing, cannot pass as a green run.
	ran := map[string]int{}

	t.Run("vocabularies", func(t *testing.T) { runVocabularies(t, h) })
	t.Run("request_cases", func(t *testing.T) { ran["request_cases"] = runRequestCases(t, h) })
	t.Run("invalid_request_cases", func(t *testing.T) { ran["invalid_request_cases"] = runInvalidRequestCases(t, h) })
	t.Run("reply_type_rules", func(t *testing.T) { ran["reply_type_rules"] = runReplyTypeRules(t, h) })
	t.Run("error_codes", func(t *testing.T) { ran["error_codes"] = runErrorCodes(t, h) })
	t.Run("ack_cases", func(t *testing.T) { ran["ack_cases"] = runACKCases(t, h) })
	t.Run("client_verification_cases", func(t *testing.T) { ran["client_verification_cases"] = runVerificationCases(t, h) })
	t.Run("redirect_info_sanitization_cases", func(t *testing.T) {
		ran["redirect_info_sanitization_cases"] = runSanitizationCases(t, h)
	})

	declared := map[string]int{
		"request_cases":                    len(vectors.RequestCases),
		"invalid_request_cases":            len(vectors.InvalidRequestCases),
		"reply_type_rules":                 3, // ack, cookie, other
		"error_codes":                      len(vectors.ErrorCodes),
		"ack_cases":                        len(vectors.ACKCases),
		"client_verification_cases":        len(vectors.ClientVerificationCases),
		"redirect_info_sanitization_cases": len(vectors.RedirectInfoSanitizationCases),
	}
	total := 0
	for _, section := range slices.Sorted(maps.Keys(declared)) {
		if declared[section] == 0 {
			t.Errorf("%s: the artifact declares no cases", section)
		}
		// A -run pattern that selects sub-cases runs fewer on purpose; the
		// completeness check is for an unfiltered run, which is what CI does.
		if ran[section] != declared[section] && !subcasesSelected() {
			t.Errorf("%s: ran %d of %d cases", section, ran[section], declared[section])
		}
		t.Logf("%-34s %d of %d", section, ran[section], declared[section])
		total += ran[section]
	}
	t.Logf("%-34s %d", "total", total)
}

// subcasesSelected reports whether this run was started with a -run pattern
// that descends into subtests, so that only some cases execute.
func subcasesSelected() bool {
	selected := flag.Lookup("test.run")
	return selected != nil && strings.Contains(selected.Value.String(), "/")
}

// runVocabularies pins the closed sets: the header types the SDK's wire layer
// uses, and that the SDK's results and reject classes are exactly the
// artifact's, so neither side can grow one the other does not know.
func runVocabularies(t *testing.T, h *harness) {
	constants := h.vectors.Constants
	if constants.KnockHeaderType != relayknock.TypeKnock || constants.ACKHeaderType != relayknock.TypeACK ||
		constants.CookieHeaderType != relayknock.TypeCookieChallenge {
		t.Fatalf("header types knock=%d ack=%d cookie=%d do not match the SDK's %d/%d/%d",
			constants.KnockHeaderType, constants.ACKHeaderType, constants.CookieHeaderType,
			relayknock.TypeKnock, relayknock.TypeACK, relayknock.TypeCookieChallenge)
	}

	var classes []string
	for _, class := range sdkRejectClasses {
		classes = append(classes, string(class))
	}
	if !slices.Equal(classes, h.vectors.RejectClasses) {
		t.Fatalf("SDK reject classes %v, artifact reject_classes %v", classes, h.vectors.RejectClasses)
	}

	// Every result the artifact names is one clientResult can return, and
	// clientResult returns nothing else.
	producible := []string{
		conformance.CRIDLinkKnockV1ResultLink, conformance.CRIDLinkKnockV1ResultUnavailable,
		conformance.CRIDLinkKnockV1ResultNotFound, conformance.CRIDLinkKnockV1ResultRateLimited,
		conformance.CRIDLinkKnockV1ResultOffline, conformance.CRIDLinkKnockV1ResultClosed,
		conformance.CRIDLinkKnockV1ResultInvalid, conformance.CRIDLinkKnockV1ResultProtocolViolation,
		conformance.CRIDLinkKnockV1ResultServerError, conformance.CRIDLinkKnockV1ResultBusy,
	}
	if !slices.Equal(slices.Sorted(slices.Values(producible)), slices.Sorted(slices.Values(h.vectors.ClientResults))) {
		t.Fatalf("results this test can observe %v, artifact client_results %v", producible, h.vectors.ClientResults)
	}
}

// runRequestCases builds each request with the real request builder and
// compares the body that reached the cell with the canonical bytes. The body is
// never taken from the case: only the CRID and the user agent of its input go
// in, through the exported call, so a case that pins what the builder does with
// a user agent — sends it, cuts it, or leaves it out — runs the SDK's own rule.
func runRequestCases(t *testing.T, h *harness) int {
	issued := h.ackCase("link_issued")
	constants := h.vectors.Constants
	ran := 0
	for _, c := range h.vectors.RequestCases {
		t.Run(c.Name, func(t *testing.T) {
			ran++
			// The answer is a link for the CRID these cases ask for, so the
			// whole request succeeds and the body is what a real one carries.
			h.cell.answer(relayknock.TypeACK, issued.Body)
			before := len(h.cell.seen())
			if _, err := h.request(c.Input.CRID, c.Input.UserAgent); err != nil {
				t.Fatalf("request: %v", err)
			}
			requests := h.cell.seen()
			if len(requests) != before+1 {
				t.Fatalf("the cell saw %d requests for one call", len(requests)-before)
			}
			sent := requests[len(requests)-1]

			if string(sent.body) != c.Serialized {
				t.Fatalf("request body\n got %s\nwant %s", sent.body, c.Serialized)
			}
			if sent.headerType != constants.KnockHeaderType {
				t.Fatalf("packet header type = %d, want %d", sent.headerType, constants.KnockHeaderType)
			}

			// The grammar the constants describe, read back from the wire.
			var body struct {
				HeaderType int                        `json:"headerType"`
				AspID      string                     `json:"aspId"`
				ResID      string                     `json:"resId"`
				UsrData    map[string]json.RawMessage `json:"usrData"`
			}
			if err := json.Unmarshal(sent.body, &body); err != nil {
				t.Fatalf("the request body is not JSON: %v", err)
			}
			if body.HeaderType != constants.KnockHeaderType || body.AspID != constants.AuthServiceID || body.ResID != constants.ResourceID {
				t.Fatalf("request names headerType=%d aspId=%q resId=%q", body.HeaderType, body.AspID, body.ResID)
			}
			for key := range body.UsrData {
				if key != constants.UserDataKeys.CRID && key != constants.UserDataKeys.UserAgent {
					t.Fatalf("request carries user-data member %q, which a v1 client never sends", key)
				}
				if slices.Contains(constants.ForbiddenUserDataKeys, key) {
					t.Fatalf("request carries the forbidden user-data member %q", key)
				}
			}
			// What was sent for the user agent is within the limit and is the
			// input, a prefix of it, or nothing at all: a user agent that holds
			// a control character, U+2028 or U+2029 is left out.
			var sentUserAgent string
			if raw, present := body.UsrData[constants.UserDataKeys.UserAgent]; present {
				if err := json.Unmarshal(raw, &sentUserAgent); err != nil {
					t.Fatal(err)
				}
			}
			if len(sentUserAgent) > constants.UserAgentMaxBytes {
				t.Fatalf("sent a %d-byte user agent, over the %d-byte limit", len(sentUserAgent), constants.UserAgentMaxBytes)
			}
			if c.Input.UserAgent == nil {
				if sentUserAgent != "" {
					t.Fatal("sent a user agent the caller did not report")
				}
			} else if !strings.HasPrefix(*c.Input.UserAgent, sentUserAgent) {
				t.Fatal("the sent user agent is not a prefix of the reported one")
			}
		})
	}
	return ran
}

// refusingClient fails the test if a request is made: it is how "before any
// network I/O" is asserted.
type refusingClient struct {
	t     *testing.T
	calls int
}

func (c *refusingClient) Do(req *http.Request) (*http.Response, error) {
	c.calls++
	c.t.Errorf("a request was sent to %s for a CRID the client must refuse", req.URL.Host)
	return nil, errors.New("no request may be sent")
}

// cridRejectClass names the CRID v1 class of a locally refused CRID. A
// well-formed CRID whose version the SDK cannot verify a link against is
// refused under the version class, with the forbidden version byte.
func cridRejectClass(err error) string {
	switch {
	case errors.Is(err, crid.ErrCharset):
		return conformance.CRIDV1RejectCharset
	case errors.Is(err, crid.ErrLength):
		return conformance.CRIDV1RejectLength
	case errors.Is(err, crid.ErrChecksum):
		return conformance.CRIDV1RejectChecksum
	case errors.Is(err, crid.ErrNonCanonical):
		return conformance.CRIDV1RejectNonCanonical
	case errors.Is(err, crid.ErrForbiddenVersion), errors.Is(err, qurl.ErrUnsupportedCRIDVersion):
		return conformance.CRIDV1RejectVersion
	default:
		return ""
	}
}

// runInvalidRequestCases confirms the request builder refuses each input
// before any network I/O, under the declared CRID v1 class.
func runInvalidRequestCases(t *testing.T, h *harness) int {
	ran := 0
	for _, c := range h.vectors.InvalidRequestCases {
		t.Run(c.Name, func(t *testing.T) {
			ran++
			if c.Outcome != conformance.ExpectReject {
				t.Fatalf("invalid request case declares outcome %q", c.Outcome)
			}
			client := &refusingClient{t: t}
			cfg := h.cfg
			cfg.HTTPClient = client
			before := len(h.cell.seen())

			issued, requestErr := qurl.RequestCRIDLinkWith(context.Background(), c.Input.CRID, cfg)
			handle, openErr := qurl.OpenCRIDWith(context.Background(), c.Input.CRID, cfg)
			if issued != nil || handle != nil {
				t.Fatal("a refused CRID returned a result")
			}
			for call, err := range map[string]error{"RequestCRIDLinkWith": requestErr, "OpenCRIDWith": openErr} {
				if got := cridRejectClass(err); got != c.CRIDRejectClass {
					t.Fatalf("%s refused under class %q (%v), want %q", call, got, err, c.CRIDRejectClass)
				}
				// A local refusal is not something the server said.
				if result := clientResult(nil, err); result != "" {
					t.Fatalf("%s reported the client result %q for a request that was never sent", call, result)
				}
			}
			if client.calls != 0 || len(h.cell.seen()) != before {
				t.Fatal("a refused CRID caused network I/O")
			}
		})
	}
	return ran
}

// runReplyTypeRules applies the three reply-type rules in the real reply
// path. The reply's header type is read before any body: the same body is a
// link under the ACK type, busy under the cookie type, and a transport error
// under every other type.
func runReplyTypeRules(t *testing.T, h *harness) int {
	rules := h.vectors.ReplyTypeRules
	issued := h.ackCase("link_issued")
	refused := h.ackCase("denied_not_found")
	ran := 0

	t.Run("ack", func(t *testing.T) {
		ran++
		if rules.ACK.HeaderType != relayknock.TypeACK || !rules.ACK.IsACK || !rules.ACK.CarriesOutcomeCode ||
			rules.ACK.Handling != conformance.CRIDLinkKnockV1HandlingInterpretACKBody {
			t.Fatalf("ack rule = %+v", rules.ACK)
		}
		h.cell.answer(rules.ACK.HeaderType, issued.Body)
		link, err := h.request(issued.RequestedCRID, nil)
		if got := clientResult(link, err); got != issued.Expected.ClientResult {
			t.Fatalf("an ACK was not interpreted by its body: result %q (%v)", got, err)
		}
		h.cell.answer(rules.ACK.HeaderType, refused.Body)
		link, err = h.request(refused.RequestedCRID, nil)
		if got := clientResult(link, err); got != refused.Expected.ClientResult {
			t.Fatalf("an ACK was not interpreted by its body: result %q (%v)", got, err)
		}
	})

	t.Run("cookie", func(t *testing.T) {
		ran++
		if rules.Cookie.HeaderType != relayknock.TypeCookieChallenge || rules.Cookie.IsACK || rules.Cookie.CarriesOutcomeCode ||
			rules.Cookie.Handling != conformance.CRIDLinkKnockV1HandlingClientResult {
			t.Fatalf("cookie rule = %+v", rules.Cookie)
		}
		// Whatever the body holds: nothing, a link-issued answer, a refusal.
		for name, body := range map[string][]byte{"empty": nil, "link issued": issued.Body, "refusal": refused.Body} {
			h.cell.answer(rules.Cookie.HeaderType, body)
			link, err := h.request(issued.RequestedCRID, nil)
			if got := clientResult(link, err); got != rules.Cookie.ClientResult {
				t.Fatalf("cookie reply with %s body: result %q (%v), want %q", name, got, err, rules.Cookie.ClientResult)
			}
		}
	})

	t.Run("other", func(t *testing.T) {
		ran++
		if rules.Other.HeaderType != 0 || rules.Other.IsACK || rules.Other.CarriesOutcomeCode ||
			rules.Other.Handling != conformance.CRIDLinkKnockV1HandlingTransportError || rules.Other.ClientResult != "" {
			t.Fatalf("other rule = %+v", rules.Other)
		}
		// Every other header type the wire can carry, each sealed by the real
		// cell key so the only thing wrong with the reply is its type. The
		// body is a complete link-issued answer, which must not be read.
		built := 0
		for headerType := 0; headerType <= 20; headerType++ {
			if headerType == rules.ACK.HeaderType || headerType == rules.Cookie.HeaderType {
				continue
			}
			h.cell.answerWith(func(seen request) ([]byte, error) {
				return buildReplyOfAnyType(h.cell, headerType, seen, issued.Body)
			})
			link, err := h.request(issued.RequestedCRID, nil)
			if link != nil || err == nil {
				t.Fatalf("header type %d: a reply that is not an answer returned %v, %v", headerType, link, err)
			}
			if got := clientResult(link, err); got != "" {
				t.Fatalf("header type %d: a transport error was reported as the client result %q", headerType, got)
			}
			var rejected *qurl.CRIDLinkRejectedError
			if errors.As(err, &rejected) {
				t.Fatalf("header type %d: the body of a foreign reply was read: %v", headerType, err)
			}
			// A reply the client authenticates and then refuses by its type is
			// a malformed reply. The re-knock type never gets that far: its
			// header digest covers a cookie the client does not hold, so it
			// fails to authenticate, which is a transport error all the same.
			if headerType != relayknock.TypeReknock && !errors.Is(err, qurl.ErrMalformedReply) {
				t.Fatalf("header type %d: error = %v, want qurl.ErrMalformedReply", headerType, err)
			}
			built++
		}
		if built != 19 {
			t.Fatalf("drove %d other header types, want 19", built)
		}
	})
	return ran
}

// buildReplyOfAnyType seals body under an arbitrary header type. No single
// helper builds them all: the responder helper builds the reply types, the
// initiator builder builds the request types (the transcript is the same in
// both directions), and the unknown-type helper builds the rest.
func buildReplyOfAnyType(c *cell, headerType int, seen request, body []byte) ([]byte, error) {
	inputs := c.replyInputs(seen, body)
	switch headerType {
	case relayknock.TypeACK, relayknock.TypeListResult, relayknock.TypeCookieChallenge, relayknock.TypeRegisterAck:
		return relayknocktest.BuildReply(headerType, inputs)
	case relayknock.TypeReknock:
		inputs.Cookie = bytes.Repeat([]byte{0x5a}, 32)
		return relayknock.BuildMessage(headerType, inputs)
	case relayknock.TypeKnock, relayknock.TypeListRequest, relayknock.TypeOTP, relayknock.TypeRegister, relayknock.TypeExit:
		return relayknock.BuildMessage(headerType, inputs)
	default:
		return relayknocktest.BuildUnknownReplyForTest(headerType, inputs)
	}
}

// runErrorCodes drives the outcome table itself, one bare ACK per code, so the
// table is pinned row by row and not only through the cases that happen to
// use it.
func runErrorCodes(t *testing.T, h *harness) int {
	issued := h.ackCase("link_issued")
	ran := 0
	for _, code := range slices.Sorted(maps.Keys(h.vectors.ErrorCodes)) {
		row := h.vectors.ErrorCodes[code]
		t.Run(code+"_"+row.Name, func(t *testing.T) {
			ran++
			// The link-issued row needs a link to issue; every other row is
			// the code and nothing else.
			body := json.RawMessage(fmt.Sprintf(`{"errCode":%q,"opnTime":0}`, code))
			if code == conformance.CRIDLinkKnockV1CodeLinkIssued {
				body = issued.Body
			}
			link, err := h.requestAfterACK(issued.RequestedCRID, body)
			if got := clientResult(link, err); got != row.ClientResult {
				t.Fatalf("code %s: result %q (%v), want %q", code, got, err, row.ClientResult)
			}
			if code == conformance.CRIDLinkKnockV1CodeLinkIssued {
				return
			}
			// A refusal carries its code for callers that handle a deny generically.
			var deny *qurl.ServerDenyError
			if !errors.As(err, &deny) || deny.ErrCode != code {
				t.Fatalf("code %s is not a *qurl.ServerDenyError carrying its code: %v", code, err)
			}
		})
	}
	return ran
}

// runACKCases feeds each ACK body through the real reply path and compares
// the result with the declared one: the client result, and for a link the
// exact link and the sanitized metadata.
func runACKCases(t *testing.T, h *harness) int {
	ran := 0
	for _, c := range h.vectors.ACKCases {
		t.Run(c.Name, func(t *testing.T) {
			ran++
			link, err := h.requestAfterACK(c.RequestedCRID, c.Body)
			if got := clientResult(link, err); got != c.Expected.ClientResult {
				t.Fatalf("result %q (%v), want %q", got, err, c.Expected.ClientResult)
			}
			if c.Expected.ClientResult != conformance.CRIDLinkKnockV1ResultLink {
				// Only the link result carries a link, and nothing else may.
				if link != nil {
					t.Fatal("a result that is not a link returned one")
				}
				if c.Expected.Link != "" || c.Expected.Info != nil {
					t.Fatalf("the artifact declares a link for the %q result", c.Expected.ClientResult)
				}
				assertNothingSurfaced(t, h, err)
				return
			}
			if link.Link != c.Expected.Link {
				t.Fatal("the returned link is not the declared one")
			}
			if c.Expected.Info == nil {
				t.Fatal("the artifact declares a link without its metadata view")
			}
			assertInfo(t, link, *c.Expected.Info)
		})
	}
	return ran
}

// runVerificationCases feeds each link-issued ACK through the real reply path
// and asserts whether its link may be used for the requested CRID, and on a
// reject which check failed and that nothing from the reply came back.
func runVerificationCases(t *testing.T, h *harness) int {
	ran := 0
	for _, c := range h.vectors.ClientVerificationCases {
		t.Run(c.Name, func(t *testing.T) {
			ran++
			link, err := h.requestAfterACK(c.RequestedCRID, c.Body)
			switch c.Outcome {
			case conformance.ExpectAccept:
				if got := clientResult(link, err); got != conformance.CRIDLinkKnockV1ResultLink {
					t.Fatalf("an acceptable link was not returned: result %q (%v)", got, err)
				}
				// The link handed back is the one the reply carried, byte for
				// byte: an accepted form is not rewritten into another one.
				var ack struct {
					RedirectURL string `json:"redirectUrl"`
				}
				if err := json.Unmarshal(c.Body, &ack); err != nil || ack.RedirectURL == "" {
					t.Fatalf("the accept case carries no link to compare with: %v", err)
				}
				if link.Link != ack.RedirectURL {
					t.Fatal("the returned link is not the link the reply carried")
				}
			case conformance.ExpectReject:
				if link != nil {
					t.Fatal("a link that failed a check was returned")
				}
				var rejected *qurl.CRIDLinkRejectedError
				if !errors.As(err, &rejected) || !errors.Is(err, qurl.ErrCRIDLinkRejected) {
					t.Fatalf("error = %v, want a *qurl.CRIDLinkRejectedError", err)
				}
				if string(rejected.Class) != c.RejectClass {
					t.Fatalf("reject class %q, want %q", rejected.Class, c.RejectClass)
				}
				// A rejected link is a hard error, not one of the results.
				if got := clientResult(link, err); got != "" {
					t.Fatalf("a rejected link was reported as the client result %q", got)
				}
				assertNothingSurfaced(t, h, err)
			default:
				t.Fatalf("unknown outcome %q", c.Outcome)
			}
		})
	}
	return ran
}

// assertNothingSurfaced checks that an error says nothing taken from the
// reply: not the fixture link, not its fragment, not the publisher.
func assertNothingSurfaced(t *testing.T, h *harness, err error) {
	t.Helper()
	if err == nil {
		return
	}
	_, fragment, _ := strings.Cut(h.vectors.Fixtures.Link, "#")
	text := fmt.Sprintf("%v | %+v | %#v", err, err, err)
	for name, secret := range map[string]string{
		"link": h.vectors.Fixtures.Link, "link fragment": fragment,
		"transport prefix": "qv2t1.", "publisher name": "Example Publisher",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("the error surfaces the %s from the reply: %s", name, text)
		}
	}
}

// runSanitizationCases puts each raw redirectInfo value in place of the
// metadata of the link-issued ACK and runs it through the whole reply path.
// The result is still a link, with the declared view of the metadata.
func runSanitizationCases(t *testing.T, h *harness) int {
	issued := h.ackCase("link_issued")
	var template map[string]json.RawMessage
	if err := json.Unmarshal(issued.Body, &template); err != nil {
		t.Fatalf("decode the link-issued ACK: %v", err)
	}
	if _, present := template["redirectInfo"]; !present {
		t.Fatal("the link-issued ACK has no redirectInfo to replace")
	}

	ran := 0
	for _, c := range h.vectors.RedirectInfoSanitizationCases {
		t.Run(c.Name, func(t *testing.T) {
			ran++
			ack := make(map[string]json.RawMessage, len(template))
			for name, value := range template {
				ack[name] = value
			}
			ack["redirectInfo"] = c.RedirectInfo
			body, err := json.Marshal(ack)
			if err != nil {
				t.Fatal(err)
			}
			link, err := h.requestAfterACK(issued.RequestedCRID, body)
			if err != nil {
				t.Fatalf("malformed metadata failed the request: %v", err)
			}
			if link.Link != issued.Expected.Link {
				t.Fatal("the returned link is not the issued one")
			}
			assertInfo(t, link, c.Expected)
		})
	}
	return ran
}
