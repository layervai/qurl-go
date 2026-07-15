package qurl

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- HTTP test double ---

type scriptedResponse struct {
	status int
	header http.Header
	body   string
	err    error // when set, Do returns this transport error
}

type scriptedDoer struct {
	responses []scriptedResponse
	calls     int
	authSeen  []string
	bodies    []string
}

func (d *scriptedDoer) Do(req *http.Request) (*http.Response, error) {
	idx := d.calls
	d.calls++
	d.authSeen = append(d.authSeen, req.Header.Get("Authorization"))
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		d.bodies = append(d.bodies, string(raw))
	}
	if idx >= len(d.responses) {
		idx = len(d.responses) - 1 // repeat the last scripted response
	}
	r := d.responses[idx]
	if r.err != nil {
		return nil, r.err
	}
	h := r.header
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(r.body)),
	}, nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// --- fixtures ---

func freshServerKeyB64(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func validAssignment(t *testing.T, agentID string) AgentAssignment {
	t.Helper()
	return AgentAssignment{
		AgentID:              agentID,
		CellID:               "cell0",
		AssignmentGeneration: 1,
		EndpointRevision:     1,
		LeaseExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		Endpoint: NHPUDPEndpoint{
			Host:               "cell0.nhp.layerv.ai",
			Port:               62206,
			ServerPublicKeyB64: freshServerKeyB64(t),
		},
	}
}

func assignmentEnvelope(t *testing.T, a AgentAssignment) string {
	t.Helper()
	raw, err := json.Marshal(apiEnvelope[AgentAssignment]{Data: a})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(raw)
}

// deterministicFetchOpts wires a scripted HTTP client plus deterministic
// clock/sleep/jitter so a bounded retry loop is driven without real time. It
// returns the recorded sleep durations via slept.
func deterministicFetchOpts(doer *scriptedDoer, clk *fakeClock, slept *[]time.Duration, extra ...AssignmentOption) []AssignmentOption {
	opts := []AssignmentOption{
		WithAssignmentHTTPClient(doer),
		WithAssignmentBaseURL("https://api.layerv.test"),
		withAssignmentClock(clk.Now),
		withAssignmentJitter(func() float64 { return 0 }),
		withAssignmentSleep(func(_ context.Context, d time.Duration) error {
			*slept = append(*slept, d)
			clk.now = clk.now.Add(d)
			return nil
		}),
	}
	return append(opts, extra...)
}

// --- success + response validation ---

func TestFetchAgentAssignment_Success(t *testing.T) {
	want := validAssignment(t, "connector-7f3c2a")
	doer := &scriptedDoer{responses: []scriptedResponse{{status: 200, body: assignmentEnvelope(t, want)}}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	got, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_enroll_key"),
		deterministicFetchOpts(doer, clk, &slept)...)
	if err != nil {
		t.Fatalf("FetchAgentAssignment: %v", err)
	}
	if got.CellID != "cell0" || got.AssignmentGeneration != 1 || got.EndpointRevision != 1 {
		t.Fatalf("assignment fields = %#v", got)
	}
	if got.Endpoint.Host != "cell0.nhp.layerv.ai" || got.Endpoint.Port != 62206 {
		t.Fatalf("endpoint = %#v", got.Endpoint)
	}
	if key, err := got.DecodedServerKey(); err != nil || len(key) != 32 {
		t.Fatalf("DecodedServerKey: key=%d err=%v", len(key), err)
	}
	if doer.calls != 1 {
		t.Fatalf("calls = %d, want 1", doer.calls)
	}
	if doer.authSeen[0] != "Bearer lv_enroll_key" {
		t.Fatalf("Authorization = %q, want the supplied bearer credential", doer.authSeen[0])
	}
	// The request must carry only the agent id — no cell/endpoint/placement hint.
	if !strings.Contains(doer.bodies[0], `"agent_id":"connector-7f3c2a"`) || strings.Contains(doer.bodies[0], "cell") {
		t.Fatalf("request body = %q", doer.bodies[0])
	}
}

func TestFetchAgentAssignment_AcceptsLayerVXYZEndpoint(t *testing.T) {
	want := validAssignment(t, "connector-7f3c2a")
	want.Endpoint.Host = "cell0.nhp.layerv.xyz"
	doer := &scriptedDoer{responses: []scriptedResponse{{status: http.StatusOK, body: assignmentEnvelope(t, want)}}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration
	got, err := FetchAgentAssignment(context.Background(), want.AgentID, BearerToken("lv_enroll_key"),
		deterministicFetchOpts(doer, clk, &slept)...)
	if err != nil {
		t.Fatalf("FetchAgentAssignment: %v", err)
	}
	if got.Endpoint.Host != want.Endpoint.Host {
		t.Fatalf("endpoint host = %q, want %q", got.Endpoint.Host, want.Endpoint.Host)
	}
}

func TestFetchAgentAssignment_RejectsInvalidResponses(t *testing.T) {
	const agentID = "connector-7f3c2a"
	cases := []struct {
		name   string
		mutate func(a *AgentAssignment)
	}{
		{"wrong agent id", func(a *AgentAssignment) { a.AgentID = "someone-else" }},
		{"missing cell id", func(a *AgentAssignment) { a.CellID = "" }},
		{"uppercase cell id", func(a *AgentAssignment) { a.CellID = "Cell0" }},
		{"trailing hyphen cell id", func(a *AgentAssignment) { a.CellID = "cell0-" }},
		{"oversize cell id", func(a *AgentAssignment) { a.CellID = "c" + strings.Repeat("0", 64) }},
		{"zero generation", func(a *AgentAssignment) { a.AssignmentGeneration = 0 }},
		{"zero endpoint revision", func(a *AgentAssignment) { a.EndpointRevision = 0 }},
		{"zero lease", func(a *AgentAssignment) { a.LeaseExpiresAt = time.Time{} }},
		{"expired lease", func(a *AgentAssignment) { a.LeaseExpiresAt = time.Now().Add(-time.Minute) }},
		{"aws elb host", func(a *AgentAssignment) { a.Endpoint.Host = "internal-cell0-123.us-east-1.elb.amazonaws.com" }},
		{"internal host", func(a *AgentAssignment) { a.Endpoint.Host = "cell0.compute.internal" }},
		{"ip literal host", func(a *AgentAssignment) { a.Endpoint.Host = "10.0.0.5" }},
		{"localhost host", func(a *AgentAssignment) { a.Endpoint.Host = "localhost" }},
		{"non LayerV host", func(a *AgentAssignment) { a.Endpoint.Host = "cell0.nhp.example.com" }},
		{"uppercase host", func(a *AgentAssignment) { a.Endpoint.Host = "Cell0.nhp.layerv.ai" }},
		{"empty DNS label", func(a *AgentAssignment) { a.Endpoint.Host = "cell0..layerv.ai" }},
		{"trailing DNS dot", func(a *AgentAssignment) { a.Endpoint.Host = "cell0.nhp.layerv.ai." }},
		{"bad DNS label", func(a *AgentAssignment) { a.Endpoint.Host = "-cell0.nhp.layerv.ai" }},
		{"port out of range", func(a *AgentAssignment) { a.Endpoint.Port = 70000 }},
		{"bad server key", func(a *AgentAssignment) { a.Endpoint.ServerPublicKeyB64 = "not-base64!!" }},
		{"short server key", func(a *AgentAssignment) {
			a.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}},
		{"unpadded server key", func(a *AgentAssignment) {
			key, err := base64.StdEncoding.DecodeString(a.Endpoint.ServerPublicKeyB64)
			if err != nil {
				t.Fatal(err)
			}
			a.Endpoint.ServerPublicKeyB64 = base64.RawStdEncoding.EncodeToString(key)
		}},
		{"low-order server key", func(a *AgentAssignment) {
			a.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}},
		{"non-canonical server key", func(a *AgentAssignment) {
			key := make([]byte, 32)
			key[0] = 0xed
			for i := 1; i < 31; i++ {
				key[i] = 0xff
			}
			key[31] = 0x7f
			a.Endpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(key)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAssignment(t, agentID)
			tc.mutate(&a)
			doer := &scriptedDoer{responses: []scriptedResponse{{status: 200, body: assignmentEnvelope(t, a)}}}
			clk := &fakeClock{now: time.Now()}
			var slept []time.Duration
			_, err := FetchAgentAssignment(context.Background(), agentID, BearerToken("lv_key"),
				deterministicFetchOpts(doer, clk, &slept)...)
			if !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

func TestFetchAgentAssignment_EmptyAndMalformedBody(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"not json", "<html>502</html>"},
		{"missing data", `{"meta":{}}`},
		{"invalid UTF-8", string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doer := &scriptedDoer{responses: []scriptedResponse{{status: 200, body: tc.body}}}
			clk := &fakeClock{now: time.Now()}
			var slept []time.Duration
			_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
				deterministicFetchOpts(doer, clk, &slept)...)
			if !errors.Is(err, ErrAssignmentInvalidResponse) {
				t.Fatalf("error = %v, want ErrAssignmentInvalidResponse", err)
			}
		})
	}
}

// --- terminal status classification ---

func problemBody(code string) string {
	return `{"error":{"type":"https://api.qurl.link/problems/` + code + `","title":"x","status":0,"code":"` + code + `"}}`
}

func TestFetchAgentAssignment_TerminalStatuses(t *testing.T) {
	cases := []struct {
		name   string
		resp   scriptedResponse
		wantIs error
	}{
		{"400 rejected", scriptedResponse{status: 400, body: problemBody("assignment_request_invalid")}, ErrAssignmentRequestRejected},
		{"401 forbidden", scriptedResponse{status: 401, body: problemBody("unauthorized")}, ErrAssignmentForbidden},
		{"403 forbidden", scriptedResponse{status: 403, body: problemBody("account_frozen")}, ErrAssignmentForbidden},
		{"409 reassignment", scriptedResponse{status: 409, body: problemBody("cell_reassignment_in_progress")}, ErrAssignmentReassignmentRequired},
		{"409 quota", scriptedResponse{status: 409, body: problemBody("agent_assignment_quota_exceeded")}, ErrAssignmentQuotaExceeded},
		{"409 unknown is not quota", scriptedResponse{status: 409, body: problemBody("conflict")}, ErrAssignmentServiceError},
		{"409 mixed-case alias rejected", scriptedResponse{status: 409, body: problemBody("CELL_REASSIGNMENT_IN_PROGRESS")}, ErrAssignmentServiceError},
		{"429 rate limited", scriptedResponse{status: 429, body: problemBody("rate_limited")}, ErrAssignmentRateLimited},
		{"500 service error", scriptedResponse{status: 500, body: problemBody("internal_error")}, ErrAssignmentServiceError},
		{"503 non-authority code terminal", scriptedResponse{status: 503, body: problemBody("service_unavailable")}, ErrAssignmentServiceError},
		{"503 mixed-case alias terminal", scriptedResponse{status: 503, body: problemBody("CELL_ASSIGNMENT_UNAVAILABLE")}, ErrAssignmentServiceError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := &scriptedDoer{responses: []scriptedResponse{tc.resp}}
			clk := &fakeClock{now: time.Now()}
			var slept []time.Duration
			_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
				deterministicFetchOpts(doer, clk, &slept)...)
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("error = %v, want errors.Is %v", err, tc.wantIs)
			}
			// A terminal status is not retried.
			if doer.calls != 1 {
				t.Fatalf("calls = %d, want 1 (terminal, no retry)", doer.calls)
			}
			if len(slept) != 0 {
				t.Fatalf("slept %v, want no backoff on a terminal status", slept)
			}
		})
	}
}

func TestFetchAgentAssignment_RateLimitedCarriesResetTiming(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "30")
	header.Set("RateLimit-Reset", "45")
	doer := &scriptedDoer{responses: []scriptedResponse{{status: 429, header: header, body: problemBody("rate_limited")}}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept)...)
	var rl *AssignmentRateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("error = %v, want *AssignmentRateLimitedError", err)
	}
	if rl.RetryAfter != 30*time.Second || rl.Reset != 45*time.Second {
		t.Fatalf("rate-limit timing = retry-after %s reset %s", rl.RetryAfter, rl.Reset)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTooManyRequests || apiErr.Code != "rate_limited" {
		t.Fatalf("rate-limit error lost API problem details: %v", err)
	}
}

func TestAssignmentRateLimitedError_NilAPIErrorStillUnwrapsSentinel(t *testing.T) {
	err := &AssignmentRateLimitedError{}
	if !errors.Is(err, ErrAssignmentRateLimited) {
		t.Fatalf("error = %v, want ErrAssignmentRateLimited", err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("error unexpectedly unwraps a nil *APIError: %#v", apiErr)
	}
}

func TestAssignmentRecoveryRequiredError_NilAPIErrorStillUnwrapsSentinels(t *testing.T) {
	err := &AssignmentRecoveryRequiredError{}
	if !errors.Is(err, ErrAssignmentRecoveryRequired) || !errors.Is(err, ErrAssignmentUnavailable) {
		t.Fatalf("error = %v, want both recovery-required and unavailable sentinels", err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("error unexpectedly unwraps a nil *APIError: %#v", apiErr)
	}
}

func TestFetchAgentAssignment_TransportErrorIsTerminal(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{{err: errors.New("connection reset")}}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration
	_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept)...)
	if !errors.Is(err, ErrAssignmentServiceError) {
		t.Fatalf("error = %v, want ErrAssignmentServiceError", err)
	}
	if doer.calls != 1 {
		t.Fatalf("calls = %d, want 1 (transport failure is terminal here)", doer.calls)
	}
}

// --- bounded 503 retry ---

func unavailable(retryAfter string) scriptedResponse {
	h := http.Header{}
	if retryAfter != "" {
		h.Set("Retry-After", retryAfter)
	}
	return scriptedResponse{status: 503, header: h, body: problemBody("cell_assignment_unavailable")}
}

func TestFetchAgentAssignment_Retries503ThenSucceeds(t *testing.T) {
	want := validAssignment(t, "connector-7f3c2a")
	doer := &scriptedDoer{responses: []scriptedResponse{
		unavailable("1"),
		unavailable("1"),
		{status: 200, body: assignmentEnvelope(t, want)},
	}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	got, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_device_key"),
		deterministicFetchOpts(doer, clk, &slept)...)
	if err != nil {
		t.Fatalf("FetchAgentAssignment: %v", err)
	}
	if got.CellID != "cell0" {
		t.Fatalf("assignment = %#v", got)
	}
	if doer.calls != 3 {
		t.Fatalf("calls = %d, want 3", doer.calls)
	}
	if len(slept) != 2 {
		t.Fatalf("slept %v, want 2 backoffs", slept)
	}
	for i, d := range slept {
		if d < time.Second {
			t.Fatalf("backoff[%d] = %s, want >= Retry-After (1s)", i, d)
		}
	}
}

func TestFetchAgentAssignment_HonorsRetryAfterAsMinimum(t *testing.T) {
	want := validAssignment(t, "connector-7f3c2a")
	doer := &scriptedDoer{responses: []scriptedResponse{
		unavailable("10"),
		{status: 200, body: assignmentEnvelope(t, want)},
	}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration
	if _, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept, WithAssignmentRetryBudget(6, time.Hour))...); err != nil {
		t.Fatalf("FetchAgentAssignment: %v", err)
	}
	if len(slept) != 1 || slept[0] != 10*time.Second {
		t.Fatalf("slept = %v, want [10s] (Retry-After honored as the minimum)", slept)
	}
}

func TestAssignmentBackoffCapsJitterButHonorsRetryAfter(t *testing.T) {
	cfg := &assignmentConfig{
		minBackoff: 8 * time.Second,
		maxBackoff: 8 * time.Second,
		jitter:     func() float64 { return 0.999 },
	}
	if got := cfg.backoff(1, 0); got != 8*time.Second {
		t.Fatalf("jittered backoff = %s, want maxBackoff 8s", got)
	}
	if got := cfg.backoff(1, 10*time.Second); got != 10*time.Second {
		t.Fatalf("Retry-After backoff = %s, want 10s minimum even above maxBackoff", got)
	}
}

func TestFetchAgentAssignment_DefaultsRetryAfterWhenAbsent(t *testing.T) {
	want := validAssignment(t, "connector-7f3c2a")
	doer := &scriptedDoer{responses: []scriptedResponse{
		unavailable(""), // no Retry-After header
		{status: 200, body: assignmentEnvelope(t, want)},
	}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration
	if _, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept)...); err != nil {
		t.Fatalf("FetchAgentAssignment: %v", err)
	}
	if len(slept) != 1 || slept[0] != defaultAssignmentRetryAfter {
		t.Fatalf("slept = %v, want [%s] (server-contract default)", slept, defaultAssignmentRetryAfter)
	}
}

func TestFetchAgentAssignment_ExhaustsByAttemptBudget(t *testing.T) {
	first := unavailable("1")
	first.body = `{"error":{"code":"cell_assignment_unavailable","detail":"first authority failure"}}`
	last := unavailable("1")
	last.body = `{"error":{"code":"cell_assignment_unavailable","detail":"last authority failure"}}`
	doer := &scriptedDoer{responses: []scriptedResponse{first, last}} // last response repeats
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept, WithAssignmentRetryBudget(3, time.Hour))...)
	if !errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("error = %v, want ErrAssignmentRecoveryRequired", err)
	}
	// The recovery-required class also carries the underlying 503 class.
	if !errors.Is(err, ErrAssignmentUnavailable) {
		t.Fatalf("error = %v, want it to also match ErrAssignmentUnavailable", err)
	}
	var rec *AssignmentRecoveryRequiredError
	if !errors.As(err, &rec) || rec.Attempts != 3 {
		t.Fatalf("recovery error = %v (attempts=%d), want 3 attempts", err, recAttempts(rec))
	}
	if rec.LastRetryAfter != time.Second || !strings.Contains(err.Error(), "last-retry-after=1s") {
		t.Fatalf("recovery error did not surface last Retry-After: %#v / %v", rec, err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable ||
		apiErr.Code != assignmentCodeUnavailable || apiErr.Detail != "last authority failure" {
		t.Fatalf("recovery error lost final API problem details: %v", err)
	}
	if doer.calls != 3 {
		t.Fatalf("calls = %d, want exactly 3 (bounded, never an unbounded loop)", doer.calls)
	}
}

func TestFetchAgentAssignment_ExhaustsByDeadlineBudget(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{unavailable("20")}} // 20s Retry-After
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept, WithAssignmentRetryBudget(100, 30*time.Second))...)
	if !errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("error = %v, want ErrAssignmentRecoveryRequired", err)
	}
	// It must not have slept past the 30s budget: one 20s sleep, then stop because
	// a second 20s delay would overrun.
	total := time.Duration(0)
	for _, d := range slept {
		total += d
	}
	if total > 30*time.Second {
		t.Fatalf("total backoff %s exceeded the 30s budget", total)
	}
	if doer.calls > 100 {
		t.Fatalf("calls = %d, unbounded", doer.calls)
	}
}

func TestFetchAgentAssignment_HugeRetryAfterCannotOverflowDeadlineGuard(t *testing.T) {
	first := unavailable("1")
	second := unavailable(strconv.FormatInt(maxHeaderDurationSeconds, 10))
	doer := &scriptedDoer{responses: []scriptedResponse{first, second}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration

	_, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", BearerToken("lv_key"),
		deterministicFetchOpts(doer, clk, &slept, WithAssignmentRetryBudget(100, time.Hour))...)
	if !errors.Is(err, ErrAssignmentRecoveryRequired) {
		t.Fatalf("error = %v, want ErrAssignmentRecoveryRequired", err)
	}
	if doer.calls != 2 || len(slept) != 1 || slept[0] != time.Second {
		t.Fatalf("calls/sleeps = %d/%v, want two calls and only the initial 1s sleep", doer.calls, slept)
	}
}

func recAttempts(e *AssignmentRecoveryRequiredError) int {
	if e == nil {
		return -1
	}
	return e.Attempts
}

// --- pre-I/O validation ---

func TestFetchAgentAssignment_ValidatesBeforeIO(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{{status: 200, body: "{}"}}}
	clk := &fakeClock{now: time.Now()}
	var slept []time.Duration
	opts := func() []AssignmentOption { return deterministicFetchOpts(doer, clk, &slept) }

	// Invalid agent id fails before any request.
	if _, err := FetchAgentAssignment(context.Background(), "Bad_ID", BearerToken("lv_key"), opts()...); !errors.Is(err, ErrInvalidAssignmentConfig) {
		t.Fatalf("invalid agent id error = %v, want ErrInvalidAssignmentConfig", err)
	}
	// Nil credential fails before any request.
	if _, err := FetchAgentAssignment(context.Background(), "connector-7f3c2a", nil, opts()...); !errors.Is(err, ErrInvalidAssignmentConfig) {
		t.Fatalf("nil credential error = %v, want ErrInvalidAssignmentConfig", err)
	}
	// Cancelled context fails before any request.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchAgentAssignment(ctx, "connector-7f3c2a", BearerToken("lv_key"), opts()...); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v, want context.Canceled", err)
	}
	if doer.calls != 0 {
		t.Fatalf("calls = %d, want 0 (all failures are pre-I/O)", doer.calls)
	}
}

func TestFetchAgentAssignment_CancelDuringBackoff(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{unavailable("1")}}
	clk := &fakeClock{now: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	// The real sleep observes the cancelled context and returns its error.
	_, err := FetchAgentAssignment(ctx, "connector-7f3c2a", BearerToken("lv_key"),
		WithAssignmentHTTPClient(doer),
		WithAssignmentBaseURL("https://api.layerv.test"),
		withAssignmentClock(clk.Now),
		withAssignmentJitter(func() float64 { return 0 }),
		withAssignmentSleep(func(ctx context.Context, _ time.Duration) error {
			cancel()
			return ctx.Err()
		}),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// --- AgentState persistence ---

func TestAgentState_AssignmentRoundTripsThroughFileStore(t *testing.T) {
	registeredAt := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(secureAgentStateTestDir(t), "state.json")
	store := FileAgentState(path)

	base, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	base.AgentID = "connector-7f3c2a"
	base.RegisteredAt = &registeredAt
	base.DeviceAPIKey = "lv_device_secret"
	assignment := validAssignment(t, "connector-7f3c2a")
	base.Assignment = &assignment

	if err := store.SaveAgentState(context.Background(), base); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Assignment == nil {
		t.Fatal("assignment did not round trip")
	}
	got := loaded.Assignment
	if got.CellID != "cell0" || got.AssignmentGeneration != 1 || got.EndpointRevision != 1 ||
		!got.LeaseExpiresAt.Equal(assignment.LeaseExpiresAt) ||
		got.Endpoint.Host != "cell0.nhp.layerv.ai" || got.Endpoint.Port != 62206 ||
		got.Endpoint.ServerPublicKeyB64 != assignment.Endpoint.ServerPublicKeyB64 {
		t.Fatalf("assignment did not round trip: %#v", got)
	}
}

func TestAgentState_AssignmentOmittedWhenAbsent(t *testing.T) {
	base, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	base.AgentID = "connector-7f3c2a"
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "assignment") {
		t.Fatalf("nil assignment must be omitted, got %s", raw)
	}
	// A legacy state file without the field loads with a nil Assignment.
	var loaded AgentState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loaded.Assignment != nil {
		t.Fatalf("assignment = %#v, want nil", loaded.Assignment)
	}
}

func TestAgentAssignment_LeaseExpired(t *testing.T) {
	a := &AgentAssignment{LeaseExpiresAt: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	if !a.LeaseExpired(a.LeaseExpiresAt) {
		t.Fatal("lease at exactly the expiry instant must be treated as expired (fail closed)")
	}
	if !a.LeaseExpired(a.LeaseExpiresAt.Add(time.Second)) {
		t.Fatal("lease after expiry must be expired")
	}
	if a.LeaseExpired(a.LeaseExpiresAt.Add(-time.Second)) {
		t.Fatal("lease before expiry must not be expired")
	}
	var absent *AgentAssignment
	if !absent.LeaseExpired(time.Now()) {
		t.Fatal("missing assignment must be treated as expired (fail closed)")
	}
}

func TestAssignmentDurationHeadersRejectOverflow(t *testing.T) {
	for _, value := range []string{"9223372036854775807", "999999999999999999999999"} {
		if got := parseRetryAfter(value, time.Now()); got != 0 {
			t.Fatalf("parseRetryAfter(%q) = %s, want 0", value, got)
		}
		if got := parseSecondsHeader(value); got != 0 {
			t.Fatalf("parseSecondsHeader(%q) = %s, want 0", value, got)
		}
	}
	farFuture := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC).Format(http.TimeFormat)
	if got := parseRetryAfter(farFuture, time.Now()); got != 0 {
		t.Fatalf("parseRetryAfter(far-future HTTP date) = %s, want 0", got)
	}
}
