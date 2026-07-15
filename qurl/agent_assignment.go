package qurl

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Native-UDP cell-assignment client for POST /v1/agent/assignment.
//
// The assignment is the authoritative, durable native-UDP placement qurl-service
// hands a registered agent. The SDK consumes it and never calculates placement,
// lists cells, derives an AWS hostname, or uses the browser relay URL. First
// assignment creation authenticates with an enrollment/account credential; every
// ordinary lease/binding refresh authenticates with the persisted immutable-bound
// DeviceAPIKey. This client is credential-agnostic: the caller supplies the
// CredentialProvider (BearerToken(enrollmentKey) for first creation, or a
// DeviceAPIKey-backed provider for refresh), so the one-refresh-path policy stays
// with the lifecycle rather than being hard-coded here.

// --- assignment types (wire `data` shape and persisted AgentState shape) ---

// NHPUDPEndpoint is the assigned native NHP UDP endpoint. Host is opaque
// LayerV-owned DNS data resolved fresh on every registration/knock exchange; a
// resolved IP is never persisted as the assignment. It is deliberately NOT an
// HTTPS URL, a raw AWS NLB hostname, or a value derived from cell_id.
type NHPUDPEndpoint struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

// AgentAssignment is one authoritative native-UDP cell assignment. It is both the
// decoded POST /v1/agent/assignment response `data` and the shape persisted in
// AgentState.Assignment, so the binding metadata a later native exchange needs —
// generation, endpoint revision, lease expiry, and the DNS endpoint — survives a
// restart. A resolved IP is never part of it.
type AgentAssignment struct {
	AgentID              string         `json:"agent_id"`
	CellID               string         `json:"cell_id"`
	AssignmentGeneration int64          `json:"assignment_generation"`
	EndpointRevision     int64          `json:"endpoint_revision"`
	LeaseExpiresAt       time.Time      `json:"lease_expires_at"`
	Endpoint             NHPUDPEndpoint `json:"nhp_udp_endpoint"`
}

// clone returns an independent copy. AgentAssignment holds only scalars, a
// time.Time, and an all-scalar NHPUDPEndpoint, so a shallow struct copy fully
// isolates it; keep this aligned if a pointer/slice/map field is ever added.
func (a *AgentAssignment) clone() *AgentAssignment {
	if a == nil {
		return nil
	}
	cloned := *a
	return &cloned
}

// DecodedServerKey returns the raw 32-byte X25519 NHP server public key from the
// assignment's endpoint. It accepts the padded or raw standard-base64 spellings a
// deployed producer may emit and validates the decoded bytes as an X25519 key.
func (a *AgentAssignment) DecodedServerKey() ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: assignment is nil", ErrAssignmentInvalidResponse)
	}
	if err := validateNHPServerPublicKey(a.Endpoint.ServerPublicKeyB64, "assignment endpoint", ErrAssignmentInvalidResponse); err != nil {
		return nil, err
	}
	return decodeNHPServerPublicKey(a.Endpoint.ServerPublicKeyB64)
}

// LeaseExpired reports whether the assignment lease has reached or passed now. A
// lease is a refresh deadline: once expired the binding must be refreshed through
// the control plane and must fail closed, never fall back to local cell selection.
func (a *AgentAssignment) LeaseExpired(now time.Time) bool {
	return a != nil && !a.LeaseExpiresAt.After(now)
}

// --- error sentinels and typed errors ---

// ErrInvalidAssignmentConfig is returned when assignment inputs or options are
// invalid before any network call.
var ErrInvalidAssignmentConfig = errors.New("qurl: invalid assignment config")

// ErrAssignmentInvalidResponse is returned when a 2xx assignment response is
// missing, malformed, echoes a different agent id, or carries an unusable
// endpoint (bad host opacity, port, or server key).
var ErrAssignmentInvalidResponse = errors.New("qurl: assignment response invalid")

// ErrAssignmentUnavailable is the retryable authority signal: HTTP 503
// cell_assignment_unavailable. The wire deliberately cannot distinguish a
// transient authority failure from a device key whose durable assignment row is
// missing, so it is retryable only within a bounded attempt/deadline budget —
// honor Retry-After as a minimum, back off, then surface recovery, never loop
// forever.
var ErrAssignmentUnavailable = errors.New("qurl: cell assignment unavailable")

// ErrAssignmentRecoveryRequired is returned when the bounded assignment-refresh
// budget (attempt maximum or elapsed deadline) is exhausted while the service
// kept returning 503. The caller must surface operator recovery rather than
// retry, because the durable assignment row may simply be missing.
var ErrAssignmentRecoveryRequired = errors.New("qurl: cell assignment recovery required")

// ErrAssignmentReassignmentRequired is returned for HTTP 409
// cell_reassignment_in_progress: an explicit cross-cell move is underway. It is
// terminal for an ordinary refresh; the agent must take the SDK-2 move /
// re-registration path rather than retry this endpoint.
var ErrAssignmentReassignmentRequired = errors.New("qurl: cell reassignment in progress")

// ErrAssignmentQuotaExceeded is returned for HTTP 409
// agent_assignment_quota_exceeded: the account reached its durable-agent
// assignment cap. Terminal; free an assignment slot before retrying.
var ErrAssignmentQuotaExceeded = errors.New("qurl: agent assignment quota exceeded")

// ErrAssignmentRateLimited is returned for HTTP 429: the per-credential
// assignment budget (60/hour) or the general account budget was exceeded. It is
// terminal for the current operation — honor the reset headers, do not treat it
// as a 503 retry, and do not rotate credentials to evade the budget.
var ErrAssignmentRateLimited = errors.New("qurl: assignment rate limited")

// ErrAssignmentRequestRejected is returned for HTTP 400 (malformed/oversized body
// or invalid agent id). Terminal; fix the request, do not retry.
var ErrAssignmentRequestRejected = errors.New("qurl: assignment request rejected")

// ErrAssignmentForbidden is returned for HTTP 401/403: missing/invalid auth, a
// frozen account, or a device key presented for a different agent id. Terminal.
var ErrAssignmentForbidden = errors.New("qurl: assignment forbidden")

// ErrAssignmentServiceError is returned for an unexpected assignment status (a
// non-cell_assignment_unavailable 5xx, or a transport-level failure). Terminal
// for this bounded client; only 503 cell_assignment_unavailable is retried.
var ErrAssignmentServiceError = errors.New("qurl: assignment service error")

// AssignmentRateLimitedError carries the retry timing a 429 reported so a caller
// can pace the next attempt. It unwraps to ErrAssignmentRateLimited.
type AssignmentRateLimitedError struct {
	// RetryAfter is the Retry-After delay, or 0 when the header was absent.
	RetryAfter time.Duration
	// Reset is the RateLimit-Reset window, or 0 when the header was absent.
	Reset time.Duration
}

func (e *AssignmentRateLimitedError) Error() string {
	return fmt.Sprintf("qurl: assignment rate limited; honor the rate-limit reset (retry-after=%s reset=%s) and do not rotate credentials to evade it", e.RetryAfter, e.Reset)
}

func (e *AssignmentRateLimitedError) Unwrap() error { return ErrAssignmentRateLimited }

// AssignmentRecoveryRequiredError reports an exhausted bounded refresh: the
// service kept returning 503 through the whole attempt/deadline budget. It
// unwraps to both ErrAssignmentRecoveryRequired and ErrAssignmentUnavailable so a
// caller can match either the terminal-recovery class or the underlying 503
// class.
type AssignmentRecoveryRequiredError struct {
	Attempts       int
	Elapsed        time.Duration
	LastRetryAfter time.Duration
}

func (e *AssignmentRecoveryRequiredError) Error() string {
	return fmt.Sprintf("qurl: cell assignment unavailable after %d attempts over %s; the durable assignment row may be missing — surface operator recovery instead of retrying (never an unbounded 5s loop)", e.Attempts, e.Elapsed)
}

func (e *AssignmentRecoveryRequiredError) Unwrap() []error {
	return []error{ErrAssignmentRecoveryRequired, ErrAssignmentUnavailable}
}

// --- client ---

// Assignment wire error codes emitted by qurl-service in the RFC 7807 `code`
// field. These are a frozen public contract; fence them exactly.
const (
	assignmentCodeUnavailable            = "cell_assignment_unavailable"
	assignmentCodeReassignmentInProgress = "cell_reassignment_in_progress"
	assignmentCodeQuotaExceeded          = "agent_assignment_quota_exceeded"
)

// Bounded-refresh defaults. The 60/hour per-credential assignment budget is a
// server contract; a single FetchAgentAssignment consumes at most
// defaultAssignmentMaxAttempts slots, and honoring Retry-After (>=5s) spaces them
// so one call stays far under the budget. The caller paces refresh cadence.
const (
	defaultAssignmentMaxAttempts = 6
	defaultAssignmentBudget      = 45 * time.Second
	defaultAssignmentMinBackoff  = 500 * time.Millisecond
	defaultAssignmentMaxBackoff  = 8 * time.Second
	// defaultAssignmentRetryAfter is the minimum 503 delay when the server omits
	// Retry-After; it matches the service's contractual Retry-After: 5.
	defaultAssignmentRetryAfter = 5 * time.Second
)

type assignmentConfig struct {
	baseURL     string
	httpClient  HTTPDoer
	maxAttempts int
	budget      time.Duration
	minBackoff  time.Duration
	maxBackoff  time.Duration
	clock       func() time.Time
	sleep       func(context.Context, time.Duration) error
	jitter      func() float64
}

// AssignmentOption customizes FetchAgentAssignment.
type AssignmentOption interface {
	applyAssignmentOption(*assignmentConfig) error
}

type assignmentOptionFunc func(*assignmentConfig) error

func (f assignmentOptionFunc) applyAssignmentOption(c *assignmentConfig) error { return f(c) }

// WithAssignmentBaseURL points the client at a non-default control-plane origin.
// Assignment refresh uses the resource/API origin, not the registration origin.
func WithAssignmentBaseURL(rawURL string) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "assignment base URL", ErrInvalidAssignmentConfig); err != nil {
			return err
		}
		c.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithAssignmentHTTPClient injects the HTTP client used for the assignment POST.
func WithAssignmentHTTPClient(client HTTPDoer) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidAssignmentConfig)
		}
		c.httpClient = client
		return nil
	})
}

// WithAssignmentRetryBudget bounds automatic 503 retries by a maximum attempt
// count and a maximum elapsed time. Both must be positive. When either is
// exhausted the client returns a typed recovery-required result rather than
// retrying further.
func WithAssignmentRetryBudget(maxAttempts int, budget time.Duration) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if maxAttempts < 1 {
			return fmt.Errorf("%w: assignment max attempts must be at least 1", ErrInvalidAssignmentConfig)
		}
		if budget <= 0 {
			return fmt.Errorf("%w: assignment retry budget must be positive", ErrInvalidAssignmentConfig)
		}
		c.maxAttempts = maxAttempts
		c.budget = budget
		return nil
	})
}

// withAssignmentClock overrides the clock (tests only).
func withAssignmentClock(clock func() time.Time) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if clock == nil {
			return fmt.Errorf("%w: clock must not be nil", ErrInvalidAssignmentConfig)
		}
		c.clock = clock
		return nil
	})
}

// withAssignmentSleep overrides the backoff sleep (tests only) so a bounded loop
// can be driven without real time passing.
func withAssignmentSleep(sleep func(context.Context, time.Duration) error) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if sleep == nil {
			return fmt.Errorf("%w: sleep must not be nil", ErrInvalidAssignmentConfig)
		}
		c.sleep = sleep
		return nil
	})
}

// withAssignmentJitter overrides the jitter source (tests only) with a function
// returning a fraction in [0,1).
func withAssignmentJitter(jitter func() float64) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if jitter == nil {
			return fmt.Errorf("%w: jitter must not be nil", ErrInvalidAssignmentConfig)
		}
		c.jitter = jitter
		return nil
	})
}

func newAssignmentConfig(opts []AssignmentOption) (*assignmentConfig, error) {
	c := &assignmentConfig{
		baseURL:     defaultAPIBaseURL,
		httpClient:  defaultAPIHTTPClient,
		maxAttempts: defaultAssignmentMaxAttempts,
		budget:      defaultAssignmentBudget,
		minBackoff:  defaultAssignmentMinBackoff,
		maxBackoff:  defaultAssignmentMaxBackoff,
		clock:       time.Now,
		sleep:       sleepWithContext,
		jitter:      cryptoJitterFraction,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil AssignmentOption", ErrInvalidAssignmentConfig)
		}
		if err := opt.applyAssignmentOption(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// FetchAgentAssignment resolves the agent's native-UDP cell assignment by POSTing
// agentID to /v1/agent/assignment, authenticated by cred. It classifies the
// response per the frozen contract: a 200 returns the validated assignment; a 503
// cell_assignment_unavailable is retried within the bounded attempt/deadline
// budget honoring Retry-After as a minimum delay with jittered bounded backoff,
// returning a typed recovery-required result on exhaustion; 400/401/403/409/429
// are terminal with their typed errors, and 429 carries the rate-limit reset.
//
// cred is the caller's choice: an enrollment/account credential for first
// creation, or a DeviceAPIKey-backed credential for ordinary refresh.
func FetchAgentAssignment(ctx context.Context, agentID string, cred CredentialProvider, opts ...AssignmentOption) (*AgentAssignment, error) {
	if err := validateContext(ctx, ErrInvalidAssignmentConfig); err != nil {
		return nil, err
	}
	if err := validateAssignmentAgentID(agentID); err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("%w: credential provider must not be nil", ErrInvalidAssignmentConfig)
	}
	cfg, err := newAssignmentConfig(opts)
	if err != nil {
		return nil, err
	}
	return cfg.resolve(ctx, agentID, cred)
}

func (c *assignmentConfig) resolve(ctx context.Context, agentID string, cred CredentialProvider) (*AgentAssignment, error) {
	start := c.clock()
	var lastRetryAfter time.Duration
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res := c.attempt(ctx, agentID, cred)
		if res.err != nil || res.assignment != nil {
			return res.assignment, res.err
		}
		// res is the retryable 503 case.
		lastRetryAfter = res.retryAfter
		elapsed := c.clock().Sub(start)
		delay := c.backoff(attempt, res.retryAfter)
		// Stop when the attempt budget is spent, the elapsed deadline is reached,
		// or the required minimum delay would overrun the deadline — never loop
		// past the budget honoring an ever-repeating Retry-After.
		if attempt >= c.maxAttempts || elapsed >= c.budget || elapsed+delay > c.budget {
			return nil, &AssignmentRecoveryRequiredError{
				Attempts:       attempt,
				Elapsed:        elapsed,
				LastRetryAfter: lastRetryAfter,
			}
		}
		if err := c.sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// backoff returns the delay before the next attempt: the larger of the honored
// Retry-After minimum and a jittered exponential backoff capped at maxBackoff.
func (c *assignmentConfig) backoff(attempt int, retryAfter time.Duration) time.Duration {
	base := c.minBackoff << (attempt - 1)
	if base <= 0 || base > c.maxBackoff {
		base = c.maxBackoff
	}
	jittered := base + time.Duration(c.jitter()*float64(base))
	if retryAfter > jittered {
		return retryAfter
	}
	return jittered
}

// assignmentAttempt is the outcome of one POST: exactly one of a validated
// assignment, a terminal error, or a retryable 503 (assignment and err both nil,
// retryAfter set).
type assignmentAttempt struct {
	assignment *AgentAssignment
	retryAfter time.Duration
	err        error
}

func (c *assignmentConfig) attempt(ctx context.Context, agentID string, cred CredentialProvider) assignmentAttempt {
	reqBody, err := json.Marshal(assignmentRequestBody{AgentID: agentID})
	if err != nil {
		return assignmentAttempt{err: fmt.Errorf("%w: encode assignment request: %w", ErrInvalidAssignmentConfig, err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/agent/assignment", bytes.NewReader(reqBody))
	if err != nil {
		return assignmentAttempt{err: fmt.Errorf("%w: build assignment request: %w", ErrInvalidAssignmentConfig, err)}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", sdkUserAgent())
	if err := cred.Authorize(ctx, req); err != nil {
		return assignmentAttempt{err: fmt.Errorf("%w: authorize assignment request: %w", ErrInvalidAssignmentConfig, err)}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// A transport-level failure is terminal for this bounded client: it is not
		// the 503 authority signal, and the request may already have consumed
		// assignment budget, so a blind retry here is unsafe.
		return assignmentAttempt{err: fmt.Errorf("%w: assignment request failed: %w", ErrAssignmentServiceError, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	defer drainResponseBody(resp.Body)

	body, err := readCappedBody(resp.Body, maxAPIResponseBodyBytes, "assignment response body")
	if err != nil {
		return assignmentAttempt{err: fmt.Errorf("%w: read assignment response: %w", ErrAssignmentServiceError, err)}
	}
	defer wipeBytes(body)

	if resp.StatusCode == http.StatusOK {
		return c.decodeSuccess(agentID, body)
	}
	return classifyAssignmentError(resp.StatusCode, body, resp.Header, c.clock())
}

func (c *assignmentConfig) decodeSuccess(agentID string, body []byte) assignmentAttempt {
	if len(bytes.TrimSpace(body)) == 0 {
		return assignmentAttempt{err: fmt.Errorf("%w: empty assignment response body", ErrAssignmentInvalidResponse)}
	}
	var env apiEnvelope[AgentAssignment]
	if err := json.Unmarshal(body, &env); err != nil {
		return assignmentAttempt{err: fmt.Errorf("%w: decode assignment response: %w", ErrAssignmentInvalidResponse, err)}
	}
	assignment := env.Data.clone()
	if err := validateAgentAssignment(assignment, agentID); err != nil {
		return assignmentAttempt{err: err}
	}
	return assignmentAttempt{assignment: assignment}
}

// classifyAssignmentError maps a non-2xx assignment response to the frozen typed
// taxonomy. Only 503 cell_assignment_unavailable is retryable.
func classifyAssignmentError(status int, body []byte, header http.Header, now time.Time) assignmentAttempt {
	var apiErr *APIError
	if !errors.As(apiErrorFromResponse(status, body), &apiErr) {
		// apiErrorFromResponse always returns *APIError; keep this defensive so a
		// future change cannot silently drop the code/status.
		return assignmentAttempt{err: fmt.Errorf("%w: unexpected assignment status %d", ErrAssignmentServiceError, status)}
	}
	retryAfter := parseRetryAfter(header.Get("Retry-After"), now)

	switch status {
	case http.StatusBadRequest:
		return assignmentAttempt{err: fmt.Errorf("%w: %w", ErrAssignmentRequestRejected, apiErr)}
	case http.StatusUnauthorized, http.StatusForbidden:
		return assignmentAttempt{err: fmt.Errorf("%w: %w", ErrAssignmentForbidden, apiErr)}
	case http.StatusConflict:
		if strings.EqualFold(apiErr.Code, assignmentCodeReassignmentInProgress) {
			return assignmentAttempt{err: fmt.Errorf("%w: %w", ErrAssignmentReassignmentRequired, apiErr)}
		}
		// agent_assignment_quota_exceeded, and any other 409, are a terminal quota
		// class for this client.
		return assignmentAttempt{err: fmt.Errorf("%w: %w", ErrAssignmentQuotaExceeded, apiErr)}
	case http.StatusTooManyRequests:
		return assignmentAttempt{err: &AssignmentRateLimitedError{
			RetryAfter: retryAfter,
			Reset:      parseSecondsHeader(header.Get("RateLimit-Reset")),
		}}
	case http.StatusServiceUnavailable:
		if strings.EqualFold(apiErr.Code, assignmentCodeUnavailable) {
			if retryAfter <= 0 {
				retryAfter = defaultAssignmentRetryAfter
			}
			return assignmentAttempt{retryAfter: retryAfter}
		}
		return assignmentAttempt{err: fmt.Errorf("%w: 503 %s", ErrAssignmentServiceError, apiErr.Code)}
	default:
		return assignmentAttempt{err: fmt.Errorf("%w: %w", ErrAssignmentServiceError, apiErr)}
	}
}

// assignmentRequestBody is the POST /v1/agent/assignment request. The SDK has
// already generated and durably saved its keypair and agent id before this call;
// no cell, endpoint, region, or placement hint is ever sent.
type assignmentRequestBody struct {
	AgentID string `json:"agent_id"`
}

// --- validation ---

// validateAssignmentAgentID enforces the frozen agent-id shape client-side so a
// malformed id fails before it can consume assignment budget on a 400.
func validateAssignmentAgentID(agentID string) error {
	if l := len(agentID); l < 2 || l > 64 {
		return fmt.Errorf("%w: agent id must be 2-64 characters", ErrInvalidAssignmentConfig)
	}
	for i := 0; i < len(agentID); i++ {
		ch := agentID[i]
		isLowerAlnum := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if i == 0 || i == len(agentID)-1 {
			if !isLowerAlnum {
				return fmt.Errorf("%w: agent id must start and end with a lowercase letter or digit", ErrInvalidAssignmentConfig)
			}
			continue
		}
		if !isLowerAlnum && ch != '-' {
			return fmt.Errorf("%w: agent id may contain only lowercase letters, digits, and hyphens", ErrInvalidAssignmentConfig)
		}
	}
	return nil
}

// validateAgentAssignment checks a decoded assignment before it is used or
// persisted: it must echo the requested agent id, carry a positive generation and
// endpoint revision, a non-zero lease, and an endpoint whose host passes the
// opacity guard, whose port is in range, and whose server key is a valid X25519
// key.
func validateAgentAssignment(a *AgentAssignment, wantAgentID string) error {
	if a == nil {
		return fmt.Errorf("%w: assignment is nil", ErrAssignmentInvalidResponse)
	}
	if a.AgentID != wantAgentID {
		return fmt.Errorf("%w: response agent id %q does not match requested %q", ErrAssignmentInvalidResponse, a.AgentID, wantAgentID)
	}
	if strings.TrimSpace(a.CellID) == "" {
		return fmt.Errorf("%w: missing cell id", ErrAssignmentInvalidResponse)
	}
	if a.AssignmentGeneration < 1 {
		return fmt.Errorf("%w: assignment generation must be >= 1", ErrAssignmentInvalidResponse)
	}
	if a.EndpointRevision < 1 {
		return fmt.Errorf("%w: endpoint revision must be >= 1", ErrAssignmentInvalidResponse)
	}
	if a.LeaseExpiresAt.IsZero() {
		return fmt.Errorf("%w: missing lease expiry", ErrAssignmentInvalidResponse)
	}
	if err := validateAssignmentEndpointHost(a.Endpoint.Host); err != nil {
		return err
	}
	if a.Endpoint.Port < 1 || a.Endpoint.Port > 65535 {
		return fmt.Errorf("%w: endpoint port %d out of range", ErrAssignmentInvalidResponse, a.Endpoint.Port)
	}
	if err := validateNHPServerPublicKey(a.Endpoint.ServerPublicKeyB64, "assignment endpoint", ErrAssignmentInvalidResponse); err != nil {
		return err
	}
	return nil
}

// validateAssignmentEndpointHost enforces host opacity: the endpoint host must be
// a LayerV-owned public DNS name, never an AWS-owned/internal hostname, a
// private/loopback/link-local IP literal, or a malformed value the SDK could not
// have derived. The host is treated as opaque otherwise — no structural
// requirement beyond rejecting these categories.
func validateAssignmentEndpointHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return fmt.Errorf("%w: missing endpoint host", ErrAssignmentInvalidResponse)
	}
	if trimmed != host {
		return fmt.Errorf("%w: endpoint host must not have surrounding whitespace", ErrAssignmentInvalidResponse)
	}
	if len(host) > 253 {
		return fmt.Errorf("%w: endpoint host exceeds 253 characters", ErrAssignmentInvalidResponse)
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return fmt.Errorf("%w: endpoint host is malformed", ErrAssignmentInvalidResponse)
	}
	lower := strings.ToLower(host)
	// A resolved IP is never a valid assignment host; reject any IP literal and,
	// in particular, private/loopback/link-local ranges.
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("%w: endpoint host must be a DNS name, not an IP literal", ErrAssignmentInvalidResponse)
	}
	for _, banned := range []string{
		".amazonaws.com",
		".elb.amazonaws.com",
		".compute.internal",
		".compute.amazonaws.com",
		".internal",
		".local",
		".localdomain",
	} {
		if strings.HasSuffix(lower, banned) {
			return fmt.Errorf("%w: endpoint host %q is an AWS-owned or internal name", ErrAssignmentInvalidResponse, host)
		}
	}
	if lower == "localhost" {
		return fmt.Errorf("%w: endpoint host must not be localhost", ErrAssignmentInvalidResponse)
	}
	return nil
}

// --- header parsing and small helpers ---

// parseRetryAfter parses a Retry-After header value: either integer seconds or an
// HTTP-date. It clamps to a non-negative duration; an absent/invalid value is 0.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// parseSecondsHeader parses an integer-seconds header (RateLimit-Reset) into a
// non-negative duration; an absent/invalid value is 0.
func parseSecondsHeader(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// sleepWithContext sleeps for d, returning early with the context error if the
// context is cancelled first.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// cryptoJitterFraction returns a fraction in [0,1) from a crypto/rand draw. The
// jitter is decorrelation, not a security primitive, but crypto/rand avoids
// pulling in a separately-seeded PRNG and any weak-RNG lint.
func cryptoJitterFraction() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	// 53-bit mantissa fraction, matching the usual [0,1) float construction.
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}
