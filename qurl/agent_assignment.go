package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// Native UDP cell assignment is a two-party authenticated exchange. The SDK
// sends NHP_LST directly to a pinned bootstrap hub and accepts only the matching
// NHP_LRT authenticated by that hub's X25519 key. It never calls an HTTP
// assignment endpoint, derives a cell from an identifier, probes another cell,
// or asks the browser relay to route a native client.

const (
	assignmentQuery                     = "cell_assignment"
	assignmentVersion                   = 1
	assignmentModeEnroll                = "enroll"
	assignmentModeRefresh               = "refresh"
	assignmentKeyKindConnectorBootstrap = "connector_bootstrap"
	assignmentKeyKindAgent              = "agent"
	// standardNHPUDPPort is the single UDP port every LayerV NHP endpoint listens
	// on -- Hub bootstrap and assigned cells alike. It is 443 because restrictive
	// egress filters usually already permit it for QUIC, and because high-entropy
	// encrypted UDP is unremarkable there: nothing here speaks QUIC or TLS, but
	// nothing on 443 is watching for a protocol shape the way a DNS or
	// tunnel-detection middlebox watches 53. Endpoints are pinned to it rather
	// than range-checked, so a deployment file cannot quietly place a cell on a
	// port the agent's network will drop.
	standardNHPUDPPort       = 443
	maxAssignmentTicketBytes = 2304
	// Pinned by TestAssignmentTicketMatchesReleasedConformanceBoundary.
	maxAssignmentTicketLifetime = 15 * time.Minute
	maxAssignmentJSONDepth      = 64
	assignmentRequestNonceBytes = 32

	// These suffixes are a release-gated trust allowlist, not runtime
	// configuration. Adding an endpoint apex requires an SDK release.
	assignmentEndpointSuffixAI  = ".layerv.ai"
	assignmentEndpointSuffixXYZ = ".layerv.xyz"

	defaultAssignmentMaxAttempts = 4
	defaultAssignmentBudget      = 30 * time.Second
	defaultAssignmentMinBackoff  = 500 * time.Millisecond
	defaultAssignmentMaxBackoff  = 8 * time.Second
)

// HubBootstrap is the out-of-band trust root for native assignment. Host, Port,
// and ServerPublicKeyB64 are one atomic revision supplied by trusted deployment
// configuration. The SDK never synthesizes any of them from an API URL, cell id,
// DNS response, or unauthenticated packet. Port must be standardNHPUDPPort,
// which an authenticated assigned-cell endpoint is held to as well.
type HubBootstrap struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

// NHPUDPEndpoint is the assigned cell's public native NHP endpoint. Host is
// opaque LayerV-owned DNS resolved fresh for each exchange; it is not an HTTPS
// URL or a raw cloud load-balancer name. Resolved IPs are never stored here.
type NHPUDPEndpoint struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ServerPublicKeyB64 string `json:"server_public_key_b64"`
}

// AgentAssignment is the durable placement returned by the hub. Agent identity
// remains the single AgentState.AgentID; it is authenticated and checked in the
// LRT but deliberately not duplicated in this persisted binding.
type AgentAssignment struct {
	CellID               string         `json:"cell_id"`
	AssignmentGeneration int64          `json:"assignment_generation"`
	EndpointRevision     int64          `json:"endpoint_revision"`
	LeaseExpiresAt       time.Time      `json:"lease_expires_at"`
	Endpoint             NHPUDPEndpoint `json:"nhp_udp_endpoint"`
}

// AssignmentRegistration is the enrollment identity the assigned-cell REG will
// present. The lifecycle persists it only inside PendingAgentActivation; it is
// not durable assignment state or a completed device credential id.
type AssignmentRegistration struct {
	KeyID   string `json:"key_id"`
	KeyKind string `json:"key_kind"`
}

// InitialAgentAssignment is the validated initial hub result. Registration,
// AssignmentTicket, and AssignmentTicketExpiresAt are ephemeral at this
// transport boundary; RegisterAgentRuntime persists their exact values into
// PendingAgentActivation before REG so an ambiguous/lost RAK can replay the
// same one-shot authorization. This transport slice treats the ticket as
// 1-2304 opaque printable non-space ASCII bytes (0x21-0x7e); assigned-cell
// registration owns qat1 semantic validation. The authenticated response's
// public expiry must be no more than the conformance maximum 900 seconds ahead.
type InitialAgentAssignment struct {
	Registration              AssignmentRegistration
	Assignment                AgentAssignment
	AssignmentTicket          string
	AssignmentTicketExpiresAt time.Time
}

// clone returns an independent assignment snapshot. AgentAssignment is
// currently value-only and TestAgentAssignmentCloneAndLease enforces that
// assumption; deep-copy any future pointer, slice, or map fields here.
func (a *AgentAssignment) clone() *AgentAssignment {
	if a == nil {
		return nil
	}
	cloned := *a
	return &cloned
}

// sameAgentAssignment compares the durable wire fields while using time.Equal
// for the lease instant. Direct struct equality would also compare time.Time's
// location and monotonic metadata, which are not part of the assignment
// contract and could cause a redundant durable write after a future in-memory
// producer starts carrying either.
func sameAgentAssignment(a, b *AgentAssignment) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.CellID == b.CellID &&
		a.AssignmentGeneration == b.AssignmentGeneration &&
		a.EndpointRevision == b.EndpointRevision &&
		a.LeaseExpiresAt.Equal(b.LeaseExpiresAt) &&
		a.Endpoint == b.Endpoint
}

// DecodedServerKey returns the assignment's canonical 32-byte X25519 server
// identity. Persisted/caller-built state is revalidated on every use.
func (a *AgentAssignment) DecodedServerKey() ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: assignment is nil", ErrAssignmentInvalidResponse)
	}
	return decodeAssignmentServerPublicKey(a.Endpoint.ServerPublicKeyB64)
}

// Validate checks every assignment trust-boundary field and requires the lease
// to be live at now. It wraps ErrAssignmentInvalidResponse on failure. Persisted
// stores use the same structural validation without the liveness requirement so
// an expired assignment can load and be refreshed.
func (a *AgentAssignment) Validate(now time.Time) error {
	if err := validatePersistedAgentAssignment(a); err != nil {
		return err
	}
	if !a.LeaseExpiresAt.After(now) {
		return fmt.Errorf("%w: assignment lease must be in the future: %w", ErrAssignmentInvalidResponse, ErrAssignmentLeaseExpired)
	}
	return nil
}

// LeaseExpired reports only whether the assignment is absent or its lease is no
// longer live. It does not validate endpoint or identity fields; caller-built
// state must pass Validate before network use. An expired lease must be refreshed
// through the hub and never permits local cell selection or fallback.
func (a *AgentAssignment) LeaseExpired(now time.Time) bool {
	return a == nil || !a.LeaseExpiresAt.After(now)
}

var (
	// ErrInvalidAssignmentConfig marks invalid hub, identity, credential, key, or
	// retry options rejected before network I/O.
	ErrInvalidAssignmentConfig = errors.New("qurl: invalid assignment config")
	// ErrAssignmentInvalidResponse marks malformed authenticated LRT JSON,
	// unknown/duplicate fields, invalid success data, or an unknown error code.
	// It is terminal: retrying cannot repair an authenticated producer-contract
	// violation and could conceal a hub deployment error.
	ErrAssignmentInvalidResponse = errors.New("qurl: assignment response invalid")
	// ErrAssignmentLeaseExpired distinguishes structurally valid persisted state
	// whose authority lease is no longer live. Validation errors in this class
	// also match ErrAssignmentInvalidResponse, but callers may safely select an
	// explicit RefreshAgentRuntime only for this narrower class.
	ErrAssignmentLeaseExpired = errors.New("qurl: assignment lease expired")
	// ErrAssignmentUnavailable marks retryable 52200, bounded together with
	// transport misses and authenticated rate limits by one operation budget.
	ErrAssignmentUnavailable = errors.New("qurl: cell assignment unavailable")
	// ErrAssignmentRecoveryRequired marks exhaustion of that bounded budget.
	ErrAssignmentRecoveryRequired = errors.New("qurl: cell assignment recovery required")
	// ErrAssignmentIdentityRejected marks 52201.
	ErrAssignmentIdentityRejected = errors.New("qurl: assignment identity rejected")
	// ErrAssignmentReassignmentRequired marks 52202.
	ErrAssignmentReassignmentRequired = errors.New("qurl: cell reassignment in progress")
	// ErrAssignmentQuotaExceeded marks 52203.
	ErrAssignmentQuotaExceeded = errors.New("qurl: agent assignment quota exceeded")
	// ErrAssignmentRateLimited marks retryable 52204. Its authenticated
	// RetryAfter is honored inside the same bounded logical operation while the
	// exact serialized request body is reused.
	ErrAssignmentRateLimited = errors.New("qurl: assignment rate limited")
	// ErrAssignmentRequestRejected marks 52205 or 52109.
	ErrAssignmentRequestRejected = errors.New("qurl: assignment request rejected")
	// ErrAssignmentKeyRejected marks initial-credential result 52106.
	ErrAssignmentKeyRejected = errors.New("qurl: assignment enrollment key rejected")
	// ErrAssignmentRegistrationDisabled marks initial-credential result 52107.
	ErrAssignmentRegistrationDisabled = errors.New("qurl: agent registration disabled")
	// ErrAssignmentBootstrapConsumed marks initial-credential result 52108. The
	// message names the remedy: one-shot enrollment tokens are single-use, so a
	// consumed token cannot be reused after a successful enrollment.
	ErrAssignmentBootstrapConsumed = errors.New("qurl: enrollment token already consumed; one-shot enrollment tokens are single-use, so mint a new enrollment token and retry")
)

// AssignmentError is a valid authenticated application error from the closed
// qurl-conformance v1 taxonomy. Policy comes only from the closed Code set;
// authenticated producer diagnostics are deliberately discarded because a
// buggy producer could reflect a submitted credential. RetryAfter is populated
// only for codes that permit it. In
// particular, 52204 is retried only inside the current bounded logical
// operation, with its RetryAfter enforced as a lower bound. The operation
// reuses the exact serialized request body and request_nonce while each new UDP
// exchange builds a fresh NHP packet.
type AssignmentError struct {
	Code       string
	RetryAfter time.Duration
	kind       error
}

func (e *AssignmentError) Error() string {
	if e == nil {
		return "qurl: assignment error"
	}
	if e.Code == "52109" {
		return "qurl: native Hub assignment request rejected (52109); correct WithAgentRuntimeIdentity or the Hub request contract before retrying"
	}
	if e.Code == "52108" {
		return ErrAssignmentBootstrapConsumed.Error()
	}
	return "qurl: assignment error " + e.Code
}

func (e *AssignmentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// ErrEndpointNoReply marks a bounded exchange in which the host resolved and
// every datagram was written successfully, but no reply of any kind ever came
// back before the budget ran out.
//
// It names an observation, not a cause. Exactly two conditions produce it and
// the client cannot tell them apart: the server is not running, or the network
// path drops the datagrams silently — a source-fenced security group, a
// corporate egress filter, a NAT that never saw a reply to map back. A DROP
// yields no ICMP and no RST, so on the wire those are identical. Any diagnosis
// beyond "nothing answered" has to come from the operator's side.
//
// It is distinct from nativeudp.ErrResolve (DNS never produced an address),
// from nativeudp.ErrServerUnauthenticated (a datagram did come back and failed
// trust), and from ErrInvalidAssignmentConfig (rejected before any I/O).
var ErrEndpointNoReply = errors.New("qurl: endpoint never replied")

// EndpointNoReplyError reports which logical destination stayed silent, how
// many attempts were spent, and the final transport cause.
//
// When the caller's own context ended the wait, that context error is preserved
// in the chain: errors.Is(err, context.DeadlineExceeded) still reports true, so
// existing cancellation handling keeps working. Previously that case returned a
// bare context.DeadlineExceeded and the destination, the attempt count, and the
// transport cause were all discarded — a hang indistinguishable from any other
// timeout in the program.
type EndpointNoReplyError struct {
	// Endpoint is the logical destination as configured, e.g.
	// "hub.nhp.layerv.xyz:443". It is deliberately the DNS name rather than a
	// resolved address: the name is what the operator has to check.
	Endpoint string
	Attempts int
	Elapsed  time.Duration
	// Last is the final transport cause, which wraps nativeudp.ErrNoReply.
	Last error
	// deadline is the caller's context error when the caller's own deadline or
	// cancellation ended the wait, and nil when the SDK's internal budget did.
	deadline error
}

func (e *EndpointNoReplyError) Error() string {
	if e == nil {
		return ErrEndpointNoReply.Error()
	}
	return fmt.Sprintf(
		"qurl: no reply from %s after %d attempt(s) over %s; the host resolved and every datagram was sent, "+
			"but nothing answered. Either the server is not running or the network path drops UDP to it silently "+
			"(a source-fenced security group or egress firewall drops without ICMP, which looks identical from here). "+
			"Verify your source address is permitted to reach %s: %v",
		e.Endpoint, e.Attempts, e.Elapsed, e.Endpoint, e.Last)
}

func (e *EndpointNoReplyError) Unwrap() []error {
	if e == nil {
		return []error{ErrEndpointNoReply}
	}
	unwrapped := []error{ErrEndpointNoReply}
	if e.Last != nil {
		unwrapped = append(unwrapped, e.Last)
	}
	if e.deadline != nil {
		unwrapped = append(unwrapped, e.deadline)
	}
	return unwrapped
}

// AssignmentRecoveryRequiredError carries the final failed attempt without
// losing its typed cause. Callers surface recovery instead of starting an
// unbounded loop. In particular, a Last cause matching
// nativeudp.ErrServerUnauthenticated is operator-actionable trust/bootstrap
// recovery and must not silently start a new logical operation.
type AssignmentRecoveryRequiredError struct {
	Attempts int
	Elapsed  time.Duration
	Last     error
}

func (e *AssignmentRecoveryRequiredError) Error() string {
	if e == nil {
		return ErrAssignmentRecoveryRequired.Error()
	}
	return recoveryBudgetErrorString("assignment", "surface recovery", e.Attempts, e.Elapsed, e.Last)
}

func (e *AssignmentRecoveryRequiredError) Unwrap() []error {
	if e == nil {
		return []error{ErrAssignmentRecoveryRequired}
	}
	return unwrapWithCause(e.Last, ErrAssignmentRecoveryRequired)
}

type assignmentConfig struct {
	maxAttempts int
	budget      time.Duration
	clock       func() time.Time
	sleep       func(context.Context, time.Duration) error
	jitter      func(time.Duration) (time.Duration, error)
	nonceSource func() ([]byte, error)
}

// AssignmentOption customizes one bounded logical Hub operation. Transport
// injection belongs to nativeudp.Options, passed directly to the public call.
type AssignmentOption interface {
	applyAssignmentOption(*assignmentConfig) error
}

type assignmentOptionFunc func(*assignmentConfig) error

func (f assignmentOptionFunc) applyAssignmentOption(c *assignmentConfig) error { return f(c) }

// WithAssignmentRetryBudget bounds one logical Hub assignment operation by
// attempts and elapsed time. Both must be positive.
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

func withAssignmentClock(clock func() time.Time) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if clock == nil {
			return fmt.Errorf("%w: assignment clock must not be nil", ErrInvalidAssignmentConfig)
		}
		c.clock = clock
		return nil
	})
}

func withAssignmentSleep(sleep func(context.Context, time.Duration) error) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if sleep == nil {
			return fmt.Errorf("%w: assignment sleep must not be nil", ErrInvalidAssignmentConfig)
		}
		c.sleep = sleep
		return nil
	})
}

func withAssignmentJitter(jitter func(time.Duration) (time.Duration, error)) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if jitter == nil {
			return fmt.Errorf("%w: assignment jitter must not be nil", ErrInvalidAssignmentConfig)
		}
		c.jitter = jitter
		return nil
	})
}

// withAssignmentNonceSource is test-only dependency injection. The source must
// return a newly owned byte slice because request construction wipes it before
// returning. Production always uses the OS cryptographic random source.
func withAssignmentNonceSource(source func() ([]byte, error)) AssignmentOption {
	return assignmentOptionFunc(func(c *assignmentConfig) error {
		if source == nil {
			return fmt.Errorf("%w: assignment request nonce source must not be nil", ErrInvalidAssignmentConfig)
		}
		c.nonceSource = source
		return nil
	})
}

func newAssignmentConfig(opts []AssignmentOption) (*assignmentConfig, error) {
	c := &assignmentConfig{
		maxAttempts: defaultAssignmentMaxAttempts,
		budget:      defaultAssignmentBudget,
		clock:       time.Now,
		sleep:       sleepAssignmentBackoff,
		jitter:      cryptoAssignmentJitter,
		nonceSource: func() ([]byte, error) { return cryptoutil.RandomBytes(assignmentRequestNonceBytes) },
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

func sleepAssignmentBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// FetchInitialAgentAssignment authenticates an enrollment credential inside an
// NHP_LST sent to the pinned hub. The stable final agentID is devId and
// transport.DeviceStaticPriv is the Noise initiator identity. The returned
// registration metadata and ticket are attempt-scoped until the lifecycle
// durably binds them into PendingAgentActivation immediately before REG.
func FetchInitialAgentAssignment(ctx context.Context, hub HubBootstrap, agentID, enrollmentCredential string, transport nativeudp.Options, opts ...AssignmentOption) (*InitialAgentAssignment, error) {
	return fetchInitialAgentAssignment(ctx, hub, agentID, enrollmentCredential, transport, nil, opts...)
}

func fetchInitialAgentAssignment(ctx context.Context, hub HubBootstrap, agentID, enrollmentCredential string, transport nativeudp.Options, beforeExchange func() error, opts ...AssignmentOption) (*InitialAgentAssignment, error) {
	endpoint, err := validateAssignmentInputs(ctx, hub, agentID, transport)
	if err != nil {
		return nil, err
	}
	if err := validateExactBearerToken(enrollmentCredential, "assignment enrollment credential", ErrInvalidAssignmentConfig); err != nil {
		return nil, err
	}
	cfg, err := newAssignmentConfig(opts)
	if err != nil {
		return nil, err
	}
	requestNonce, err := drawAssignmentRequestNonce(cfg)
	if err != nil {
		return nil, err
	}
	body, err := marshalAssignmentRequest(assignmentListRequest{
		UsrID: "", DevID: agentID, AspID: agentAspID,
		UsrData: assignmentRequestData{
			Query: assignmentQuery, Version: assignmentVersion, Mode: assignmentModeEnroll,
			RequestNonce: requestNonce, Credential: enrollmentCredential,
		},
	})
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)

	return runNativeExchange(ctx, cfg, endpoint, body, transport, beforeExchange, nativeudp.AssignmentList, assignmentRetryInfo, newAssignmentRecovery, func(reply []byte, now time.Time) (*InitialAgentAssignment, error) {
		return parseInitialAssignmentReply(reply, agentID, now)
	})
}

// RefreshAgentAssignment sends only the registered Noise identity and stable
// final agentID to the hub. The body has empty usrId and no enrollment or device
// credential. A successful refresh returns only durable assignment state.
func RefreshAgentAssignment(ctx context.Context, hub HubBootstrap, agentID string, transport nativeudp.Options, opts ...AssignmentOption) (*AgentAssignment, error) {
	return refreshAgentAssignment(ctx, hub, agentID, transport, nil, opts...)
}

func refreshAgentAssignment(ctx context.Context, hub HubBootstrap, agentID string, transport nativeudp.Options, beforeExchange func() error, opts ...AssignmentOption) (*AgentAssignment, error) {
	endpoint, err := validateAssignmentInputs(ctx, hub, agentID, transport)
	if err != nil {
		return nil, err
	}
	cfg, err := newAssignmentConfig(opts)
	if err != nil {
		return nil, err
	}
	requestNonce, err := drawAssignmentRequestNonce(cfg)
	if err != nil {
		return nil, err
	}
	body, err := marshalAssignmentRequest(assignmentListRequest{
		UsrID: "", DevID: agentID, AspID: agentAspID,
		UsrData: assignmentRequestData{Query: assignmentQuery, Version: assignmentVersion, Mode: assignmentModeRefresh, RequestNonce: requestNonce},
	})
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	return runNativeExchange(ctx, cfg, endpoint, body, transport, beforeExchange, nativeudp.AssignmentList, assignmentRetryInfo, newAssignmentRecovery, func(reply []byte, now time.Time) (*AgentAssignment, error) {
		return parseRefreshAssignmentReply(reply, agentID, now)
	})
}

// recoveryFunc builds the phase-specific recovery-required error for a final
// failed attempt. Assignment and completion share one bounded retry loop while
// preserving distinct public recovery error types.
type recoveryFunc func(attempts int, elapsed time.Duration, last error) error

func newAssignmentRecovery(attempts int, elapsed time.Duration, last error) error {
	return &AssignmentRecoveryRequiredError{Attempts: attempts, Elapsed: elapsed, Last: last}
}

type nativeExchangeFunc func(context.Context, nativeudp.Endpoint, []byte, nativeudp.Options) (*relayknock.Reply, error)

// runNativeExchange is the single bounded, jittered retry driver for
// authenticated NHP assignment, registration, and pending-credential
// completion transactions. exchange fixes the NHP request/reply type for the
// phase; retryInfo classifies retryable failures and newRecovery preserves the
// phase's public recovery error type.
func runNativeExchange[T any](ctx context.Context, c *assignmentConfig, endpoint nativeudp.Endpoint, body []byte, transport nativeudp.Options, beforeExchange func() error, exchange nativeExchangeFunc, retryInfo func(error) (time.Duration, bool), newRecovery recoveryFunc, parse func([]byte, time.Time) (*T, error)) (*T, error) {
	start := c.clock()
	transactionCtx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	// Reporting a silent endpoint takes two things: at least one attempt that
	// completed a full send-and-wait with nothing back (lastSilent), and no
	// attempt that contradicted it (silence). A dial fault, an authenticated
	// reply, or a rejected datagram all clear silence, because then the endpoint
	// is demonstrably not just swallowing traffic and the ordinary recovery error
	// is the honest report.
	silence := true
	var lastSilent error
	observedSilence := func() bool { return silence && lastSilent != nil }
	for attempt := 1; ; attempt++ {
		if beforeExchange != nil {
			if err := beforeExchange(); err != nil {
				return nil, err
			}
		}
		reply, err := exchange(transactionCtx, endpoint, body, transport)
		replyAuthenticated := err == nil
		if replyAuthenticated {
			result, parseErr := parse(reply.Body, c.clock())
			wipeBytes(reply.Body)
			if parseErr == nil {
				return result, nil
			}
			err = parseErr
		}
		switch {
		case errors.Is(err, nativeudp.ErrNoReply):
			lastSilent = err
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// A deadline firing mid-attempt is the absence of evidence, not
			// evidence the endpoint would have answered. It must not clear a
			// silence observation that earlier completed attempts established.
		default:
			silence = false
		}
		retryAfter, retryable := retryInfo(err)
		if replyAuthenticated && !retryable {
			// A parsed authenticated terminal result wins over a retry-budget
			// deadline that fires concurrently. In particular, identity rejection
			// must remain terminal rather than being recast as recovery permission.
			return nil, err
		}
		// An unauthenticated datagram is not an authenticated terminal policy
		// result. If the whole transaction deadline fired concurrently, bounded
		// recovery wins; a later whole exchange uses fresh randomness and never
		// accepts or falls through from this rejected datagram.
		if transactionCtx.Err() != nil {
			if ctx.Err() != nil {
				// The caller's own deadline or cancellation ended the wait. Returning
				// a bare ctx.Err() here discarded the destination, the attempt count,
				// and the transport cause, so a caller whose deadline matched the
				// internal budget saw only "context deadline exceeded". Keep the
				// context error in the chain and name what stayed silent.
				if observedSilence() {
					return nil, c.noReply(endpoint, attempt, start, lastSilent, ctx.Err())
				}
				return nil, ctx.Err()
			}
			return nil, c.recoveryRequired(newRecovery, attempt, start, c.withSilence(endpoint, attempt, start, observedSilence(), errors.Join(err, transactionCtx.Err())))
		}
		if !retryable {
			return nil, err
		}
		elapsed := c.elapsedSince(start)
		// Preserve observed elapsed time for ordinary attempt exhaustion; a fixed
		// test clock can therefore report zero. recoveryRequired clamps separately
		// only when the real transaction deadline proves the budget was exhausted.
		if attempt == c.maxAttempts || elapsed >= c.budget {
			return nil, newRecovery(attempt, elapsed, c.withSilence(endpoint, attempt, start, observedSilence(), err))
		}
		delay, backoffErr := c.backoff(attempt, retryAfter)
		if backoffErr != nil {
			return nil, newRecovery(attempt, elapsed, errors.Join(err, backoffErr))
		}
		if delay > c.budget-elapsed {
			return nil, newRecovery(attempt, elapsed, c.withSilence(endpoint, attempt, start, observedSilence(), err))
		}
		if sleepErr := c.sleep(transactionCtx, delay); sleepErr != nil {
			if ctx.Err() != nil {
				if observedSilence() {
					return nil, c.noReply(endpoint, attempt, start, lastSilent, ctx.Err())
				}
				return nil, ctx.Err()
			}
			if transactionCtx.Err() != nil {
				return nil, c.recoveryRequired(newRecovery, attempt, start, c.withSilence(endpoint, attempt, start, observedSilence(), errors.Join(err, transactionCtx.Err())))
			}
			return nil, sleepErr
		}
	}
}

// noReply builds the typed silent-endpoint error for an exchange in which every
// attempt was written successfully and none were answered.
func (c *assignmentConfig) noReply(endpoint nativeudp.Endpoint, attempts int, start time.Time, last, deadline error) error {
	return &EndpointNoReplyError{
		Endpoint: net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)),
		Attempts: attempts,
		Elapsed:  c.elapsedSince(start),
		Last:     last,
		deadline: deadline,
	}
}

// withSilence enriches a budget-exhaustion cause when the whole exchange was
// silence. The phase's public recovery type still wraps it, so the existing
// recovery taxonomy is unchanged and callers additionally gain
// ErrEndpointNoReply and the destination that stayed quiet.
func (c *assignmentConfig) withSilence(endpoint nativeudp.Endpoint, attempts int, start time.Time, silence bool, cause error) error {
	if !silence {
		return cause
	}
	return c.noReply(endpoint, attempts, start, cause, nil)
}

func (c *assignmentConfig) recoveryRequired(newRecovery recoveryFunc, attempts int, start time.Time, last error) error {
	elapsed := c.elapsedSince(start)
	if elapsed < c.budget {
		// The real transaction timer may expire while a test clock is fixed or
		// moves backward. Report the budget that was actually exhausted.
		elapsed = c.budget
	}
	return newRecovery(attempts, elapsed, last)
}

func (c *assignmentConfig) elapsedSince(start time.Time) time.Duration {
	elapsed := c.clock().Sub(start)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func assignmentRetryInfo(err error) (time.Duration, bool) {
	if nativeTransportRetryable(err) {
		return 0, true
	}
	var appErr *AssignmentError
	if errors.As(err, &appErr) && (errors.Is(appErr, ErrAssignmentUnavailable) ||
		errors.Is(appErr, ErrAssignmentRateLimited) ||
		// 52202 says a move is in flight right now, which is transient by
		// definition: the same request a moment later gets the new placement.
		// Surfacing it made every caller hand-write a retry for a condition the
		// Hub had already described as temporary. Its wire grammar still forbids
		// retryAfterSeconds, so this waits on the shared jittered backoff inside
		// the same bounded operation and still surfaces recovery if the budget
		// runs out.
		errors.Is(appErr, ErrAssignmentReassignmentRequired)) {
		return appErr.RetryAfter, true
	}
	return 0, false
}

func nativeTransportRetryable(err error) bool {
	return errors.Is(err, nativeudp.ErrTransport) || errors.Is(err, nativeudp.ErrResolve)
}

func (c *assignmentConfig) backoff(attempt int, retryAfter time.Duration) (time.Duration, error) {
	shift := attempt - 1
	window := defaultAssignmentMaxBackoff
	if shift < 63 && defaultAssignmentMinBackoff <= defaultAssignmentMaxBackoff>>shift {
		window = defaultAssignmentMinBackoff << shift
	}
	jittered, err := c.jitter(window)
	if err != nil {
		return 0, fmt.Errorf("draw assignment retry jitter: %w", err)
	}
	if jittered < 0 || jittered >= window {
		return 0, errors.New("assignment retry jitter must be in [0, window)")
	}
	// Authenticated RetryAfter is a lower bound, not a value to clamp. If it
	// exceeds the remaining operation budget, the caller surfaces recovery
	// rather than sleeping past that budget.
	return max(retryAfter, jittered), nil
}

func cryptoAssignmentJitter(window time.Duration) (time.Duration, error) {
	random, err := cryptoutil.RandomInt64n(int64(window))
	if err != nil {
		return 0, err
	}
	return time.Duration(random), nil
}

func validateAssignmentInputs(ctx context.Context, hub HubBootstrap, agentID string, transport nativeudp.Options) (nativeudp.Endpoint, error) {
	if err := validateContext(ctx, ErrInvalidAssignmentConfig); err != nil {
		return nativeudp.Endpoint{}, err
	}
	if err := validateAssignmentAgentID(agentID); err != nil {
		return nativeudp.Endpoint{}, err
	}
	if len(transport.DeviceStaticPriv) != x25519key.Size {
		return nativeudp.Endpoint{}, fmt.Errorf("%w: assignment initiator private key must be %d bytes", ErrInvalidAssignmentConfig, x25519key.Size)
	}
	return hub.nativeEndpoint()
}

func (h HubBootstrap) nativeEndpoint() (nativeudp.Endpoint, error) {
	if err := validateAssignmentEndpointHost(h.Host, "hub host", ErrInvalidAssignmentConfig); err != nil {
		return nativeudp.Endpoint{}, err
	}
	if h.Port != standardNHPUDPPort {
		return nativeudp.Endpoint{}, fmt.Errorf("%w: unsupported hub UDP port %d (want %d)", ErrInvalidAssignmentConfig, h.Port, standardNHPUDPPort)
	}
	key, err := x25519key.DecodeCanonicalBase64(h.ServerPublicKeyB64)
	if err != nil {
		return nativeudp.Endpoint{}, fmt.Errorf("%w: invalid hub server public key: %w", ErrInvalidAssignmentConfig, err)
	}
	return nativeudp.Endpoint{Host: h.Host, Port: h.Port, ServerStaticPub: key}, nil
}

type assignmentListRequest struct {
	UsrID   string                `json:"usrId"`
	DevID   string                `json:"devId"`
	AspID   string                `json:"aspId"`
	UsrData assignmentRequestData `json:"usrData"`
}

type assignmentRequestData struct {
	Query        string `json:"query"`
	Version      int    `json:"version"`
	Mode         string `json:"mode"`
	RequestNonce string `json:"request_nonce"`
	Credential   string `json:"credential,omitempty"`
}

func drawAssignmentRequestNonce(c *assignmentConfig) (string, error) {
	nonce, err := c.nonceSource()
	defer wipeBytes(nonce)
	if err != nil {
		return "", fmt.Errorf("qurl: generate assignment request nonce: %w", err)
	}
	if len(nonce) != assignmentRequestNonceBytes {
		return "", fmt.Errorf("%w: assignment request nonce source returned %d bytes (want %d)", ErrInvalidAssignmentConfig, len(nonce), assignmentRequestNonceBytes)
	}
	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

func marshalAssignmentRequest(request assignmentListRequest) ([]byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode assignment request: %w", ErrInvalidAssignmentConfig, err)
	}
	if len(body) > nhpcontract.MaxApplicationBodySize {
		size := len(body)
		wipeBytes(body)
		return nil, fmt.Errorf("%w: encoded assignment request of %d bytes exceeds the %d-byte NHP maximum", ErrInvalidAssignmentConfig, size, nhpcontract.MaxApplicationBodySize)
	}
	return body, nil
}

type assignmentEnvelope struct {
	ErrCode           string          `json:"errCode"`
	ErrMsg            string          `json:"errMsg,omitempty"`
	RetryAfterSeconds *int64          `json:"retryAfterSeconds,omitempty"`
	List              json.RawMessage `json:"list,omitempty"`
}

type assignmentListHeader struct {
	Query   string `json:"query"`
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	AgentID string `json:"agent_id"`
}

type initialAssignmentList struct {
	assignmentListHeader
	Registration              json.RawMessage `json:"registration"`
	Assignment                json.RawMessage `json:"assignment"`
	AssignmentTicket          string          `json:"assignment_ticket"`
	AssignmentTicketExpiresAt string          `json:"assignment_ticket_expires_at"`
}

type refreshAssignmentList struct {
	assignmentListHeader
	Assignment json.RawMessage `json:"assignment"`
}

type assignmentWire struct {
	CellID               string          `json:"cell_id"`
	AssignmentGeneration int64           `json:"assignment_generation"`
	EndpointRevision     int64           `json:"endpoint_revision"`
	LeaseExpiresAt       string          `json:"lease_expires_at"`
	Endpoint             json.RawMessage `json:"nhp_udp_endpoint"`
}

func parseInitialAssignmentReply(body []byte, wantAgentID string, now time.Time) (*InitialAgentAssignment, error) {
	list, err := parseAssignmentEnvelope(body, true)
	if err != nil {
		return nil, err
	}
	var wire initialAssignmentList
	if err := decodeExactObject(list, &wire,
		[]string{"query", "version", "mode", "agent_id", "registration", "assignment", "assignment_ticket", "assignment_ticket_expires_at"}); err != nil {
		return nil, invalidAssignmentResponse("initial assignment list", err)
	}
	if err := validateAssignmentListHeader("initial assignment list", wire.assignmentListHeader, assignmentModeEnroll, wantAgentID); err != nil {
		return nil, err
	}

	var registration AssignmentRegistration
	if err := decodeExactObject(wire.Registration, &registration, []string{"key_id", "key_kind"}); err != nil {
		return nil, invalidAssignmentResponse("initial registration metadata", err)
	}
	if !validAPIKeyID(registration.KeyID) {
		return nil, invalidAssignmentResponse("initial registration metadata", errors.New("key_id is not canonical"))
	}
	if !validPublicRegistrationKeyKind(registration.KeyKind) {
		return nil, invalidAssignmentResponse("initial registration metadata", fmt.Errorf("unsupported key_kind %q", registration.KeyKind))
	}

	assignment, err := parseWireAssignment(wire.Assignment, now)
	if err != nil {
		return nil, err
	}
	if err := validateOpaqueAssignmentTicket(wire.AssignmentTicket); err != nil {
		return nil, invalidAssignmentResponse("initial assignment ticket", err)
	}
	ticketExpiry, err := parseCanonicalRFC3339(wire.AssignmentTicketExpiresAt)
	if err != nil {
		return nil, invalidAssignmentResponse("assignment_ticket_expires_at", err)
	}
	if !ticketExpiry.After(now) {
		return nil, invalidAssignmentResponse("assignment_ticket_expires_at", errors.New("ticket is not in the future"))
	}
	if ticketExpiry.Sub(now) > maxAssignmentTicketLifetime {
		return nil, invalidAssignmentResponse("assignment_ticket_expires_at", errors.New("ticket exceeds the conformance maximum lifetime"))
	}
	if !assignment.LeaseExpiresAt.After(ticketExpiry) {
		return nil, invalidAssignmentResponse("initial assignment deadlines", errors.New("ticket must expire before lease"))
	}
	return &InitialAgentAssignment{
		Registration:              registration,
		Assignment:                *assignment,
		AssignmentTicket:          wire.AssignmentTicket,
		AssignmentTicketExpiresAt: ticketExpiry,
	}, nil
}

func parseRefreshAssignmentReply(body []byte, wantAgentID string, now time.Time) (*AgentAssignment, error) {
	list, err := parseAssignmentEnvelope(body, false)
	if err != nil {
		return nil, err
	}
	var wire refreshAssignmentList
	if err := decodeExactObject(list, &wire, []string{"query", "version", "mode", "agent_id", "assignment"}); err != nil {
		return nil, invalidAssignmentResponse("refresh assignment list", err)
	}
	if err := validateAssignmentListHeader("refresh assignment list", wire.assignmentListHeader, assignmentModeRefresh, wantAgentID); err != nil {
		return nil, err
	}
	return parseWireAssignment(wire.Assignment, now)
}

func validateAssignmentListHeader(part string, header assignmentListHeader, wantMode, wantAgentID string) error {
	if header.Query != assignmentQuery || header.Version != assignmentVersion || header.Mode != wantMode {
		return invalidAssignmentResponse(part, errors.New("query/version/mode mismatch"))
	}
	if header.AgentID != wantAgentID {
		return invalidAssignmentResponse(part, fmt.Errorf("agent_id %q does not match %q", header.AgentID, wantAgentID))
	}
	return nil
}

func parseAssignmentEnvelope(body []byte, initial bool) (json.RawMessage, error) {
	fields, err := exactObjectFields(body)
	if err != nil {
		return nil, invalidAssignmentResponse("LRT envelope", err)
	}
	if _, ok := fields["errCode"]; !ok {
		return nil, invalidAssignmentResponse("LRT envelope", errors.New("missing errCode"))
	}
	var envelope assignmentEnvelope
	if err := strictDecodeJSON(body, &envelope); err != nil {
		return nil, invalidAssignmentResponse("LRT envelope", err)
	}
	if envelope.ErrCode == "0" {
		if _, ok := fields["list"]; len(fields) != 2 || !ok {
			return nil, invalidAssignmentResponse("success LRT envelope", errors.New("must contain exactly errCode and list"))
		}
		if isJSONNull(envelope.List) {
			return nil, invalidAssignmentResponse("success LRT envelope", errors.New("list must be an object"))
		}
		return envelope.List, nil
	}
	if _, present := fields["list"]; present {
		return nil, invalidAssignmentResponse("error LRT envelope", errors.New("list is forbidden on error"))
	}
	return nil, classifyAssignmentApplicationError(envelope, fields, initial)
}

func classifyAssignmentApplicationError(envelope assignmentEnvelope, fields map[string]json.RawMessage, initial bool) error {
	if rawMessage, present := fields["errMsg"]; present && isJSONNull(rawMessage) {
		return invalidAssignmentResponse("error LRT envelope", errors.New("errMsg must be a string when present"))
	}
	var kind error
	// These flags describe the authenticated error body's retryAfterSeconds wire
	// grammar. Transaction retry policy is decided separately by assignmentRetryInfo.
	retryPermitted := false
	retryRequired := false
	switch envelope.ErrCode {
	case "52200":
		kind, retryPermitted = ErrAssignmentUnavailable, true
	case "52201":
		kind = ErrAssignmentIdentityRejected
	case "52202":
		kind = ErrAssignmentReassignmentRequired
	case "52203":
		kind = ErrAssignmentQuotaExceeded
	case "52204":
		kind, retryPermitted, retryRequired = ErrAssignmentRateLimited, true, true
	case "52205":
		kind = ErrAssignmentRequestRejected
	case "52106":
		if initial {
			kind = ErrAssignmentKeyRejected
		}
	case "52107":
		if initial {
			kind = ErrAssignmentRegistrationDisabled
		}
	case "52108":
		if initial {
			kind = ErrAssignmentBootstrapConsumed
		}
	case "52109":
		if initial {
			kind = ErrAssignmentRequestRejected
		}
	}
	if kind == nil {
		return invalidAssignmentResponse("error LRT envelope", errors.New("unknown or phase-invalid errCode"))
	}

	retryAfter, err := parseEnvelopeRetryAfter(envelope, fields, retryPermitted, retryRequired)
	if err != nil {
		return invalidAssignmentResponse("error LRT envelope", err)
	}
	return &AssignmentError{Code: envelope.ErrCode, RetryAfter: retryAfter, kind: kind}
}

// parseEnvelopeRetryAfter validates the authenticated LRT error body's
// retryAfterSeconds wire grammar shared by every phase-specific classifier and
// returns the bounded retry delay. retryPermitted/retryRequired describe the
// code-specific grammar; the returned error is a plain reason the caller wraps
// in its own phase-specific class. This is the single overflow guard for the
// seconds-to-Duration conversion so the load-bearing bound cannot drift between
// the assignment and completion classifiers.
func parseEnvelopeRetryAfter(envelope assignmentEnvelope, fields map[string]json.RawMessage, retryPermitted, retryRequired bool) (time.Duration, error) {
	_, retryPresent := fields["retryAfterSeconds"]
	if retryRequired && !retryPresent {
		return 0, errors.New("retryAfterSeconds is required")
	}
	if retryPresent && !retryPermitted {
		return 0, errors.New("retryAfterSeconds is forbidden for this code")
	}
	if !retryPresent {
		return 0, nil
	}
	if envelope.RetryAfterSeconds == nil || *envelope.RetryAfterSeconds <= 0 || *envelope.RetryAfterSeconds > math.MaxInt64/int64(time.Second) {
		return 0, errors.New("retryAfterSeconds must be a positive bounded integer")
	}
	return time.Duration(*envelope.RetryAfterSeconds) * time.Second, nil
}

func parseWireAssignment(raw []byte, now time.Time) (*AgentAssignment, error) {
	assignment, err := parsePersistedWireAssignment(raw)
	if err != nil {
		return nil, err
	}
	// parsePersistedWireAssignment already validated the complete structural
	// trust boundary; only liveness remains for an authenticated wire result.
	if !assignment.LeaseExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: assignment lease must be in the future: %w", ErrAssignmentInvalidResponse, ErrAssignmentLeaseExpired)
	}
	return assignment, nil
}

// parsePersistedWireAssignment validates the complete authenticated wire shape
// without requiring a live lease. Credential recovery uses this only to learn
// and durably close an already-expired replay episode; its caller must not use
// the returned endpoint for network I/O.
func parsePersistedWireAssignment(raw []byte) (*AgentAssignment, error) {
	var wire assignmentWire
	if err := decodeExactObject(raw, &wire,
		[]string{"cell_id", "assignment_generation", "endpoint_revision", "lease_expires_at", "nhp_udp_endpoint"}); err != nil {
		return nil, invalidAssignmentResponse("assignment", err)
	}
	var endpoint NHPUDPEndpoint
	if err := decodeExactObject(wire.Endpoint, &endpoint, []string{"host", "port", "server_public_key_b64"}); err != nil {
		return nil, invalidAssignmentResponse("assignment endpoint", err)
	}
	lease, err := parseCanonicalRFC3339(wire.LeaseExpiresAt)
	if err != nil {
		return nil, invalidAssignmentResponse("lease_expires_at", err)
	}
	assignment := &AgentAssignment{
		CellID: wire.CellID, AssignmentGeneration: wire.AssignmentGeneration,
		EndpointRevision: wire.EndpointRevision, LeaseExpiresAt: lease, Endpoint: endpoint,
	}
	if err := validatePersistedAgentAssignment(assignment); err != nil {
		return nil, err
	}
	return assignment, nil
}

func validatePersistedAgentAssignment(a *AgentAssignment) error {
	if a == nil || !validAssignmentCellID(a.CellID) {
		return invalidAssignmentResponse("assignment", errors.New("invalid cell_id"))
	}
	if a.AssignmentGeneration < 1 || a.EndpointRevision < 1 {
		return invalidAssignmentResponse("assignment", errors.New("generation and endpoint revision must be positive"))
	}
	if a.LeaseExpiresAt.IsZero() {
		return invalidAssignmentResponse("assignment", errors.New("lease must be nonzero"))
	}
	if err := validateAssignmentEndpointHost(a.Endpoint.Host, "assignment endpoint", ErrAssignmentInvalidResponse); err != nil {
		return err
	}
	// Pinned, not range-checked: an assigned cell the agent cannot reach through
	// its egress filter is worse than a rejected assignment, and the Hub response
	// that carries this endpoint is exactly the input an operator misconfiguration
	// would arrive through.
	if a.Endpoint.Port != standardNHPUDPPort {
		return invalidAssignmentResponse("assignment endpoint", fmt.Errorf("unsupported UDP port %d (want %d)", a.Endpoint.Port, standardNHPUDPPort))
	}
	if _, err := decodeAssignmentServerPublicKey(a.Endpoint.ServerPublicKeyB64); err != nil {
		return err
	}
	return nil
}

func validateAssignmentAgentID(agentID string) error {
	if len(agentID) < 2 || len(agentID) > 64 {
		return fmt.Errorf("%w: agent id must be 2-64 characters", ErrInvalidAssignmentConfig)
	}
	for i, b := range []byte(agentID) {
		alphaNumeric := isASCIILowerAlnum(b)
		if i == 0 || i == len(agentID)-1 {
			if !alphaNumeric {
				return fmt.Errorf("%w: agent id must start and end with a lowercase letter or digit", ErrInvalidAssignmentConfig)
			}
			continue
		}
		if !alphaNumeric && b != '-' {
			return fmt.Errorf("%w: agent id may contain only lowercase letters, digits, and hyphens", ErrInvalidAssignmentConfig)
		}
	}
	return nil
}

func validateAssignmentEndpointHost(host, part string, errKind error) error {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return fmt.Errorf("%w: %s: host must be a canonical lowercase DNS name", errKind, part)
	}
	for label := range strings.SplitSeq(host, ".") {
		if !validAssignmentDNSLabel(label) {
			return fmt.Errorf("%w: %s: host must be a canonical lowercase DNS name", errKind, part)
		}
	}
	if !strings.HasSuffix(host, assignmentEndpointSuffixAI) && !strings.HasSuffix(host, assignmentEndpointSuffixXYZ) {
		return fmt.Errorf("%w: %s: host must be below a LayerV-owned DNS apex", errKind, part)
	}
	return nil
}

func validAssignmentDNSLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, b := range []byte(label) {
		if !isASCIILowerLDH(b) {
			return false
		}
	}
	return true
}

func validAssignmentCellID(cellID string) bool {
	if len(cellID) < 1 || len(cellID) > 64 || cellID[0] < 'a' || cellID[0] > 'z' {
		return false
	}
	for _, b := range []byte(cellID[1:]) {
		if !isASCIILowerLDH(b) {
			return false
		}
	}
	return cellID[len(cellID)-1] != '-'
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func isASCIILowerAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func isASCIILowerLDH(b byte) bool {
	return isASCIILowerAlnum(b) || b == '-'
}

func validPublicRegistrationKeyKind(kind string) bool {
	switch kind {
	case keyKindBootstrap, assignmentKeyKindConnectorBootstrap, keyKindAccount, assignmentKeyKindAgent:
		return true
	default:
		return false
	}
}

func validateOpaqueAssignmentTicket(ticket string) error {
	if ticket == "" || len(ticket) > maxAssignmentTicketBytes {
		return errors.New("ticket must be non-empty printable ASCII within the size bound")
	}
	for i := range len(ticket) {
		if ticket[i] < 0x21 || ticket[i] > 0x7e {
			return errors.New("ticket must contain only printable ASCII bytes")
		}
	}
	return nil
}

func parseCanonicalRFC3339(value string) (time.Time, error) {
	// qurl-conformance v0.3.0 freezes hub response timestamps as UTC with a
	// trailing Z and no fractional seconds; alternate RFC3339 spellings are not
	// part of the producer contract.
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("must be RFC3339: %w", err)
	}
	// Require the UTC location identity as well as the spelling round trip:
	// numeric +00:00 denotes the same instant but is not the producer's Z form.
	if parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must use canonical UTC RFC3339 spelling")
	}
	return parsed, nil
}

func decodeAssignmentServerPublicKey(encoded string) ([]byte, error) {
	key, err := x25519key.DecodeCanonicalBase64(encoded)
	if err != nil {
		return nil, invalidAssignmentResponse("assignment endpoint", fmt.Errorf("server public key must be canonical padded standard-base64 X25519: %w", err))
	}
	return key, nil
}

func invalidAssignmentResponse(part string, _ error) error {
	// The cause may contain an authenticated producer's reflected enrollment
	// credential in a value or even a JSON field name. Keep the stable class and
	// code-owned phase, never the raw parser text.
	return fmt.Errorf("%w: invalid %s", ErrAssignmentInvalidResponse, part)
}

func decodeExactObject(raw []byte, dst any, required []string) error {
	// These intentionally separate passes enforce distinct invariants: the token
	// walk rejects duplicates, the map checks presence, and the typed decode pins
	// each phase's exact allowlist and value types.
	fields, err := exactObjectFields(raw)
	if err != nil {
		return err
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing required field %q", field)
		}
	}
	return strictDecodeJSON(raw, dst)
}

// exactObjectFields rejects duplicate keys at every nesting level before
// encoding/json can collapse them. It then returns the top-level raw fields so
// callers can enforce phase-dependent presence rules; the final typed decode
// enforces each object's exact allowlist and value types.
func exactObjectFields(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("top-level value must be an object")
	}
	if err := walkJSONObject(decoder, 1); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("top-level value must be an object")
	}
	return fields, nil
}

func walkJSONObject(decoder *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if err := walkJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '}' {
		return errors.New("unterminated JSON object")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, parentDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	depth := parentDepth + 1
	if depth > maxAssignmentJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxAssignmentJSONDepth)
	}
	switch delim {
	case '{':
		return walkJSONObject(decoder, depth)
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closeDelim, ok := closing.(json.Delim); !ok || closeDelim != ']' {
			return errors.New("unterminated JSON array")
		}
		return nil
	default:
		return errors.New("unexpected closing JSON delimiter")
	}
}
