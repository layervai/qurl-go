package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// ErrAssignmentEndpointRefreshRequired means initial enrollment completed but
// the control plane rotated the endpoint before the freshly minted device key
// became visible. The completed credential and original live binding are
// durable; run RefreshAgentRegistration to authenticate and adopt the new
// endpoint. Completion must not be retried.
var ErrAssignmentEndpointRefreshRequired = errors.New("qurl: assignment endpoint refresh required")

// ErrAgentRuntimeReopenRequired means initial enrollment completed and durably
// saved the device credential, but the immediate post-mint assignment
// confirmation failed. The wrapped error remains matchable for diagnostics.
// Reopen the durable state, then handle the wrapped assignment outcome; never
// repeat completion or clear the state in response to this error.
var ErrAgentRuntimeReopenRequired = errors.New("qurl: registered agent runtime must be reopened")

// AgentAssignmentChangedError reports a control-plane generation/cell change
// that ordinary refresh cannot adopt. It unwraps to
// ErrAssignmentReassignmentRequired. The explicit move workflow must update all
// dependent state before a later SDK operation adopts the new generation.
type AgentAssignmentChangedError struct {
	PersistedCellID     string
	PersistedGeneration int64
	CurrentCellID       string
	CurrentGeneration   int64
}

func (e *AgentAssignmentChangedError) Error() string {
	return fmt.Sprintf("qurl: assignment changed from cell %q generation %d to cell %q generation %d; complete the explicit reassignment workflow before retrying",
		e.PersistedCellID, e.PersistedGeneration, e.CurrentCellID, e.CurrentGeneration)
}

func (e *AgentAssignmentChangedError) Unwrap() error { return ErrAssignmentReassignmentRequired }

// AgentRuntimeOption configures ordinary registered-agent assignment refresh.
// The unexported method keeps the option vocabulary closed so enrollment-only
// options (OTP, takeover, registration origin) cannot accidentally enter the
// steady-state path.
type AgentRuntimeOption interface {
	applyAgentRuntimeOption(*agentRuntimeConfig) error
}

// AgentRuntimeRegistrationOption is accepted by both RegisterAgentRuntime and
// RefreshAgentRegistration. It covers only the shared resource/assignment
// origin and native UDP transport; enrollment-only options remain RegisterOption.
type AgentRuntimeRegistrationOption interface {
	RegisterOption
	AgentRuntimeOption
}

// AgentRuntimeUDPOption is the subset of runtime registration options that
// configures a single native UDP exchange. The closed marker prevents
// assignment-retry options from being silently accepted by KnockRegisteredAgent,
// which performs no control-plane retry.
type AgentRuntimeUDPOption interface {
	AgentRuntimeRegistrationOption
	applyAgentRuntimeUDPOption()
}

type agentRuntimeConfig struct {
	baseURL      string
	httpClient   HTTPDoer
	maxAttempts  int
	budget       time.Duration
	resolver     nativeudp.Resolver
	dialer       nativeudp.Dialer
	timeout      time.Duration
	maxAddresses int
	clock        func() time.Time
	sleep        func(context.Context, time.Duration) error
	jitter       func() (float64, error)
}

func defaultAgentRuntimeConfig() agentRuntimeConfig {
	// Resolver, dialer, timeout, and maxAddresses intentionally remain zero:
	// agentRuntimeConfig.udpOptions forwards them to nativeudp.Options, whose
	// documented zero values select the production resolver/dialer and bounded
	// transport defaults. Runtime options override only the fields a caller sets.
	return agentRuntimeConfig{
		baseURL:     defaultAPIBaseURL,
		httpClient:  defaultAPIHTTPClient,
		maxAttempts: defaultAssignmentMaxAttempts,
		budget:      defaultAssignmentBudget,
		clock:       time.Now,
		sleep:       sleepWithContext,
		jitter:      cryptoJitterFraction,
	}
}

func newAgentRuntimeConfig(opts []AgentRuntimeOption) (*agentRuntimeConfig, error) {
	cfg := defaultAgentRuntimeConfig()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil AgentRuntimeOption", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(&cfg); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

func (c *agentRuntimeConfig) assignmentOptions() []AssignmentOption {
	return []AssignmentOption{
		WithAssignmentBaseURL(c.baseURL),
		WithAssignmentHTTPClient(c.httpClient),
		WithAssignmentRetryBudget(c.maxAttempts, c.budget),
		withAssignmentClock(c.clock),
		withAssignmentSleep(c.sleep),
		withAssignmentJitterSource(c.jitter),
	}
}

func (c *agentRuntimeConfig) udpOptions(privateKey []byte) nativeudp.Options {
	return nativeudp.Options{
		DeviceStaticPriv: privateKey,
		Resolver:         c.resolver,
		Dialer:           c.dialer,
		Timeout:          c.timeout,
		MaxAddresses:     c.maxAddresses,
	}
}

type agentRuntimeAssignmentBudgetOption struct {
	maxAttempts int
	budget      time.Duration
}

// WithAgentRuntimeAssignmentRetryBudget sets the bounded 503 retry budget for
// both initial runtime assignment and ordinary refresh.
func WithAgentRuntimeAssignmentRetryBudget(maxAttempts int, budget time.Duration) AgentRuntimeRegistrationOption {
	return agentRuntimeAssignmentBudgetOption{maxAttempts: maxAttempts, budget: budget}
}

func (o agentRuntimeAssignmentBudgetOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error {
	if o.maxAttempts < 1 || o.budget <= 0 {
		return fmt.Errorf("%w: assignment retry attempts and budget must be positive", ErrInvalidRegisterConfig)
	}
	c.maxAttempts = o.maxAttempts
	c.budget = o.budget
	return nil
}

func (o agentRuntimeAssignmentBudgetOption) applyRegisterOption(c *registerConfig) error {
	return o.applyAgentRuntimeOption(&c.runtime)
}

type agentRuntimeResolverOption struct{ resolver nativeudp.Resolver }

// WithAgentRuntimeUDPResolver injects native assignment DNS resolution.
func WithAgentRuntimeUDPResolver(resolver nativeudp.Resolver) AgentRuntimeUDPOption {
	return agentRuntimeResolverOption{resolver: resolver}
}

func (agentRuntimeResolverOption) applyAgentRuntimeUDPOption() {}

func (o agentRuntimeResolverOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error {
	if o.resolver == nil {
		return fmt.Errorf("%w: native UDP resolver must not be nil", ErrInvalidRegisterConfig)
	}
	c.resolver = o.resolver
	return nil
}

func (o agentRuntimeResolverOption) applyRegisterOption(c *registerConfig) error {
	return o.applyAgentRuntimeOption(&c.runtime)
}

type agentRuntimeDialerOption struct{ dialer nativeudp.Dialer }

// WithAgentRuntimeUDPDialer injects the native UDP socket dialer.
func WithAgentRuntimeUDPDialer(dialer nativeudp.Dialer) AgentRuntimeUDPOption {
	return agentRuntimeDialerOption{dialer: dialer}
}

func (agentRuntimeDialerOption) applyAgentRuntimeUDPOption() {}

func (o agentRuntimeDialerOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error {
	if o.dialer == nil {
		return fmt.Errorf("%w: native UDP dialer must not be nil", ErrInvalidRegisterConfig)
	}
	c.dialer = o.dialer
	return nil
}

func (o agentRuntimeDialerOption) applyRegisterOption(c *registerConfig) error {
	return o.applyAgentRuntimeOption(&c.runtime)
}

type agentRuntimeUDPBoundsOption struct {
	timeout      time.Duration
	maxAddresses int
}

// WithAgentRuntimeUDPBounds sets the per-address socket deadline and DNS address
// fan-out cap. Both must be positive.
func WithAgentRuntimeUDPBounds(timeout time.Duration, maxAddresses int) AgentRuntimeUDPOption {
	return agentRuntimeUDPBoundsOption{timeout: timeout, maxAddresses: maxAddresses}
}

func (agentRuntimeUDPBoundsOption) applyAgentRuntimeUDPOption() {}

func (o agentRuntimeUDPBoundsOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error {
	if o.timeout <= 0 || o.maxAddresses < 1 {
		return fmt.Errorf("%w: native UDP timeout and max addresses must be positive", ErrInvalidRegisterConfig)
	}
	c.timeout = o.timeout
	c.maxAddresses = o.maxAddresses
	return nil
}

func (o agentRuntimeUDPBoundsOption) applyRegisterOption(c *registerConfig) error {
	return o.applyAgentRuntimeOption(&c.runtime)
}

type agentRuntimeTestOption func(*agentRuntimeConfig) error

func (o agentRuntimeTestOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error { return o(c) }
func (o agentRuntimeTestOption) applyRegisterOption(c *registerConfig) error {
	return o(&c.runtime)
}

type agentRuntimeClockOption struct{ clock func() time.Time }

func (o agentRuntimeClockOption) applyAgentRuntimeUDPOption() {}

func (o agentRuntimeClockOption) applyAgentRuntimeOption(c *agentRuntimeConfig) error {
	if o.clock == nil {
		return fmt.Errorf("%w: runtime clock must not be nil", ErrInvalidRegisterConfig)
	}
	c.clock = o.clock
	return nil
}

func (o agentRuntimeClockOption) applyRegisterOption(c *registerConfig) error {
	return o.applyAgentRuntimeOption(&c.runtime)
}

func withAgentRuntimeClock(clock func() time.Time) AgentRuntimeUDPOption {
	return agentRuntimeClockOption{clock: clock}
}

func withAgentRuntimeSleep(sleep func(context.Context, time.Duration) error) AgentRuntimeRegistrationOption {
	return agentRuntimeTestOption(func(c *agentRuntimeConfig) error {
		if sleep == nil {
			return fmt.Errorf("%w: runtime sleep must not be nil", ErrInvalidRegisterConfig)
		}
		c.sleep = sleep
		return nil
	})
}

func withAgentRuntimeJitter(jitter func() float64) AgentRuntimeRegistrationOption {
	if jitter == nil {
		return agentRuntimeTestOption(func(*agentRuntimeConfig) error {
			return fmt.Errorf("%w: runtime jitter must not be nil", ErrInvalidRegisterConfig)
		})
	}
	return withAgentRuntimeJitterSource(func() (float64, error) { return jitter(), nil })
}

func withAgentRuntimeJitterSource(jitter func() (float64, error)) AgentRuntimeRegistrationOption {
	return agentRuntimeTestOption(func(c *agentRuntimeConfig) error {
		if jitter == nil {
			return fmt.Errorf("%w: runtime jitter source must not be nil", ErrInvalidRegisterConfig)
		}
		c.jitter = jitter
		return nil
	})
}

// RefreshAgentRegistration is the sole ordinary registered-agent refresh path.
// It loads the completed state once under the setup lock, uses only the persisted
// immutable device credential against the resource/API origin, validates the
// authoritative assignment, performs native UDP REG/RAK, and saves the refreshed
// lease/binding without registration-info or completion. The returned Client is
// primed from that same load and the binding owns the one retained private-key
// copy. A generation or cell change is terminal before UDP or state mutation.
// The setup lock remains held across the bounded assignment request and native
// REG exchange, so concurrent lifecycle operations on the same local state wait
// for this transition rather than observing or committing an intermediate view.
// With defaults, retry pacing has a 45-second budget, each API request has the
// SDK's 30-second HTTP timeout, and native REG tries at most three addresses with
// a three-second per-address deadline. Callers must pass a finite context to cap
// the whole lock-held transition; context.Background can retain the local-file
// lock through the full budgets. Custom transports must preserve equivalent bounds.
func RefreshAgentRegistration(ctx context.Context, store AgentStateStore, opts ...AgentRuntimeOption) (*Client, *AgentRuntimeBinding, error) {
	if store == nil {
		return nil, nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	cfg, err := newAgentRuntimeConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	var privateKey []byte
	defer func() { wipeBytes(privateKey) }()
	state, err := withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		persisted, err := loadCompletedRegisteredState(ctx, store, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}
		if err := validateAgentAssignmentShape(persisted.Assignment, persisted.AgentID); err != nil {
			return nil, fmt.Errorf("%w: persisted assignment: %w", ErrInvalidRegisterConfig, err)
		}
		if err := validatePersistedNativeRegistrationCredential(persisted, ErrInvalidRegisterConfig); err != nil {
			return nil, err
		}
		privateKey, err = decodeRuntimePrivateKey(persisted, ErrInvalidRegisterConfig)
		if err != nil {
			return nil, err
		}

		assignment, err := FetchAgentAssignment(ctx, persisted.AgentID, BearerToken(persisted.DeviceAPIKey), cfg.assignmentOptions()...)
		if err != nil {
			return nil, err
		}
		if err := ensureAssignmentContinuity(persisted.Assignment, assignment); err != nil {
			return nil, err
		}

		candidate := persisted.clone()
		expectedPeer := adoptAssignment(candidate, assignment)
		bindingChanged := !assignment.equal(persisted.Assignment) ||
			persisted.NHPPeer == nil || *persisted.NHPPeer != *expectedPeer
		// Steady-state REG intentionally carries no enrollment metadata. The
		// qurl-service producer treats empty hostname/version as "preserve existing"
		// and takeover=false as the non-rotating same-key registration path.
		if err := nativeRegisterAgent(ctx, candidate, privateKey, candidate.DeviceAPIKeyID, candidate.DeviceAPIKey, registerUserData{}, pathDevice, cfg); err != nil {
			return nil, err
		}
		if bindingChanged {
			if err := store.SaveAgentState(ctx, candidate); err != nil {
				return nil, fmt.Errorf("%w: persist native assignment binding: %w", ErrAgentBindingPersistence, err)
			}
		}
		return candidate, nil
	})
	if err != nil {
		return nil, nil, err
	}
	client := newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey, cfg.clock)
	binding := newAgentRuntimeBinding(state, privateKey)
	privateKey = nil
	return client, binding, nil
}

func ensureAssignmentContinuity(persisted, current *AgentAssignment) error {
	if current == nil {
		return fmt.Errorf("%w: current assignment is nil", ErrAssignmentInvalidResponse)
	}
	if persisted == nil {
		return nil
	}
	if persisted.CellID != current.CellID || persisted.AssignmentGeneration != current.AssignmentGeneration {
		return &AgentAssignmentChangedError{
			PersistedCellID:     persisted.CellID,
			PersistedGeneration: persisted.AssignmentGeneration,
			CurrentCellID:       current.CellID,
			CurrentGeneration:   current.AssignmentGeneration,
		}
	}
	if current.EndpointRevision < persisted.EndpointRevision {
		return fmt.Errorf("%w: endpoint revision regressed from %d to %d", ErrAssignmentInvalidResponse, persisted.EndpointRevision, current.EndpointRevision)
	}
	if current.EndpointRevision == persisted.EndpointRevision && current.Endpoint != persisted.Endpoint {
		return fmt.Errorf("%w: endpoint changed without incrementing endpoint_revision", ErrAssignmentInvalidResponse)
	}
	// The control plane remains authoritative for the lease. It may shorten a
	// live same-revision lease to accelerate the next refresh before planned
	// reassignment; rejecting that response would make the SDK outlive the
	// authority's deadline. FetchAgentAssignment has already required it to be
	// live, and the caller adopts the returned instant durably.
	return nil
}

func assignmentPeer(assignment *AgentAssignment) *NHPServerPeerInfo {
	if assignment == nil {
		return nil
	}
	return &NHPServerPeerInfo{
		PublicKeyB64: assignment.Endpoint.ServerPublicKeyB64,
		Host:         assignment.Endpoint.Host,
		Port:         assignment.Endpoint.Port,
		ExpireTime:   assignment.LeaseExpiresAt.Unix(),
	}
}

// adoptAssignment stamps a freshly fetched assignment and its derived peer onto
// one state candidate so the two durable views cannot drift at call sites. It
// returns that same derived peer for callers that also compare binding changes.
func adoptAssignment(state *AgentState, assignment *AgentAssignment) *NHPServerPeerInfo {
	state.Assignment = assignment.clone()
	state.NHPPeer = assignmentPeer(assignment)
	return state.NHPPeer
}

func (a *AgentAssignment) nativeEndpoint() (nativeudp.Endpoint, error) {
	serverKey, err := a.DecodedServerKey()
	if err != nil {
		return nativeudp.Endpoint{}, err
	}
	return nativeudp.Endpoint{
		Host:            a.Endpoint.Host,
		Port:            a.Endpoint.Port,
		ServerStaticPub: serverKey,
	}, nil
}

func nativeRegisterAgent(ctx context.Context, state *AgentState, privateKey []byte, keyID, credential string, userData registerUserData, path pathKind, cfg *agentRuntimeConfig) error {
	if err := validateAgentAssignment(state.Assignment, state.AgentID, cfg.clock()); err != nil {
		return err
	}
	if err := validateAPIKeyID(keyID, "native registration key id", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	if err := validateExactBearerToken(credential, "native registration credential", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	endpoint, err := state.Assignment.nativeEndpoint()
	if err != nil {
		return err
	}
	body, err := marshalRegisterRequestBody(keyID, state.AgentID, credential, userData)
	if err != nil {
		return err
	}
	defer wipeBytes(body)
	reply, err := nativeudp.Register(ctx, endpoint, body, cfg.udpOptions(privateKey))
	if err != nil {
		// Keep native and relay REG failures in one enrollment taxonomy. In
		// particular, nativeudp rejects a mis-correlated RAK with the shared
		// relayknock.ErrMalformedReply sentinel; callers must see that beneath
		// ErrRegisterReplyMalformed just as they do on the relay path.
		return normalizeRelayError(err, ErrRegisterReplyMalformed)
	}
	if reply.IsCookieChallenge() {
		return fmt.Errorf("%w: native registration returned an overload cookie challenge", ErrRegistrationRetryLater)
	}
	if !reply.IsRegisterAck() {
		return fmt.Errorf("%w: unexpected native registration reply type %d", ErrRegisterReplyMalformed, reply.Type)
	}
	ack, err := parseNativeRegisterAck(reply.Body)
	if err != nil {
		return err
	}
	return rakResult(ack, path)
}

const (
	postMintVisibilityMaxAttempts = 4
	postMintVisibilityBudget      = 3 * time.Second
	postMintVisibilityBackoff     = 100 * time.Millisecond
)

// confirmFreshDeviceAssignment is the only place an assignment 401 is retried.
// Local provenance is stronger than the indistinguishable wire response: this
// is called synchronously only after this SDK received and durably saved a newly
// minted device key. Revoked/unknown-key 401s on every ordinary path remain
// terminal. The finite retry does not expand FetchAgentAssignment's 401 policy.
// This deliberately uses a fixed local backoff rather than jitter or Retry-After:
// one SDK is waiting for its own just-minted credential to become visible, while
// the 401 response is not a fleet-wide overload signal and carries no retry hint.
// The three-second budget covers only those exact 401 revisits. Each fetch retains
// its separate bounded 503 authority policy, which may consume its own budget
// before returning recovery-required; the caller context caps total wall time.
func (c *agentRuntimeConfig) confirmFreshDeviceAssignment(ctx context.Context, store AgentStateStore, state *AgentState) (*AgentState, error) {
	if state == nil || state.Assignment == nil {
		return nil, fmt.Errorf("%w: post-mint confirmation requires a persisted assignment", ErrAssignmentInvalidResponse)
	}
	start := c.clock()
	assignmentOpts := c.assignmentOptions()
	for attempt := 1; ; attempt++ {
		assignment, err := FetchAgentAssignment(ctx, state.AgentID, BearerToken(state.DeviceAPIKey), assignmentOpts...)
		if err != nil {
			if !isPostMintVisibilityMiss(err) {
				return nil, err
			}
			elapsed := c.clock().Sub(start)
			if attempt >= postMintVisibilityMaxAttempts || elapsed >= postMintVisibilityBudget {
				return nil, err
			}
			delay := postMintVisibilityBackoff << (attempt - 1)
			if delay > postMintVisibilityBudget-elapsed {
				return nil, err
			}
			if err := c.sleep(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		if err := ensureAssignmentContinuity(state.Assignment, assignment); err != nil {
			return nil, err
		}
		if assignment.EndpointRevision != state.Assignment.EndpointRevision {
			return nil, fmt.Errorf("%w: endpoint revision advanced from %d to %d during enrollment", ErrAssignmentEndpointRefreshRequired, state.Assignment.EndpointRevision, assignment.EndpointRevision)
		}
		if assignment.equal(state.Assignment) {
			return state, nil
		}
		candidate := state.clone()
		adoptAssignment(candidate, assignment)
		if err := store.SaveAgentState(ctx, candidate); err != nil {
			return nil, fmt.Errorf("%w: persist post-mint assignment lease: %w", ErrAgentBindingPersistence, err)
		}
		return candidate, nil
	}
}

func isPostMintVisibilityMiss(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusUnauthorized &&
		apiErr.Code == assignmentCodeAPIKeyInvalid
}

// NativeKnockResult is the authenticated, resource-specific admission returned
// by KnockRegisteredAgent. A result exists only when the requested resource has
// both a non-empty AC token and a non-empty ResourceHost in the ACK. ACToken is
// a bearer credential: do not log, serialize, or include this result in support
// bundles. String and GoString redact it for ordinary fmt formatting, but callers
// remain responsible for every explicit field read or serialization.
type NativeKnockResult struct {
	ACToken      string
	ResourceHost string
	OpenTime     uint32
	AgentAddr    string
}

// String returns a summary that never renders the bearer admission token.
func (r NativeKnockResult) String() string {
	return fmt.Sprintf("qurl.NativeKnockResult{ACToken:[REDACTED], ResourceHost:%q, OpenTime:%d, AgentAddr:%q}", r.ResourceHost, r.OpenTime, r.AgentAddr)
}

// GoString provides the same token redaction for %#v formatting.
func (r NativeKnockResult) GoString() string { return r.String() }

type nativeAgentKnockACK struct {
	ErrCode           nativeJSONValue[string] `json:"errCode"`
	ErrMsg            nativeJSONValue[string] `json:"errMsg"`
	ResourceHost      nativeJSONStringMap     `json:"resHost"`
	OpenTime          nativeJSONValue[uint32] `json:"opnTime"`
	AuthProviderToken nativeJSONValue[string] `json:"aspToken"`
	AgentAddr         nativeJSONValue[string] `json:"agentAddr"`
	ACTokens          nativeJSONStringMap     `json:"acTokens"`
	PreAccessActions  nativePreAccessActions  `json:"preActions"`
	RedirectURL       nativeJSONValue[string] `json:"redirectUrl"`
}

// nativeJSONValue distinguishes an absent optional field from an explicit null
// while delegating exact JSON type/range enforcement to encoding/json. OpenNHP's
// optional errMsg/aspToken/redirectUrl producer fields are value strings tagged
// omitempty, so it emits either a string or no field, never an explicit null.
type nativeJSONValue[T any] struct {
	Value   T
	Present bool
}

func (v *nativeJSONValue[T]) UnmarshalJSON(data []byte) error {
	v.Present = true
	if isJSONNull(data) {
		return errors.New("must not be JSON null")
	}
	return json.Unmarshal(data, &v.Value)
}

// nativeJSONStringMap distinguishes the live denial's whole-map null from an
// absent mandatory field while requiring every object value to be an exact JSON
// string. encoding/json otherwise accepts a null map entry as "".
type nativeJSONStringMap struct {
	Value   map[string]string
	Present bool
}

func (v *nativeJSONStringMap) UnmarshalJSON(data []byte) error {
	v.Present = true
	if isJSONNull(data) {
		v.Value = nil
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return errors.New("must be a JSON object or null")
	}
	v.Value = make(map[string]string, len(raw))
	for key, valueJSON := range raw {
		var value nativeJSONValue[string]
		if err := json.Unmarshal(valueJSON, &value); err != nil {
			return fmt.Errorf("map entry %q: %w", key, err)
		}
		v.Value[key] = value.Value
	}
	return nil
}

// nativeAgentPreAccessInfo mirrors the current OpenNHP producer value shape so
// the envelope remains type-fenced. qURL Connector does not implement OpenNHP's
// required NHP_ACC phase, so interpretNativeAgentKnockReply rejects every
// non-null action instead of falsely reporting that the resource is ready.
type nativeAgentPreAccessInfo struct {
	AccessIP       nativeJSONValue[string] `json:"acIp"`
	AccessPort     nativeJSONValue[string] `json:"acPort"`
	ACPublicKey    nativeJSONValue[string] `json:"acPubKey"`
	ACToken        nativeJSONValue[string] `json:"acToken"`
	ACCipherScheme nativeJSONValue[int]    `json:"acCipherScheme"`
}

func (v nativeAgentPreAccessInfo) validateRequiredFields() error {
	return requirePresentFields("pre-access action field",
		presenceField{name: "acIp", present: v.AccessIP.Present},
		presenceField{name: "acPort", present: v.AccessPort.Present},
		presenceField{name: "acPubKey", present: v.ACPublicKey.Present},
		presenceField{name: "acToken", present: v.ACToken.Present},
		presenceField{name: "acCipherScheme", present: v.ACCipherScheme.Present},
	)
}

type nativePreAccessActions struct {
	RequiresAction bool
}

func (v *nativePreAccessActions) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		// ServerKnockAckMsg marks the field omitempty and the UDP producer
		// initializes it to a non-nil map. The current wire can therefore omit it
		// or send an object, but never sends a top-level null.
		return errors.New("must be a JSON object, not null")
	}
	var actions map[string]json.RawMessage
	if err := json.Unmarshal(data, &actions); err != nil {
		return err
	}
	if actions == nil {
		return errors.New("must be a JSON object")
	}
	for resourceID, actionJSON := range actions {
		if isJSONNull(actionJSON) {
			continue
		}
		var action nativeAgentPreAccessInfo
		if err := strictDecodeJSON(actionJSON, &action); err != nil {
			return fmt.Errorf("pre-access action %q: %w", resourceID, err)
		}
		if err := action.validateRequiredFields(); err != nil {
			return fmt.Errorf("pre-access action %q: %w", resourceID, err)
		}
		v.RequiresAction = true
	}
	return nil
}

func isJSONNull(data []byte) bool {
	return bytes.Equal(bytes.TrimSpace(data), []byte("null"))
}

func (a nativeAgentKnockACK) validateRequiredFields() error {
	return requirePresentFields("native knock ACK field",
		presenceField{name: "errCode", present: a.ErrCode.Present},
		presenceField{name: "resHost", present: a.ResourceHost.Present},
		presenceField{name: "opnTime", present: a.OpenTime.Present},
		presenceField{name: "agentAddr", present: a.AgentAddr.Present},
		presenceField{name: "acTokens", present: a.ACTokens.Present},
	)
}

type presenceField struct {
	name    string
	present bool
}

func requirePresentFields(prefix string, fields ...presenceField) error {
	for _, field := range fields {
		if !field.present {
			return fmt.Errorf("%s %s is missing", prefix, field.name)
		}
	}
	return nil
}

// KnockRegisteredAgent sends one caller-correlated native UDP NHP_KNK to the
// binding's assigned cell and returns only the requested resource's admission.
// It validates the live assignment and required RunID before DNS/socket I/O,
// authenticates the server through the pinned assignment key, and fails closed
// on malformed/wrong-resource ACKs. deviceStaticPrivateKey is normally obtained
// once from AgentRuntimeBinding.TakeDeviceStaticPrivateKey and retained by the
// connector for its process lifetime; the caller owns and must wipe it.
func KnockRegisteredAgent(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte, knockResourceID string, opts NativeKnockOptions, transportOpts ...AgentRuntimeUDPOption) (*NativeKnockResult, error) {
	if binding == nil {
		return nil, fmt.Errorf("%w: runtime binding must not be nil", ErrInvalidNativeKnockInput)
	}
	if len(deviceStaticPrivateKey) != x25519key.Size {
		return nil, fmt.Errorf("%w: device static private key must be %d bytes", ErrInvalidNativeKnockInput, x25519key.Size)
	}
	runtimeOpts := make([]AgentRuntimeOption, len(transportOpts))
	for i, opt := range transportOpts {
		runtimeOpts[i] = opt
	}
	// Reuse the shared runtime validator so clocks, resolver/dialer injection,
	// and UDP bounds have identical semantics across REG and KNK. The closed
	// AgentRuntimeUDPOption vocabulary excludes assignment retry/sleep/jitter
	// options; those default fields are inert during this single exchange.
	cfg, err := newAgentRuntimeConfig(runtimeOpts)
	if err != nil {
		return nil, fmt.Errorf("%w: native UDP transport options: %w", ErrInvalidNativeKnockInput, err)
	}
	assignment := binding.assignment()
	if err := validateAgentAssignment(assignment, binding.AgentID, cfg.clock()); err != nil {
		return nil, fmt.Errorf("%w: runtime assignment: %w", ErrInvalidNativeKnockInput, err)
	}
	body, err := marshalNativeKnockApplicationBody(binding.AgentID, knockResourceID, opts)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	endpoint, err := assignment.nativeEndpoint()
	if err != nil {
		return nil, err
	}
	reply, err := nativeudp.Knock(ctx, endpoint, body, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	return interpretNativeAgentKnockReply(reply, knockResourceID)
}

func interpretNativeAgentKnockReply(reply *relayknock.Reply, knockResourceID string) (*NativeKnockResult, error) {
	if reply == nil {
		return nil, fmt.Errorf("%w: native knock reply is nil", ErrMalformedReply)
	}
	if reply.IsCookieChallenge() {
		return nil, ErrServerOverloaded
	}
	if !reply.IsACK() {
		return nil, fmt.Errorf("%w: unexpected native knock reply type %d", ErrMalformedReply, reply.Type)
	}
	if err := rejectDuplicateJSONFields(reply.Body); err != nil {
		return nil, fmt.Errorf("%w: native knock ACK contains malformed or duplicate JSON fields: %w", ErrMalformedReply, err)
	}
	var ack *nativeAgentKnockACK
	if err := strictDecodeJSON(reply.Body, &ack); err != nil {
		return nil, fmt.Errorf("%w: parse native knock ACK: %w", ErrMalformedReply, err)
	}
	if ack == nil {
		return nil, fmt.Errorf("%w: native knock ACK must be an object", ErrMalformedReply)
	}
	if err := ack.validateRequiredFields(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedReply, err)
	}
	// KNK keeps the producer's historical exact empty-or-"0" success convention.
	// Unlike relay-era REG, it deliberately does not trim whitespace: a padded
	// code is producer drift and fails closed. Even an authenticated empty-code
	// ACK cannot succeed unless it also carries a non-empty token and host for
	// this exact requested resource below.
	if ack.ErrCode.Value != "" && ack.ErrCode.Value != errSuccess {
		return nil, &ServerDenyError{ErrCode: ack.ErrCode.Value, ErrMsg: ack.ErrMsg.Value}
	}
	if ack.PreAccessActions.RequiresAction {
		return nil, fmt.Errorf("%w: native knock ACK requires an unsupported pre-access action", ErrMalformedReply)
	}
	token := ack.ACTokens.Value[knockResourceID]
	host := ack.ResourceHost.Value[knockResourceID]
	if token == "" || host == "" || token != strings.TrimSpace(token) || host != strings.TrimSpace(host) {
		return nil, fmt.Errorf("%w: success ACK missing canonical non-empty token or resource host for requested resource", ErrMalformedReply)
	}
	return &NativeKnockResult{ACToken: token, ResourceHost: host, OpenTime: ack.OpenTime.Value, AgentAddr: ack.AgentAddr.Value}, nil
}
