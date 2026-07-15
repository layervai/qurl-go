package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// ErrAssignmentEndpointRefreshRequired means initial enrollment completed but
// the control plane rotated the endpoint before the freshly minted device key
// became visible. The completed credential and original live binding are
// durable; run RefreshAgentRegistration to authenticate and adopt the new
// endpoint. Completion must not be retried.
var ErrAssignmentEndpointRefreshRequired = errors.New("qurl: assignment endpoint refresh required")

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
	jitter       func() float64
}

func defaultAgentRuntimeConfig() agentRuntimeConfig {
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
		withAssignmentJitter(c.jitter),
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
func WithAgentRuntimeUDPResolver(resolver nativeudp.Resolver) AgentRuntimeRegistrationOption {
	return agentRuntimeResolverOption{resolver: resolver}
}

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
func WithAgentRuntimeUDPDialer(dialer nativeudp.Dialer) AgentRuntimeRegistrationOption {
	return agentRuntimeDialerOption{dialer: dialer}
}

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
func WithAgentRuntimeUDPBounds(timeout time.Duration, maxAddresses int) AgentRuntimeRegistrationOption {
	return agentRuntimeUDPBoundsOption{timeout: timeout, maxAddresses: maxAddresses}
}

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

func withAgentRuntimeClock(clock func() time.Time) AgentRuntimeRegistrationOption {
	return agentRuntimeTestOption(func(c *agentRuntimeConfig) error {
		if clock == nil {
			return fmt.Errorf("%w: runtime clock must not be nil", ErrInvalidRegisterConfig)
		}
		c.clock = clock
		return nil
	})
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
	return agentRuntimeTestOption(func(c *agentRuntimeConfig) error {
		if jitter == nil {
			return fmt.Errorf("%w: runtime jitter must not be nil", ErrInvalidRegisterConfig)
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
		candidate.Assignment = assignment.clone()
		candidate.NHPPeer = assignmentPeer(assignment)
		if err := nativeRegisterAgent(ctx, candidate, privateKey, candidate.DeviceAPIKeyID, candidate.DeviceAPIKey, registerUserData{}, pathDevice, cfg); err != nil {
			return nil, err
		}
		if err := store.SaveAgentState(ctx, candidate); err != nil {
			return nil, fmt.Errorf("%w: persist native assignment binding: %w", ErrAgentBindingPersistence, err)
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

func nativeRegisterAgent(ctx context.Context, state *AgentState, privateKey []byte, keyID, credential string, userData registerUserData, path pathKind, cfg *agentRuntimeConfig) error {
	if err := validateAgentAssignment(state.Assignment, state.AgentID, cfg.clock()); err != nil {
		return err
	}
	if err := validateDeviceAPIKeyID(keyID, "native registration key id", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	if err := validateExactBearerToken(credential, "native registration credential", ErrInvalidRegisterConfig); err != nil {
		return err
	}
	serverKey, err := state.Assignment.DecodedServerKey()
	if err != nil {
		return err
	}
	defer wipeBytes(serverKey)
	body, err := json.Marshal(registerRequestBody{
		UsrID:   keyID,
		DevID:   state.AgentID,
		AspID:   agentAspID,
		OTP:     credential,
		UsrData: userData,
	})
	if err != nil {
		return fmt.Errorf("qurl: encode native registration body: %w", err)
	}
	defer wipeBytes(body)
	reply, err := nativeudp.Register(ctx, nativeudp.Endpoint{
		Host:            state.Assignment.Endpoint.Host,
		Port:            state.Assignment.Endpoint.Port,
		ServerStaticPub: serverKey,
	}, body, cfg.udpOptions(privateKey))
	if err != nil {
		return err
	}
	if reply.IsCookieChallenge() {
		return fmt.Errorf("%w: native registration returned an overload cookie challenge", ErrRegistrationRetryLater)
	}
	if !reply.IsRegisterAck() {
		return fmt.Errorf("%w: unexpected native registration reply type %d", ErrRegisterReplyMalformed, reply.Type)
	}
	ack, err := parseRegisterAck(reply.Body)
	if err != nil {
		return err
	}
	if !ack.isSuccess() {
		return mapRAKError(ack, path)
	}
	return nil
}

const (
	postMintVisibilityMaxAttempts = 4
	postMintVisibilityBudget      = 3 * time.Second
	postMintVisibilityBackoff     = 100 * time.Millisecond
	assignmentCodeAPIKeyInvalid   = "api_key_invalid"
)

// confirmFreshDeviceAssignment is the only place an assignment 401 is retried.
// Local provenance is stronger than the indistinguishable wire response: this
// is called synchronously only after this SDK received and durably saved a newly
// minted device key. Revoked/unknown-key 401s on every ordinary path remain
// terminal. The finite retry does not expand FetchAgentAssignment's 401 policy.
func (c *agentRuntimeConfig) confirmFreshDeviceAssignment(ctx context.Context, store AgentStateStore, state *AgentState) (*AgentState, error) {
	start := c.clock()
	for attempt := 1; ; attempt++ {
		assignment, err := FetchAgentAssignment(ctx, state.AgentID, BearerToken(state.DeviceAPIKey), c.assignmentOptions()...)
		if err == nil {
			if err := ensureAssignmentContinuity(state.Assignment, assignment); err != nil {
				return nil, err
			}
			if assignment.EndpointRevision != state.Assignment.EndpointRevision {
				return nil, fmt.Errorf("%w: endpoint revision advanced from %d to %d during enrollment", ErrAssignmentEndpointRefreshRequired, state.Assignment.EndpointRevision, assignment.EndpointRevision)
			}
			candidate := state.clone()
			candidate.Assignment = assignment.clone()
			candidate.NHPPeer = assignmentPeer(assignment)
			if err := store.SaveAgentState(ctx, candidate); err != nil {
				return nil, fmt.Errorf("%w: persist post-mint assignment lease: %w", ErrAgentBindingPersistence, err)
			}
			return candidate, nil
		}
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
// both a non-empty AC token and a non-empty ResourceHost in the ACK.
type NativeKnockResult struct {
	ACToken      string
	ResourceHost string
	OpenTime     uint32
	AgentAddr    string
}

type nativeAgentKnockACK struct {
	ErrCode      string            `json:"errCode"`
	ErrMsg       string            `json:"errMsg"`
	ResourceHost map[string]string `json:"resHost"`
	OpenTime     uint32            `json:"opnTime"`
	AgentAddr    string            `json:"agentAddr"`
	ACTokens     map[string]string `json:"acTokens"`
}

// KnockRegisteredAgent sends one caller-correlated native UDP NHP_KNK to the
// binding's assigned cell and returns only the requested resource's admission.
// It validates the live assignment and required RunID before DNS/socket I/O,
// authenticates the server through the pinned assignment key, and fails closed
// on malformed/wrong-resource ACKs. deviceStaticPrivateKey is normally obtained
// once from AgentRuntimeBinding.TakeDeviceStaticPrivateKey and retained by the
// connector for its process lifetime; the caller owns and must wipe it.
func KnockRegisteredAgent(ctx context.Context, binding *AgentRuntimeBinding, deviceStaticPrivateKey []byte, knockResourceID string, opts NativeKnockOptions, transportOpts ...AgentRuntimeOption) (*NativeKnockResult, error) {
	if binding == nil {
		return nil, fmt.Errorf("%w: runtime binding must not be nil", ErrInvalidNativeKnockInput)
	}
	cfg, err := newAgentRuntimeConfig(transportOpts)
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
	serverKey, err := assignment.DecodedServerKey()
	if err != nil {
		return nil, err
	}
	defer wipeBytes(serverKey)
	reply, err := nativeudp.Knock(ctx, nativeudp.Endpoint{
		Host:            assignment.Endpoint.Host,
		Port:            assignment.Endpoint.Port,
		ServerStaticPub: serverKey,
	}, body, cfg.udpOptions(deviceStaticPrivateKey))
	if err != nil {
		if errors.Is(err, relayknock.ErrMalformedReply) {
			return nil, fmt.Errorf("%w: %w", ErrMalformedReply, err)
		}
		return nil, err
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
		return nil, fmt.Errorf("%w: native knock ACK contains malformed or duplicate JSON fields", ErrMalformedReply)
	}
	var ack nativeAgentKnockACK
	decoder := json.NewDecoder(bytes.NewReader(reply.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ack); err != nil {
		return nil, fmt.Errorf("%w: parse native knock ACK: %w", ErrMalformedReply, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing native knock ACK data", ErrMalformedReply)
		}
		return nil, fmt.Errorf("%w: parse trailing native knock ACK data: %w", ErrMalformedReply, err)
	}
	if ack.ErrCode != "" && ack.ErrCode != errSuccess {
		return nil, &ServerDenyError{ErrCode: ack.ErrCode}
	}
	token := ack.ACTokens[knockResourceID]
	host := ack.ResourceHost[knockResourceID]
	if strings.TrimSpace(token) == "" || strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("%w: success ACK missing non-empty token or resource host for requested resource", ErrMalformedReply)
	}
	return &NativeKnockResult{ACToken: token, ResourceHost: host, OpenTime: ack.OpenTime, AgentAddr: ack.AgentAddr}, nil
}
