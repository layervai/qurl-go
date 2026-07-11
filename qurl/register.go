package qurl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/layervai/qurl-go/relayknock"
)

// RegisterAgent is the NHP-native front door for enrolling an agent and getting
// a ready-to-use Client. It is idempotent: the first call enrolls and persists a
// device credential into store; later calls load that credential and return a
// Client without qURL API calls. Loading a network-backed or sealed store may
// still call its storage or key provider.
//
// The key argument is used only during first enrollment. Once store holds a
// completed registration the fast path serves the Client entirely from it and
// does not re-validate key, so rotating or mistyping the key against an
// already-registered store is not detected — the persisted device credential is
// authoritative from then on.
//
//	client, err := qurl.RegisterAgent(ctx, apiKey, store)
//	resource, err := client.ProtectURL(ctx, "https://dashboard.internal.acme.com")
//	portal, err := resource.CreatePortal(ctx, qurl.ValidFor(time.Hour))
//	fmt.Println(portal.Link)
//
// Two enrollment paths are selected by the key, transparently:
//
//   - A pre-issued (bootstrap) key IS the enrollment credential: RegisterAgent
//     completes in one call.
//   - An account key uses email one-time codes. The first call asks LayerV to
//     email a code and returns *OTPPendingError (Unwrap → ErrOTPPending); re-run
//     RegisterAgent with WithOTP once the code arrives to finish. See WithOTP /
//     WithOTPProvider for the re-entrant UX.
//
// store persists AgentState, which becomes a credential file once enrollment
// completes (see AgentState). Registration proves the agent's X25519 device key
// through the NHP Noise handshake, so the same keypair is reused across resumes.
//
// Each state write is atomic. For a FileAgentState the SDK also serializes
// concurrent first-registration setup across processes with a mandatory file
// lock (flock on a sidecar beside the state file): the racer that loses
// blocks until the winner enrolls, then loads the now-registered state via the
// fast path and returns a Client without re-sending a one-time code. Lock
// acquisition/release failures fail closed rather than risking competing
// identities. This applies to FileAgentState and SealedFileAgentStateStore.
//
// A custom or networked AgentStateStore cannot be locked for you, so concurrent
// callers sharing one are not serialized. On the account (email-OTP) path each
// concurrent fresh run generates its own device identity and dispatches its own
// one-time code, so concurrent setup multiplies OTP emails (last write to the
// state file wins) — serialize enrollment per store yourself.
func RegisterAgent(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*Client, error) {
	cfg, err := newRegisterConfig(opts)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("%w: API key must not be empty", ErrInvalidRegisterConfig)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	cfg.requireDeviceKey = true
	if _, err := cfg.run(ctx, key, store); err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.baseURL, cfg.httpClient), nil
}

// registerConfig is the resolved option set plus the fixed dependencies a
// registration run needs.
type registerConfig struct {
	baseURL     string
	httpClient  HTTPDoer
	deviceID    string
	otp         string
	otpProvider func(context.Context) (string, error)
	takeover    bool
	hostname    string
	version     string

	// relayURL / nhpPeer are optional overrides; when unset the values come from
	// the registration-info pre-flight.
	relayURLOverride string
	nhpPeerOverride  *NHPServerPeerInfo

	// requireDeviceKey makes the fast path fail closed when a registered state
	// carries no device credential. RegisterAgent sets it (a Client needs the
	// credential); BootstrapAgent leaves it false so a legacy bootstrap-era state
	// without a device key still returns.
	requireDeviceKey bool

	// invalidConfigErr is the caller-facing sentinel wrapped into the engine's
	// config-class failures (device-id mismatch, key decode, server_id mismatch,
	// loaded-state validation), so each front door keeps its documented error
	// class: RegisterAgent → ErrInvalidRegisterConfig, BootstrapAgent →
	// ErrInvalidBootstrapConfig.
	invalidConfigErr error

	// clock is injected in tests; production uses time.Now.
	clock func() time.Time
}

func newRegisterConfig(opts []RegisterOption) (*registerConfig, error) {
	cfg := &registerConfig{
		baseURL:          defaultAPIBaseURL,
		httpClient:       defaultAPIHTTPClient,
		invalidConfigErr: ErrInvalidRegisterConfig,
		clock:            time.Now,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil RegisterOption", ErrInvalidRegisterConfig)
		}
		if err := opt.applyRegisterOption(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.otp != "" && cfg.otpProvider != nil {
		return nil, fmt.Errorf("%w: set only one of WithOTP or WithOTPProvider", ErrInvalidRegisterConfig)
	}
	return cfg, nil
}

// otpResendCooldown is how long the account path waits before re-sending an
// email one-time code on a rapid re-run, so repeated RegisterAgent calls do not
// spam the account with codes.
const otpResendCooldown = 60 * time.Second

// run drives the registration state machine to a *Client. State is derived from
// AgentState fields (no enum): absent → keypair-persisted → otp_pending → registered.
func (cfg *registerConfig) run(ctx context.Context, key string, store AgentStateStore) (result *AgentState, resultErr error) {
	// Preserve the documented zero-qURL-API, read-only fast path: a completed
	// state no longer needs setup serialization and must remain usable when the
	// state directory is mounted read-only or local locking is unsupported. The
	// store load itself may call a remote storage or key provider.
	state, found, err := loadAgentStateIfPresent(ctx, store, cfg.invalidConfigErr)
	if err != nil {
		return nil, err
	}
	if found && state.RegisteredAt != nil {
		return cfg.finishRegisteredAgentState(state)
	}

	// Mandatory serialization starts only for incomplete/fresh setup. Two racers
	// would otherwise mint competing identities and race the atomic save. After
	// acquiring, reload: another process may have completed enrollment while this
	// caller waited, in which case the second fast-path check returns its state.
	releaseSetupLock, err := acquireAgentSetupLock(ctx, store)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := releaseSetupLock(); err != nil {
			// Even if enrollment and its atomic state write succeeded, fail this call
			// because lock ownership is now ambiguous. A retry recovers without a
			// second enrollment by reading the completed state on the pre-lock path.
			lockErr := fmt.Errorf("%w: release setup lock: %w", ErrAgentSetupLock, err)
			result = nil
			if resultErr == nil {
				resultErr = lockErr
			} else {
				resultErr = errors.Join(resultErr, lockErr)
			}
		}
	}()

	state, err = loadOrCreateAgentState(ctx, store, cfg.invalidConfigErr)
	if err != nil {
		return nil, err
	}
	if state.RegisteredAt != nil {
		return cfg.finishRegisteredAgentState(state)
	}

	// Persist the device identity (keypair + stable device id) BEFORE any
	//    network call so an interrupted registration resumes with the same
	//    identity the server will bind.
	if err := cfg.ensureDeviceID(state); err != nil {
		return nil, err
	}
	if state.SchemaVersion < agentStateSchemaVersion {
		state.SchemaVersion = agentStateSchemaVersion
	}
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}

	// Pre-flight: registration-info tells us the path (key_kind), the key id,
	//    the NHP peer, and the relay coordinates. Side-effect-free.
	info, err := cfg.fetchRegistrationInfo(ctx, key)
	if err != nil {
		return nil, err
	}
	// Assert the pre-flight's own server_id agrees with its own peer key — an
	// integrity check on the registration-info response, independent of any
	// WithNHPPeer override (which selects the peer to knock, not what the service
	// reported).
	if err := cfg.assertServerIDMatches(info.Relay.ServerID, &info.NHPServerPeer); err != nil {
		return nil, err
	}
	peer := cfg.resolvePeer(info)
	relayURL := cfg.resolveRelayURL(info)
	state.NHPPeer = peer
	state.RelayURL = relayURL
	state.KeyID = info.KeyID
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}

	switch strings.TrimSpace(info.KeyKind) {
	case keyKindBootstrap:
		return cfg.runBootstrapPath(ctx, key, store, state, peer, relayURL)
	case keyKindAccount:
		if strings.TrimSpace(info.MaskedEmail) == "" {
			// Fail fast before spending an OTP round trip: an account key with no
			// email on file can never receive the code.
			return nil, fmt.Errorf("%w: the account key has no email on file for the one-time code; add an email or use a pre-issued key", ErrNoAccountEmail)
		}
		return cfg.runAccountPath(ctx, key, store, state, peer, relayURL, info.MaskedEmail)
	default:
		// validate() already rejected unknown kinds; defensive.
		return nil, fmt.Errorf("%w: registration-info returned unknown key_kind %q", cfg.invalidConfigErr, info.KeyKind)
	}
}

func loadAgentStateIfPresent(ctx context.Context, store AgentStateStore, invalidConfigErr error) (*AgentState, bool, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if err := state.ensureKeypair(invalidConfigErr); err != nil {
			return nil, false, err
		}
		return state, true, nil
	case errors.Is(err, ErrAgentStateNotFound):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("%w: load agent state: %w", invalidConfigErr, err)
	}
}

func (cfg *registerConfig) finishRegisteredAgentState(state *AgentState) (*AgentState, error) {
	// A RegisterAgent Client authorizes with the REST device key and never knocks
	// the persisted NHP peer, so an expired peer does not block its fast path. The
	// knock-only BootstrapAgent path still requires a live peer.
	if err := validateRegisteredAgentState(state, cfg.clock(), !cfg.requireDeviceKey, cfg.invalidConfigErr); err != nil {
		return nil, err
	}
	if cfg.requireDeviceKey && strings.TrimSpace(state.DeviceAPIKey) == "" {
		return nil, fmt.Errorf("%w: agent %q is registered but its device credential is absent from this state; clear or replace the persisted AgentState (or use a fresh AgentStateStore) and register again", ErrDeviceCredentialMissing, state.AgentID)
	}
	if err := cfg.reconcileDeviceID(state); err != nil {
		return nil, err
	}
	return state, nil
}

// runBootstrapPath is PATH A: the pre-issued key is the enrollment credential.
// REG directly with the key secret as the credential, then completion-fetch.
//
// Unlike runAccountPath, this path intentionally skips the crash-recovery
// tryCompletionProbe and always REGs. The tradeoff is documented: a bootstrap
// process that crashed after a prior RAK but before completion will re-REG on the
// next run, which — like the account path's transient-fault fall-through — relies
// on the server treating a repeat REG for the same device key as idempotent. The
// probe is skipped here to keep the one-call bootstrap path lean; the account
// path pays for it because its resume is already multi-call.
func (cfg *registerConfig) runBootstrapPath(ctx context.Context, key string, store AgentStateStore, state *AgentState, peer *NHPServerPeerInfo, relayURL string) (*AgentState, error) {
	return cfg.registerAndComplete(ctx, key, store, state, peer, relayURL, key, pathBootstrap)
}

// runAccountPath is PATH B: email one-time code. It is re-entrant across process
// runs, driven by AgentState.OTPRequestedAt:
//
//   - Fresh request (not yet otp_pending): email the code and persist
//     OTPRequestedAt (a code can only be valid after this send). Then a static
//     WithOTP pauses with *OTPPendingError (its literal cannot match the
//     just-sent email — use the emailed code next run), while a WithOTPProvider
//     resolves the freshly sent code and REGs in the same call (single-call
//     flow). With no code source, pause.
//   - Resume (otp_pending already set): probe completion FIRST — a prior run may
//     have gotten the RAK but crashed before completion, so the device is already
//     enrolled and the probe finishes the run without a code (self-heals even
//     with no code in hand, and avoids invoking a real-work provider). If not yet
//     enrolled, resolve the code and REG; with no code source, re-send after the
//     cooldown and pause.
func (cfg *registerConfig) runAccountPath(ctx context.Context, key string, store AgentStateStore, state *AgentState, peer *NHPServerPeerInfo, relayURL, maskedEmail string) (*AgentState, error) {
	// Ensure the code has been requested before any code can be valid. On a fresh
	// store this emails the code; on a resume (OTPRequestedAt already set) it does
	// nothing unless a code source is absent and the cooldown has elapsed (below).
	freshRequest := state.OTPRequestedAt == nil
	if freshRequest {
		if err := cfg.requestOTP(ctx, store, state, peer, relayURL, key); err != nil {
			return nil, err
		}
	}

	// On a resume, probe completion BEFORE resolving any code: a prior run may
	// have gotten the RAK but crashed before completion, so the device is already
	// enrolled server-side and completion finishes the run without a code. Doing
	// this first means (a) a no-code resume still self-heals, and (b) a
	// WithOTPProvider (which may do real work — a mailbox poll) is not invoked
	// when the probe can finish. A fresh request has nothing enrolled yet, so the
	// probe is skipped to keep the first-call path lean (no wasted 404).
	if !freshRequest {
		if done, doneState, err := cfg.tryCompletionProbe(ctx, key, store, state, pathAccount); done {
			return doneState, err
		}
	}

	// A static WithOTP literal supplied on the SAME call that just emailed a code
	// cannot match that fresh email — pause and let the caller re-run with the
	// newly emailed code. A WithOTPProvider is exempt: it reads the just-sent code.
	if freshRequest && cfg.otp != "" {
		return nil, cfg.otpPending(state, maskedEmail)
	}

	code, err := cfg.resolveOTP(ctx)
	if err != nil {
		return nil, err
	}
	if code == "" {
		// No code source: re-send once the cooldown elapses (so a long-idle
		// re-run refreshes an expired code), then pause for the caller to supply
		// the code on the next run.
		if cfg.clock().Sub(derefTime(state.OTPRequestedAt, cfg.clock())) >= otpResendCooldown {
			if err := cfg.requestOTP(ctx, store, state, peer, relayURL, key); err != nil {
				return nil, err
			}
		}
		return nil, cfg.otpPending(state, maskedEmail)
	}

	return cfg.registerAndComplete(ctx, key, store, state, peer, relayURL, code, pathAccount)
}

// otpPending builds the account-path pause point returned when the emailed code
// has been requested and RegisterAgent is waiting for the caller to supply it.
// Both pause sites — a fresh WithOTP literal that cannot match the just-sent
// code, and a no-code resume — return this same shape.
func (cfg *registerConfig) otpPending(state *AgentState, maskedEmail string) *OTPPendingError {
	return &OTPPendingError{
		RequestedAt: derefTime(state.OTPRequestedAt, cfg.clock()),
		MaskedEmail: maskedEmail,
	}
}

// registerAndComplete runs the shared REG → success-check → completion tail both
// enrollment paths end with. credential is the key secret (bootstrap) or the
// one-time code (account); path selects the RAK error mapping.
func (cfg *registerConfig) registerAndComplete(ctx context.Context, key string, store AgentStateStore, state *AgentState, peer *NHPServerPeerInfo, relayURL, credential string, path pathKind) (*AgentState, error) {
	ack, err := cfg.registerExchange(ctx, state, peer, relayURL, credential)
	if err != nil {
		return nil, err
	}
	if !ack.isSuccess() {
		return nil, mapRAKError(ack, path)
	}
	return cfg.completeAndPersist(ctx, key, store, state, path)
}

// requestOTP records OTPRequestedAt (otp_pending) and THEN dispatches the OTP
// email. The order is deliberate and anti-spam: persisting before sending means
// a persist failure emits no email (the caller retries as a still-fresh request,
// no code wasted), while a send failure after a successful persist leaves the
// state otp_pending — so the retry resumes under the 60s resend cooldown instead
// of re-emailing immediately. (Send-then-persist would, on a store with
// intermittent write failures, dispatch a code, fail the save, and re-send on
// the next run as a fresh request with no backoff.) On a persist failure the
// in-memory OTPRequestedAt mutation is rolled back so it matches what was stored.
func (cfg *registerConfig) requestOTP(ctx context.Context, store AgentStateStore, state *AgentState, peer *NHPServerPeerInfo, relayURL, key string) error {
	now := cfg.clock()
	prev := state.OTPRequestedAt
	state.OTPRequestedAt = &now
	if err := store.SaveAgentState(ctx, state); err != nil {
		state.OTPRequestedAt = prev // roll back the in-memory mutation
		return err
	}
	return cfg.sendOTP(ctx, state, peer, relayURL, key)
}

// tryCompletionProbe attempts a completion fetch to self-heal a crash that
// happened after the registration RAK but before completion. done is true when
// the probe resolved the run (success → registered state, or a terminal
// completion error); done is false when the device is not yet enrolled OR the
// probe hit a transient fault — in both cases the caller should proceed to REG,
// since the probe is only an optimization and REG is the real path.
//
// The self-heal relies on the qurl-service completion endpoint being idempotent
// for an already-enrolled device: a probe for a device a prior crashed run
// already enrolled must return that device's credential again (rather than a
// conflict), which is the completion grace-window contract implemented in
// qurl-service #1182. Without it a probe on the happy resume path would surface a
// spurious already-issued denial instead of finishing the run.
func (cfg *registerConfig) tryCompletionProbe(ctx context.Context, key string, store AgentStateStore, state *AgentState, path pathKind) (done bool, doneState *AgentState, err error) {
	comp, err := cfg.postCompletion(ctx, key, state, path)
	if err != nil {
		if isCompletionNotYetRegistered(err) || isTransientCompletionError(err) {
			// Not yet registered, or a transient blip on the optimization probe:
			// fall through to REG rather than aborting the whole registration.
			// Falling through on a transient (5xx) fault relies on the server
			// treating a repeat REG for the same device key as idempotent — the
			// same lost-response-retry assumption BootstrapAgent documents. A
			// non-idempotent server would instead answer 52103 (identity conflict)
			// and misleadingly suggest WithTakeover for what was really a transient
			// blip; that trade-off is accepted because the device is not yet
			// confirmed enrolled here, so REG (the real path) is the safe action.
			return false, nil, nil
		}
		// Any other completion error is terminal — most notably a structured
		// device_key_already_issued 409 (the device is registered but its key was
		// already issued and cannot be re-fetched). That is a real answer the
		// caller must act on, so surface it rather than treating the probe as a
		// no-op and proceeding to REG; the "optimization only" framing applies to
		// the not-yet-registered and transient cases above, not to a terminal denial.
		//
		// A bare transport fault (connection reset/timeout, no *APIError) also lands
		// here rather than falling through — deliberately: the post-REG completion
		// fetch hits the SAME endpoint, so a genuinely-down completion path would
		// fail identically after a wasted REG. Aborting fast at the probe (which the
		// account resume simply re-runs) is preferable, and context cancellation
		// (surfaced by postCompletion) is likewise correctly terminal.
		return true, nil, err
	}
	doneState, err = cfg.persistCompletion(ctx, store, state, comp)
	return true, doneState, err
}

// registerExchange builds and sends the NHP_REG round trip, returning the
// decrypted NHP_RAK body. credential is the enrollment credential (key secret on
// the bootstrap path, one-time code on the account path).
func (cfg *registerConfig) registerExchange(ctx context.Context, state *AgentState, peer *NHPServerPeerInfo, relayURL, credential string) (*registerAckBody, error) {
	devicePriv, serverPub, err := cfg.decodeNHPKeys(state, peer)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(registerRequestBody{
		UsrID: state.KeyID,
		DevID: state.AgentID,
		AspID: agentAspID,
		OTP:   credential,
		UsrData: registerUserData{
			Hostname: cfg.hostname,
			Version:  cfg.version,
			Takeover: cfg.takeover,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("qurl: encode registration body: %w", err)
	}
	reply, err := relayknock.Exchange(ctx, relayURL, serverPub, relayknock.TypeRegister, body, relayknock.KnockOptions{
		HTTPClient:       relayHTTPClient(cfg.httpClient),
		DeviceStaticPriv: devicePriv,
	})
	if err != nil {
		// A counter/type-mismatch reply from Exchange (relayknock.ErrMalformedReply)
		// is mapped into the enrollment taxonomy as ErrRegisterReplyMalformed rather
		// than surfacing as a raw string; transport faults become *RelayError.
		return nil, normalizeRelayError(err, ErrRegisterReplyMalformed)
	}
	if reply.IsCookieChallenge() {
		// The relay is under load and returned an overload cookie-challenge instead
		// of a registration reply. This is a "retry later" signal, distinct from a
		// protocol violation — surface it as such so the caller can back off.
		return nil, fmt.Errorf("%w: the registration relay returned an overload cookie-challenge; back off briefly and re-run", ErrRegistrationRetryLater)
	}
	if !reply.IsRegisterAck() {
		return nil, fmt.Errorf("%w: unexpected NHP reply type %d to a registration", cfg.invalidConfigErr, reply.Type)
	}
	return parseRegisterAck(reply.Body)
}

// sendOTP dispatches the one-way NHP_OTP that asks LayerV to email a one-time
// code. A relay 202 (empty) means dispatched; there is no NHP reply.
func (cfg *registerConfig) sendOTP(ctx context.Context, state *AgentState, peer *NHPServerPeerInfo, relayURL, key string) error {
	devicePriv, serverPub, err := cfg.decodeNHPKeys(state, peer)
	if err != nil {
		return err
	}
	// The API key secret rides in the NHP "pass" field, whose name is fixed by the
	// enrollment wire contract. It is not logged and is sealed inside the NHP
	// AES-256-GCM body before it leaves the process (relayknock.Send), so this is
	// a deliberate credential carriage, not an accidental secret in a payload.
	body, err := json.Marshal(otpRequestBody{ //nolint:gosec // G117: "pass" is the contract field name for the sealed OTP credential
		UsrID: state.KeyID,
		DevID: state.AgentID,
		AspID: agentAspID,
		Pass:  key,
	})
	if err != nil {
		return fmt.Errorf("qurl: encode otp request body: %w", err)
	}
	if err := relayknock.Send(ctx, relayURL, serverPub, body, relayknock.KnockOptions{
		HTTPClient:       relayHTTPClient(cfg.httpClient),
		DeviceStaticPriv: devicePriv,
	}); err != nil {
		// Send is one-way (no reply to correlate), so it only yields transport
		// faults (*RelayError); the malformed-reply class is passed for symmetry
		// with the REG path and never triggers here.
		return normalizeRelayError(err, ErrRegisterReplyMalformed)
	}
	return nil
}

// completeAndPersist runs the completion fetch and persists the resulting
// registered state, returning it.
func (cfg *registerConfig) completeAndPersist(ctx context.Context, key string, store AgentStateStore, state *AgentState, path pathKind) (*AgentState, error) {
	comp, err := cfg.postCompletion(ctx, key, state, path)
	if err != nil {
		return nil, err
	}
	return cfg.persistCompletion(ctx, store, state, comp)
}

// persistCompletion writes the completed registration into store and returns the
// registered state.
func (cfg *registerConfig) persistCompletion(ctx context.Context, store AgentStateStore, state *AgentState, comp *completionResponse) (*AgentState, error) {
	if err := cfg.reconcileCompletionDeviceID(state, comp); err != nil {
		return nil, err
	}
	state.AgentID = comp.AgentID
	state.RegisteredAt = comp.RegisteredAt
	// Replace the persisted NHP peer with the completion response's peer WITHOUT
	// re-running assertServerIDMatches (the registration-info integrity check).
	// That is safe here: the completion peer arrived over the authenticated qurl-
	// service TLS connection and already passed validateNHPServerPeerInfo, and the
	// RegisterAgent Client authorizes with the REST device bearer — it never
	// NHP-knocks this peer — so there is no live server_id⇄fingerprint gap to close.
	// A knock-only BootstrapAgent DOES later knock this peer; there it is trusted on
	// the same authenticated-TLS origin, and completionResponse carries no server_id
	// to assert against, so the TLS-authenticated origin is the trust anchor.
	peer := comp.NHPServerPeer
	state.NHPPeer = &peer
	state.DeviceAPIKey = comp.DeviceAPIKey
	state.OTPRequestedAt = nil
	state.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}
	return state, nil
}

// --- qurl-service HTTPS endpoints (Bearer <apiKey>) ---

// fetchRegistrationInfo runs the side-effect-free GET /v1/agent/registration-info
// pre-flight.
func (cfg *registerConfig) fetchRegistrationInfo(ctx context.Context, key string) (*registrationInfoResponse, error) {
	var env apiEnvelope[registrationInfoResponse]
	if err := doAuthorizedJSON(ctx, cfg.httpClient, cfg.baseURL, BearerToken(key).Authorize, http.MethodGet, "/v1/agent/registration-info", nil, &env); err != nil {
		return nil, cfg.mapRegistrationHTTPError(err)
	}
	if err := env.Data.validate(cfg.clock(), cfg.invalidConfigErr); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// postCompletion runs POST /v1/agent/registration/complete, minting (or
// returning) the device REST credential.
func (cfg *registerConfig) postCompletion(ctx context.Context, key string, state *AgentState, path pathKind) (*completionResponse, error) {
	reqBody := completeRequestBody{
		DeviceID:        state.AgentID,
		DevicePubKeyB64: state.PublicKeyB64,
	}
	var env apiEnvelope[completionResponse]
	if err := doAuthorizedJSON(ctx, cfg.httpClient, cfg.baseURL, BearerToken(key).Authorize, http.MethodPost, "/v1/agent/registration/complete", reqBody, &env); err != nil {
		return nil, cfg.mapCompletionHTTPError(err, path)
	}
	if err := env.Data.validate(cfg.clock(), cfg.invalidConfigErr); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// mapRegistrationHTTPError maps the registration-info HTTP failure to a typed
// error where the code is known (invalid key, disabled), else returns it
// unchanged (still a wrapped *APIError the caller can inspect).
func (cfg *registerConfig) mapRegistrationHTTPError(err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(apiErr.Code)) {
	case "invalid_api_key", "key_rejected", "unauthorized":
		return fmt.Errorf("%w: the API key was rejected by the registration service: %w", ErrKeyRejected, err)
	case "registration_disabled":
		return fmt.Errorf("%w: %w", ErrRegistrationDisabled, err)
	}
	if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: the API key was rejected by the registration service: %w", ErrKeyRejected, err)
	}
	return err
}

// mapCompletionHTTPError maps the completion HTTP failure. A 409
// device_key_already_issued means the device was registered but its key was
// already issued and this local state cannot reproduce it — a
// ErrDeviceCredentialMissing situation the caller resolves by re-registering
// under a new device id or with takeover.
func (cfg *registerConfig) mapCompletionHTTPError(err error, path pathKind) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	// The consumed-setup-key code is a bootstrap-path concept (a one-shot key
	// accepted once within the completion grace window), so gate it on
	// pathBootstrap — an account-path completion must not surface the bootstrap
	// sentinel (mirrors how mapRAKError keeps 52100 path-dependent). Check it
	// before the generic already-issued mapping, since both can arrive as HTTP 409.
	if path == pathBootstrap && isBootstrapConsumedCompletion(apiErr) {
		return fmt.Errorf("%w: %s: %w", ErrBootstrapSetupKeyConsumed, bootstrapConsumedGuidance, err)
	}
	if isDeviceKeyAlreadyIssued(apiErr) {
		return fmt.Errorf("%w: the device was registered but its API key was already issued and cannot be re-fetched; re-register under a new device id (qurl.WithDeviceID) or re-bind with qurl.WithTakeover: %w", ErrDeviceCredentialMissing, err)
	}
	return err
}

// isCompletionNotYetRegistered reports whether a completion error means the
// device is not yet enrolled (the expected outcome of the crash-recovery probe
// before REG has run), so the account path should proceed to REG rather than
// surface the error. A structured not-registered code is authoritative; a bare
// 404 is also accepted because by the completion step the base URL already
// worked for registration-info, so a 404 here means the endpoint reports the
// device absent — and proceeding to REG (the real path) is safe either way.
func isCompletionNotYetRegistered(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(apiErr.Code)) {
	case "device_not_registered", "registration_incomplete", "not_registered":
		return true
	}
	return apiErr.StatusCode == http.StatusNotFound
}

// isTransientCompletionError reports whether a completion error is a retryable
// server-side fault (5xx). On the crash-recovery probe this means "proceed to
// REG" rather than abort, since the probe is only an optimization.
func isTransientCompletionError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode >= 500 && apiErr.StatusCode <= 599
}

// isDeviceKeyAlreadyIssued matches ONLY the structured device_key_already_issued
// code, not a bare 409. The mapped error (ErrDeviceCredentialMissing) tells the
// operator to re-register under a new device id or re-bind — destructive advice
// that must not fire for an unrelated infra 409 that arrived with no structured
// code; those surface as the raw *APIError instead.
func isDeviceKeyAlreadyIssued(apiErr *APIError) bool {
	return strings.EqualFold(strings.TrimSpace(apiErr.Code), "device_key_already_issued")
}

func isBootstrapConsumedCompletion(apiErr *APIError) bool {
	code := strings.ToLower(strings.TrimSpace(apiErr.Code))
	return code == "setup_key_consumed" || code == "bootstrap_setup_key_consumed"
}

// --- device identity ---

// ensureDeviceID sets state.AgentID to the configured device id, or generates a
// stable one when none is configured and none is already persisted. The server
// never returns a generated id (the RAK shape is frozen), so the SDK owns id
// generation and persists it before any network call.
func (cfg *registerConfig) ensureDeviceID(state *AgentState) error {
	if cfg.deviceID != "" {
		if state.AgentID != "" && state.AgentID != cfg.deviceID {
			return cfg.errDeviceIDMismatch(state.AgentID, cfg.deviceID)
		}
		state.AgentID = cfg.deviceID
		return nil
	}
	if state.AgentID == "" {
		id, err := generateDeviceID()
		if err != nil {
			return err
		}
		state.AgentID = id
	}
	return nil
}

// reconcileDeviceID checks a configured device id against an already-registered
// state on the fast path.
func (cfg *registerConfig) reconcileDeviceID(state *AgentState) error {
	if cfg.deviceID != "" && state.AgentID != "" && cfg.deviceID != state.AgentID {
		return cfg.errDeviceIDMismatch(state.AgentID, cfg.deviceID)
	}
	return nil
}

// errDeviceIDMismatch is the shared "saved id does not match requested id" error
// both device-id guards raise (they cover different transitions but report the
// same conflict).
func (cfg *registerConfig) errDeviceIDMismatch(saved, requested string) error {
	return fmt.Errorf("%w: saved device id %q does not match requested device id %q", cfg.invalidConfigErr, saved, requested)
}

// reconcileCompletionDeviceID guards against a completion response that reports a
// different agent id than the one the SDK registered (the id is SDK-owned and
// frozen, so a mismatch is a server contract violation).
func (cfg *registerConfig) reconcileCompletionDeviceID(state *AgentState, comp *completionResponse) error {
	if state.AgentID != "" && comp.AgentID != "" && state.AgentID != comp.AgentID {
		return fmt.Errorf("%w: completion response agent id %q does not match registered device id %q", cfg.invalidConfigErr, comp.AgentID, state.AgentID)
	}
	return nil
}

// generateDeviceID mints a stable random device id. agent_id == NHP devId, so it
// must be a plain identifier; a hex token is safe on every wire the id crosses.
func generateDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("qurl: generate device id: %w", err)
	}
	return "agent-" + hex.EncodeToString(b[:]), nil
}

// resolveOTP returns the one-time code to use: the WithOTP value, or the result
// of a WithOTPProvider call, or "" when neither is set.
func (cfg *registerConfig) resolveOTP(ctx context.Context) (string, error) {
	if cfg.otp != "" {
		return cfg.otp, nil
	}
	if cfg.otpProvider != nil {
		code, err := cfg.otpProvider(ctx)
		if err != nil {
			return "", fmt.Errorf("qurl: one-time code provider: %w", err)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return "", fmt.Errorf("%w: one-time code provider returned an empty code — on a fresh store the provider is called right after the code is dispatched, so it must await email delivery", ErrInvalidRegisterConfig)
		}
		return code, nil
	}
	return "", nil
}

// --- peer / relay / server-id resolution ---

func (cfg *registerConfig) resolvePeer(info *registrationInfoResponse) *NHPServerPeerInfo {
	// Return the address of a local copy either way, so the result never aliases
	// info.NHPServerPeer's field or the caller's override pointer.
	peer := info.NHPServerPeer
	if cfg.nhpPeerOverride != nil {
		peer = *cfg.nhpPeerOverride
	}
	return &peer
}

func (cfg *registerConfig) resolveRelayURL(info *registrationInfoResponse) string {
	if cfg.relayURLOverride != "" {
		return cfg.relayURLOverride
	}
	return strings.TrimRight(info.Relay.BaseURL, "/")
}

// assertServerIDMatches checks the relay server_id returned by registration-info
// equals the fingerprint independently computed from the NHP peer public key.
// They MUST agree (both are base64url(sha256(pubkey)[:8])); a mismatch means the
// pre-flight's routing id and peer key disagree, so fail closed rather than knock
// a server the key does not match.
func (cfg *registerConfig) assertServerIDMatches(serverID string, peer *NHPServerPeerInfo) error {
	peerKey, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKeyB64)
	if err != nil {
		// validateNHPServerPeerInfo already accepted this key; defensive.
		return fmt.Errorf("%w: NHP peer public key is not standard base64: %w", cfg.invalidConfigErr, err)
	}
	computed := relayknock.PubKeyFingerprint(peerKey)
	if serverID != computed {
		return fmt.Errorf("%w: registration-info relay server_id %q does not match the NHP peer key fingerprint %q", cfg.invalidConfigErr, serverID, computed)
	}
	return nil
}

// decodeNHPKeys returns the agent device private key and the server static public
// key as raw bytes for a relayknock call.
func (cfg *registerConfig) decodeNHPKeys(state *AgentState, peer *NHPServerPeerInfo) (devicePriv, serverPub []byte, err error) {
	devicePriv, err = base64.StdEncoding.Strict().DecodeString(state.PrivateKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode device private key: %w", cfg.invalidConfigErr, err)
	}
	serverPub, err = base64.StdEncoding.Strict().DecodeString(peer.PublicKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode NHP peer public key: %w", cfg.invalidConfigErr, err)
	}
	return devicePriv, serverPub, nil
}

// relayHTTPClient adapts the qurl HTTPDoer to the relayknock HTTPDoer. The two
// interfaces are structurally identical (Do(*http.Request)), so the value passes
// through; nil stays nil, letting relayknock fall back to its default client.
func relayHTTPClient(client HTTPDoer) relayknock.HTTPDoer {
	if client == nil {
		return nil
	}
	return client
}

func derefTime(t *time.Time, fallback time.Time) time.Time {
	if t == nil {
		return fallback
	}
	return *t
}

// --- store-backed credential provider ---

// newStoreBackedClient builds a Client whose credentials come from the device
// API key persisted in store, wrapped in CachedCredentials so a rotated key is
// picked up within the TTL without rebuilding the client. Construction makes
// no qURL API calls; loading a network-backed store can still perform I/O.
func newStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer) *Client {
	provider := CachedCredentials(&storeCredentialProvider{store: store}, storeCredentialCacheTTL)
	return &Client{
		credentials: provider,
		baseURL:     baseURL,
		httpClient:  httpClient,
	}
}

// storeCredentialCacheTTL bounds how long a device API key read from the store is
// reused before being re-read, so a rotation is picked up promptly.
const storeCredentialCacheTTL = time.Minute

// storeCredentialProvider authorizes Client requests with the DeviceAPIKey read
// from the AgentStateStore. Reading on demand (behind a short cache) means a
// rotated credential in the store is observed without rebuilding the client.
type storeCredentialProvider struct {
	store AgentStateStore
}

func (p *storeCredentialProvider) Authorize(ctx context.Context, req *http.Request) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("%w: credential store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return err
	}
	state, err := p.store.LoadAgentState(ctx)
	if err != nil {
		// Add Client-layer context rather than surfacing the raw store error
		// verbatim (the underlying store sentinel stays matchable via %w),
		// consistent with how the enrollment engine re-wraps load failures.
		return fmt.Errorf("qurl: load device credential for authorization: %w", err)
	}
	if state == nil {
		return fmt.Errorf("%w: agent state store returned no state", ErrDeviceCredentialMissing)
	}
	token := strings.TrimSpace(state.DeviceAPIKey)
	if token == "" {
		return fmt.Errorf("%w: agent state holds no device credential", ErrDeviceCredentialMissing)
	}
	return setBearer(req, token)
}

// --- options ---

// RegisterOption customizes RegisterAgent.
type RegisterOption interface {
	applyRegisterOption(*registerConfig) error
}

type registerOptionFunc func(*registerConfig) error

func (f registerOptionFunc) applyRegisterOption(o *registerConfig) error { return f(o) }

// WithDeviceID sets the stable device id (which is also the enrolled agent id and
// the NHP device id). When omitted, RegisterAgent generates a stable id on the
// first run and persists it.
//
// WithDeviceID takes effect only on that first run, before any id is persisted:
// it names the id to enroll instead of a generated one. Once a device id has been
// persisted (generated or supplied), a later run that passes a DIFFERING
// WithDeviceID is REJECTED with ErrInvalidRegisterConfig rather than silently
// re-binding — the persisted identity is authoritative. Re-running with the same
// id (or with none) is fine. The server never returns a generated id.
func WithDeviceID(id string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%w: device id must not be empty", ErrInvalidRegisterConfig)
		}
		o.deviceID = id
		return nil
	})
}

// WithOTP supplies the email one-time code to finish account-key registration.
// Set it on the resume call after LayerV emails the code. Ignored on the
// pre-issued (bootstrap) key path, which needs no code.
func WithOTP(code string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if strings.TrimSpace(code) == "" {
			return fmt.Errorf("%w: one-time code must not be empty", ErrInvalidRegisterConfig)
		}
		o.otp = strings.TrimSpace(code)
		return nil
	})
}

// WithOTPProvider supplies a callback that returns the email one-time code, for
// callers that fetch the code programmatically (for example from a mailbox API)
// rather than passing a literal. It is called only on the account-key path when a
// code is needed. Set at most one of WithOTP or WithOTPProvider.
//
// On a fresh store the code is dispatched and then the provider is invoked in the
// same RegisterAgent call, so the provider must tolerate or await email delivery
// (poll/block until the code arrives). A provider that returns before the code is
// deliverable hands back a stale or empty value: an empty (whitespace-only) return
// fails fast with ErrInvalidRegisterConfig before any registration round trip,
// while a non-empty but wrong code reaches the enrollment service and fails with
// ErrOTPIncorrect. On a resume (the code was requested on an earlier call) the
// provider runs only if a crash-recovery completion probe did not already finish.
//
// For an SDK local-file store the enclosing RegisterAgent call holds the mandatory
// cross-process setup lock for the whole provider call, so a provider that blocks
// for seconds/minutes keeps a second process sharing the same store blocked for
// that window (the loser then fast-paths once this call enrolls).
func WithOTPProvider(provider func(ctx context.Context) (string, error)) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if provider == nil {
			return fmt.Errorf("%w: one-time code provider must not be nil", ErrInvalidRegisterConfig)
		}
		o.otpProvider = provider
		return nil
	})
}

// WithTakeover re-binds a device identity that is already enrolled to a different
// key or agent, resolving an ErrAgentIdentityConflict. Use it deliberately: it
// replaces the prior binding.
func WithTakeover() RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		o.takeover = true
		return nil
	})
}

// WithRegisterHostname records the local hostname in registration audit metadata.
func WithRegisterHostname(hostname string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if strings.TrimSpace(hostname) == "" {
			return fmt.Errorf("%w: hostname must not be empty", ErrInvalidRegisterConfig)
		}
		o.hostname = hostname
		return nil
	})
}

// WithRegisterVersion records the local build version in registration audit
// metadata.
func WithRegisterVersion(version string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if strings.TrimSpace(version) == "" {
			return fmt.Errorf("%w: version must not be empty", ErrInvalidRegisterConfig)
		}
		o.version = version
		return nil
	})
}

// WithRegisterBaseURL points RegisterAgent at a non-default LayerV API origin for
// the registration-info and completion HTTPS endpoints. Most applications do not
// need this.
//
// This origin also becomes the base URL of the returned Client, so the agent's
// later resource calls (ProtectURL, portals) go to the same host — enrollment and
// resource APIs both live on qurl-service. There is no way to point only the
// enrollment endpoints elsewhere while leaving the Client on the default origin.
func WithRegisterBaseURL(rawURL string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "register base URL", ErrInvalidRegisterConfig); err != nil {
			return err
		}
		o.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithRegisterHTTPClient injects the HTTP client used for the registration HTTPS
// endpoints and the relay POSTs. Without it, RegisterAgent uses a shared client
// with a 30-second timeout and no redirect following. Callers can still bound
// each call with ctx.
//
// The injected client is also reused as the returned Client's HTTP client, so an
// application with fixed-egress requirements (a pinned transport or outbound
// proxy) gets the same egress for enrollment and for the agent's later resource
// calls from this one option.
func WithRegisterHTTPClient(client HTTPDoer) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidRegisterConfig)
		}
		o.httpClient = client
		return nil
	})
}

// WithRelayURL overrides the NHP relay base URL that registration-info would
// otherwise supply. Advanced: use it only when routing NHP through a specific
// relay, for example in tests. Like WithNHPPeer, an overridden relay bypasses the
// registration-info integrity check, so route only through a relay you trust.
func WithRelayURL(rawURL string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "relay URL", ErrInvalidRegisterConfig); err != nil {
			return err
		}
		o.relayURLOverride = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithNHPPeer overrides the NHP server peer that registration-info would
// otherwise supply. Advanced: pairs with WithRelayURL for a pinned or test NHP
// endpoint.
//
// An overridden peer is NOT covered by the registration-info server_id ⇄
// peer-key fingerprint check: that check validates only the peer the service
// reported, and this override replaces it afterward. So the "we only knock a
// server whose key matches the routing id" guarantee does not apply here — pin
// only a peer you trust.
//
// The pre-flight still asserts its OWN internal consistency (the reported
// server_id must match the reported peer key) before the override is applied, so
// a self-inconsistent registration-info response is rejected even when you
// override. If you override because the reported peer is unreachable, the response
// must still be internally consistent for registration to proceed.
//
// The override governs the peer used for the REG round trip. After a successful
// registration the persisted AgentState.NHPPeer is replaced by the completion
// response's authoritative peer, so a knock-only agent's later knocks (and any
// re-registration) use that server-reported peer, not this override.
func WithNHPPeer(peer NHPServerPeerInfo) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		// o.clock is initialized to time.Now before options apply; using it keeps
		// the direct wall-clock call out of the engine for a consistent seam.
		if err := validateNHPServerPeerInfo(peer, o.clock(), true, "WithNHPPeer", ErrInvalidRegisterConfig); err != nil {
			return err
		}
		p := peer
		o.nhpPeerOverride = &p
		return nil
	})
}
