package qurl

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, err
	}
	cfg.requireDeviceKey = true
	if _, err := cfg.run(ctx, key, store); err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.clientBaseURL, cfg.clientHTTPClient), nil
}

// RegisterAgentRuntime registers or reopens an agent and returns both its
// store-backed resource Client and the validated runtime binding needed for an
// immediate relay knock. Unlike composing RegisterAgent with a later store
// load, this captures the private key before registration network I/O and primes
// the Client credential cache from the same in-memory AgentState. The caller
// must immediately defer binding.Destroy, then take and eventually wipe the
// runtime private key. The primed credential is cached for one minute; a later
// owner-side revocation becomes visible after that TTL. Account enrollment
// behavior matches RegisterAgent. On the completed fast path an expired peer
// is rejected because it cannot be knocked; call RefreshAgentRegistration with
// an enrollment key to obtain a fresh binding.
func RegisterAgentRuntime(ctx context.Context, key string, store AgentStateStore, opts ...RegisterOption) (*Client, *AgentRuntimeBinding, error) {
	cfg, err := validateRegisterInputs(ctx, key, store, opts)
	if err != nil {
		return nil, nil, err
	}
	cfg.requireDeviceKey = true
	cfg.captureRuntime = true
	defer cfg.wipeRuntimePrivateKey()
	state, err := cfg.run(ctx, key, store)
	if err != nil {
		return nil, nil, err
	}
	privateKey := cfg.takeRuntimePrivateKey()
	defer func() { wipeBytes(privateKey) }()
	client := newPrimedStoreBackedClient(store, cfg.clientBaseURL, cfg.clientHTTPClient, state.DeviceAPIKey, cfg.clock)
	binding := newAgentRuntimeBinding(state, privateKey)
	privateKey = nil // binding owns the slice and its cleanup from this point.
	return client, binding, nil
}

// registerConfig is the resolved option set plus the fixed dependencies a
// registration run needs.
type registerConfig struct {
	baseURL           string
	httpClient        HTTPDoer
	clientBaseURL     string
	clientHTTPClient  HTTPDoer
	deviceID          string
	otp               string
	otpProvider       func(context.Context) (string, error)
	takeover          bool
	hostname          string
	version           string
	allowedKeyKinds   map[RegistrationKeyKind]struct{}
	captureRuntime    bool
	runtimePrivateKey []byte

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

func (cfg *registerConfig) captureRuntimeKey(state *AgentState) error {
	if !cfg.captureRuntime {
		return nil
	}
	privateKey, err := decodeRuntimePrivateKey(state, cfg.invalidConfigErr)
	if err != nil {
		return err
	}
	cfg.wipeRuntimePrivateKey()
	cfg.runtimePrivateKey = privateKey
	return nil
}

func (cfg *registerConfig) takeRuntimePrivateKey() []byte {
	privateKey := cfg.runtimePrivateKey
	cfg.runtimePrivateKey = nil
	return privateKey
}

func (cfg *registerConfig) wipeRuntimePrivateKey() {
	wipeBytes(cfg.runtimePrivateKey)
	cfg.runtimePrivateKey = nil
}

func newRegisterConfig(opts []RegisterOption) (*registerConfig, error) {
	cfg := &registerConfig{
		baseURL:          defaultAPIBaseURL,
		httpClient:       defaultAPIHTTPClient,
		clientBaseURL:    defaultAPIBaseURL,
		clientHTTPClient: defaultAPIHTTPClient,
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
	// Validate the peer only after every option resolves so an injected test
	// clock has identical semantics regardless of its position relative to
	// WithNHPPeer. Production configurations retain the default wall clock.
	if cfg.nhpPeerOverride != nil {
		if err := validateNHPServerPeerInfo(*cfg.nhpPeerOverride, cfg.clock(), true, "WithNHPPeer", ErrInvalidRegisterConfig); err != nil {
			return nil, err
		}
	}
	if cfg.otp != "" && cfg.otpProvider != nil {
		return nil, fmt.Errorf("%w: set only one of WithOTP or WithOTPProvider", ErrInvalidRegisterConfig)
	}
	return cfg, nil
}

// validateRegisterInputs resolves options and enforces the input contract
// shared by RegisterAgent, RefreshAgentRegistration, and
// RecoverAgentCredential.
func validateRegisterInputs(ctx context.Context, key string, store AgentStateStore, opts []RegisterOption) (*registerConfig, error) {
	cfg, err := newRegisterConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := validateExactBearerToken(key, "API key", ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	return cfg, nil
}

// otpResendCooldown is how long the account path waits before re-sending an
// email one-time code on a rapid re-run, so repeated RegisterAgent calls do not
// spam the account with codes.
const otpResendCooldown = 60 * time.Second

// run drives the registration state machine to a *Client. State is derived from
// AgentState fields (no enum): absent → keypair-persisted → otp_pending → registered.
func (cfg *registerConfig) run(ctx context.Context, key string, store AgentStateStore) (*AgentState, error) {
	// Preserve the documented zero-qURL-API, read-only fast path: a completed
	// state no longer needs setup serialization and must remain usable when the
	// state directory is mounted read-only or local locking is unsupported. The
	// store load itself may call a remote storage or key provider.
	state, found, err := loadAgentStateIfPresent(ctx, store, cfg.invalidConfigErr)
	if err != nil {
		return nil, err
	}
	if found && state.RegisteredAt != nil {
		// RegisterAgentRuntime may decode the key into its synchronized return
		// binding here, but it does not mutate or save the completed AgentState;
		// the same read-only, lock-free guarantee therefore still applies.
		return cfg.finishRegisteredAgentState(state)
	}

	// Mandatory serialization starts only for incomplete/fresh setup. Two racers
	// would otherwise mint competing identities and race the atomic save. After
	// acquiring, reload: another process may have completed enrollment while this
	// caller waited, in which case the second fast-path check returns its state.
	return withAgentSetupLock(ctx, store, func() (*AgentState, error) {
		return cfg.runLocked(ctx, key, store)
	})
}

func (cfg *registerConfig) runLocked(ctx context.Context, key string, store AgentStateStore) (*AgentState, error) {
	// Reload under the lock even when the pre-lock load found incomplete state.
	// A sealed store intentionally unwraps again here: only the locked snapshot
	// may drive mutation after another process had a chance to finish setup.
	state, err := loadOrCreateAgentState(ctx, store, cfg.invalidConfigErr)
	if err != nil {
		return nil, err
	}
	if state.RegisteredAt != nil {
		return cfg.finishRegisteredAgentState(state)
	}

	// Persist the device identity (keypair + stable device id) BEFORE any
	// network call so an interrupted registration resumes with the same
	// identity the server will bind.
	if err := cfg.ensureDeviceID(state); err != nil {
		return nil, err
	}
	if state.SchemaVersion < agentStateSchemaVersion {
		state.SchemaVersion = agentStateSchemaVersion
	}
	// Runtime registration validates local key custody before any external side
	// effect. On the account path this intentionally decodes the key before an
	// OTP email may be sent and then wipes it when the call pauses: fail fast on
	// an unusable store instead of emailing a code for a run that cannot finish.
	if err := cfg.captureRuntimeKey(state); err != nil {
		return nil, err
	}
	if err := store.SaveAgentState(ctx, state); err != nil {
		return nil, err
	}

	// Pre-flight: registration-info tells us the path (key_kind), the key id,
	// the NHP peer, and the relay coordinates. Side-effect-free.
	info, peer, relayURL, err := cfg.preflight(ctx, key)
	if err != nil {
		return nil, err
	}
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
		if err := requireAccountKeyEmail(info); err != nil {
			return nil, err
		}
		return cfg.runAccountPath(ctx, key, store, state, peer, relayURL, info.MaskedEmail)
	default:
		// validate() already rejected unknown kinds; defensive.
		return nil, cfg.errUnknownKeyKind(info.KeyKind)
	}
}

// requireAccountKeyEmail fails fast before spending an OTP round trip when an
// account key has no masked email on file: it can never receive the code. Shared
// by enrollment and forced refresh/recovery so the precondition cannot drift.
func requireAccountKeyEmail(info *registrationInfoResponse) error {
	if strings.TrimSpace(info.MaskedEmail) == "" {
		return fmt.Errorf("%w: the account key has no email on file for the one-time code; add an email or use a pre-issued key", ErrNoAccountEmail)
	}
	return nil
}

func (cfg *registerConfig) errUnknownKeyKind(kind string) error {
	return fmt.Errorf("%w: registration-info returned unknown key_kind %q", cfg.invalidConfigErr, kind)
}

func loadAgentStateIfPresent(ctx context.Context, store AgentStateStore, invalidConfigErr error) (*AgentState, bool, error) {
	state, err := store.LoadAgentState(ctx)
	switch {
	case err == nil:
		if err := validateLoadedAgentAssignment(state); err != nil {
			return nil, false, fmt.Errorf("%w: %w", invalidConfigErr, err)
		}
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
	// knock-only BootstrapAgent and combined runtime paths require a live peer.
	if cfg.captureRuntime {
		if err := validateCompletedAgentIdentity(state, cfg.invalidConfigErr); err != nil {
			return nil, err
		}
		if err := validateAgentRuntimeMetadata(state, cfg.clock(), cfg.invalidConfigErr); err != nil {
			return nil, err
		}
	} else {
		if err := validateRegisteredAgentState(state, cfg.clock(), !cfg.requireDeviceKey, cfg.invalidConfigErr); err != nil {
			return nil, err
		}
	}
	if cfg.requireDeviceKey {
		if err := validatePersistedDeviceCredential(state, cfg.invalidConfigErr); err != nil {
			return nil, err
		}
	}
	if err := cfg.reconcileDeviceID(state); err != nil {
		return nil, err
	}
	if err := cfg.captureRuntimeKey(state); err != nil {
		return nil, err
	}
	return state, nil
}

func validateAgentRuntimeMetadata(state *AgentState, now time.Time, errKind error) error {
	if state == nil || state.NHPPeer == nil {
		return fmt.Errorf("%w: agent runtime state missing NHP peer", errKind)
	}
	if err := validateNHPServerPeerInfo(*state.NHPPeer, now, true, "agent runtime state", errKind); err != nil {
		return err
	}
	if strings.TrimSpace(state.KeyID) == "" {
		return fmt.Errorf("%w: agent runtime state missing key id", errKind)
	}
	if err := validateHTTPSOrLoopbackURL(state.RelayURL, "agent runtime relay URL", errKind); err != nil {
		return err
	}
	return nil
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
	freshRequest := state.OTPRequestedAt == nil
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

	code, err := cfg.accountCredentialOrPause(ctx, key, store, state, state, maskedEmail)
	if err != nil {
		return nil, err
	}
	return cfg.registerAndComplete(ctx, key, store, state, peer, relayURL, code, pathAccount)
}

// accountCredentialOrPause shares the account OTP dispatch/resume ordering
// across enrollment, refresh, and recovery. A fresh operation persists and
// dispatches before consulting a provider that may await that email. A resume
// resolves an available literal/provider code first and redispatches after the
// cooldown only when no code source exists, avoiding unnecessary email fan-out.
// persisted owns the durable cooldown marker; requestState supplies the current
// peer/relay coordinates used for dispatch.
func (cfg *registerConfig) accountCredentialOrPause(ctx context.Context, key string, store AgentStateStore, persisted, requestState *AgentState, maskedEmail string) (string, error) {
	now := cfg.clock()
	freshRequest := persisted.OTPRequestedAt == nil
	if freshRequest {
		if err := cfg.requestOTPAt(ctx, store, persisted, requestState, key, now); err != nil {
			return "", err
		}
		// A literal supplied on the call that just dispatched a fresh code cannot
		// match that email. Providers are exempt because they may await delivery.
		if cfg.otp != "" {
			return "", cfg.otpPending(persisted, maskedEmail)
		}
	}

	code, err := cfg.resolveOTP(ctx)
	if err != nil {
		return "", err
	}
	if code != "" {
		return code, nil
	}
	// !freshRequest guarantees OTPRequestedAt is non-nil here, so dereference the
	// durable cooldown marker directly rather than through a nil fallback.
	if !freshRequest && now.Sub(*persisted.OTPRequestedAt) >= otpResendCooldown {
		if err := cfg.requestOTPAt(ctx, store, persisted, requestState, key, now); err != nil {
			return "", err
		}
	}
	return "", cfg.otpPending(persisted, maskedEmail)
}

// otpPending builds the account-path pause point returned when the emailed code
// has been requested and the current lifecycle operation awaits the caller.
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
	if err := cfg.registerExchangeChecked(ctx, state, peer, relayURL, credential, path); err != nil {
		return nil, err
	}
	if cfg.captureRuntime {
		if err := validateAgentRuntimeMetadata(state, cfg.clock(), cfg.invalidConfigErr); err != nil {
			return nil, err
		}
	}
	return cfg.completeAndPersist(ctx, key, store, state, path)
}

// registerExchangeChecked runs NHP_REG/NHP_RAK and maps an authenticated denial
// through the enrollment taxonomy. Enrollment/recovery and completion-free
// binding refresh share this single RAK success gate.
func (cfg *registerConfig) registerExchangeChecked(ctx context.Context, state *AgentState, peer *NHPServerPeerInfo, relayURL, credential string, path pathKind) error {
	ack, err := cfg.registerExchange(ctx, state, peer, relayURL, credential)
	if err != nil {
		return err
	}
	if !ack.isSuccess() {
		return mapRAKError(ack, path)
	}
	return nil
}

// requestOTPAt centralizes the anti-spam save-before-send ordering. persisted is
// the durable state whose cooldown marker changes; requestState may be a
// refreshed candidate whose current peer/relay coordinates must carry the OTP.
// This pre-send write commits only OTPRequestedAt on persisted; candidate's new
// binding metadata is not durable until an authenticated RAK succeeds. If the
// relay send fails, the marker deliberately remains durable and this call
// returns the transport error; a retry inside the cooldown may therefore return
// OTPPendingError even though delivery is unconfirmed. ErrOTPPending denotes a
// durable cooldown/resume state, never proof that the email was delivered.
func (cfg *registerConfig) requestOTPAt(ctx context.Context, store AgentStateStore, persisted, requestState *AgentState, key string, now time.Time) error {
	previous := persisted.OTPRequestedAt
	persisted.OTPRequestedAt = &now
	if err := store.SaveAgentState(ctx, persisted); err != nil {
		persisted.OTPRequestedAt = previous // restore the unsaved in-memory value
		return err
	}
	return cfg.sendOTP(ctx, requestState, requestState.NHPPeer, requestState.RelayURL, key)
}

// tryCompletionProbe attempts a completion fetch to self-heal a crash that
// happened after the registration RAK but before completion. done is true when
// the probe resolved the run (success → registered state, or a terminal
// completion error); done is false only when the service authoritatively says
// the device is not enrolled, in which case the caller proceeds to REG.
//
// Completion is first-issue-only. A 5xx, transport failure, malformed 2xx, or
// invalid response is therefore terminal recovery-required ambiguity: the
// service may have minted the key even though this process could not persist it.
// Falling through after such an error would risk a second completion attempt.
func (cfg *registerConfig) tryCompletionProbe(ctx context.Context, key string, store AgentStateStore, state *AgentState, path pathKind) (done bool, doneState *AgentState, err error) {
	comp, err := cfg.postCompletion(ctx, key, state, path, true)
	if err != nil {
		if errors.Is(err, ErrCredentialRecoveryRequired) {
			// Completion was dispatched and may have minted the one-time plaintext
			// credential. Never fall through to REG + a second completion attempt.
			return true, nil, err
		}
		if isCompletionNotYetRegistered(err) {
			// This structured absence is the sole safe fall-through: no credential
			// was minted, so REG followed by one completion is still first issue.
			return false, nil, nil
		}
		// Any other completion error is terminal — most notably a structured
		// device_key_already_issued 409 (the device is registered but its key was
		// already issued and cannot be re-fetched). That is a real answer the
		// caller must act on, so surface it rather than proceeding to REG.
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
	defer wipeBytes(devicePriv)
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
	// relayknock.Exchange synchronously seals body into a separate packet before
	// starting RelayPost; the HTTP transport never references this plaintext.
	// Wiping after Exchange returns is therefore safe, unlike doAuthorizedJSON's
	// raw request buffer, which net/http may still be consuming after Do returns.
	defer wipeBytes(body)
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
	defer wipeBytes(devicePriv)
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
	// relayknock.Send synchronously seals body into a separate packet before its
	// HTTP POST, so no transport reader can race this plaintext wipe after return.
	defer wipeBytes(body)
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
	comp, err := cfg.postCompletion(ctx, key, state, path, false)
	if err != nil {
		return nil, err
	}
	return cfg.persistCompletion(ctx, store, state, comp)
}

// persistCompletion writes the completed registration into store and returns the
// registered state.
func (cfg *registerConfig) persistCompletion(ctx context.Context, store AgentStateStore, state *AgentState, comp *completionResponse) (*AgentState, error) {
	if comp == nil {
		return nil, credentialPersistenceFailure(state.AgentID, fmt.Errorf("%w: completion response is nil", cfg.invalidConfigErr))
	}
	// A successful completion response contains the only plaintext copy the
	// service will reveal. Keep exactly one durable reference on success and drop
	// the response object's reference on every path. Go string backing storage
	// cannot be zeroed, so clearing this reference is best-effort lifetime
	// reduction rather than a guaranteed memory wipe.
	defer func() { comp.DeviceAPIKey = "" }()
	if err := cfg.reconcileCompletionDeviceID(state, comp); err != nil {
		return nil, credentialPersistenceFailure(state.AgentID, err)
	}
	if err := cfg.assertCompletionPeerMatchesRegistration(state, comp); err != nil {
		return nil, credentialPersistenceFailure(state.AgentID, err)
	}
	previous := *state
	state.AgentID = comp.AgentID
	state.RegisteredAt = comp.RegisteredAt
	// Preserve the peer that authenticated the successful RAK. Completion is a
	// credential-mint response, not authority to rotate the Noise peer after the
	// handshake; assert it agrees above and never replace the RAK peer here.
	state.DeviceAPIKey = comp.DeviceAPIKey
	state.OTPRequestedAt = nil
	state.SchemaVersion = agentStateSchemaVersion
	if err := store.SaveAgentState(ctx, state); err != nil {
		*state = previous
		return nil, credentialPersistenceFailure(previous.AgentID, err)
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

// preflight returns the validated registration description and selected NHP
// endpoint shared by enrollment, refresh, and recovery. The service-reported
// server id is checked against its own peer before any trusted override is
// selected, and key-kind policy runs before OTP or NHP side effects.
func (cfg *registerConfig) preflight(ctx context.Context, key string) (*registrationInfoResponse, *NHPServerPeerInfo, string, error) {
	// This GET is side-effect-free: an outcome-unknown transport wrapper is a
	// normal read failure here. Only mutation callers interpret it as possible
	// committed-side-effect ambiguity.
	info, err := cfg.fetchRegistrationInfo(ctx, key)
	if err != nil {
		return nil, nil, "", err
	}
	if err := cfg.requireAllowedKeyKind(info.KeyKind); err != nil {
		return nil, nil, "", err
	}
	if err := cfg.assertServerIDMatches(info.Relay.ServerID, &info.NHPServerPeer); err != nil {
		return nil, nil, "", err
	}
	return info, cfg.resolvePeer(info), cfg.resolveRelayURL(info), nil
}

// postCompletion runs POST /v1/agent/registration/complete, which mints the
// first-issue-only device REST credential. allowBareNotEnrolled is true only for
// the pre-REG crash probe; after REG, an unstructured 404 is mint-ambiguous.
func (cfg *registerConfig) postCompletion(ctx context.Context, key string, state *AgentState, path pathKind, allowBareNotEnrolled bool) (*completionResponse, error) {
	reqBody := completeRequestBody{
		DeviceID:        state.AgentID,
		DevicePubKeyB64: state.PublicKeyB64,
	}
	var env apiEnvelope[completionResponse]
	if err := doAuthorizedJSON(ctx, cfg.httpClient, cfg.baseURL, BearerToken(key).Authorize, http.MethodPost, "/v1/agent/registration/complete", reqBody, &env); err != nil {
		mapped := cfg.mapCompletionHTTPError(err, path, state.AgentID)
		if errors.Is(mapped, ErrCredentialRecoveryRequired) {
			return nil, mapped
		}
		if isAuthoritativeNoWriteCompletionError(mapped, allowBareNotEnrolled) {
			// Only explicitly modeled qurl-service responses may bypass ambiguity:
			// each proves the atomic mint transaction made no device-key write.
			return nil, mapped
		}
		var outcomeUnknown *apiRequestOutcomeUnknownError
		var apiErr *APIError
		if errors.As(mapped, &outcomeUnknown) || errors.As(mapped, &apiErr) {
			// Once completion was dispatched, every unclassified HTTP response is
			// ambiguous regardless of status. A new service-side 4xx must be added
			// to the authoritative no-write taxonomy before the SDK may trust it.
			return nil, credentialPersistenceFailure(state.AgentID, mapped)
		}
		return nil, mapped
	}
	if err := env.Data.validate(cfg.clock(), cfg.invalidConfigErr); err != nil {
		env.Data.DeviceAPIKey = ""
		return nil, credentialPersistenceFailure(state.AgentID, err)
	}
	return &env.Data, nil
}

func credentialPersistenceFailure(deviceID string, cause error) *CredentialPersistenceError {
	return &CredentialPersistenceError{DeviceID: deviceID, Cause: cause}
}

func (cfg *registerConfig) assertCompletionPeerMatchesRegistration(state *AgentState, comp *completionResponse) error {
	if state == nil || state.NHPPeer == nil {
		return fmt.Errorf("%w: authenticated registration state is missing its NHP peer", cfg.invalidConfigErr)
	}
	// persistCompletion, the sole production caller, rejects a nil completion
	// response before reaching this invariant check.
	registeredKey, err := decodeNHPServerPublicKey(state.NHPPeer.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("%w: decode authenticated registration NHP peer public key: %w", cfg.invalidConfigErr, err)
	}
	completionKey, err := decodeNHPServerPublicKey(comp.NHPServerPeer.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("%w: decode completion NHP peer public key: %w", cfg.invalidConfigErr, err)
	}
	// Compare only the key: the RAK-authenticated coordinates remain authoritative,
	// and same-key host/port differences are deployment skew rather than rotation.
	if !bytes.Equal(completionKey, registeredKey) {
		return fmt.Errorf("%w: completion response NHP peer does not match the peer that authenticated the registration acknowledgement", cfg.invalidConfigErr)
	}
	return nil
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
	case "registration_rate_limited", "rate_limited", "too_many_requests":
		return fmt.Errorf("%w: %w", ErrRegistrationRateLimited, err)
	}
	if mapped := mapCommonRegistrationHTTPError(apiErr, err, "the API key was rejected by the registration service", "registration preflight is temporarily unavailable"); mapped != nil {
		return mapped
	}
	return err
}

// mapCommonRegistrationHTTPError maps statuses shared by registration preflight
// and completion admission. Callers supply path-specific message context and
// retain their distinct mappings when this returns nil.
func mapCommonRegistrationHTTPError(apiErr *APIError, err error, rejectedMsg, unavailableMsg string) error {
	switch {
	case apiErr.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %w", ErrRegistrationRateLimited, err)
	case apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s: %w", ErrKeyRejected, rejectedMsg, err)
	case apiErr.StatusCode == http.StatusServiceUnavailable && strings.EqualFold(strings.TrimSpace(apiErr.Code), "service_unavailable"):
		return fmt.Errorf("%w: %s: %w", ErrRegistrationRetryLater, unavailableMsg, err)
	}
	return nil
}

func isAuthoritativeNoWriteCompletionError(err error, allowBareNotEnrolled bool) bool {
	if errors.Is(err, ErrRegistrationRateLimited) ||
		errors.Is(err, ErrDeviceKeyQuotaExceeded) ||
		errors.Is(err, ErrRegistrationRequestTooLarge) ||
		errors.Is(err, ErrRegistrationRetryLater) ||
		errors.Is(err, ErrKeyRejected) ||
		errors.Is(err, ErrBootstrapSetupKeyConsumed) ||
		isStructuredCompletionNotYetRegistered(err) {
		return true
	}
	return allowBareNotEnrolled && isCompletionNotYetRegistered(err)
}

// mapCompletionHTTPError maps the completion HTTP failure. A 409
// device_key_already_issued means the device was registered but its key was
// already issued and this local state cannot reproduce it. Surface the explicit
// same-id recovery class; ordinary RegisterAgent must never mint around it.
func (cfg *registerConfig) mapCompletionHTTPError(err error, path pathKind, deviceID string) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if isDeviceKeyQuotaExceeded(apiErr) {
		return &DeviceKeyQuotaExceededError{DeviceID: deviceID, Cause: err}
	}
	if apiErr.StatusCode == http.StatusRequestEntityTooLarge {
		return &RegistrationRequestTooLargeError{DeviceID: deviceID, Cause: err}
	}
	// The consumed-setup-key code is a bootstrap-path concept (a one-shot key
	// accepted once within the completion grace window), so gate it on
	// pathBootstrap — an account-path completion must not surface the bootstrap
	// sentinel (mirrors how mapRAKError keeps 52100 path-dependent). Check it
	// before the generic already-issued mapping, since both can arrive as HTTP 409.
	if path == pathBootstrap && isBootstrapConsumedCompletion(apiErr) {
		return fmt.Errorf("%w: %s: %w", ErrBootstrapSetupKeyConsumed, bootstrapConsumedGuidance, err)
	}
	// qurl-service guarantees completion 401/403 responses are emitted before
	// its atomic mint writes a device credential. That producer-owned no-write
	// invariant is what makes the shared admission mapping safe on this mutating
	// endpoint; if the service contract changes, these statuses must stop being
	// authoritative in isAuthoritativeNoWriteCompletionError.
	if mapped := mapCommonRegistrationHTTPError(apiErr, err, "the API key was rejected with no device-key write", "completion returned an authoritative no-write admission failure"); mapped != nil {
		return mapped
	}
	if isDeviceKeyAlreadyIssued(apiErr) {
		return &CredentialRecoveryRequiredError{DeviceID: deviceID, Cause: err}
	}
	return err
}

func isDeviceKeyQuotaExceeded(apiErr *APIError) bool {
	return apiErr.StatusCode == http.StatusConflict &&
		strings.EqualFold(strings.TrimSpace(apiErr.Code), "device_key_quota_exceeded")
}

// isCompletionNotYetRegistered reports whether a completion error means the
// device is not yet enrolled (the expected outcome of the crash-recovery probe
// before REG has run), so the account path should proceed to REG rather than
// surface the error. A structured not-registered code is authoritative. A bare
// 404 is accepted only by the pre-REG probe caller: no REG has run in that call,
// so proceeding to the real registration path cannot duplicate its own mint.
func isCompletionNotYetRegistered(err error) bool {
	if isStructuredCompletionNotYetRegistered(err) {
		return true
	}
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func isStructuredCompletionNotYetRegistered(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode != http.StatusNotFound {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(apiErr.Code)) {
	case "agent_not_enrolled", "device_not_registered", "registration_incomplete", "not_registered":
		return true
	}
	return false
}

// isDeviceKeyAlreadyIssued matches ONLY structured HTTP 409
// device_key_already_issued, not a bare 409 or the same code on another status.
// The mapped error tells the operator to revoke the prior agent key and run
// explicit same-id recovery. Every non-exact response remains persistence
// ambiguity while preserving the underlying *APIError for errors.As.
func isDeviceKeyAlreadyIssued(apiErr *APIError) bool {
	return apiErr.StatusCode == http.StatusConflict &&
		strings.EqualFold(strings.TrimSpace(apiErr.Code), "device_key_already_issued")
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
	peerKey, err := decodeNHPServerPublicKey(peer.PublicKeyB64)
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
	serverPub, err = decodeNHPServerPublicKey(peer.PublicKeyB64)
	if err != nil {
		// Callers can install their defer only after both decodes succeed.
		wipeBytes(devicePriv)
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
// API key persisted in store, wrapped in CachedCredentials. An existing Client
// can retain its prior key for up to storeCredentialCacheTTL; recovery callers
// should use the newly returned Client when they need the replacement at once.
// Construction makes no qURL API calls; loading a network-backed store can
// still perform I/O. This unprimed path uses the production wall clock; only
// the internal primed runtime/recovery constructors accept an injected clock
// for deterministic cache-expiry tests.
func newStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer) *Client {
	return newStoreBackedClientWithCredential(store, baseURL, httpClient, "", time.Now)
}

// newPrimedStoreBackedClient is deliberately infallible after callers validate
// the exact credential as part of their pre-commit state/completion contract.
// Keeping construction infallible prevents a committed lifecycle mutation from
// acquiring a new post-commit error tail merely while materializing its Client.
// Do not add revalidation here: all three callers validate exact bearer bytes
// before the commit/return boundary, and a new failure here would recreate a
// committed-but-no-Client outcome. Keeping this helper unexported makes that
// precondition auditable without a fallback or panic.
func newPrimedStoreBackedClient(store AgentStateStore, baseURL string, httpClient HTTPDoer, validatedDeviceAPIKey string, now func() time.Time) *Client {
	return newStoreBackedClientWithCredential(store, baseURL, httpClient, validatedDeviceAPIKey, now)
}

// newStoreBackedClientWithCredential optionally primes the one-minute cache from
// an already validated AgentState so a combined runtime open does not unseal or
// reload the same store on its first resource request. The wrapped store provider
// remains authoritative after the cache expires.
func newStoreBackedClientWithCredential(store AgentStateStore, baseURL string, httpClient HTTPDoer, deviceAPIKey string, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	provider := &cachedCredentialProvider{
		provider: &storeCredentialProvider{store: store},
		ttl:      storeCredentialCacheTTL,
		now:      now,
	}
	if deviceAPIKey != "" {
		// The provider is not yet shared: construction finishes before the Client
		// escapes, and every later cache read/write remains mutex-protected.
		provider.authorization = "Bearer " + deviceAPIKey
		provider.expiresAt = provider.now().Add(provider.ttl)
	}
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
// from AgentStateStore. CachedCredentials bounds store reads and observes a
// replacement after the one-minute cache expires.
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
	if err := validatePersistedDeviceCredential(state, ErrInvalidClientConfig); err != nil {
		return err
	}
	token := state.DeviceAPIKey
	// The exact bytes were validated above; do not route through setBearer,
	// whose trimming behavior is reserved for caller-supplied Client tokens.
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// --- options ---

// RegisterOption customizes registered-agent enrollment and repair operations,
// including RegisterAgentRuntime.
type RegisterOption interface {
	applyRegisterOption(*registerConfig) error
}

// AgentClientOption configures the store-backed resource Client consistently
// whether it is returned by RegisterAgent, RegisterAgentRuntime, or
// RecoverAgentCredential, or opened later by either OpenRegisteredAgent API.
// WithAgentClientBaseURL and WithAgentClientHTTPClient implement this interface
// and can be passed to either the RegisterOption or ClientOption entry points.
type AgentClientOption interface {
	RegisterOption
	ClientOption
}

// RegistrationKeyKind is the key class reported by registration-info.
// Callers that only accept pre-issued enrollment keys can restrict registration
// before any OTP dispatch or NHP registration side effect.
type RegistrationKeyKind string

const (
	// RegistrationKeyKindBootstrap is a pre-issued headless enrollment key.
	RegistrationKeyKindBootstrap RegistrationKeyKind = keyKindBootstrap
	// RegistrationKeyKindAccount is an account API key requiring email OTP.
	RegistrationKeyKindAccount RegistrationKeyKind = keyKindAccount
)

// applyLifecycleDefaultKeyPolicy gives the new repair-oriented lifecycle APIs a
// fail-safe fleet default without changing RegisterAgent's account-enrollment
// compatibility. Interactive account-key refresh/recovery remains available by
// explicitly opting in with WithAllowedRegistrationKeyKinds.
func (cfg *registerConfig) applyLifecycleDefaultKeyPolicy() {
	if cfg.allowedKeyKinds == nil {
		cfg.allowedKeyKinds = map[RegistrationKeyKind]struct{}{
			RegistrationKeyKindBootstrap: {},
		}
	}
}

func (cfg *registerConfig) requireAllowedKeyKind(raw string) error {
	if cfg.allowedKeyKinds == nil {
		return nil
	}
	kind := RegistrationKeyKind(strings.TrimSpace(raw))
	if _, ok := cfg.allowedKeyKinds[kind]; ok {
		return nil
	}
	allowed := make([]RegistrationKeyKind, 0, len(cfg.allowedKeyKinds))
	for candidate := range cfg.allowedKeyKinds {
		allowed = append(allowed, candidate)
	}
	slices.Sort(allowed)
	return &RegistrationKeyKindDisallowedError{Kind: kind, Allowed: allowed}
}

// WithAllowedRegistrationKeyKinds restricts the registration key kinds a
// caller accepts. The policy is evaluated immediately after the side-effect-free
// registration-info preflight and before OTP dispatch or NHP registration.
func WithAllowedRegistrationKeyKinds(kinds ...RegistrationKeyKind) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if len(kinds) == 0 {
			return fmt.Errorf("%w: at least one registration key kind is required", ErrInvalidRegisterConfig)
		}
		o.allowedKeyKinds = make(map[RegistrationKeyKind]struct{}, len(kinds))
		for _, kind := range kinds {
			switch kind {
			case RegistrationKeyKindBootstrap, RegistrationKeyKindAccount:
				o.allowedKeyKinds[kind] = struct{}{}
			default:
				return fmt.Errorf("%w: unknown registration key kind %q", ErrInvalidRegisterConfig, kind)
			}
		}
		return nil
	})
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
// This option affects only registration-info and completion. The returned
// Client remains on the default production API origin unless
// WithAgentClientBaseURL is set. Staging, loopback, and custom deployments must
// set both options deliberately to prevent resource calls reaching production.
func WithRegisterBaseURL(rawURL string) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if err := validateHTTPSOrLoopbackURL(rawURL, "register base URL", ErrInvalidRegisterConfig); err != nil {
			return err
		}
		o.baseURL = strings.TrimRight(rawURL, "/")
		return nil
	})
}

// WithAgentClientBaseURL points the registered agent's resource Client at a
// non-default API origin, independently of WithRegisterBaseURL. The same option
// can be reused with RegisterAgent, RegisterAgentRuntime,
// RecoverAgentCredential, OpenRegisteredAgent, and OpenRegisteredAgentRuntime.
// Generic Clients may continue to use WithBaseURL.
func WithAgentClientBaseURL(rawURL string) AgentClientOption {
	return agentClientBaseURLOption(rawURL)
}

type agentClientBaseURLOption string

// validateAgentClientBaseURL validates the resource-client base URL and returns
// its normalized (trailing-slash-trimmed) form. Shared by the RegisterOption and
// ClientOption applications of WithAgentClientBaseURL so the validation and
// normalization stay identical across both entry points.
func validateAgentClientBaseURL(rawURL string, errKind error) (string, error) {
	if err := validateHTTPSOrLoopbackURL(rawURL, "agent client base URL", errKind); err != nil {
		return "", err
	}
	return strings.TrimRight(rawURL, "/"), nil
}

func (o agentClientBaseURLOption) applyRegisterOption(cfg *registerConfig) error {
	normalized, err := validateAgentClientBaseURL(string(o), ErrInvalidRegisterConfig)
	if err != nil {
		return err
	}
	cfg.clientBaseURL = normalized
	return nil
}

func (o agentClientBaseURLOption) applyClientOption(cfg *clientOptions) error {
	normalized, err := validateAgentClientBaseURL(string(o), ErrInvalidClientConfig)
	if err != nil {
		return err
	}
	if err := claimClientOptionSource(&cfg.baseURLSource, clientOptionSourceAgent, "WithBaseURL", "WithAgentClientBaseURL"); err != nil {
		return err
	}
	cfg.baseURL = normalized
	return nil
}

// WithRegisterHTTPClient injects the HTTP client used for the registration HTTPS
// endpoints and the relay POSTs. Without it, RegisterAgent uses a shared client
// with a 30-second timeout and no redirect following. Callers can still bound
// each call with ctx.
//
// This option affects only registration and relay traffic. Use
// WithAgentClientHTTPClient independently for the returned Client.
func WithRegisterHTTPClient(client HTTPDoer) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: HTTP client must not be nil", ErrInvalidRegisterConfig)
		}
		o.httpClient = client
		return nil
	})
}

// WithAgentClientHTTPClient injects the resource Client transport independently
// of registration and relay traffic. The same option can be reused with
// RegisterAgent, RegisterAgentRuntime, RecoverAgentCredential,
// OpenRegisteredAgent, and OpenRegisteredAgentRuntime.
func WithAgentClientHTTPClient(client HTTPDoer) AgentClientOption {
	return agentClientHTTPClientOption{client: client}
}

type agentClientHTTPClientOption struct {
	client HTTPDoer
}

func (o agentClientHTTPClientOption) applyRegisterOption(cfg *registerConfig) error {
	if o.client == nil {
		return fmt.Errorf("%w: agent Client HTTP client must not be nil", ErrInvalidRegisterConfig)
	}
	cfg.clientHTTPClient = o.client
	return nil
}

func (o agentClientHTTPClientOption) applyClientOption(cfg *clientOptions) error {
	if o.client == nil {
		return fmt.Errorf("%w: agent Client HTTP client must not be nil", ErrInvalidClientConfig)
	}
	if err := claimClientOptionSource(&cfg.httpClientSource, clientOptionSourceAgent, "WithHTTPClient", "WithAgentClientHTTPClient"); err != nil {
		return err
	}
	cfg.httpClient = o.client
	return nil
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
// The override is not covered by registration-info's server-id/peer-key check;
// pin only a peer you trust. The preflight still rejects an internally
// inconsistent registration-info response before applying the override. REG/RAK
// authenticates the selected peer, and completion may only corroborate its key.
// A different completion key fails recovery-required after completion may have
// minted a credential, so differing overrides require a custom/test service
// configured to agree. Success persists the selected peer in AgentState.
func WithNHPPeer(peer NHPServerPeerInfo) RegisterOption {
	return registerOptionFunc(func(o *registerConfig) error {
		p := peer
		o.nhpPeerOverride = &p
		return nil
	})
}
