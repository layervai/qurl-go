package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/layervai/qurl-go/internal/x25519key"
)

// OpenRegisteredAgent opens a Client from a completed AgentState without making
// enrollment or resource API calls. Loading a custom network-backed store may
// still perform the store's own I/O, and loading a sealed store may call its key
// wrapper or KMS.
// The device credential is read from store behind a one-minute cache. Native
// assignment absence, corruption, or expiry does not invalidate this resource
// client; qURL Connector callers that will knock must instead use
// ConnectAgentRuntime, which validates the assignment and renews an expired
// lease. The persisted agent id and X25519 keypair remain the durable device
// identity.
//
// WithAgentClientBaseURL and WithAgentClientHTTPClient can be reused across
// native registration, refresh, and open. Ordinary WithBaseURL and
// WithHTTPClient ClientOptions remain supported here too.
func OpenRegisteredAgent(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, error) {
	client, _, err := OpenRegisteredAgentWithIdentity(ctx, store, opts...)
	return client, err
}

// OpenRegisteredAgentWithIdentity opens a resource Client and returns the
// authoritative agent id from the exact completed AgentState snapshot that
// primed the Client. It performs exactly one store load and no resource or
// lifecycle network call. Future credential reloads fail closed if the store
// presents a different agent id, preventing a long-lived Client from silently
// crossing identities after its one-minute credential cache expires.
func OpenRegisteredAgentWithIdentity(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, string, error) {
	return openRegisteredAgentWithIdentity(ctx, store, time.Now, opts...)
}

func openRegisteredAgentWithIdentity(ctx context.Context, store AgentStateStore, now func() time.Time, opts ...ClientOption) (*Client, string, error) {
	cfg, err := validateRegisteredAgentOpenInputs(ctx, store, opts)
	if err != nil {
		return nil, "", err
	}
	if now == nil {
		now = time.Now
	}
	type openResult struct {
		client  *Client
		agentID string
	}
	result, err := withAgentStoreContinuity(store, func(*openResult) {}, func(retained AgentStateStore) (*openResult, error) {
		state, err := loadCompletedRegisteredState(ctx, retained, ErrInvalidClientConfig)
		if err != nil {
			return nil, err
		}
		defer clearOwnedAgentState(state)
		return &openResult{
			client:  newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey, state.AgentID, now),
			agentID: state.AgentID,
		}, nil
	})
	if err != nil {
		return nil, "", err
	}
	return result.client, result.agentID, nil
}

// WithAgentRuntimeOfflineOpen keeps ConnectAgentRuntime free of network I/O.
// The call then serves only an existing completed registration: a live lease is
// returned as usual, while an expired lease fails with ErrAssignmentLeaseExpired
// instead of renewing through the Hub, and the binding a successful call returns
// does not renew itself either. Use it when a process must be able to start
// without reaching LayerV, or when renewal has to happen at a moment you choose;
// recover with an explicit RefreshAgentRuntime.
//
// Enrollment needs the network this option forbids, so combining it with
// WithAgentRuntimeEnrollmentCredential,
// WithAgentRuntimeEnrollmentCredentialProvider, or
// WithAgentRuntimeOTPProvider fails with ErrInvalidRegisterConfig.
//
// It is deliberately not a ClientOption: it means nothing to the resource-only
// OpenRegisteredAgent or to NewClient, so those must not silently accept it. It
// is equally meaningless to RefreshAgentRuntime and RecoverAgentRuntime, whose
// sole purpose is a network exchange, so those exclude it at compile time too.
func WithAgentRuntimeOfflineOpen() AgentRuntimeRegistrationOption {
	return nativeRuntimeOptionFunc(func(c *nativeAgentRuntimeConfig) error {
		c.offlineOpen = true
		return nil
	})
}

func validateRegisteredAgentOpenInputs(ctx context.Context, store AgentStateStore, opts []ClientOption) (clientOptions, error) {
	if store == nil {
		return clientOptions{}, fmt.Errorf("%w: agent state store must not be nil", ErrInvalidClientConfig)
	}
	if err := validateContext(ctx, ErrInvalidClientConfig); err != nil {
		return clientOptions{}, err
	}
	cfg, err := applyClientOptions(opts)
	if err != nil {
		return clientOptions{}, err
	}
	if cfg.issuerStatePath != "" {
		return clientOptions{}, fmt.Errorf("%w: WithIssuerStatePath is not valid with registered-agent open APIs", ErrInvalidClientConfig)
	}
	return cfg, nil
}

// AgentRuntimeBinding is a registered or refreshed identity and assigned NHP
// endpoint needed for an immediate native UDP qURL Connector knock. It
// deliberately excludes DeviceAPIKey, schema, and OTP state. The private key
// remains sensitive. Treat the returned
// pointer as the owning handle: do not copy or log the binding. Accidental value
// copies share one synchronized key owner, so they cannot duplicate the one-shot
// transfer. Exported identity and assignment fields are read-only observability;
// mutating them does not retarget a knock and instead fails the authoritative
// snapshot check. Immediately defer Destroy after a successful lifecycle call,
// transfer key ownership exactly once with TakeDeviceStaticPrivateKey, and wipe
// those bytes after use. A runtime cleanup best-effort wipes a retained key only
// after every accidental copy becomes unreachable; it is defense in depth, not
// a substitute for deterministic Destroy.
//
// A binding keeps its own assignment lease current. KnockRegisteredAgent and
// ExitRegisteredAgentSessions renew it through the Hub as it approaches expiry, so
// a process may hold one binding indefinitely without tracking leases.
//
// The exported assignment fields are written once, when the binding is created,
// and are never touched again. They are a stable record of the placement this
// binding started from, safe to read from any goroutine. Renewal updates the
// live placement instead, which Assignment returns.
type AgentRuntimeBinding struct {
	AgentID              string
	PublicKeyB64         string
	RegisteredAt         time.Time
	CellID               string
	AssignmentGeneration int64
	EndpointRevision     int64
	LeaseExpiresAt       time.Time
	NHPUDPEndpoint       NHPUDPEndpoint
	DeviceAPIKeyID       string

	authoritativeAgentID      string
	authoritativePublicKeyB64 string
	authoritativeAssignment   *AgentAssignment
	renewedAssignment         *AgentAssignment
	deviceStaticPrivateKey    *agentRuntimePrivateKey
	renewal                   *agentRuntimeRenewal
}

// agentRuntimeRenewal carries what a held binding needs to renew its own lease:
// the store that owns the durable assignment and the lifecycle transport that
// produced it. It is absent only for a binding built outside a lifecycle call,
// which then keeps the pre-renewal behavior of failing on an expired lease.
type agentRuntimeRenewal struct {
	mu    sync.Mutex
	store AgentStateStore
	hub   HubBootstrap
	cfg   *nativeAgentRuntimeConfig
}

// Assignment returns the binding's current authoritative placement, including
// any lease renewal or relocation a knock has applied. Use it whenever you need
// live placement; the exported fields deliberately keep their construction-time
// values and will be stale after a renewal.
func (b *AgentRuntimeBinding) Assignment() AgentAssignment {
	if b == nil {
		return AgentAssignment{}
	}
	if b.renewal == nil {
		if live := b.livePlacement(); live != nil {
			return *live
		}
		return AgentAssignment{}
	}
	b.renewal.mu.Lock()
	defer b.renewal.mu.Unlock()
	if live := b.livePlacement(); live != nil {
		return *live
	}
	return AgentAssignment{}
}

// agentRuntimePrivateKey centralizes one-shot ownership across accidental
// AgentRuntimeBinding value copies. A conventional noCopy marker on the binding
// is intentionally unsuitable: go vet would reject the value-receiver
// String/GoString methods required to redact explicitly dereferenced formatting.
// Sharing this synchronized cell makes the underlying copy hazard safe instead.
type agentRuntimePrivateKey struct {
	mu      sync.Mutex
	value   []byte
	cleanup *runtime.Cleanup
}

// withBorrow keeps the private key owned by the binding while fn performs one
// synchronous operation. The mutex deliberately remains held across network
// I/O: Take and Destroy must wait for fn to return so a caller cannot transfer
// or wipe the key underneath an in-flight native exchange. The borrowed slice
// must not escape fn.
func (k *agentRuntimePrivateKey) withBorrow(errKind error, fn func([]byte) error) error {
	if errKind == nil {
		errKind = ErrInvalidNativeKnockInput
	}
	if k == nil || fn == nil {
		return fmt.Errorf("%w: runtime binding does not own a device key", errKind)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.value) == 0 {
		return fmt.Errorf("%w: runtime binding device key was already transferred or destroyed", errKind)
	}
	return fn(k.value)
}

func newAgentRuntimePrivateKey(value []byte) *agentRuntimePrivateKey {
	key := &agentRuntimePrivateKey{value: value}
	// The cleanup argument references only the separate byte-slice backing array,
	// never key itself, so it cannot keep the cleanup target reachable. Take and
	// Destroy stop this cleanup synchronously before transferring or wiping value.
	cleanup := runtime.AddCleanup(key, wipeBytes, value)
	key.cleanup = &cleanup
	return key
}

func (k *agentRuntimePrivateKey) stopCleanupLocked() {
	if k.cleanup == nil {
		return
	}
	k.cleanup.Stop()
	k.cleanup = nil
}

func (k *agentRuntimePrivateKey) take() []byte {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopCleanupLocked()
	value := k.value
	k.value = nil
	return value
}

func (k *agentRuntimePrivateKey) destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopCleanupLocked()
	wipeBytes(k.value)
	k.value = nil
}

// String returns a redacted runtime summary. The value receiver deliberately
// protects both pointer and dereferenced-value formatting; its copy contains
// only a pointer to the synchronized key owner and does not transfer key
// ownership. Callers must still avoid making binding copies. fmt safely renders
// a nil *AgentRuntimeBinding as <nil>, but a direct method call on a nil pointer
// cannot reach this value-receiver method and panics; use fmt for nullable values.
func (b AgentRuntimeBinding) String() string {
	return fmt.Sprintf("qurl.AgentRuntimeBinding{AgentID:%q, CellID:%q, AssignmentGeneration:%d, EndpointRevision:%d, LeaseExpiresAt:%q, NHPUDPEndpoint:{Host:%q, Port:%d, ServerPublicKeyB64:[REDACTED]}, DeviceAPIKeyID:%q, DeviceStaticPrivateKey:[REDACTED]}",
		b.AgentID, b.CellID, b.AssignmentGeneration, b.EndpointRevision, b.LeaseExpiresAt.Format(time.RFC3339Nano), b.NHPUDPEndpoint.Host, b.NHPUDPEndpoint.Port, b.DeviceAPIKeyID)
}

// GoString returns a redacted runtime summary for pointer or value %#v
// formatting.
func (b AgentRuntimeBinding) GoString() string { return b.String() }

// TakeDeviceStaticPrivateKey transfers ownership of the retained 32-byte X25519
// private key for KnockRegisteredAgent and clears it from the binding. It
// returns nil after the first call. The caller must wipe the returned slice
// after the knocker no longer needs it. Calling this method on a nil binding is
// safe and returns nil; unlike these pointer-receiver lifecycle methods, a
// direct String call on a nil binding cannot reach its value receiver.
func (b *AgentRuntimeBinding) TakeDeviceStaticPrivateKey() []byte {
	if b == nil {
		return nil
	}
	return b.deviceStaticPrivateKey.take()
}

// Destroy zeros the private-key slice retained by the binding. It is idempotent
// and becomes a no-op after TakeDeviceStaticPrivateKey transfers ownership.
// As with all Go memory wiping, copies outside this binding remain the caller's
// responsibility. Destroy is synchronized with TakeDeviceStaticPrivateKey
// across accidental value copies, though callers should still keep the
// pointer-owned lifecycle explicit. Calling Destroy on a nil binding is safe.
func (b *AgentRuntimeBinding) Destroy() {
	if b == nil {
		return
	}
	b.deviceStaticPrivateKey.destroy()
}

func decodeRuntimePrivateKey(state *AgentState, errKind error) ([]byte, error) {
	// Device private keys are generated and persisted only by this SDK using
	// padded StdEncoding. Unlike server public keys received across the wire,
	// accepting RawStdEncoding here would expand a local custody format that has
	// no legitimate raw producer and could conceal state corruption.
	privateKey, err := base64.StdEncoding.Strict().DecodeString(state.PrivateKeyB64)
	if err != nil {
		wipeBytes(privateKey)
		return nil, fmt.Errorf("%w: decode agent runtime private key: %w", errKind, err)
	}
	if len(privateKey) != x25519key.Size {
		wipeBytes(privateKey)
		return nil, fmt.Errorf("%w: agent runtime private key must be %d bytes", errKind, x25519key.Size)
	}
	return privateKey, nil
}

// newAgentRuntimeBinding is deliberately infallible: callers decode the
// retained private key before any lifecycle network I/O and validate runtime
// metadata before calling it. Mutating lifecycle paths additionally wait until
// state is durably saved and the setup lock is released. Preconditions:
// state, state.RegisteredAt, and state.Assignment are non-nil, and privateKey is
// a validated 32-byte X25519 key owned by this constructor.
func newAgentRuntimeBinding(state *AgentState, privateKey []byte) *AgentRuntimeBinding {
	return &AgentRuntimeBinding{
		AgentID:                   state.AgentID,
		PublicKeyB64:              state.PublicKeyB64,
		RegisteredAt:              *state.RegisteredAt,
		DeviceAPIKeyID:            state.DeviceAPIKeyID,
		CellID:                    state.Assignment.CellID,
		AssignmentGeneration:      state.Assignment.AssignmentGeneration,
		EndpointRevision:          state.Assignment.EndpointRevision,
		LeaseExpiresAt:            state.Assignment.LeaseExpiresAt,
		NHPUDPEndpoint:            state.Assignment.Endpoint,
		authoritativeAgentID:      state.AgentID,
		authoritativePublicKeyB64: state.PublicKeyB64,
		authoritativeAssignment:   state.Assignment.clone(),
		deviceStaticPrivateKey:    newAgentRuntimePrivateKey(privateKey),
	}
}

func (b *AgentRuntimeBinding) assignment() *AgentAssignment {
	if b == nil {
		return nil
	}
	return b.livePlacement()
}

// attachRenewal lets a binding produced by a lifecycle call keep its own lease
// current. The config is the one that built the binding, so a renewal reuses the
// same Hub trust root and lifecycle transport rather than inventing defaults.
// With no resolvable hub — the legitimately hub-less deployment class, since a
// broken QURL_DEPLOYMENT already failed at config time — the binding completes
// the open but cannot renew itself, deliberately matching the old Open
// contract for warm opens.
func (b *AgentRuntimeBinding) attachRenewal(store AgentStateStore, cfg *nativeAgentRuntimeConfig) {
	if b == nil || store == nil || cfg == nil || cfg.hub == nil {
		return
	}
	renewalCfg := *cfg
	// continuityStore is scoped to the lifecycle call that is finishing now.
	// A later renewal retains its own store capability instead.
	renewalCfg.continuityStore = nil
	// Renewal sends no credential, so the binding must not hold one for the life
	// of the process just because the lifecycle call was given one.
	renewalCfg.deviceCredential = ""
	renewalCfg.enrollCredential = ""
	renewalCfg.enrollCredentialSet = false
	renewalCfg.enrollCredentialProvider = nil
	renewalCfg.otpProvider = nil
	b.renewal = &agentRuntimeRenewal{store: baseAgentStateStore(store), hub: *cfg.hub, cfg: &renewalCfg}
}

// liveSessionAssignment returns the placement a session exchange should use. It
// renews through the Hub when the lease has expired or is close enough that the
// admission would be worthless, then applies the tamper check against the same
// placement it just published. Renewal, republication, and that check all happen
// under one lock so concurrent knocks on a shared binding cannot observe a
// half-updated snapshot.
//
// Renewal ahead of expiry is best effort: while the current lease is still live,
// a Hub failure returns that live placement instead of an error, so a transient
// outage never takes down a working agent. Only an already-expired lease turns a
// renewal failure into a failed exchange.
func (b *AgentRuntimeBinding) liveSessionAssignment(ctx context.Context, deviceStaticPrivateKey []byte, now time.Time) (*AgentAssignment, error) {
	if b.renewal == nil {
		return b.checkedAssignment(b.assignment())
	}
	b.renewal.mu.Lock()
	defer b.renewal.mu.Unlock()
	current := b.livePlacement()
	if current == nil || !now.Add(sessionLeaseRenewalLead).Before(current.LeaseExpiresAt) {
		expired := current == nil || current.LeaseExpired(now)
		fresh, err := b.renewal.cfg.renewSessionAssignment(ctx, b.renewal.hub, b.renewal.store, b.AgentID, deviceStaticPrivateKey, now)
		switch {
		case err == nil:
			b.adoptRenewedAssignmentLocked(fresh)
			current = b.livePlacement()
		case expired:
			return nil, err
		}
	}
	return b.checkedAssignment(current)
}

// checkedAssignment rejects edited exported assignment fields, so tampering with
// them still cannot retarget an exchange. It compares them against
// authoritativeAssignment, which is fixed at construction exactly like the
// exported fields are; a renewal lands in renewedAssignment instead, so the two
// can never drift apart and no caller has to keep a second copy in step.
func (b *AgentRuntimeBinding) checkedAssignment(assignment *AgentAssignment) (*AgentAssignment, error) {
	if assignment == nil {
		return nil, fmt.Errorf("%w: runtime binding has no authoritative assignment", ErrInvalidNativeKnockInput)
	}
	origin := b.authoritativeAssignment
	if origin == nil || b.CellID != origin.CellID ||
		b.AssignmentGeneration != origin.AssignmentGeneration ||
		b.EndpointRevision != origin.EndpointRevision ||
		b.NHPUDPEndpoint != origin.Endpoint {
		return nil, fmt.Errorf("%w: runtime binding does not match its authoritative assignment", ErrInvalidNativeKnockInput)
	}
	return assignment.clone(), nil
}

// adoptRenewedAssignmentLocked stores a renewed placement without touching the
// exported fields. Those are written once, at construction, so a caller may read
// them from any goroutine at any time without racing a renewal. Assignment is
// the live view.
func (b *AgentRuntimeBinding) adoptRenewedAssignmentLocked(fresh *AgentAssignment) {
	b.renewedAssignment = fresh.clone()
}

// livePlacement is the placement an exchange should actually use: the most
// recent renewal if one has happened, otherwise the construction-time authority.
func (b *AgentRuntimeBinding) livePlacement() *AgentAssignment {
	if b.renewedAssignment != nil {
		return b.renewedAssignment
	}
	return b.authoritativeAssignment
}

// loadCompletedRegisteredState enforces the completed identity and intact
// credential precondition shared by both registered-agent open APIs.
func loadCompletedRegisteredState(ctx context.Context, store AgentStateStore, errKind error) (*AgentState, error) {
	state, err := loadExistingAgentState(ctx, store, errKind)
	if err != nil {
		return nil, err
	}
	if err := validateCompletedAgentIdentity(state, errKind); err != nil {
		clearOwnedAgentState(state)
		return nil, err
	}
	if err := validatePersistedCredentialForState(state, errKind); err != nil {
		clearOwnedAgentState(state)
		return nil, err
	}
	return state, nil
}

func loadExistingAgentState(ctx context.Context, store AgentStateStore, errKind error) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		clearOwnedAgentState(state)
		return nil, fmt.Errorf("%w: load agent state: %w", errKind, err)
	}
	if err := prepareLoadedAgentState(state, errKind); err != nil {
		clearOwnedAgentState(state)
		return nil, err
	}
	return state, nil
}

// clearOwnedAgentState promptly drops all references held by one caller-owned
// loaded snapshot after its required identity and credential fields have been
// copied into their next owner. Go strings cannot be reliably overwritten, but
// clearing the complete struct avoids retaining private-key and recovery fields
// that a resource Client does not need.
func clearOwnedAgentState(state *AgentState) {
	if state != nil {
		*state = AgentState{}
	}
}

// withAgentSetupLock holds the SDK local-file setup lock across an entire native
// lifecycle transition and makes release failure override a nominal success.
// cleanup releases resources owned by the result before release failure hides
// it; it must be non-nil and accept the zero value because fn may fail without
// a result.
// Custom and network stores retain the documented caller-serialization
// requirement.
func withAgentSetupLock[T any](ctx context.Context, store AgentStateStore, cleanup func(T), fn func(context.Context, AgentStateStore) (T, error)) (result T, resultErr error) {
	retainedStore, validateContinuity, releaseContinuity, err := retainAgentStateContinuity(store)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := releaseContinuity(); err != nil {
			continuityErr := fmt.Errorf("%w: release lifecycle state capability: %w", ErrAgentStateContinuity, err)
			cleanup(result)
			var zero T
			result = zero
			if resultErr == nil {
				resultErr = continuityErr
			} else {
				resultErr = errors.Join(resultErr, continuityErr)
			}
		}
	}()
	if err := validateContinuity(); err != nil {
		return result, err
	}
	lockedStore, release, err := acquireAgentSetupLockStore(ctx, retainedStore)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := validateContinuity(); err != nil {
			cleanup(result)
			var zero T
			result = zero
			if resultErr == nil {
				resultErr = err
			} else {
				resultErr = errors.Join(resultErr, err)
			}
		}
		if err := release(); err != nil {
			lockErr := fmt.Errorf("%w: release setup lock: %w", ErrAgentSetupLock, err)
			cleanup(result)
			var zero T
			result = zero
			if resultErr == nil {
				resultErr = lockErr
			} else {
				resultErr = errors.Join(resultErr, lockErr)
			}
		}
	}()
	return fn(markSetupLockReentry(ctx, store), lockedStore)
}

// withAgentStoreContinuity retains a local directory capability for an
// otherwise lock-free operation such as warm open. It validates both boundaries
// and makes a final continuity/release failure override apparent success.
func withAgentStoreContinuity[T any](store AgentStateStore, cleanup func(T), fn func(AgentStateStore) (T, error)) (result T, resultErr error) {
	retainedStore, validateContinuity, release, err := retainAgentStateContinuity(store)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := validateContinuity(); err != nil {
			cleanup(result)
			var zero T
			result = zero
			if resultErr == nil {
				resultErr = err
			} else {
				resultErr = errors.Join(resultErr, err)
			}
		}
		if err := release(); err != nil {
			cleanup(result)
			var zero T
			result = zero
			wrapped := fmt.Errorf("%w: release state capability: %w", ErrAgentStateContinuity, err)
			if resultErr == nil {
				resultErr = wrapped
			} else {
				resultErr = errors.Join(resultErr, wrapped)
			}
		}
	}()
	if err := validateContinuity(); err != nil {
		return result, err
	}
	return fn(retainedStore)
}
