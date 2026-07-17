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
// client; qURL Connector callers that will knock must instead open or explicitly
// refresh the registered runtime. The persisted agent id and X25519 keypair
// remain the durable device identity.
//
// WithAgentClientBaseURL and WithAgentClientHTTPClient can be reused across
// native registration, refresh, and open. Ordinary WithBaseURL and
// WithHTTPClient ClientOptions remain supported here too.
func OpenRegisteredAgent(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, error) {
	cfg, err := validateRegisteredAgentOpenInputs(ctx, store, opts)
	if err != nil {
		return nil, err
	}
	if _, err := loadCompletedRegisteredState(ctx, store, ErrInvalidClientConfig); err != nil {
		return nil, err
	}
	return newStoreBackedClient(store, cfg.baseURL, cfg.httpClient), nil
}

// OpenRegisteredAgentRuntime opens both a store-backed resource Client and the
// validated runtime binding needed for an immediate native UDP qURL Connector
// knock. It performs one AgentStateStore load, no enrollment/resource API calls,
// requires a live authority-provided assignment, and primes the Client's one-minute
// credential cache from that same state so its first request does not reload or
// unseal the store. Unlike resource-only OpenRegisteredAgent, it rejects an expired
// assignment without network I/O because that endpoint cannot be knocked; call
// RefreshAgentRuntime through the pinned Hub to obtain a fresh binding.
// The caller must immediately defer binding.Destroy, then take and eventually
// wipe the runtime private key.
func OpenRegisteredAgentRuntime(ctx context.Context, store AgentStateStore, opts ...ClientOption) (*Client, *AgentRuntimeBinding, error) {
	return openRegisteredAgentRuntime(ctx, store, nil, opts...)
}

func openRegisteredAgentRuntime(ctx context.Context, store AgentStateStore, now func() time.Time, opts ...ClientOption) (*Client, *AgentRuntimeBinding, error) {
	// A nil clock selects the production wall clock; tests pass an explicit clock
	// only when they need deterministic assignment and cache-expiry boundaries.
	if now == nil {
		now = time.Now
	}
	cfg, err := validateRegisteredAgentOpenInputs(ctx, store, opts)
	if err != nil {
		return nil, nil, err
	}
	state, err := loadCompletedRegisteredState(ctx, store, ErrInvalidClientConfig)
	if err != nil {
		return nil, nil, err
	}
	if err := validateAgentRuntimeMetadata(state, now(), ErrInvalidClientConfig); err != nil {
		return nil, nil, err
	}
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidClientConfig)
	if err != nil {
		return nil, nil, err
	}
	defer func() { wipeBytes(privateKey) }()
	client := newPrimedStoreBackedClient(store, cfg.baseURL, cfg.httpClient, state.DeviceAPIKey, now)
	binding := newAgentRuntimeBinding(state, privateKey)
	privateKey = nil // binding owns the slice and its cleanup from this point.
	return client, binding, nil
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
	deviceStaticPrivateKey    *agentRuntimePrivateKey
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
		return nil, err
	}
	if err := validatePersistedCredentialForState(state, errKind); err != nil {
		return nil, err
	}
	return state, nil
}

func loadExistingAgentState(ctx context.Context, store AgentStateStore, errKind error) (*AgentState, error) {
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: load agent state: %w", errKind, err)
	}
	if err := prepareLoadedAgentState(state, errKind); err != nil {
		return nil, err
	}
	return state, nil
}

// withAgentSetupLock holds the SDK local-file setup lock across an entire native
// lifecycle transition and makes release failure override a nominal success.
// Custom and network stores retain the documented caller-serialization
// requirement.
func withAgentSetupLock[T any](ctx context.Context, store AgentStateStore, fn func() (T, error)) (result T, resultErr error) {
	release, err := acquireAgentSetupLock(ctx, store)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := release(); err != nil {
			lockErr := fmt.Errorf("%w: release setup lock: %w", ErrAgentSetupLock, err)
			var zero T
			result = zero
			if resultErr == nil {
				resultErr = lockErr
			} else {
				resultErr = errors.Join(resultErr, lockErr)
			}
		}
	}()
	return fn()
}
