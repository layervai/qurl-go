package qurl

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/layervai/qurl-go/internal/agentstatecontract"
	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/internal/udpfence"
	"github.com/layervai/qurl-go/internal/x25519key"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

const (
	credentialRecoveryQuery                 = "agent_credential_recovery" //nolint:gosec // Protocol query name, not a credential.
	credentialRecoveryVersion               = 1
	credentialRecoveryMode                  = "recover"
	credentialRecoveryGrantPrefix           = "qrg1."
	credentialRecoveryMaxGrantBytes         = 2304
	credentialRecoveryGrantLifetime         = 15 * time.Minute
	credentialRecoveryFinalSaveTimeout      = 10 * time.Second
	credentialRecoveryUnavailableCode       = "52400"
	credentialRecoveryCredentialRejectCode  = "52401"
	credentialRecoveryHubIdentityCode       = "52402"
	credentialRecoveryRevokeRequiredCode    = "52403"
	credentialRecoveryRateLimitedCode       = "52404"
	credentialRecoveryHubInvalidCode        = "52405"
	credentialRecoveryAssignmentCode        = "52406"
	credentialReplacementUnavailableCode    = "52410"
	credentialRecoveryGrantRejectCode       = "52411"
	credentialRecoveryCellIdentityCode      = "52412"
	credentialRecoveryCandidateConflictCode = "52413"
	credentialRecoveryCellInvalidCode       = "52414"
)

// AgentCredentialRecoveryHorizon is the immutable client recovery window for
// one revoked-device episode. Its anchor is the first authenticated Hub grant
// expiry, never local receipt time or a later grant.
const AgentCredentialRecoveryHorizon = 90 * 24 * time.Hour

var (
	// ErrCredentialRecoveryInvalidResponse marks malformed authenticated Hub or
	// assigned-cell LRT data. It is terminal and never triggers endpoint fallback.
	ErrCredentialRecoveryInvalidResponse = errors.New("qurl: credential recovery response invalid")
	// ErrCredentialRecoveryUnavailable marks retryable Hub 52400.
	ErrCredentialRecoveryUnavailable = errors.New("qurl: credential recovery unavailable")
	// ErrRecoveryCredentialRejected marks terminal Hub 52401 without disclosing
	// whether the qurl:agent credential was absent, inactive, expired, or wrong.
	ErrRecoveryCredentialRejected = errors.New("qurl: recovery credential rejected")
	// ErrCredentialRecoveryIdentityRejected marks terminal Hub 52402 or cell 52412.
	ErrCredentialRecoveryIdentityRejected = errors.New("qurl: credential recovery identity rejected")
	// ErrCredentialRecoveryRevokeRequired marks Hub 52403: the current device
	// credential must be deliberately revoked before replacement.
	ErrCredentialRecoveryRevokeRequired = errors.New("qurl: revoke current device credential before recovery")
	// ErrCredentialRecoveryRateLimited marks retryable Hub 52404.
	ErrCredentialRecoveryRateLimited = errors.New("qurl: credential recovery rate limited")
	// ErrCredentialRecoveryRequestRejected marks terminal Hub 52405 or cell 52414.
	ErrCredentialRecoveryRequestRejected = errors.New("qurl: credential recovery request rejected")
	// ErrCredentialRecoveryAssignmentRequired marks terminal Hub 52406.
	ErrCredentialRecoveryAssignmentRequired = errors.New("qurl: credential recovery assignment requires operator recovery")
	// ErrCredentialReplacementUnavailable marks retryable assigned-cell 52410.
	ErrCredentialReplacementUnavailable = errors.New("qurl: credential replacement unavailable")
	// ErrCredentialRecoveryGrantRejected marks terminal assigned-cell 52411. The
	// exact candidate remains durable; the next explicit call may ask Hub for a
	// fresh grant but must not rotate that candidate or its episode anchor.
	ErrCredentialRecoveryGrantRejected = errors.New("qurl: credential recovery grant rejected")
	// ErrCredentialRecoveryCandidateConflict marks terminal cell 52413.
	ErrCredentialRecoveryCandidateConflict = errors.New("qurl: credential recovery candidate conflict")
	// ErrCredentialRecoveryRetryRequired marks bounded transport/application
	// retry exhaustion while durable state remains the only resume authority.
	ErrCredentialRecoveryRetryRequired = errors.New("qurl: credential recovery retry required")
	// ErrCredentialRecoveryCandidatePersistence marks a failed or ambiguous
	// save of the replacement candidate after authenticated Hub issuance.
	ErrCredentialRecoveryCandidatePersistence = errors.New("qurl: credential recovery candidate persistence failed")
	// ErrCredentialRecoveryExpired marks either the exact Authority-anchored
	// horizon or the earlier conservative cutoff on a still-unanchored Hub Issue.
	// No recovery datagram is sent at or after the applicable boundary.
	ErrCredentialRecoveryExpired = errors.New("qurl: credential recovery horizon expired")
	// ErrCredentialRecoveredAssignmentRefreshRequired means the assigned cell
	// committed the replacement credential and that result is durable, but the
	// SDK could not also obtain and persist a live Hub assignment. The caller must
	// refresh the runtime; it must not start another credential-recovery episode.
	ErrCredentialRecoveredAssignmentRefreshRequired = errors.New("qurl: credential recovered; assignment refresh required")
)

type credentialRecoveryPhase string

const (
	credentialRecoveryHubPhase  credentialRecoveryPhase = "hub_issue_recovery" //nolint:gosec // Protocol phase name, not a credential.
	credentialRecoveryCellPhase credentialRecoveryPhase = "assigned_cell_complete_recovery"
)

// CredentialRecoveryError is one authenticated closed-taxonomy 524xx denial.
// Only Code, Phase, and RetryAfter are retained; producer diagnostics are
// discarded so a buggy server cannot reflect a credential, grant, or candidate.
type CredentialRecoveryError struct {
	Code       string
	Phase      string
	RetryAfter time.Duration
	kind       error
}

func (e *CredentialRecoveryError) Error() string {
	if e == nil {
		return "qurl: credential recovery error"
	}
	return fmt.Sprintf("qurl: credential recovery %s error %s", e.Phase, e.Code)
}

func (e *CredentialRecoveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// CredentialRecoveryRetryRequiredError reports one exhausted Hub or cell
// logical-operation budget. It preserves the last classification without
// leaking secret-bearing bodies.
type CredentialRecoveryRetryRequiredError struct {
	Phase    string
	Attempts int
	Elapsed  time.Duration
	Last     error
}

// CredentialRecoveryCandidatePersistenceError reports that the exact recovery
// candidate could not be proven durable. It is recovery-specific and also
// unwraps ErrAgentBindingPersistence for generic store handling.
type CredentialRecoveryCandidatePersistenceError struct {
	AgentID string
	Cause   error
}

func (e *CredentialRecoveryCandidatePersistenceError) Error() string {
	agentID := ""
	if e != nil {
		agentID = e.AgentID
	}
	return fmt.Sprintf("%s for agent %q; reload the same state before retrying", ErrCredentialRecoveryCandidatePersistence, agentID)
}

func (e *CredentialRecoveryCandidatePersistenceError) Unwrap() []error {
	if e == nil {
		return []error{ErrCredentialRecoveryCandidatePersistence, ErrAgentBindingPersistence}
	}
	return unwrapWithCause(e.Cause, ErrCredentialRecoveryCandidatePersistence, ErrAgentBindingPersistence)
}

func (e *CredentialRecoveryRetryRequiredError) Error() string {
	if e == nil {
		return ErrCredentialRecoveryRetryRequired.Error()
	}
	return recoveryBudgetErrorString("credential recovery "+e.Phase, "resume the persisted recovery episode", e.Attempts, e.Elapsed, e.Last)
}

func (e *CredentialRecoveryRetryRequiredError) Unwrap() []error {
	if e == nil {
		return []error{ErrCredentialRecoveryRetryRequired}
	}
	return unwrapWithCause(e.Last, ErrCredentialRecoveryRetryRequired)
}

// CredentialRecoveryExpiredError carries the non-secret deadline that stopped
// recovery before another datagram write. It is either the immutable Authority
// episode deadline or the earlier local cutoff persisted before that Authority
// anchor was known.
type CredentialRecoveryExpiredError struct {
	RecoveryExpiresAt time.Time
}

func (e *CredentialRecoveryExpiredError) Error() string {
	if e == nil {
		return ErrCredentialRecoveryExpired.Error()
	}
	return fmt.Sprintf("%s at %s; persisted candidate was preserved", ErrCredentialRecoveryExpired, e.RecoveryExpiresAt.UTC().Format(time.RFC3339))
}

func (e *CredentialRecoveryExpiredError) Unwrap() error { return ErrCredentialRecoveryExpired }

// CredentialRecoveredAssignmentRefreshRequiredError preserves the cause of a
// failed post-recovery Hub refresh. At this point the replacement credential is
// already durable; call RefreshAgentRuntime rather than RecoverAgentRuntime.
type CredentialRecoveredAssignmentRefreshRequiredError struct {
	Cause error
}

func (e *CredentialRecoveredAssignmentRefreshRequiredError) Error() string {
	return ErrCredentialRecoveredAssignmentRefreshRequired.Error() + "; call RefreshAgentRuntime before using the runtime"
}

func (e *CredentialRecoveredAssignmentRefreshRequiredError) Unwrap() []error {
	if e == nil || e.Cause == nil {
		return []error{ErrCredentialRecoveredAssignmentRefreshRequired}
	}
	return []error{ErrCredentialRecoveredAssignmentRefreshRequired, e.Cause}
}

// RecoverAgentRuntime explicitly replaces a revoked or lost device API
// credential while preserving the persisted agent id and X25519 identity. It
// sends IssueCredentialRecovery to the pinned Hub over NHP/UDP, persists one
// exact candidate with the Authority-selected cell endpoint/key, then sends
// CompleteCredentialRecovery directly to that cell over NHP/UDP. It never uses
// HTTP, the browser relay, caller-selected placement, address derivation, cell
// probing, or cross-cell fallback.
//
// A pending episode resumes the exact cell request before Hub is consulted. An
// authenticated 52411 marks that grant for explicit renewal on the next call;
// transport ambiguity keeps the exact grant and request. Final credential
// persistence runs once after the network retry loop, so a store failure cannot
// mint or rotate a replacement candidate. The returned Client's ordinary qURL
// resource operations remain the separate steady-state HTTPS API.
func RecoverAgentRuntime(ctx context.Context, recoveryCredential string, store AgentStateStore, opts ...AgentRuntimeRecoveryOption) (*Client, *AgentRuntimeBinding, error) {
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return nil, nil, err
	}
	if store == nil {
		return nil, nil, fmt.Errorf("%w: state store must not be nil", ErrInvalidRegisterConfig)
	}
	cfg, err := newNativeAgentCredentialRecoveryConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	result, err := withAgentSetupLock(ctx, store, destroyNativeRuntimeResult, func() (*nativeRuntimeResult, error) {
		return cfg.recoverAgentRuntimeLocked(ctx, recoveryCredential, store)
	})
	if err != nil {
		return nil, nil, err
	}
	return result.split()
}

func newNativeAgentCredentialRecoveryConfig(opts []AgentRuntimeRecoveryOption) (*nativeAgentRuntimeConfig, error) {
	c := defaultNativeAgentRuntimeConfig()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil credential recovery option", ErrInvalidRegisterConfig)
		}
		if err := opt.applyAgentRuntimeOption(c); err != nil {
			return nil, err
		}
	}
	if c.hub == nil {
		return nil, fmt.Errorf("%w: WithAgentRuntimeRecoveryHub is required", ErrInvalidRegisterConfig)
	}
	if _, err := c.hub.nativeEndpoint(); err != nil {
		return nil, fmt.Errorf("%w: Hub trust root: %w", ErrInvalidRegisterConfig, err)
	}
	return c, nil
}

func (c *nativeAgentRuntimeConfig) recoverAgentRuntimeLocked(ctx context.Context, recoveryCredential string, store AgentStateStore) (*nativeRuntimeResult, error) {
	state, err := loadExistingAgentState(ctx, store, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	if err := validateCompletedAgentIdentity(state, ErrInvalidRegisterConfig); err != nil {
		return nil, err
	}
	if state.PendingActivation != nil || state.PendingCompletion != nil {
		return nil, fmt.Errorf("%w: finish or explicitly abandon pending registration before credential recovery", ErrInvalidRegisterConfig)
	}
	if !isNativeAgentRuntimeState(state) {
		return nil, fmt.Errorf("%w: credential recovery requires persisted native runtime identity", ErrInvalidRegisterConfig)
	}
	// Recovery is an assignment-preserving transition. Require the already-
	// validated persisted assignment before decoding the private key, saving any
	// intent, resolving DNS, or emitting a datagram.
	if state.Assignment == nil {
		return nil, fmt.Errorf("%w: credential recovery requires a persisted assignment", ErrInvalidRegisterConfig)
	}
	privateKey, err := decodeRuntimePrivateKey(state, ErrInvalidRegisterConfig)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(privateKey)

	if state.PendingCredentialRecovery == nil && state.PendingCredentialRecoveryIssue != nil {
		if err := c.requireCredentialRecoveryIssueLive(state.PendingCredentialRecoveryIssue); err != nil {
			return nil, err
		}
	}
	if state.PendingCredentialRecovery == nil || state.PendingCredentialRecovery.NeedsFreshGrant || state.PendingCredentialRecoveryIssue != nil {
		usedNonce, err := c.issueAndPersistCredentialRecovery(ctx, recoveryCredential, store, state, privateKey, "")
		if err != nil {
			return nil, err
		}
		// An exact Issue replay may arrive after its 15-minute grant or assignment
		// lease has expired while the 90-day episode remains live. Persist its
		// immutable anchor and candidate, then spend at most one new nonce in this
		// explicit call. Never send the stale grant to a cell.
		if state.PendingCredentialRecovery != nil && state.PendingCredentialRecovery.NeedsFreshGrant {
			if _, err := c.issueAndPersistCredentialRecovery(ctx, recoveryCredential, store, state, privateKey, usedNonce); err != nil {
				return nil, err
			}
			if state.PendingCredentialRecovery.NeedsFreshGrant {
				return nil, &CredentialRecoveryRetryRequiredError{
					Phase: string(credentialRecoveryHubPhase), Attempts: 2,
					Last: errors.New("authenticated Hub recovery grant replay is no longer live"),
				}
			}
		}
	}

	keyID, err := c.completeCredentialRecovery(ctx, state, privateKey)
	if err != nil {
		if errors.Is(err, ErrCredentialRecoveryGrantRejected) {
			if saveErr := c.markCredentialRecoveryGrantRejected(ctx, store, state); saveErr != nil {
				return nil, errors.Join(err, saveErr)
			}
		}
		return nil, err
	}
	pending := state.PendingCredentialRecovery
	next := state.clone()
	next.DeviceAPIKey = pending.DeviceAPIKey
	next.DeviceAPIKeyID = keyID
	next.Assignment = pending.Assignment.clone()
	next.PendingCredentialRecovery = nil
	next.PendingCredentialRecoveryIssue = nil
	next.SchemaVersion = agentStateSchemaVersion
	// The authenticated cell may already have committed even if the caller is
	// canceled as the LRT arrives. Persist that irreversible result under a small
	// detached deadline while the setup lock is still held; otherwise an exact
	// replay may be forbidden once the recovery horizon closes.
	persistCtx, cancelPersist := credentialRecoveryPersistenceContext(ctx)
	defer cancelPersist()
	if err := c.saveCredentialRecoveryState(persistCtx, store, state, next, ErrAgentBindingPersistence, "persist recovered native credential"); err != nil {
		return nil, err
	}
	return c.finishRecoveredRuntime(ctx, store, state, privateKey)
}

func (c *nativeAgentRuntimeConfig) finishRecoveredRuntime(ctx context.Context, store AgentStateStore, state *AgentState, privateKey []byte) (*nativeRuntimeResult, error) {
	if state == nil || state.Assignment == nil {
		return nil, &CredentialRecoveredAssignmentRefreshRequiredError{
			Cause: fmt.Errorf("%w: recovered state has no assignment", ErrInvalidAgentState),
		}
	}
	if state.Assignment.LeaseExpired(c.clock()) {
		fresh, err := c.refreshAssignmentLifecycle(ctx, *c.hub, state.AgentID, privateKey)
		if err != nil {
			return nil, &CredentialRecoveredAssignmentRefreshRequiredError{Cause: err}
		}
		// Recovery is already an explicit authority-directed transition. Accept a
		// reassignment here only when the authenticated Hub advances generation;
		// the ordinary standalone refresh API keeps its explicit adoption option.
		if err := ensureRefreshAssignmentContinuity(state.Assignment, fresh, true); err != nil {
			return nil, &CredentialRecoveredAssignmentRefreshRequiredError{Cause: err}
		}
		if !sameAgentAssignment(state.Assignment, fresh) {
			next := state.clone()
			next.Assignment = fresh.clone()
			if err := c.saveCredentialRecoveryState(ctx, store, state, next, ErrAgentBindingPersistence, "persist post-recovery assignment refresh"); err != nil {
				return nil, &CredentialRecoveredAssignmentRefreshRequiredError{Cause: err}
			}
		}
	}
	result, err := finishNativeRuntimeResult(store, state, c)
	if errors.Is(err, ErrAssignmentLeaseExpired) {
		return nil, &CredentialRecoveredAssignmentRefreshRequiredError{Cause: err}
	}
	return result, err
}

type credentialRecoveryIssue struct {
	Assignment             AgentAssignment
	RecoveryGrant          string
	RecoveryGrantIssuedAt  time.Time
	RecoveryGrantExpiresAt time.Time
	NeedsFreshGrant        bool
}

type credentialRecoveryRequestData struct {
	Query        string `json:"query"`
	Version      int    `json:"version"`
	Mode         string `json:"mode"`
	RequestNonce string `json:"request_nonce"`
	Credential   string `json:"credential"`
}

type credentialRecoveryRawRequest struct {
	UsrID   string          `json:"usrId"`
	DevID   string          `json:"devId"`
	AspID   string          `json:"aspId"`
	UsrData json.RawMessage `json:"usrData"`
}

type credentialRecoveryIssueList struct {
	Query                  string          `json:"query"`
	Version                int             `json:"version"`
	Mode                   string          `json:"mode"`
	AgentID                string          `json:"agent_id"`
	Assignment             json.RawMessage `json:"assignment"`
	RecoveryGrant          string          `json:"recovery_grant"`
	RecoveryGrantIssuedAt  string          `json:"recovery_grant_issued_at"`
	RecoveryGrantExpiresAt string          `json:"recovery_grant_expires_at"`
}

const (
	credentialRecoveryIssuePrefix       = `{"usrId":"","devId":"`                                                                                 //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryIssueAgentSuffix  = `","aspId":"agent","usrData":{"query":"cell_assignment","version":1,"mode":"recover","request_nonce":"` //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryIssueNonceSuffix  = `","credential":"`                                                                                      //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryIssueSuffix       = `"}}`
	credentialRecoveryCompletePrefix    = `{"usrId":"","devId":"`                                                                           //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryCompleteAgentTail = `","aspId":"agent","usrData":{"query":"agent_credential_recovery","version":1,"recovery_grant":"` //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryCompleteGrantTail = `","device_api_key":"`                                                                            //nolint:gosec // JSON wire syntax, not a credential.
	credentialRecoveryCompleteSuffix    = `"}}`
)

func marshalCredentialRecoveryIssueRequest(agentID, nonce, credential string) ([]byte, error) {
	if validateAssignmentAgentID(agentID) != nil || validateCredentialRecoveryRequestNonce(nonce) != nil ||
		validateNativeDeviceCredential(credential, "recovery credential", ErrInvalidRegisterConfig) != nil {
		return nil, invalidCredentialRecoveryRequest(credentialRecoveryHubPhase)
	}
	want := len(credentialRecoveryIssuePrefix) + len(agentID) + len(credentialRecoveryIssueAgentSuffix) +
		len(nonce) + len(credentialRecoveryIssueNonceSuffix) + len(credential) + len(credentialRecoveryIssueSuffix)
	body := make([]byte, 0, want)
	body = append(body, credentialRecoveryIssuePrefix...)
	body = append(body, agentID...)
	body = append(body, credentialRecoveryIssueAgentSuffix...)
	body = append(body, nonce...)
	body = append(body, credentialRecoveryIssueNonceSuffix...)
	body = append(body, credential...)
	body = append(body, credentialRecoveryIssueSuffix...)
	if len(body) != want || cap(body) != want || len(body) > nhpcontract.MaxApplicationBodySize {
		wipeBytes(body)
		return nil, fmt.Errorf("%w: encoded Hub recovery request exceeds NHP application limit", ErrInvalidRegisterConfig)
	}
	return body, nil
}

func (c *nativeAgentRuntimeConfig) issueAndPersistCredentialRecovery(ctx context.Context, credential string, store AgentStateStore, state *AgentState, privateKey []byte, forbiddenNonce string) (string, error) {
	renewal := state.PendingCredentialRecovery != nil
	var (
		boundary     *credentialRecoveryBoundary
		operationCtx                    = ctx
		cancel       context.CancelFunc = func() {}
	)
	if renewal {
		if !state.PendingCredentialRecovery.NeedsFreshGrant {
			return "", fmt.Errorf("%w: usable recovery grant cannot issue another Hub request", ErrInvalidAgentState)
		}
		var err error
		boundary, operationCtx, cancel, err = c.credentialRecoveryBoundary(ctx, state.PendingCredentialRecovery)
		if err != nil {
			return "", err
		}
	} else if state.PendingCredentialRecoveryIssue != nil {
		var err error
		boundary, operationCtx, cancel, err = c.credentialRecoveryIssueBoundary(ctx, state.PendingCredentialRecoveryIssue)
		if err != nil {
			return "", err
		}
	}
	defer func() { cancel() }()
	if err := validateNativeDeviceCredential(credential, "recovery credential", ErrInvalidRegisterConfig); err != nil {
		return "", err
	}

	if state.PendingCredentialRecoveryIssue == nil {
		if err := c.persistCredentialRecoveryIssueIntent(operationCtx, store, state, credential, forbiddenNonce); err != nil {
			return "", err
		}
		if renewal {
			if err := boundary.check(); err != nil {
				return "", err
			}
		} else {
			var err error
			boundary, operationCtx, cancel, err = c.credentialRecoveryIssueBoundary(ctx, state.PendingCredentialRecoveryIssue)
			if err != nil {
				return "", err
			}
		}
	} else {
		if !sameCredentialRecoveryCredential(credential, state.PendingCredentialRecoveryIssue.RecoveryCredentialFingerprintB64) {
			return "", fmt.Errorf("%w: recovery credential does not match pending Hub issue", ErrInvalidRegisterConfig)
		}
		if !sameCredentialRecoveryHub(*c.hub, state.PendingCredentialRecoveryIssue) {
			return "", fmt.Errorf("%w: Hub trust root does not match pending credential recovery issue", ErrInvalidRegisterConfig)
		}
	}
	usedNonce := state.PendingCredentialRecoveryIssue.RequestNonce
	if forbiddenNonce != "" && usedNonce == forbiddenNonce {
		return "", fmt.Errorf("%w: fresh credential recovery Hub request reused its prior nonce", ErrInvalidAgentState)
	}

	issued, err := c.issueCredentialRecovery(operationCtx, state.AgentID, credential, usedNonce, privateKey)
	if err != nil {
		if terminalCredentialRecoveryHubError(err) {
			if clearErr := c.clearCredentialRecoveryIssueIntent(ctx, store, state); clearErr != nil {
				return "", errors.Join(err, clearErr)
			}
		}
		if boundary != nil {
			return "", boundary.mapError(ctx, operationCtx, err)
		}
		return "", err
	}
	if renewal {
		if err := boundary.check(); err != nil {
			return "", err
		}
		persistCtx, cancelPersist := credentialRecoveryPersistenceContext(operationCtx)
		defer cancelPersist()
		return usedNonce, c.persistRenewedCredentialRecovery(persistCtx, store, state, issued)
	}
	candidate, err := c.generateDeviceCredential()
	if err != nil {
		return "", err
	}
	persistCtx, cancelPersist := credentialRecoveryPersistenceContext(operationCtx)
	defer cancelPersist()
	return usedNonce, c.persistInitialCredentialRecovery(persistCtx, store, state, issued, candidate)
}

func credentialRecoveryPersistenceContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), credentialRecoveryFinalSaveTimeout)
}

func terminalCredentialRecoveryHubError(err error) bool {
	var classified *CredentialRecoveryError
	return errors.As(err, &classified) && classified.Phase == string(credentialRecoveryHubPhase) && classified.RetryAfter == 0
}

func (c *nativeAgentRuntimeConfig) clearCredentialRecoveryIssueIntent(ctx context.Context, store AgentStateStore, state *AgentState) error {
	if state == nil || state.PendingCredentialRecoveryIssue == nil {
		return nil
	}
	next := state.clone()
	next.PendingCredentialRecoveryIssue = nil
	return c.saveCredentialRecoveryState(ctx, store, state, next, ErrAgentBindingPersistence, "clear terminal credential recovery Hub request intent")
}

func (c *nativeAgentRuntimeConfig) persistCredentialRecoveryIssueIntent(ctx context.Context, store AgentStateStore, state *AgentState, credential, forbiddenNonce string) error {
	retry, err := newAssignmentConfig(c.assignmentOptions)
	if err != nil {
		return err
	}
	nonce, err := drawAssignmentRequestNonce(retry)
	if err != nil {
		return err
	}
	if forbiddenNonce != "" && nonce == forbiddenNonce {
		return fmt.Errorf("%w: fresh credential recovery Hub request reused its prior nonce", ErrInvalidAgentState)
	}
	next := state.clone()
	now := c.clock().UTC().Truncate(time.Second)
	replayNotAfter, err := credentialRecoveryDeadline(now)
	if err != nil {
		return err
	}
	if state.PendingCredentialRecovery != nil && state.PendingCredentialRecovery.RecoveryExpiresAt.Before(replayNotAfter) {
		replayNotAfter = state.PendingCredentialRecovery.RecoveryExpiresAt
	}
	next.PendingCredentialRecoveryIssue = &PendingAgentCredentialRecoveryIssue{
		RequestNonce:                     nonce,
		ReplayNotAfter:                   replayNotAfter,
		RecoveryCredentialFingerprintB64: credentialRecoveryCredentialFingerprint(credential),
		AgentID:                          state.AgentID,
		AgentPublicKeyB64:                state.PublicKeyB64,
		HubHost:                          c.hub.Host,
		HubPort:                          c.hub.Port,
		HubServerPublicKeyB64:            c.hub.ServerPublicKeyB64,
	}
	next.SchemaVersion = agentStateSchemaVersion
	if err := validatePendingCredentialRecoveryIssue(next.PendingCredentialRecoveryIssue); err != nil {
		return err
	}
	return c.saveCredentialRecoveryState(ctx, store, state, next, ErrAgentBindingPersistence, "persist credential recovery Hub request intent")
}

func (c *nativeAgentRuntimeConfig) issueCredentialRecovery(ctx context.Context, agentID, credential, nonce string, privateKey []byte) (*credentialRecoveryIssue, error) {
	endpoint, err := validateAssignmentInputs(ctx, *c.hub, agentID, c.udpOptions(privateKey))
	if err != nil {
		return nil, err
	}
	retry, err := newAssignmentConfig(c.assignmentOptions)
	if err != nil {
		return nil, err
	}
	body, err := marshalCredentialRecoveryIssueRequest(agentID, nonce, credential)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(body)
	return runNativeExchange(ctx, retry, endpoint, body, c.udpOptions(privateKey), nativeudp.AssignmentList,
		credentialRecoveryRetryInfo, newCredentialRecoveryRequired(credentialRecoveryHubPhase),
		func(reply []byte, now time.Time) (*credentialRecoveryIssue, error) {
			return parseCredentialRecoveryIssueReply(reply, agentID, now)
		})
}

func validateCredentialRecoveryIssueRequest(body []byte) error {
	var outer credentialRecoveryRawRequest
	if err := decodeExactObject(body, &outer, []string{"usrId", "devId", "aspId", "usrData"}); err != nil {
		return invalidCredentialRecoveryRequest(credentialRecoveryHubPhase)
	}
	var data credentialRecoveryRequestData
	if err := decodeExactObject(outer.UsrData, &data, []string{"query", "version", "mode", "request_nonce", "credential"}); err != nil ||
		outer.UsrID != "" || validateAssignmentAgentID(outer.DevID) != nil || outer.AspID != agentAspID ||
		data.Query != assignmentQuery || data.Version != assignmentVersion || data.Mode != credentialRecoveryMode ||
		validateCredentialRecoveryRequestNonce(data.RequestNonce) != nil ||
		validateNativeDeviceCredential(data.Credential, "recovery credential", ErrInvalidRegisterConfig) != nil {
		return invalidCredentialRecoveryRequest(credentialRecoveryHubPhase)
	}
	return nil
}

func parseCredentialRecoveryIssueReply(body []byte, wantAgentID string, now time.Time) (*credentialRecoveryIssue, error) {
	list, err := parseCredentialRecoveryEnvelope(body, credentialRecoveryHubPhase)
	if err != nil {
		return nil, err
	}
	var wire credentialRecoveryIssueList
	if err := decodeExactObject(list, &wire, []string{
		"query", "version", "mode", "agent_id", "assignment", "recovery_grant", "recovery_grant_issued_at", "recovery_grant_expires_at",
	}); err != nil {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	if wire.Query != assignmentQuery || wire.Version != assignmentVersion || wire.Mode != credentialRecoveryMode || wire.AgentID != wantAgentID {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	if err := validateCredentialRecoveryGrant(wire.RecoveryGrant); err != nil {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	issuedAt, err := parseCanonicalRFC3339(wire.RecoveryGrantIssuedAt)
	if err != nil {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	expiresAt, err := parseCanonicalRFC3339(wire.RecoveryGrantExpiresAt)
	if err != nil || expiresAt.Sub(issuedAt) != credentialRecoveryGrantLifetime {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	if _, err := credentialRecoveryDeadline(expiresAt); err != nil {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	// Issue is exactly idempotent by request nonce and can therefore replay after
	// the 15-minute grant or assignment lease expires. Decode the complete trust
	// binding structurally in every case, then explicitly mark stale authority
	// data so callers persist the original episode anchor but never write it to a
	// cell. A live result has the same validation plus both liveness checks below.
	assignment, err := parsePersistedWireAssignment(wire.Assignment)
	if err != nil || !expiresAt.Before(assignment.LeaseExpiresAt) {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryHubPhase)
	}
	now = now.UTC()
	return &credentialRecoveryIssue{
		Assignment: *assignment, RecoveryGrant: wire.RecoveryGrant,
		RecoveryGrantIssuedAt: issuedAt, RecoveryGrantExpiresAt: expiresAt,
		NeedsFreshGrant: !now.Before(expiresAt) || !now.Before(assignment.LeaseExpiresAt),
	}, nil
}

func (c *nativeAgentRuntimeConfig) persistInitialCredentialRecovery(ctx context.Context, store AgentStateStore, state *AgentState, issued *credentialRecoveryIssue, candidate string) error {
	if issued == nil {
		return fmt.Errorf("%w: missing authenticated Hub recovery result", ErrCredentialRecoveryInvalidResponse)
	}
	if err := ensureRefreshAssignmentContinuity(state.Assignment, &issued.Assignment, true); err != nil {
		return fmt.Errorf("%w: initial credential recovery assignment: %w", ErrCredentialRecoveryInvalidResponse, err)
	}
	deadline, err := credentialRecoveryDeadline(issued.RecoveryGrantExpiresAt)
	if err != nil {
		return err
	}
	next := state.clone()
	next.Assignment = issued.Assignment.clone()
	// The authenticated Hub result proves that Authority observed the current
	// device credential as revoked. Do not retain that unusable bearer secret or
	// its stale public id beside the pending replacement candidate.
	next.DeviceAPIKey = ""
	next.DeviceAPIKeyID = ""
	next.PendingCredentialRecovery = &PendingAgentCredentialRecovery{
		RecoveryGrant: issued.RecoveryGrant, RecoveryGrantIssuedAt: issued.RecoveryGrantIssuedAt,
		RecoveryGrantExpiresAt:       issued.RecoveryGrantExpiresAt,
		RecoveryAnchorGrantExpiresAt: issued.RecoveryGrantExpiresAt, RecoveryExpiresAt: deadline,
		DeviceAPIKey: candidate, Assignment: issued.Assignment,
		NeedsFreshGrant: issued.NeedsFreshGrant,
	}
	next.PendingCredentialRecoveryIssue = nil
	next.SchemaVersion = agentStateSchemaVersion
	if err := validatePendingAgentCredentialRecovery(next.PendingCredentialRecovery, next); err != nil {
		return err
	}
	if err := c.saveCredentialRecoveryState(ctx, store, state, next, ErrCredentialRecoveryCandidatePersistence, "persist credential recovery candidate"); err != nil {
		return &CredentialRecoveryCandidatePersistenceError{AgentID: state.AgentID, Cause: err}
	}
	return c.requireCredentialRecoveryLive(state.PendingCredentialRecovery)
}

func (c *nativeAgentRuntimeConfig) persistRenewedCredentialRecovery(ctx context.Context, store AgentStateStore, state *AgentState, issued *credentialRecoveryIssue) error {
	if issued == nil || state.PendingCredentialRecovery == nil {
		return fmt.Errorf("%w: missing renewed recovery state", ErrInvalidAgentState)
	}
	if err := c.requireCredentialRecoveryLive(state.PendingCredentialRecovery); err != nil {
		return err
	}
	if err := ensureRefreshAssignmentContinuity(&state.PendingCredentialRecovery.Assignment, &issued.Assignment, true); err != nil {
		return fmt.Errorf("%w: renewed credential recovery assignment: %w", ErrCredentialRecoveryInvalidResponse, err)
	}
	next := state.clone()
	next.Assignment = issued.Assignment.clone()
	pending := next.PendingCredentialRecovery
	pending.Assignment = issued.Assignment
	pending.RecoveryGrant = issued.RecoveryGrant
	pending.RecoveryGrantIssuedAt = issued.RecoveryGrantIssuedAt
	pending.RecoveryGrantExpiresAt = issued.RecoveryGrantExpiresAt
	pending.NeedsFreshGrant = issued.NeedsFreshGrant
	next.PendingCredentialRecoveryIssue = nil
	if err := validatePendingAgentCredentialRecovery(pending, next); err != nil {
		return err
	}
	return c.saveCredentialRecoveryState(ctx, store, state, next, ErrAgentBindingPersistence, "persist renewed credential recovery grant")
}

type credentialRecoveryCompletionRequestData struct {
	Query         string `json:"query"`
	Version       int    `json:"version"`
	RecoveryGrant string `json:"recovery_grant"`
	DeviceAPIKey  string `json:"device_api_key"`
}

type credentialRecoveryCompletionList struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

func marshalCredentialRecoveryCompletionRequest(agentID, grant, candidate string) ([]byte, error) {
	if validateAssignmentAgentID(agentID) != nil || validateCredentialRecoveryGrant(grant) != nil ||
		validateNativeDeviceCredential(candidate, "recovery candidate", ErrInvalidRegisterConfig) != nil {
		return nil, invalidCredentialRecoveryRequest(credentialRecoveryCellPhase)
	}
	want := len(credentialRecoveryCompletePrefix) + len(agentID) + len(credentialRecoveryCompleteAgentTail) +
		len(grant) + len(credentialRecoveryCompleteGrantTail) + len(candidate) + len(credentialRecoveryCompleteSuffix)
	body := make([]byte, 0, want)
	body = append(body, credentialRecoveryCompletePrefix...)
	body = append(body, agentID...)
	body = append(body, credentialRecoveryCompleteAgentTail...)
	body = append(body, grant...)
	body = append(body, credentialRecoveryCompleteGrantTail...)
	body = append(body, candidate...)
	body = append(body, credentialRecoveryCompleteSuffix...)
	if len(body) != want || cap(body) != want || len(body) > nhpcontract.MaxApplicationBodySize {
		wipeBytes(body)
		return nil, fmt.Errorf("%w: encoded assigned-cell recovery request exceeds NHP application limit", ErrInvalidRegisterConfig)
	}
	return body, nil
}

func validateCredentialRecoveryCompletionRequest(body []byte) error {
	var outer credentialRecoveryRawRequest
	if err := decodeExactObject(body, &outer, []string{"usrId", "devId", "aspId", "usrData"}); err != nil {
		return invalidCredentialRecoveryRequest(credentialRecoveryCellPhase)
	}
	var data credentialRecoveryCompletionRequestData
	if err := decodeExactObject(outer.UsrData, &data, []string{"query", "version", "recovery_grant", "device_api_key"}); err != nil ||
		outer.UsrID != "" || validateAssignmentAgentID(outer.DevID) != nil || outer.AspID != agentAspID ||
		data.Query != credentialRecoveryQuery || data.Version != credentialRecoveryVersion ||
		validateCredentialRecoveryGrant(data.RecoveryGrant) != nil ||
		validateNativeDeviceCredential(data.DeviceAPIKey, "recovery candidate", ErrInvalidRegisterConfig) != nil {
		return invalidCredentialRecoveryRequest(credentialRecoveryCellPhase)
	}
	return nil
}

func (c *nativeAgentRuntimeConfig) completeCredentialRecovery(ctx context.Context, state *AgentState, privateKey []byte) (string, error) {
	pending := state.PendingCredentialRecovery
	if pending == nil || pending.NeedsFreshGrant {
		return "", fmt.Errorf("%w: credential recovery has no usable persisted grant", ErrInvalidAgentState)
	}
	boundary, recoveryCtx, cancel, err := c.credentialRecoveryBoundary(ctx, pending)
	if err != nil {
		return "", err
	}
	defer cancel()
	body, err := marshalCredentialRecoveryCompletionRequest(state.AgentID, pending.RecoveryGrant, pending.DeviceAPIKey)
	if err != nil {
		return "", err
	}
	defer wipeBytes(body)
	endpoint, err := assignmentNativeEndpoint(&pending.Assignment)
	if err != nil {
		return "", err
	}
	retry, err := newAssignmentConfig(c.assignmentOptions)
	if err != nil {
		return "", err
	}
	keyID, err := runNativeExchange(recoveryCtx, retry, endpoint, body, c.udpOptions(privateKey), nativeudp.List,
		credentialRecoveryRetryInfo, newCredentialRecoveryRequired(credentialRecoveryCellPhase),
		func(reply []byte, _ time.Time) (*string, error) {
			return parseCredentialRecoveryCompletionReply(reply)
		})
	if err != nil {
		return "", boundary.mapError(ctx, recoveryCtx, err)
	}
	// The fence immediately before the UDP write is the client authorization
	// boundary. Once an authenticated success arrives, preserve it even if the
	// local clock crossed the horizon while the datagram was in flight: the cell
	// may already have committed and no post-horizon retry is permitted.
	return *keyID, nil
}

func parseCredentialRecoveryCompletionReply(body []byte) (*string, error) {
	list, err := parseCredentialRecoveryEnvelope(body, credentialRecoveryCellPhase)
	if err != nil {
		return nil, err
	}
	var wire credentialRecoveryCompletionList
	if err := decodeExactObject(list, &wire, []string{"query", "version", "device_api_key_id"}); err != nil {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryCellPhase)
	}
	if wire.Query != credentialRecoveryQuery || wire.Version != credentialRecoveryVersion || !validAPIKeyID(wire.DeviceAPIKeyID) {
		return nil, invalidCredentialRecoveryResponse(credentialRecoveryCellPhase)
	}
	return &wire.DeviceAPIKeyID, nil
}

func parseCredentialRecoveryEnvelope(body []byte, phase credentialRecoveryPhase) (json.RawMessage, error) {
	fields, err := exactObjectFields(body)
	if err != nil {
		return nil, invalidCredentialRecoveryResponse(phase)
	}
	if _, ok := fields["errCode"]; !ok {
		return nil, invalidCredentialRecoveryResponse(phase)
	}
	var envelope assignmentEnvelope
	if err := strictDecodeJSON(body, &envelope); err != nil {
		return nil, invalidCredentialRecoveryResponse(phase)
	}
	if envelope.ErrCode == "0" {
		if _, ok := fields["list"]; len(fields) != 2 || !ok || isJSONNull(envelope.List) {
			return nil, invalidCredentialRecoveryResponse(phase)
		}
		return envelope.List, nil
	}
	if _, ok := fields["list"]; ok {
		return nil, invalidCredentialRecoveryResponse(phase)
	}
	return nil, classifyCredentialRecoveryError(envelope, fields, phase)
}

func classifyCredentialRecoveryError(envelope assignmentEnvelope, fields map[string]json.RawMessage, phase credentialRecoveryPhase) error {
	if raw, ok := fields["errMsg"]; ok && isJSONNull(raw) {
		return invalidCredentialRecoveryResponse(phase)
	}
	var kind error
	var retry time.Duration
	switch phase {
	case credentialRecoveryHubPhase:
		switch envelope.ErrCode {
		case credentialRecoveryUnavailableCode:
			kind, retry = ErrCredentialRecoveryUnavailable, 5*time.Second
		case credentialRecoveryCredentialRejectCode:
			kind = ErrRecoveryCredentialRejected
		case credentialRecoveryHubIdentityCode:
			kind = ErrCredentialRecoveryIdentityRejected
		case credentialRecoveryRevokeRequiredCode:
			kind = ErrCredentialRecoveryRevokeRequired
		case credentialRecoveryRateLimitedCode:
			kind, retry = ErrCredentialRecoveryRateLimited, 60*time.Second
		case credentialRecoveryHubInvalidCode:
			kind = ErrCredentialRecoveryRequestRejected
		case credentialRecoveryAssignmentCode:
			kind = ErrCredentialRecoveryAssignmentRequired
		}
	case credentialRecoveryCellPhase:
		switch envelope.ErrCode {
		case credentialReplacementUnavailableCode:
			kind, retry = ErrCredentialReplacementUnavailable, 5*time.Second
		case credentialRecoveryGrantRejectCode:
			kind = ErrCredentialRecoveryGrantRejected
		case credentialRecoveryCellIdentityCode:
			kind = ErrCredentialRecoveryIdentityRejected
		case credentialRecoveryCandidateConflictCode:
			kind = ErrCredentialRecoveryCandidateConflict
		case credentialRecoveryCellInvalidCode:
			kind = ErrCredentialRecoveryRequestRejected
		}
	}
	if kind == nil {
		return invalidCredentialRecoveryResponse(phase)
	}
	retryAfter, err := parseEnvelopeRetryAfter(envelope, fields, retry > 0, retry > 0)
	if err != nil || retryAfter != retry {
		return invalidCredentialRecoveryResponse(phase)
	}
	return &CredentialRecoveryError{Code: envelope.ErrCode, Phase: string(phase), RetryAfter: retryAfter, kind: kind}
}

func invalidCredentialRecoveryResponse(phase credentialRecoveryPhase) error {
	return fmt.Errorf("%w: invalid %s LRT", ErrCredentialRecoveryInvalidResponse, phase)
}

func invalidCredentialRecoveryRequest(phase credentialRecoveryPhase) error {
	return fmt.Errorf("%w: invalid %s LST", ErrInvalidRegisterConfig, phase)
}

func credentialRecoveryRetryInfo(err error) (time.Duration, bool) {
	if nativeTransportRetryable(err) {
		return 0, true
	}
	var appErr *CredentialRecoveryError
	if errors.As(err, &appErr) && appErr.RetryAfter > 0 &&
		(errors.Is(appErr, ErrCredentialRecoveryUnavailable) || errors.Is(appErr, ErrCredentialRecoveryRateLimited) || errors.Is(appErr, ErrCredentialReplacementUnavailable)) {
		return appErr.RetryAfter, true
	}
	return 0, false
}

func newCredentialRecoveryRequired(phase credentialRecoveryPhase) recoveryFunc {
	return func(attempts int, elapsed time.Duration, last error) error {
		return &CredentialRecoveryRetryRequiredError{Phase: string(phase), Attempts: attempts, Elapsed: elapsed, Last: last}
	}
}

func validateCredentialRecoveryGrant(grant string) error {
	if len(grant) <= len(credentialRecoveryGrantPrefix) || len(grant) > credentialRecoveryMaxGrantBytes || !strings.HasPrefix(grant, credentialRecoveryGrantPrefix) {
		return errors.New("invalid recovery grant")
	}
	for i := len(credentialRecoveryGrantPrefix); i < len(grant); i++ {
		b := grant[i]
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return errors.New("invalid recovery grant")
		}
	}
	return nil
}

func validateCredentialRecoveryRequestNonce(nonce string) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	defer wipeBytes(raw)
	if err != nil || len(raw) != assignmentRequestNonceBytes || base64.RawURLEncoding.EncodeToString(raw) != nonce {
		return errors.New("invalid credential recovery request nonce")
	}
	return nil
}

func credentialRecoveryCredentialFingerprint(credential string) string {
	const domain = agentstatecontract.PendingCredentialRecoveryCredentialFingerprintDomain
	material := make([]byte, len(domain)+len(credential))
	copy(material, domain)
	copy(material[len(domain):], credential)
	digest := sha256.Sum256(material)
	wipeBytes(material)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func sameCredentialRecoveryCredential(credential, wantFingerprint string) bool {
	got := credentialRecoveryCredentialFingerprint(credential)
	return subtle.ConstantTimeCompare([]byte(got), []byte(wantFingerprint)) == 1
}

func validatePendingCredentialRecoveryIssue(issue *PendingAgentCredentialRecoveryIssue) error {
	invalid := func() error {
		return fmt.Errorf("%w: pending credential recovery Hub issue is invalid", ErrInvalidAgentState)
	}
	if issue == nil || validateCredentialRecoveryRequestNonce(issue.RequestNonce) != nil {
		return invalid()
	}
	if issue.ReplayNotAfter.IsZero() || issue.ReplayNotAfter.Location() != time.UTC || issue.ReplayNotAfter.Nanosecond() != 0 {
		return invalid()
	}
	if validateAssignmentAgentID(issue.AgentID) != nil {
		return invalid()
	}
	publicKey, err := x25519key.DecodeCanonicalBase64(issue.AgentPublicKeyB64)
	wipeBytes(publicKey)
	if err != nil {
		return invalid()
	}
	fingerprint, err := base64.RawURLEncoding.Strict().DecodeString(issue.RecoveryCredentialFingerprintB64)
	defer wipeBytes(fingerprint)
	if err != nil || len(fingerprint) != sha256.Size || base64.RawURLEncoding.EncodeToString(fingerprint) != issue.RecoveryCredentialFingerprintB64 {
		return invalid()
	}
	if _, err := (HubBootstrap{Host: issue.HubHost, Port: issue.HubPort, ServerPublicKeyB64: issue.HubServerPublicKeyB64}).nativeEndpoint(); err != nil {
		return invalid()
	}
	return nil
}

func sameCredentialRecoveryHub(hub HubBootstrap, issue *PendingAgentCredentialRecoveryIssue) bool {
	return issue != nil && hub.Host == issue.HubHost && hub.Port == issue.HubPort && hub.ServerPublicKeyB64 == issue.HubServerPublicKeyB64
}

func credentialRecoveryDeadline(anchor time.Time) (time.Time, error) {
	if anchor.IsZero() || anchor.Location() != time.UTC || anchor.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("%w: credential recovery anchor is invalid", ErrInvalidAgentState)
	}
	deadline := anchor.Add(AgentCredentialRecoveryHorizon)
	if !deadline.After(anchor) || deadline.Year() > 9999 {
		return time.Time{}, fmt.Errorf("%w: credential recovery deadline is out of range", ErrInvalidAgentState)
	}
	return deadline, nil
}

func validatePendingAgentCredentialRecovery(pending *PendingAgentCredentialRecovery, state *AgentState) error {
	invalid := func() error { return fmt.Errorf("%w: pending credential recovery is invalid", ErrInvalidAgentState) }
	if pending == nil || state == nil || state.Assignment == nil || !sameAgentAssignment(&pending.Assignment, state.Assignment) {
		return invalid()
	}
	if validateCredentialRecoveryGrant(pending.RecoveryGrant) != nil ||
		validateNativeDeviceCredential(pending.DeviceAPIKey, "pending recovery candidate", ErrInvalidAgentState) != nil {
		return invalid()
	}
	if pending.RecoveryGrantIssuedAt.Location() != time.UTC || pending.RecoveryGrantIssuedAt.Nanosecond() != 0 ||
		pending.RecoveryGrantExpiresAt.Location() != time.UTC || pending.RecoveryGrantExpiresAt.Nanosecond() != 0 ||
		pending.RecoveryGrantExpiresAt.Sub(pending.RecoveryGrantIssuedAt) != credentialRecoveryGrantLifetime ||
		!pending.RecoveryGrantExpiresAt.Before(pending.Assignment.LeaseExpiresAt) {
		return invalid()
	}
	deadline, err := credentialRecoveryDeadline(pending.RecoveryAnchorGrantExpiresAt)
	if err != nil || pending.RecoveryExpiresAt.Location() != time.UTC || pending.RecoveryExpiresAt.Nanosecond() != 0 || !pending.RecoveryExpiresAt.Equal(deadline) {
		return invalid()
	}
	return nil
}

func (c *nativeAgentRuntimeConfig) requireCredentialRecoveryLive(pending *PendingAgentCredentialRecovery) error {
	if pending == nil {
		return fmt.Errorf("%w: pending credential recovery is missing", ErrInvalidAgentState)
	}
	if !c.clock().UTC().Before(pending.RecoveryExpiresAt) {
		return &CredentialRecoveryExpiredError{RecoveryExpiresAt: pending.RecoveryExpiresAt}
	}
	return nil
}

func (c *nativeAgentRuntimeConfig) requireCredentialRecoveryIssueLive(issue *PendingAgentCredentialRecoveryIssue) error {
	if issue == nil {
		return fmt.Errorf("%w: pending credential recovery Hub issue is missing", ErrInvalidAgentState)
	}
	if !c.clock().UTC().Before(issue.ReplayNotAfter) {
		return &CredentialRecoveryExpiredError{RecoveryExpiresAt: issue.ReplayNotAfter}
	}
	return nil
}

type credentialRecoveryBoundary struct {
	deadline time.Time
	clock    func() time.Time
	expired  atomic.Bool
}

func (c *nativeAgentRuntimeConfig) credentialRecoveryBoundary(ctx context.Context, pending *PendingAgentCredentialRecovery) (*credentialRecoveryBoundary, context.Context, context.CancelFunc, error) {
	if err := c.requireCredentialRecoveryLive(pending); err != nil {
		return nil, nil, nil, err
	}
	boundary := &credentialRecoveryBoundary{deadline: pending.RecoveryExpiresAt, clock: c.clock}
	now := c.clock().UTC()
	if err := boundary.checkAt(now); err != nil {
		return nil, nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, boundary.deadline.Sub(now))
	return boundary, udpfence.With(bounded, boundary.check), cancel, nil
}

func (c *nativeAgentRuntimeConfig) credentialRecoveryIssueBoundary(ctx context.Context, issue *PendingAgentCredentialRecoveryIssue) (*credentialRecoveryBoundary, context.Context, context.CancelFunc, error) {
	if err := c.requireCredentialRecoveryIssueLive(issue); err != nil {
		return nil, nil, nil, err
	}
	boundary := &credentialRecoveryBoundary{deadline: issue.ReplayNotAfter, clock: c.clock}
	now := c.clock().UTC()
	if err := boundary.checkAt(now); err != nil {
		return nil, nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, boundary.deadline.Sub(now))
	return boundary, udpfence.With(bounded, boundary.check), cancel, nil
}

func (b *credentialRecoveryBoundary) expiredError() error {
	return &CredentialRecoveryExpiredError{RecoveryExpiresAt: b.deadline}
}

func (b *credentialRecoveryBoundary) check() error {
	if b == nil || b.clock == nil || b.deadline.IsZero() {
		return fmt.Errorf("%w: credential recovery boundary is invalid", ErrInvalidAgentState)
	}
	return b.checkAt(b.clock().UTC())
}

func (b *credentialRecoveryBoundary) checkAt(now time.Time) error {
	if b.expired.Load() || now.IsZero() || !now.Before(b.deadline) {
		b.expired.Store(true)
		return b.expiredError()
	}
	return nil
}

func (b *credentialRecoveryBoundary) mapError(parent, bounded context.Context, err error) error {
	if err == nil || errors.Is(err, ErrCredentialRecoveryExpired) {
		return err
	}
	var authenticated *CredentialRecoveryError
	if errors.As(err, &authenticated) || errors.Is(err, ErrCredentialRecoveryInvalidResponse) {
		return err
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	if bounded.Err() != nil {
		return b.expiredError()
	}
	return err
}

func (c *nativeAgentRuntimeConfig) markCredentialRecoveryGrantRejected(ctx context.Context, store AgentStateStore, state *AgentState) error {
	if state.PendingCredentialRecovery == nil || state.PendingCredentialRecovery.NeedsFreshGrant {
		return nil
	}
	next := state.clone()
	next.PendingCredentialRecovery.NeedsFreshGrant = true
	return c.saveCredentialRecoveryState(ctx, store, state, next, ErrAgentBindingPersistence, "persist rejected recovery grant")
}

func (c *nativeAgentRuntimeConfig) saveCredentialRecoveryState(ctx context.Context, store AgentStateStore, current, next *AgentState, kind error, action string) error {
	if err := store.SaveAgentState(ctx, next); err != nil {
		if reconciled, ok := c.reconcileCredentialRecoveryState(ctx, store, next); ok {
			*current = *reconciled
			return nil
		}
		return fmt.Errorf("%w: %s: %w", kind, action, err)
	}
	*current = *next
	return nil
}

func (c *nativeAgentRuntimeConfig) reconcileCredentialRecoveryState(ctx context.Context, store AgentStateStore, expected *AgentState) (*AgentState, bool) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	reloadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	loaded, err := store.LoadAgentState(reloadCtx)
	if err != nil || prepareLoadedAgentState(loaded, ErrInvalidRegisterConfig) != nil || !sameCredentialRecoveryState(loaded, expected) {
		return nil, false
	}
	return loaded, true
}

func sameCredentialRecoveryState(left, right *AgentState) bool {
	if left == nil || right == nil || left.AgentID != right.AgentID || left.PrivateKeyB64 != right.PrivateKeyB64 || left.PublicKeyB64 != right.PublicKeyB64 ||
		left.SchemaVersion != right.SchemaVersion || left.DeviceAPIKey != right.DeviceAPIKey || left.DeviceAPIKeyID != right.DeviceAPIKeyID ||
		!sameOptionalRecoveryTime(left.RegisteredAt, right.RegisteredAt) || !sameOptionalAgentAssignment(left.Assignment, right.Assignment) ||
		(left.PendingActivation == nil) != (right.PendingActivation == nil) || (left.PendingCompletion == nil) != (right.PendingCompletion == nil) ||
		(left.PendingCredentialRecovery == nil) != (right.PendingCredentialRecovery == nil) || (left.PendingCredentialRecoveryIssue == nil) != (right.PendingCredentialRecoveryIssue == nil) {
		return false
	}
	if left.PendingActivation != nil || left.PendingCompletion != nil {
		return false
	}
	if left.PendingCredentialRecovery != nil {
		l, r := left.PendingCredentialRecovery, right.PendingCredentialRecovery
		if l.RecoveryGrant != r.RecoveryGrant || !l.RecoveryGrantIssuedAt.Equal(r.RecoveryGrantIssuedAt) || !l.RecoveryGrantExpiresAt.Equal(r.RecoveryGrantExpiresAt) ||
			!l.RecoveryAnchorGrantExpiresAt.Equal(r.RecoveryAnchorGrantExpiresAt) || !l.RecoveryExpiresAt.Equal(r.RecoveryExpiresAt) ||
			l.DeviceAPIKey != r.DeviceAPIKey || !sameAgentAssignment(&l.Assignment, &r.Assignment) || l.NeedsFreshGrant != r.NeedsFreshGrant {
			return false
		}
	}
	if left.PendingCredentialRecoveryIssue != nil {
		l, r := left.PendingCredentialRecoveryIssue, right.PendingCredentialRecoveryIssue
		if *l != *r {
			return false
		}
	}
	return true
}

func sameOptionalRecoveryTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func sameOptionalAgentAssignment(left, right *AgentAssignment) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return sameAgentAssignment(left, right)
}
