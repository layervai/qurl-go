package qurl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	portalOpenTimeout       = 15 * time.Second
	portalOpenTimeoutMax    = 60 * time.Second
	portalRenewalMinimumGap = 5 * time.Second
	portalRetryInitialDelay = 500 * time.Millisecond
	portalRetryMaximumDelay = 2 * time.Second
)

var (
	// ErrPortalOpenTimeout reports that the PortalOpener's configured NHP open
	// timeout expired. An open stopped only by its caller deadline does not wrap
	// this error.
	ErrPortalOpenTimeout = errors.New("qurl: portal opener open timeout")
	// ErrPortalOpenerNotStarted reports that Do was called before the first Start
	// attempt completed. A caller-canceled or caller-deadlined first attempt
	// returns to this state; a platform failure moves the opener to not-ready.
	ErrPortalOpenerNotStarted = errors.New("qurl: portal opener has not started")
	// ErrPortalOpenerNotReady reports that no unexpired cached portal handle is
	// available. Do never opens or waits for one.
	ErrPortalOpenerNotReady = errors.New("qurl: portal opener has no active session")
	// ErrPortalOpenerClosed reports use after Close.
	ErrPortalOpenerClosed = errors.New("qurl: portal opener is closed")
	// ErrPortalTargetChanged reports that a renewal authenticated a different
	// target. A long-lived opener is bound to the first authenticated ACK target.
	ErrPortalTargetChanged = errors.New("qurl: portal renewal changed the authenticated target")
	// ErrPortalRedirect reports that a redirect was rejected because the caller
	// selected RejectPortalRedirects or the target changed origin.
	ErrPortalRedirect = errors.New("qurl: protected request redirect refused")
	// ErrPortalNativeOnly reports that the resolved deployment has no native cell
	// entry. PortalOpener never falls back to the HTTPS relay.
	ErrPortalNativeOnly = errors.New("qurl: portal opener requires a native cell catalog")
)

type portalOpenerState uint8

const (
	portalOpenerNew portalOpenerState = iota
	portalOpenerStarting
	portalOpenerRunning
	portalOpenerDegraded
	portalOpenerClosed
)

// PortalOpenerFailureClass is a secret-free class for the most recent failed
// open. It lets operators distinguish a changed authenticated target from a
// general open failure without exposing the target or transport error.
type PortalOpenerFailureClass string

const (
	// PortalOpenerFailureNone means the latest open succeeded or no open failed.
	PortalOpenerFailureNone PortalOpenerFailureClass = ""
	// PortalOpenerFailureOpen means an open failed for a reason other than a changed target.
	PortalOpenerFailureOpen PortalOpenerFailureClass = "open_failed"
	// PortalOpenerFailureTargetChanged means a renewal authenticated another target.
	PortalOpenerFailureTargetChanged PortalOpenerFailureClass = "target_changed"
)

// PortalOpenerOption configures NewPortalOpener.
type PortalOpenerOption interface {
	applyPortalOpenerOption(*portalOpenerConfig) error
}

type portalOpenerOptionFunc func(*portalOpenerConfig) error

func (f portalOpenerOptionFunc) applyPortalOpenerOption(cfg *portalOpenerConfig) error {
	return f(cfg)
}

type portalOpenerConfig struct {
	explicitConfig *Config
	httpClient     *http.Client
	openTimeout    time.Duration
}

// WithPortalOpenerConfig supplies explicit trust and cell configuration. When
// omitted, Start resolves the default provider or QURL_DEPLOYMENT. Relay fields
// are deliberately ignored, and PortalSession is replaced with opener-owned
// state: PortalOpener is native-only and owns one visitor lifecycle.
func WithPortalOpenerConfig(cfg Config) PortalOpenerOption {
	return portalOpenerOptionFunc(func(opener *portalOpenerConfig) error {
		configCopy := cfg
		opener.explicitConfig = &configCopy
		return nil
	})
}

// WithPortalOpenerHTTPClient supplies the protected-content HTTP client. Its
// transport and timeout are retained. A CookieJar is rejected because the
// opener installs the authenticated qurl_vsession cookie per request and must
// not persist it outside the active handle. A caller redirect policy is also
// rejected because Do installs the authenticated-handle policy per request.
func WithPortalOpenerHTTPClient(client *http.Client) PortalOpenerOption {
	return portalOpenerOptionFunc(func(opener *portalOpenerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: nil protected-content HTTP client", ErrNotConfigured)
		}
		if client.Jar != nil {
			return fmt.Errorf("%w: protected-content HTTP client must not use a CookieJar", ErrNotConfigured)
		}
		if client.CheckRedirect != nil {
			return fmt.Errorf("%w: protected-content HTTP client must not set CheckRedirect", ErrNotConfigured)
		}
		clientCopy := *client
		opener.httpClient = &clientCopy
		return nil
	})
}

// WithPortalOpenerOpenTimeout sets the deadline for each native NHP open,
// including the synchronous first Start and background renewal attempts. The
// value must be positive and no more than 60 seconds. The default is 15 seconds.
func WithPortalOpenerOpenTimeout(timeout time.Duration) PortalOpenerOption {
	return portalOpenerOptionFunc(func(opener *portalOpenerConfig) error {
		if timeout <= 0 || timeout > portalOpenTimeoutMax {
			return fmt.Errorf("%w: portal open timeout must be from 1ns to %s", ErrNotConfigured, portalOpenTimeoutMax)
		}
		opener.openTimeout = timeout
		return nil
	})
}

// PortalRequestBuilder builds one request for the target selected by Do or
// DoDescendant. The URL value is a fresh copy. Both methods reject any returned
// request whose URL or Host differs from that target.
type PortalRequestBuilder func(target *url.URL) (*http.Request, error)

// PortalRequestOption configures one PortalOpener.Do call.
type PortalRequestOption interface {
	applyPortalRequestOption(*portalRequestConfig) error
}

type portalRequestOptionFunc func(*portalRequestConfig) error

func (f portalRequestOptionFunc) applyPortalRequestOption(cfg *portalRequestConfig) error {
	return f(cfg)
}

type portalRequestConfig struct {
	rejectRedirects bool
}

// RejectPortalRedirects makes any HTTP redirect an error. Without this option,
// Do follows only redirects on the authenticated HTTPS origin and reauthorizes
// each redirected request with the active session handle.
func RejectPortalRedirects() PortalRequestOption {
	return portalRequestOptionFunc(func(cfg *portalRequestConfig) error {
		cfg.rejectRedirects = true
		return nil
	})
}

// PortalOpenerState is the public lifecycle state reported by Health.
type PortalOpenerState string

const (
	// PortalOpenerStateNew means Start has not completed a platform attempt. A
	// caller-canceled or caller-deadlined first attempt returns to this state.
	PortalOpenerStateNew PortalOpenerState = "new"
	// PortalOpenerStateStarting means the first open is in progress.
	PortalOpenerStateStarting PortalOpenerState = "starting"
	// PortalOpenerStateReady means an unexpired cached handle is usable.
	PortalOpenerStateReady PortalOpenerState = "ready"
	// PortalOpenerStateDegraded means no cached handle is ready or recovery failed.
	PortalOpenerStateDegraded PortalOpenerState = "degraded"
	// PortalOpenerStateClosed means Close completed or the receiver is nil.
	PortalOpenerStateClosed PortalOpenerState = "closed"
)

// PortalOpenerHealth is a secret-free snapshot suitable for readiness and
// diagnostics. It never includes the qURL, target URL, session ID, or cookie.
type PortalOpenerHealth struct {
	State               PortalOpenerState
	Ready               bool
	ExpiresAt           time.Time
	RenewAt             time.Time
	LastOpenSucceededAt time.Time
	LastFailureClass    PortalOpenerFailureClass
	ConsecutiveFailures uint32
}

type portalStartAttempt struct {
	done     chan struct{}
	err      error
	recovery bool
}

type portalOpenFunc func(context.Context, string, Config) (*ResourceHandle, error)

// PortalOpener owns one native-only, proactively renewed qURL visitor session.
// Start performs the first NHP open. Do and DoDescendant use only the cached
// handle: they never open, resolve, mint, list, retry, or sleep on the request
// path.
type PortalOpener struct {
	mu sync.RWMutex

	link           string
	explicitConfig *Config
	httpClient     http.Client
	session        PortalSession
	state          portalOpenerState
	startAttempt   *portalStartAttempt
	active         *ResourceHandle
	target         string
	expiresAt      time.Time
	renewAt        time.Time
	lastSuccess    time.Time
	lastFailure    PortalOpenerFailureClass
	failures       uint32
	resolvedConfig *Config

	lifecycle context.Context
	cancel    context.CancelFunc
	loopDone  chan struct{}
	// readinessChanged is closed and replaced after each successful open. A
	// Start caller that finds an expired handle can wait for either a late
	// background recovery or the renewal loop to stop without waiting for the
	// next full renewal cycle after recovery.
	readinessChanged chan struct{}
	closeDone        chan struct{}

	open              portalOpenFunc
	now               func() time.Time
	openTimeout       time.Duration
	renewalLead       func(time.Duration) time.Duration
	renewalMinimumGap time.Duration
	retryInitial      time.Duration
	retryMaximum      time.Duration
}

// NewPortalOpener constructs a native-only opener for one qURL. Construction
// does no I/O. Call Start during application startup and Close during shutdown.
func NewPortalOpener(qurlLink string, options ...PortalOpenerOption) (*PortalOpener, error) {
	if strings.TrimSpace(qurlLink) == "" {
		return nil, fmt.Errorf("%w: empty qURL", ErrNotConfigured)
	}
	cfg := portalOpenerConfig{httpClient: &http.Client{}, openTimeout: portalOpenTimeout}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: nil PortalOpenerOption", ErrNotConfigured)
		}
		if err := option.applyPortalOpenerOption(&cfg); err != nil {
			return nil, err
		}
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	return &PortalOpener{
		link:              qurlLink,
		explicitConfig:    cfg.explicitConfig,
		httpClient:        *cfg.httpClient,
		state:             portalOpenerNew,
		lifecycle:         lifecycle,
		cancel:            cancel,
		readinessChanged:  make(chan struct{}),
		closeDone:         make(chan struct{}),
		open:              EnterPortalWith,
		now:               time.Now,
		openTimeout:       cfg.openTimeout,
		renewalLead:       defaultPortalRenewalLead,
		renewalMinimumGap: portalRenewalMinimumGap,
		retryInitial:      portalRetryInitialDelay,
		retryMaximum:      portalRetryMaximumDelay,
	}, nil
}

// Start synchronously obtains the first native NHP session and starts proactive
// renewal. Each open is bounded by the configured open timeout and returns
// ErrPortalOpenTimeout if that timeout expires. Concurrent calls share one
// initial open and its first caller's context, so cancellation or expiration of
// that context cancels the shared attempt without recording a platform failure.
// Call Start from service lifecycle code, not a request-scoped goroutine. A
// failed Start can be retried. Start is idempotent while the cached handle is
// usable, and it is the explicit single-flight recovery path after bounded
// renewal failures expire that handle.
func (o *PortalOpener) Start(ctx context.Context) error {
	if o == nil {
		return ErrPortalOpenerClosed
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil Start context", ErrNotConfigured)
	}
	for {
		o.mu.Lock()
		switch o.state {
		case portalOpenerRunning:
			if o.active != nil && o.now().Before(o.expiresAt) {
				o.mu.Unlock()
				return nil
			}
			// A bounded renewal cycle can still be closing as the old handle
			// expires. Wait for that one background owner before starting an
			// explicit recovery. This path is called by lifecycle code, never Do.
			loopDone := o.loopDone
			readinessChanged := o.readinessChanged
			o.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-readinessChanged:
				continue
			case <-loopDone:
				continue
			}
		case portalOpenerClosed:
			o.mu.Unlock()
			return ErrPortalOpenerClosed
		case portalOpenerStarting:
			attempt := o.startAttempt
			o.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-attempt.done:
				return attempt.err
			}
		case portalOpenerNew, portalOpenerDegraded:
			attempt := &portalStartAttempt{
				done: make(chan struct{}), recovery: o.state == portalOpenerDegraded,
			}
			o.startAttempt = attempt
			o.state = portalOpenerStarting
			o.mu.Unlock()
			return o.runStart(ctx, attempt)
		default:
			o.mu.Unlock()
			return ErrPortalOpenerClosed
		}
	}
}

func (o *PortalOpener) runStart(ctx context.Context, attempt *portalStartAttempt) error {
	startCtx, cancel := context.WithCancel(ctx)
	bridgeDone := make(chan struct{})
	go func() {
		select {
		case <-o.lifecycle.Done():
			cancel()
		case <-bridgeDone:
		}
	}()
	defer func() {
		close(bridgeDone)
		cancel()
	}()

	o.mu.RLock()
	expectedTarget := o.target
	o.mu.RUnlock()
	cfg, err := o.nativeConfig(startCtx)
	var opened *portalOpenResult
	if err == nil {
		opened, err = o.openPortal(startCtx, cfg, expectedTarget)
	}
	callerErr := ctx.Err()

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == portalOpenerClosed {
		err = ErrPortalOpenerClosed
		clearPortalOpenResult(opened)
	} else if err != nil {
		clearPortalOpenResult(opened)
		o.clearActiveLocked()
		callerGaveUp := (errors.Is(callerErr, context.Canceled) && errors.Is(err, context.Canceled)) ||
			(errors.Is(callerErr, context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) &&
				!errors.Is(err, ErrPortalOpenTimeout))
		if callerGaveUp {
			if attempt.recovery {
				o.state = portalOpenerDegraded
			} else {
				o.state = portalOpenerNew
			}
		} else {
			o.state = portalOpenerDegraded
			o.lastFailure = classifyPortalOpenerFailure(err)
			o.failures++
		}
	} else {
		o.installLocked(opened)
		configCopy := cfg
		o.resolvedConfig = &configCopy
		o.state = portalOpenerRunning
		o.loopDone = make(chan struct{})
		// Renewal belongs to the opener lifecycle, not the caller's Start context.
		// The Start context is canceled when this function returns.
		//nolint:contextcheck // opener-owned background lifecycle is intentional
		go o.renewLoop(o.lifecycle, o.loopDone)
	}
	attempt.err = err
	close(attempt.done)
	return err
}

func (o *PortalOpener) nativeConfig(ctx context.Context) (Config, error) {
	var (
		cfg Config
		err error
	)
	if o.explicitConfig != nil {
		cfg = *o.explicitConfig
	} else {
		cfg, err = resolveDefaultConfig(ctx)
		if err != nil {
			return Config{}, err
		}
	}
	if cfg.TrustStore == nil {
		return Config{}, fmt.Errorf("%w: PortalOpener requires issuer trust", ErrNotConfigured)
	}
	if cfg.Cells == nil {
		return Config{}, ErrPortalNativeOnly
	}
	// A PortalOpener is never allowed to downgrade to relay HTTP, even when its
	// caller or deployment also configures a valid relay fallback.
	cfg.RelayAllowlist = nil
	cfg.HTTPClient = nil
	cfg.PortalSession = &o.session
	return cfg, nil
}

type portalOpenResult struct {
	handle    *ResourceHandle
	target    string
	expiresAt time.Time
	renewAt   time.Time
	openedAt  time.Time
}

func (o *PortalOpener) openPortal(ctx context.Context, cfg Config, expectedTarget string) (*portalOpenResult, error) {
	// Keep the monotonic reading for all internal lifetime comparisons. UTC is
	// applied only to the outward health snapshot.
	startedAt := o.now()
	openCtx, cancel := context.WithTimeoutCause(ctx, o.openTimeout, ErrPortalOpenTimeout)
	defer cancel()
	handle, err := o.open(openCtx, o.link, cfg)
	if err != nil {
		if errors.Is(context.Cause(openCtx), ErrPortalOpenTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrPortalOpenTimeout, err)
		}
		return nil, err
	}
	if handle != nil {
		defer func() { handle.authProviderToken = "" }()
	}
	if handle == nil || handle.OpenSeconds == 0 || handle.SessionID == 0 || !validAuthProviderToken(handle.authProviderToken) {
		return nil, fmt.Errorf("%w: opener received an incomplete handle", ErrMalformedReply)
	}
	target, err := url.Parse(handle.ResourceURL)
	if err != nil || target.Fragment != "" {
		return nil, fmt.Errorf("%w: opener received an invalid target", ErrMalformedReply)
	}
	if _, _, ok := normalizedHTTPSOrigin(target); !ok {
		return nil, fmt.Errorf("%w: opener received an invalid target", ErrMalformedReply)
	}
	canonicalTarget := target.String()
	if expectedTarget != "" && canonicalTarget != expectedTarget {
		return nil, ErrPortalTargetChanged
	}
	lifetime := time.Duration(handle.OpenSeconds) * time.Second
	expiresAt := startedAt.Add(lifetime)
	openedAt := o.now()
	if !openedAt.Before(expiresAt) {
		return nil, fmt.Errorf("%w: opener handle expired before installation", ErrMalformedReply)
	}
	renewAt := expiresAt.Add(-o.renewalLead(lifetime))
	minimumRenewAt := openedAt.Add(o.renewalMinimumGap)
	if renewAt.Before(minimumRenewAt) {
		renewAt = minimumRenewAt
		if renewAt.After(expiresAt) {
			renewAt = expiresAt
		}
	}
	handleCopy := *handle
	handleCopy.ResourceURL = canonicalTarget
	return &portalOpenResult{
		handle: &handleCopy, target: canonicalTarget, expiresAt: expiresAt,
		renewAt: renewAt, openedAt: openedAt,
	}, nil
}

func classifyPortalOpenerFailure(err error) PortalOpenerFailureClass {
	if err == nil {
		return PortalOpenerFailureNone
	}
	if errors.Is(err, ErrPortalTargetChanged) {
		return PortalOpenerFailureTargetChanged
	}
	return PortalOpenerFailureOpen
}

func defaultPortalRenewalLead(lifetime time.Duration) time.Duration {
	lead := lifetime / 5
	if lead < 5*time.Second {
		lead = 5 * time.Second
	}
	if lead > time.Minute {
		lead = time.Minute
	}
	if lead >= lifetime {
		lead = lifetime / 2
	}
	return lead
}

func (o *PortalOpener) installLocked(opened *portalOpenResult) {
	o.clearActiveLocked()
	o.active = opened.handle
	o.target = opened.target
	o.expiresAt = opened.expiresAt
	o.renewAt = opened.renewAt
	o.lastSuccess = opened.openedAt
	o.lastFailure = PortalOpenerFailureNone
	o.failures = 0
	close(o.readinessChanged)
	o.readinessChanged = make(chan struct{})
}

func (o *PortalOpener) clearActiveLocked() {
	if o.active != nil {
		o.active.authProviderToken = ""
	}
	o.active = nil
}

func clearPortalOpenResult(opened *portalOpenResult) {
	if opened != nil && opened.handle != nil {
		opened.handle.authProviderToken = ""
	}
}

func (o *PortalOpener) renewLoop(lifecycle context.Context, done chan struct{}) {
	defer func() {
		// A renewal owner must never leave a running opener behind after it
		// exits. Start waits on done when a running handle is expired; degrading
		// here makes that wake-up a state transition instead of a possible
		// closed-channel spin if a future return path misses its local cleanup.
		o.mu.Lock()
		if o.state == portalOpenerRunning && o.loopDone == done {
			o.state = portalOpenerDegraded
			o.clearActiveLocked()
		}
		o.mu.Unlock()
		close(done)
	}()
	for {
		o.mu.RLock()
		renewAt := o.renewAt
		expiresAt := o.expiresAt
		target := o.target
		cfg := *o.resolvedConfig
		o.mu.RUnlock()
		if !o.waitUntil(renewAt) {
			return
		}

		delay := o.retryInitial
		for {
			// Retry only while the old handle remains usable. This uses the full
			// proactive renewal window for transient failures without creating an
			// unbounded background retry loop after admission expires.
			if !o.now().Before(expiresAt) {
				o.mu.Lock()
				if o.state == portalOpenerRunning && o.expiresAt.Equal(expiresAt) {
					o.state = portalOpenerDegraded
					o.clearActiveLocked()
				}
				o.mu.Unlock()
				return
			}
			attemptCtx, cancel := context.WithDeadline(lifecycle, expiresAt)
			opened, err := o.openPortal(attemptCtx, cfg, target)
			cancel()
			if err == nil {
				o.mu.Lock()
				if o.state != portalOpenerRunning {
					clearPortalOpenResult(opened)
					o.mu.Unlock()
					return
				}
				o.installLocked(opened)
				o.mu.Unlock()
				break
			}
			o.mu.Lock()
			if o.state != portalOpenerRunning {
				o.mu.Unlock()
				return
			}
			o.failures++
			o.lastFailure = classifyPortalOpenerFailure(err)
			o.mu.Unlock()
			if errors.Is(err, ErrPortalTargetChanged) {
				// A changed authenticated target is not transient. Keep the already
				// authenticated handle until expiry, then require explicit recovery.
				if !o.waitUntil(expiresAt) {
					return
				}
				o.mu.Lock()
				if o.state == portalOpenerRunning && o.expiresAt.Equal(expiresAt) {
					o.state = portalOpenerDegraded
					o.clearActiveLocked()
				}
				o.mu.Unlock()
				return
			}
			remaining := expiresAt.Sub(o.now())
			if remaining <= 0 {
				continue
			}
			wait := delay
			if wait > remaining {
				wait = remaining
			}
			if !o.waitFor(wait) {
				return
			}
			delay *= 2
			if delay > o.retryMaximum {
				delay = o.retryMaximum
			}
		}
	}
}

func (o *PortalOpener) waitUntil(deadline time.Time) bool {
	delay := deadline.Sub(o.now())
	if delay <= 0 {
		return true
	}
	return o.waitFor(delay)
}

func (o *PortalOpener) waitFor(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-o.lifecycle.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Do sends one request to the exact authenticated ACK target with the cached
// session. It returns immediately with ErrPortalOpenerNotReady when no active
// handle exists; it never performs an NHP open or waits for renewal. Close
// cancels an active request and its response-body reads and prevents later
// redirect legs. Close does not wait for Do and cannot retract bytes already
// handed to a transport. A returned body read interrupted by Close reports its
// native request-context error, typically context.Canceled, not
// ErrPortalOpenerClosed. If request cancellation and Close happen together,
// ErrPortalOpenerClosed takes precedence before a response is returned. The
// caller must close every returned response body; until then, the body retains
// the request cancellation hook that lets Close abort body reads.
func (o *PortalOpener) Do(ctx context.Context, build PortalRequestBuilder, options ...PortalRequestOption) (*http.Response, error) {
	return o.do(ctx, nil, false, build, options...)
}

// DoDescendant sends one request to a descendant of the authenticated ACK
// target with the cached session. Each caller value is one path segment; the
// SDK encodes it before appending it. Empty segments, dot segments, and values
// that can introduce an authority, path separator, query, fragment, or
// backslash are rejected. Like Do, this method never performs an NHP open or
// waits for renewal.
func (o *PortalOpener) DoDescendant(ctx context.Context, pathSegments []string, build PortalRequestBuilder, options ...PortalRequestOption) (*http.Response, error) {
	return o.do(ctx, pathSegments, true, build, options...)
}

func (o *PortalOpener) do(ctx context.Context, pathSegments []string, descendant bool, build PortalRequestBuilder, options ...PortalRequestOption) (*http.Response, error) {
	if o == nil {
		return nil, ErrPortalOpenerClosed
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil request context", ErrInvalidContentRequest)
	}
	if build == nil {
		return nil, fmt.Errorf("%w: nil request builder", ErrInvalidContentRequest)
	}
	if descendant {
		if err := validatePortalDescendantSegments(pathSegments); err != nil {
			return nil, err
		}
	}
	requestCfg := portalRequestConfig{}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: nil PortalRequestOption", ErrInvalidContentRequest)
		}
		if err := option.applyPortalRequestOption(&requestCfg); err != nil {
			return nil, err
		}
	}

	o.mu.RLock()
	state := o.state
	recovering := state == portalOpenerStarting && o.startAttempt != nil && o.startAttempt.recovery
	var handle ResourceHandle
	active := o.active != nil
	if active {
		handle = *o.active
	}
	targetRaw := o.target
	expiresAt := o.expiresAt
	client := o.httpClient
	o.mu.RUnlock()
	if state == portalOpenerClosed {
		return nil, ErrPortalOpenerClosed
	}
	if recovering {
		return nil, ErrPortalOpenerNotReady
	}
	if state == portalOpenerDegraded {
		return nil, ErrPortalOpenerNotReady
	}
	if state != portalOpenerRunning {
		return nil, ErrPortalOpenerNotStarted
	}
	if !active || targetRaw == "" || !o.now().Before(expiresAt) {
		return nil, ErrPortalOpenerNotReady
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	stopLifecycleCancel := context.AfterFunc(o.lifecycle, cancelRequest) //nolint:contextcheck // fuse caller and opener lifecycles
	releaseRequest := func() {
		stopLifecycleCancel()
		cancelRequest()
	}
	releaseOnReturn := true
	defer func() {
		if releaseOnReturn {
			releaseRequest()
		}
	}()
	if o.lifecycle.Err() != nil {
		return nil, ErrPortalOpenerClosed
	}
	trustedTarget, err := url.Parse(targetRaw)
	if err != nil {
		return nil, ErrPortalOpenerNotReady
	}
	requestTarget := trustedTarget
	if descendant {
		requestTarget = appendPortalDescendantSegments(trustedTarget, pathSegments)
	}
	requestTargetRaw := requestTarget.String()
	builderTarget := *requestTarget
	req, err := build(&builderTarget)
	if err != nil {
		closePortalRequestBody(req)
		return nil, err
	}
	if req == nil || req.URL == nil {
		closePortalRequestBody(req)
		return nil, fmt.Errorf("%w: builder returned no request", ErrInvalidContentRequest)
	}
	if req.URL.String() != requestTargetRaw || (req.Host != "" && req.Host != requestTarget.Host) {
		closePortalRequestBody(req)
		return nil, fmt.Errorf("%w: request changed the authenticated target", ErrInvalidContentRequest)
	}
	req = req.Clone(requestCtx)
	targetCopy := *requestTarget
	req.URL = &targetCopy
	// Pin the wire Host to the authority signed by the caller after it received
	// the authenticated target. A proxy-facing Host override cannot change it.
	req.Host = requestTarget.Host
	if err := handle.AuthorizeContentRequest(req); err != nil {
		closePortalRequestBody(req)
		return nil, err
	}
	if requestCfg.rejectRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			if o.lifecycle.Err() != nil {
				return ErrPortalOpenerClosed
			}
			return ErrPortalRedirect
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if o.lifecycle.Err() != nil {
				return ErrPortalOpenerClosed
			}
			err := handle.CheckContentRedirect(req, via)
			if errors.Is(err, ErrInvalidContentRequest) {
				return fmt.Errorf("%w: %s", ErrPortalRedirect, err.Error())
			}
			return err
		}
	}
	response, err := client.Do(req)
	if err != nil {
		if o.lifecycle.Err() != nil {
			return nil, ErrPortalOpenerClosed
		}
		// net/http can return the previous response with a redirect-policy error.
		// Its body is already closed; keep the PortalOpener error contract simple.
		return nil, err
	}
	if o.lifecycle.Err() != nil {
		_ = response.Body.Close()
		return nil, ErrPortalOpenerClosed
	}
	response.Body = &portalResponseBody{ReadCloser: response.Body, release: releaseRequest}
	releaseOnReturn = false
	return response, nil
}

func validatePortalDescendantSegments(pathSegments []string) error {
	if len(pathSegments) == 0 {
		return fmt.Errorf("%w: at least one descendant path segment is required", ErrInvalidContentRequest)
	}
	for index, segment := range pathSegments {
		if segment == "" {
			return fmt.Errorf("%w: descendant path segment %d is empty", ErrInvalidContentRequest, index)
		}
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: descendant path segment %d is a dot segment", ErrInvalidContentRequest, index)
		}
		if strings.ContainsAny(segment, "/\\?#") {
			return fmt.Errorf("%w: descendant path segment %d contains a reserved delimiter", ErrInvalidContentRequest, index)
		}
	}
	return nil
}

func appendPortalDescendantSegments(target *url.URL, pathSegments []string) *url.URL {
	descendant := *target
	baseEscapedPath := target.EscapedPath()
	separator := "/"
	if strings.HasSuffix(baseEscapedPath, "/") {
		separator = ""
	}
	escapedSegments := make([]string, len(pathSegments))
	for index, segment := range pathSegments {
		escapedSegments[index] = url.PathEscape(segment)
	}
	descendant.Path += separator + strings.Join(pathSegments, "/")
	descendant.RawPath = baseEscapedPath + separator + strings.Join(escapedSegments, "/")
	return &descendant
}

type portalResponseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (body *portalResponseBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.release)
	return err
}

func closePortalRequestBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

// Health returns a secret-free, nonblocking lifecycle snapshot.
func (o *PortalOpener) Health() PortalOpenerHealth {
	if o == nil {
		return PortalOpenerHealth{State: PortalOpenerStateClosed}
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	health := PortalOpenerHealth{
		ExpiresAt: o.expiresAt.UTC(), RenewAt: o.renewAt.UTC(),
		LastOpenSucceededAt: o.lastSuccess.UTC(), LastFailureClass: o.lastFailure,
		ConsecutiveFailures: o.failures,
	}
	switch o.state {
	case portalOpenerNew:
		health.State = PortalOpenerStateNew
	case portalOpenerStarting:
		if o.startAttempt != nil && o.startAttempt.recovery {
			health.State = PortalOpenerStateDegraded
		} else {
			health.State = PortalOpenerStateStarting
		}
	case portalOpenerDegraded:
		health.State = PortalOpenerStateDegraded
	case portalOpenerClosed:
		health.State = PortalOpenerStateClosed
	case portalOpenerRunning:
		health.Ready = o.active != nil && o.now().Before(o.expiresAt)
		if health.Ready {
			health.State = PortalOpenerStateReady
		} else {
			health.State = PortalOpenerStateDegraded
		}
	default:
		health.State = PortalOpenerStateClosed
	}
	return health
}

// Close cancels background renewal and any active Do, then waits for any active
// Start or renewal to stop. It does not wait for Do and cannot retract bytes
// already handed to a transport. Applications that require a strict outbound
// request fence must stop and drain request handlers before Close. Close is
// idempotent.
func (o *PortalOpener) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.state == portalOpenerClosed {
		done := o.closeDone
		o.mu.Unlock()
		<-done
		return nil
	}
	starting := o.startAttempt
	loopDone := o.loopDone
	o.state = portalOpenerClosed
	o.cancel()
	o.mu.Unlock()
	if starting != nil {
		<-starting.done
	}
	if loopDone != nil {
		<-loopDone
	}
	o.mu.Lock()
	o.clearActiveLocked()
	o.link = ""
	o.target = ""
	o.expiresAt = time.Time{}
	o.renewAt = time.Time{}
	o.lastSuccess = time.Time{}
	o.lastFailure = PortalOpenerFailureNone
	o.failures = 0
	o.resolvedConfig = nil
	o.explicitConfig = nil
	o.session.clear()
	close(o.closeDone)
	o.mu.Unlock()
	return nil
}

// String returns a redacted representation that never includes the qURL,
// authenticated target, visitor capability, or application-session cookie.
func (*PortalOpener) String() string { return "qurl.PortalOpener{[REDACTED]}" }

// GoString returns the same redacted representation as String.
func (o *PortalOpener) GoString() string { return o.String() }
