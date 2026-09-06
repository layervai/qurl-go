package qurl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	portalOpenTimeout       = 15 * time.Second
	portalRetryInitialDelay = 500 * time.Millisecond
	portalRetryMaximumDelay = 2 * time.Second
	portalRenewalAttempts   = 4
)

var (
	// ErrPortalOpenerNotStarted reports that Do was called before Start completed.
	ErrPortalOpenerNotStarted = errors.New("qurl: portal opener has not started")
	// ErrPortalOpenerNotReady reports that no unexpired cached portal handle is
	// available. Do never opens or waits for one.
	ErrPortalOpenerNotReady = errors.New("qurl: portal opener has no active session")
	// ErrPortalOpenerClosed reports use after Close.
	ErrPortalOpenerClosed = errors.New("qurl: portal opener is closed")
	// ErrPortalTargetChanged reports that a renewal authenticated a different
	// target. A long-lived opener is bound to the first authenticated ACK target.
	ErrPortalTargetChanged = errors.New("qurl: portal renewal changed the authenticated target")
	// ErrPortalRedirect reports that a caller selected RejectPortalRedirects and
	// the protected target returned a redirect.
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
}

// WithPortalOpenerConfig supplies explicit trust and cell configuration. When
// omitted, Start resolves the default provider or QURL_DEPLOYMENT. Relay fields
// are deliberately ignored: PortalOpener is native-only.
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
// not persist it outside the active handle.
func WithPortalOpenerHTTPClient(client *http.Client) PortalOpenerOption {
	return portalOpenerOptionFunc(func(opener *portalOpenerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: nil protected-content HTTP client", ErrNotConfigured)
		}
		if client.Jar != nil {
			return fmt.Errorf("%w: protected-content HTTP client must not use a CookieJar", ErrNotConfigured)
		}
		clientCopy := *client
		opener.httpClient = &clientCopy
		return nil
	})
}

// PortalRequestBuilder builds one request for the exact target authenticated by
// the NHP ACK. The URL value is a fresh copy. Do rejects any returned request
// whose URL or Host differs from that target.
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

// PortalOpenerHealth is a secret-free snapshot suitable for readiness and
// diagnostics. It never includes the qURL, target URL, session ID, or cookie.
type PortalOpenerHealth struct {
	State               string
	Ready               bool
	ExpiresAt           time.Time
	RenewAt             time.Time
	LastOpenSucceededAt time.Time
	ConsecutiveFailures uint32
}

type portalStartAttempt struct {
	done     chan struct{}
	err      error
	recovery bool
}

type portalOpenFunc func(context.Context, string, Config) (*ResourceHandle, error)

// PortalOpener owns one native-only, proactively renewed qURL visitor session.
// Start performs the first NHP open. Do uses only the cached handle: it never
// opens, resolves, mints, lists, retries, or sleeps on the request path.
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
	failures       uint32
	resolvedConfig *Config

	lifecycle context.Context
	cancel    context.CancelFunc
	loopDone  chan struct{}
	closeDone chan struct{}

	open         portalOpenFunc
	now          func() time.Time
	openTimeout  time.Duration
	renewalLead  func(time.Duration) time.Duration
	retryInitial time.Duration
	retryMaximum time.Duration
	retryLimit   int // positive invariant; tests may reduce it but never disable renewal
}

// NewPortalOpener constructs a native-only opener for one qURL. Construction
// does no I/O. Call Start during application startup and Close during shutdown.
func NewPortalOpener(qurlLink string, options ...PortalOpenerOption) (*PortalOpener, error) {
	if strings.TrimSpace(qurlLink) == "" {
		return nil, fmt.Errorf("%w: empty qURL", ErrNotConfigured)
	}
	cfg := portalOpenerConfig{httpClient: &http.Client{}}
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
		link:           qurlLink,
		explicitConfig: cfg.explicitConfig,
		httpClient:     *cfg.httpClient,
		state:          portalOpenerNew,
		lifecycle:      lifecycle,
		cancel:         cancel,
		closeDone:      make(chan struct{}),
		open:           EnterPortalWith,
		now:            time.Now,
		openTimeout:    portalOpenTimeout,
		renewalLead:    defaultPortalRenewalLead,
		retryInitial:   portalRetryInitialDelay,
		retryMaximum:   portalRetryMaximumDelay,
		retryLimit:     portalRenewalAttempts,
	}, nil
}

// Start synchronously obtains the first native NHP session and starts proactive
// renewal. Concurrent calls share one initial open. A failed Start can be
// retried. Start is idempotent while the cached handle is usable, and it is the
// explicit single-flight recovery path after bounded renewal failures expire
// that handle.
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
			o.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
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
	o.mu.RLock()
	expectedTarget := o.target
	o.mu.RUnlock()
	cfg, err := o.nativeConfig(ctx)
	var opened *portalOpenResult
	if err == nil {
		opened, err = o.openPortal(ctx, cfg, expectedTarget)
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == portalOpenerClosed {
		err = ErrPortalOpenerClosed
		clearPortalOpenResult(opened)
	} else if err != nil {
		if attempt.recovery {
			o.state = portalOpenerDegraded
		} else {
			o.state = portalOpenerNew
		}
		o.failures++
	} else {
		o.installLocked(opened)
		configCopy := cfg
		o.resolvedConfig = &configCopy
		o.state = portalOpenerRunning
		o.loopDone = make(chan struct{})
		go o.renewLoop(o.loopDone)
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
	startedAt := o.now().UTC()
	openCtx, cancel := context.WithTimeout(ctx, o.openTimeout)
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
	handle, err := o.open(openCtx, o.link, cfg)
	if err != nil {
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
	if !o.now().Before(expiresAt) {
		return nil, ErrPortalOpenerNotReady
	}
	renewAt := expiresAt.Add(-o.renewalLead(lifetime))
	handleCopy := *handle
	handleCopy.ResourceURL = canonicalTarget
	return &portalOpenResult{
		handle: &handleCopy, target: canonicalTarget, expiresAt: expiresAt,
		renewAt: renewAt, openedAt: o.now().UTC(),
	}, nil
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
	if o.active != nil {
		o.active.authProviderToken = ""
	}
	o.active = opened.handle
	o.target = opened.target
	o.expiresAt = opened.expiresAt
	o.renewAt = opened.renewAt
	o.lastSuccess = opened.openedAt
	o.failures = 0
}

func clearPortalOpenResult(opened *portalOpenResult) {
	if opened != nil && opened.handle != nil {
		opened.handle.authProviderToken = ""
	}
}

func (o *PortalOpener) renewLoop(done chan struct{}) {
	defer close(done)
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
		for attempt := 1; attempt <= o.retryLimit; attempt++ {
			opened, err := o.openPortal(o.lifecycle, cfg, target)
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
			o.mu.Unlock()
			if attempt == o.retryLimit || !o.now().Add(delay).Before(expiresAt) {
				// Do not hot-loop after the bounded renewal attempts. Keep the old
				// handle usable until expiry, then make Start the explicit recovery
				// path. A successful recovery remains bound to the first target.
				if !o.waitUntil(expiresAt) {
					return
				}
				o.mu.Lock()
				if o.state == portalOpenerRunning && o.expiresAt.Equal(expiresAt) {
					o.state = portalOpenerDegraded
				}
				o.mu.Unlock()
				return
			}
			if !o.waitFor(delay) {
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
// handle exists; it never performs an NHP open or waits for renewal.
func (o *PortalOpener) Do(ctx context.Context, build PortalRequestBuilder, options ...PortalRequestOption) (*http.Response, error) {
	if o == nil {
		return nil, ErrPortalOpenerClosed
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil request context", ErrInvalidContentRequest)
	}
	if build == nil {
		return nil, fmt.Errorf("%w: nil request builder", ErrInvalidContentRequest)
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
	trustedTarget, err := url.Parse(targetRaw)
	if err != nil {
		return nil, ErrPortalOpenerNotReady
	}
	builderTarget := *trustedTarget
	req, err := build(&builderTarget)
	if err != nil {
		return nil, err
	}
	if req == nil || req.URL == nil {
		closePortalRequestBody(req)
		return nil, fmt.Errorf("%w: builder returned no request", ErrInvalidContentRequest)
	}
	if req.URL.String() != targetRaw || (req.Host != "" && req.Host != trustedTarget.Host) {
		closePortalRequestBody(req)
		return nil, fmt.Errorf("%w: request changed the authenticated target", ErrInvalidContentRequest)
	}
	req = req.Clone(ctx)
	targetCopy := *trustedTarget
	req.URL = &targetCopy
	// Pin the wire Host to the authority signed by the caller after it received
	// the authenticated target. A proxy-facing Host override cannot change it.
	req.Host = trustedTarget.Host
	if err := handle.AuthorizeContentRequest(req); err != nil {
		closePortalRequestBody(req)
		return nil, err
	}
	if requestCfg.rejectRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return ErrPortalRedirect
		}
	} else {
		client.CheckRedirect = handle.CheckContentRedirect
	}
	return client.Do(req)
}

func closePortalRequestBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

// Health returns a secret-free, nonblocking lifecycle snapshot.
func (o *PortalOpener) Health() PortalOpenerHealth {
	if o == nil {
		return PortalOpenerHealth{State: "closed"}
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	health := PortalOpenerHealth{
		ExpiresAt: o.expiresAt, RenewAt: o.renewAt,
		LastOpenSucceededAt: o.lastSuccess, ConsecutiveFailures: o.failures,
	}
	switch o.state {
	case portalOpenerNew:
		health.State = "new"
	case portalOpenerStarting:
		if o.startAttempt != nil && o.startAttempt.recovery {
			health.State = "degraded"
		} else {
			health.State = "starting"
		}
	case portalOpenerDegraded:
		health.State = "degraded"
	case portalOpenerClosed:
		health.State = "closed"
	case portalOpenerRunning:
		health.Ready = o.active != nil && o.now().Before(o.expiresAt)
		if health.Ready {
			health.State = "ready"
		} else {
			health.State = "degraded"
		}
	default:
		health.State = "closed"
	}
	return health
}

// Close cancels background renewal and waits for any active Start or renewal to
// stop. It is idempotent.
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
	if o.active != nil {
		o.active.authProviderToken = ""
	}
	o.active = nil
	o.link = ""
	o.target = ""
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
