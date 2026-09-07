package qurl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

func portalOpenerFixture(t *testing.T) (string, Config) {
	t.Helper()
	link, trust, _ := generatedAcceptLink(t)
	return link, Config{
		TrustStore: trust,
		Cells:      unreachableCellCatalog(t, vectorCellKeyB64(t)),
	}
}

func portalTestHandle(target, token string, lifetime uint32, sessionID uint64) *ResourceHandle {
	return &ResourceHandle{
		ResourceURL: target, OpenSeconds: lifetime, SessionID: sessionID,
		authProviderToken: token,
	}
}

func closePortalOpener(t *testing.T, opener *PortalOpener) {
	t.Helper()
	if err := opener.Close(); err != nil {
		t.Fatalf("close opener: %v", err)
	}
}

func waitForPortalCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for portal opener condition")
		}
		time.Sleep(time.Millisecond)
	}
}

type blockingPortalProvider struct {
	entered chan struct{}
	once    sync.Once
}

func (p *blockingPortalProvider) Resolve(ctx context.Context) (*TrustStore, *RelayAllowlist, error) {
	p.once.Do(func() { close(p.entered) })
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func TestPortalOpenerStartCachesHandleAndDoDoesNotOpen(t *testing.T) {
	var requests atomic.Int32
	var wantHost string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.URL.Path != "/internal/v1/delegated-mint-capabilities" || req.Host != wantHost {
			t.Errorf("protected request target = %s host=%q", req.URL.Path, req.Host)
		}
		cookie, err := req.Cookie(qurlVsessionCookieName)
		if err != nil || cookie.Value != testAuthProviderToken {
			t.Errorf("protected request cookie = %#v, %v", cookie, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(server.Close)
	parsedServerURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	wantHost = parsedServerURL.Host

	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link,
		WithPortalOpenerConfig(cfg),
		WithPortalOpenerHTTPClient(server.Client()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	target := server.URL + "/internal/v1/delegated-mint-capabilities"
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		opens.Add(1)
		return portalTestHandle(target, testAuthProviderToken, 60, 9), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if health := opener.Health(); !health.Ready || health.State != "ready" || health.ExpiresAt.IsZero() || health.LastOpenSucceededAt.IsZero() {
		t.Fatalf("health after Start = %#v", health)
	}

	for range 8 {
		resp, err := opener.Do(t.Context(), func(authenticatedTarget *url.URL) (*http.Request, error) {
			return http.NewRequestWithContext(t.Context(), http.MethodPost, authenticatedTarget.String(), strings.NewReader(`{"request":true}`))
		}, RejectPortalRedirects())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("Do performed %d extra opens", got-1)
	}
	if got := requests.Load(); got != 8 {
		t.Fatalf("protected requests = %d, want 8", got)
	}
}

func TestPortalOpenerOptionsFailClosed(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var nilOption PortalOpenerOption
	for name, testCase := range map[string]struct {
		link    string
		options []PortalOpenerOption
	}{
		"empty link":       {link: " \t"},
		"nil option":       {link: link, options: []PortalOpenerOption{nilOption}},
		"nil client":       {link: link, options: []PortalOpenerOption{WithPortalOpenerHTTPClient(nil)}},
		"cookie jar":       {link: link, options: []PortalOpenerOption{WithPortalOpenerHTTPClient(&http.Client{Jar: jar})}},
		"redirect policy":  {link: link, options: []PortalOpenerOption{WithPortalOpenerHTTPClient(&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }})}},
		"zero timeout":     {link: link, options: []PortalOpenerOption{WithPortalOpenerOpenTimeout(0)}},
		"negative timeout": {link: link, options: []PortalOpenerOption{WithPortalOpenerOpenTimeout(-time.Second)}},
		"large timeout":    {link: link, options: []PortalOpenerOption{WithPortalOpenerOpenTimeout(portalOpenTimeoutMax + time.Nanosecond)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewPortalOpener(testCase.link, testCase.options...)
			if !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("NewPortalOpener error = %v, want ErrNotConfigured", err)
			}
		})
	}

	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerOpenTimeout(27*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	if opener.openTimeout != 27*time.Second {
		t.Fatalf("open timeout = %s, want 27s", opener.openTimeout)
	}
}

func TestPortalOpenerOpenTimeoutBoundsStart(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link,
		WithPortalOpenerConfig(cfg), WithPortalOpenerOpenTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := opener.Start(ctx); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrPortalOpenTimeout) {
		t.Fatalf("Start timeout error = %v, want context deadline exceeded", err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("caller context ended before SDK timeout result: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Start ignored configured open timeout: %s", elapsed)
	}
	if health := opener.Health(); health.State != PortalOpenerStateDegraded || health.Ready || health.ConsecutiveFailures != 1 {
		t.Fatalf("health after timed-out Start = %#v", health)
	}
}

func TestPortalOpenerCallerCanceledStartDoesNotRecordPlatformFailure(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := opener.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want context canceled", err)
	}
	health := opener.Health()
	if health.State != PortalOpenerStateNew || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureNone || health.ConsecutiveFailures != 0 {
		t.Fatalf("caller-canceled Start health = %+v", health)
	}
	response, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("Do builder ran after a caller-canceled first Start")
		return nil, errors.New("builder ran")
	})
	if response != nil {
		_ = response.Body.Close()
	}
	if response != nil || !errors.Is(err, ErrPortalOpenerNotStarted) {
		t.Fatalf("Do after caller-canceled first Start = %#v, %v", response, err)
	}
}

func TestPortalOpenerCallerDeadlineDoesNotRecordPlatformFailure(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	startErr := opener.Start(ctx)
	if !errors.Is(startErr, context.DeadlineExceeded) {
		t.Fatalf("Start error = %v, want context deadline exceeded", startErr)
	}
	if errors.Is(startErr, ErrPortalOpenTimeout) {
		t.Fatalf("caller deadline error = %v, must not match ErrPortalOpenTimeout", startErr)
	}
	health := opener.Health()
	if health.State != PortalOpenerStateNew || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureNone || health.ConsecutiveFailures != 0 {
		t.Fatalf("caller-deadline Start health = %+v", health)
	}
	response, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("Do builder ran after a caller-deadline first Start")
		return nil, errors.New("builder ran")
	})
	if response != nil {
		_ = response.Body.Close()
	}
	if response != nil || !errors.Is(err, ErrPortalOpenerNotStarted) {
		t.Fatalf("Do after caller-deadline first Start = %#v, %v", response, err)
	}
}

func TestPortalOpenerCallerCanceledRecoveryPreservesFailureHealth(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	platformErr := errors.New("platform unavailable")
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) { return nil, platformErr }
	if err := opener.Start(t.Context()); !errors.Is(err, platformErr) {
		t.Fatalf("initial Start = %v, want platform failure", err)
	}
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := opener.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery Start = %v, want context canceled", err)
	}
	health := opener.Health()
	if health.State != PortalOpenerStateDegraded || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureOpen || health.ConsecutiveFailures != 1 {
		t.Fatalf("caller-canceled recovery health = %+v", health)
	}
}

func TestPortalOpenerCallerDeadlineRecoveryPreservesFailureHealth(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	platformErr := errors.New("platform unavailable")
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) { return nil, platformErr }
	if err := opener.Start(t.Context()); !errors.Is(err, platformErr) {
		t.Fatalf("initial Start = %v, want platform failure", err)
	}
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if err := opener.Start(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recovery Start = %v, want context deadline exceeded", err)
	}
	health := opener.Health()
	if health.State != PortalOpenerStateDegraded || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureOpen || health.ConsecutiveFailures != 1 {
		t.Fatalf("caller-deadline recovery health = %+v", health)
	}
}

func TestPortalOpenerCallerDeadlineDoesNotMaskSDKTimeout(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		<-ctx.Done()
		return nil, errors.Join(ErrPortalOpenTimeout, ctx.Err())
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	startErr := opener.Start(ctx)
	if !errors.Is(startErr, ErrPortalOpenTimeout) || !errors.Is(startErr, context.DeadlineExceeded) {
		t.Fatalf("Start error = %v, want ErrPortalOpenTimeout and context deadline exceeded", startErr)
	}
	if health := opener.Health(); health.State != PortalOpenerStateDegraded || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureOpen || health.ConsecutiveFailures != 1 {
		t.Fatalf("SDK-timeout Start health = %+v", health)
	}
}

func TestPortalOpenerRealNativeCallerDeadlineDoesNotRecordPlatformFailure(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	resolverEntered := make(chan struct{})
	cfg.nativeUDPOptions = &nativeudp.Options{
		Resolver: assignmentTestResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			close(resolverEntered)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
		Timeout: time.Second, MaxAddresses: 1,
	}
	opener, err := NewPortalOpener(link,
		WithPortalOpenerConfig(cfg), WithPortalOpenerOpenTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	startErr := opener.Start(ctx)
	if !errors.Is(startErr, context.DeadlineExceeded) || errors.Is(startErr, ErrPortalOpenTimeout) {
		t.Fatalf("native Start error = %v, want caller deadline only", startErr)
	}
	select {
	case <-resolverEntered:
	default:
		t.Fatal("native Start did not reach the real UDP resolver path")
	}
	if health := opener.Health(); health.State != PortalOpenerStateNew || health.Ready ||
		health.LastFailureClass != PortalOpenerFailureNone || health.ConsecutiveFailures != 0 {
		t.Fatalf("native caller-deadline Start health = %+v", health)
	}
}

func TestPortalOpenerOpenTimeoutBoundsBackgroundRenewal(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link,
		WithPortalOpenerConfig(cfg), WithPortalOpenerOpenTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return time.Minute }
	opener.renewalMinimumGap = time.Millisecond
	opener.retryInitial = time.Second
	opener.retryMaximum = time.Second

	renewalErr := make(chan error, 1)
	renewalElapsed := make(chan time.Duration, 1)
	var opens atomic.Int32
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 92), nil
		}
		started := time.Now()
		<-ctx.Done()
		renewalErr <- ctx.Err()
		renewalElapsed <- time.Since(started)
		return nil, ctx.Err()
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-renewalErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("background renewal error = %v, want context deadline exceeded", err)
	}
	if elapsed := <-renewalElapsed; elapsed > time.Second {
		t.Fatalf("background renewal ignored configured open timeout: %s", elapsed)
	}
	waitForPortalCondition(t, time.Second, func() bool { return opener.Health().ConsecutiveFailures == 1 })
	if health := opener.Health(); !health.Ready || health.LastFailureClass != PortalOpenerFailureOpen {
		t.Fatalf("health after timed-out background renewal = %#v", health)
	}
}

func TestPortalOpenerStartRejectsMissingTrustAndIncompleteHandles(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	missingTrust := cfg
	missingTrust.TrustStore = nil
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(missingTrust))
	if err != nil {
		t.Fatal(err)
	}
	if err := opener.Start(t.Context()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing trust Start error = %v, want ErrNotConfigured", err)
	}
	if health := opener.Health(); health.State != PortalOpenerStateDegraded || health.Ready || health.ConsecutiveFailures != 1 {
		t.Fatalf("health after failed initial Start = %#v", health)
	}
	response, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("Do builder ran after failed initial Start")
		return nil, errors.New("builder ran after failed initial Start")
	})
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, ErrPortalOpenerNotReady) {
		t.Fatalf("Do after failed initial Start = %v, want ErrPortalOpenerNotReady", err)
	}
	closePortalOpener(t, opener)

	for name, handle := range map[string]*ResourceHandle{
		"nil":           nil,
		"zero lifetime": portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 0, 1),
		"zero session":  portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 0),
		"bad token":     portalTestHandle("https://r_test.qurl.site/fixed", "bad token", 60, 1),
	} {
		t.Run(name, func(t *testing.T) {
			opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
			if err != nil {
				t.Fatal(err)
			}
			opener.open = func(context.Context, string, Config) (*ResourceHandle, error) { return handle, nil }
			if err := opener.Start(t.Context()); !errors.Is(err, ErrMalformedReply) {
				t.Fatalf("Start error = %v, want ErrMalformedReply", err)
			}
			closePortalOpener(t, opener)
		})
	}

	opener, err = NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var clockReads atomic.Int32
	opener.now = func() time.Time {
		if clockReads.Add(1) == 1 {
			return now
		}
		return now.Add(time.Second)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 1, 1), nil
	}
	if err := opener.Start(t.Context()); !errors.Is(err, ErrMalformedReply) || errors.Is(err, ErrPortalOpenerNotReady) {
		t.Fatalf("expired-during-open Start error = %v, want ErrMalformedReply only", err)
	}
	closePortalOpener(t, opener)
}

func TestPortalOpenerKeepsInternalDeadlinesMonotonic(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	now := time.Now()
	opener.now = func() time.Time { return now }
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 91), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	opener.mu.RLock()
	expiresAt, renewAt, lastSuccess := opener.expiresAt, opener.renewAt, opener.lastSuccess
	opener.mu.RUnlock()
	for name, value := range map[string]time.Time{
		"expiry": expiresAt, "renewal": renewAt, "success": lastSuccess,
	} {
		if reflect.DeepEqual(value, value.Round(0)) {
			t.Fatalf("internal %s time lost its monotonic reading", name)
		}
	}
	health := opener.Health()
	for name, value := range map[string]time.Time{
		"expiry": health.ExpiresAt, "renewal": health.RenewAt, "success": health.LastOpenSucceededAt,
	} {
		if value.Location() != time.UTC || !reflect.DeepEqual(value, value.Round(0)) {
			t.Fatalf("health %s time = %v, want UTC without an internal monotonic reading", name, value)
		}
	}
}

func TestPortalOpenerSuccessfulOpenCannotScheduleBackToBackRenewal(t *testing.T) {
	startedAt := time.Now()
	tests := map[string]struct {
		openLatency time.Duration
		wantRenewAt time.Time
	}{
		"short remaining window":  {openLatency: 14 * time.Second, wantRenewAt: startedAt.Add(19 * time.Second)},
		"planned renewal elapsed": {openLatency: 16 * time.Second, wantRenewAt: startedAt.Add(20 * time.Second)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			link, cfg := portalOpenerFixture(t)
			opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closePortalOpener(t, opener) })
			openedAt := startedAt.Add(test.openLatency)
			current := startedAt
			opener.now = func() time.Time { return current }
			opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
				current = openedAt
				return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 20, 93), nil
			}

			opened, err := opener.openPortal(t.Context(), cfg, "")
			if err != nil {
				t.Fatal(err)
			}
			wantExpiry := startedAt.Add(20 * time.Second)
			if !opened.openedAt.Equal(openedAt) || !opened.expiresAt.Equal(wantExpiry) || !opened.renewAt.Equal(test.wantRenewAt) {
				t.Fatalf("delayed open times = %s/%s/%s, want %s/%s/%s",
					opened.openedAt, opened.expiresAt, opened.renewAt, openedAt, wantExpiry, test.wantRenewAt)
			}
			if !opened.renewAt.After(opened.openedAt) {
				t.Fatalf("renewal at %s is not after successful open at %s", opened.renewAt, opened.openedAt)
			}
		})
	}
}

func TestPortalOpenerCloseCancelsBlockedConfigResolution(t *testing.T) {
	provider := &blockingPortalProvider{entered: make(chan struct{})}
	installDefaultProvider(t, provider)
	opener, err := NewPortalOpener("https://qurl.link/#blocked-provider")
	if err != nil {
		t.Fatal(err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- opener.Start(context.Background()) }()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("Start did not enter provider resolution")
	}
	closeErr := make(chan error, 1)
	go func() { closeErr <- opener.Close() }()
	select {
	case err := <-closeErr:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on provider resolution after lifecycle cancellation")
	}
	select {
	case err := <-startErr:
		if !errors.Is(err, ErrPortalOpenerClosed) {
			t.Fatalf("Start after Close = %v, want ErrPortalOpenerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after Close")
	}
}

func TestPortalOpenerConcurrentStartIsSingleFlight(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	entered := make(chan struct{})
	release := make(chan struct{})
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			close(entered)
		}
		<-release
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 11), nil
	}

	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() { errs <- opener.Start(t.Context()) })
	}
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Start: %v", err)
		}
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("concurrent Start opens = %d, want 1", got)
	}
}

func TestPortalOpenerRenewalUsesFullWindowAndStopsAtExpiry(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return 2900 * time.Millisecond }
	opener.renewalMinimumGap = time.Millisecond
	opener.retryInitial = 10 * time.Millisecond
	opener.retryMaximum = 20 * time.Millisecond
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 3, 12), nil
		}
		return nil, errors.New("scripted native renewal failure")
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitForPortalCondition(t, time.Second, func() bool { return opener.Health().ConsecutiveFailures >= 4 })
	if health := opener.Health(); health.ConsecutiveFailures < 4 || health.LastFailureClass != PortalOpenerFailureOpen || !health.Ready {
		t.Fatalf("health while renewal uses remaining headroom = %#v", health)
	}
	opener.mu.RLock()
	loopDone := opener.loopDone
	opener.mu.RUnlock()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not stop at handle expiry")
	}
	stoppedAt := opens.Load()
	time.Sleep(30 * time.Millisecond)
	if got := opens.Load(); got != stoppedAt {
		t.Fatalf("renewal continued after expiry: opens moved from %d to %d", stoppedAt, got)
	}
	if health := opener.Health(); health.State != PortalOpenerStateDegraded || health.Ready {
		t.Fatalf("health after renewal window expired = %#v", health)
	}
	opener.mu.RLock()
	active := opener.active
	opener.mu.RUnlock()
	if active != nil {
		t.Fatal("expired renewal retained the active bearer handle")
	}
}

func TestPortalOpenerStartReturnsWhenLateRenewalRestoresReadiness(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })

	// Start renewal immediately, then keep its result under explicit channel
	// control. This proves the lifecycle seam without wall-clock scheduling.
	opener.renewalLead = func(time.Duration) time.Duration { return time.Minute }
	opener.renewalMinimumGap = time.Millisecond
	renewalEntered := make(chan struct{})
	releaseRenewal := make(chan struct{})
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 22), nil
		}
		close(renewalEntered)
		<-releaseRenewal
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 3600, 23), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-renewalEntered

	// Model the exact reviewed state: the old handle expires while the final
	// bounded renewal attempt is still in flight.
	opener.mu.Lock()
	opener.expiresAt = opener.now().Add(-time.Second)
	opener.mu.Unlock()
	startCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	startErr := make(chan error, 1)
	go func() { startErr <- opener.Start(startCtx) }()
	close(releaseRenewal)
	if err := <-startErr; err != nil {
		t.Fatalf("Start did not observe late renewal success: %v", err)
	}
	if health := opener.Health(); !health.Ready || health.State != "ready" {
		t.Fatalf("late renewal health = %#v", health)
	}
}

func TestPortalOpenerExpiredAfterBoundedRenewalCanRecoverWithStart(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return 1990 * time.Millisecond }
	opener.renewalMinimumGap = time.Millisecond
	opener.retryInitial = 100 * time.Millisecond
	opener.retryMaximum = 200 * time.Millisecond
	var opens atomic.Int32
	var recoveryPhase atomic.Int32
	var explicitOpens atomic.Int32
	recoveryEntered := make(chan struct{})
	releaseRecovery := make(chan struct{})
	recoveryErr := errors.New("scripted explicit recovery failure")
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 2, 20), nil
		}
		switch recoveryPhase.Load() {
		case 0:
			return nil, errors.New("scripted bounded renewal failure")
		case 1:
			explicitOpens.Add(1)
			recoveryPhase.Store(2)
			return nil, recoveryErr
		case 2:
			explicitOpens.Add(1)
			close(recoveryEntered)
			<-releaseRecovery
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 21), nil
		default:
			return nil, errors.New("unexpected extra open")
		}
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	opener.mu.RLock()
	failedLoopDone := opener.loopDone
	opener.mu.RUnlock()
	select {
	case <-failedLoopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded renewal loop did not finish after handle expiry")
	}
	recoveryPhase.Store(1)
	if health := opener.Health(); health.State != "degraded" || health.Ready {
		t.Fatalf("health after bounded renewal expiry = %#v", health)
	}
	resp, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("Do builder ran with an expired handle")
		return nil, errors.New("builder ran with an expired handle")
	})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !errors.Is(err, ErrPortalOpenerNotReady) {
		t.Fatalf("expired Do response=%#v error=%v", resp, err)
	}
	if err := opener.Start(t.Context()); !errors.Is(err, recoveryErr) {
		t.Fatalf("first explicit recovery error = %v", err)
	}
	if health := opener.Health(); health.State != "degraded" || health.Ready {
		t.Fatalf("failed explicit recovery left unstable state: %#v", health)
	}
	opener.mu.RLock()
	active := opener.active
	opener.mu.RUnlock()
	if active != nil {
		t.Fatal("failed explicit recovery retained an expired bearer handle")
	}

	const callers = 12
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() { errs <- opener.Start(t.Context()) })
	}
	<-recoveryEntered
	if health := opener.Health(); health.State != "degraded" || health.Ready {
		t.Fatalf("blocked explicit recovery health = %#v", health)
	}
	resp, err = opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("Do builder ran during explicit recovery")
		return nil, errors.New("builder ran during explicit recovery")
	})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !errors.Is(err, ErrPortalOpenerNotReady) {
		t.Fatalf("Do during explicit recovery response=%#v error=%v", resp, err)
	}
	close(releaseRecovery)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("explicit Start recovery: %v", err)
		}
	}
	if got := explicitOpens.Load(); got != 2 {
		t.Fatalf("single-flight explicit recovery opens = %d, want one failed and one successful", got)
	}
	if health := opener.Health(); health.State != "ready" || !health.Ready || health.ConsecutiveFailures != 0 {
		t.Fatalf("health after explicit recovery = %#v", health)
	}
}

func TestPortalOpenerSuccessfulRenewalAtomicallyReplacesCachedHandle(t *testing.T) {
	const renewedToken = "e30.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	var receivedToken atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie(qurlVsessionCookieName)
		if err != nil {
			t.Error(err)
			return
		}
		receivedToken.Store(cookie.Value)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return 9990 * time.Millisecond }
	opener.renewalMinimumGap = time.Millisecond
	var opens atomic.Int32
	var sessionMu sync.Mutex
	var sessions []*PortalSession
	target := server.URL + "/fixed"
	opener.open = func(_ context.Context, _ string, openCfg Config) (*ResourceHandle, error) {
		sessionMu.Lock()
		sessions = append(sessions, openCfg.PortalSession)
		sessionMu.Unlock()
		count := opens.Add(1)
		if count == 1 {
			return portalTestHandle(target, testAuthProviderToken, 10, 18), nil
		}
		return portalTestHandle(target, renewedToken, 60, 19), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	opener.mu.RLock()
	retiredHandle := opener.active
	opener.mu.RUnlock()
	waitForPortalCondition(t, time.Second, func() bool {
		return opens.Load() == 2 && time.Until(opener.Health().ExpiresAt) > 30*time.Second
	})
	resp, err := opener.Do(t.Context(), func(authenticatedTarget *url.URL) (*http.Request, error) {
		return http.NewRequestWithContext(t.Context(), http.MethodPost, authenticatedTarget.String(), http.NoBody)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if token, _ := receivedToken.Load().(string); token != renewedToken {
		t.Fatalf("Do used token %q, want renewed handle", token)
	}
	if retiredHandle == nil || retiredHandle.authProviderToken != "" {
		t.Fatal("renewal retained the retired bearer token")
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if len(sessions) != 2 || sessions[0] == nil || sessions[0] != sessions[1] {
		t.Fatal("renewal did not retain one private PortalSession")
	}
}

func TestPortalOpenerRenewalRefusesChangedAuthenticatedTarget(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return 1990 * time.Millisecond }
	opener.renewalMinimumGap = time.Millisecond
	opener.retryInitial = time.Millisecond
	opener.retryMaximum = time.Millisecond
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 2, 13), nil
		}
		return portalTestHandle("https://r_other.qurl.site/fixed", testAuthProviderToken, 60, 14), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitForPortalCondition(t, time.Second, func() bool { return opener.Health().ConsecutiveFailures == 1 })
	if health := opener.Health(); !health.Ready || health.LastFailureClass != PortalOpenerFailureTargetChanged {
		t.Fatalf("changed-target renewal health = %#v, want ready old handle and target_changed", health)
	}
	opener.mu.RLock()
	failedLoopDone := opener.loopDone
	opener.mu.RUnlock()
	select {
	case <-failedLoopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("target-change renewal loop did not reach degraded state")
	}
	if err := opener.Start(t.Context()); !errors.Is(err, ErrPortalTargetChanged) {
		t.Fatalf("recovery Start target-change error = %v", err)
	}
	if health := opener.Health(); health.State != "degraded" || health.Ready || health.LastFailureClass != PortalOpenerFailureTargetChanged {
		t.Fatalf("target-change recovery left unstable health = %#v", health)
	}
}

type closeTrackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestPortalOpenerCanonicalizesAuthenticatedTargetBeforeReady(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.EscapedPath() != "/reports/Q3%20summary" {
			t.Errorf("request escaped path = %q", req.URL.EscapedPath())
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	rawTarget := server.URL + "/reports/Q3 summary"
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle(rawTarget, testAuthProviderToken, 60, 30), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if health := opener.Health(); health.State != "ready" || !health.Ready {
		t.Fatalf("canonical target health = %#v", health)
	}
	opener.mu.RLock()
	storedTarget := opener.target
	opener.mu.RUnlock()
	if storedTarget != server.URL+"/reports/Q3%20summary" {
		t.Fatalf("stored canonical target = %q", storedTarget)
	}
	resp, err := opener.Do(t.Context(), func(target *url.URL) (*http.Request, error) {
		return http.NewRequestWithContext(t.Context(), http.MethodPost, target.String(), http.NoBody)
	}, RejectPortalRedirects())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestPortalOpenerDoPinsExactTargetAndWireHost(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	target := server.URL + "/fixed"
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle(target, testAuthProviderToken, 60, 15), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*url.URL, *http.Request){
		"URL": func(target *url.URL, req *http.Request) {
			target.Path = "/changed"
			req.URL = target
		},
		"Host": func(_ *url.URL, req *http.Request) { req.Host = "proxy.invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			body := &closeTrackingBody{Reader: bytes.NewReader([]byte("body"))}
			resp, err := opener.Do(t.Context(), func(authenticatedTarget *url.URL) (*http.Request, error) {
				req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, authenticatedTarget.String(), body)
				if requestErr == nil {
					mutate(authenticatedTarget, req)
				}
				return req, requestErr
			})
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, ErrInvalidContentRequest) {
				t.Fatalf("changed %s error = %v, want ErrInvalidContentRequest", name, err)
			}
			if !body.closed.Load() {
				t.Fatal("rejected request body was not closed")
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("changed target sent %d requests", got)
	}
}

func TestPortalOpenerDoClosesBuilderBodyWhenBuilderReturnsError(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle(server.URL+"/fixed", testAuthProviderToken, 60, 15), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	body := &closeTrackingBody{Reader: bytes.NewReader([]byte("body"))}
	wantErr := errors.New("request signing failed")
	response, err := opener.Do(t.Context(), func(target *url.URL) (*http.Request, error) {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, target.String(), body)
		if requestErr != nil {
			return nil, requestErr
		}
		return request, wantErr
	})
	if response != nil {
		_ = response.Body.Close()
		t.Fatal("builder error returned a response")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Do error = %v, want %v", err, wantErr)
	}
	if !body.closed.Load() {
		t.Fatal("builder-error request body was not closed")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("builder error sent %d requests", got)
	}
}

func TestPortalOpenerRedirectPolicies(t *testing.T) {
	var sameOriginEnd atomic.Int32
	var crossOriginRequests atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		crossOriginRequests.Add(1)
	}))
	t.Cleanup(destination.Close)
	var origin *httptest.Server
	origin = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := req.Cookie(qurlVsessionCookieName); err != nil {
			t.Error("redirected request lost its session cookie")
		}
		switch req.URL.Path {
		case "/same":
			http.Redirect(w, req, origin.URL+"/end", http.StatusTemporaryRedirect)
		case "/end":
			sameOriginEnd.Add(1)
		case "/cross":
			http.Redirect(w, req, destination.URL+"/end", http.StatusTemporaryRedirect)
		}
	}))
	t.Cleanup(origin.Close)

	for name, path := range map[string]string{"same origin": "/same", "reject all": "/same", "cross origin": "/cross"} {
		t.Run(name, func(t *testing.T) {
			link, cfg := portalOpenerFixture(t)
			opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(origin.Client()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closePortalOpener(t, opener) })
			target := origin.URL + path
			opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
				return portalTestHandle(target, testAuthProviderToken, 60, 16), nil
			}
			if err := opener.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			options := []PortalRequestOption(nil)
			if name == "reject all" {
				options = append(options, RejectPortalRedirects())
			}
			resp, err := opener.Do(t.Context(), func(authenticatedTarget *url.URL) (*http.Request, error) {
				return http.NewRequestWithContext(t.Context(), http.MethodPost, authenticatedTarget.String(), http.NoBody)
			}, options...)
			if resp != nil {
				_ = resp.Body.Close()
			}
			switch name {
			case "same origin":
				if err != nil {
					t.Fatal(err)
				}
				if resp == nil {
					t.Fatal("same-origin redirect returned no response")
				}
			case "reject all":
				if !errors.Is(err, ErrPortalRedirect) {
					t.Fatalf("redirect error = %v, want ErrPortalRedirect", err)
				}
				if resp != nil {
					t.Fatal("rejected redirect returned a response with an error")
				}
			case "cross origin":
				if !errors.Is(err, ErrPortalRedirect) {
					t.Fatalf("cross-origin redirect error = %v, want ErrPortalRedirect", err)
				}
				if errors.Is(err, ErrInvalidContentRequest) {
					t.Fatalf("cross-origin redirect error = %v, must not report a caller error", err)
				}
				if resp != nil {
					t.Fatal("cross-origin redirect returned a response with an error")
				}
			}
		})
	}
	if sameOriginEnd.Load() != 1 {
		t.Fatalf("same-origin destination requests = %d, want 1", sameOriginEnd.Load())
	}
	if crossOriginRequests.Load() != 0 {
		t.Fatalf("cross-origin destination received %d requests", crossOriginRequests.Load())
	}
}

type closeIgnoringRedirectTransport struct {
	firstLeg        chan struct{}
	releaseFirstLeg chan struct{}
	redirected      atomic.Int32
}

func (transport *closeIgnoringRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/start" {
		close(transport.firstLeg)
		<-transport.releaseFirstLeg // Deliberately ignore request cancellation.
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"https://portal.example/end"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}
	transport.redirected.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

type portalContextBody struct {
	ctx     context.Context
	content chan string
}

func (body *portalContextBody) Read(destination []byte) (int, error) {
	select {
	case <-body.ctx.Done():
		return 0, body.ctx.Err()
	case content := <-body.content:
		return copy(destination, content), io.EOF
	}
}

func (*portalContextBody) Close() error { return nil }

type portalContextBodyTransport struct {
	body chan *portalContextBody
}

type closeIgnoringResponseTransport struct {
	entered chan struct{}
	release chan struct{}
	body    *closeTrackingBody
}

func (transport *closeIgnoringResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	close(transport.entered)
	<-transport.release // Deliberately ignore request cancellation.
	return &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
		Body: transport.body,
	}, nil
}

func (transport *portalContextBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := &portalContextBody{ctx: req.Context(), content: make(chan string, 1)}
	transport.body <- body
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       body,
		Request:    req,
	}, nil
}

func TestPortalOpenerDoKeepsResponseBodyContextAlive(t *testing.T) {
	transport := &portalContextBodyTransport{body: make(chan *portalContextBody, 1)}
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://portal.example/content", testAuthProviderToken, 60, 18), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })

	response, err := opener.Do(t.Context(), func(target *url.URL) (*http.Request, error) {
		return http.NewRequestWithContext(t.Context(), http.MethodGet, target.String(), http.NoBody)
	})
	if err != nil {
		t.Fatal(err)
	}
	body := <-transport.body
	body.content <- "ok"
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(content) != "ok" {
		t.Fatalf("response body = %q, want ok", content)
	}
	_ = response.Body.Close()
}

func TestPortalOpenerCloseCancelsResponseBodyRead(t *testing.T) {
	transport := &portalContextBodyTransport{body: make(chan *portalContextBody, 1)}
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://portal.example/content", testAuthProviderToken, 60, 19), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	response, err := opener.Do(context.Background(), func(target *url.URL) (*http.Request, error) { //nolint:bodyclose // closed after the cancellation assertion
		return http.NewRequestWithContext(context.Background(), http.MethodGet, target.String(), http.NoBody)
	})
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, requestErr := io.ReadAll(response.Body)
		readErr <- requestErr
	}()
	if err := opener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("response body read after Close = %v, want context canceled", err)
	}
	_ = response.Body.Close()
}

func TestPortalOpenerCloseRaceDiscardsSuccessfulTransportResponse(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("ok")}
	transport := &closeIgnoringResponseTransport{entered: make(chan struct{}), release: make(chan struct{}), body: body}
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://portal.example/content", testAuthProviderToken, 60, 20), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		response, requestErr := opener.Do(context.Background(), func(target *url.URL) (*http.Request, error) {
			return http.NewRequestWithContext(context.Background(), http.MethodGet, target.String(), http.NoBody)
		})
		if response != nil {
			_ = response.Body.Close()
		}
		result <- requestErr
	}()
	<-transport.entered
	if err := opener.Close(); err != nil {
		t.Fatal(err)
	}
	close(transport.release)
	if err := <-result; !errors.Is(err, ErrPortalOpenerClosed) {
		t.Fatalf("Do close race = %v, want ErrPortalOpenerClosed", err)
	}
	if !body.closed.Load() {
		t.Fatal("Do close race did not close the discarded response body")
	}
}

func TestPortalOpenerCloseCancelsRequestBeforeRedirect(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options []PortalRequestOption
	}{
		{name: "follow same-origin redirects"},
		{name: "reject redirects", options: []PortalRequestOption{RejectPortalRedirects()}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &closeIgnoringRedirectTransport{
				firstLeg: make(chan struct{}), releaseFirstLeg: make(chan struct{}),
			}

			link, cfg := portalOpenerFixture(t)
			opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closePortalOpener(t, opener) })
			opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
				return portalTestHandle("https://portal.example/start", testAuthProviderToken, 60, 16), nil
			}
			if err := opener.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			doErr := make(chan error, 1)
			go func() {
				response, requestErr := opener.Do(context.Background(), func(target *url.URL) (*http.Request, error) {
					return http.NewRequestWithContext(context.Background(), http.MethodGet, target.String(), http.NoBody)
				}, testCase.options...)
				if response != nil {
					_ = response.Body.Close()
				}
				doErr <- requestErr
			}()
			<-transport.firstLeg
			if err := opener.Close(); err != nil {
				t.Fatal(err)
			}
			close(transport.releaseFirstLeg)
			if err := <-doErr; !errors.Is(err, ErrPortalOpenerClosed) {
				t.Fatalf("Do error = %v, want ErrPortalOpenerClosed", err)
			} else if errors.Is(err, ErrPortalRedirect) {
				t.Fatalf("Do error = %v, Close must take precedence over ErrPortalRedirect", err)
			}
			if transport.redirected.Load() != 0 {
				t.Fatalf("redirect requests after Close = %d, want 0", transport.redirected.Load())
			}
		})
	}
}

func TestPortalOpenerNativeOnlyRemovesRelayFallback(t *testing.T) {
	link, trust, _ := generatedAcceptLink(t)
	doer := &refusingDoer{t: t}
	cfg := Config{
		TrustStore: trust,
		Cells:      unreachableCellCatalog(t, otherCellKeyB64(t)),
		RelayAllowlist: NewRelayAllowlist([]string{
			"relay.example.com",
		}),
		HTTPClient: doer,
	}
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	if err := opener.Start(t.Context()); !errors.Is(err, ErrCellNotInCatalog) {
		t.Fatalf("unknown native cell error = %v, want ErrCellNotInCatalog", err)
	}
	if doer.called {
		t.Fatal("native-only opener fell back to relay HTTP")
	}
}

func TestPortalOpenerRequiresNativeCatalogBeforeParsingLink(t *testing.T) {
	_, trust, _ := generatedAcceptLink(t)
	opener, err := NewPortalOpener("not-a-qurl", WithPortalOpenerConfig(Config{
		TrustStore: trust, RelayAllowlist: relayExampleAllowlist(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	if err := opener.Start(t.Context()); !errors.Is(err, ErrPortalNativeOnly) {
		t.Fatalf("missing native catalog error = %v, want ErrPortalNativeOnly", err)
	}
}

func TestPortalOpenerRealNativeLoopbackToProtectedHTTP(t *testing.T) {
	var contentRequests atomic.Int32
	var deniedRequests atomic.Int32
	content := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/internal/v1/delegated-mint-capabilities" {
			t.Errorf("content request = %s %s", req.Method, req.URL.Path)
		}
		cookie, err := req.Cookie(qurlVsessionCookieName)
		if err != nil || cookie.Value != testAuthProviderToken {
			deniedRequests.Add(1)
			http.Error(w, "NHP admission required", http.StatusForbidden)
			return
		}
		contentRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(content.Close)
	directRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		content.URL+"/internal/v1/delegated-mint-capabilities", strings.NewReader(`{"issue":true}`))
	if err != nil {
		t.Fatal(err)
	}
	directResponse, err := content.Client().Do(directRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = directResponse.Body.Close()
	if directResponse.StatusCode != http.StatusForbidden || deniedRequests.Load() != 1 || contentRequests.Load() != 0 {
		t.Fatalf("pre-knock request status=%d denied=%d admitted=%d, want 403/1/0",
			directResponse.StatusCode, deniedRequests.Load(), contentRequests.Load())
	}

	peer, link, cfg := newPortalSessionPeer(t, false)
	peer.mu.Lock()
	peer.redirectURL = content.URL + "/internal/v1/delegated-mint-capabilities"
	peer.mu.Unlock()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	go func() {
		defer close(done)
		packet := make([]byte, 65536)
		for {
			n, addr, readErr := conn.ReadFromUDP(packet)
			if readErr != nil {
				return
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				peer.server.URL+"/relay/"+relayknock.PubKeyFingerprint(peer.serverKey.PublicKey().Bytes()),
				bytes.NewReader(packet[:n]))
			peer.serveHTTP(recorder, request)
			if recorder.Code == http.StatusOK {
				if _, writeErr := conn.WriteToUDP(recorder.Body.Bytes(), addr); writeErr != nil {
					t.Error(writeErr)
				}
			}
		}
	}()
	catalog, err := NewCellCatalog([]CellEntry{{
		ServerPublicKeyB64: base64.RawURLEncoding.EncodeToString(peer.serverKey.PublicKey().Bytes()),
		CellID:             "loopback-test-cell", Host: "cell.example.test", Port: standardNHPUDPPort,
	}})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cells = catalog
	cfg.nativeUDPOptions = &nativeudp.Options{
		Resolver: assignmentTestResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer:  assignmentTestDialer{target: conn.LocalAddr().String()},
		Timeout: time.Second, MaxAddresses: 1,
	}
	opener, err := NewPortalOpener(link,
		WithPortalOpenerConfig(cfg), WithPortalOpenerHTTPClient(content.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	if err := opener.Start(t.Context()); err != nil {
		t.Fatalf("native Start: %v", err)
	}
	resp, err := opener.Do(t.Context(), func(authenticatedTarget *url.URL) (*http.Request, error) {
		return http.NewRequestWithContext(t.Context(), http.MethodPost, authenticatedTarget.String(), strings.NewReader(`{"issue":true}`))
	}, RejectPortalRedirects())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if contentRequests.Load() != 1 {
		t.Fatalf("protected content requests = %d, want 1", contentRequests.Load())
	}
	if deniedRequests.Load() != 1 {
		t.Fatalf("denied protected content requests = %d, want only the pre-knock request", deniedRequests.Load())
	}
	peer.mu.Lock()
	knocks := len(peer.capability)
	peer.mu.Unlock()
	if knocks != 1 {
		t.Fatalf("native NHP knocks = %d, want 1", knocks)
	}
}

func TestPortalOpenerHealthAndFormattingDoNotExposeSecrets(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://r_secret.qurl.site/private", testAuthProviderToken, 60, 17), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	healthJSON, err := json.Marshal(opener.Health())
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(healthJSON), opener.String(), opener.GoString()} {
		if strings.Contains(rendered, link) || strings.Contains(rendered, "r_secret") || strings.Contains(rendered, testAuthProviderToken) {
			t.Fatalf("diagnostic exposed portal secret or target: %s", rendered)
		}
	}
}

func TestPortalOpenerCloseCancelsStartAndIsIdempotent(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	opener.open = func(ctx context.Context, _ string, _ Config) (*ResourceHandle, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	startErr := make(chan error, 1)
	go func() { startErr <- opener.Start(context.Background()) }()
	<-entered
	if err := opener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-startErr; !errors.Is(err, ErrPortalOpenerClosed) {
		t.Fatalf("canceled Start error = %v, want ErrPortalOpenerClosed", err)
	}
	if err := opener.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if opener.link != "" || opener.target != "" || opener.active != nil || opener.session.state != nil {
		t.Fatal("Close retained qURL or active session material")
	}
	health := opener.Health()
	if health.State != PortalOpenerStateClosed || health.Ready || !health.ExpiresAt.IsZero() ||
		!health.RenewAt.IsZero() || !health.LastOpenSucceededAt.IsZero() ||
		health.LastFailureClass != PortalOpenerFailureNone || health.ConsecutiveFailures != 0 {
		t.Fatalf("Health after Close retained lifecycle state: %+v", health)
	}
	resp, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		return nil, errors.New("builder must not run after Close")
	})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrPortalOpenerClosed) {
		t.Fatalf("Do after Close = %v, want ErrPortalOpenerClosed", err)
	}
}

func TestPortalOpenerCloseClearsHealthLifetime(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 24), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if health := opener.Health(); health.ExpiresAt.IsZero() || health.RenewAt.IsZero() || health.LastOpenSucceededAt.IsZero() {
		t.Fatalf("started opener has incomplete health: %+v", health)
	}
	if err := opener.Close(); err != nil {
		t.Fatal(err)
	}
	health := opener.Health()
	if health.State != PortalOpenerStateClosed || health.Ready || !health.ExpiresAt.IsZero() ||
		!health.RenewAt.IsZero() || !health.LastOpenSucceededAt.IsZero() ||
		health.LastFailureClass != PortalOpenerFailureNone || health.ConsecutiveFailures != 0 {
		t.Fatalf("Health after successful Close retained lifecycle state: %+v", health)
	}
}

func TestPortalOpenerRenewLoopUnexpectedExitDegrades(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 23), nil
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })

	opener.mu.RLock()
	loopDone := opener.loopDone
	opener.mu.RUnlock()
	// Simulate a future renewal return path that stops its lifecycle without
	// first changing opener state. The loop-level defer must fail closed.
	opener.cancel()
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("renewal loop did not stop")
	}
	if health := opener.Health(); health.State != PortalOpenerStateDegraded || health.Ready {
		t.Fatalf("unexpected renewal exit health = %+v, want degraded and not ready", health)
	}
	if opener.active != nil {
		t.Fatal("unexpected renewal exit retained the active handle")
	}
}

func TestPortalOpenerCloseRaceClearsUninstalledBearer(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	returnedHandle := portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 60, 22)
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		close(entered)
		<-release
		return returnedHandle, nil
	}
	startErr := make(chan error, 1)
	go func() { startErr <- opener.Start(context.Background()) }()
	<-entered
	closeErr := make(chan error, 1)
	go func() { closeErr <- opener.Close() }()
	waitForPortalCondition(t, time.Second, func() bool {
		return opener.Health().State == "closed"
	})
	close(release)
	if err := <-startErr; !errors.Is(err, ErrPortalOpenerClosed) {
		t.Fatalf("Start close-race error = %v", err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("Close race error = %v", err)
	}
	if returnedHandle.authProviderToken != "" {
		t.Fatal("Close race retained an opened but uninstalled bearer token")
	}
}

func TestPortalOpenerDoBeforeStartReturnsImmediately(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	started := time.Now()
	resp, err := opener.Do(t.Context(), func(*url.URL) (*http.Request, error) {
		t.Fatal("request builder ran without an active handle")
		return nil, errors.New("builder ran without an active handle")
	})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrPortalOpenerNotStarted) {
		t.Fatalf("Do before Start = %v, want ErrPortalOpenerNotStarted", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("Do before Start blocked for %s", elapsed)
	}
}
