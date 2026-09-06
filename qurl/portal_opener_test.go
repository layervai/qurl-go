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

func TestPortalOpenerRenewalIsProactiveSingleFlightAndBounded(t *testing.T) {
	link, cfg := portalOpenerFixture(t)
	opener, err := NewPortalOpener(link, WithPortalOpenerConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePortalOpener(t, opener) })
	opener.renewalLead = func(time.Duration) time.Duration { return 9990 * time.Millisecond }
	opener.retryInitial = 2 * time.Millisecond
	opener.retryMaximum = 4 * time.Millisecond
	opener.retryLimit = 3
	var opens atomic.Int32
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		if opens.Add(1) == 1 {
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 10, 12), nil
		}
		return nil, errors.New("scripted native renewal failure")
	}
	if err := opener.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitForPortalCondition(t, time.Second, func() bool { return opens.Load() == 4 })
	time.Sleep(20 * time.Millisecond)
	if got := opens.Load(); got != 4 {
		t.Fatalf("bounded renewal attempts = %d, want 3 after initial open", got-1)
	}
	health := opener.Health()
	if health.ConsecutiveFailures != 3 || health.LastFailureClass != PortalOpenerFailureOpen || !health.Ready {
		t.Fatalf("health during bounded renewal failure = %#v", health)
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
	opener.retryInitial = time.Millisecond
	opener.retryMaximum = time.Millisecond
	opener.retryLimit = 2
	var opens atomic.Int32
	recoveryEntered := make(chan struct{})
	releaseRecovery := make(chan struct{})
	recoveryErr := errors.New("scripted explicit recovery failure")
	opener.open = func(context.Context, string, Config) (*ResourceHandle, error) {
		switch opens.Add(1) {
		case 1:
			return portalTestHandle("https://r_test.qurl.site/fixed", testAuthProviderToken, 2, 20), nil
		case 2, 3:
			return nil, errors.New("scripted bounded renewal failure")
		case 4:
			return nil, recoveryErr
		case 5:
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
	if got := opens.Load(); got != 5 {
		t.Fatalf("single-flight recovery opens = %d, want one failed and one successful explicit recovery", got-3)
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
	opener.retryInitial = time.Millisecond
	opener.retryMaximum = time.Millisecond
	opener.retryLimit = 1
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
			case "reject all":
				if !errors.Is(err, ErrPortalRedirect) {
					t.Fatalf("redirect error = %v, want ErrPortalRedirect", err)
				}
			case "cross origin":
				if !errors.Is(err, ErrInvalidContentRequest) {
					t.Fatalf("cross-origin redirect error = %v, want ErrInvalidContentRequest", err)
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
	content := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		contentRequests.Add(1)
		if req.Method != http.MethodPost || req.URL.Path != "/internal/v1/delegated-mint-capabilities" {
			t.Errorf("content request = %s %s", req.Method, req.URL.Path)
		}
		cookie, err := req.Cookie(qurlVsessionCookieName)
		if err != nil || cookie.Value != testAuthProviderToken {
			t.Errorf("content cookie = %#v, %v", cookie, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(content.Close)

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
