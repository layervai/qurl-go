package qurl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenRegisteredAgent_ZeroNetworkIgnoresKnockPeer(t *testing.T) {
	cases := []struct {
		name string
		edit func(*AgentState)
	}{
		{name: "missing", edit: func(state *AgentState) { state.NHPPeer = nil }},
		{name: "malformed", edit: func(state *AgentState) {
			state.NHPPeer = &NHPServerPeerInfo{PublicKeyB64: "not-base64", Host: "", Port: -1}
		}},
		{name: "expired", edit: func(state *AgentState) {
			state.NHPPeer.ExpireTime = time.Now().Add(-time.Hour).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			state := h.loadState(t)
			tc.edit(state)
			if err := h.store.SaveAgentState(context.Background(), state); err != nil {
				t.Fatalf("save peer variant: %v", err)
			}

			var networkCalls atomic.Int32
			refusing := doerFunc(func(*http.Request) (*http.Response, error) {
				networkCalls.Add(1)
				return nil, errors.New("unexpected network call")
			})
			client, err := OpenRegisteredAgent(context.Background(), h.store,
				WithBaseURL("https://resources.example.test"),
				WithHTTPClient(refusing),
			)
			if err != nil {
				t.Fatalf("OpenRegisteredAgent: %v", err)
			}
			if client == nil {
				t.Fatal("OpenRegisteredAgent returned nil Client")
			}
			if networkCalls.Load() != 0 {
				t.Fatalf("OpenRegisteredAgent network calls = %d, want 0", networkCalls.Load())
			}
		})
	}
}

func TestRefreshAgentRegistration_RotatesBindingPreservesCredentialAndSkipsCompletion(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	if _, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	before := h.loadState(t)
	before.NHPPeer = nil
	before.RelayURL = ""
	if err := h.store.SaveAgentState(context.Background(), before); err != nil {
		t.Fatalf("save lost binding: %v", err)
	}

	rotated := newFakeNHPServer(t)
	rotatedRelay := httptest.NewServer(rotated.handler())
	t.Cleanup(rotatedRelay.Close)
	h.svc.mu.Lock()
	h.svc.nhp = rotated
	h.svc.keyID = "key_rotated"
	h.svc.mu.Unlock()
	inner := h.svc.handler(rotatedRelay.URL)
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agent/registration-info" {
			state, err := h.store.LoadAgentState(r.Context())
			if err != nil {
				t.Errorf("load state for rotated peer: %v", err)
			} else {
				pub, decErr := base64.StdEncoding.DecodeString(state.PublicKeyB64)
				if decErr != nil {
					t.Errorf("decode device pub: %v", decErr)
				} else {
					rotated.setExpectDevicePub(pub)
				}
			}
		}
		inner.ServeHTTP(w, r)
	}))

	completeBefore := h.svc.completionCalls.Load()
	refreshed, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	if refreshed.DeviceAPIKey != before.DeviceAPIKey {
		t.Fatalf("DeviceAPIKey changed during refresh")
	}
	if refreshed.RegisteredAt == nil || !refreshed.RegisteredAt.Equal(*before.RegisteredAt) {
		t.Fatalf("RegisteredAt changed during refresh: before=%v after=%v", before.RegisteredAt, refreshed.RegisteredAt)
	}
	if refreshed.NHPPeer.PublicKeyB64 != rotated.serverPubB64() || refreshed.RelayURL != rotatedRelay.URL || refreshed.KeyID != "key_rotated" {
		t.Fatalf("rotated binding not persisted: %#v", refreshed)
	}
	if h.svc.completionCalls.Load() != completeBefore {
		t.Fatal("binding refresh called registration completion")
	}
	if rotated.regCount() != 1 {
		t.Fatalf("rotated REG count = %d, want 1", rotated.regCount())
	}
}

func TestRefreshAgentRegistration_SaveFailureDoesNotCommitNewBinding(t *testing.T) {
	h := registeredHarness(t)
	before := h.loadState(t)
	h.svc.mu.Lock()
	h.svc.keyID = "key_new_binding"
	h.svc.mu.Unlock()
	saveFailure := errors.New("injected refresh save failure")
	failing := &failingSaveStore{
		inner: h.store,
		failWhen: func(state *AgentState) bool {
			return state.KeyID == "key_new_binding"
		},
		failErr:   saveFailure,
		failsLeft: 1,
	}
	h.store = failing

	_, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.Is(err, saveFailure) {
		t.Fatalf("want refresh save failure, got %v", err)
	}
	after, err := failing.inner.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load state after failed refresh: %v", err)
	}
	if after.KeyID != before.KeyID || after.RelayURL != before.RelayURL || after.DeviceAPIKey != before.DeviceAPIKey {
		t.Fatalf("failed refresh committed partial metadata: before=%#v after=%#v", before, after)
	}
}

func TestRegisterAgent_RegisterOriginDoesNotRetargetReturnedClient(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if client.baseURL != defaultAPIBaseURL {
		t.Fatalf("returned Client baseURL = %q, want independent default %q", client.baseURL, defaultAPIBaseURL)
	}
}

func TestRefreshAgentRegistration_TakeoverCookieAndRateLimit(t *testing.T) {
	t.Run("takeover", func(t *testing.T) {
		h := registeredHarness(t)
		if _, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts(WithTakeover())...); err != nil {
			t.Fatalf("RefreshAgentRegistration: %v", err)
		}
		h.nhp.mu.Lock()
		last := h.nhp.regs[len(h.nhp.regs)-1]
		h.nhp.mu.Unlock()
		if !last.UsrData.Takeover {
			t.Fatal("forced REG did not carry takeover=true")
		}
	})

	t.Run("cookie challenge", func(t *testing.T) {
		h := registeredHarness(t)
		h.nhp.mu.Lock()
		h.nhp.replyREGWithCOK = true
		h.nhp.mu.Unlock()
		_, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRetryLater) {
			t.Fatalf("want ErrRegistrationRetryLater, got %v", err)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		h := registeredHarness(t)
		h.nhp.mu.Lock()
		h.nhp.rakErrCode = rakRateLimited
		h.nhp.mu.Unlock()
		_, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRateLimited) {
			t.Fatalf("want ErrRegistrationRateLimited, got %v", err)
		}
	})

	t.Run("registration HTTP rate limited", func(t *testing.T) {
		h := registeredHarness(t)
		regsBefore := h.nhp.regCount()
		h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":{"code":"rate_limited","detail":"slow down"}}`)
		}))
		_, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
		if !errors.Is(err, ErrRegistrationRateLimited) {
			t.Fatalf("want ErrRegistrationRateLimited, got %v", err)
		}
		if h.nhp.regCount() != regsBefore {
			t.Fatal("HTTP preflight rate limit still sent REG")
		}
	})
}

func TestRegisterAgent_KeyKindPolicyRejectsBeforeOTPOrREG(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_account", h.store, h.registerOpts(
		WithAllowedRegistrationKeyKinds(RegistrationKeyKindBootstrap),
	)...)
	if !errors.Is(err, ErrRegistrationKeyKindDisallowed) {
		t.Fatalf("want ErrRegistrationKeyKindDisallowed, got %v", err)
	}
	var disallowed *RegistrationKeyKindDisallowedError
	if !errors.As(err, &disallowed) || disallowed.Kind != RegistrationKeyKindAccount {
		t.Fatalf("typed disallowed error = %#v", disallowed)
	}
	if h.nhp.otpCount() != 0 || h.nhp.regCount() != 0 {
		t.Fatalf("policy rejection made NHP side effects: otp=%d reg=%d", h.nhp.otpCount(), h.nhp.regCount())
	}
	state := h.loadState(t)
	if state.OTPRequestedAt != nil {
		t.Fatalf("policy rejection mutated OTP-pending state: %#v", state.OTPRequestedAt)
	}
}

func TestRefreshAgentRegistration_AccountOTPResumeDoesNotComplete(t *testing.T) {
	h := registeredHarness(t)
	h.svc.mu.Lock()
	h.svc.keyKind = keyKindAccount
	h.svc.maskedEmail = "j***@example.test"
	h.svc.mu.Unlock()
	completeBefore := h.svc.completionCalls.Load()

	_, err := RefreshAgentRegistration(context.Background(), "lv_account", h.store, h.registerOpts()...)
	var pending *OTPPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("first account refresh: want OTPPendingError, got %v", err)
	}
	if h.nhp.otpCount() != 1 || h.nhp.regCount() != 1 { // initial bootstrap REG only
		t.Fatalf("first account refresh side effects: otp=%d regs=%d", h.nhp.otpCount(), h.nhp.regCount())
	}

	h.nhp.mu.Lock()
	h.nhp.expectCredential = "424242"
	h.nhp.mu.Unlock()
	state, err := RefreshAgentRegistration(context.Background(), "lv_account", h.store, h.registerOpts(WithOTP("424242"))...)
	if err != nil {
		t.Fatalf("account refresh resume: %v", err)
	}
	if state.DeviceAPIKey != "lv_device_secret" {
		t.Fatal("account binding refresh replaced device credential")
	}
	if h.svc.completionCalls.Load() != completeBefore {
		t.Fatal("account binding refresh called completion")
	}
}

func TestCredentialPersistenceFailureAndExplicitSameIDRecovery(t *testing.T) {
	h := newRegisterHarness(t)
	persistFailure := errors.New("injected final save failure")
	failing := &failingSaveStore{
		inner: h.store,
		failWhen: func(state *AgentState) bool {
			return state.RegisteredAt != nil && state.DeviceAPIKey != ""
		},
		failErr:   persistFailure,
		failsLeft: 1,
	}
	h.store = failing
	h.armDevicePubOnInfo()

	_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistErr *CredentialPersistenceError
	if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) || !errors.Is(err, persistFailure) {
		t.Fatalf("want typed credential persistence error, got %v", err)
	}
	if h.svc.completionCalls.Load() != 1 {
		t.Fatalf("completion calls after failed final save = %d, want 1", h.svc.completionCalls.Load())
	}
	preRecovery := h.loadState(t)
	if preRecovery.AgentID != persistErr.DeviceID || preRecovery.DeviceAPIKey != "" {
		t.Fatalf("pre-recovery state/device mismatch: state=%#v err=%#v", preRecovery, persistErr)
	}

	// A normal restart gets the server's first-issue-only denial and maps it to
	// the same recovery class; it does not overwrite local state or mint again.
	h.svc.mu.Lock()
	h.svc.completionStatus = http.StatusConflict
	h.svc.completionCode = "device_key_already_issued"
	h.svc.mu.Unlock()
	_, err = RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var recoveryErr *CredentialRecoveryRequiredError
	if !errors.As(err, &recoveryErr) || recoveryErr.DeviceID != preRecovery.AgentID || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("restart recovery error = %v", err)
	}
	unchanged := h.loadState(t)
	if unchanged.DeviceAPIKey != "" || unchanged.AgentID != preRecovery.AgentID {
		t.Fatalf("ordinary restart mutated recovery state: %#v", unchanged)
	}
	completeBeforeRevoke := h.svc.completionCalls.Load()
	_, err = RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.As(err, &recoveryErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("explicit recovery before owner revoke = %v", err)
	}
	if h.svc.completionCalls.Load() != completeBeforeRevoke+1 {
		t.Fatalf("pre-revoke recovery completion calls = %d, want exactly one", h.svc.completionCalls.Load()-completeBeforeRevoke)
	}

	// Model owner revoke clearing the issued sentinel, then recover the exact
	// same id/keypair. Recovery makes one completion request and durably reopens.
	h.svc.mu.Lock()
	h.svc.completionStatus = 0
	h.svc.completionCode = ""
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	completeBefore := h.svc.completionCalls.Load()
	client, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts(
		WithDeviceID(preRecovery.AgentID),
	)...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	if client == nil {
		t.Fatal("RecoverAgentCredential returned nil Client")
	}
	if h.svc.completionCalls.Load() != completeBefore+1 {
		t.Fatalf("recovery completion calls = %d, want exactly one", h.svc.completionCalls.Load()-completeBefore)
	}
	recovered := h.loadState(t)
	if recovered.AgentID != preRecovery.AgentID || recovered.PrivateKeyB64 != preRecovery.PrivateKeyB64 || recovered.DeviceAPIKey != "lv_device_recovered" {
		t.Fatalf("same-id recovery did not preserve identity/replace credential: %#v", recovered)
	}
	if _, err := OpenRegisteredAgent(context.Background(), h.store); err != nil {
		t.Fatalf("durable reopen after recovery: %v", err)
	}
}

func TestRegisterAgent_PostCompletionContractFailuresRequireRecoveryWithoutRetry(t *testing.T) {
	rotated := newFakeNHPServer(t)
	cases := []struct {
		name string
		edit func(*fakeService)
	}{
		{name: "rotated peer", edit: func(service *fakeService) {
			service.completionPeer = &NHPServerPeerInfo{
				PublicKeyB64: rotated.serverPubB64(),
				Host:         "rotated.example.test",
				Port:         62206,
			}
		}},
		{name: "invalid peer", edit: func(service *fakeService) {
			service.completionPeer = &NHPServerPeerInfo{
				PublicKeyB64: service.nhp.serverPubB64(),
				Host:         "nhp.example.test",
				Port:         0,
			}
		}},
		{name: "agent id mismatch", edit: func(service *fakeService) {
			service.agentID = "agent-different"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			tc.edit(h.svc)
			h.armDevicePubOnInfo()

			_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			var persistErr *CredentialPersistenceError
			if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("want post-completion CredentialPersistenceError, got %v", err)
			}
			if strings.Contains(err.Error(), "lv_device_secret") {
				t.Fatalf("error exposed completion credential: %v", err)
			}
			if h.svc.completionCalls.Load() != 1 {
				t.Fatalf("completion calls = %d, want exactly 1", h.svc.completionCalls.Load())
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("invalid completion response was persisted: %#v", state)
			}
			if state.NHPPeer == nil || state.NHPPeer.PublicKeyB64 != h.nhp.serverPubB64() {
				t.Fatalf("authenticated RAK peer was not preserved: %#v", state.NHPPeer)
			}
		})
	}
}

func TestRecoverAgentCredential_CompletionPeerRotationFailsClosed(t *testing.T) {
	h := registeredHarness(t)
	before := h.loadState(t)
	rotated := newFakeNHPServer(t)
	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_rotated"
	h.svc.completionPeer = &NHPServerPeerInfo{
		PublicKeyB64: rotated.serverPubB64(),
		Host:         "rotated.example.test",
		Port:         62206,
	}
	h.svc.mu.Unlock()

	completeBefore := h.svc.completionCalls.Load()
	_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	var persistErr *CredentialPersistenceError
	if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("want recovery-required peer mismatch, got %v", err)
	}
	if h.svc.completionCalls.Load() != completeBefore+1 {
		t.Fatalf("recovery completion calls = %d, want exactly 1", h.svc.completionCalls.Load()-completeBefore)
	}
	after := h.loadState(t)
	if after.DeviceAPIKey != before.DeviceAPIKey || after.NHPPeer.PublicKeyB64 != before.NHPPeer.PublicKeyB64 {
		t.Fatalf("failed recovery replaced durable credential/peer: before=%#v after=%#v", before, after)
	}
}

func TestPersistCompletion_PeerMismatchDropsPlaintextReference(t *testing.T) {
	state, err := newAgentState()
	if err != nil {
		t.Fatalf("newAgentState: %v", err)
	}
	state.AgentID = "agent-original"
	peerA := newFakeNHPServer(t)
	peerB := newFakeNHPServer(t)
	state.NHPPeer = &NHPServerPeerInfo{
		PublicKeyB64: peerA.serverPubB64(),
		Host:         "peer-a.example.test",
		Port:         62206,
	}
	now := time.Now().UTC()
	comp := &completionResponse{
		AgentID:      state.AgentID,
		RegisteredAt: &now,
		NHPServerPeer: NHPServerPeerInfo{
			PublicKeyB64: peerB.serverPubB64(),
			Host:         "peer-b.example.test",
			Port:         62206,
		},
		DeviceAPIKey: "lv_plaintext_must_drop",
	}
	cfg, err := newRegisterConfig(nil)
	if err != nil {
		t.Fatalf("newRegisterConfig: %v", err)
	}
	_, err = cfg.persistCompletion(context.Background(), memoryAgentStateStore{}, state, comp)
	if !errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("persistCompletion: want recovery-required, got %v", err)
	}
	if comp.DeviceAPIKey != "" {
		t.Fatal("completion response retained plaintext credential after rejection")
	}
	if state.DeviceAPIKey != "" || state.NHPPeer.PublicKeyB64 != peerA.serverPubB64() {
		t.Fatalf("rejected completion mutated state: %#v", state)
	}
}

func TestRegisterAgent_CompletionOutcomeUnknownRequiresRecoveryWithoutRetry(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*registerHarness, *atomic.Int32) RegisterOption
	}{
		{name: "malformed successful response", configure: func(h *registerHarness, attempts *atomic.Int32) RegisterOption {
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, `{"data":`)
					return
				}
				inner.ServeHTTP(w, r)
			}))
			return nil
		}},
		{name: "server error", configure: func(h *registerHarness, attempts *atomic.Int32) RegisterOption {
			h.handlerMu.Lock()
			inner := h.handler
			h.handlerMu.Unlock()
			h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = fmt.Fprint(w, `{"error":{"code":"upstream_unavailable","detail":"unknown outcome"}}`)
					return
				}
				inner.ServeHTTP(w, r)
			}))
			return nil
		}},
		{name: "transport failure", configure: func(_ *registerHarness, attempts *atomic.Int32) RegisterOption {
			client := doerFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost && req.URL.Path == "/v1/agent/registration/complete" {
					attempts.Add(1)
					return nil, errors.New("injected completion transport loss")
				}
				return http.DefaultClient.Do(req)
			})
			return WithRegisterHTTPClient(client)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			h.armDevicePubOnInfo()
			var attempts atomic.Int32
			opt := tc.configure(h, &attempts)
			opts := h.registerOpts()
			if opt != nil {
				opts = append(opts, opt)
			}

			_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, opts...)
			var persistErr *CredentialPersistenceError
			if !errors.As(err, &persistErr) || !errors.Is(err, ErrCredentialRecoveryRequired) {
				t.Fatalf("want ambiguous completion persistence error, got %v", err)
			}
			if attempts.Load() != 1 {
				t.Fatalf("completion attempts = %d, want exactly 1", attempts.Load())
			}
			if h.nhp.regCount() != 1 {
				t.Fatalf("REG count = %d, want 1", h.nhp.regCount())
			}
			state := h.loadState(t)
			if state.RegisteredAt != nil || state.DeviceAPIKey != "" {
				t.Fatalf("ambiguous completion persisted credential: %#v", state)
			}
		})
	}
}

func TestRegisterAgent_CompletionPreAuthUnavailableRemainsRetryable(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	h.handlerMu.Lock()
	inner := h.handler
	h.handlerMu.Unlock()
	var attempts atomic.Int32
	h.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/agent/registration/complete" {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":{"code":"service_unavailable","detail":"pre-auth limiter unavailable"}}`)
			return
		}
		inner.ServeHTTP(w, r)
	}))

	_, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
	if !errors.Is(err, ErrRegistrationRetryLater) {
		t.Fatalf("want retry-later pre-auth failure, got %v", err)
	}
	if errors.Is(err, ErrCredentialRecoveryRequired) {
		t.Fatalf("pre-auth service_unavailable must not be ambiguous mint: %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("completion attempts = %d, want 1", attempts.Load())
	}
}

func TestAgentLifecycle_RegistrationAndResourceOriginsRemainIndependent(t *testing.T) {
	h := newRegisterHarness(t)
	h.svc.expectedBearer = "lv_enroll"
	h.armDevicePubOnInfo()

	var resourceCalls atomic.Int32
	var credentialMu sync.Mutex
	wantCredential := "lv_device_secret"
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resources" {
			t.Errorf("resource origin got unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		credentialMu.Lock()
		want := wantCredential
		credentialMu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+want {
			t.Errorf("resource Authorization = %q, want Bearer %q", got, want)
		}
		resourceCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"resource_id":"r_lifecycle123","target_url":"https://internal.example.test","status":"active"}}`)
	}))
	t.Cleanup(resourceServer.Close)

	registerOpts := h.registerOpts(WithAgentClientBaseURL(resourceServer.URL))
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, registerOpts...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	protectOnce(t, client)

	reopened, err := OpenRegisteredAgent(context.Background(), h.store, WithBaseURL(resourceServer.URL))
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	protectOnce(t, reopened)

	completeBeforeRefresh := h.svc.completionCalls.Load()
	if _, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, registerOpts...); err != nil {
		t.Fatalf("RefreshAgentRegistration: %v", err)
	}
	if h.svc.completionCalls.Load() != completeBeforeRefresh {
		t.Fatal("refresh crossed into completion")
	}

	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	credentialMu.Lock()
	wantCredential = "lv_device_recovered"
	credentialMu.Unlock()
	recoveredClient, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, registerOpts...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	protectOnce(t, recoveredClient)

	if resourceCalls.Load() != 3 {
		t.Fatalf("resource calls = %d, want 3", resourceCalls.Load())
	}
	if h.svc.infoCalls.Load() != 3 {
		t.Fatalf("registration-info calls = %d, want 3 (initial, refresh, recovery)", h.svc.infoCalls.Load())
	}
}

func TestAgentLifecycle_RegistrationAndResourceTransportsRemainIndependent(t *testing.T) {
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()

	var resourceCredentialMu sync.Mutex
	resourceCredential := "lv_device_secret"
	resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceCredentialMu.Lock()
		want := resourceCredential
		resourceCredentialMu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+want {
			t.Errorf("resource Authorization = %q, want Bearer %q", got, want)
		}
		_, _ = fmt.Fprint(w, `{"data":{"resource_id":"r_transport123","target_url":"https://internal.example.test","status":"active"}}`)
	}))
	t.Cleanup(resourceServer.Close)

	apiHost := strings.TrimPrefix(h.apiSrv.URL, "http://")
	relayHost := strings.TrimPrefix(h.relaySrv.URL, "http://")
	resourceHost := strings.TrimPrefix(resourceServer.URL, "http://")
	var registrationCalls, registrationRefusals atomic.Int32
	registrationTransport := doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != apiHost && req.URL.Host != relayHost {
			registrationRefusals.Add(1)
			return nil, fmt.Errorf("registration transport refused host %q", req.URL.Host)
		}
		registrationCalls.Add(1)
		return http.DefaultClient.Do(req)
	})
	var resourceCalls, resourceRefusals atomic.Int32
	resourceTransport := doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != resourceHost {
			resourceRefusals.Add(1)
			return nil, fmt.Errorf("resource transport refused host %q", req.URL.Host)
		}
		resourceCalls.Add(1)
		return http.DefaultClient.Do(req)
	})

	opts := h.registerOpts(
		WithRegisterHTTPClient(registrationTransport),
		WithAgentClientBaseURL(resourceServer.URL),
		WithAgentClientHTTPClient(resourceTransport),
	)
	client, err := RegisterAgent(context.Background(), "lv_enroll", h.store, opts...)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	protectOnce(t, client)

	h.svc.mu.Lock()
	h.svc.deviceAPIKey = "lv_device_recovered"
	h.svc.mu.Unlock()
	resourceCredentialMu.Lock()
	resourceCredential = "lv_device_recovered"
	resourceCredentialMu.Unlock()
	recovered, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, opts...)
	if err != nil {
		t.Fatalf("RecoverAgentCredential: %v", err)
	}
	protectOnce(t, recovered)

	opened, err := OpenRegisteredAgent(context.Background(), h.store,
		WithBaseURL(resourceServer.URL),
		WithHTTPClient(resourceTransport),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgent: %v", err)
	}
	protectOnce(t, opened)

	if registrationCalls.Load() < 6 { // two each: info, relay REG, completion
		t.Fatalf("registration transport calls = %d, want at least 6", registrationCalls.Load())
	}
	if resourceCalls.Load() != 3 {
		t.Fatalf("resource transport calls = %d, want 3", resourceCalls.Load())
	}
	if registrationRefusals.Load() != 0 || resourceRefusals.Load() != 0 {
		t.Fatalf("transport crossed origins: registration refusals=%d resource refusals=%d", registrationRefusals.Load(), resourceRefusals.Load())
	}
}

func TestAgentLifecycleMutationsParticipateInSharedSetupLock(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		h := registeredHarness(t)
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
		if _, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
			t.Fatalf("RefreshAgentRegistration: %v", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("refresh setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
	})

	t.Run("recover", func(t *testing.T) {
		h := registeredHarness(t)
		h.svc.mu.Lock()
		h.svc.deviceAPIKey = "lv_device_recovered"
		h.svc.mu.Unlock()
		var acquired, released atomic.Int32
		h.store = instrumentFileStoreLock(t, h.store, &acquired, &released)
		if _, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
			t.Fatalf("RecoverAgentCredential: %v", err)
		}
		if acquired.Load() != 1 || released.Load() != 1 {
			t.Fatalf("recovery setup lock acquire/release = %d/%d, want 1/1", acquired.Load(), released.Load())
		}
	})

	for _, tc := range []struct {
		name string
		run  func(*registerHarness) error
	}{
		{name: "refresh acquisition failure", run: func(h *registerHarness) error {
			_, err := RefreshAgentRegistration(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			return err
		}},
		{name: "recovery acquisition failure", run: func(h *registerHarness) error {
			_, err := RecoverAgentCredential(context.Background(), "lv_enroll", h.store, h.registerOpts()...)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := registeredHarness(t)
			fileStore, ok := h.store.(fileAgentStateStore)
			if !ok {
				t.Fatalf("store type = %T, want fileAgentStateStore", h.store)
			}
			lockFailure := errors.New("injected lifecycle lock failure")
			fileStore.lockFile = func(context.Context, string) (setupLock, error) {
				return nil, lockFailure
			}
			h.store = fileStore
			infoBefore := h.svc.infoCalls.Load()
			err := tc.run(h)
			if !errors.Is(err, ErrAgentSetupLock) || !errors.Is(err, lockFailure) {
				t.Fatalf("lock failure = %v, want ErrAgentSetupLock and injected cause", err)
			}
			if h.svc.infoCalls.Load() != infoBefore {
				t.Fatal("lifecycle mutation performed network I/O after setup-lock failure")
			}
		})
	}
}

type trackingSetupLock struct {
	released *atomic.Int32
}

func (l *trackingSetupLock) Close() error {
	l.released.Add(1)
	return nil
}

func instrumentFileStoreLock(t *testing.T, store AgentStateStore, acquired, released *atomic.Int32) AgentStateStore {
	t.Helper()
	fileStore, ok := store.(fileAgentStateStore)
	if !ok {
		t.Fatalf("store type = %T, want fileAgentStateStore", store)
	}
	wantPath := fileStore.setupLockPath()
	fileStore.lockFile = func(_ context.Context, path string) (setupLock, error) {
		if path != wantPath {
			t.Errorf("setup lock path = %q, want %q", path, wantPath)
		}
		acquired.Add(1)
		return &trackingSetupLock{released: released}, nil
	}
	return fileStore
}

func registeredHarness(t *testing.T) *registerHarness {
	t.Helper()
	h := newRegisterHarness(t)
	h.armDevicePubOnInfo()
	if _, err := RegisterAgent(context.Background(), "lv_enroll", h.store, h.registerOpts()...); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	return h
}

func protectOnce(t *testing.T, client *Client) {
	t.Helper()
	resource, err := client.ProtectURL(context.Background(), "https://internal.example.test")
	if err != nil {
		t.Fatalf("ProtectURL: %v", err)
	}
	if !strings.HasPrefix(resource.ID, "r_") {
		t.Fatalf("resource ID = %q", resource.ID)
	}
}
