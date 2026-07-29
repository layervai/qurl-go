package nativeudp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/layervai/qurl-go/qurl"
)

const (
	sandboxKMSKeyIDEnv = "QURL_GO_SANDBOX_KMS_KEY_ID"
	sandboxKMSKeyID    = "alias/layerv-nhp-sandbox-udp-proof-agent-seal"
)

var sandboxKMSKeyARNPattern = regexp.MustCompile(`^arn:aws:kms:us-east-2:767397897469:key/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

type sandboxKMSWrapperFactoryFunc func(context.Context, string) (qurl.AgentStateKeyWrapper, error)

var sandboxKMSWrapperFactory sandboxKMSWrapperFactoryFunc = func(context.Context, string) (qurl.AgentStateKeyWrapper, error) {
	return nil, errors.New("AWS KMS proof adapter is not compiled; run with -tags=qurl_sandbox_kms")
}

func openSandboxKMSSealedStore(ctx context.Context, cfg sandboxConfig) (*qurl.SealedFileAgentStateStore, error) {
	wrapper, err := sandboxKMSWrapperFactory(ctx, cfg.kmsKeyID)
	if err != nil {
		return nil, fmt.Errorf("construct sandbox KMS wrapper: %w", err)
	}
	store, err := qurl.NewSealedFileAgentState(
		cfg.statePath,
		"aws-kms",
		wrapper,
		qurl.WithExpectedSealedAgentID(cfg.agentID),
	)
	if err != nil {
		return nil, fmt.Errorf("construct sandbox sealed state: %w", err)
	}
	return store, nil
}

type sandboxSealedEnvelope struct {
	Version    int    `json:"version"`
	Purpose    string `json:"purpose"`
	AgentID    string `json:"agent_id"`
	ProviderID string `json:"provider_id"`
	WrappedKey struct {
		Version    int    `json:"version"`
		Ciphertext []byte `json:"ciphertext"`
		Metadata   struct {
			KeyID string `json:"key_id"`
		} `json:"metadata"`
	} `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func proveSandboxKMSColdState(ctx context.Context, t testFataler, cfg sandboxConfig, store qurl.AgentStateStore) string {
	t.Helper()
	state, err := store.LoadAgentState(ctx)
	if err != nil {
		t.Fatalf("load KMS-sealed state: %v", err)
	}
	if state.PrivateKeyB64 == "" || state.DeviceAPIKey == "" {
		t.Fatal("registered state is missing private credential material")
	}
	raw, err := os.ReadFile(cfg.statePath)
	if err != nil {
		t.Fatalf("read KMS-sealed state: %v", err)
	}
	for name, secret := range map[string]string{
		"device private key":    state.PrivateKeyB64,
		"device API key":        state.DeviceAPIKey,
		"enrollment credential": cfg.enrollment,
	} {
		if secret == "" {
			t.Fatalf("%s proof value is empty", name)
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("KMS-sealed state durably persisted the plaintext %s", name)
		}
	}
	var envelope sandboxSealedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatal("KMS-sealed state is not one strict envelope")
	}
	if envelope.Version != 1 || envelope.Purpose != "qurl-go/agent-state" ||
		envelope.AgentID != cfg.agentID || envelope.ProviderID != "aws-kms" ||
		envelope.WrappedKey.Version != 1 || len(envelope.WrappedKey.Ciphertext) == 0 ||
		len(envelope.Nonce) != 12 || len(envelope.Ciphertext) == 0 ||
		!isExactSandboxKMSKeyARN(envelope.WrappedKey.Metadata.KeyID) {
		t.Fatal("KMS-sealed state is missing its exact authenticated envelope or key binding")
	}
	info, err := os.Lstat(cfg.statePath)
	if err != nil {
		t.Fatalf("inspect KMS-sealed state: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("KMS-sealed state mode = %v, want regular non-symlink 0600", info.Mode())
	}
	return envelope.WrappedKey.Metadata.KeyID
}

func isExactSandboxKMSKeyARN(value string) bool {
	return sandboxKMSKeyARNPattern.MatchString(value)
}

func TestExactSandboxKMSKeyARN(t *testing.T) {
	for name, testCase := range map[string]struct {
		value string
		want  bool
	}{
		"uuid": {
			value: "arn:aws:kms:us-east-2:767397897469:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			want:  true,
		},
		"multi-region": {
			value: "arn:aws:kms:us-east-2:767397897469:key/mrk-0123456789abcdef0123456789abcdef",
			want:  true,
		},
		"arbitrary key resource": {
			value: "arn:aws:kms:us-east-2:767397897469:key/not-a-real-key-id",
		},
		"wrong account": {
			value: "arn:aws:kms:us-east-2:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isExactSandboxKMSKeyARN(testCase.value); got != testCase.want {
				t.Fatalf("isExactSandboxKMSKeyARN(%q) = %t, want %t", testCase.value, got, testCase.want)
			}
		})
	}
}

func removeSandboxSetupCredential(t testFataler, cfg *sandboxConfig) {
	t.Helper()
	if err := os.Unsetenv(enrollmentEnv); err != nil {
		t.Fatalf("remove enrollment credential environment source: %v", err)
	}
	cfg.enrollment = ""
	for _, name := range []string{
		enrollmentEnv,
		"QURL_GO_SANDBOX_RECOVERY_CREDENTIAL",
		"LAYERV_AGENT_RECOVERY_CREDENTIAL",
	} {
		if value, present := os.LookupEnv(name); present && value != "" {
			t.Fatalf("setup or recovery credential source %s remains present", name)
		}
	}
}

func proveSandboxKMSCredentiallessWarmRestart(
	ctx context.Context,
	t testFataler,
	cfg sandboxConfig,
	store qurl.AgentStateStore,
	httpTrap *lifecycleHTTPTrap,
) {
	t.Helper()
	for _, name := range []string{
		enrollmentEnv,
		"QURL_GO_SANDBOX_RECOVERY_CREDENTIAL",
		"LAYERV_AGENT_RECOVERY_CREDENTIAL",
	} {
		if value, present := os.LookupEnv(name); present && value != "" {
			t.Fatalf("credentialless restart retained credential source %s", name)
		}
	}
	client, binding, err := qurl.OpenRegisteredAgentRuntime(ctx, store,
		qurl.WithAgentClientBaseURL("http://127.0.0.1:1"),
		qurl.WithAgentClientHTTPClient(httpTrap),
	)
	if err != nil {
		t.Fatalf("OpenRegisteredAgentRuntime from KMS-sealed state: %v", err)
	}
	if client == nil || binding == nil {
		t.Fatal("KMS-sealed warm open returned a nil client or binding")
	}
	defer binding.Destroy()
	privateKey := binding.TakeDeviceStaticPrivateKey()
	if len(privateKey) != x25519PublicKeyLength {
		clear(privateKey)
		t.Fatalf("KMS-sealed warm private key length = %d, want %d", len(privateKey), x25519PublicKeyLength)
	}
	defer clear(privateKey)
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		t.Fatalf("NewCycleRunID: %v", err)
	}
	result, err := qurl.KnockRegisteredAgent(
		ctx,
		binding,
		privateKey,
		cfg.knockResourceID,
		qurl.NativeKnockOptions{RunID: runID},
	)
	if err != nil {
		t.Fatalf("credentialless KMS-sealed knock: %v", err)
	}
	if result == nil || result.ACToken == "" || result.ResourceHost == "" {
		t.Fatal("credentialless KMS-sealed knock returned incomplete authenticated admission")
	}
}

// testFataler is the small testing surface used by the proof helpers.
type testFataler interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func cleanupSandboxSealedProofFiles(cfg sandboxConfig) {
	for _, path := range [...]string{
		cfg.statePath + ".lock",
		cfg.statePath,
		filepath.Join(filepath.Dir(cfg.statePath), ".qurl-sealed-agent-state-*"),
	} {
		if strings.Contains(path, "*") {
			matches, _ := filepath.Glob(path)
			for _, match := range matches {
				_ = os.Remove(match)
			}
			continue
		}
		_ = os.Remove(path)
	}
}
