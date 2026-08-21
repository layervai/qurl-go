package nativeudp_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/layervai/qurl-go/qurl"
)

const (
	otpE2ECanaryCommitmentPathEnv = "QURL_OTP_E2E_CANARY_COMMITMENT_PATH"
	otpE2EBindingCommitmentDomain = "layerv:qurl-go:otp-schema-v2-canary:binding:v1"
)

// otpE2ECanaryCommitment is the only canary evidence written to the hosted
// runner. The linked digest lets the protected server-side verifier correlate
// one registration, claim, public key, and device credential without
// publishing any of their raw identifiers.
type otpE2ECanaryCommitment struct {
	SchemaVersion    int    `json:"schema_version"`
	BindingSHA256    string `json:"binding_sha256"`
	GitHubRunID      uint64 `json:"github_run_id"`
	GitHubRunAttempt uint64 `json:"github_run_attempt"`
}

func parseCanonicalPositiveDecimal(name, raw string) (uint64, error) {
	if raw == "" || raw[0] == '0' {
		return 0, fmt.Errorf("%s must be a canonical positive decimal", name)
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("%s must be a canonical positive decimal", name)
	}
	return value, nil
}

func writeLengthFrame(digest hash.Hash, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("binding commitment field is not valid UTF-8")
	}
	if uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("binding commitment field exceeds uint32 framing")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	if _, err := digest.Write(length[:]); err != nil {
		return err
	}
	_, err := io.WriteString(digest, value)
	return err
}

func otpE2EBindingCommitment(binding *qurl.AgentRuntimeBinding) (string, error) {
	if binding == nil || binding.AgentID == "" || binding.PublicKeyB64 == "" || binding.DeviceAPIKeyID == "" {
		return "", errors.New("OTP canary commitment requires a complete runtime binding")
	}
	for name, value := range map[string]string{
		"agent id": binding.AgentID, "public key": binding.PublicKeyB64, "device API key id": binding.DeviceAPIKeyID,
	} {
		if value != strings.TrimSpace(value) || !utf8.ValidString(value) {
			return "", fmt.Errorf("OTP canary %s is not canonical UTF-8", name)
		}
	}
	decodedPublicKey, err := base64.StdEncoding.Strict().DecodeString(binding.PublicKeyB64)
	if err != nil || len(decodedPublicKey) != 32 || base64.StdEncoding.EncodeToString(decodedPublicKey) != binding.PublicKeyB64 {
		return "", errors.New("OTP canary public key is not canonical padded standard-base64 X25519")
	}

	digest := sha256.New()
	_, _ = io.WriteString(digest, otpE2EBindingCommitmentDomain)
	_, _ = digest.Write([]byte{0})
	for _, value := range []string{binding.AgentID, binding.PublicKeyB64, binding.DeviceAPIKeyID} {
		if err := writeLengthFrame(digest, value); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeOTPE2ECanaryCommitment(path string, binding *qurl.AgentRuntimeBinding, runIDRaw, runAttemptRaw string) (resultErr error) {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("OTP canary commitment path must be a clean absolute path")
	}
	bindingSHA256, err := otpE2EBindingCommitment(binding)
	if err != nil {
		return err
	}
	runID, err := parseCanonicalPositiveDecimal("GITHUB_RUN_ID", runIDRaw)
	if err != nil {
		return err
	}
	runAttempt, err := parseCanonicalPositiveDecimal("GITHUB_RUN_ATTEMPT", runAttemptRaw)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create OTP canary commitment exclusively: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if resultErr != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove incomplete OTP canary commitment: %w", removeErr))
			}
		}
	}()

	// OpenFile is already restrictive, but chmod makes the exact post-create
	// mode independent of a caller's umask before evidence is written.
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict OTP canary commitment: %w", err)
	}
	receipt := otpE2ECanaryCommitment{
		SchemaVersion: 1, BindingSHA256: bindingSHA256,
		GitHubRunID: runID, GitHubRunAttempt: runAttempt,
	}
	if err := json.NewEncoder(file).Encode(receipt); err != nil {
		return fmt.Errorf("encode OTP canary commitment: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync OTP canary commitment: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close OTP canary commitment: %w", err)
	}
	closed = true
	return nil
}

func TestOTPE2EBindingCommitmentKnownAnswer(t *testing.T) {
	for name, test := range map[string]struct {
		binding *qurl.AgentRuntimeBinding
		want    string
	}{
		"shared service vector": {
			binding: &qurl.AgentRuntimeBinding{
				AgentID:        "agent-canary-01",
				PublicKeyB64:   "AjPwBu9L7RROoKW7RscGfHwqzsX4zIEfPfWf3NWsdhQ=",
				DeviceAPIKeyID: "key_Durable12345",
			},
			want: "88e8071c4c5e1e5222dda436d6f6f93f6654120d68190206bad3fce1a63189bc",
		},
		"independent framing vector": {
			binding: &qurl.AgentRuntimeBinding{
				AgentID:        "agent-canary-123",
				PublicKeyB64:   "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
				DeviceAPIKeyID: "key_AbCdEf123456",
			},
			want: "4bfd4703c58df7e2cd3db3b28612670a3c2d81c4f94bee8cb1500c76f33218c6",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := otpE2EBindingCommitment(test.binding)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("binding commitment = %s, want frozen KAT %s", got, test.want)
			}
		})
	}
}

func TestWriteOTPE2ECanaryCommitment(t *testing.T) {
	binding := &qurl.AgentRuntimeBinding{
		AgentID:        "agent-canary-01",
		PublicKeyB64:   "AjPwBu9L7RROoKW7RscGfHwqzsX4zIEfPfWf3NWsdhQ=",
		DeviceAPIKeyID: "key_Durable12345",
	}

	t.Run("exact non-secret receipt", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary-binding-commitment.json")
		if err := writeOTPE2ECanaryCommitment(path, binding, "1234567890", "2"); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("commitment mode = %s, want regular file", info.Mode())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("commitment mode = %s, want 0600", info.Mode())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "{\"schema_version\":1,\"binding_sha256\":\"88e8071c4c5e1e5222dda436d6f6f93f6654120d68190206bad3fce1a63189bc\",\"github_run_id\":1234567890,\"github_run_attempt\":2}\n"
		if string(raw) != want {
			t.Fatalf("commitment receipt = %q, want exact canonical schema", raw)
		}
		for _, forbidden := range []string{binding.AgentID, binding.PublicKeyB64, binding.DeviceAPIKeyID} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("commitment receipt exposed a raw binding field")
			}
		}
	})

	for _, path := range []string{"", "relative.json", filepath.Join(t.TempDir(), "receipt.json") + " "} {
		if err := writeOTPE2ECanaryCommitment(path, binding, "1", "1"); err == nil {
			t.Errorf("unsafe path %q was accepted", path)
		}
	}

	for name, value := range map[string]string{
		"empty": "", "zero": "0", "leading zero": "01", "negative": "-1", "space": "1 ", "overflow": "18446744073709551616",
	} {
		t.Run("invalid run id "+name, func(t *testing.T) {
			if err := writeOTPE2ECanaryCommitment(filepath.Join(t.TempDir(), "receipt.json"), binding, value, "1"); err == nil {
				t.Fatalf("run id %q was accepted", value)
			}
		})
		t.Run("invalid run attempt "+name, func(t *testing.T) {
			if err := writeOTPE2ECanaryCommitment(filepath.Join(t.TempDir(), "receipt.json"), binding, "1", value); err == nil {
				t.Fatalf("run attempt %q was accepted", value)
			}
		})
	}

	t.Run("refuses overwrite and symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "existing.json")
		if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeOTPE2ECanaryCommitment(target, binding, "1", "1"); err == nil {
			t.Fatal("existing commitment path was overwritten")
		}
		link := filepath.Join(dir, "symlink.json")
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation is unavailable on this Windows runner: %v", err)
			}
			t.Fatal(err)
		}
		if err := writeOTPE2ECanaryCommitment(link, binding, "1", "1"); err == nil {
			t.Fatal("symlink commitment path was followed")
		}
		if raw, err := os.ReadFile(target); err != nil || string(raw) != "preserve" {
			t.Fatalf("existing target after refusal = %q, %v", raw, err)
		}
	})

	if err := writeOTPE2ECanaryCommitment(filepath.Join(t.TempDir(), "nil.json"), nil, "1", "1"); err == nil {
		t.Fatal("nil binding was accepted")
	}
	for name, mutate := range map[string]func(*qurl.AgentRuntimeBinding){
		"agent id":          func(got *qurl.AgentRuntimeBinding) { got.AgentID = "" },
		"public key":        func(got *qurl.AgentRuntimeBinding) { got.PublicKeyB64 = "" },
		"device API key id": func(got *qurl.AgentRuntimeBinding) { got.DeviceAPIKeyID = "" },
		"invalid public key": func(got *qurl.AgentRuntimeBinding) {
			got.PublicKeyB64 = "not-base64"
		},
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			incomplete := *binding
			mutate(&incomplete)
			if err := writeOTPE2ECanaryCommitment(filepath.Join(t.TempDir(), "invalid.json"), &incomplete, "1", "1"); err == nil {
				t.Fatalf("binding with invalid %s was accepted", name)
			}
		})
	}
}
