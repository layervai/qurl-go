package qurl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// AnonymousEnrollmentCredential selects device-owned enrollment. The returned
// value is public, not a bearer secret: the authority requires the matching
// authenticated Noise peer before it can register the device. The lv_live_
// envelope is required by the existing NHP credential parser; it does not
// confer bearer authority. Continue to redact all lv_live_ values in logs.
func AnonymousEnrollmentCredential(ctx context.Context, request AgentEnrollmentCredentialRequest) (string, error) {
	if err := validateContext(ctx, ErrInvalidRegisterConfig); err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(request.PublicKeyB64)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != request.PublicKeyB64 {
		return "", fmt.Errorf("%w: anonymous enrollment requires a canonical 32-byte device public key", ErrInvalidRegisterConfig)
	}
	if err := validatePersistedNativeAgentID(request.AgentID); err != nil {
		return "", fmt.Errorf("%w: anonymous enrollment agent ID: %w", ErrInvalidRegisterConfig, err)
	}
	digest := sha256.Sum256([]byte("qurl-anonymous-enrollment-v1\x00" + request.PublicKeyB64 + "\x00" + request.AgentID))
	return "lv_live_" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
