package qurl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// AnonymousEnrollmentCredential selects device-owned enrollment. The returned
// value is public, not a bearer secret: the authority requires the matching
// authenticated Noise peer before it can register the device.
func AnonymousEnrollmentCredential(_ context.Context, request AgentEnrollmentCredentialRequest) (string, error) {
	key, err := base64.StdEncoding.DecodeString(request.PublicKeyB64)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != request.PublicKeyB64 || validatePersistedNativeAgentID(request.AgentID) != nil {
		return "", fmt.Errorf("%w: anonymous enrollment requires a durable device identity", ErrInvalidRegisterConfig)
	}
	digest := sha256.Sum256([]byte("qurl-anonymous-enrollment-v1\x00" + request.PublicKeyB64 + "\x00" + request.AgentID))
	return "lv_live_" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
