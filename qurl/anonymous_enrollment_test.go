package qurl

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAnonymousEnrollmentBindsDurableIdentity(t *testing.T) {
	request := AgentEnrollmentCredentialRequest{AgentID: "anonymous-device", PublicKeyB64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))}
	credential, err := AnonymousEnrollmentCredential(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if credential != "lv_live_NEQgOQ806WZu0yxqK0jVSCmdwi4QyJb1w2hC38wJGao" {
		t.Fatalf("wire vector changed: %s", credential)
	}
	request.PendingActivationRecovery = true
	replay, err := AnonymousEnrollmentCredential(context.Background(), request)
	if err != nil || replay != credential {
		t.Fatalf("retry changed enrollment: %v", err)
	}
	request.AgentID = "another-device"
	other, err := AnonymousEnrollmentCredential(context.Background(), request)
	if err != nil || other == credential {
		t.Fatal("agent identity is not bound")
	}
	request.PublicKeyB64 = "invalid"
	if _, err := AnonymousEnrollmentCredential(context.Background(), request); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if !registeredAgentResourceRouteAllowed("POST", "/v1/account/link") || registeredAgentResourceRouteAllowed("GET", "/v1/account/link") || registeredAgentResourceRouteAllowed("POST", "/v1/account/owners") {
		t.Fatal("account route authority widened")
	}
}
