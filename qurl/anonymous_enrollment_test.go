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
	urlAlphabetRequest := request
	urlAlphabetRequest.AgentID = "anonymous-device-0"
	urlAlphabet, err := AnonymousEnrollmentCredential(context.Background(), urlAlphabetRequest)
	if err != nil || urlAlphabet != "lv_live_eppwweaMNn_pXSsO06rZ_bsd29TmtBlhjK-bDXSOEA4" {
		t.Fatalf("base64url vector changed: %v", err)
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
}

func TestAnonymousEnrollmentRejectsInvalidIdentity(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	for _, request := range []AgentEnrollmentCredentialRequest{
		{AgentID: "device", PublicKeyB64: validKey[:8] + "\n" + validKey[8:]},
		{AgentID: "device", PublicKeyB64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 31)))},
		{AgentID: "device", PublicKeyB64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 33)))},
		{PublicKeyB64: validKey},
		{AgentID: "invalid agent ID", PublicKeyB64: validKey},
	} {
		if _, err := AnonymousEnrollmentCredential(context.Background(), request); err == nil {
			t.Errorf("invalid identity accepted: %+v", request)
		}
	}
}
