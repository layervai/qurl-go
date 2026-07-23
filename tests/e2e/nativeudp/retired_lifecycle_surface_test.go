package nativeudp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

const reviewedRetiredLifecycleSurfaceSHA256 = "3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c"

type retiredLifecycleSurface struct {
	SchemaVersion                       int                     `json:"schema_version"`
	Gate                                string                  `json:"gate"`
	PublicHTTPOperations                []retiredHTTPOperation  `json:"public_http_operations"`
	InternalHTTPOperations              []retiredHTTPOperation  `json:"internal_http_operations"`
	RetiredRelaySDKAliases              []retiredRelayAlias     `json:"retired_relay_sdk_aliases"`
	RelayMessageTypeAliases             []relayMessageTypeAlias `json:"relay_message_type_aliases"`
	RetainedRelayHTTPOperations         []retiredHTTPOperation  `json:"retained_relay_http_operations"`
	RelayForbiddenLifecycleMessageTypes []string                `json:"relay_forbidden_lifecycle_message_types"`
	RelayPostRemovalInjectionTypes      []string                `json:"relay_post_removal_injection_message_types"`
}

type retiredHTTPOperation struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id"`
}

type retiredRelayAlias struct {
	Package              string   `json:"package"`
	Symbol               string   `json:"symbol"`
	RequestMessageTypes  []string `json:"request_message_types"`
	ResponseMessageTypes []string `json:"response_message_types"`
}

type relayMessageTypeAlias struct {
	Alias       string `json:"alias"`
	MessageType string `json:"message_type"`
	WireValue   int    `json:"wire_value"`
}

func TestRetiredLifecycleSurfaceContract(t *testing.T) {
	raw, err := os.ReadFile("retired_lifecycle_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRetiredLifecycleSurface(raw)
	if err != nil {
		t.Fatalf("decode retired lifecycle surface: %v", err)
	}
	want := retiredLifecycleSurface{
		SchemaVersion: 1,
		Gate:          "udp_lifecycle_retirement",
		PublicHTTPOperations: []retiredHTTPOperation{
			{Method: "POST", Path: "/v1/agent/bootstrap", OperationID: "postV1AgentBootstrap"},
			{Method: "GET", Path: "/v1/agent/registration-info", OperationID: "getV1AgentRegistrationInfo"},
			{Method: "POST", Path: "/v1/agent/registration/complete", OperationID: "postV1AgentRegistrationComplete"},
		},
		InternalHTTPOperations: []retiredHTTPOperation{
			{Method: "POST", Path: "/internal/v1/agent/otp", OperationID: "handlers.AgentOTPInternalHandler.IssueOTP"},
			{Method: "POST", Path: "/internal/v1/agent/register", OperationID: "handlers.AgentOTPInternalHandler.Register"},
		},
		RetiredRelaySDKAliases: []retiredRelayAlias{
			{Package: "relayknock", Symbol: "Exchange", RequestMessageTypes: []string{"NHP_REG"}, ResponseMessageTypes: []string{"NHP_RAK"}},
			{Package: "relayknock", Symbol: "Send", RequestMessageTypes: []string{"NHP_OTP"}, ResponseMessageTypes: []string{}},
		},
		RelayMessageTypeAliases: []relayMessageTypeAlias{
			{Alias: "relayknock.TypeListRequest", MessageType: "NHP_LST", WireValue: 5},
			{Alias: "relayknock.TypeListResult", MessageType: "NHP_LRT", WireValue: 6},
			{Alias: "relayknock.TypeOTP", MessageType: "NHP_OTP", WireValue: 12},
			{Alias: "relayknock.TypeRegister", MessageType: "NHP_REG", WireValue: 13},
			{Alias: "relayknock.TypeRegisterAck", MessageType: "NHP_RAK", WireValue: 14},
		},
		RetainedRelayHTTPOperations: []retiredHTTPOperation{
			{Method: "POST", Path: "/relay/{serverId}", OperationID: "relay.handleRelay"},
		},
		RelayForbiddenLifecycleMessageTypes: []string{"NHP_OTP", "NHP_REG", "NHP_RAK", "NHP_LST", "NHP_LRT"},
		RelayPostRemovalInjectionTypes:      []string{"NHP_OTP", "NHP_REG", "NHP_LST", "NHP_LRT"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retired lifecycle surface = %#v, want exact reviewed contract %#v", got, want)
	}

	digest, err := canonicalJSONSHA256(raw)
	if err != nil {
		t.Fatalf("hash retired lifecycle surface: %v", err)
	}
	if digest != reviewedRetiredLifecycleSurfaceSHA256 {
		t.Fatalf("retired lifecycle surface SHA-256 = %s, want reviewed literal %s", digest, reviewedRetiredLifecycleSurfaceSHA256)
	}
}

func decodeRetiredLifecycleSurface(raw []byte) (retiredLifecycleSurface, error) {
	return decodeStrictJSON[retiredLifecycleSurface](raw, "retired lifecycle surface")
}

func canonicalJSONSHA256(raw []byte) (string, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("JSON contains trailing input: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func TestDecodeRetiredLifecycleSurfaceRejectsAmbiguousJSON(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate key": `{"schema_version":1,"schema_version":1}`,
		"unknown key":   `{"unknown":true}`,
		"trailing JSON": `{}` + `{}`,
		"non-finite":    `{"schema_version":1e9999}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRetiredLifecycleSurface([]byte(raw)); err == nil {
				t.Fatal("decode accepted ambiguous retired lifecycle surface JSON")
			}
		})
	}
}
