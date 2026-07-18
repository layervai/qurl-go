package qurl

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/layervai/qurl-go/internal/nhpcontract"
	"github.com/layervai/qurl-go/relayknock"
)

func TestMarshalNativeKnockApplicationBody(t *testing.T) {
	const runID = "0123456789abcdef"
	got, err := marshalNativeKnockApplicationBody("agent-01", "connector-01", NativeKnockOptions{RunID: runID})
	if err != nil {
		t.Fatalf("marshalNativeKnockApplicationBody: %v", err)
	}
	const want = `{"headerType":1,"usrId":"agent-01","devId":"agent-01","aspId":"agent","resId":"connector-01","runId":"0123456789abcdef"}`
	if string(got) != want {
		t.Fatalf("native knock body = %s, want %s", got, want)
	}
}

func TestMarshalNativeSessionApplicationBody_ConformanceSessionVectors(t *testing.T) {
	vectors, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-session vectors: %v", err)
	}
	for _, tc := range []struct {
		name       string
		headerType int
		packet     conformance.AgentSessionPacket
	}{
		{name: "knock", headerType: nhpKNKHeaderType, packet: vectors.OverloadReknock.KnockRequest},
		{name: "reknock", headerType: nhpRKNHeaderType, packet: vectors.OverloadReknock.ReknockRequest},
		{name: "exit", headerType: nhpEXTHeaderType, packet: vectors.CleanExit.Request},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields nativeAgentKnockBody
			if err := json.Unmarshal([]byte(tc.packet.BodyJSON), &fields); err != nil {
				t.Fatalf("decode conformance body: %v", err)
			}
			got, err := marshalNativeSessionApplicationBody(fields.DeviceID, fields.KnockResourceID, NativeKnockOptions{RunID: fields.RunID}, tc.headerType)
			if err != nil {
				t.Fatalf("marshal session body: %v", err)
			}
			if !bytes.Equal(got, []byte(tc.packet.BodyJSON)) {
				t.Fatalf("session body mismatch:\n got=%s\nwant=%s", got, tc.packet.BodyJSON)
			}
			if fields.HeaderType != tc.headerType || fields.UserID != fields.DeviceID || fields.AuthServiceID != agentAspID {
				t.Fatalf("conformance session fields drifted: %#v", fields)
			}
		})
	}
	if _, err := marshalNativeSessionApplicationBody("agent-01", "connector-01", NativeKnockOptions{RunID: "0123456789abcdef"}, 7); !errors.Is(err, ErrInvalidNativeKnockInput) {
		t.Fatalf("unsupported session header error = %v, want ErrInvalidNativeKnockInput", err)
	}
}

func TestInterpretNativeAgentKnockReply_ConformanceSessionACKs(t *testing.T) {
	vectors, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-session vectors: %v", err)
	}
	for _, tc := range []struct {
		name    string
		request conformance.AgentSessionPacket
		ack     conformance.AgentSessionPacket
	}{
		{name: "reknock", request: vectors.OverloadReknock.ReknockRequest, ack: vectors.OverloadReknock.ACK},
		{name: "exit", request: vectors.CleanExit.Request, ack: vectors.CleanExit.ACK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var request nativeAgentKnockBody
			if err := json.Unmarshal([]byte(tc.request.BodyJSON), &request); err != nil {
				t.Fatalf("decode conformance request body: %v", err)
			}
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: relayknock.TypeACK, Body: []byte(tc.ack.BodyJSON)}, request.KnockResourceID)
			if err != nil {
				t.Fatalf("interpret conformance ACK: %v", err)
			}
			if result == nil || result.ACToken == "" || result.ResourceHost == "" {
				t.Fatalf("conformance ACK did not contain a full admission envelope: %#v", result)
			}
		})
	}
}

func TestMarshalNativeKnockApplicationBody_RejectsRunIDBeforeOtherInputs(t *testing.T) {
	secretShapedRunID := "SECRET-UPPERCASE"
	_, err := marshalNativeKnockApplicationBody("", "", NativeKnockOptions{RunID: secretShapedRunID})
	if !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrInvalidCycleRunID) {
		t.Fatalf("invalid RunID error = %v, want ErrInvalidNativeKnockInput + ErrInvalidCycleRunID", err)
	}
	if strings.Contains(err.Error(), secretShapedRunID) {
		t.Fatalf("invalid RunID error leaked rejected value: %v", err)
	}
	if strings.Contains(err.Error(), "agent id") || strings.Contains(err.Error(), "knock resource id") {
		t.Fatalf("invalid RunID did not fail at the first validation boundary: %v", err)
	}
}

func TestMarshalNativeKnockApplicationBody_ValidatesIdentities(t *testing.T) {
	tests := []struct {
		name            string
		agentID         string
		knockResourceID string
		wantMessage     string
	}{
		{name: "empty agent id", knockResourceID: "connector-01", wantMessage: "agent id must not be blank"},
		{name: "whitespace agent id", agentID: " \t", knockResourceID: "connector-01", wantMessage: "agent id must not be blank"},
		{name: "leading agent id whitespace", agentID: " agent-01", knockResourceID: "connector-01", wantMessage: "agent id must not have surrounding whitespace"},
		{name: "trailing agent id whitespace", agentID: "agent-01\n", knockResourceID: "connector-01", wantMessage: "agent id must not have surrounding whitespace"},
		{name: "embedded agent id control", agentID: "agent\n01", knockResourceID: "connector-01", wantMessage: "agent id must not contain control characters"},
		{name: "invalid UTF-8 agent id", agentID: "agent-\xff", knockResourceID: "connector-01", wantMessage: "agent id must be valid UTF-8"},
		{name: "empty knock resource id", agentID: "agent-01", wantMessage: "knock resource id must not be blank"},
		{name: "whitespace knock resource id", agentID: "agent-01", knockResourceID: "\n", wantMessage: "knock resource id must not be blank"},
		{name: "leading knock resource id whitespace", agentID: "agent-01", knockResourceID: " connector-01", wantMessage: "knock resource id must not have surrounding whitespace"},
		{name: "trailing knock resource id whitespace", agentID: "agent-01", knockResourceID: "connector-01\t", wantMessage: "knock resource id must not have surrounding whitespace"},
		{name: "embedded knock resource id control", agentID: "agent-01", knockResourceID: "connector\x0001", wantMessage: "knock resource id must not contain control characters"},
		{name: "invalid UTF-8 knock resource id", agentID: "agent-01", knockResourceID: "connector-\xff", wantMessage: "knock resource id must be valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalNativeKnockApplicationBody(tt.agentID, tt.knockResourceID, NativeKnockOptions{RunID: "0123456789abcdef"})
			if !errors.Is(err, ErrInvalidNativeKnockInput) {
				t.Fatalf("error = %v, want ErrInvalidNativeKnockInput", err)
			}
			if errors.Is(err, ErrInvalidCycleRunID) {
				t.Fatalf("identity error = %v, must not expose ErrInvalidCycleRunID", err)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("error = %v, want message containing %q", err, tt.wantMessage)
			}
		})
	}
}

func TestMarshalNativeKnockApplicationBody_AllowsPrintableInternalWhitespace(t *testing.T) {
	const printableUnicodeSpace = "\u00a0"
	agentID := "agent " + printableUnicodeSpace + "01"
	knockResourceID := "connector " + printableUnicodeSpace + "01"
	got, err := marshalNativeKnockApplicationBody(agentID, knockResourceID, NativeKnockOptions{RunID: "0123456789abcdef"})
	if err != nil {
		t.Fatalf("marshalNativeKnockApplicationBody: %v", err)
	}
	want := `{"headerType":1,"usrId":"` + agentID + `","devId":"` + agentID + `","aspId":"agent","resId":"` + knockResourceID + `","runId":"0123456789abcdef"}`
	if string(got) != want {
		t.Fatalf("native knock body = %s, want %s", got, want)
	}
}

func TestMarshalNativeKnockApplicationBody_RejectsOversizedEncodedBody(t *testing.T) {
	const runID = "0123456789abcdef"
	base, err := marshalNativeKnockApplicationBody("a", "r", NativeKnockOptions{RunID: runID})
	if err != nil {
		t.Fatalf("marshal base body: %v", err)
	}
	resourceAtLimit := strings.Repeat("r", nhpcontract.MaxApplicationBodySize-len(base)+1)
	atLimit, err := marshalNativeKnockApplicationBody("a", resourceAtLimit, NativeKnockOptions{RunID: runID})
	if err != nil {
		t.Fatalf("marshal body at NHP maximum: %v", err)
	}
	if len(atLimit) != nhpcontract.MaxApplicationBodySize {
		t.Fatalf("body length = %d, want NHP maximum %d", len(atLimit), nhpcontract.MaxApplicationBodySize)
	}

	// One more valid identity byte exercises the aggregate serialized-body
	// boundary directly.
	_, err = marshalNativeKnockApplicationBody("a", resourceAtLimit+"r", NativeKnockOptions{RunID: runID})
	if !errors.Is(err, ErrInvalidNativeKnockInput) {
		t.Fatalf("oversized body error = %v, want ErrInvalidNativeKnockInput", err)
	}
	if !strings.Contains(err.Error(), "encoded body exceeds NHP maximum") {
		t.Fatalf("oversized body error = %v, want encoded-body limit context", err)
	}
}

func TestNativeKnockApplicationConformance(t *testing.T) {
	vectors, err := conformance.AgentKnockApplication()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-knock application vectors: %v", err)
	}
	fields := vectors.Request.Fields
	if fields.UserID != fields.DeviceID {
		t.Fatalf("registered-agent vector user_id = %q, device_id = %q; the native SDK derives both from persisted agent_id", fields.UserID, fields.DeviceID)
	}

	canonical, err := marshalNativeKnockApplicationBody(fields.DeviceID, fields.KnockResourceID, NativeKnockOptions{RunID: fields.RunID})
	if err != nil {
		t.Fatalf("marshal canonical native knock body: %v", err)
	}
	if !bytes.Equal(canonical, []byte(vectors.Request.BodyJSON)) {
		t.Fatalf("canonical native knock body mismatch:\n got=%s\nwant=%s", canonical, vectors.Request.BodyJSON)
	}
	if vectors.Request.WireType != nhpKNKHeaderType || fields.HeaderType != nhpKNKHeaderType || fields.AuthServiceID != agentAspID {
		t.Fatalf("agent-knock vector constants drifted: wire=%d header=%d asp=%q", vectors.Request.WireType, fields.HeaderType, fields.AuthServiceID)
	}

	for _, vector := range vectors.RequestCases {
		t.Run(vector.Name, func(t *testing.T) {
			assertNativeKnockRequestVector(t, fields, canonical, vector)
		})
	}

	applicationCases := 0
	for _, vector := range vectors.ReplyCases {
		if vector.RejectClass == conformance.AgentKnockRejectCounter || vector.RejectClass == conformance.AgentKnockRejectReplyType {
			// These cases are consumed with the same corpus in nativeudp's
			// correlation-layer test, before an application interpreter can run.
			continue
		}
		applicationCases++
		t.Run("reply/"+vector.Name, func(t *testing.T) {
			result, err := interpretNativeAgentKnockReply(&relayknock.Reply{Type: vector.ReplyType, Body: []byte(vector.BodyJSON)}, fields.KnockResourceID)
			switch vector.Outcome {
			case conformance.AgentKnockOutcomeSuccess:
				if err != nil || result == nil || result.ACToken != vector.ExpectedACToken || result.ResourceHost != vector.ExpectedResourceHost {
					t.Fatalf("success reply = %#v, %v; want token=%q host=%q", result, err, vector.ExpectedACToken, vector.ExpectedResourceHost)
				}
			case conformance.AgentKnockOutcomeDeny:
				var deny *ServerDenyError
				if result != nil || !errors.As(err, &deny) || errors.Is(err, ErrMalformedReply) {
					t.Fatalf("deny reply = %#v, %T: %v", result, err, err)
				}
			case conformance.AgentKnockOutcomeRetry:
				if result != nil || !errors.Is(err, ErrServerOverloaded) {
					t.Fatalf("retry reply = %#v, %v, want ErrServerOverloaded", result, err)
				}
			case conformance.AgentKnockOutcomeReject:
				if result != nil || !errors.Is(err, ErrMalformedReply) {
					t.Fatalf("rejected reply = %#v, %v, want ErrMalformedReply", result, err)
				}
			default:
				t.Fatalf("unknown golden reply outcome %q", vector.Outcome)
			}
		})
	}
	if applicationCases != len(vectors.ReplyCases)-2 {
		t.Fatalf("application golden reply cases = %d, want %d", applicationCases, len(vectors.ReplyCases)-2)
	}
}

func assertNativeKnockRequestVector(
	t *testing.T,
	fields conformance.AgentKnockApplicationRequestFields,
	canonical []byte,
	vector conformance.AgentKnockRequestCase,
) {
	t.Helper()
	want := vector.NativeConnector
	switch want.Outcome {
	case conformance.ExpectAccept:
		if want.ParsedRunID == nil {
			t.Fatal("accept vector has no parsed_run_id")
		}
		got, err := marshalNativeKnockApplicationBody(fields.DeviceID, fields.KnockResourceID, NativeKnockOptions{RunID: *want.ParsedRunID})
		if err != nil {
			t.Fatalf("accepted RunID rejected: %v", err)
		}
		if !bytes.Equal(got, []byte(vector.BodyJSON)) {
			t.Fatalf("accepted body mismatch:\n got=%s\nwant=%s", got, vector.BodyJSON)
		}
	case conformance.ExpectReject:
		switch want.RejectClass {
		case conformance.AgentKnockRejectMissingRunID, conformance.AgentKnockRejectInvalidRunID:
			runID := runIDFromSingleCanonicalField(t, []byte(vector.BodyJSON))
			_, err := marshalNativeKnockApplicationBody(fields.DeviceID, fields.KnockResourceID, NativeKnockOptions{RunID: runID})
			if !errors.Is(err, ErrInvalidNativeKnockInput) || !errors.Is(err, ErrInvalidCycleRunID) {
				t.Fatalf("rejected RunID error = %v, want native input + cycle RunID sentinels", err)
			}
		case conformance.AgentKnockRejectBodyParse:
			// The typed SDK accepts semantic fields, never caller-authored JSON.
			// Duplicate/alias spellings therefore have no input path. Fence that
			// the production serializer emits exactly one canonical runId key and
			// cannot reproduce any of the raw body-parse rejects.
			if bytes.Equal(canonical, []byte(vector.BodyJSON)) {
				t.Fatal("typed native serializer reproduced a duplicate/alias reject vector")
			}
			rejectKeys := topLevelJSONKeyCounts(t, []byte(vector.BodyJSON))
			if rejectKeys["runId"] < 2 && rejectKeys["runID"] == 0 && rejectKeys["run_id"] == 0 {
				t.Fatalf("body_parse vector no longer exercises a duplicate/alias RunID key: %#v", rejectKeys)
			}
			keys := topLevelJSONKeyCounts(t, canonical)
			if keys["runId"] != 1 || keys["runID"] != 0 || keys["run_id"] != 0 {
				t.Fatalf("typed native serializer RunID keys = %#v, want one exact runId", keys)
			}
		default:
			t.Fatalf("unknown native connector reject class %q", want.RejectClass)
		}
	default:
		t.Fatalf("unknown native connector outcome %q", want.Outcome)
	}
}

func runIDFromSingleCanonicalField(t *testing.T, body []byte) string {
	t.Helper()
	var wire struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("decode vector body: %v", err)
	}
	return wire.RunID
}

func topLevelJSONKeyCounts(t *testing.T, body []byte) map[string]int {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		t.Fatalf("decode vector object start: token=%v err=%v", start, err)
	}
	counts := make(map[string]int)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("decode vector key: %v", err)
		}
		name, ok := key.(string)
		if !ok {
			t.Fatalf("vector key token type = %T, want string", key)
		}
		counts[name]++
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatalf("decode vector field %q: %v", name, err)
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		t.Fatalf("decode vector object end: token=%v err=%v", end, err)
	}
	return counts
}
