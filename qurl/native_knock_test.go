package qurl

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
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

func TestMarshalNativeKnockApplicationBody_RejectsRunIDBeforeOtherInputs(t *testing.T) {
	secretShapedRunID := "SECRET-UPPERCASE"
	_, err := marshalNativeKnockApplicationBody("", "", NativeKnockOptions{RunID: secretShapedRunID})
	if !errors.Is(err, ErrInvalidNativeKnockOptions) || !errors.Is(err, ErrInvalidCycleRunID) {
		t.Fatalf("invalid RunID error = %v, want ErrInvalidNativeKnockOptions + ErrInvalidCycleRunID", err)
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
	}{
		{name: "empty agent id", knockResourceID: "connector-01"},
		{name: "whitespace agent id", agentID: " \t", knockResourceID: "connector-01"},
		{name: "empty knock resource id", agentID: "agent-01"},
		{name: "whitespace knock resource id", agentID: "agent-01", knockResourceID: "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalNativeKnockApplicationBody(tt.agentID, tt.knockResourceID, NativeKnockOptions{RunID: "0123456789abcdef"})
			if !errors.Is(err, ErrInvalidNativeKnockOptions) {
				t.Fatalf("error = %v, want ErrInvalidNativeKnockOptions", err)
			}
		})
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
			if !errors.Is(err, ErrInvalidNativeKnockOptions) || !errors.Is(err, ErrInvalidCycleRunID) {
				t.Fatalf("rejected RunID error = %v, want native options + cycle RunID sentinels", err)
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
