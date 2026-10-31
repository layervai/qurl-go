package qurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStrictJSONProfiles(t *testing.T) {
	nested := func(value string, wrappers int) string {
		return strings.Repeat(`{"a":`, wrappers) + value + strings.Repeat("}", wrappers)
	}
	arrays := func(depth int) string {
		return `{"a":` + strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth) + "}"
	}
	tests := []struct {
		name            string
		raw             string
		accept          [3]bool // assignment, sealed state, qv2 structural pass
		sealedDuplicate bool
		sealedDepth     bool
	}{
		{name: "empty"},
		{name: "whitespace", raw: " \n\t"},
		{name: "empty object", raw: `{}`, accept: [3]bool{true, true, true}},
		{name: "scalar", raw: `1`, accept: [3]bool{false, true, false}},
		{name: "array", raw: `[]`, accept: [3]bool{false, true, false}},
		{name: "top null", raw: `null`, accept: [3]bool{false, true, false}},
		{name: "known field", raw: `{"a":1}`, accept: [3]bool{true, true, true}},
		{name: "raw lexemes", raw: `{ "a": 1e02, "b": [ 1 , 2 ] }`, accept: [3]bool{true, true, true}},
		{name: "unknown root field", raw: `{"c":1}`, accept: [3]bool{true, true, false}},
		{name: "top duplicate", raw: `{"a":1,"a":2}`, sealedDuplicate: true},
		{name: "escaped duplicate", raw: `{"a":1,"\u0061":2}`, sealedDuplicate: true},
		{name: "nested duplicate", raw: `{"a":{"b":1,"b":2}}`, accept: [3]bool{false, false, true}, sealedDuplicate: true},
		{name: "array duplicate", raw: `{"a":[{"b":1,"b":2}]}`, accept: [3]bool{false, false, true}, sealedDuplicate: true},
		{name: "root field null", raw: `{"a":null}`, accept: [3]bool{true, true, false}},
		{name: "nested null", raw: `{"a":{"b":null}}`, accept: [3]bool{true, true, true}},
		{name: "truncated object", raw: `{"a":`},
		{name: "missing object close", raw: `{"a":1`},
		{name: "missing array close", raw: `{"a":[1`},
		{name: "truncated array", raw: `{"a":[`},
		{name: "wrong closing token", raw: `{"a":[1,}`},
		{name: "trailing object", raw: `{} {}`},
		{name: "trailing scalar", raw: `{} true`},
		{name: "trailing closing token", raw: `{} }`},
		{name: "trailing malformed token", raw: `{} ?`},
		{name: "exact large number", raw: `{"a":1e9999}`, accept: [3]bool{true, false, true}},
		{name: "invalid UTF8 value", raw: "{\"a\":\"\xff\"}", accept: [3]bool{false, true, true}},
		{name: "sealed last empty container", raw: nested(`{}`, 32), accept: [3]bool{true, true, true}},
		{name: "sealed container too deep", raw: nested(`{}`, 33), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "sealed last scalar", raw: nested(`0`, 32), accept: [3]bool{true, true, true}},
		{name: "sealed scalar too deep", raw: nested(`0`, 33), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "assignment last container", raw: nested(`{}`, 63), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "assignment container too deep", raw: nested(`{}`, 64), accept: [3]bool{false, false, true}, sealedDepth: true},
		{name: "assignment last scalar", raw: nested(`0`, 64), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "assignment scalar parent too deep", raw: nested(`0`, 65), accept: [3]bool{false, false, true}, sealedDepth: true},
		{name: "sealed array last scalar", raw: arrays(31), accept: [3]bool{true, true, true}},
		{name: "sealed array scalar too deep", raw: arrays(32), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "assignment last array", raw: arrays(63), accept: [3]bool{true, false, true}, sealedDepth: true},
		{name: "assignment array too deep", raw: arrays(64), accept: [3]bool{false, false, true}, sealedDepth: true},
		{name: "qv2 iterative nested drain", raw: arrays(2048), accept: [3]bool{false, false, true}, sealedDepth: true},
	}
	for _, tc := range tests {
		for index, profile := range []string{"assignment", "sealed", "qv2"} {
			t.Run(tc.name+"/"+profile, func(t *testing.T) {
				var fields map[string]json.RawMessage
				var err error
				switch profile {
				case "assignment":
					fields, err = exactObjectFields([]byte(tc.raw))
				case "sealed":
					err = rejectDuplicateJSONFields([]byte(tc.raw))
				case "qv2":
					_, err = strictObjectWalk([]byte(tc.raw), map[string]struct{}{"a": {}, "b": {}})
				}
				if (err == nil) != tc.accept[index] {
					t.Fatalf("accept = %t, want %t: %v", err == nil, tc.accept[index], err)
				}
				duplicate := errors.Is(err, errDuplicateSealedJSONField)
				depth := errors.Is(err, errSealedJSONNesting)
				strict := errors.Is(err, ErrStrictParse)
				if duplicate != (profile == "sealed" && tc.sealedDuplicate) || depth != (profile == "sealed" && tc.sealedDepth) || strict != (profile == "qv2" && err != nil) {
					t.Fatalf("error taxonomy changed: %v", err)
				}
				message := ""
				if err != nil {
					message = err.Error()
				}
				record := struct {
					Name, Profile, Error     string
					Fields                   map[string]json.RawMessage
					Duplicate, Depth, Strict bool
				}{tc.name, profile, message, fields, duplicate, depth, strict}
				encoded, encodeErr := json.Marshal(record)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				t.Logf("STRICT_JSON_PROFILE %s", encoded)
			})
		}
	}
}

func TestQV2NestedContainersRemainRejectedByTypedDecode(t *testing.T) {
	for _, value := range []string{`{"a":1,"a":2}`, `[null]`, `{"a":null}`} {
		raw := []byte(fmt.Sprintf(`{"%s":%s}`, fieldQurlUserPrivateKeyB64, value))
		if _, err := parseSecret(raw); !errors.Is(err, ErrStrictParse) {
			t.Fatalf("nested qv2 scalar field = %v, want ErrStrictParse", err)
		}
	}
}

func TestStrictObjectWalkNilAllowlist(t *testing.T) {
	if _, err := strictObjectWalk([]byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := strictObjectWalk([]byte(`{"a":1}`), nil); !errors.Is(err, ErrStrictParse) {
		t.Fatalf("nil allowlist = %v, want ErrStrictParse", err)
	}
}

func TestJSONStructureRejectsUnboundedDuplicateWalk(t *testing.T) {
	_, problem := walkJSONStructure([]byte(`{}`), jsonStructurePolicy{
		deepDuplicates: true, maxContainerDepth: -1, maxValueDepth: -1,
	})
	if problem == nil || problem.kind != jsonStructureSyntax || problem.cause == nil {
		t.Fatalf("unbounded duplicate walk = %v, want policy error", problem)
	}
}
