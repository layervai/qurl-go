package qv2

import (
	"strings"
	"testing"
)

const (
	validSignaturePayloadJSON    = `"claims_b64":"claims","sig_b64":"sig","sig_encoding":"raw_r_s","signing_input_b64":"input"`
	validDERSignaturePayloadJSON = `"claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`
)

func vectorJSON(fields string) string {
	return `{"vectors":[{` + fields + `,` + validSignaturePayloadJSON + `}]}`
}

func derVectorJSON(fields string) string {
	return `{"vectors":[{` + fields + `,` + validDERSignaturePayloadJSON + `}]}`
}

func vectorFileJSON(fields string) string {
	return `{"vectors":[{` + fields + `}]}`
}

func TestLoadVectorBytesValidatesSignatureRejectClass(t *testing.T) {
	tests := []struct {
		name            string
		json            string
		wantExpect      string
		wantRejectClass string
		wantErrSubstr   string
	}{
		{
			name:          "malformed_json",
			json:          `{"vectors":[`,
			wantErrSubstr: "parse vector file",
		},
		{
			name:          "empty_vectors",
			json:          `{"vectors":[]}`,
			wantErrSubstr: "vector file has no vectors",
		},
		{
			name:       "accept_without_reject_class",
			json:       vectorJSON(`"name":"accept_valid_low_s","expect":"accept","reason":"valid signature"`),
			wantExpect: ExpectAccept,
		},
		{
			name:            "reject_with_high_s",
			json:            vectorJSON(`"name":"reject_high_s","expect":"reject","reason":"signature is not low-S normalized","reject_class":"high_s"`),
			wantExpect:      ExpectReject,
			wantRejectClass: RejectClassHighS,
		},
		{
			name:            "reject_with_wrong_length",
			json:            derVectorJSON(`"name":"reject_wrong_length_der","expect":"reject","reason":"signature is not exactly 64 bytes","reject_class":"wrong_length"`),
			wantExpect:      ExpectReject,
			wantRejectClass: RejectClassWrongLength,
		},
		{
			name:          "accept_with_reject_class",
			json:          vectorJSON(`"name":"bad_accept","expect":"accept","reason":"valid signature","reject_class":"high_s"`),
			wantErrSubstr: `accept signature vector "bad_accept" has reject_class "high_s"`,
		},
		{
			name:          "duplicate_name",
			json:          `{"vectors":[{` + `"name":"dupe","expect":"accept","reason":"valid signature",` + validSignaturePayloadJSON + `},{` + `"name":"dupe","expect":"accept","reason":"another valid signature",` + validSignaturePayloadJSON + `}]}`,
			wantErrSubstr: `duplicate signature vector name "dupe"`,
		},
		{
			name:          "reject_without_reject_class",
			json:          vectorJSON(`"name":"stale_reject","expect":"reject","reason":"high_s"`),
			wantErrSubstr: `reject signature vector "stale_reject" is missing reject_class`,
		},
		{
			name:          "accept_with_empty_reject_class",
			json:          vectorJSON(`"name":"bad_accept_empty","expect":"accept","reason":"valid signature","reject_class":""`),
			wantErrSubstr: `accept signature vector "bad_accept_empty" has reject_class ""`,
		},
		{
			name:          "reject_with_empty_reject_class",
			json:          vectorJSON(`"name":"bad_reject_empty","expect":"reject","reason":"unknown class","reject_class":""`),
			wantErrSubstr: `reject signature vector "bad_reject_empty" has reject_class ""`,
		},
		{
			name:          "reject_with_unknown_reject_class",
			json:          vectorJSON(`"name":"bad_reject","expect":"reject","reason":"unknown class","reject_class":"bogus"`),
			wantErrSubstr: `reject signature vector "bad_reject" has reject_class "bogus"`,
		},
		{
			name:          "unknown_expect",
			json:          vectorJSON(`"name":"bad_expect","expect":"maybe","reason":"unknown expectation"`),
			wantErrSubstr: `signature vector "bad_expect" has expect "maybe"`,
		},
		{
			name:          "empty_name",
			json:          vectorJSON(`"expect":"accept","reason":"valid signature"`),
			wantErrSubstr: `signature vector at index 0 has empty name`,
		},
		{
			name:          "blank_name",
			json:          vectorJSON(`"name":"   ","expect":"accept","reason":"valid signature"`),
			wantErrSubstr: `signature vector at index 0 has empty name`,
		},
		{
			name:          "empty_reason",
			json:          vectorJSON(`"name":"missing_reason","expect":"accept"`),
			wantErrSubstr: `signature vector "missing_reason" has empty reason`,
		},
		{
			name:          "blank_reason",
			json:          vectorJSON(`"name":"blank_reason","expect":"accept","reason":"   "`),
			wantErrSubstr: `signature vector "blank_reason" has empty reason`,
		},
		{
			name:          "missing_claims_b64",
			json:          vectorFileJSON(`"name":"missing_claims","expect":"accept","reason":"valid signature","sig_b64":"sig","sig_encoding":"raw_r_s","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_claims" has empty claims_b64`,
		},
		{
			name:          "missing_sig_b64",
			json:          vectorFileJSON(`"name":"missing_sig","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_encoding":"raw_r_s","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_sig" has empty sig_b64`,
		},
		{
			name:          "missing_sig_encoding",
			json:          vectorFileJSON(`"name":"missing_encoding","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "missing_encoding" has empty sig_encoding`,
		},
		{
			name:          "unknown_sig_encoding",
			json:          vectorFileJSON(`"name":"unknown_encoding","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"pem","signing_input_b64":"input"`),
			wantErrSubstr: `signature vector "unknown_encoding" has sig_encoding "pem", want raw_r_s|der`,
		},
		{
			name:          "accept_with_der_sig_encoding",
			json:          vectorFileJSON(`"name":"bad_accept_der","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`),
			wantErrSubstr: `accept signature vector "bad_accept_der" has sig_encoding "der", want raw_r_s`,
		},
		{
			name:          "high_s_with_der_sig_encoding",
			json:          vectorFileJSON(`"name":"bad_high_s_der","expect":"reject","reason":"high-S signature","reject_class":"high_s","claims_b64":"claims","sig_b64":"sig","sig_encoding":"der","signing_input_b64":"input"`),
			wantErrSubstr: `reject signature vector "bad_high_s_der" with reject_class "high_s" has sig_encoding "der", want raw_r_s`,
		},
		{
			name:          "wrong_length_with_raw_sig_encoding",
			json:          vectorJSON(`"name":"bad_wrong_length_raw","expect":"reject","reason":"wrong-length signature","reject_class":"wrong_length"`),
			wantErrSubstr: `reject signature vector "bad_wrong_length_raw" with reject_class "wrong_length" has sig_encoding "raw_r_s", want der`,
		},
		{
			name:          "missing_signing_input_b64",
			json:          vectorFileJSON(`"name":"missing_signing_input","expect":"accept","reason":"valid signature","claims_b64":"claims","sig_b64":"sig","sig_encoding":"raw_r_s"`),
			wantErrSubstr: `signature vector "missing_signing_input" has empty signing_input_b64`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vf, err := LoadVectorBytes([]byte(tt.json))
			if tt.wantErrSubstr != "" && err == nil {
				t.Fatal("LoadVectorBytes() error = nil, want error")
			}
			if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("LoadVectorBytes() error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
			if tt.wantErrSubstr == "" && err != nil {
				t.Fatalf("LoadVectorBytes(): %v", err)
			}
			if tt.wantErrSubstr != "" {
				return
			}
			got := vf.Vectors[0]
			if got.Expect != tt.wantExpect {
				t.Fatalf("parsed expect = %q, want %q", got.Expect, tt.wantExpect)
			}
			gotRejectClass := ""
			if got.RejectClass != nil {
				gotRejectClass = *got.RejectClass
			}
			if gotRejectClass != tt.wantRejectClass {
				t.Fatalf("parsed reject_class = %q, want %q", gotRejectClass, tt.wantRejectClass)
			}
		})
	}
}

func signatureRejectClass(t *testing.T, v SignatureVector) string {
	t.Helper()
	if v.RejectClass == nil {
		t.Fatalf("reject vector %q must carry reject_class after LoadVectorBytes", v.Name)
	}
	return *v.RejectClass
}
