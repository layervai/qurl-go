package qurl

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNewCycleRunID_DeterministicAndExactEntropyConsumption(t *testing.T) {
	entropy := bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03, 0xfe, 0xfd, 0xfc, 0xff, 0x7a})
	startLen := entropy.Len()

	got, err := newCycleRunID(entropy)
	if err != nil {
		t.Fatalf("newCycleRunID: %v", err)
	}
	if want := "00010203fefdfcff"; got != want {
		t.Fatalf("newCycleRunID = %q, want %q", got, want)
	}
	if consumed := startLen - entropy.Len(); consumed != cycleRunIDEntropyBytes {
		t.Fatalf("newCycleRunID consumed %d bytes, want exactly %d", consumed, cycleRunIDEntropyBytes)
	}
	if err := ValidateCycleRunID(got); err != nil {
		t.Fatalf("generated cycle RunID is not canonical: %v", err)
	}
}

func TestNewCycleRunID_ProducesCanonicalValue(t *testing.T) {
	runID, err := NewCycleRunID()
	if err != nil {
		t.Fatalf("NewCycleRunID: %v", err)
	}
	if err := ValidateCycleRunID(runID); err != nil {
		t.Fatalf("NewCycleRunID returned %q: %v", runID, err)
	}
}

func TestNewCycleRunID_EntropyFailures(t *testing.T) {
	sentinel := errors.New("entropy unavailable")
	tests := []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{name: "terminal error", reader: cycleRunIDErrorReader{err: sentinel}, want: sentinel},
		{name: "short read", reader: bytes.NewReader(make([]byte, cycleRunIDEntropyBytes-1)), want: io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newCycleRunID(tt.reader)
			if got != "" {
				t.Fatalf("newCycleRunID = %q on entropy failure, want empty", got)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("newCycleRunID error = %v, want errors.Is(..., %v)", err, tt.want)
			}
		})
	}
}

func TestValidateCycleRunID(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "mixed canonical", value: "0123456789abcdef", valid: true},
		{name: "all zero", value: "0000000000000000", valid: true},
		{name: "all f", value: "ffffffffffffffff", valid: true},
		{name: "missing", value: ""},
		{name: "surrounding space", value: " 123456789abcdef"},
		{name: "internal space", value: "01234567 9abcdef"},
		{name: "uppercase", value: "0123456789abcdeF"},
		{name: "fifteen characters", value: "0123456789abcde"},
		{name: "seventeen characters", value: "0123456789abcdef0"},
		{name: "non hex", value: "0123456789abcdeg"},
		{name: "newline", value: "0123456789abcde\n"},
		{name: "nul", value: "0123456789abcde\x00"},
		{name: "unicode byte length", value: "0123456789abcdé"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCycleRunID(tt.value)
			if tt.valid {
				if err != nil {
					t.Fatalf("ValidateCycleRunID(%q) = %v, want nil", tt.value, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidCycleRunID) {
				t.Fatalf("ValidateCycleRunID(%q) = %v, want ErrInvalidCycleRunID", tt.value, err)
			}
			if tt.value != "" && strings.Contains(err.Error(), tt.value) {
				t.Fatalf("ValidateCycleRunID(%q) leaked rejected input in %q", tt.value, err)
			}
		})
	}
}

func FuzzValidateCycleRunID(f *testing.F) {
	for _, seed := range []string{
		"0123456789abcdef",
		"",
		"0123456789abcdeF",
		"01234567 9abcdef",
		"0123456789abcdé",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, runID string) {
		wantValid := len(runID) == cycleRunIDLength
		for i := 0; wantValid && i < len(runID); i++ {
			c := runID[i]
			wantValid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		}

		err := ValidateCycleRunID(runID)
		if wantValid && err != nil {
			t.Fatalf("ValidateCycleRunID(%q) = %v, want nil", runID, err)
		}
		if !wantValid && !errors.Is(err, ErrInvalidCycleRunID) {
			t.Fatalf("ValidateCycleRunID(%q) = %v, want ErrInvalidCycleRunID", runID, err)
		}
	})
}

type cycleRunIDErrorReader struct{ err error }

func (r cycleRunIDErrorReader) Read([]byte) (int, error) { return 0, r.err }
