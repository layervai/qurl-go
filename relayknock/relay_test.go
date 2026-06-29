package relayknock

import "testing"

func TestRelayErrorString(t *testing.T) {
	tests := []struct {
		name string
		err  *RelayError
		want string
	}{
		{name: "nil", err: nil, want: "relay error"},
		{name: "empty", err: &RelayError{}, want: "relay error"},
		{name: "message", err: &RelayError{Msg: "relay failed"}, want: "relay failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("RelayError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
