package nhpwire

import (
	"bytes"
	"compress/zlib"
	"testing"
)

// TestInflateZlib_FailsClosedOnOversize pins the fail-closed guard: a stream that
// inflates past PacketBufferSize returns an explicit error rather than a silently
// truncated (corrupt) body. The compress flag rides on the server reply, so this
// is the SDK refusing an over-large inflated body from a misbehaving server.
func TestInflateZlib_FailsClosedOnOversize(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	// Zeroes compress well, so a modest wire body inflates well past the cap.
	if _, err := w.Write(make([]byte, PacketBufferSize+1024)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	if _, err := inflateZlib(buf.Bytes()); err == nil {
		t.Fatal("inflateZlib accepted an over-large inflated body; want a fail-closed error")
	}
}

// TestInflateZlib_AcceptsAtLimit confirms the guard does not reject a body that
// inflates to exactly the limit (the +1 read distinguishes exact-fit from
// truncation).
func TestInflateZlib_AcceptsAtLimit(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(make([]byte, PacketBufferSize)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	body, err := inflateZlib(buf.Bytes())
	if err != nil {
		t.Fatalf("inflateZlib rejected an exactly-at-limit body: %v", err)
	}
	if len(body) != PacketBufferSize {
		t.Fatalf("inflated length = %d, want %d", len(body), PacketBufferSize)
	}
}
