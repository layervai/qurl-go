package cryptoutil

import "testing"

func TestRandomValues(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("RandomBytes length = %d, want 32", len(b))
	}
	if _, err := RandomUint64(); err != nil {
		t.Fatalf("RandomUint64: %v", err)
	}
	if _, err := RandomUint32(); err != nil {
		t.Fatalf("RandomUint32: %v", err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, want 0", i, v)
		}
	}
	Wipe(nil) // must not panic
}
