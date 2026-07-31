package qurl

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Duplicate-key rejection is covered by TestNewCellCatalogRejectsDuplicateKeys
// in portal_nativeudp_test.go and is deliberately not repeated here.

// The catalog decides which cell a verified link is allowed to be knocked at
// directly, and every rejection path below degrades to the relay rather than to
// an error if it is skipped. A silent degradation is the failure mode worth
// testing: it looks like success.

func testCellKey(t *testing.T, seed byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate cell key: %v", err)
	}
	key[0] = seed
	return key
}

func TestNewCellCatalogRejectsEmpty(t *testing.T) {
	if _, err := NewCellCatalog(nil); !errors.Is(err, ErrNoCellEndpoints) {
		t.Fatalf("nil entries: got %v, want ErrNoCellEndpoints", err)
	}
	if _, err := NewCellCatalog([]CellEntry{}); !errors.Is(err, ErrNoCellEndpoints) {
		t.Fatalf("empty entries: got %v, want ErrNoCellEndpoints", err)
	}
}

func TestNewCellCatalogRejectsMalformedEntries(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testCellKey(t, 2))
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))

	for _, tc := range []struct {
		name  string
		entry CellEntry
		want  string
	}{
		{"no key", CellEntry{CellID: "c", Host: "h", Port: 1}, "has no server public key"},
		{"blank key", CellEntry{CellID: "c", Host: "h", Port: 1, ServerPublicKeyB64: "   "}, "has no server public key"},
		{"not base64", CellEntry{CellID: "c", Host: "h", Port: 1, ServerPublicKeyB64: "!!!not base64!!!"}, "not valid base64"},
		{"key too short", CellEntry{CellID: "c", Host: "h", Port: 1, ServerPublicKeyB64: short}, "31 bytes, want 32"},
		{"key too long", CellEntry{CellID: "c", Host: "h", Port: 1, ServerPublicKeyB64: long}, "33 bytes, want 32"},
		{"no host", CellEntry{CellID: "c", Port: 1, ServerPublicKeyB64: good}, "has no host"},
		{"blank host", CellEntry{CellID: "c", Host: "  ", Port: 1, ServerPublicKeyB64: good}, "has no host"},
		{"port zero", CellEntry{CellID: "c", Host: "h", ServerPublicKeyB64: good}, "out-of-range port"},
		{"port negative", CellEntry{CellID: "c", Host: "h", Port: -1, ServerPublicKeyB64: good}, "out-of-range port"},
		{"port too high", CellEntry{CellID: "c", Host: "h", Port: 65536, ServerPublicKeyB64: good}, "out-of-range port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCellCatalog([]CellEntry{tc.entry})
			if err == nil {
				t.Fatalf("entry was accepted; a bad cell would degrade to the relay silently")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// One bad entry must fail the whole catalog. Dropping just the bad cell would
// leave its links quietly falling back to the relay.
func TestNewCellCatalogFailsWholeCatalogOnOneBadEntry(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testCellKey(t, 3))
	if _, err := NewCellCatalog([]CellEntry{
		{CellID: "good", Host: "a.example", Port: 62206, ServerPublicKeyB64: good},
		{CellID: "bad", Host: "b.example", Port: 62206, ServerPublicKeyB64: "nope"},
	}); err == nil {
		t.Fatal("catalog built despite a malformed entry")
	}
}

// Operators copy these keys between Terraform, SSM, and JSON, which disagree
// about base64 alphabet and padding. All four spellings of one key must produce
// the same catalog entry, or a cell becomes unreachable over punctuation.
func TestCellCatalogAcceptsEveryBase64Spelling(t *testing.T) {
	key := testCellKey(t, 4)
	// Force a byte that differs between the standard and URL alphabets so the
	// spellings are genuinely distinct strings, not the same text four times.
	key[1], key[2] = 0xFB, 0xFF
	spellings := map[string]string{
		"std":    base64.StdEncoding.EncodeToString(key),
		"rawStd": base64.RawStdEncoding.EncodeToString(key),
		"url":    base64.URLEncoding.EncodeToString(key),
		"rawURL": base64.RawURLEncoding.EncodeToString(key),
		"padded": "  " + base64.StdEncoding.EncodeToString(key) + "  ",
	}
	distinct := map[string]bool{}
	for _, s := range spellings {
		distinct[strings.TrimSpace(s)] = true
	}
	if len(distinct) < 2 {
		t.Fatal("test key does not actually distinguish base64 alphabets")
	}
	for name, encoded := range spellings {
		t.Run(name, func(t *testing.T) {
			catalog, err := NewCellCatalog([]CellEntry{
				{CellID: "cell0", Host: "a.example", Port: 62206, ServerPublicKeyB64: encoded},
			})
			if err != nil {
				t.Fatalf("spelling %s rejected: %v", name, err)
			}
			ep, ok := catalog.lookup(key)
			if !ok {
				t.Fatalf("spelling %s built a catalog that does not match its own key", name)
			}
			if ep.Host != "a.example" || ep.Port != 62206 || ep.CellID != "cell0" {
				t.Fatalf("spelling %s produced %+v", name, ep)
			}
		})
	}
}

func TestCellCatalogLookup(t *testing.T) {
	known := testCellKey(t, 5)
	other := testCellKey(t, 6)
	catalog, err := NewCellCatalog([]CellEntry{
		{CellID: "cell0", Host: "a.example", Port: 62206,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(known)},
	})
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}

	if _, ok := catalog.lookup(known); !ok {
		t.Fatal("known cell key did not match")
	}
	// An unknown cell is not an error: it is a cell this build predates, and it
	// must route through the relay rather than fail.
	if _, ok := catalog.lookup(other); ok {
		t.Fatal("unknown cell key matched; an open would be sent to the wrong cell")
	}
	if _, ok := catalog.lookup(nil); ok {
		t.Fatal("nil key matched")
	}
	if _, ok := catalog.lookup([]byte{}); ok {
		t.Fatal("empty key matched")
	}
	// A truncated prefix of a known key must not match: matching on anything
	// less than the whole key would let a partial value select a real cell.
	if _, ok := catalog.lookup(known[:16]); ok {
		t.Fatal("truncated key matched a full cell key")
	}

	// A nil catalog is the "this build ships no cells" case and must report
	// false rather than panic, because that is the relay-fallback path.
	var nilCatalog *CellCatalog
	if _, ok := nilCatalog.lookup(known); ok {
		t.Fatal("nil catalog reported a match")
	}
}

// The catalog must not alias its caller's slice: a later mutation of the entry
// list cannot be allowed to repoint a cell.
func TestCellCatalogIsIndependentOfCallerSlice(t *testing.T) {
	key := testCellKey(t, 7)
	entries := []CellEntry{
		{CellID: "cell0", Host: "a.example", Port: 62206,
			ServerPublicKeyB64: base64.StdEncoding.EncodeToString(key)},
	}
	catalog, err := NewCellCatalog(entries)
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}
	entries[0].Host = "attacker.example"
	entries[0].Port = 1

	ep, ok := catalog.lookup(key)
	if !ok {
		t.Fatal("cell vanished after caller mutated its own slice")
	}
	if ep.Host != "a.example" || ep.Port != 62206 {
		t.Fatalf("catalog followed a caller mutation: %+v", ep)
	}
}

func TestDecodeCellPublicKeyRoundTrip(t *testing.T) {
	key := testCellKey(t, 8)
	got, err := decodeCellPublicKey(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("decoded key does not equal the original")
	}
}
